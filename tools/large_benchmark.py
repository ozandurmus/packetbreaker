"""Bounded-memory 5-file benchmark. Run each stage under /usr/bin/time -l on macOS."""

import argparse
import csv
import hashlib
import heapq
import json
from pathlib import Path
import resource
import socket
import struct
import subprocess
import tempfile
import time

from packetbreaker.analysis import analyze
from packetbreaker.ingest import find_tshark, ingest, tuple_id
from packetbreaker.store import PACKET_COLUMNS, Project
from packetbreaker.synthetic import tcp_packet

ANALYSIS_FIELDS = {
    "frame": "frame.number",
    "stream": "tcp.stream",
    "retrans": "tcp.analysis.retransmission",
    "fast_retrans": "tcp.analysis.fast_retransmission",
    "spurious": "tcp.analysis.spurious_retransmission",
    "out_of_order": "tcp.analysis.out_of_order",
    "acked_unseen": "tcp.analysis.ack_lost_segment",
    "zero_window": "tcp.analysis.zero_window",
    "rtt": "tcp.analysis.ack_rtt",
}


def record_result(root, name, result):
    result["parent_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    result["child_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    (root / f"{name}.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)


def generate(root, frames, small_frames):
    root.mkdir(parents=True, exist_ok=True)
    captures = root / "captures"
    captures.mkdir(exist_ok=True)
    files = []
    points = []
    body = b"packetbreaker-benchmark".ljust(192, b"x")
    for hop, count in enumerate([frames] + [small_frames] * 4):
        path = captures / f"point-{hop}.pcap"
        offset = hop * 0.01

        def setup():
            records = []
            for flow in range(50):
                client = f"10.1.0.{flow + 1}"
                t = 1700000000 + flow * 0.00001
                for fw, delay, seq, ack, flags in (
                    (True, 0, 1000, 0, 2),
                    (False, 0.001, 9000, 1001, 18),
                    (True, 0.002, 1001, 9001, 16),
                ):
                    src, dst, sp, dp = (
                        (client, "203.0.113.20", 50000, 443) if fw else ("203.0.113.20", client, 443, 50000)
                    )
                    at = t + delay + (hop if fw else 4 - hop) * 0.0001 + offset
                    records.append(
                        (at, tcp_packet(src, dst, sp, dp, seq, ack, flags, b"", flow * 3 + flags, 64 - hop))
                    )
            return iter(sorted(records))

        def traffic(fw):
            pairs = count // 2
            for pair in range(pairs):
                flow = pair % 50
                r = pair // 50
                client = f"10.1.0.{flow + 1}"
                src, dst, sp, dp = (
                    (client, "203.0.113.20", 50000, 443) if fw else ("203.0.113.20", client, 443, 50000)
                )
                seq, ack = (1001 + r * 192, 9001 + r * 192) if fw else (9001 + r * 192, 1001 + (r + 1) * 192)
                ts = (
                    1700000000
                    + 0.01
                    + pair * 0.00002
                    + (0 if fw else 0.0005)
                    + (hop if fw else 4 - hop) * 0.0001
                    + offset
                )
                yield (
                    ts,
                    tcp_packet(
                        src, dst, sp, dp, seq, ack, 24, body, (pair * 2 + (0 if fw else 1)) % 65536, 64 - hop
                    ),
                )

        with path.open("wb", buffering=1024 * 1024) as f:
            f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            total = 0
            for ts, packet in heapq.merge(setup(), traffic(True), traffic(False), key=lambda x: x[0]):
                us = round(ts * 1e6)
                seconds, microseconds = divmod(us, 1000000)
                f.write(struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)))
                f.write(packet)
                total += 1
                if total % 1000000 == 0:
                    print(f"generated point {hop}: {total} frames", flush=True)
        files.append(str(path))
        points.append(dict(id=f"p{hop}", label=f"Point {hop}", device=f"Device {hop}", capture_id=path.name))
        print(f"generated {path.name}: {total} frames, {path.stat().st_size} bytes", flush=True)
    config = dict(
        files=files,
        topology=dict(
            points=points, forward=[f"p{i}" for i in range(5)], reverse=[], client_cidrs=["10.0.0.0/8"]
        ),
    )
    (root / "config.json").write_text(json.dumps(config, indent=2))


def production_ingest(root):
    config = json.loads((root / "config.json").read_text())
    project = Project(root / "project")
    timings = []
    start = time.monotonic()
    for point, path in zip(config["topology"]["points"], config["files"]):
        file_start = time.monotonic()
        last = 0

        def progress(**status):
            nonlocal last
            if status.get("frames", 0) >= last + 500000:
                last = status["frames"]
                print(f"{Path(path).name}: {last} indexed", flush=True)

        point["capture_id"] = ingest(project, path, progress=progress)
        elapsed = time.monotonic() - file_start
        with project.connect() as db:
            count = db.execute(
                "SELECT count(*) FROM packets WHERE capture_id=?", [point["capture_id"]]
            ).fetchone()[0]
        timings.append(
            dict(
                file=path,
                frames=count,
                input_bytes=Path(path).stat().st_size,
                seconds=elapsed,
                frames_per_second=count / elapsed,
                capture_id=point["capture_id"],
            )
        )
    with project.connect() as db:
        project.set(db, "topology", config["topology"])
    total = sum(t["frames"] for t in timings)
    elapsed = time.monotonic() - start
    record_result(
        root,
        "ingest",
        dict(
            frames=total,
            input_bytes=sum(t["input_bytes"] for t in timings),
            seconds=elapsed,
            frames_per_second=total / elapsed,
            files=timings,
        ),
    )


def production_analysis(root):
    project = Project(root / "project")
    with project.connect() as db:
        topology = project.get(db, "topology")
    start = time.monotonic()
    report = analyze(project, topology, progress=lambda **s: print(s["state"], flush=True))
    elapsed = time.monotonic() - start
    record_result(
        root,
        "analysis",
        dict(
            seconds=elapsed,
            verdict=report["verdict"],
            flow_count=report["flow_count"],
            findings=len(report["findings"]),
            segments=len(report["segments"]),
        ),
    )


def dpkt_core(path, cid):
    import dpkt

    with Path(path).open("rb") as f:
        reader = dpkt.pcap.Reader(f)
        if reader.datalink() != 1:
            raise ValueError("Experiment supports full Ethernet captures only; not a production fallback")
        for frame, (ts, wire) in enumerate(reader, 1):
            ip = dpkt.ethernet.Ethernet(wire).data
            if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
                raise ValueError(
                    "Experimental equality gate requires IPv4/TCP; unsupported inputs cannot be adopted"
                )
            tcp = ip.data
            src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            length = ip.len - ip.hl * 4 - tcp.off * 4
            prefix = tcp.data[:64].hex()
            mss = 0
            for kind, value in dpkt.tcp.parse_opts(tcp.opts):
                if kind == 2 and len(value) == 2:
                    mss = struct.unpack("!H", value)[0]
            identity = ["TCP", ip.id, tcp.seq, tcp.ack, tcp.flags, length, "", "", "", ""]
            p = dict(
                capture_id=cid,
                frame=frame,
                ts=float(ts),
                iface=0,
                src=src,
                dst=dst,
                sport=tcp.sport,
                dport=tcp.dport,
                proto="TCP",
                ipid=ip.id,
                seq=tcp.seq,
                ack=tcp.ack,
                flags=tcp.flags,
                length=length,
                wirelen=len(wire),
                caplen=len(wire),
                prefix=prefix or None,
                payload_hash=hashlib.sha256(tcp.data[:64]).hexdigest() if prefix else None,
                signature=hashlib.sha256(json.dumps(identity).encode()).hexdigest(),
                tuple_key=tuple_id("TCP", src, tcp.sport, dst, tcp.dport),
                reverse_tuple=tuple_id("TCP", dst, tcp.dport, src, tcp.sport),
                stream=None,
                ttl=ip.ttl,
                dscp=ip.tos >> 2,
                mss=mss,
                window=tcp.win,
                retrans=None,
                fast_retrans=None,
                spurious=None,
                out_of_order=None,
                acked_unseen=None,
                zero_window=None,
                rtt=None,
                unsupported="Possible offload super-frame; byte-range correlation is not available in Phase 1"
                if length > 9000
                else None,
                frame_hash=hashlib.md5(wire).hexdigest(),
                icmp_id=None,
                icmp_seq=None,
                icmp_type=None,
                dns_id=None,
                dns_response=False,
            )
            yield [p[k] for k in PACKET_COLUMNS]


def candidate_index(root):
    reference = json.loads((root / "ingest.json").read_text())["files"][0]
    path = reference["file"]
    cid = reference["capture_id"]
    project = Project(root / "dpkt-project")
    start = time.monotonic()
    count = 0
    with project.connect(allow_external=True) as db, tempfile.TemporaryDirectory(dir=root) as temp:
        db.execute("DELETE FROM packets")
        batch = []
        csv_path = Path(temp) / "core.csv"

        def flush():
            with csv_path.open("w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(PACKET_COLUMNS)
                writer.writerows(batch)
            db.execute(
                "INSERT INTO packets SELECT * FROM read_csv(?,header=true,columns=?,nullstr=?)",
                [str(csv_path), PACKET_COLUMNS, ""],
            )
            batch.clear()

        for row in dpkt_core(path, cid):
            batch.append(row)
            count += 1
            if len(batch) >= 50000:
                flush()
            if count % 1000000 == 0:
                print(f"dpkt: {count} indexed", flush=True)
        if batch:
            flush()
        core_seconds = time.monotonic() - start
        print(f"dpkt first pass finished in {core_seconds:.3f} seconds", flush=True)
        enrichment_start = time.monotonic()
        columns = {k: PACKET_COLUMNS[k] for k in ANALYSIS_FIELDS}
        db.execute("CREATE TEMP TABLE enrichment (" + ",".join(f"{k} {v}" for k, v in columns.items()) + ")")
        command = [
            find_tshark(),
            "-n",
            "-l",
            "-r",
            path,
            "-o",
            "tcp.relative_sequence_numbers:FALSE",
            "-o",
            "tcp.desegment_tcp_streams:FALSE",
            "-o",
            "ip.defragment:FALSE",
            "-o",
            "ipv6.defragment:FALSE",
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
        ]
        for field in ANALYSIS_FIELDS.values():
            command += ["-e", field]
        csv_path = Path(temp) / "analysis.csv"
        with (Path(temp) / "stderr").open("w+") as err:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, text=True)
            batch = []

            def flush_analysis():
                with csv_path.open("w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(columns)
                    writer.writerows(batch)
                db.execute(
                    "INSERT INTO enrichment SELECT * FROM read_csv(?,header=true,columns=?,nullstr=?)",
                    [str(csv_path), columns, ""],
                )
                batch.clear()

            try:
                for values in csv.reader(proc.stdout, delimiter="\t"):
                    p = dict(zip(ANALYSIS_FIELDS, values))
                    row = [
                        int(p["frame"]),
                        int(p["stream"]) if p["stream"] else -1,
                        bool(p["retrans"] or p["fast_retrans"]),
                        bool(p["fast_retrans"]),
                        bool(p["spurious"]),
                        bool(p["out_of_order"]),
                        bool(p["acked_unseen"]),
                        bool(p["zero_window"]),
                        float(p["rtt"]) if p["rtt"] else None,
                    ]
                    batch.append(row)
                    if len(batch) >= 50000:
                        flush_analysis()
                if batch:
                    flush_analysis()
                proc.wait()
                if proc.returncode:
                    err.seek(0)
                    raise RuntimeError(err.read(4000))
            finally:
                proc.stdout.close()
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
        db.execute(
            "UPDATE packets SET "
            + ",".join(f"{k}=e.{k}" for k in columns if k != "frame")
            + " FROM enrichment e WHERE packets.frame=e.frame"
        )
        enrichment_seconds = time.monotonic() - enrichment_start
    elapsed = time.monotonic() - start
    record_result(
        root,
        "dpkt",
        dict(
            frames=count,
            core_seconds=core_seconds,
            core_frames_per_second=count / core_seconds,
            tshark_enrichment_seconds=enrichment_seconds,
            hybrid_seconds=elapsed,
            hybrid_frames_per_second=count / elapsed,
            tshark_only_seconds=reference["seconds"],
            core_speedup=reference["seconds"] / core_seconds,
            hybrid_speedup=reference["seconds"] / elapsed,
        ),
    )


def verify(root):
    import duckdb

    cid = json.loads((root / "ingest.json").read_text())["files"][0]["capture_id"]
    with duckdb.connect(
        config={"memory_limit": "512MB", "threads": "2", "temp_directory": str(root / "verify-spill")}
    ) as db:
        for name, folder in (("reference", "project"), ("candidate", "dpkt-project")):
            literal = str(root / folder / "project.duckdb").replace("'", "''")
            db.execute(f"ATTACH '{literal}' AS {name} (READ_ONLY)")
        columns = list(PACKET_COLUMNS)
        mismatch = " OR ".join(f"a.{c} IS DISTINCT FROM b.{c}" for c in columns)
        counts = db.execute(
            f"""SELECT count(*),count(*) FILTER(WHERE {mismatch}) FROM
            (SELECT * FROM reference.packets WHERE capture_id=?) a FULL OUTER JOIN candidate.packets b
            ON a.capture_id=b.capture_id AND a.frame=b.frame""",
            [cid],
        ).fetchone()
        record_result(
            root,
            "equality",
            dict(rows=counts[0], mismatched_rows=counts[1], fields=columns, exactly_equal=counts[1] == 0),
        )
        if counts[1]:
            changed = db.execute(
                f"""SELECT {",".join(f"count(*) FILTER(WHERE a.{c} IS DISTINCT FROM b.{c}) AS {c}" for c in columns)}
                FROM (SELECT * FROM reference.packets WHERE capture_id=?) a FULL OUTER JOIN candidate.packets b
                ON a.capture_id=b.capture_id AND a.frame=b.frame""",
                [cid],
            ).fetchone()
            print({c: n for c, n in zip(columns, changed) if n}, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=["generate", "ingest", "analyze", "dpkt", "verify"])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frames", type=int, default=5000000)
    parser.add_argument("--small-frames", type=int, default=100000)
    args = parser.parse_args()
    root = args.directory.resolve()
    if args.stage == "generate":
        generate(root, args.frames, args.small_frames)
    else:
        {
            "ingest": production_ingest,
            "analyze": production_analysis,
            "dpkt": candidate_index,
            "verify": verify,
        }[args.stage](root)
