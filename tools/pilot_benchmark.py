"""Six-file synthetic pilot corpus and same-input stages; run measurements with time -l."""

import argparse
import heapq
import json
from pathlib import Path
import struct
import sys
import time


def generate(root, frames=8300000, small=100000):
    from packetbreaker.synthetic import tcp_packet

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
    from capture_realism_fixtures import tunnel, fragments
    import socket

    root.mkdir(parents=True, exist_ok=True)
    captures = root / "captures"
    captures.mkdir(exist_ok=True)
    body = b"packetbreaker-pilot-scale".ljust(192, b"x")
    names = ["FW1 ingress", "FW1 egress", "FW2 ingress", "FW2 egress", "Switch", "Server"]
    points = []
    files = []
    counts = []

    def sum16(data):
        return sum(struct.unpack("!" + str(len(data) // 2) + "H", data))

    def fold(value):
        while value >> 16:
            value = (value & 65535) + (value >> 16)
        return (~value) & 65535

    for hop, count in enumerate([frames] + [small] * 5):
        path = captures / f"point-{hop}.pcap"
        offset = hop * 0.01
        templates = {}
        for flow in range(50):
            for fw in (True, False):
                client = f"10.1.0.{flow + 1}"
                src, dst = (client, "203.0.113.20") if fw else ("203.0.113.20", client)
                sp, dp = (50000, 443) if fw else (443, 50000)
                a, b = socket.inet_aton(src), socket.inet_aton(dst)
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 232, 0, 0x4000, 64 - hop, 6, 0, a, b)
                tcp = struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 80, 24, 65535, 0, 0)
                base = sum16(a + b + struct.pack("!BBH", 0, 6, 212) + tcp + body)
                templates[(flow, fw)] = (ip, tcp, base, sum16(ip))

        def traffic(fw):
            for pair in range(count // 2):
                flow = pair % 50
                r = pair // 50
                seq, ack = (1001 + r * 192, 9001 + r * 192) if fw else (9001 + r * 192, 1001 + (r + 1) * 192)
                pid = (pair * 2 + int(not fw)) % 65536
                ip, tcp, base, ipsum = templates[(flow, fw)]
                ih = (
                    ip[:4]
                    + struct.pack("!H", pid)
                    + ip[6:10]
                    + struct.pack("!H", fold(ipsum + pid))
                    + ip[12:]
                )
                th = (
                    tcp[:4]
                    + struct.pack("!II", seq, ack)
                    + tcp[12:16]
                    + struct.pack(
                        "!H", fold(base + (seq >> 16) + (seq & 65535) + (ack >> 16) + (ack & 65535))
                    )
                    + tcp[18:]
                )
                packet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ih + th + body
                jitter = ((pair * 17) % 11 - 5) * 0.0000001
                at = (
                    1700000000
                    + 0.01
                    + pair * 0.00002
                    + (0 if fw else 0.0005)
                    + (hop if fw else 5 - hop) * 0.0001
                    + offset
                    + jitter
                )
                yield at, packet

        setup = []
        for flow in range(50):
            client = f"10.1.0.{flow + 1}"
            for fw, delay, seq, ack, flags in [
                (True, 0, 1000, 0, 2),
                (False, 0.001, 9000, 1001, 18),
                (True, 0.002, 1001, 9001, 16),
            ]:
                src, dst, sp, dp = (
                    (client, "203.0.113.20", 50000, 443) if fw else ("203.0.113.20", client, 443, 50000)
                )
                setup.append(
                    (
                        1700000000 + flow * 0.00001 + delay + (hop if fw else 5 - hop) * 0.0001 + offset,
                        tcp_packet(src, dst, sp, dp, seq, ack, flags, b"", flow * 3 + flags, 64 - hop),
                    )
                )
        physical = 0
        with path.open("wb", buffering=1024 * 1024) as out:
            out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for at, packet in heapq.merge(
                iter(sorted(setup)), traffic(True), traffic(False), key=lambda r: r[0]
            ):
                parts = (
                    [tunnel(packet, "erspan2")]
                    if hop == 2
                    else fragments(packet, fragment_id=int.from_bytes(packet[18:20], "big"))
                    if hop == 4 and len(packet) > 54
                    else [packet]
                )
                for index, part in enumerate(parts):
                    us = round((at + index * 0.000001) * 1e6)
                    sec, micro = divmod(us, 1000000)
                    out.write(struct.pack("<IIII", sec, micro, len(part), len(part)))
                    out.write(part)
                    physical += 1
                if physical % 1000000 == 0:
                    print(f"{path.name}: {physical}", flush=True)
        cid = path.name
        files.append(str(path.resolve()))
        counts.append(dict(file=path.name, frames=physical, bytes=path.stat().st_size))
        points.append(
            dict(
                id=f"p{hop}",
                label=names[hop],
                device="FW1" if hop < 2 else "FW2" if hop < 4 else names[hop],
                side="ingress" if hop in (0, 2) else "egress" if hop in (1, 3) else "both",
                capture_id=cid,
                x=hop * 220,
                y=100,
            )
        )
        print(counts[-1], flush=True)
    (root / "config.json").write_text(
        json.dumps(
            dict(
                files=files,
                counts=counts,
                logical_frames=[frames + 150] + [small + 150] * 5,
                topology=dict(points=points, forward=[p["id"] for p in points], client_cidrs=["10.0.0.0/8"]),
            ),
            indent=2,
        )
    )


def run(stage, source, output):
    from packetbreaker.store import Project
    from packetbreaker.batch_ingest import ingest_many
    from packetbreaker.analysis import analyze

    config = json.loads((source / "config.json").read_text())
    output.mkdir(parents=True, exist_ok=True)
    if stage == "ingest" and (output / "project/project.duckdb").exists():
        raise ValueError("Fresh output required")
    start = time.perf_counter()
    if stage != "cached":
        project = Project(output / "project")
    if stage == "ingest":
        ids = ingest_many(project, config["files"], workers=1)
        for p, cid in zip(config["topology"]["points"], ids):
            p["capture_id"] = cid
        with project.connect() as db:
            project.set(db, "topology", config["topology"])
        result = dict(
            frames=sum(c["inventory"]["packet_count"] for c in project.inventory()),
            input_bytes=sum(c["bytes"] for c in config["counts"]),
        )
    elif stage in ("analyze", "control"):
        with project.connect() as db:
            # Each measurement includes fresh secondary tshark indexes, even after a failed trial.
            existing = {r[0] for r in db.execute("SHOW TABLES").fetchall()}
            for table in (
                "layer_cache",
                "layer_packets",
                "app_protocol_cache",
                "app_protocol",
                "tcp_point_analysis",
            ):
                if table in existing:
                    db.execute("DELETE FROM " + table)
            topology = project.get(db, "topology")
        if stage == "control":
            selected = {"p0", "p1", "p3", "p5"}
            topology["points"] = [p for p in topology["points"] if p["id"] in selected]
            topology["forward"] = [p for p in topology["forward"] if p in selected]
            topology["reverse"] = []

        def progress(**values):
            if "state" in values:
                print(f"{time.perf_counter() - start:.2f}s {values['state']}", flush=True)

        report = analyze(project, topology, progress=progress)
        result = dict(
            flows=report["flow_count"],
            findings=report["finding_count"],
            classes=sorted({f["type"] for f in report["findings"]}),
            matchable=[s.get("eligible_ratio") for s in report["segments"]],
            common=report["window"],
        )
    else:
        import unittest.mock

        with unittest.mock.patch("subprocess.Popen", side_effect=AssertionError("cached open re-parsed")):
            project = Project(output / "project")
            project.inventory()
            with project.connect() as db:
                report = project.get(db, "report")
        result = dict(cached=bool(report), captures=len(project.inventory()))
    result.update(stage=stage, seconds=time.perf_counter() - start)
    if stage == "ingest":
        result["frames_per_second"] = result["frames"] / result["seconds"]
    (output / (stage + ".json")).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("stage", choices=["generate", "ingest", "analyze", "control", "cached"])
    p.add_argument("source", type=Path)
    p.add_argument("output", type=Path, nargs="?")
    p.add_argument("--frames", type=int, default=8300000)
    p.add_argument("--small", type=int, default=100000)
    a = p.parse_args()
    generate(a.source, a.frames, a.small) if a.stage == "generate" else run(a.stage, a.source, a.output)
