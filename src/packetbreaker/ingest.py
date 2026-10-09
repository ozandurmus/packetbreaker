import csv
from functools import lru_cache
import re
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import math
import uuid

from .metadata import metadata
from .timestamps import timestamp_reason
from .store import PACKET_COLUMNS
from .vendors import VENDOR_FIELDS, CHECKPOINT_FIELDS, F5_FIELDS, HTTP_FIELDS, decoded_vendor

FIELDS = """frame.number frame.time_epoch frame.interface_id ip.src ipv6.src ip.dst ipv6.dst
ip.proto ipv6.nxt ip.id ipv6.flow tcp.srcport udp.srcport tcp.dstport udp.dstport
 tcp.seq_raw tcp.ack_raw tcp.flags tcp.len udp.length ip.len ipv6.plen frame.len frame.cap_len
 tcp.payload udp.payload icmp.ident icmp.seq icmp.type icmpv6.type tcp.stream
 ip.ttl ipv6.hlim ip.dsfield.dscp tcp.options.mss_val tcp.window_size_value
 tcp.analysis.retransmission tcp.analysis.fast_retransmission tcp.analysis.spurious_retransmission
 tcp.analysis.out_of_order tcp.analysis.ack_lost_segment tcp.analysis.zero_window tcp.analysis.ack_rtt
 ip.flags.mf ip.frag_offset ipv6.fraghdr.offset ipv6.fraghdr.more frame.protocols frame.md5_hash dns.id dns.flags.response""".split()
PATH_FIELDS = """ipv6.tclass.dscp tcp.options tcp.options.wscale.shift tcp.options.sack_perm
 tcp.options.timestamp.tsval tcp.options.timestamp.tsecr ip.flags.df icmp.code icmp.mtu
 icmpv6.code icmpv6.mtu""".split()
FIELDS += PATH_FIELDS
BASE_FIELDS = FIELDS.copy()
FIELDS += VENDOR_FIELDS
CAPLEN_INDEX = list(PACKET_COLUMNS).index("caplen")
PARSER_VERSION = 9
csv.field_size_limit(16 * 1024 * 1024)


def find_tshark(override=None):
    candidates = (
        [override]
        if override
        else [
            shutil.which("tshark"),
            str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Wireshark/tshark.exe"),
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
        ]
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    raise ValueError("tshark was not found. Install Wireshark, or set the full tshark path in Settings.")


def number(value, default=0):
    if value in ("True", "False"):
        return int(value == "True")
    return int(value, 16) if value.startswith("0x") else int(value) if value else default


@lru_cache(maxsize=65536)
def tuple_id(proto, src, sport, dst, dport):
    return json.dumps([proto, src, sport, dst, dport], separators=(",", ":"))


@lru_cache(maxsize=65536)
def packet_signature(*identity):
    return hashlib.sha256(json.dumps(identity).encode()).hexdigest()


def parse_packet(values, capture_id, prefix_bytes, fields=FIELDS):
    d = dict(zip(fields, values))

    def g(k):
        return d.get(k, "").split(",")[0]

    src, dst = g("ip.src") or g("ipv6.src"), g("ip.dst") or g("ipv6.dst")
    proto = (
        "TCP"
        if g("tcp.srcport")
        else "UDP"
        if g("udp.srcport")
        else ("ICMP" if g("icmp.type") else "ICMPv6" if g("icmpv6.type") else "OTHER")
    )
    quoted = {"src": None, "dst": None, "sport": None, "dport": None, "seq": None}
    if (g("ip.proto") or g("ipv6.nxt")) in ("1", "58"):
        for name in ("src", "dst"):
            addresses = (d.get("ip." + name) or d.get("ipv6." + name) or "").split(",")
            quoted[name] = addresses[1] if len(addresses) > 1 else None
        quoted.update(
            sport=number(g("tcp.srcport"), None),
            dport=number(g("tcp.dstport"), None),
            seq=number(g("tcp.seq_raw"), None),
        )
    outer_proto = g("ip.proto") or g("ipv6.nxt")
    if outer_proto in ("1", "58"):
        proto = "ICMP" if outer_proto == "1" else "ICMPv6"
        # tshark also decodes the quoted transport inside ICMP errors. Keep it out of outer identity.
        for field in list(d):
            if field.startswith(("tcp.", "udp.")):
                d[field] = ""
    sport, dport = number(g("tcp.srcport") or g("udp.srcport")), number(g("tcp.dstport") or g("udp.dstport"))
    seq, ack, flags = number(g("tcp.seq_raw")), number(g("tcp.ack_raw")), number(g("tcp.flags"))
    length = (
        number(g("tcp.len"))
        if proto == "TCP"
        else max(0, number(g("udp.length")) - 8)
        if proto == "UDP"
        else number(g("ip.len") or g("ipv6.plen"))
    )
    payload = (g("tcp.payload") or g("udp.payload")).replace(":", "")[: prefix_bytes * 2]
    ipid = number(g("ip.id") or g("ipv6.flow"))
    identity = [
        proto,
        ipid,
        seq,
        ack,
        flags,
        length,
        g("icmp.ident"),
        g("icmp.seq"),
        g("icmp.type"),
        g("icmpv6.type"),
    ]
    wirelen, caplen = number(g("frame.len")), number(g("frame.cap_len"))
    unsupported = ""
    if proto not in ("TCP", "UDP", "ICMP", "ICMPv6"):
        unsupported = "Transport identity unsupported in Phase 1"
    if any(
        number(g(x)) for x in ("ip.flags.mf", "ip.frag_offset", "ipv6.fraghdr.offset", "ipv6.fraghdr.more")
    ):
        unsupported = "Fragmented packet; reassembly correlation is not available in Phase 1"
    if length > 9000 and proto != "TCP":
        unsupported = "Possible offload super-frame; byte-range correlation is not available in Phase 1"
    if proto == "UDP" and not payload:
        unsupported = "UDP payload unavailable; identity is insufficient"
    if {"vxlan", "geneve", "gre"} & set(g("frame.protocols").split(":")):
        unsupported = "Tunnel encapsulation; decapsulation selection is not available in Phase 1"
    p = dict(
        capture_id=capture_id,
        frame=number(g("frame.number")),
        ts=float(g("frame.time_epoch")),
        iface=number(g("frame.interface_id")),
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto=proto,
        ipid=ipid,
        seq=seq,
        ack=ack,
        flags=flags,
        length=length,
        wirelen=wirelen,
        caplen=caplen,
        prefix=payload,
        payload_hash=hashlib.sha256(bytes.fromhex(payload)).hexdigest() if payload else "",
        signature=packet_signature(*identity),
        tuple_key=tuple_id(proto, src, sport, dst, dport),
        reverse_tuple=tuple_id(proto, dst, dport, src, sport),
        stream=number(g("tcp.stream"), -1),
        ttl=number(g("ip.ttl") or g("ipv6.hlim")),
        dscp=number(g("ip.dsfield.dscp") or g("ipv6.tclass.dscp")),
        mss=number(g("tcp.options.mss_val")),
        window=number(g("tcp.window_size_value")),
        retrans=bool(g("tcp.analysis.retransmission") or g("tcp.analysis.fast_retransmission")),
        fast_retrans=bool(g("tcp.analysis.fast_retransmission")),
        spurious=bool(g("tcp.analysis.spurious_retransmission")),
        out_of_order=bool(g("tcp.analysis.out_of_order")),
        acked_unseen=bool(g("tcp.analysis.ack_lost_segment")),
        zero_window=bool(g("tcp.analysis.zero_window")),
        rtt=float(g("tcp.analysis.ack_rtt")) if g("tcp.analysis.ack_rtt") else None,
        unsupported=unsupported,
        frame_hash=g("frame.md5_hash"),
        icmp_id=number(g("icmp.ident"), None),
        icmp_seq=number(g("icmp.seq"), None),
        icmp_type=number(g("icmp.type") or g("icmpv6.type"), None),
        dns_id=number(g("dns.id"), None),
        dns_response=bool(number(g("dns.flags.response"))),
        vendor=decoded_vendor(d),
        path_fields=json.dumps(
            {
                "quoted": quoted,
                "window_scale": number(g("tcp.options.wscale.shift"), None),
                "tcp_options": g("tcp.options") if caplen == wirelen else None,
                "sack_permitted": bool(g("tcp.options.sack_perm")) if caplen == wirelen else None,
                "timestamp_value": number(g("tcp.options.timestamp.tsval"), None),
                "timestamp_echo": number(g("tcp.options.timestamp.tsecr"), None),
                "df": bool(number(g("ip.flags.df"))) if g("ip.src") else None,
                "icmp_type": number(g("icmp.type") or g("icmpv6.type"), None),
                "icmp_code": number(g("icmp.code") or g("icmpv6.code"), None),
                "icmp_mtu": number(g("icmp.mtu") or g("icmpv6.mtu"), None),
                "payload_sha256": hashlib.sha256(
                    bytes.fromhex((g("tcp.payload") or g("udp.payload")).replace(":", ""))
                ).hexdigest()
                if length and proto in ("TCP", "UDP")
                else None,
                "payload_complete": caplen == wirelen
                and len((g("tcp.payload") or g("udp.payload")).replace(":", "")) == length * 2,
            },
            separators=(",", ":"),
        ),
    )
    return [p[k] for k in PACKET_COLUMNS]


def ingest(
    project,
    path,
    tshark=None,
    prefix_bytes=64,
    cancel=None,
    progress=None,
    batch_size=50000,
    profile=None,
    checkpoint_uuid=False,
    source_metadata=None,
    f5_trailer=None,
):
    cancel = cancel or threading.Event()
    progress = progress or (lambda **kw: None)
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise ValueError("Capture file does not exist")
    if not 8 <= prefix_bytes <= 4096:
        raise ValueError("Payload prefix must be between 8 and 4096 bytes")
    stat = path.stat()
    with project.connect() as db:
        existing = db.execute(
            "SELECT id,identity,state,checkpoint,inventory FROM captures WHERE path=?", [str(path)]
        ).fetchone()
        if f5_trailer is None:
            f5_trailer = bool(existing and json.loads(existing[4]).get("f5_fields"))
        if source_metadata is None and existing:
            source_metadata = json.loads(existing[4]).get("source_metadata")
        identity = json.dumps(
            [
                str(path),
                stat.st_size,
                stat.st_mtime_ns,
                PARSER_VERSION,
                prefix_bytes,
                checkpoint_uuid,
                source_metadata,
                f5_trailer,
            ]
        )
        if existing and existing[1] == identity and existing[2] == "ready":
            progress(state="cached", frames=existing[3])
            return existing[0]
    binary = find_tshark(tshark)
    progress(state="scanning metadata", frames=0)
    info = metadata(path, cancel)
    info["source_metadata"] = source_metadata
    info["vendor_fields_version"] = 1
    info["f5_fields"] = bool(f5_trailer)
    if info.get("frame_limit") == 0:
        raise ValueError("Capture contains zero usable frames")
    timestamp_upper = time.time() + 86400
    cid = existing[0] if existing else uuid.uuid4().hex
    checkpoint = existing[3] if existing and existing[1] == identity and existing[2] != "stale" else 0
    with project.connect() as db:
        if not checkpoint:
            db.execute("DELETE FROM packets WHERE capture_id=?", [cid])
            db.execute("DELETE FROM excluded_frames WHERE capture_id=?", [cid])
        db.execute(
            "INSERT OR REPLACE INTO captures VALUES (?,?,?,?,?,?,?,?)",
            [cid, str(path), path.name, identity, "ingesting", checkpoint, json.dumps(info), None],
        )
        project.set(db, "report", None)
    cmd = [
        binary,
        "-n",
        "-l",
        "-r",
        str(path),
        "-o",
        "tcp.relative_sequence_numbers:FALSE",
        "-o",
        "frame.generate_md5_hash:TRUE",
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
        "occurrence=a",
    ]
    active_fields = BASE_FIELDS.copy()
    if f5_trailer:
        cmd += ["--enable-protocol", "f5ethtrailer"]
        active_fields += F5_FIELDS + HTTP_FIELDS
    if info["format"] == "snoop":
        active_fields += CHECKPOINT_FIELDS
        cmd += [
            "-o",
            "eth.interpret_as_fw1_monitor:TRUE",
            "-o",
            "fw1.iflist_with_chain:TRUE",
            "-o",
            f"fw1.with_uuid:{str(checkpoint_uuid).upper()}",
        ]
        info["checkpoint_uuid"] = checkpoint_uuid
    if info.get("frame_limit") is not None:
        cmd += ["-c", str(info["frame_limit"])]
    for field in active_fields:
        cmd += ["-e", field]
    metrics = dict(csv_write_cpu_s=0.0, duckdb_cpu_s=0.0, duckdb_wait_s=0.0, duckdb_hold_s=0.0)
    batch, last, seen = [], checkpoint, 0
    excluded = []
    with tempfile.TemporaryDirectory(prefix="ingest-", dir=project.path) as temp:
        batch_path = Path(temp) / "batch.csv"

        def flush():
            if not batch and not excluded:
                return
            cpu_start = time.thread_time() if profile is not None else 0
            with batch_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(PACKET_COLUMNS)
                writer.writerows(batch)
            if profile is not None:
                metrics["csv_write_cpu_s"] += time.thread_time() - cpu_start
            wait_start = time.monotonic() if profile is not None else 0
            cpu_start = time.thread_time() if profile is not None else 0
            with project.connect(allow_external=True) as db:
                hold_start = time.monotonic() if profile is not None else 0
                if profile is not None:
                    metrics["duckdb_wait_s"] += hold_start - wait_start
                db.execute("BEGIN")
                try:
                    if batch:
                        db.execute(
                            "INSERT INTO packets SELECT * FROM read_csv(?, header=true, columns=?, nullstr=?)",
                            [str(batch_path), PACKET_COLUMNS, ""],
                        )
                    if excluded:
                        db.executemany("INSERT INTO excluded_frames VALUES (?,?,?,?)", excluded)
                    db.execute("UPDATE captures SET checkpoint=? WHERE id=?", [last, cid])
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
            if profile is not None:
                metrics["duckdb_hold_s"] += time.monotonic() - hold_start
                metrics["duckdb_cpu_s"] += time.thread_time() - cpu_start
            batch.clear()
            excluded.clear()
            progress(state="ingesting", frames=last, bytes_total=stat.st_size, bytes_observed=seen)

        with open(Path(temp) / "stderr.log", "w+", encoding="utf-8") as errors:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=errors, text=True, encoding="utf-8", errors="replace"
            )
            done = threading.Event()

            def cancel_watcher():
                while not done.wait(0.1):
                    if cancel.is_set():
                        if proc.poll() is None:
                            proc.terminate()
                        return

            watcher = threading.Thread(target=cancel_watcher, daemon=True)
            watcher.start()
            parse_cpu_start = time.thread_time() if profile is not None else 0
            try:
                for values in csv.reader(proc.stdout, delimiter="\t"):
                    if cancel.is_set():
                        raise InterruptedError("Ingest cancelled; committed frames can be resumed")
                    if not values:
                        continue
                    frame = number(values[0])
                    if frame <= checkpoint:
                        continue
                    last = frame
                    try:
                        observed_ts = float(values[1])
                    except (ValueError, IndexError):
                        observed_ts = None
                    reason = timestamp_reason(observed_ts, timestamp_upper)
                    if reason:
                        excluded.append(
                            (
                                cid,
                                frame,
                                reason,
                                observed_ts
                                if observed_ts is not None and math.isfinite(observed_ts)
                                else None,
                            )
                        )
                        if len(excluded) >= batch_size:
                            flush()
                        continue
                    packet = parse_packet(values, cid, prefix_bytes, active_fields)
                    seen += packet[CAPLEN_INDEX]
                    batch.append(packet)
                    if len(batch) >= batch_size:
                        flush()
                proc.wait()
                if cancel.is_set():
                    raise InterruptedError("Ingest cancelled; committed frames can be resumed")
                errors.seek(0)
                stderr = errors.read(8000)
                tail_error = bool(
                    re.search(
                        r"cut short|short read|truncat(?:ed|ion).*(?:packet|record|block)", stderr, re.I
                    )
                )
                tail_error = tail_error or bool(
                    info.get("damaged_tail") and re.search(r"damaged|corrupt|block length", stderr, re.I)
                )
                if proc.returncode and not (last > 0 and tail_error):
                    raise ValueError("tshark failed: " + stderr)
                flush()
                if path.stat().st_size != stat.st_size or path.stat().st_mtime_ns != stat.st_mtime_ns:
                    raise ValueError("Capture changed during ingestion; attach it again to rebuild")
                with project.connect() as db:
                    r = db.execute(
                        """SELECT min(ts),max(ts),count(*),count(*) FILTER(WHERE caplen<wirelen),
                        count(*) FILTER(WHERE length>1500),count(*) FILTER(WHERE unsupported IS NOT NULL),
                        max(caplen),min(caplen) FILTER(WHERE caplen<wirelen),max(caplen) FILTER(WHERE caplen<wirelen)
                        FROM packets WHERE capture_id=?""",
                        [cid],
                    ).fetchone()
                    if not r[2]:
                        raise ValueError("Capture contains zero usable frames")
                    info["warnings"] = (
                        [f"File ends mid-packet; last partial record ignored; {r[2]} packets usable"]
                        if tail_error or info.get("damaged_tail")
                        else []
                    )
                    if info.get("zero_tail_bytes"):
                        info["warnings"].append(
                            f"Zero-filled tail ignored: {info['zero_tail_records']} records / {info['zero_tail_bytes'] / 1_000_000:.2f} MB (likely preallocated or copied while still being written)"
                        )
                    reasons = dict(
                        db.execute(
                            "SELECT reason,count(*) FROM excluded_frames WHERE capture_id=? GROUP BY reason",
                            [cid],
                        ).fetchall()
                    )
                    info["timestamp_excluded_counts"] = reasons
                    if reasons:
                        info["warnings"].append(
                            f"Excluded {sum(reasons.values())} packets with invalid capture timestamps: "
                            + ", ".join(f"{k}: {v}" for k, v in sorted(reasons.items()))
                        )
                    info["vendor_stages"] = [
                        dict(stage=stage, count=count)
                        for stage, count in db.execute(
                            "SELECT json_extract_string(vendor,'$.stage'),count(*) FROM packets WHERE capture_id=? AND vendor IS NOT NULL GROUP BY 1",
                            [cid],
                        ).fetchall()
                    ]
                    if source_metadata:
                        info["warnings"].append(
                            f"Fortinet text: {source_metadata.get('skipped_lines', 0)} skipped lines; {source_metadata.get('skipped_packets', 0)} incomplete/unsupported packets skipped"
                        )
                        if source_metadata.get("relative_timestamps"):
                            info["warnings"].append(
                                "Low clock confidence: relative text timestamps use a user-supplied start time"
                            )
                    info["timestamps_validated"] = True
                    info["records_read"] = last
                    info.update(
                        start=r[0],
                        end=r[1],
                        packet_count=r[2],
                        duration=(r[1] - r[0]) if r[0] is not None else 0,
                        truncated=r[3],
                        possible_offload=r[4],
                        unsupported=r[5],
                        observed_max_caplen=r[6],
                        truncated_caplen_min=r[7],
                        truncated_caplen_max=r[8],
                    )
                    db.execute(
                        "UPDATE captures SET state='ready',inventory=?,error=NULL WHERE id=?",
                        [json.dumps(info), cid],
                    )
                progress(state="ready", frames=last, usable_packets=r[2], warnings=info["warnings"])
                return cid
            except BaseException as exc:
                with project.connect() as db:
                    db.execute(
                        "UPDATE captures SET state=?,error=? WHERE id=?",
                        ["cancelled" if isinstance(exc, InterruptedError) else "error", str(exc), cid],
                    )
                raise
            finally:
                if profile is not None:
                    metrics["row_processing_cpu_s"] = (
                        time.thread_time()
                        - parse_cpu_start
                        - metrics["csv_write_cpu_s"]
                        - metrics["duckdb_cpu_s"]
                    )
                    profile[cid] = metrics
                done.set()
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                proc.stdout.close()
                watcher.join(timeout=1)
