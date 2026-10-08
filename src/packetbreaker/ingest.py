import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import uuid

from .metadata import metadata
from .store import PACKET_COLUMNS

FIELDS = """frame.number frame.time_epoch frame.interface_id ip.src ipv6.src ip.dst ipv6.dst
ip.proto ipv6.nxt ip.id ipv6.flow tcp.srcport udp.srcport tcp.dstport udp.dstport
 tcp.seq_raw tcp.ack_raw tcp.flags tcp.len udp.length ip.len ipv6.plen frame.len frame.cap_len
 tcp.payload udp.payload icmp.ident icmp.seq icmp.type icmpv6.type tcp.stream
 ip.ttl ipv6.hlim ip.dsfield.dscp tcp.options.mss_val tcp.window_size_value
 tcp.analysis.retransmission tcp.analysis.fast_retransmission tcp.analysis.spurious_retransmission
 tcp.analysis.out_of_order tcp.analysis.ack_lost_segment tcp.analysis.zero_window tcp.analysis.ack_rtt
 ip.flags.mf ip.frag_offset ipv6.fraghdr.offset ipv6.fraghdr.more frame.protocols frame.md5_hash dns.id dns.flags.response""".split()
PARSER_VERSION = 4
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


def tuple_id(proto, src, sport, dst, dport):
    return json.dumps([proto, src, sport, dst, dport], separators=(",", ":"))


def parse_packet(values, capture_id, prefix_bytes):
    d = dict(zip(FIELDS, values))

    def g(k):
        return d.get(k, "")

    src, dst = g("ip.src") or g("ipv6.src"), g("ip.dst") or g("ipv6.dst")
    proto = (
        "TCP"
        if g("tcp.srcport")
        else "UDP"
        if g("udp.srcport")
        else ("ICMP" if g("icmp.type") else "ICMPv6" if g("icmpv6.type") else "OTHER")
    )
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
    if proto not in ("TCP", "UDP", "ICMP"):
        unsupported = "Transport identity unsupported in Phase 1"
    if any(
        number(g(x)) for x in ("ip.flags.mf", "ip.frag_offset", "ipv6.fraghdr.offset", "ipv6.fraghdr.more")
    ):
        unsupported = "Fragmented packet; reassembly correlation is not available in Phase 1"
    if length > 9000:
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
        signature=hashlib.sha256(json.dumps(identity).encode()).hexdigest(),
        tuple_key=tuple_id(proto, src, sport, dst, dport),
        reverse_tuple=tuple_id(proto, dst, dport, src, sport),
        stream=number(g("tcp.stream"), -1),
        ttl=number(g("ip.ttl") or g("ipv6.hlim")),
        dscp=number(g("ip.dsfield.dscp")),
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
        icmp_type=number(g("icmp.type"), None),
        dns_id=number(g("dns.id"), None),
        dns_response=bool(number(g("dns.flags.response"))),
    )
    return [p[k] for k in PACKET_COLUMNS]


def ingest(project, path, tshark=None, prefix_bytes=64, cancel=None, progress=None, batch_size=5000):
    cancel = cancel or threading.Event()
    progress = progress or (lambda **kw: None)
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise ValueError("Capture file does not exist")
    if not 8 <= prefix_bytes <= 4096:
        raise ValueError("Payload prefix must be between 8 and 4096 bytes")
    stat = path.stat()
    identity = json.dumps([str(path), stat.st_size, stat.st_mtime_ns, PARSER_VERSION, prefix_bytes])
    with project.connect() as db:
        existing = db.execute(
            "SELECT id,identity,state,checkpoint FROM captures WHERE path=?", [str(path)]
        ).fetchone()
        if existing and existing[1] == identity and existing[2] == "ready":
            progress(state="cached", frames=existing[3])
            return existing[0]
    binary = find_tshark(tshark)
    info = metadata(path, cancel)
    cid = existing[0] if existing else uuid.uuid4().hex
    checkpoint = existing[3] if existing and existing[1] == identity else 0
    with project.connect() as db:
        if not checkpoint:
            db.execute("DELETE FROM packets WHERE capture_id=?", [cid])
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
        "occurrence=f",
    ]
    for field in FIELDS:
        cmd += ["-e", field]
    batch, last, seen = [], checkpoint, 0
    with tempfile.TemporaryDirectory(prefix="ingest-", dir=project.path) as temp:
        batch_path = Path(temp) / "batch.csv"

        def flush():
            if not batch:
                return
            with batch_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(PACKET_COLUMNS)
                writer.writerows(batch)
            with project.connect(allow_external=True) as db:
                db.execute("BEGIN")
                try:
                    db.execute(
                        "INSERT INTO packets SELECT * FROM read_csv(?, header=true, columns=?, nullstr=?)",
                        [str(batch_path), PACKET_COLUMNS, ""],
                    )
                    db.execute("UPDATE captures SET checkpoint=? WHERE id=?", [last, cid])
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
            batch.clear()
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
            try:
                for values in csv.reader(proc.stdout, delimiter="\t"):
                    if cancel.is_set():
                        raise InterruptedError("Ingest cancelled; committed frames can be resumed")
                    if not values:
                        continue
                    frame = number(values[0])
                    if frame <= checkpoint:
                        continue
                    packet = parse_packet(values, cid, prefix_bytes)
                    last = frame
                    seen += packet[list(PACKET_COLUMNS).index("caplen")]
                    batch.append(packet)
                    if len(batch) >= batch_size:
                        flush()
                proc.wait()
                if cancel.is_set():
                    raise InterruptedError("Ingest cancelled; committed frames can be resumed")
                if proc.returncode:
                    errors.seek(0)
                    raise ValueError("tshark failed: " + errors.read(4000))
                flush()
                if path.stat().st_size != stat.st_size or path.stat().st_mtime_ns != stat.st_mtime_ns:
                    raise ValueError("Capture changed during ingestion; attach it again to rebuild")
                with project.connect() as db:
                    r = db.execute(
                        """SELECT min(ts),max(ts),count(*),count(*) FILTER(WHERE caplen<wirelen),
                        count(*) FILTER(WHERE length>1500),count(*) FILTER(WHERE unsupported IS NOT NULL)
                        FROM packets WHERE capture_id=?""",
                        [cid],
                    ).fetchone()
                    info.update(
                        start=r[0],
                        end=r[1],
                        packet_count=r[2],
                        duration=(r[1] - r[0]) if r[0] is not None else 0,
                        truncated=r[3],
                        possible_offload=r[4],
                        unsupported=r[5],
                    )
                    db.execute(
                        "UPDATE captures SET state='ready',inventory=?,error=NULL WHERE id=?",
                        [json.dumps(info), cid],
                    )
                progress(state="ready", frames=last)
                return cid
            except BaseException as exc:
                with project.connect() as db:
                    db.execute(
                        "UPDATE captures SET state=?,error=? WHERE id=?",
                        ["cancelled" if isinstance(exc, InterruptedError) else "error", str(exc), cid],
                    )
                raise
            finally:
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
