"""Point-scoped tshark fields; no payload dissection or whole-capture Python rows."""

import csv
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .application_index import can_decode_source, read_filter, running
from .ingest import find_tshark
from .store import rows

FIELDS = """frame.number frame.time_epoch ip.src ipv6.src ip.dst ipv6.dst udp.srcport udp.dstport frame.protocols
ntp.flags.mode ntp.org ntp.xmt snmp.request_id snmp.msgID snmp.data radius.id radius.code radius.authenticator syslog.level""".split()
FIELDS += """tcp.srcport tcp.dstport tcp.seq_raw rtp.ssrc rtp.seq rtp.timestamp rtp.p_type rtp.version
sip.Call-ID sip.CSeq.seq sip.CSeq.method sip.Method sip.Status-Code sip.Contact sip.Via sip.Via.branch
sdp.connection_info.address sdp.media.port sdp.media.media sdp.media.format sdp.media_attr""".split()
FIELDS += ["snmp.version", "snmp.community"]
VERSION = 4


def index_udp(project, db, topology, cancel=None, progress=None, *, batch_headers=True):
    db.execute(
        "CREATE TABLE IF NOT EXISTS udp_decode_cache(point VARCHAR PRIMARY KEY,identity VARCHAR,reason VARCHAR)"
    )
    field_columns = ",".join(chr(34) + f + chr(34) for f in FIELDS)
    schema = ",".join('"' + f + '" VARCHAR' for f in FIELDS)
    db.execute(f"CREATE TABLE IF NOT EXISTS udp_decoded(point VARCHAR,frame BIGINT,{schema})")
    existing = {row[0] for row in db.execute("DESCRIBE udp_decoded").fetchall()}
    for field in FIELDS:
        if field not in existing:
            db.execute(f'ALTER TABLE udp_decoded ADD COLUMN "{field}" VARCHAR')
    if not db.execute(
        "SELECT 1 FROM obs WHERE proto='UDP' AND dns_id IS NULL OR proto='TCP' AND (sport=5060 OR dport=5060 OR json_extract_string(path_fields,'$.sip_probe')='1') LIMIT 1"
    ).fetchone():
        db.execute("DELETE FROM udp_decoded")
        db.execute("DELETE FROM udp_decode_cache")
        return []
    statuses = []
    file_headers = {}
    binary = None
    for point in topology.points:
        if not db.execute(
            "SELECT 1 FROM obs WHERE point=? AND (proto='UDP' AND dns_id IS NULL OR proto='TCP' AND (sport=5060 OR dport=5060 OR json_extract_string(path_fields,'$.sip_probe')='1')) LIMIT 1",
            [point.id],
        ).fetchone():
            db.execute("DELETE FROM udp_decoded WHERE point=?", [point.id])
            continue
        capture = rows(db, "SELECT path,identity,inventory FROM captures WHERE id=?", [point.capture_id])[0]
        identity = json.dumps(
            [
                VERSION,
                batch_headers,
                capture["identity"],
                topology.rtp_port_ranges,
                point.model_dump(
                    exclude={"x", "y", "label", "device", "kind", "translation", "payload_transform"}
                ),
            ],
            sort_keys=True,
        )
        cached = db.execute(
            "SELECT identity,reason FROM udp_decode_cache WHERE point=?", [point.id]
        ).fetchone()
        if cached and cached[0] == identity:
            statuses.append(dict(point=point.id, reason=cached[1], cached=True))
            continue
        db.execute("DELETE FROM udp_decoded WHERE point=?", [point.id])
        reason = None
        try:
            source = Path(capture["path"])
            stat = source.stat()
            original = json.loads(capture["identity"])
            if [str(source), stat.st_size, stat.st_mtime_ns] != original[:3]:
                raise ValueError("Capture changed; reattach before UDP analysis")
            if (
                point.vendor == "f5"
                or db.execute(
                    "SELECT 1 FROM obs WHERE point=? AND (json_exists(path_fields,'$.tunnel') OR json_exists(path_fields,'$.fragment')) LIMIT 1",
                    [point.id],
                ).fetchone()
            ):
                raise ValueError("UDP protocol index unknown for this vendor/tunnel/fragment view")
            binary = binary or find_tshark(project.get(db, "preferences", {}).get("tshark"))
            inv = json.loads(capture["inventory"])
            options = []
            if inv.get("format") == "snoop":
                options = [
                    "-o",
                    "eth.interpret_as_fw1_monitor:TRUE",
                    "-o",
                    "fw1.iflist_with_chain:TRUE",
                    "-o",
                    f"fw1.with_uuid:{str(inv.get('checkpoint_uuid', False)).upper()}",
                ]
            env = os.environ.copy()
            env.pop("SSLKEYLOGFILE", None)
            if progress:
                progress(state="reading UDP protocol fields", point=point.id)
            count = db.execute("SELECT count(*) FROM obs WHERE point=?", [point.id]).fetchone()[0]
            # Explicit UDP decode-as makes these header fields packet-local. TCP SIP still isolates before reassembly.
            header_only = bool(
                batch_headers
                and topology.rtp_port_ranges
                and point.vendor == "none"
                and inv.get("format") != "snoop"
                and sum(p.capture_id == point.capture_id for p in topology.points) > 1
                and not db.execute(
                    "SELECT 1 FROM obs WHERE capture_id=? AND proto='TCP' AND (sport=5060 OR dport=5060 OR json_extract_string(path_fields,'$.sip_probe')='1') LIMIT 1",
                    [point.capture_id],
                ).fetchone()
            )
            header_table = file_headers.get(point.capture_id) if header_only else None
            with (
                tempfile.TemporaryDirectory(prefix="udp-point-") as directory,
                tempfile.TemporaryFile(mode="w+", encoding="utf-8") as errors,
            ):
                selected = source
                direct = header_only or can_decode_source(point, inv, count)
                if not direct:
                    selected = Path(directory) / "point.pcapng"
                    cmd = [
                        binary,
                        "-n",
                        "-r",
                        str(source),
                        "-Y",
                        read_filter(point, inv),
                        "-w",
                        str(selected),
                        "-F",
                        "pcapng",
                        *options,
                    ]
                    if inv.get("frame_limit") is not None:
                        cmd += ["-c", str(inv["frame_limit"])]
                    with running(cmd, errors, env, cancel, subprocess.DEVNULL) as proc:
                        code = proc.wait()
                    if code:
                        raise ValueError("Point isolation failed")
                db.execute(
                    "CREATE OR REPLACE TEMP TABLE udp_frame_map AS SELECT *,row_number() OVER(ORDER BY frame) AS ordinal FROM obs WHERE point=?",
                    [point.id],
                )
                if not header_table:
                    output = Path(directory) / "fields.csv"
                    cmd = [
                        binary,
                        "-n",
                        "-2",
                        "-r",
                        str(selected),
                        "-Y",
                        ("udp" if header_only else "(udp || sip)")
                        + " && !dns && !(gre || vxlan || geneve || icmp || icmpv6)",
                        "-T",
                        "fields",
                        "-E",
                        "header=y",
                        "-E",
                        "separator=,",
                        "-E",
                        "quote=d",
                        "-E",
                        "occurrence=a",
                        *options,
                    ]
                    if direct and inv.get("frame_limit") is not None:
                        cmd += ["-c", str(inv["frame_limit"])]
                    for lo, hi in topology.rtp_port_ranges:
                        cmd += ["-d", f"udp.port=={lo}-{hi},rtp"]
                    for field in FIELDS:
                        cmd += ["-e", field]
                    with output.open("wb") as stream, running(cmd, errors, env, cancel, stream) as proc:
                        code = proc.wait()
                    if cancel and cancel.is_set():
                        raise InterruptedError("UDP indexing cancelled")
                    if code:
                        errors.seek(0)
                        raise ValueError("UDP decode failed: " + errors.read(1000))
                    db.execute(f"CREATE OR REPLACE TEMP TABLE udp_raw({schema})")
                    shape = json.dumps([{field: "VARCHAR" for field in FIELDS}])
                    buffer = []

                    def flush():
                        if buffer:
                            db.execute(
                                "INSERT INTO udp_raw SELECT r.* FROM(SELECT unnest(from_json(?,?)) r)",
                                [json.dumps(buffer), shape],
                            )
                            buffer.clear()

                    def load_fields():
                        db.execute("DELETE FROM udp_raw")
                        with output.open(encoding="utf-8", newline="") as stream:
                            reader = csv.DictReader(stream)
                            if reader.fieldnames != FIELDS:
                                raise ValueError("UDP decoder field schema differs")
                            for record in reader:
                                buffer.append({k: v or None for k, v in record.items()})
                                if len(buffer) >= 4096:
                                    flush()
                            flush()

                    load_fields()
                    # SDP is authoritative port negotiation; never infer RTP from arbitrary UDP bytes.
                    learned = db.execute(
                        """SELECT DISTINCT try_cast(port AS INTEGER) FROM udp_raw,unnest(string_split("sdp.media.port",',')) p(port) WHERE try_cast(port AS INTEGER) BETWEEN 1 AND 65535 LIMIT 257"""
                    ).fetchall()
                    if len(learned) > 256:
                        raise ValueError("Too many SDP media ports; narrow the selected window/capture")
                    if learned and not topology.rtp_port_ranges:
                        for (port,) in learned:
                            cmd += ["-d", f"udp.port=={port},rtp"]
                        with output.open("wb") as stream, running(cmd, errors, env, cancel, stream) as proc:
                            code = proc.wait()
                        if code:
                            raise ValueError("SDP-directed media decode failed")
                        load_fields()
                    if header_only:
                        header_table = f"udp_headers_{len(file_headers)}"
                        db.execute(f"CREATE OR REPLACE TEMP TABLE {header_table} AS SELECT * FROM udp_raw")
                        file_headers[point.capture_id] = header_table
                if header_only:
                    db.execute(f"""CREATE OR REPLACE TEMP TABLE udp_raw AS SELECT r.* FROM {header_table} r
                        JOIN udp_frame_map o ON try_cast(r."frame.number" AS BIGINT)=o.frame""")
                join = 'r."frame.number"::BIGINT=o.frame' if direct else 'r."frame.number"::BIGINT=o.ordinal'
                valid = """coalesce(r."ip.src",r."ipv6.src")=o.src AND coalesce(r."ip.dst",r."ipv6.dst")=o.dst
                    AND try_cast(coalesce(r."udp.srcport",r."tcp.srcport") AS INTEGER)=o.sport AND try_cast(coalesce(r."udp.dstport",r."tcp.dstport") AS INTEGER)=o.dport
                    AND abs(try_cast(r."frame.time_epoch" AS DOUBLE)-o.ts)<0.000002"""
                wrong = db.execute(
                    f"SELECT count(*) FROM udp_raw r LEFT JOIN udp_frame_map o ON {join} WHERE o.frame IS NULL OR NOT coalesce({valid},false)"
                ).fetchone()[0]
                if wrong:
                    raise ValueError("Decoded UDP fields do not uniquely map to original frames")
                db.execute(
                    f"INSERT INTO udp_decoded(point,frame,{field_columns}) SELECT o.point,o.frame,r.* FROM udp_raw r JOIN udp_frame_map o ON {join}"
                )
        except (ValueError, OSError) as exc:
            reason = str(exc)
            db.execute("DELETE FROM udp_decoded WHERE point=?", [point.id])
        db.execute("INSERT OR REPLACE INTO udp_decode_cache VALUES (?,?,?)", [point.id, identity, reason])
        statuses.append(dict(point=point.id, reason=reason, cached=False))
    return statuses


def protocol_evidence(db, predicate, params, limit=128):
    """Add tshark header identity to portable filters, in one bounded metadata lookup."""
    from .evidence import evidence

    refs = evidence(db, predicate, params, limit)
    if not refs:
        return refs
    selected = [dict(point=r["point"], frame=r["frame"]) for r in refs]
    decoded = rows(
        db,
        """SELECT d.* FROM udp_decoded d JOIN(SELECT unnest(from_json(?, '[{"point":"VARCHAR","frame":"BIGINT"}]')) r) s
        ON d.point=s.r.point AND d.frame=s.r.frame""",
        [json.dumps(selected)],
    )
    lookup = {(d["point"], d["frame"]): d for d in decoded}
    numeric = (
        "rtp.ssrc",
        "rtp.seq",
        "rtp.timestamp",
        "snmp.request_id",
        "radius.id",
        "radius.code",
        "ntp.flags.mode",
        "sip.CSeq.seq",
    )
    for ref in refs:
        data = lookup.get((ref["point"], ref["frame"]), {})
        if not ref.get("content_filter"):
            continue
        identity = {}
        for field in numeric:
            value = data.get(field)
            if value is None:
                continue
            try:
                value = int(value, 16) if value.startswith("0x") else int(value)
            except ValueError:
                continue
            ref["content_filter"] += f" && {field} == {value}"
            identity[field] = value
        value = data.get("sip.Call-ID")
        if value and "," not in value:
            ref["content_filter"] += " && sip.Call-ID == " + json.dumps(value)
            identity["sip.Call-ID"] = value
        if identity:
            ref["protocol_identity"] = identity
    return refs


def frame_evidence(db, pairs):
    """Fetch bounded button references together rather than one SQL query per button."""
    pairs = list(dict.fromkeys((point, frame) for point, frame in pairs if frame is not None))
    result = {}
    for start in range(0, len(pairs), 512):
        wanted = [dict(point=p, frame=f) for p, f in pairs[start : start + 512]]
        refs = protocol_evidence(
            db,
            'EXISTS(SELECT 1 FROM(SELECT unnest(from_json(?, \'[{"point":"VARCHAR","frame":"BIGINT"}]\')) r) s WHERE s.r.point=o.point AND s.r.frame=o.frame)',
            [json.dumps(wanted)],
            512,
        )
        result.update({(r["point"], r["frame"]): r for r in refs})
    return result
