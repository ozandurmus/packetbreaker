"""Bounded, cached tshark application-event index. This module does not dissect bytes."""

from contextlib import contextmanager
from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

from .ingest import find_tshark
from .metadata import metadata as capture_metadata
from .store import rows

VERSION = 7
MAX_EVENTS = 10000
MAX_JSON = 4 * 1024 * 1024


def values(tree, name):
    result = []
    if isinstance(tree, dict):
        for key, value in tree.items():
            if key == name:
                result.extend(value if isinstance(value, list) else [value])
            else:
                result.extend(values(value, name))
    elif isinstance(tree, list):
        for child in tree:
            result.extend(values(child, name))
    return result


def first(tree, name, default=None):
    found = values(tree, name)
    return found[0] if found else default


def integer(value, default=0):
    try:
        return int(str(value), 0) if str(value).startswith("0x") else int(value)
    except (TypeError, ValueError):
        return default


def ip_list(value):
    result = []
    for token in (value or "").split(","):
        try:
            result.append(str(ipaddress.ip_address(token.strip())))
        except ValueError:
            continue
    return result


def certificate_names(tree, name):
    subtrees = values(tree, name + "_tree")
    attributes = []

    def walk(value):
        if isinstance(value, dict):
            if "x509if.type" in value or "x509if.oid" in value:
                text = (
                    values(value, "x509sat.uTF8String")
                    + values(value, "x509sat.printableString")
                    + values(value, "x509sat.iA5String")
                )
                attributes.extend(f"{value.get('x509if.oid') or value.get('x509if.type')}={v}" for v in text)
            else:
                for child in value.values():
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    for subtree in subtrees:
        walk(subtree)
    return ", ".join(attributes) or None


def certificates(tree):
    found = []

    def walk(node):
        if isinstance(node, dict):
            if "tls.handshake.certificate" in node:
                encoded = node["tls.handshake.certificate"]
                encoded = encoded if isinstance(encoded, list) else [encoded]
                sub = node.get("tls.handshake.certificate_tree", {})
                sub = sub if isinstance(sub, list) else [sub]
                for i, der in enumerate(encoded):
                    info = sub[i] if i < len(sub) else {}
                    found.append(
                        dict(
                            fingerprint=hashlib.sha256(bytes.fromhex(der.replace(":", ""))).hexdigest(),
                            subject=certificate_names(info, "x509af.subject"),
                            issuer=certificate_names(info, "x509af.issuer"),
                        )
                    )
            else:
                for child in node.values():
                    walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(tree)
    return found


def event_rows(packet):
    layers = packet["_source"]["layers"]
    if "tcp" not in layers:
        return []
    frame = integer(first(layers.get("frame", {}), "frame.number"))
    parts = [integer(v) for v in values(layers, "tcp.segment")] or [frame]
    tcp = {}

    def collect(node):
        if isinstance(node, dict):
            for key, value in node.items():
                tcp.setdefault(key, []).extend(value if isinstance(value, list) else [value])
                collect(value)
        elif isinstance(node, list):
            for value in node:
                collect(value)

    # Visit tshark's TCP tree once; dense flight/ACK state needs many of its fields.
    collect(layers.get("tcp", {}))
    stamp = first(layers.get("frame", {}), "frame.time_epoch")
    observed = (
        float(stamp) if "T" not in stamp else datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    )
    common = dict(
        observed=observed,
        local_frame=frame,
        components=parts,
        protocol_stream=integer(tcp.get("tcp.stream", [None])[0], -1),
        src=first(layers.get("ip", {}), "ip.src") or first(layers.get("ipv6", {}), "ipv6.src"),
        raw_seq=integer(tcp.get("tcp.seq_raw", [None])[0]),
        tcp_len=integer(tcp.get("tcp.len", [None])[0]),
    )
    result = []
    analysis = {
        name: bool(tcp.get("tcp.analysis." + field))
        for name, field in (
            ("retrans", "retransmission"),
            ("fast_retrans", "fast_retransmission"),
            ("spurious", "spurious_retransmission"),
            ("out_of_order", "out_of_order"),
            ("zero_window", "zero_window"),
            ("duplicate_ack", "duplicate_ack"),
            ("window_full", "window_full"),
            ("zero_probe", "zero_window_probe"),
        )
    }
    for name, field in (("rtt", "tcp.analysis.ack_rtt"), ("rto_seconds", "tcp.analysis.rto")):
        value = tcp.get(field, [None])[0]
        analysis[name] = float(value) if value else None
    analysis.update(
        bytes_in_flight=integer(tcp.get("tcp.analysis.bytes_in_flight", [None])[0], None),
        rto_frame=integer(tcp.get("tcp.analysis.rto_frame", [None])[0], None),
        sack_left=integer(tcp.get("tcp.options.sack_le", [None])[0], None),
        sack_right=integer(tcp.get("tcp.options.sack_re", [None])[0], None),
    )
    if any(analysis.values()) or analysis["bytes_in_flight"] is not None:
        result.append({**common, "components": [frame], "kind": "tcp_analysis", "metadata": analysis})
    http = layers.get("http", {})
    if values(http, "http.request.method"):
        method = values(http, "http.request.method")
        uri = values(http, "http.request.uri")
        version = values(http, "http.request.version")
        reason = (
            None
            if len(method) == len(uri) == len(version) == 1
            else "Multiple HTTP messages in one frame; byte boundaries unknown"
        )
        content = integer(first(http, "http.content_length"), 0)
        raw_length = values(http, "http.content_length_header")
        if len(raw_length) > 1 or raw_length and not str(raw_length[0]).isdigit():
            reason = reason or "Ambiguous or invalid HTTP content length"
        body = first(http, "http.file_data", "")
        if first(http, "http.transfer_encoding") or first(http, "http.content_encoding"):
            reason = reason or "Encoded/chunked request byte boundary not supported"
        if content and len(body.replace(":", "")) // 2 != content:
            reason = reason or "Request body incomplete in tshark decode"
        result.append(
            {
                **common,
                "kind": "http_request",
                "metadata": dict(
                    line=f"{method[0]} {uri[0]} {version[0]}"
                    if len(method) == len(uri) == len(version) == 1
                    else None,
                    host=(first(http, "http.host") or "").strip().lower() or None,
                    xff=ip_list(first(http, "http.x_forwarded_for")),
                    ready=not reason,
                    reason=reason,
                ),
            }
        )
    if first(http, "http.response.code"):
        content = integer(first(http, "http.content_length"), 0)
        body = first(http, "http.file_data", "")
        response_ready = len(values(http, "http.response.code")) == 1 and not first(
            http, "http.transfer_encoding"
        )
        response_ready = response_ready and (not content or len(body.replace(":", "")) // 2 == content)
        result.append(
            {
                **common,
                "kind": "http_response",
                "metadata": dict(
                    request_in=integer(first(http, "http.request_in"), None),
                    code=integer(first(http, "http.response.code")),
                    ready=response_ready,
                ),
            }
        )
    tls = layers.get("tls", {})
    types = [integer(v) for v in values(tls, "tls.handshake.type")]
    if 1 in types:
        names = values(tls, "tls.handshake.extensions_server_name")
        sni = names[0].lower().rstrip(".") if len(names) == 1 else None
        result.append(
            {
                **common,
                "kind": "tls_setup",
                "metadata": dict(
                    sni=sni, ready=bool(sni), reason=None if sni else "TLS SNI absent or ambiguous"
                ),
            }
        )
    if 2 in types:
        version = integer(
            first(tls, "tls.handshake.extensions.supported_version") or first(tls, "tls.handshake.version")
        )
        result.append({**common, "kind": "tls_server", "metadata": dict(version=version)})
    if 11 in types:
        result.append({**common, "kind": "tls_certificate", "metadata": dict(chain=certificates(tls))})
    return result


def json_packets(stream):
    decoder = json.JSONDecoder()
    buffer = ""
    while True:
        block = stream.read(65536)
        if block:
            buffer += block
        while True:
            buffer = buffer.lstrip(" \r\n\t[,")
            if not buffer or buffer.startswith("]"):
                break
            try:
                record, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                break
            yield record
            buffer = buffer[end:]
        if len(buffer) > MAX_JSON:
            raise ValueError("Application metadata record exceeds 4 MiB budget")
        if not block:
            if buffer.strip(" \r\n\t],"):
                raise ValueError("Incomplete tshark JSON application record")
            break


def can_decode_source(point, inventory, count):
    return (
        point.interface is None
        and point.source_cidr is None
        and point.vendor == "none"
        and inventory.get("timestamps_validated", False)
        and inventory.get("records_read") == inventory.get("packet_count") == count
        and len(inventory.get("interfaces", [])) == 1
        and not inventory.get("damaged_tail")
        and inventory.get("frame_limit") is None
    )


def read_filter(point, inventory):
    # Inventory uses doubles; one microsecond padding preserves nanosecond filter endpoints.
    # The count and field checks below still require exact identity with the validated index.
    terms = [
        f"frame.time_epoch >= {inventory['start'] - 1e-6:.9f}",
        f"frame.time_epoch <= {inventory['end'] + 1e-6:.9f}",
    ]
    if point.interface is not None:
        terms.append(f"frame.interface_id == {point.interface}")
    if point.source_cidr:
        family = "ipv6" if ":" in point.source_cidr else "ip"
        terms.append(f"{family}.src == {point.source_cidr}")
    if point.vendor == "checkpoint":
        stage = point.vendor_stage
        terms.append("fw1.direction == " + json.dumps(stage[0]))
        if len(stage) > 1:
            terms.append("fw1.chain == " + json.dumps(stage[1:]))
        elif stage in ("o", "O"):
            terms.append("fw1.chain != " + json.dumps("e" if stage == "o" else "E"))
        if point.vendor_interface:
            terms.append("fw1.interface == " + json.dumps(point.vendor_interface))
    return " && ".join(terms)


@contextmanager
def running(command, errors, environment, cancel, stdout=subprocess.PIPE):
    proc = subprocess.Popen(
        command, stdout=stdout, stderr=errors, text=True, encoding="utf-8", env=environment
    )
    done = threading.Event()

    def watch():
        while not done.wait(0.1):
            if cancel and cancel.is_set():
                if proc.poll() is None:
                    proc.terminate()
                return

    watcher = threading.Thread(target=watch, daemon=True) if cancel else None
    if watcher:
        watcher.start()
    try:
        yield proc
    finally:
        done.set()
        if proc.poll() is None:
            proc.terminate()
        proc.wait()
        if watcher:
            watcher.join()
        if proc.stdout:
            proc.stdout.close()


def index_applications(project, db, topology, cancel=None, progress=None):
    db.execute(
        "CREATE TABLE IF NOT EXISTS app_protocol(point VARCHAR,capture_id VARCHAR,frame BIGINT,kind VARCHAR,components VARCHAR,protocol_stream BIGINT,metadata VARCHAR)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS app_protocol_cache(point VARCHAR PRIMARY KEY,identity VARCHAR,reason VARCHAR)"
    )
    db.execute("CREATE TABLE IF NOT EXISTS tcp_point_analysis(point VARCHAR,frame BIGINT,metadata VARCHAR)")
    db.execute(
        "CREATE OR REPLACE TEMP TABLE tcp_state_raw(point VARCHAR,local_frame BIGINT,src VARCHAR,raw_seq BIGINT,tcp_len BIGINT,observed DOUBLE,metadata VARCHAR)"
    )
    needed = (
        any(p.translation == "full_proxy" for p in topology.points)
        or db.execute(
            "SELECT count(*) FROM obs WHERE proto='TCP' AND (json_extract_string(path_fields,'$.tls_record_type') IN ('20','21','22','23','24') OR (NOT coalesce(json_exists(path_fields,'$.tls_record_type'),false) AND NOT coalesce(try_cast(json_extract_string(path_fields,'$.transport_index') AS INTEGER)=1,false)))"
        ).fetchone()[0]
        > 0
    )
    if not needed:
        # A new non-TLS generation must not reuse certificates/state from older captures.
        for table in ("app_protocol", "app_protocol_cache", "tcp_point_analysis"):
            db.execute("DELETE FROM " + table)
        return []
    binary = find_tshark(project.get(db, "preferences", {}).get("tshark"))
    statuses = []
    for point in topology.points:
        capture = db.execute(
            "SELECT path,identity,inventory FROM captures WHERE id=?", [point.capture_id]
        ).fetchone()
        if not db.execute("SELECT count(*) FROM obs WHERE point=?", [point.id]).fetchone()[0]:
            continue
        identity = json.dumps(
            [
                capture[1],
                point.model_dump(
                    exclude={"x", "y", "label", "device", "kind", "translation", "payload_transform"}
                ),
                VERSION,
                binary,
            ],
            sort_keys=True,
        )
        existing = db.execute(
            "SELECT identity,reason FROM app_protocol_cache WHERE point=?", [point.id]
        ).fetchone()
        if existing and existing[0] == identity:
            if existing[1] is None:
                apply_tcp_analysis(db, point.id)
            statuses.append(dict(point=point.id, reason=existing[1], cached=True))
            continue
        if cancel and cancel.is_set():
            raise InterruptedError("Application indexing cancelled")
        if progress:
            progress(state="reading application metadata", point=point.id)
        inventory = json.loads(capture[2])
        reason = None
        events = []
        state_buffer = []

        def flush_state():
            if state_buffer:
                schema = '[{"point":"VARCHAR","local_frame":"BIGINT","src":"VARCHAR","raw_seq":"BIGINT","tcp_len":"BIGINT","observed":"DOUBLE","metadata":"VARCHAR"}]'
                db.execute(
                    "INSERT INTO tcp_state_raw SELECT r.* FROM (SELECT unnest(from_json(?,?)) r)",
                    [json.dumps(state_buffer), schema],
                )
                state_buffer.clear()

        db.execute("DELETE FROM tcp_state_raw WHERE point=?", [point.id])
        db.execute("DELETE FROM tcp_point_analysis WHERE point=?", [point.id])
        db.execute("DELETE FROM app_protocol WHERE point=?", [point.id])
        try:
            source = Path(capture[0])
            stat = source.stat()
            indexed = json.loads(capture[1])
            if [str(source), stat.st_size, stat.st_mtime_ns] != indexed[:3]:
                raise ValueError("Capture changed; reattach before application analysis")
            if point.vendor == "f5":
                raise ValueError("F5 trailer points use the existing vendor adapter")
            options = []
            if inventory.get("format") == "snoop":
                options = [
                    "-o",
                    "eth.interpret_as_fw1_monitor:TRUE",
                    "-o",
                    "fw1.iflist_with_chain:TRUE",
                    "-o",
                    f"fw1.with_uuid:{str(inventory.get('checkpoint_uuid', False)).upper()}",
                ]
            environment = os.environ.copy()
            environment.pop("SSLKEYLOGFILE", None)
            with (
                tempfile.TemporaryDirectory(prefix="app-point-") as directory,
                tempfile.TemporaryFile(mode="w+", encoding="utf-8") as errors,
            ):
                selected = Path(directory) / "point.pcapng"
                # Isolate capture points before reassembly: duplicate copies otherwise poison TLS/HTTP state.
                count = db.execute("SELECT count(*) FROM obs WHERE point=?", [point.id]).fetchone()[0]
                if can_decode_source(point, inventory, count):
                    selected = source
                else:
                    select = [
                        binary,
                        "-n",
                        "-r",
                        str(source),
                        "-Y",
                        read_filter(point, inventory),
                        "-w",
                        str(selected),
                        "-F",
                        "pcapng",
                        "-o",
                        "tcp.desegment_tcp_streams:FALSE",
                        *options,
                    ]
                    if inventory.get("frame_limit") is not None:
                        select += ["-c", str(inventory["frame_limit"])]
                    with running(select, errors, environment, cancel, subprocess.DEVNULL) as proc:
                        code = proc.wait()
                    if cancel and cancel.is_set():
                        raise InterruptedError("Application indexing cancelled")
                    if code and not inventory.get("damaged_tail"):
                        errors.seek(0)
                        raise ValueError("Point selection failed: " + errors.read(4000))
                    count = db.execute("SELECT count(*) FROM obs WHERE point=?", [point.id]).fetchone()[0]
                    if capture_metadata(selected, cancel)["complete_records"] != count:
                        raise ValueError("Selected point frame count disagrees with index")
                command = [
                    binary,
                    "-n",
                    "-2",
                    "-r",
                    str(selected),
                    "-Y",
                    "tcp && !(vxlan || geneve || gre || icmp || icmpv6)",
                    "-o",
                    "tcp.desegment_tcp_streams:TRUE",
                    "-o",
                    "ip.defragment:FALSE",
                    "-o",
                    "ipv6.defragment:FALSE",
                    "-o",
                    "tcp.reassemble_out_of_order:TRUE",
                    "-o",
                    "http.desegment_body:TRUE",
                    "-o",
                    "tls.keylog_file:",
                    "-o",
                    "tls.debug_file:",
                    "-T",
                    "json",
                    "--no-duplicate-keys",
                    *options,
                ]
                errors.seek(0)
                errors.truncate()
                with running(command, errors, environment, cancel) as proc:
                    for packet in json_packets(proc.stdout):
                        for event in event_rows(packet):
                            if event["kind"] == "tcp_analysis":
                                state_buffer.append(
                                    dict(
                                        point=point.id,
                                        local_frame=event["local_frame"],
                                        src=event["src"],
                                        raw_seq=event["raw_seq"],
                                        tcp_len=event["tcp_len"],
                                        observed=event["observed"],
                                        metadata=json.dumps(event["metadata"]),
                                    )
                                )
                                if len(state_buffer) >= 1000:
                                    flush_state()
                            else:
                                events.append(event)
                        if len(events) > MAX_EVENTS:
                            raise ValueError(
                                "Application index exceeds 10,000 events per point; narrow capture"
                            )
                    code = proc.wait()
                if cancel and cancel.is_set():
                    raise InterruptedError("Application indexing cancelled")
                if code:
                    errors.seek(0)
                    raise ValueError("Application tshark decode failed: " + errors.read(4000))
            flush_state()
            db.execute(
                """CREATE OR REPLACE TEMP TABLE tcp_state_mapping AS SELECT point,frame,src,ts,raw_seq,length,
                row_number() OVER(ORDER BY frame) AS local_frame FROM obs WHERE point=?""",
                [point.id],
            )
            invalid = db.execute(
                """SELECT count(*) FROM tcp_state_raw s LEFT JOIN tcp_state_mapping m USING(point,local_frame)
                WHERE s.point=? AND (m.frame IS NULL OR s.src<>m.src OR s.raw_seq<>m.raw_seq OR s.tcp_len<>m.length OR abs(s.observed-m.ts)>1e-6)""",
                [point.id],
            ).fetchone()[0]
            if invalid:
                raise ValueError("Isolated TCP state mapping disagrees with packet index")
            db.execute(
                """INSERT INTO tcp_point_analysis SELECT s.point,m.frame,
                json_merge_patch(s.metadata,json_object('rto_frame',reference.frame))
                FROM tcp_state_raw s JOIN tcp_state_mapping m USING(point,local_frame)
                LEFT JOIN tcp_state_mapping reference ON reference.point=s.point AND reference.local_frame=try_cast(json_extract_string(s.metadata,'$.rto_frame') AS BIGINT)
                WHERE s.point=?""",
                [point.id],
            )
            ordinals = set()
            for event in events:
                ordinals.update(event["components"])
                ordinals.add(event["local_frame"])
                if event["metadata"].get("request_in"):
                    ordinals.add(event["metadata"]["request_in"])
                if event["metadata"].get("rto_frame"):
                    ordinals.add(event["metadata"]["rto_frame"])
            mapped = (
                rows(
                    db,
                    """SELECT * FROM (SELECT frame,src,ts,raw_seq,length,row_number() OVER(ORDER BY frame) AS local_frame
                FROM obs WHERE point=?) WHERE local_frame IN (SELECT unnest(?::BIGINT[]))""",
                    [point.id, sorted(ordinals)],
                )
                if ordinals
                else []
            )
            mapping = {r["local_frame"]: r for r in mapped}
            records = []
            for event in events:
                source_frame = mapping.get(event["local_frame"])
                if (
                    not source_frame
                    or source_frame["src"] != event["src"]
                    or source_frame["raw_seq"] != event["raw_seq"]
                    or source_frame["length"] != event["tcp_len"]
                    or abs(source_frame["ts"] - event["observed"]) > 1e-6
                ):
                    raise ValueError(
                        "Application frame mapping disagrees with packet index; use unambiguous point filters"
                    )
                if any(f not in mapping for f in event["components"]):
                    raise ValueError("Application component frame not indexed")
                meta = event["metadata"]
                reference = meta.get("request_in")
                if reference:
                    meta["request_in"] = mapping[reference]["frame"] if reference in mapping else None
                if meta.get("rto_frame"):
                    meta["rto_frame"] = mapping.get(meta["rto_frame"], {}).get("frame")
                records.append(
                    dict(
                        point=point.id,
                        capture_id=point.capture_id,
                        frame=source_frame["frame"],
                        kind=event["kind"],
                        components=json.dumps([mapping[f]["frame"] for f in event["components"]]),
                        protocol_stream=event["protocol_stream"],
                        metadata=json.dumps(meta),
                    )
                )
            if records:
                schema = '[{"point":"VARCHAR","capture_id":"VARCHAR","frame":"BIGINT","kind":"VARCHAR","components":"VARCHAR","protocol_stream":"BIGINT","metadata":"VARCHAR"}]'
                db.execute(
                    "INSERT INTO app_protocol SELECT r.* FROM (SELECT unnest(from_json(?,?)) r)",
                    [json.dumps(records), schema],
                )
        except (OSError, ValueError, RecursionError) as exc:
            if cancel and cancel.is_set():
                raise InterruptedError("Application indexing cancelled")
            reason = str(exc)
            db.execute("DELETE FROM app_protocol WHERE point=?", [point.id])
            db.execute("DELETE FROM tcp_point_analysis WHERE point=?", [point.id])
        db.execute("INSERT OR REPLACE INTO app_protocol_cache VALUES (?,?,?)", [point.id, identity, reason])
        if reason is None:
            apply_tcp_analysis(db, point.id)
        statuses.append(dict(point=point.id, reason=reason, cached=False))
    return statuses


def apply_tcp_analysis(db, point):
    # A merged multi-point file makes tshark mistake traveling copies for retransmissions.
    # Replace stateful TCP fields only after a successful isolated decode.
    db.execute(
        """UPDATE obs SET retrans=false,fast_retrans=false,spurious=false,out_of_order=false,
        zero_window=false,rtt=NULL,path_fields=json_merge_patch(path_fields,
        '{"duplicate_ack":false,"window_full":false,"zero_probe":false,"rto_seconds":null,"rto_frame":null,"bytes_in_flight":null}') WHERE point=?""",
        [point],
    )
    db.execute(
        """UPDATE obs SET retrans=try_cast(json_extract_string(a.metadata,'$.retrans') AS BOOLEAN),
        fast_retrans=try_cast(json_extract_string(a.metadata,'$.fast_retrans') AS BOOLEAN),
        spurious=try_cast(json_extract_string(a.metadata,'$.spurious') AS BOOLEAN),
        out_of_order=try_cast(json_extract_string(a.metadata,'$.out_of_order') AS BOOLEAN),
        zero_window=try_cast(json_extract_string(a.metadata,'$.zero_window') AS BOOLEAN),
        rtt=try_cast(json_extract_string(a.metadata,'$.rtt') AS DOUBLE),
        path_fields=json_merge_patch(obs.path_fields,a.metadata)
        FROM tcp_point_analysis a WHERE obs.point=a.point AND obs.frame=a.frame AND a.point=?""",
        [point],
    )
