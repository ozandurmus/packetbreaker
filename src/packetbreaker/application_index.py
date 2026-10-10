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

VERSION = 2
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
    frame = integer(first(layers.get("frame", {}), "frame.number"))
    parts = [integer(v) for v in values(layers, "tcp.segment")] or [frame]
    tcp = layers.get("tcp", {})
    stamp = first(layers.get("frame", {}), "frame.time_epoch")
    observed = (
        float(stamp) if "T" not in stamp else datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    )
    common = dict(
        observed=observed,
        local_frame=frame,
        components=parts,
        protocol_stream=integer(first(tcp, "tcp.stream"), -1),
        src=first(layers.get("ip", {}), "ip.src") or first(layers.get("ipv6", {}), "ipv6.src"),
        raw_seq=integer(first(tcp, "tcp.seq_raw")),
        tcp_len=integer(first(tcp, "tcp.len")),
    )
    result = []
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
        result.append(
            {
                **common,
                "kind": "http_response",
                "metadata": dict(
                    request_in=integer(first(http, "http.request_in"), None),
                    code=integer(first(http, "http.response.code")),
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
    needed = (
        any(p.translation == "full_proxy" for p in topology.points)
        or db.execute(
            "SELECT count(*) FROM obs WHERE json_extract_string(path_fields,'$.tls_record_type') IN ('20','21','22','23','24')"
        ).fetchone()[0]
        > 0
    )
    if not needed:
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
            statuses.append(dict(point=point.id, reason=existing[1], cached=True))
            continue
        if cancel and cancel.is_set():
            raise InterruptedError("Application indexing cancelled")
        if progress:
            progress(state="reading application metadata", point=point.id)
        inventory = json.loads(capture[2])
        reason = None
        events = []
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
                    "http.request or http.response or tls.handshake",
                    "-o",
                    "tcp.desegment_tcp_streams:TRUE",
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
                        events.extend(event_rows(packet))
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
            ordinals = set()
            for event in events:
                ordinals.update(event["components"])
                ordinals.add(event["local_frame"])
                if event["metadata"].get("request_in"):
                    ordinals.add(event["metadata"]["request_in"])
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
        db.execute("INSERT OR REPLACE INTO app_protocol_cache VALUES (?,?,?)", [point.id, identity, reason])
        statuses.append(dict(point=point.id, reason=reason, cached=False))
    return statuses
