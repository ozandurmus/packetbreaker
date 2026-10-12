"""Select one tshark-decoded IP/transport layer; never dissect packet bytes."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from datetime import datetime

from .application_index import first, values, json_packets, read_filter, running, can_decode_source
from .ingest import FIELDS, find_tshark, number, parse_packet, packet_signature, tuple_id
from .metadata import metadata
from .store import PACKET_COLUMNS, rows

VERSION = 3
TUNNELS = {"gre", "vxlan", "geneve"}


def flat(tree):
    result = {}

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if not isinstance(v, (dict, list)):
                    result.setdefault(k, str(v))
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(tree)
    return result


def occurrence(layers, stack, name, position):
    value = layers.get(name)
    index = stack[:position].count(name)
    if isinstance(value, list):
        return value[index] if index < len(value) else None
    return value if index == 0 else None


def decoded_layers(layers):
    stack = first(layers.get("frame", {}), "frame.protocols", "").split(":")
    net = [i for i, p in enumerate(stack) if p in ("ip", "ipv6")]
    tunnels = [i for i, p in enumerate(stack) if p in TUNNELS]
    result = dict(reason=None, layers={}, tunnel=None)
    if not tunnels and not net:
        return result
    if tunnels and (len(tunnels) != 1 or not net or not any(i > tunnels[0] for i in net)):
        result["reason"] = "Unknown tunnel layer: nested or incomplete IP envelope"
        return result
    positions = (
        dict(outer=net[0], inner=next(i for i in net if i > tunnels[0])) if tunnels else {"plain": net[0]}
    )
    outer = flat(occurrence(layers, stack, stack[net[0]], net[0]))
    kind = "erspan" if "erspan" in stack else stack[tunnels[0]] if tunnels else None
    info = dict(
        kind=kind,
        outer_src=outer.get("ip.src") or outer.get("ipv6.src"),
        outer_dst=outer.get("ip.dst") or outer.get("ipv6.dst"),
        session=first(layers.get("erspan", {}), "erspan.spanid"),
        vni=first(layers.get("vxlan", {}), "vxlan.vni") or first(layers.get("geneve", {}), "geneve.vni"),
        truncated=bool(number(first(layers.get("erspan", {}), "erspan.truncated", "0"))),
    )
    result["tunnel"] = info if tunnels else None
    for choice, pos in positions.items():
        family = stack[pos]
        ip = occurrence(layers, stack, family, pos)
        if not isinstance(ip, dict) or not first(ip, family + ".src") or not first(ip, family + ".dst"):
            result["reason"] = "Unknown tunnel layer: missing decoded IP identity"
            continue
        end = next((i for i in net if i > pos), len(stack))
        data = {**flat(layers.get("frame", {})), **flat(ip)}
        # Only the L4 protocol belonging to this IP occurrence may supply ports/sequence.
        l4pos = next((i for i in range(pos + 1, end) if stack[i] in ("tcp", "udp", "icmp", "icmpv6")), None)
        scope = {family: stack[:pos].count(family) + 1}
        if l4pos is not None:
            proto = stack[l4pos]
            data.update(flat(occurrence(layers, stack, proto, l4pos)))
            scope[proto] = stack[:l4pos].count(proto) + 1
            if choice == "inner":
                for p in ("dns", "http", "tls"):
                    data.update(flat(layers.get(p, {})))
        if "ipv6.fraghdr" in stack[pos:end]:
            scope["ipv6.fraghdr"] = stack[:end].count("ipv6.fraghdr")
        data["frame.protocols"] = ":".join(p for p in stack[pos:end] if p not in TUNNELS and p != "erspan")
        raw = layers.get(family + "_raw")
        raw = raw[scope[family] - 1] if raw and isinstance(raw[0], list) else raw
        result["layers"][choice] = dict(fields=data, scope=scope, raw=raw, ip=ip, family=family)
    return result


def layer_rows(layers, cid, prefix_bytes):
    decoded = decoded_layers(layers)
    result = []
    for choice, layer in decoded["layers"].items():
        data = layer["fields"]
        stamp = data["frame.time_epoch"]
        if "T" in stamp:
            data["frame.time_epoch"] = str(datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp())
        fragment = fragment_metadata(layer)
        if fragment and fragment["complete"]:
            reassembled = number(first(layer["ip"], layer["family"] + ".reassembled.length", "0"))
            if layer["family"] == "ip":
                data["ip.len"] = str(reassembled + number(data.get("ip.hdr_len", "0")))
            else:
                data["ipv6.plen"] = str(reassembled)
        row = dict(zip(PACKET_COLUMNS, parse_packet([data.get(k, "") for k in FIELDS], cid, prefix_bytes)))
        if choice == "outer" and decoded["tunnel"]["kind"] in ("gre", "erspan"):
            # Raw spans/offsets are supplied by tshark, not inferred by a packet parser.
            raw = layer["raw"]
            frame_raw = layers.get("frame_raw", [""])[0]
            if raw:
                start = (int(raw[1]) + int(raw[2])) * 2
                size = (
                    number(data.get("ip.len", "0")) - int(raw[2])
                    if "ip.src" in data
                    else number(data.get("ipv6.plen", "0"))
                )
                payload = frame_raw[start : start + max(0, size) * 2]
                row.update(
                    proto="GRE",
                    sport=0,
                    dport=0,
                    seq=0,
                    ack=0,
                    flags=0,
                    length=size,
                    prefix=payload[: prefix_bytes * 2],
                    payload_hash=hashlib.sha256(bytes.fromhex(payload[: prefix_bytes * 2])).hexdigest(),
                    signature=packet_signature("GRE", row["ipid"], size),
                    unsupported="",
                )
                row["tuple_key"] = tuple_id("GRE", row["src"], 0, row["dst"], 0)
                row["reverse_tuple"] = tuple_id("GRE", row["dst"], 0, row["src"], 0)
        info = {**decoded["tunnel"], "layer": choice, "scope": layer["scope"]} if decoded["tunnel"] else None
        if choice == "inner":
            info["truncated"] |= row["caplen"] < row["wirelen"]
        meta = json.loads(row["path_fields"])
        if info:
            meta["tunnel"] = info
        if fragment:
            meta["fragment"] = fragment
            if fragment["complete"] and not fragment["invalid"]:
                row["unsupported"] = ""
        row["path_fields"] = json.dumps(meta)
        result.append(dict(layer=choice, local_frame=row["frame"], packet=row))
    return result, decoded["reason"]


def apply_layers(project, db, point, cancel=None):
    count = db.execute(
        "SELECT count(*) FROM obs WHERE point=? AND (unsupported LIKE 'Tunnel encapsulation%' OR unsupported LIKE 'Fragmented packet%')",
        [point.id],
    ).fetchone()[0]
    if not count:
        return
    db.execute(
        "CREATE TABLE IF NOT EXISTS layer_cache(point VARCHAR PRIMARY KEY,identity VARCHAR,reason VARCHAR)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS layer_packets(point VARCHAR,layer VARCHAR,frame BIGINT,packet VARCHAR)"
    )
    capture = rows(db, "SELECT * FROM captures WHERE id=?", [point.capture_id])[0]
    inventory = json.loads(capture["inventory"])
    selection = point.model_copy(update={"source_cidr": None})
    identity = json.dumps(
        [
            capture["identity"],
            selection.model_dump(
                exclude={
                    "x",
                    "y",
                    "label",
                    "device",
                    "kind",
                    "translation",
                    "payload_transform",
                    "matching_layer",
                }
            ),
            VERSION,
        ],
        sort_keys=True,
    )
    cached = db.execute("SELECT identity,reason FROM layer_cache WHERE point=?", [point.id]).fetchone()
    if not cached or cached[0] != identity:
        binary = find_tshark(project.get(db, "preferences", {}).get("tshark"))
        source = Path(capture["path"])
        stat = source.stat()
        if [str(source), stat.st_size, stat.st_mtime_ns] != json.loads(capture["identity"])[:3]:
            raise ValueError("Capture changed; reattach before layer selection")
        db.execute("DELETE FROM layer_packets WHERE point=?", [point.id])
        db.execute(
            "CREATE OR REPLACE TEMP TABLE layer_frames AS SELECT row_number() OVER(ORDER BY frame) AS local_frame,frame,ts FROM obs WHERE point=?",
            [point.id],
        )
        prefix_bytes = project.get(db, "preferences", {}).get("prefix_bytes", 64)
        batch = []

        def flush():
            if batch:
                db.execute(
                    """INSERT INTO layer_packets SELECT ?,r.layer,f.frame,to_json(r.packet)
                    FROM (SELECT unnest(from_json(?,?)) r) JOIN layer_frames f ON r.local_frame=f.local_frame
                    WHERE abs(r.packet.ts-f.ts)<0.000002""",
                    [
                        point.id,
                        json.dumps(batch),
                        json.dumps([dict(layer="VARCHAR", local_frame="BIGINT", packet=PACKET_COLUMNS)]),
                    ],
                )
                batch.clear()

        reason = None
        try:
            if point.vendor != "none":
                raise ValueError("Tunnel layer selection with a vendor adapter is unknown")
            environment = os.environ.copy()
            environment.pop("SSLKEYLOGFILE", None)
            with (
                tempfile.TemporaryDirectory(prefix="packetbreaker-layer-") as directory,
                tempfile.TemporaryFile(mode="w+", encoding="utf-8") as errors,
            ):
                selected = Path(directory) / "point.pcapng"
                count = db.execute("SELECT count(*) FROM layer_frames").fetchone()[0]
                if can_decode_source(selection, inventory, count):
                    selected = source
                else:
                    select = [
                        binary,
                        "-n",
                        "-r",
                        str(source),
                        "-Y",
                        read_filter(selection, inventory),
                        "-w",
                        str(selected),
                        "-F",
                        "pcapng",
                        "-o",
                        "ip.defragment:FALSE",
                        "-o",
                        "ipv6.defragment:FALSE",
                    ]
                    if inventory.get("frame_limit") is not None:
                        select += ["-c", str(inventory["frame_limit"])]
                    with running(select, errors, environment, cancel, subprocess.DEVNULL) as proc:
                        code = proc.wait()
                    if cancel and cancel.is_set():
                        raise InterruptedError("Layer indexing cancelled")
                    if code and not inventory.get("damaged_tail"):
                        raise ValueError("tshark point selection failed")
                    expected = db.execute("SELECT count(*) FROM layer_frames").fetchone()[0]
                    if metadata(selected, cancel)["complete_records"] != expected:
                        raise ValueError("Layer frame mapping differs from validated index")
                cmd = [
                    binary,
                    "-n",
                    "-2",
                    "-r",
                    str(selected),
                    "-Y",
                    "gre || vxlan || geneve || ip.flags.mf || ip.frag_offset > 0 || ipv6.fraghdr",
                    "-T",
                    "json",
                    "-x",
                    "--no-duplicate-keys",
                    "-o",
                    "ip.defragment:TRUE",
                    "-o",
                    "ipv6.defragment:TRUE",
                    "-o",
                    "tcp.desegment_tcp_streams:FALSE",
                ]
                with running(cmd, errors, environment, cancel) as proc:
                    for packet in json_packets(proc.stdout):
                        decoded, _ = layer_rows(
                            packet["_source"]["layers"],
                            point.capture_id,
                            prefix_bytes,
                        )
                        batch.extend(decoded)
                        if len(batch) >= 500:
                            flush()
                    code = proc.wait()
                if cancel and cancel.is_set():
                    raise InterruptedError("Layer indexing cancelled")
                if code:
                    raise ValueError("tshark layer decode failed")
                flush()
        except (ValueError, OSError) as exc:
            reason = str(exc)
            db.execute("DELETE FROM layer_packets WHERE point=?", [point.id])
        db.execute("INSERT OR REPLACE INTO layer_cache VALUES (?,?,?)", [point.id, identity, reason])
    else:
        reason = cached[1]
    if reason:
        db.execute(
            "UPDATE obs SET unsupported=? WHERE point=? AND (unsupported LIKE 'Tunnel encapsulation%' OR unsupported LIKE 'Fragmented packet%')",
            ["Capture layer decode unavailable: " + reason, point.id],
        )
        return
    chosen = point.matching_layer
    db.execute(
        """CREATE OR REPLACE TEMP TABLE chosen_layer AS SELECT frame,from_json(packet,?) AS p
        FROM layer_packets WHERE point=? AND (layer='plain' OR layer=? OR (? IS NULL AND layer='inner'
        AND json_extract_string(json_extract_string(packet,'$.path_fields'),'$.tunnel.kind')='erspan'))""",
        [json.dumps(PACKET_COLUMNS), point.id, chosen, chosen],
    )
    columns = [k for k in PACKET_COLUMNS if k not in ("frame", "capture_id", "iface", "frame_hash", "ts")]
    db.execute(
        "UPDATE obs SET "
        + ",".join(f'"{k}"=c.p."{k}"' for k in columns)
        + ",raw_seq=c.p.seq,raw_ack=c.p.ack,canon=c.p.tuple_key FROM chosen_layer c WHERE obs.point=? AND obs.frame=c.frame AND (json_extract_string(c.p.path_fields,'$.fragment.complete') IS DISTINCT FROM 'false' OR json_exists(c.p.path_fields,'$.tunnel'))",
        [point.id],
    )
    db.execute(
        "UPDATE obs SET path_fields=json_merge_patch(obs.path_fields,c.p.path_fields) FROM chosen_layer c WHERE obs.point=? AND obs.frame=c.frame AND json_exists(c.p.path_fields,'$.fragment')",
        [point.id],
    )
    # The decoder's frame ordinal is private; evidence always uses the original capture frame.
    db.execute(
        "UPDATE obs SET unsupported='Tunnel encapsulation: choose inner or outer; incomplete/nested layers stay unknown' WHERE point=? AND unsupported LIKE 'Tunnel encapsulation%'",
        [point.id],
    )


def tunnel_report(db):
    return rows(
        db,
        """SELECT point,count(*) FILTER(WHERE json_exists(path_fields,'$.tunnel')) AS selected,
        count(*) FILTER(WHERE unsupported LIKE 'Tunnel encapsulation%') AS unselected,
        min(json_extract_string(path_fields,'$.tunnel.layer')) AS layer,
        count(*) FILTER(WHERE json_extract_string(path_fields,'$.tunnel.layer')='inner'
        AND try_cast(json_extract_string(path_fields,'$.tunnel.truncated') AS BOOLEAN)) AS truncated_inner
        FROM obs GROUP BY point HAVING selected+unselected>0""",
    )


def fragment_metadata(layer):
    data, ip, family = layer["fields"], layer["ip"], layer["family"]
    offset = number(data.get("ip.frag_offset" if family == "ip" else "ipv6.fraghdr.offset", "0")) * 8
    more = bool(number(data.get("ip.flags.mf" if family == "ip" else "ipv6.fraghdr.more", "0")))
    if not offset and not more:
        return None
    complete = bool(first(ip, family + ".reassembled.length"))
    target = first(ip, "ip.reassembled_in" if family == "ip" else "ipv6.reassembled.in")
    invalid = any(
        any(number(str(v)) for v in values(ip, family + ".fragment." + k))
        for k in ("overlap", "overlap.conflict", "multipletails", "toolongfragment", "error")
    )
    size = (
        number(data.get("ip.len", "0")) - number(data.get("ip.hdr_len", "0"))
        if family == "ip"
        else number(data.get("ipv6.plen", "0")) - 8
    )
    if family == "ipv6":
        raw_fragment = ip.get("ipv6.fraghdr_raw")
        if raw_fragment and layer["raw"]:
            size = number(data.get("ipv6.plen", "0")) - (
                int(raw_fragment[1]) + int(raw_fragment[2]) - int(layer["raw"][1]) - 40
            )
        else:
            invalid = True
    return dict(
        id=data.get("ip.id") if family == "ip" else data.get("ipv6.fraghdr.ident"),
        protocol=data.get("ip.proto") if family == "ip" else data.get("ipv6.fraghdr.nxt"),
        family=family,
        offset=offset,
        more=more,
        size=size,
        complete=complete,
        invalid=invalid,
        target=int(target) if target else int(data["frame.number"]) if complete else None,
        members=[int(v) for v in values(ip, family + ".fragment")],
        local_frame=int(data["frame.number"]),
    )
