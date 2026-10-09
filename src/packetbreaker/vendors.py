"""Vendor metadata adapters. All protocol fields are decoded by tshark."""

import json

CHECKPOINT_FIELDS = ["fw1.direction", "fw1.chain", "fw1.interface", "fw1.uuid"]
F5_FIELDS = [
    "f5ethtrailer." + name
    for name in (
        "flowid",
        "peerid",
        "peeraddr",
        "peeraddr6",
        "peerport",
        "peerremoteaddr",
        "peerremoteaddr6",
        "peerremoteport",
        "peerlocaladdr",
        "peerlocaladdr6",
        "peerlocalport",
        "ingress",
        "vip",
        "tmm",
        "slot",
        "rstcause",
        "rstcauseval",
        "rstcausetxt",
    )
]
HTTP_FIELDS = ["http.request.method", "http.request.uri", "http.request.version"]
VENDOR_FIELDS = CHECKPOINT_FIELDS + F5_FIELDS + HTTP_FIELDS


def decoded_vendor(fields):
    decoded = {key: fields.get(key) for key in VENDOR_FIELDS if fields.get(key)}
    if not any(k in decoded for k in CHECKPOINT_FIELDS + F5_FIELDS):
        return None
    if decoded.get("fw1.direction"):
        direction, chain = decoded["fw1.direction"], decoded.get("fw1.chain", "")
        decoded["adapter"] = "checkpoint"
        decoded["stage"] = direction + chain if direction + chain in ("oe", "OE") else direction
    elif decoded.get("f5ethtrailer.flowid"):
        decoded["adapter"] = "f5"
    return json.dumps(decoded)


def point_selector(point):
    if point.vendor == "checkpoint":
        return " AND json_extract_string(vendor,'$.stage')=?", [point.vendor_stage]
    if point.vendor == "f5":
        return (
            " AND EXISTS(SELECT 1 FROM f5_connections c WHERE c.capture_id=packets.capture_id AND c.stream=packets.stream AND c.role=?)",
            [point.vendor_stage],
        )
    return "", []


def checkpoint_audit(db, topology):
    """Upgrade only complete, explicitly attested inspection paths; reuse packet identities."""
    from .store import rows
    from .evidence import evidence

    result = []
    used = set(topology.forward + topology.reverse)
    for point in topology.points:
        if point.vendor != "checkpoint" or point.vendor_stage != "i" or point.id not in used:
            continue
        downstream = [
            p
            for p in topology.points
            if p.vendor == "checkpoint"
            and p.device == point.device
            and p.capture_id == point.capture_id
            and p.id in used
            and p.vendor_stage != "i"
        ]
        stages = {p.vendor_stage for p in downstream}
        inv = json.loads(
            db.execute("SELECT inventory FROM captures WHERE id=?", [point.capture_id]).fetchone()[0]
        )
        complete = (
            point.inspection_complete
            and {"I", "o"} <= stages
            and not (
                inv.get("damaged_tail")
                or inv.get("zero_tail_bytes")
                or inv.get("timestamp_excluded_counts")
                or inv.get("ifdrop")
                or inv.get("osdrop")
            )
        )
        end = inv.get("end")
        missing = rows(
            db,
            """SELECT o.* FROM obs o WHERE point=? AND eligible AND NOT EXISTS(
            SELECT 1 FROM obs b WHERE b.packet_key=o.packet_key AND b.point IN (SELECT unnest(?::VARCHAR[])))""",
            [point.id, [p.id for p in downstream]],
        )
        for obs in missing:
            covered = complete and end is not None and obs["ts"] + topology.match_window_ms / 1000 <= end
            result.append(
                dict(
                    point=point.id,
                    device=point.device,
                    stage="i → no I/o",
                    flow=obs["flow"],
                    packet_key=obs["packet_key"],
                    frame=obs["frame"],
                    capture_id=point.capture_id,
                    time=obs["corrected"],
                    status="confirmed_device_drop" if covered else "unknown",
                    reason="Packet absent after pre-inbound inspection in a complete mapped stage capture"
                    if covered
                    else "Inspection coverage incomplete or not attested; cannot confirm a device drop",
                    evidence=evidence(db, "o.point=? AND o.frame=?", [point.id, obs["frame"]], 1),
                )
            )
    return result


def prepare_f5_connections(db, topology):
    """Identify local streams with reciprocal TMM IDs, never merge the proxy's TCP legs."""
    import ipaddress
    from .store import rows

    ids = list({p.capture_id for p in topology.points if p.vendor == "f5"})
    db.execute("""CREATE OR REPLACE TABLE f5_connections(capture_id VARCHAR,stream BIGINT,
        flowid VARCHAR,peerid VARCHAR,tmm VARCHAR,role VARCHAR,reason VARCHAR)""")
    if not ids:
        return
    networks = [ipaddress.ip_network(c) for c in topology.client_cidrs]
    tuples = rows(
        db,
        """SELECT DISTINCT capture_id,stream,src,dst,
        json_extract_string(vendor,'$."f5ethtrailer.flowid"') AS flowid,
        json_extract_string(vendor,'$."f5ethtrailer.peerid"') AS peerid,
        concat(json_extract_string(vendor,'$."f5ethtrailer.slot"'),':',json_extract_string(vendor,'$."f5ethtrailer.tmm"')) AS tmm
        FROM packets WHERE capture_id IN (SELECT unnest(?::VARCHAR[])) AND proto='TCP'
        AND json_extract_string(vendor,'$.adapter')='f5' """,
        [ids],
    )
    grouped = {}
    for row in tuples:
        key = (row["capture_id"], row["stream"], row["flowid"], row["peerid"], row["tmm"])
        client = any(ipaddress.ip_address(ip) in net for ip in (row["src"], row["dst"]) for net in networks)
        grouped[key] = grouped.get(key, False) or client
    ids_to_keys = {}
    for key in grouped:
        ids_to_keys.setdefault((key[0], key[4], key[2]), []).append(key)
    records = []
    for key, is_client in grouped.items():
        cid, stream, fid, peer, tmm = key
        peers = ids_to_keys.get((cid, tmm, peer), [])
        reason = None
        if not fid or not peer or fid.strip("0x0") == "" or peer.strip("0x0") == "" or tmm == ":":
            reason = "Missing/zero F5 flow, peer or processor identity"
        elif len(ids_to_keys[(cid, tmm, fid)]) != 1 or len(peers) != 1:
            reason = "Missing or reused F5 flow/peer ID; session correspondence unknown"
        elif peers[0][3] != fid or grouped[peers[0]] == is_client:
            reason = "Non-reciprocal F5 IDs or ambiguous client networks; narrow the client CIDRs"
        role = "client" if is_client else "server"
        records.append([cid, stream, fid, peer, tmm, role if reason is None else "unknown", reason])
    if records:
        db.executemany("INSERT INTO f5_connections VALUES (?,?,?,?,?,?,?)", records)


def f5_report(db, topology):
    from collections import defaultdict
    from .store import rows
    from .evidence import evidence

    if not any(p.vendor == "f5" for p in topology.points):
        return dict(pairs=[], requests=[], resets=[])
    connections = rows(db, "SELECT * FROM f5_connections")
    result = dict(pairs=connections, requests=[], resets=[])
    points = {p.id: p for p in topology.points}
    for c in connections:
        if c["role"] != "client":
            continue
        peer = next(
            (
                x
                for x in connections
                if x["capture_id"] == c["capture_id"]
                and x["tmm"] == c["tmm"]
                and x["flowid"] == c["peerid"]
                and x["role"] == "server"
            ),
            None,
        )
        if not peer:
            continue
        packets = rows(
            db,
            """SELECT * FROM obs WHERE capture_id=? AND stream IN (?,?)
            AND json_extract_string(vendor,'$."http.request.method"') IS NOT NULL ORDER BY ts,frame LIMIT 2001""",
            [c["capture_id"], c["stream"], peer["stream"]],
        )
        c["client_flow"] = db.execute(
            "SELECT min(flow) FROM obs WHERE capture_id=? AND stream=?", [c["capture_id"], c["stream"]]
        ).fetchone()[0]
        c["server_flow"] = db.execute(
            "SELECT min(flow) FROM obs WHERE capture_id=? AND stream=?", [c["capture_id"], peer["stream"]]
        ).fetchone()[0]
        if len(packets) > 2000:
            c["reason"] = "F5 request evidence budget exceeded (2000 request observations)"
            continue
        requests = defaultdict(lambda: [[], []])
        seen = set()
        for p in packets:
            v = json.loads(p["vendor"])
            key = (v["http.request.method"], v.get("http.request.uri"), v.get("http.request.version"))
            identity = (p["stream"], p["seq"], key)
            if identity in seen:
                continue
            seen.add(identity)
            requests[key][0 if p["stream"] == c["stream"] else 1].append(p)
        for key, (left, right) in requests.items():
            for i, a in enumerate(left):
                b = right[i] if len(left) == len(right) else None
                reason = None if b else "Request counts differ across proxy legs; correspondence unknown"
                # Repeated indistinguishable requests can be pipelined/reordered by a proxy.
                if len(left) > 1:
                    reason = "Repeated identical request lines: per-request proxy association unknown"
                dwell = (b["ts"] - a["ts"]) * 1000 if b else None
                if dwell is not None and dwell < 0:
                    reason = "Server request precedes client request; pairing/streaming order unknown"
                refs = evidence(
                    db,
                    "o.capture_id=? AND o.frame IN (?,?)",
                    [c["capture_id"], a["frame"], b["frame"] if b else -1],
                    2,
                )
                result["requests"].append(
                    dict(
                        device=points[a["point"]].device,
                        request=" ".join(x or "" for x in key),
                        client_flow=c["client_flow"],
                        server_flow=c["server_flow"],
                        flowid=c["flowid"],
                        peerid=c["peerid"],
                        request_dwell_ms=dwell if reason is None else None,
                        clock_uncertainty_ms=0,
                        reason=reason,
                        evidence=refs,
                        note="Same-capture interval between tshark-decoded request-bearing frames; not whole-body completion or server processing",
                    )
                )
    reset_rows = rows(
        db,
        """SELECT * FROM obs WHERE json_extract_string(vendor,'$."f5ethtrailer.rstcausetxt"') IS NOT NULL ORDER BY ts LIMIT 200""",
    )
    for r in reset_rows:
        result["resets"].append(
            dict(
                device=points[r["point"]].device,
                flow=r["flow"],
                time=r["corrected"],
                reason=json.loads(r["vendor"])["f5ethtrailer.rstcausetxt"],
                evidence=evidence(db, "o.point=? AND o.frame=?", [r["point"], r["frame"]], 1),
            )
        )
    return result
