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
    if not any(
        fields.get(k)
        for k in (
            "fw1.direction",
            "f5ethtrailer.flowid",
            "f5ethtrailer.ingress",
            "f5ethtrailer.peeraddr",
            "f5ethtrailer.peeraddr6",
            "f5ethtrailer.rstcausetxt",
        )
    ):
        return None
    decoded = {key: fields.get(key) for key in VENDOR_FIELDS if fields.get(key)}
    if not any(k in decoded for k in CHECKPOINT_FIELDS + F5_FIELDS):
        return None
    if decoded.get("fw1.direction"):
        direction, chain = decoded["fw1.direction"], decoded.get("fw1.chain", "")
        decoded["adapter"] = "checkpoint"
        decoded["stage"] = direction + chain if direction + chain in ("oe", "OE") else direction
    else:
        decoded["adapter"] = "f5"
    return json.dumps(decoded)


def point_selector(point):
    if point.vendor == "checkpoint":
        clause, values = " AND json_extract_string(vendor,'$.stage')=?", [point.vendor_stage]
        if point.vendor_interface:
            clause += " AND json_extract_string(vendor,'$.\"fw1.interface\"')=?"
            values.append(point.vendor_interface)
        return clause, values
    if point.vendor == "f5":
        return (
            " AND EXISTS(SELECT 1 FROM f5_connections c WHERE c.capture_id=packets.capture_id AND c.stream=packets.stream AND c.role=?)",
            [point.vendor_stage],
        )
    return "", []


def prepare_f5_connections(db, topology):
    """Identify local streams with reciprocal TMM IDs, never merge the proxy's TCP legs."""
    import ipaddress
    from .store import rows

    ids = list({p.capture_id for p in topology.points if p.vendor == "f5"})
    db.execute("""CREATE OR REPLACE TABLE f5_connections(capture_id VARCHAR,stream BIGINT,
        flowid VARCHAR,peerid VARCHAR,tmm VARCHAR,role VARCHAR,reason VARCHAR)""")
    if not ids:
        return
    for cid, name, inventory in db.execute(
        "SELECT id,name,inventory FROM captures WHERE id IN (SELECT unnest(?::VARCHAR[]))", [ids]
    ).fetchall():
        if not json.loads(inventory).get("f5_fields"):
            raise ValueError(
                f"{name}: enable F5 trailer decoding in Settings and reattach to index TMM fields"
            )
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
        peers = [k for k in ids_to_keys.get((cid, tmm, peer), []) if k[3] == fid]
        reason = None
        if (
            not fid
            or not peer
            or fid.strip("0x0") == ""
            or peer.strip("0x0") == ""
            or "," in fid
            or "," in peer
            or tmm.startswith(":")
            or tmm.endswith(":")
        ):
            reason = "Missing/zero F5 flow, peer or processor identity"
        elif len({k[1] for k in ids_to_keys[(cid, tmm, fid)]}) != 1 or len(peers) != 1:
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
    connections = rows(
        db,
        """WITH clients AS (
        SELECT * FROM f5_connections WHERE role='client' ORDER BY capture_id,stream,peerid LIMIT 100)
        SELECT * FROM clients UNION SELECT p.* FROM f5_connections p JOIN clients c
        ON p.capture_id=c.capture_id AND p.tmm=c.tmm AND p.flowid=c.peerid AND p.peerid=c.flowid
        UNION (SELECT * FROM f5_connections WHERE role='unknown' ORDER BY capture_id,stream LIMIT 20)""",
    )
    result = dict(
        pairs=connections,
        requests=[],
        resets=[],
        connection_count=db.execute("SELECT count(*) FROM f5_connections").fetchone()[0],
        note="Overview shows up to 100 connection pairs, 20 unknown mappings, 200 requests and 200 reset annotations. Full frame metadata remains in the flow ladder.",
    )
    points = {p.id: p for p in topology.points}
    for c in connections:
        if c["role"] != "client" or len(result["requests"]) >= 200:
            continue
        peer = next(
            (
                x
                for x in connections
                if x["capture_id"] == c["capture_id"]
                and x["tmm"] == c["tmm"]
                and x["flowid"] == c["peerid"]
                and x["peerid"] == c["flowid"]
                and x["role"] == "server"
            ),
            None,
        )
        if not peer:
            continue
        packets = rows(
            db,
            """SELECT * FROM obs WHERE capture_id=? AND stream IN (?,?)
            AND json_extract_string(vendor,'$."http.request.method"') IS NOT NULL
            AND ((json_extract_string(vendor,'$."f5ethtrailer.flowid"')=? AND json_extract_string(vendor,'$."f5ethtrailer.peerid"')=?)
              OR (json_extract_string(vendor,'$."f5ethtrailer.flowid"')=? AND json_extract_string(vendor,'$."f5ethtrailer.peerid"')=?))
            ORDER BY ts,frame LIMIT 2001""",
            [
                c["capture_id"],
                c["stream"],
                peer["stream"],
                c["flowid"],
                c["peerid"],
                c["peerid"],
                c["flowid"],
            ],
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
                if len(result["requests"]) >= 200:
                    break
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
