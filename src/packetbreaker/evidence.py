"""Portable Wireshark filters built only from observed fields."""

import ipaddress
import json
from .store import rows


def tuple_filter(proto, src, dst, sport, dport, bidirectional=False):
    try:
        family = "ipv6" if ipaddress.ip_address(src).version == 6 else "ip"
        if ipaddress.ip_address(dst).version != ipaddress.ip_address(src).version:
            return None
    except (ValueError, TypeError):
        return None
    protocol = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "ICMPv6": "icmpv6"}.get(proto)
    if not protocol:
        return None

    def one(a, b, pa, pb):
        result = f"{family}.src == {a} && {family}.dst == {b} && {protocol}"
        if protocol in ("tcp", "udp"):
            result += f" && {protocol}.srcport == {int(pa)} && {protocol}.dstport == {int(pb)}"
        return "(" + result + ")"

    forward = one(src, dst, sport, dport)
    return (
        "(" + " || ".join(sorted([forward, one(dst, src, dport, sport)])) + ")" if bidirectional else forward
    )


def content_filter(packet):
    result = tuple_filter(packet["proto"], packet["src"], packet["dst"], packet["sport"], packet["dport"])
    if result is None:
        return None
    result += f" && {'ipv6.flow' if ':' in packet['src'] else 'ip.id'} == {int(packet['ipid'])}"
    if packet["proto"] == "TCP":
        result += f" && tcp.seq_raw == {packet['seq']} && tcp.ack_raw == {packet['ack']} && tcp.len == {packet['length']} && tcp.flags == 0x{packet['flags']:04x}"
    elif packet["proto"] == "UDP":
        result += f" && udp.length == {packet['length'] + 8}"
        if packet["dns_id"] is not None:
            result += f" && dns.id == {packet['dns_id']}"
    elif packet["proto"] == "ICMP":
        for field, key in (("icmp.type", "icmp_type"), ("icmp.ident", "icmp_id"), ("icmp.seq", "icmp_seq")):
            if packet[key] is not None:
                result += f" && {field} == {packet[key]}"
    return result


def prepare_flow_filters(db):
    metadata = rows(
        db,
        """SELECT flow,capture_id,tuple_key,min(ts) AS start,max(ts) AS "end"
        FROM obs GROUP BY flow,capture_id,tuple_key""",
    )
    grouped = {}
    for item in metadata:
        proto, src, sport, dst, dport = json.loads(item["tuple_key"])
        expression = tuple_filter(proto, src, dst, sport, dport, True)
        if not expression:
            continue
        group = grouped.setdefault(
            (item["flow"], item["capture_id"]), dict(expressions=set(), start=item["start"], end=item["end"])
        )
        group["expressions"].add(expression)
        group["start"] = min(group["start"], item["start"])
        group["end"] = max(group["end"], item["end"])
    db.execute("CREATE OR REPLACE TABLE flow_filters(flow VARCHAR,capture_id VARCHAR,display_filter VARCHAR)")
    data = []
    for (flow, cid), g in grouped.items():
        expression = "(" + " || ".join(sorted(g["expressions"])) + ")"
        # Widen by a microsecond to retain nanosecond timestamps rounded to DuckDB doubles.
        expression += (
            f" && frame.time_epoch >= {g['start'] - 1e-6:.9f} && frame.time_epoch <= {g['end'] + 1e-6:.9f}"
        )
        data.append((flow, cid, expression))
    if data:
        db.executemany("INSERT INTO flow_filters VALUES (?,?,?)", data)


def evidence(db, predicate, params, limit=128, _expand_ranges=True):
    data = rows(
        db,
        f"""SELECT o.point,c.name AS file,o.capture_id,o.frame,
        'frame.number == ' || o.frame AS display_filter,o.ts AS observed_time,o.corrected AS corrected_time,
        o.vendor,o.packet_key,o.flow,o.proto,o.src,o.dst,o.sport,o.dport,o.ipid,o.raw_seq AS seq,o.raw_ack AS ack,o.seq AS canonical_seq,o.ack AS canonical_ack,o.translation_reason,o.flags,o.length,
        o.dns_id,o.icmp_id,o.icmp_seq,o.icmp_type
        FROM obs o JOIN captures c ON c.id=o.capture_id WHERE {predicate}
        ORDER BY o.corrected NULLS LAST,o.point,o.frame LIMIT {int(limit)}""",
        params,
    )
    range_context = {}
    has_ranges = (
        _expand_ranges
        and data
        and db.execute(
            "SELECT count(*) FROM information_schema.tables WHERE table_name='byte_flows'"
        ).fetchone()[0]
    )
    if has_ranges and db.execute("SELECT count(*) FROM byte_flows").fetchone()[0]:
        keys = list({e["packet_key"] for e in data})
        peers = rows(
            db,
            """SELECT point,source_frame,list(DISTINCT struct_pack(start_seq:=lo,end_seq:=hi,bytes:=range_length)) AS ranges
            FROM byte_obs WHERE is_atom AND eligible AND packet_key IN (
                SELECT packet_key FROM byte_obs WHERE is_atom AND eligible AND source_packet_key IN (SELECT unnest(?::VARCHAR[])))
            GROUP BY point,source_frame ORDER BY point,source_frame""",
            [keys],
        )
        range_context = {(r["point"], r["source_frame"]): r["ranges"][:128] for r in peers}
        # Keep at least one representative per point before adding additional split frames.
        chosen = list(dict.fromkeys((r["point"], r["frame"]) for r in data))
        for point in dict.fromkeys(r["point"] for r in peers):
            peer = next(r for r in peers if r["point"] == point)
            if not any(p == point for p, f in chosen):
                chosen.append((point, peer["source_frame"]))
        chosen += [key for key in range_context if key not in chosen]
        chosen = chosen[:limit]
        selected = " OR ".join("(o.point=? AND o.frame=?)" for _ in chosen)
        result = evidence(db, selected, [v for pair in chosen for v in pair], limit, _expand_ranges=False)
        for item in result:
            item["byte_ranges"] = range_context.get((item["point"], item["frame"]), [])
            item["range_note"] = (
                "One-to-many TCP sequence-range evidence; up to 128 ranges shown per frame. Offload timestamps describe the captured unit, not each wire segment; payload comparison is limited to captured prefixes."
            )
        return result
    flows = list({e["flow"] for e in data if e["flow"]})
    filters = {}
    if (
        flows
        and db.execute(
            "SELECT count(*) FROM information_schema.tables WHERE table_name='flow_filters'"
        ).fetchone()[0]
    ):
        filters = {
            (flow, cid): value
            for flow, cid, value in db.execute(
                "SELECT * FROM flow_filters WHERE flow IN (SELECT unnest(?::VARCHAR[]))", [flows]
            ).fetchall()
        }
    result = []
    for e in data:
        item = {
            key: e[key]
            for key in (
                "point",
                "file",
                "capture_id",
                "frame",
                "display_filter",
                "observed_time",
                "corrected_time",
            )
        }
        if e["seq"] != e["canonical_seq"] or e["ack"] != e["canonical_ack"] or e["translation_reason"]:
            item["sequence_translation"] = dict(
                observed_seq=e["seq"],
                observed_ack=e["ack"],
                canonical_seq=e["canonical_seq"],
                canonical_ack=e["canonical_ack"],
                seq_offset=(e["seq"] - e["canonical_seq"]) % 4294967296,
                ack_offset=(e["ack"] - e["canonical_ack"]) % 4294967296,
                reason=e["translation_reason"],
            )
        if e.get("vendor"):
            item["vendor"] = json.loads(e["vendor"])
        item["content_filter"] = content_filter(e)
        item["flow_filter"] = filters.get((e["flow"], e["capture_id"])) or tuple_filter(
            e["proto"], e["src"], e["dst"], e["sport"], e["dport"], True
        )
        item["filter_note"] = (
            "Content filters survive frame renumbering; identical retransmissions or merged capture points can match multiple frames. Compare observed time."
            if item["content_filter"]
            else "No supported IP/L4 tuple is available for a content filter."
        )
        result.append(item)
    return result
