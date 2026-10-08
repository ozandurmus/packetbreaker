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


def evidence(db, predicate, params, limit=128):
    data = rows(
        db,
        f"""SELECT o.point,c.name AS file,o.capture_id,o.frame,
        'frame.number == ' || o.frame AS display_filter,o.ts AS observed_time,o.corrected AS corrected_time,
        o.flow,o.proto,o.src,o.dst,o.sport,o.dport,o.ipid,o.seq,o.ack,o.flags,o.length,
        o.dns_id,o.icmp_id,o.icmp_seq,o.icmp_type
        FROM obs o JOIN captures c ON c.id=o.capture_id WHERE {predicate}
        ORDER BY o.corrected NULLS LAST,o.point,o.frame LIMIT {int(limit)}""",
        params,
    )
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
