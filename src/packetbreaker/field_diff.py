"""Compare observed headers of an already matched occurrence, never infer missing fields."""

import json
from .store import rows
from .evidence import evidence
from .topology import Topology

FIELDS = (
    "src",
    "dst",
    "sport",
    "dport",
    "ttl",
    "dscp",
    "mss",
    "window_scale",
    "tcp_options",
    "sack_permitted",
    "timestamp_value",
    "timestamp_echo",
    "seq_offset",
    "payload_sha256",
    "ipid",
)
TOOLTIP = (
    "Raw observed fields across an occurrence matched using confirmed tuple/sequence mappings. "
    "Payload hashes cover the complete captured transport payload only; truncated payloads and "
    "different offload boundaries are unknown. IPv6 IP ID is not applicable (flow label is separate). "
    "A difference alone does not prove malicious modification."
)


def values(packet):
    value = {**packet, **json.loads(packet.get("path_fields") or "{}")}
    value["seq_offset"] = (
        (packet["raw_seq"] - packet["seq"]) % 4294967296 if packet["proto"] == "TCP" else None
    )
    if not value.get("payload_complete"):
        value["payload_sha256"] = None
    if ":" in packet["src"]:
        value["ipid"] = None
    if not (packet["flags"] & 2) or not packet["mss"]:
        value["mss"] = None
    return value


def field_diffs(db, topology, packet_key=None, limit=200):
    paths = [("forward", topology.forward), ("reverse", topology.reverse or topology.forward[::-1])]
    points = {p.id: p for p in topology.points}
    result = []
    for direction, path in paths:
        for a, b in zip(path, path[1:]):
            matched = rows(
                db,
                """SELECT a AS before_packet,b AS after_packet
                FROM obs a JOIN obs b ON a.packet_key=b.packet_key
                WHERE a.point=? AND b.point=? AND a.direction=? AND a.eligible AND b.eligible
                AND (? IS NULL OR a.packet_key=?)
                ORDER BY a.corrected,a.frame LIMIT ?""",
                [a, b, direction, packet_key, packet_key, limit + 1],
            )
            keys = list(
                {r[side]["packet_key"] for r in matched for side in ("before_packet", "after_packet")}
            )
            refs = (
                evidence(
                    db,
                    "o.point IN (?,?) AND o.packet_key IN (SELECT unnest(?::VARCHAR[]))",
                    [a, b, keys],
                    (limit + 1) * 2,
                    _expand_ranges=False,
                )
                if keys
                else []
            )
            refmap = {(r["point"], r["frame"]): r for r in refs}
            for pair in matched:
                packet, peer = pair["before_packet"], pair["after_packet"]
                left, right = values(packet), values(peer)
                fields = {
                    name: dict(
                        before=left.get(name),
                        after=right.get(name),
                        status="unknown"
                        if left.get(name) is None or right.get(name) is None
                        else "unchanged"
                        if left[name] == right[name]
                        else "changed",
                    )
                    for name in FIELDS
                }
                if packet["length"] != peer["length"]:
                    fields["payload_sha256"]["status"] = "unknown"
                result.append(
                    dict(
                        point_a=a,
                        point_b=b,
                        device=points[a].device if points[a].device == points[b].device else None,
                        location=f"{points[a].label} → {points[b].label}",
                        packet_key=packet["packet_key"],
                        flow=packet["flow"],
                        time=packet["corrected"],
                        direction=direction,
                        fields=fields,
                        tooltip=TOOLTIP,
                        evidence=[refmap[(a, packet["frame"])], refmap[(b, peer["frame"])]],
                    )
                )
                if len(result) >= limit:
                    return dict(
                        items=result,
                        limit=limit,
                        note="Bounded matched-packet sample; select a packet in the stream drill-down for its comparisons.",
                    )
    return dict(
        items=result,
        limit=limit,
        note="Unmatched, unsupported proxy boundaries and differently segmented offload frames have no packet-level comparison: unknown.",
    )


def packet_diff(project, packet_key):
    with project.connect() as db:
        if not project.get(db, "report"):
            raise ValueError("Run analysis before inspecting field differences")
        return field_diffs(db, Topology.model_validate(project.get(db, "topology")), packet_key)
