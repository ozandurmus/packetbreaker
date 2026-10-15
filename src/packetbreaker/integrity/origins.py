"""RST and ICMP error origin attribution checks."""

import json

from ..store import rows
from .common import LIMIT, ORIGIN_TIP, endpoint_pattern, metadata


class OriginChecksMixin:
    def _origin_reference_samples(self, path, packet, endpoint_available):
        if not endpoint_available:
            return [], []
        samples = rows(
            self.db,
            """SELECT * FROM obs WHERE point=? AND canon=? AND proto='TCP' AND (flags&4)=0 AND eligible
            AND corrected BETWEEN ? AND ? ORDER BY corrected LIMIT 16""",
            [
                path[0],
                packet["canon"],
                (packet["corrected"] or packet["ts"]) - 30,
                (packet["corrected"] or packet["ts"]) + 30,
            ],
        )
        if packet["proto"] in ("ICMP", "ICMPv6"):
            quoted = metadata(packet).get("quoted") or {}
            samples = rows(
                self.db,
                """SELECT * FROM obs WHERE point=? AND src=? AND dst=?
                AND proto='TCP' AND sport=? AND dport=? AND eligible
                AND corrected BETWEEN ? AND ? ORDER BY corrected LIMIT 16""",
                [
                    path[0],
                    packet["src"],
                    packet["dst"],
                    quoted.get("dport"),
                    quoted.get("sport"),
                    (packet["corrected"] or packet["ts"]) - 30,
                    (packet["corrected"] or packet["ts"]) + 30,
                ],
            )
        endpoint_keys = [p["packet_key"] for p in samples]
        local_samples = (
            rows(
                self.db,
                """SELECT * FROM obs WHERE point=? AND eligible
            AND packet_key IN (SELECT unnest(?::VARCHAR[])) ORDER BY corrected LIMIT 16""",
                [packet["point"], endpoint_keys],
            )
            if endpoint_keys
            else []
        )
        return samples, local_samples

    def origins(self):
        if not self.hints["origins"]:
            return
        for segment in self.segments:
            if segment.get("location") == "device_stage":
                continue
            for packet in self.candidates(
                segment,
                "(b.proto='TCP' AND (b.flags&4)>0) OR (b.proto='ICMP' AND json_extract_string(b.path_fields,'$.icmp_type')='3') OR (b.proto='ICMPv6' AND json_extract_string(b.path_fields,'$.icmp_type') IN ('1','2'))",
            ):
                path = (
                    self.topology.forward
                    if segment["direction"] == "forward"
                    else (self.topology.reverse or self.topology.forward[::-1])
                )
                upstream = path[: path.index(segment["point_b"])]
                seen = self.db.execute(
                    "SELECT count(*) FROM obs WHERE point IN (SELECT unnest(?::VARCHAR[])) AND packet_key=?",
                    [upstream, packet["packet_key"]],
                ).fetchone()[0]
                if seen:
                    continue
                endpoint_available = self.has_endpoint(path, segment["direction"])
                samples, local_samples = self._origin_reference_samples(path, packet, endpoint_available)
                pattern = endpoint_pattern(samples, packet)
                comparison_ttls = sorted({p["ttl"] for p in local_samples})
                pattern["ttl_values_at_first_point"] = comparison_ttls
                pattern["ttl_consistent_with_endpoint"] = (
                    packet["ttl"] in comparison_ttls if len(local_samples) >= 3 else None
                )

                why = self.reason(segment, packet["corrected"])
                if segment.get("location") != "device":
                    why = why or "Capture points do not bracket one device; injection source unknown"
                if not packet["eligible"] or packet.get("translation_reason"):
                    why = (
                        packet.get("translation_reason")
                        or packet.get("excluded_reason")
                        or "Unmatchable origin identity"
                    )
                if not endpoint_available:
                    why = "no endpoint-side capture"
                elif pattern["ttl_consistent_with_endpoint"] is True:
                    why = why or "Endpoint-origin TTL pattern is consistent; capture miss cannot be excluded"
                elif pattern["ttl_consistent_with_endpoint"] is None:
                    why = why or "Insufficient matched endpoint references at the first-observation point"
                if pattern["status"] == "unknown":
                    why = why or pattern["reason"]
                vendor = json.loads(packet.get("vendor") or "{}")
                label = "RST" if packet["proto"] == "TCP" else "ICMP unreachable"
                reset = vendor.get("f5ethtrailer.rstcausetxt")
                summary = (
                    f"{label} injected by {segment['device']}"
                    if not why
                    else f"{label} first observed at {self.points[packet['point']].label} ({self.location(segment)}); origin unknown: {why}"
                )
                if reset:
                    summary += f"; F5 reset explanation: {reset}"
                self.add(
                    segment,
                    "reset_origin" if packet["proto"] == "TCP" else "icmp_origin",
                    packet,
                    summary,
                    ORIGIN_TIP,
                    dict(
                        first_point=packet["point"],
                        endpoint_pattern=pattern,
                        quality_reason=why,
                        vendor=vendor,
                    ),
                    not why,
                    [packet, *samples[:7], *local_samples[:7]],
                    severity="high",
                    cause="vendor_reset_evidence" if reset else "unknown",
                )

    def endpoint_origins(self):
        if not self.hints["origins"]:
            return
        for direction, path in (
            ("forward", self.topology.forward),
            ("reverse", self.topology.reverse or self.topology.forward[::-1]),
        ):
            if len(path) < 2:
                continue
            segment = next(
                (s for s in self.segments if s["point_a"] == path[0] and s["direction"] == direction), None
            )
            if not segment:
                continue
            packets = rows(
                self.db,
                """SELECT *,count(*) OVER(PARTITION BY flow,proto) AS origin_count
                FROM integrity_obs WHERE point=? AND direction=? AND ((proto='TCP' AND (flags&4)>0)
                OR (proto='ICMP' AND json_extract_string(path_fields,'$.icmp_type')='3')
                OR (proto='ICMPv6' AND json_extract_string(path_fields,'$.icmp_type') IN ('1','2')))
                QUALIFY row_number() OVER(PARTITION BY flow,proto ORDER BY corrected,frame)=1 LIMIT ?""",
                [path[0], direction, LIMIT],
            )
            endpoint_available = self.has_endpoint(path, direction)
            for packet in packets:
                refs = rows(
                    self.db,
                    "SELECT * FROM obs WHERE point=? AND canon=? AND (flags&4)=0 AND proto='TCP' AND eligible ORDER BY corrected LIMIT 8",
                    [path[0], packet["canon"]],
                )
                label = "RST" if packet["proto"] == "TCP" else "ICMP error"
                self.add(
                    {**segment, "device": self.points[path[0]].device if endpoint_available else None},
                    "reset_origin" if packet["proto"] == "TCP" else "icmp_origin",
                    packet,
                    f"{label} first observed at {self.points[path[0]].label}; "
                    + (
                        "source authenticity unknown"
                        if endpoint_available
                        else "origin unknown: no endpoint-side capture"
                    ),
                    ORIGIN_TIP,
                    dict(
                        count=packet["origin_count"],
                        first_point=path[0],
                        endpoint_pattern=endpoint_pattern(refs if endpoint_available else [], packet),
                        quality_reason=None if endpoint_available else "no endpoint-side capture",
                    ),
                    endpoint_available,
                    [packet, *refs],
                    severity="quality",
                )
