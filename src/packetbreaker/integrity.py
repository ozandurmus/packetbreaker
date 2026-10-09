"""Bounded path checks. Positive field changes and absence-based hypotheses stay distinct."""

import json
from .evidence import evidence
from .headlines import time_labels
from .store import rows

LIMIT = 200
ORIGIN_TIP = (
    "Origin is the first observed point along the configured direction, not the lowest raw timestamp. "
    "Device injection requires a paired ingress/egress, usable clock and coverage, no upstream occurrence, "
    "and endpoint reference packets. TTL/IP ID are supporting patterns, never authentication. "
    "Unreported capture loss or an unmodelled alternate path can mimic injection; policy/IPS cause is unknown without device evidence."
)


def metadata(packet):
    return json.loads(packet.get("path_fields") or "{}")


def endpoint_pattern(samples, packet):
    """Describe evidence, without treating constant/zero IP IDs as fingerprints."""
    if len(samples) < 3:
        return dict(status="unknown", reason="Fewer than three endpoint reference packets")
    ttls = sorted({p["ttl"] for p in samples})
    ids = [p["ipid"] for p in samples]
    pattern = "unknown" if ":" in packet["src"] else "constant" if len(set(ids)) == 1 else "varying"
    return dict(
        status="observed",
        ttl_values=ttls,
        candidate_ttl=packet["ttl"],
        ttl_matches=packet["ttl"] in ttls,
        ip_id_pattern=pattern,
        candidate_ip_id=packet["ipid"] if ":" not in packet["src"] else None,
        ip_id_note="Constant, randomized and per-destination IDs cannot authenticate origin",
    )


class Checks:
    def __init__(self, db, topology, segments, coverage, models, start, end):
        self.db, self.topology, self.segments = db, topology, segments
        self.points = {p.id: p for p in topology.points}
        self.coverage = {c["point"]: c for c in coverage}
        self.models = models
        self.start, self.end = start, end
        self.findings = []
        self.notes = []
        self.inventories = {
            cid: json.loads(inv) for cid, inv in db.execute("SELECT id,inventory FROM captures").fetchall()
        }

    def reason(self, segment, ts):
        if ts is None:
            return "Clock correction unavailable"
        if segment.get("reason"):
            return segment["reason"]
        for point in (segment["point_a"], segment["point_b"]):
            model = self.models[self.points[point].capture_id]
            if model.uncertainty is None:
                return "Clock uncertainty unverified"
            coverage = self.coverage.get(point, {})
            margin = self.topology.match_window_ms / 1000 + model.uncertainty
            if (
                coverage.get("start") is None
                or not coverage["start"] + margin <= ts <= coverage["end"] - margin
            ):
                return "Coverage does not bracket the complete matching window"
            inventory = self.inventories[self.points[point].capture_id]
            if any(
                inventory.get(k)
                for k in ("ifdrop", "osdrop", "truncated_tail", "damaged_tail", "invalid_timestamps")
            ):
                return "Capture quality prevents absence-based attribution"
        return None

    def refs(self, packets):
        selected = list(dict.fromkeys((p["point"], p["frame"]) for p in packets))[:16]
        if not selected:
            return []
        predicate = " OR ".join("(o.point=? AND o.frame=?)" for _ in selected)
        return evidence(self.db, predicate, [v for pair in selected for v in pair], 16, _expand_ranges=False)

    def add(
        self,
        segment,
        kind,
        packet,
        summary,
        tooltip,
        metrics=None,
        supported=True,
        packets=None,
        severity="low",
        cause="unknown",
    ):
        ts = packet.get("corrected") or packet["ts"]
        if self.start is not None and ts < self.start or self.end is not None and ts > self.end:
            return
        self.findings.append(
            dict(
                id=f"integrity:{segment['id']}:{kind}:{packet['frame']}:{len(self.findings)}",
                type=kind,
                hop=segment["id"],
                device=segment.get("device"),
                direction=segment["direction"],
                severity=severity if supported else "unknown",
                confidence="supported" if supported else "unknown",
                time_range=[ts, ts],
                time_labels=time_labels(ts, self.topology.report_timezone),
                metrics={"count": 1, **(metrics or {})},
                summary=summary,
                headline=summary,
                tooltip=tooltip,
                cause=cause,
                evidence=self.refs(packets or [packet]),
                evidence_note="Observed frame filters; absence is conditional on capture coverage",
                clock_caveat="Times are clock-corrected estimates; see segment clock uncertainty",
            )
        )

    def candidates(self, segment, condition):
        data = rows(
            self.db,
            f"""SELECT b.* FROM obs b WHERE b.point=? AND b.direction=? AND ({condition})
            AND NOT EXISTS(SELECT 1 FROM observation_matches m WHERE m.point_a=? AND m.point_b=b.point AND m.key_b=b.packet_key)
            ORDER BY b.corrected NULLS LAST,b.frame LIMIT ?""",
            [segment["point_b"], segment["direction"], segment["point_a"], LIMIT + 1],
        )
        if len(data) > LIMIT:
            self.notes.append(f"{segment['id']}: candidate display bounded to {LIMIT}; more candidates exist")
        return data[:LIMIT]

    def origins(self):
        for segment in self.segments:
            if segment.get("location") != "device":
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
                pattern = endpoint_pattern(samples, packet)
                why = self.reason(segment, packet["corrected"])
                if not packet["eligible"] or packet.get("translation_reason"):
                    why = (
                        packet.get("translation_reason")
                        or packet.get("excluded_reason")
                        or "Unmatchable origin identity"
                    )
                if pattern["status"] == "unknown":
                    why = why or pattern["reason"]
                vendor = json.loads(packet.get("vendor") or "{}")
                label = "RST" if packet["proto"] == "TCP" else "ICMP unreachable"
                reset = vendor.get("f5ethtrailer.rstcausetxt")
                summary = (
                    f"{label} injected by {segment['device']}"
                    if not why
                    else f"{label} first observed at {self.points[packet['point']].label}; origin unknown: {why}"
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
                    [packet, *samples],
                    severity="high",
                    cause="vendor_reset_evidence" if reset else "unknown",
                )


def analyze_integrity(db, topology, segments, coverage, models, start, end):
    checks = Checks(db, topology, segments, coverage, models, start, end)
    checks.origins()
    return checks.findings, checks.notes
