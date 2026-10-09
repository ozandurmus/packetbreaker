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

    def payload_changes(self):
        for segment in self.segments:
            a, b = self.points[segment["point_a"]], self.points[segment["point_b"]]
            if a.device != b.device or any(
                p.translation == "full_proxy" or p.payload_transform != "none" for p in (a, b)
            ):
                continue
            candidates = rows(
                self.db,
                """SELECT * FROM (SELECT a AS before_packet,b AS after_packet
                FROM obs a JOIN obs b ON a.canon=b.canon AND a.seq=b.seq AND a.ack=b.ack
                AND a.flags=b.flags AND a.length=b.length AND a.direction=b.direction
                WHERE a.point=? AND b.point=? AND a.direction=? AND a.proto='TCP' AND a.length>0
                AND a.eligible AND b.eligible AND a.translation_reason IS NULL AND b.translation_reason IS NULL
                AND abs(a.corrected-b.corrected)<=?
                QUALIFY count(*) OVER(PARTITION BY a.frame)=1 AND count(*) OVER(PARTITION BY b.frame)=1
                 ) paired WHERE json_extract_string(before_packet.path_fields,'$.payload_complete')='true'
                AND json_extract_string(after_packet.path_fields,'$.payload_complete')='true'
                AND json_extract_string(before_packet.path_fields,'$.payload_sha256')<>json_extract_string(after_packet.path_fields,'$.payload_sha256')
                ORDER BY before_packet.corrected LIMIT ?""",
                [a.id, b.id, segment["direction"], self.topology.match_window_ms / 1000, LIMIT + 1],
            )
            if len(candidates) > LIMIT:
                self.notes.append(
                    f"{segment['id']}: payload comparison sample limited to {LIMIT} unique pairs"
                )
            for pair in candidates[:LIMIT]:
                before, after = pair["before_packet"], pair["after_packet"]
                x, y = metadata(before), metadata(after)
                if (
                    not x.get("payload_complete")
                    or not y.get("payload_complete")
                    or x.get("payload_sha256") == y.get("payload_sha256")
                ):
                    continue
                why = self.reason(segment, before["corrected"])
                self.add(
                    segment,
                    "payload_modified",
                    before,
                    f"Payload changed across {a.device}"
                    if not why
                    else f"Payload comparison unknown at {a.device}: {why}",
                    "Unique canonical tuple/SEQ/ACK/flags/length pair within the match window; complete payload hashes differ. Ambiguous retries and offload boundaries are excluded. A change does not establish malicious intent.",
                    dict(
                        before_sha256=x["payload_sha256"],
                        after_sha256=y["payload_sha256"],
                        quality_reason=why,
                    ),
                    not why,
                    [before, after],
                    severity="high",
                )

    def downstream_only(self):
        modified = {
            (e["point"], e["frame"])
            for f in self.findings
            if f["type"] == "payload_modified"
            for e in f["evidence"]
        }
        for segment in self.segments:
            path = (
                self.topology.forward
                if segment["direction"] == "forward"
                else (self.topology.reverse or self.topology.forward[::-1])
            )
            if segment["point_b"] not in path or segment.get("location") == "device_stage":
                continue
            upstream = path[: path.index(segment["point_b"])]
            for packet in self.candidates(segment, "b.eligible AND b.proto='TCP' AND b.length>0"):
                if (packet["point"], packet["frame"]) in modified:
                    continue
                if self.db.execute(
                    "SELECT count(*) FROM obs WHERE point IN (SELECT unnest(?::VARCHAR[])) AND packet_key=?",
                    [upstream, packet["packet_key"]],
                ).fetchone()[0]:
                    continue
                why = self.reason(segment, packet["corrected"])
                self.add(
                    segment,
                    "downstream_packet",
                    packet,
                    f"Downstream-only packet at {self.points[packet['point']].label}; origin unknown"
                    + (
                        f": {why}"
                        if why
                        else "; injection and capture miss cannot be separated by absence alone"
                    ),
                    "Packet observed downstream without a matching upstream occurrence in the configured path. Unreported capture loss, translation or alternate routing can explain it; this is not confirmed malicious injection.",
                    dict(quality_reason=why),
                    False,
                )


def analyze_integrity(db, topology, segments, coverage, models, start, end):
    checks = Checks(db, topology, segments, coverage, models, start, end)
    checks.origins()
    checks.payload_changes()
    checks.downstream_only()
    return checks.findings, checks.notes
