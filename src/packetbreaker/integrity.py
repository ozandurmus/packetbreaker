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

    def changed_pair(self, segment, condition):
        return rows(
            self.db,
            f"""SELECT a AS before_packet,b AS after_packet,count(*) OVER() AS count
            FROM obs a JOIN obs b ON a.packet_key=b.packet_key WHERE a.point=? AND b.point=?
            AND a.direction=? AND a.eligible AND b.eligible AND ({condition})
            ORDER BY a.corrected LIMIT 1""",
            [segment["point_a"], segment["point_b"], segment["direction"]],
        )

    def mtu(self):
        for segment in self.segments:
            if segment.get("location") == "device_stage":
                continue
            for pair in self.changed_pair(segment, "(a.flags&2)>0 AND a.mss>b.mss AND b.mss>0"):
                before, after = pair["before_packet"], pair["after_packet"]
                self.add(
                    segment,
                    "mss_clamping",
                    before,
                    f"MSS clamping at {segment.get('device') or segment['label']}: {before['mss']} → {after['mss']} B",
                    "MSS advertisement reduced between matched SYNs. This is observed clamping, not proof of a path MTU fault.",
                    dict(count=pair["count"], before_mss=before["mss"], after_mss=after["mss"]),
                    True,
                    [before, after],
                )
            losses = rows(
                self.db,
                """SELECT a.flow,min(a.length) AS min_length,count(DISTINCT a.seq) AS lost_ranges,
                first(a ORDER BY a.corrected) AS packet FROM events e JOIN obs a ON a.packet_key=e.packet_key AND a.point=e.point_a
                WHERE e.point_a=? AND e.point_b=? AND e.direction=? AND e.kind IN ('impactful_loss','unrecovered_loss','recovered_loss')
                AND a.proto='TCP' AND a.length BETWEEN 1200 AND 9000
                GROUP BY a.flow HAVING count(DISTINCT a.seq)>=3 LIMIT ?""",
                [segment["point_a"], segment["point_b"], segment["direction"], LIMIT],
            )
            for loss in losses:
                packet = loss["packet"]
                small = rows(
                    self.db,
                    """SELECT a.* FROM obs a WHERE a.point=? AND a.flow=? AND a.direction=?
                    AND a.length>0 AND a.length<? AND EXISTS(SELECT 1 FROM observation_matches m
                    WHERE m.point_a=a.point AND m.point_b=? AND m.key_a=a.packet_key)
                    ORDER BY a.corrected LIMIT 3""",
                    [
                        segment["point_a"],
                        packet["flow"],
                        segment["direction"],
                        loss["min_length"] / 2,
                        segment["point_b"],
                    ],
                )
                if len(small) < 3:
                    continue
                why = self.reason(segment, packet["corrected"])
                if ":" not in packet["src"] and metadata(packet).get("df") is not True:
                    why = why or "IPv4 DF not established"
                feedback = rows(
                    self.db,
                    """SELECT * FROM obs o WHERE proto IN ('ICMP','ICMPv6')
                    AND ((json_extract_string(path_fields,'$.icmp_type')='3' AND json_extract_string(path_fields,'$.icmp_code')='4')
                         OR (proto='ICMPv6' AND json_extract_string(path_fields,'$.icmp_type')='2'))
                    AND EXISTS(SELECT 1 FROM obs p WHERE p.flow=?
                       AND p.src=json_extract_string(o.path_fields,'$.quoted.src')
                       AND p.dst=json_extract_string(o.path_fields,'$.quoted.dst')
                       AND p.sport=try_cast(json_extract_string(o.path_fields,'$.quoted.sport') AS INTEGER)
                       AND p.dport=try_cast(json_extract_string(o.path_fields,'$.quoted.dport') AS INTEGER)
                       AND p.raw_seq=try_cast(json_extract_string(o.path_fields,'$.quoted.seq') AS BIGINT))
                    ORDER BY corrected LIMIT 4""",
                    [packet["flow"]],
                )
                name = segment.get("device") or self.points[segment["point_a"]].device
                self.add(
                    segment,
                    "mtu_black_hole",
                    packet,
                    f"MTU/PMTUD black-hole pattern after {name}, toward {self.points[segment['point_b']].label}; cause unknown"
                    + (f" ({why})" if why else ""),
                    "At least three distinct large TCP ranges disappear while three smaller payload segments of the same flow pass. DF/IPv6 and quoted-flow ICMP feedback are shown. Size-selective policy or capture loss can mimic MTU trouble; missing ICMP is not proof it was never sent.",
                    dict(
                        count=loss["lost_ranges"],
                        large_min_bytes=loss["min_length"],
                        small_passed=len(small),
                        df=metadata(packet).get("df"),
                        icmp_feedback="present" if feedback else "not observed; generation/delivery unknown",
                        advertised_mtu=[metadata(p).get("icmp_mtu") for p in feedback],
                        quality_reason=why,
                    ),
                    not why,
                    [packet, *small, *feedback],
                    severity="high",
                )

    def path_checks(self):
        for segment in self.segments:
            if segment.get("location") == "device_stage":
                continue
            a, b = self.points[segment["point_a"]], self.points[segment["point_b"]]
            if "full_proxy" in (a.translation, b.translation):
                continue
            conditions = [
                (
                    "ttl_path",
                    "a.ttl-b.ttl>1 OR a.ttl<b.ttl",
                    "TTL/hop-limit path deviation",
                    "A matched packet lost more than one TTL step or increased TTL between drawn adjacent points. Extra routing, a tunnel, TTL rewrite or a loop is possible; this alone cannot distinguish them.",
                ),
                (
                    "dscp_remark",
                    "a.dscp<>b.dscp",
                    "DSCP remarking",
                    "DSCP changed between matched packets. This is observed remarking, not necessarily a fault.",
                ),
                (
                    "option_stripping",
                    "a.caplen=a.wirelen AND b.caplen=b.wirelen AND ((json_extract_string(a.path_fields,'$.sack_permitted')='true' AND json_extract_string(b.path_fields,'$.sack_permitted')='false') OR (json_extract_string(a.path_fields,'$.window_scale') IS NOT NULL AND json_extract_string(b.path_fields,'$.window_scale') IS NULL) OR (json_extract_string(a.path_fields,'$.timestamp_value') IS NOT NULL AND json_extract_string(b.path_fields,'$.timestamp_value') IS NULL))",
                    "TCP option stripping",
                    "A decoded SACK-permitted, window-scale or timestamp option present upstream is absent downstream in a complete matched packet. Expected SYN-only option absence on later packets is never compared.",
                ),
            ]
            for kind, condition, label, tooltip in conditions:
                for pair in self.changed_pair(segment, condition):
                    before, after = pair["before_packet"], pair["after_packet"]
                    self.add(
                        segment,
                        kind,
                        before,
                        f"{label} at {segment.get('device') or segment['label']}",
                        tooltip,
                        dict(
                            count=pair["count"],
                            before=dict(ttl=before["ttl"], dscp=before["dscp"], options=metadata(before)),
                            after=dict(ttl=after["ttl"], dscp=after["dscp"], options=metadata(after)),
                        ),
                        True,
                        [before, after],
                    )
        handled = set()
        for segment in self.segments:
            point = segment["point_a"]
            if point in handled:
                continue
            handled.add(point)
            duplicate = rows(
                self.db,
                "SELECT *,count(*) OVER() AS duplicate_count FROM obs WHERE point=? AND excluded_reason='span_duplicate' ORDER BY corrected LIMIT 1",
                [point],
            )
            for packet in duplicate:
                self.add(
                    segment,
                    "capture_duplicate",
                    packet,
                    f"SPAN/double-capture pattern at {self.points[point].device}",
                    "Byte-identical complete frames at the same capture point within the configured microsecond threshold are capture duplicates. Wire-level duplication inside that resolution cannot be distinguished.",
                    dict(count=packet["duplicate_count"], duplicate_us=self.topology.duplicate_us),
                    True,
                    severity="quality",
                )
            repeat = rows(
                self.db,
                """SELECT a AS first_packet,b AS repeat_packet FROM obs a JOIN obs b
                ON a.point=b.point AND a.signature=b.signature AND a.canon=b.canon AND a.frame<b.frame
                WHERE a.point=? AND a.eligible AND b.eligible AND a.proto='TCP' AND a.length>0
                AND a.ttl>b.ttl AND a.payload_hash=b.payload_hash AND b.ts-a.ts BETWEEN 0 AND 1
                ORDER BY a.corrected LIMIT 1""",
                [point],
            )
            for pair in repeat:
                packet = pair["first_packet"]
                self.add(
                    segment,
                    "duplication",
                    packet,
                    f"Repeated packet with falling TTL at {self.points[point].device}; loop or network duplication suspected",
                    "Same tuple, sequence identity and payload prefix reappeared with lower TTL. It is not a byte-identical SPAN duplicate; TTL rewriting and retransmission remain alternatives, so root cause is unknown.",
                    dict(ttl_before=packet["ttl"], ttl_after=pair["repeat_packet"]["ttl"]),
                    False,
                    [packet, pair["repeat_packet"]],
                )
            # Exact-byte repeats outside SPAN tolerance still cannot prove wire duplication vs retransmission.
            repeat = rows(
                self.db,
                """SELECT a AS first_packet,b AS repeat_packet FROM obs a JOIN obs b
                ON a.point=b.point AND a.frame_hash=b.frame_hash AND a.frame<b.frame
                WHERE a.point=? AND a.eligible AND b.eligible AND a.caplen=a.wirelen AND b.caplen=b.wirelen
                AND b.ts-a.ts>? AND b.ts-a.ts<0.001 ORDER BY a.corrected LIMIT 1""",
                [point, self.topology.duplicate_us / 1e6],
            )
            for pair in repeat:
                self.add(
                    segment,
                    "duplication",
                    pair["first_packet"],
                    f"Possible packet duplication at {self.points[point].device}; cause unknown",
                    "Identical complete bytes repeat outside the SPAN tolerance but within 1 ms. Timing alone cannot distinguish network duplication, retransmission, or a slower capture mirror.",
                    supported=False,
                    packets=[pair["first_packet"], pair["repeat_packet"]],
                )
        if self.topology.reverse:
            for point in set(self.topology.forward) - set(self.topology.reverse):
                segment = next(
                    (s for s in self.segments if s["point_a"] == point and s["direction"] == "forward"), None
                )
                if not segment:
                    continue
                packets = rows(
                    self.db,
                    """SELECT f AS forward_packet,r AS return_packet FROM obs f JOIN obs r ON f.flow=r.flow
                    WHERE f.point=? AND f.direction='forward' AND f.eligible AND r.eligible AND r.direction='reverse'
                    AND r.point IN (SELECT unnest(?::VARCHAR[]))
                    AND NOT EXISTS(SELECT 1 FROM obs q WHERE q.point=f.point AND q.flow=f.flow AND q.direction='reverse')
                    ORDER BY f.corrected,r.corrected LIMIT 1""",
                    [point, self.topology.reverse],
                )
                for pair in packets:
                    packet = pair["forward_packet"]
                    self.add(
                        segment,
                        "asymmetric_routing",
                        packet,
                        f"Asymmetric return bypasses {self.points[point].device} in the configured path",
                        "Forward traffic is observed here; the same flow returns at a different configured point and no return packet is captured here. This supports the declared asymmetric path, not a device fault; hidden capture loss can mimic absence.",
                        dict(bypassed_point=point, return_point=pair["return_packet"]["point"]),
                        True,
                        [packet, pair["return_packet"]],
                        severity="quality",
                    )


def analyze_integrity(db, topology, segments, coverage, models, start, end):
    checks = Checks(db, topology, segments, coverage, models, start, end)
    checks.origins()
    checks.payload_changes()
    checks.downstream_only()
    checks.mtu()
    checks.path_checks()
    return checks.findings, checks.notes
