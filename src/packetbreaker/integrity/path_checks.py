"""MTU/MSS, header field mutation, duplication, and asymmetric routing checks."""

from itertools import groupby

from ..store import rows
from .common import LIMIT, duplicate_pairs, metadata


class PathChecksMixin:
    def mtu(self):
        for segment in self.segments:
            if segment.get("location") == "device_stage":
                continue
            for pair in (
                self.changed_pair(segment, "(a.flags&2)>0 AND a.mss>b.mss AND b.mss>0")
                if self.hints["mss"]
                else []
            ):
                before, after = pair["before_packet"], pair["after_packet"]
                self.add(
                    segment,
                    "mss_clamping",
                    before,
                    f"MSS clamping at {self.location(segment)}: {before['mss']} → {after['mss']} B",
                    "MSS advertisement reduced between matched SYNs. This is observed clamping, not proof of a path MTU fault.",
                    dict(count=pair["count"], before_mss=before["mss"], after_mss=after["mss"]),
                    True,
                    [before, after],
                )
            if not self.hints["large"]:
                continue
            losses = rows(
                self.db,
                """SELECT a.flow,min(least(a.length,coalesce(e.missing_bytes,a.length))) AS min_length,count(DISTINCT a.seq) AS lost_ranges,
                first(a ORDER BY a.corrected) AS packet,list(DISTINCT a.frame) AS large_frames FROM events e JOIN obs a ON a.packet_key=e.packet_key AND a.point=e.point_a
                WHERE e.point_a=? AND e.point_b=? AND e.direction=? AND e.kind IN ('impactful_loss','unrecovered_loss','recovered_loss')
                AND a.proto='TCP' AND a.length BETWEEN 1200 AND 9000
                AND coalesce(e.missing_bytes,a.length)>=greatest(1200,.9*coalesce(
                    (SELECT min(m.mss) FROM obs m WHERE m.flow=a.flow AND m.direction<>a.direction AND m.mss>0),
                    CASE WHEN contains(a.src,':') THEN 1440 ELSE 1460 END))
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
                name = self.location(segment)
                large_packets = rows(
                    self.db,
                    "SELECT * FROM obs WHERE point=? AND frame IN (SELECT unnest(?::BIGINT[])) ORDER BY corrected",
                    [segment["point_a"], loss["large_frames"][:3]],
                )
                self.add(
                    segment,
                    "mtu_black_hole",
                    packet,
                    f"MTU/PMTUD black-hole pattern at {name}; cause unknown" + (f" ({why})" if why else ""),
                    "At least three distinct near-MSS TCP ranges disappear (missing bytes, not the enclosing GRO frame size) while three smaller payload segments of the same flow pass. DF/IPv6 and quoted-flow ICMP feedback are shown. Size-selective policy or capture loss can mimic MTU trouble; missing ICMP is not proof it was never sent.",
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
                    [*large_packets, *small, *feedback],
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
                if kind == "ttl_path" and (a.stage_capture or b.stage_capture):
                    continue
                if (
                    kind == "dscp_remark"
                    and not self.hints["dscp"]
                    or kind == "option_stripping"
                    and not self.hints["options"]
                ):
                    continue
                for pair in self.changed_pair(segment, condition):
                    before, after = pair["before_packet"], pair["after_packet"]
                    self.add(
                        segment,
                        kind,
                        before,
                        f"{label} at {self.location(segment)}",
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
            repeats = self.repeats.get(point, {})
            if not repeats.get("identical") and not repeats.get("repeated"):
                continue
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
            repeat = duplicate_pairs(self.db, point, self.topology.duplicate_us, "loop")
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
            repeat = duplicate_pairs(self.db, point, self.topology.duplicate_us, "identical")
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
        self.asymmetric_paths()

    def asymmetric_paths(self):
        forward, reverse = self.topology.forward, self.topology.reverse
        if not reverse:
            return
        targets = []
        # Consolidate an entire bypassed device instead of blaming every adjacent edge.
        for device, group in groupby(enumerate(forward), key=lambda entry: self.points[entry[1]].device):
            entries = list(group)
            missing = [p for _, p in entries]
            lo, hi = entries[0][0], entries[-1][0]
            if lo == 0 or hi == len(forward) - 1 or any(p in reverse for p in missing):
                continue
            segment = next(
                (s for s in self.segments if s["direction"] == "forward" and s["point_a"] == missing[0]), None
            )
            if segment:
                targets.append(({**segment, "device": device}, missing, [forward[lo - 1], forward[hi + 1]]))
        for segment in self.segments:
            a, b = segment["point_a"], segment["point_b"]
            if (
                segment["direction"] == "forward"
                and segment.get("location") == "link"
                and not (self.points[a].stage_capture or self.points[b].stage_capture)
                and a in reverse
                and b in reverse
            ):
                if reverse.index(a) > reverse.index(b) + 1:
                    targets.append((segment, [], [a, b]))
        for segment, missing, anchors in targets:
            a, b = anchors
            if a not in reverse or b not in reverse or reverse.index(b) >= reverse.index(a):
                continue
            alternative = reverse[reverse.index(b) + 1 : reverse.index(a)]
            if not alternative:
                continue
            point = missing[0] if missing else segment["point_a"]
            pairs = rows(
                self.db,
                """WITH forward_first AS (
                SELECT * FROM integrity_obs WHERE point=? AND direction='forward' AND eligible
                QUALIFY row_number() OVER(PARTITION BY flow ORDER BY corrected,frame)=1),
                return_first AS (
                SELECT * FROM integrity_obs WHERE point IN (SELECT unnest(?::VARCHAR[])) AND direction='reverse' AND eligible
                QUALIFY row_number() OVER(PARTITION BY flow ORDER BY corrected,point,frame)=1)
                SELECT f AS forward_packet,r AS return_packet FROM forward_first f JOIN return_first r USING(flow)
                WHERE NOT EXISTS(SELECT 1 FROM integrity_obs q WHERE q.flow=f.flow AND q.direction='reverse' AND q.point IN (SELECT unnest(?::VARCHAR[])))
                AND (SELECT count(DISTINCT point) FROM integrity_obs q WHERE q.flow=f.flow AND q.direction='reverse' AND q.eligible AND q.point IN (SELECT unnest(?::VARCHAR[])))=2
                ORDER BY f.corrected,r.corrected LIMIT 1""",
                [point, alternative, missing, anchors],
            )
            for pair in pairs:
                self.add(
                    segment,
                    "asymmetric_routing",
                    pair["forward_packet"],
                    f"Asymmetric return bypasses {self.location(segment)} in the configured path",
                    "Forward evidence plus same-flow return evidence on the declared alternate path and both bounding points. A bypassed device is reported once; a detoured inter-device edge stays a link, not a device fault.",
                    dict(
                        bypassed_points=missing,
                        return_point=pair["return_packet"]["point"],
                        bounding_points=anchors,
                    ),
                    True,
                    [pair["forward_packet"], pair["return_packet"]],
                    severity="quality",
                )
