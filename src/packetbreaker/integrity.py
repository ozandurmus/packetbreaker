"""Bounded path checks. Positive field changes and absence-based hypotheses stay distinct."""

import json
from .evidence import evidence
from .headlines import time_labels
from .store import rows

LIMIT = 200
ORIGIN_TIP = (
    "Origin is the first observed point along the configured direction, not the lowest raw timestamp. "
    "Device injection requires a paired ingress/egress, usable clock and coverage, no upstream occurrence, "
    "and endpoint reference packets. Endpoint-consistent TTL at the same capture point leaves capture miss unresolved. TTL/IP ID are supporting patterns, never authentication. "
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
        candidate_id_steps=[(packet["ipid"] - p["ipid"]) % 65536 for p in samples[-3:]]
        if ":" not in packet["src"]
        else None,
        endpoint_id_steps=[(b - a) % 65536 for a, b in zip(ids, ids[1:])]
        if ":" not in packet["src"]
        else None,
        ip_id_note="Constant, randomized and per-destination IDs cannot authenticate origin",
    )


def link_modified_payloads(db, topology, models):
    """Index unique header-matched payload changes once for matching and findings."""
    points = {p.id: p for p in topology.points}
    edges = [
        (a, b, direction)
        for direction, path in (
            ("forward", topology.forward),
            ("reverse", topology.reverse or topology.forward[::-1]),
        )
        for a, b in zip(path, path[1:])
        if "full_proxy" not in (points[a].translation, points[b].translation)
    ]
    db.execute(
        "CREATE OR REPLACE TEMP TABLE modified_payload_pairs(point_a VARCHAR,point_b VARCHAR,direction VARCHAR,frame_a BIGINT,frame_b BIGINT)"
    )
    db.execute("""CREATE OR REPLACE TEMP TABLE modified_headers AS SELECT point,canon,seq,ack,flags,length,direction,frame,corrected,
        json_extract_string(path_fields,'$.payload_complete') AS complete,json_extract_string(path_fields,'$.payload_sha256') AS digest
        FROM obs WHERE proto='TCP' AND length>0 AND eligible AND translation_reason IS NULL""")
    # Narrow rows, one edge at a time; keep uniqueness before filtering changed hashes.
    for point_a, point_b, direction in edges:
        db.execute(
            """INSERT INTO modified_payload_pairs WITH pairs AS (
            SELECT a.frame AS frame_a,b.frame AS frame_b,a.complete AS complete_a,b.complete AS complete_b,
                a.digest AS digest_a,b.digest AS digest_b
            FROM (SELECT * FROM modified_headers WHERE point=? AND direction=?) a
            JOIN (SELECT * FROM modified_headers WHERE point=? AND direction=?) b
            ON a.canon=b.canon AND a.seq=b.seq AND a.ack=b.ack AND a.flags=b.flags AND a.length=b.length
            WHERE abs(a.corrected-b.corrected)<=?
            QUALIFY count(*) OVER(PARTITION BY a.frame)=1 AND count(*) OVER(PARTITION BY b.frame)=1)
            SELECT ?,?,?,frame_a,frame_b FROM pairs WHERE complete_a='true' AND complete_b='true' AND digest_a<>digest_b""",
            [
                point_a,
                direction,
                point_b,
                direction,
                topology.match_window_ms / 1000,
                point_a,
                point_b,
                direction,
            ],
        )
    db.execute("DROP TABLE modified_headers")
    changed = set(db.execute("SELECT DISTINCT point_a,point_b FROM modified_payload_pairs").fetchall())
    for a, b, _ in edges:
        if (a, b) not in changed or any(models[points[p].capture_id].uncertainty is None for p in (a, b)):
            continue
        # Read current keys at each edge so successive mutations remain one physical occurrence.
        db.execute(
            """UPDATE obs SET packet_key=paired.before_key FROM (
            SELECT a.packet_key AS before_key,b.packet_key AS after_key FROM modified_payload_pairs m
            JOIN obs a ON a.point=m.point_a AND a.frame=m.frame_a
            JOIN obs b ON b.point=m.point_b AND b.frame=m.frame_b WHERE m.point_a=? AND m.point_b=?) paired
            WHERE obs.packet_key=paired.after_key""",
            [a, b],
        )


def duplicate_pairs(db, point, duplicate_us, mode):
    # Compare adjacent repeats, never all pairs of a long constant-ID/ACK stream.
    if mode == "loop":
        partition = "canon,signature,payload_hash"
        eligible = "eligible AND proto='TCP' AND length>0"
        condition = "previous_ttl>ttl AND ts-previous_ts BETWEEN 0 AND 1"
    elif mode == "identical":
        partition = "frame_hash"
        eligible = "eligible AND caplen=wirelen AND frame_hash IS NOT NULL"
        condition = "ts-previous_ts>? AND ts-previous_ts<0.001"
    else:
        raise ValueError("Unknown duplication check")
    return rows(
        db,
        f"""WITH sequenced AS (
        SELECT point,frame,ts,ttl,lag(frame) OVER w AS previous_frame,
        lag(ts) OVER w AS previous_ts,lag(ttl) OVER w AS previous_ttl
        FROM integrity_obs WHERE point=? AND {eligible}
        WINDOW w AS (PARTITION BY {partition} ORDER BY ts,frame)),
        candidate AS (SELECT * FROM sequenced WHERE {condition} ORDER BY ts,frame LIMIT 1)
        SELECT a AS first_packet,b AS repeat_packet FROM candidate c
        JOIN obs a ON a.point=c.point AND a.frame=c.previous_frame
        JOIN obs b ON b.point=c.point AND b.frame=c.frame""",
        [point, duplicate_us / 1e6] if mode == "identical" else [point],
    )


class Checks:
    def __init__(self, db, topology, segments, coverage, models, start, end):
        self.db, self.topology, self.segments = db, topology, segments
        self.points = {p.id: p for p in topology.points}
        self.coverage = {c["point"]: c for c in coverage}
        self.models = models
        self.start, self.end = start, end
        db.execute(
            "CREATE OR REPLACE TEMP TABLE integrity_window AS SELECT ?::DOUBLE AS start,?::DOUBLE AS stop",
            [start, end],
        )
        db.execute(
            "CREATE OR REPLACE TEMP VIEW integrity_obs AS SELECT o.* FROM obs o,integrity_window w WHERE (w.start IS NULL OR coalesce(o.corrected,o.ts)>=w.start) AND (w.stop IS NULL OR coalesce(o.corrected,o.ts)<w.stop)"
        )
        self.hints = rows(
            db,
            """SELECT bool_or((flags&4)>0 OR proto IN ('ICMP','ICMPv6')) AS origins,
            count(DISTINCT dscp)>1 AS dscp, max(mss)>0 AS mss,
            bool_or(json_extract_string(path_fields,'$.tcp_options')<>'') AS options,
            bool_or(length>=1200) AS large FROM obs""",
        )[0]
        self.repeats = {
            r["point"]: r
            for r in rows(
                db,
                """SELECT point,
            count(*)-count(DISTINCT frame_hash) AS identical,
            count(*)-count(DISTINCT canon || signature) AS repeated,
            count(*) FILTER(WHERE excluded_reason='span_duplicate') AS span FROM obs GROUP BY point""",
            )
        }
        db.execute(
            "CREATE OR REPLACE TEMP TABLE integrity_edges AS SELECT unnest(?::VARCHAR[]) AS id,unnest(?::VARCHAR[]) AS point_a,unnest(?::VARCHAR[]) AS point_b,unnest(?::VARCHAR[]) AS direction",
            [[s[k] for s in segments] for k in ("id", "point_a", "point_b", "direction")],
        )
        self.candidate_cache = {}
        self.change_cache = {}
        self.findings = []
        self.notes = []
        self.inventories = {
            cid: json.loads(inv) for cid, inv in db.execute("SELECT id,inventory FROM captures").fetchall()
        }

    def location(self, segment):
        return (
            segment.get("device")
            or f"link between {self.points[segment['point_a']].label} and {self.points[segment['point_b']].label}"
        )

    def has_endpoint(self, path, direction):
        return bool(path) and self.points[path[0]].kind == ("Client" if direction == "forward" else "Server")

    def reason(self, segment, ts):
        if ts is None:
            return "Clock correction unavailable"
        if segment.get("reason"):
            return segment["reason"]
        for point in (segment["point_a"], segment["point_b"]):
            model = self.models[self.points[point].capture_id]
            if model.uncertainty is None:
                return "Clock uncertainty unverified"
            if self.points[point].vendor == "checkpoint" and not self.points[point].inspection_complete:
                return "Check Point inspection coverage is not attested complete"
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
                for k in ("ifdrop", "osdrop", "truncated_tail", "damaged_tail", "timestamp_excluded_counts")
            ):
                return "Capture quality prevents absence-based attribution"
        return None

    def refs(self, packets):
        selected = list(dict.fromkeys((p["point"], p["frame"]) for p in packets))[:16]
        if not selected:
            return []
        predicate = " OR ".join("(o.point=? AND o.frame=?)" for _ in selected)
        refs = evidence(self.db, predicate, [v for pair in selected for v in pair], 16, _expand_ranges=False)
        order = {pair: i for i, pair in enumerate(selected)}
        return sorted(refs, key=lambda r: order.get((r["point"], r["frame"]), len(order)))

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
        if condition not in self.candidate_cache:
            data = rows(
                self.db,
                f"""SELECT e.id,b AS packet FROM integrity_edges e JOIN integrity_obs b
                ON b.point=e.point_b AND b.direction=e.direction WHERE ({condition})
                AND NOT EXISTS(SELECT 1 FROM observation_matches m WHERE m.point_a=e.point_a AND m.point_b=b.point AND m.key_b=b.packet_key)
                QUALIFY row_number() OVER(PARTITION BY e.id ORDER BY b.corrected NULLS LAST,b.frame)<=?""",
                [LIMIT + 1],
            )
            grouped = {}
            for row in data:
                grouped.setdefault(row["id"], []).append(row["packet"])
            self.candidate_cache[condition] = grouped
        data = self.candidate_cache[condition].get(segment["id"], [])
        if len(data) > LIMIT:
            self.notes.append(f"{segment['id']}: candidate display bounded to {LIMIT}; more candidates exist")
        return data[:LIMIT]

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
                endpoint_available = self.has_endpoint(path, segment["direction"])
                if not endpoint_available:
                    samples = []
                # Compare TTL at the first-observation point, using endpoint packets that actually traversed it.
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

    def payload_changes(self):
        for segment in self.segments:
            a, b = self.points[segment["point_a"]], self.points[segment["point_b"]]
            if any(p.translation == "full_proxy" for p in (a, b)) or (
                a.device == b.device and any(p.payload_transform != "none" for p in (a, b))
            ):
                continue
            candidates = rows(
                self.db,
                """SELECT a AS before_packet,b AS after_packet FROM modified_payload_pairs m
                JOIN integrity_obs a ON a.point=m.point_a AND a.frame=m.frame_a
                JOIN integrity_obs b ON b.point=m.point_b AND b.frame=m.frame_b
                WHERE m.point_a=? AND m.point_b=? AND m.direction=? AND a.eligible AND b.eligible
                    AND a.translation_reason IS NULL AND b.translation_reason IS NULL
                ORDER BY a.corrected LIMIT ?""",
                [a.id, b.id, segment["direction"], LIMIT + 1],
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
                    f"Payload changed across {self.location(segment)}"
                    if not why
                    else f"Payload comparison unknown at {self.location(segment)}: {why}",
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
            if segment.get("reason"):
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
        key = (segment["id"], condition)
        if key not in self.change_cache:
            pair = rows(
                self.db,
                f"""SELECT arg_min(a.frame,(a.corrected,a.frame)) AS frame_a,
                arg_min(b.frame,(a.corrected,a.frame)) AS frame_b,count(*) AS count
                FROM (SELECT * FROM integrity_obs WHERE point=? AND direction=? AND eligible) a
                JOIN (SELECT * FROM integrity_obs WHERE point=? AND direction=? AND eligible) b USING(packet_key)
                WHERE ({condition})""",
                [segment["point_a"], segment["direction"], segment["point_b"], segment["direction"]],
            )[0]
            item = None
            if pair["count"]:
                item = dict(
                    id=segment["id"],
                    count=pair["count"],
                    before_packet=rows(
                        self.db,
                        "SELECT * FROM integrity_obs WHERE point=? AND frame=? LIMIT 1",
                        [segment["point_a"], pair["frame_a"]],
                    )[0],
                    after_packet=rows(
                        self.db,
                        "SELECT * FROM integrity_obs WHERE point=? AND frame=? LIMIT 1",
                        [segment["point_b"], pair["frame_b"]],
                    )[0],
                )
            self.change_cache[key] = item
        item = self.change_cache[key]
        return [item] if item else []

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
        from itertools import groupby

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


def analyze_integrity(db, topology, segments, coverage, models, start, end):
    checks = Checks(db, topology, segments, coverage, models, start, end)
    checks.origins()
    checks.endpoint_origins()
    checks.payload_changes()
    checks.downstream_only()
    checks.mtu()
    checks.path_checks()
    return checks.findings, checks.notes


def group_downstream_findings(findings, topology):
    points = {p.id: p for p in topology.points}
    paths = {
        "forward": topology.forward,
        "reverse": topology.reverse or list(reversed(topology.forward)),
    }

    def seg_index(hop, direction):
        parts = hop.split(":")
        if len(parts) != 3:
            return None
        path = paths.get(direction, [])
        return path.index(parts[1]) if parts[1] in path else None

    captures_by_dir = {}
    for f in findings:
        if f["type"] == "capture_miss":
            idx = seg_index(f["hop"], f["direction"])
            if idx is not None:
                captures_by_dir.setdefault(f["direction"], []).append((idx, f))

    grouped_by_miss = {}
    kept = []
    for f in findings:
        if f["type"] != "downstream_packet":
            kept.append(f)
            continue
        idx = seg_index(f["hop"], f["direction"])
        candidates = [
            (m_idx, m_f)
            for m_idx, m_f in captures_by_dir.get(f["direction"], [])
            if idx is not None
            and m_idx <= idx
            and f["time_range"][0] + 0.005 >= m_f["time_range"][0]
        ]
        if not candidates:
            kept.append(f)
            continue
        _, target_miss = max(candidates, key=lambda item: (item[0], item[1]["time_range"][0]))
        grouped_by_miss.setdefault(target_miss["id"], (target_miss, []))[1].append(f)

    for target_miss, downstreams in grouped_by_miss.values():
        count = sum(df["metrics"].get("count", 1) for df in downstreams)
        labels = []
        for df in downstreams:
            parts = df["hop"].split(":")
            label = points[parts[2]].label if len(parts) == 3 and parts[2] in points else df["hop"]
            if label not in labels:
                labels.append(label)
        line = (
            f"{count} downstream-only packet observation(s) at {', '.join(labels)} "
            f"follow this capture miss (origin unknown; consistent with upstream capture miss)."
        )
        target_miss["downstream_summary"] = line
        target_miss["downstream_count"] = count
        target_miss["metrics"]["downstream_packet_count"] = count
        target_miss["summary"] = f"{target_miss['summary']} {line}"
        if "headline" in target_miss:
            target_miss["headline"] = f"{target_miss['headline']} {line}"
        seen_refs = {(r.get("point"), r.get("frame")) for r in target_miss["evidence"]}
        for df in downstreams:
            for r in df["evidence"]:
                key = (r.get("point"), r.get("frame"))
                if key not in seen_refs and len(target_miss["evidence"]) < 16:
                    seen_refs.add(key)
                    target_miss["evidence"].append(r)

    findings[:] = kept

