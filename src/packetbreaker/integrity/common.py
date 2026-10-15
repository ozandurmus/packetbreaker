"""Shared helpers, duplication checks, and base class for bounded path integrity checks."""

import json

from ..evidence import evidence
from ..headlines import time_labels
from ..store import rows

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


class BaseChecks:
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
