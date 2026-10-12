"""Observed TCP lifecycle and conservative, local stateful-device heuristics."""

from .store import rows
from .evidence import evidence

LIFECYCLE_NOTE = (
    "Observed SYN-anchored sessions, not the device's internal table. SYN retries count once; "
    "established requires a sequence-consistent SYN/SYNACK/final ACK at the same point. "
    "Half-open occupancy ends at establishment, RST, FIN or the configured observation timeout. "
    "FIN means closure started, not proof both endpoints released state. Missing SYN is unknown. "
    "Capture absence, timeout and source diversity do not prove intent or resource exhaustion."
)


def build_lifecycle(db, topology, coverage, series, window):
    timeout = topology.session_timeout_seconds
    # Work at local session granularity. Flags alone cannot turn a late ACK into establishment.
    db.execute("""CREATE OR REPLACE TEMP TABLE session_syns AS SELECT point,flow,canon,canon_reverse,
        seq,src,dst,sport,dport,min(corrected) AS start,arg_min(frame,corrected) AS syn_frame,
        count(*) AS syn_attempts FROM obs WHERE proto='TCP' AND eligible AND (flags&18)=2
        AND corrected IS NOT NULL GROUP BY ALL""")
    db.execute(f"""CREATE OR REPLACE TEMP TABLE session_replies AS SELECT s.*,
        min(a.corrected) AS synack,arg_min(a.frame,a.corrected) AS synack_frame,
        arg_min(a.seq,a.corrected) AS server_seq FROM session_syns s LEFT JOIN obs a
        ON a.point=s.point AND a.flow=s.flow AND a.canon=s.canon_reverse AND a.eligible
        AND (a.flags&18)=18 AND a.ack=(s.seq+1)%4294967296
        AND a.corrected>=s.start AND a.corrected<s.start+{timeout} GROUP BY ALL""")
    db.execute(f"""CREATE OR REPLACE TEMP TABLE session_acks AS SELECT s.*,
        min(a.corrected) AS established,arg_min(a.frame,a.corrected) AS ack_frame
        FROM session_replies s LEFT JOIN obs a ON a.point=s.point AND a.flow=s.flow
        AND a.canon=s.canon AND a.eligible AND (a.flags&23)=16
        AND a.seq=(s.seq+1)%4294967296 AND a.ack=(s.server_seq+1)%4294967296
        AND a.corrected>=s.synack AND a.corrected<s.start+{timeout} GROUP BY ALL""")
    db.execute(f"""CREATE OR REPLACE TABLE session_lifecycle AS WITH ends AS(
        SELECT s.*,min(a.corrected) AS closed,arg_min(a.frame,a.corrected) AS close_frame,
        bool_or((a.flags&4)>0) AS rst FROM session_acks s LEFT JOIN obs a
        ON a.point=s.point AND a.flow=s.flow AND a.eligible AND (a.flags&5)>0
        AND a.corrected>=s.start AND a.corrected<s.start+{timeout} GROUP BY ALL)
        SELECT *,CASE WHEN closed IS NOT NULL THEN 'closed' WHEN established IS NOT NULL THEN 'established'
        ELSE 'half_open' END AS status,least(coalesce(established,start+{timeout}),
            coalesce(closed,start+{timeout}),start+{timeout}) AS half_open_end FROM ends""")
    origin, width, count = series.get("start"), topology.bucket_seconds, series.get("bucket_count", 0)
    bypoint = {c["point"]: c for c in coverage}
    db.execute("CREATE OR REPLACE TEMP TABLE session_points(point VARCHAR,start DOUBLE,finish DOUBLE)")
    db.executemany(
        "INSERT INTO session_points VALUES (?,?,?)",
        [
            (p.id, bypoint.get(p.id, {}).get("start"), bypoint.get(p.id, {}).get("end"))
            for p in topology.points
        ],
    )
    db.execute(
        'CREATE OR REPLACE TABLE session_buckets(point VARCHAR,bucket BIGINT,start DOUBLE,"end" DOUBLE,coverage VARCHAR,syns BIGINT,synacks BIGINT,established BIGINT,closed BIGINT,half_open BIGINT)'
    )
    if origin is not None and count:
        db.execute(f"""INSERT INTO session_buckets WITH grid AS(
            SELECT p.*,i AS bucket,{origin}+i*{width} AS lo,{origin}+(i+1)*{width} AS hi
            FROM session_points p CROSS JOIN range({count}) r(i)), stats AS(
            SELECT g.point,g.bucket,g.lo,g.hi,g.start<=g.lo AND g.finish>=g.hi AS covered,
            count(*) FILTER(WHERE s.start>=g.lo AND s.start<g.hi) AS syns,
            count(*) FILTER(WHERE s.synack>=g.lo AND s.synack<g.hi) AS synacks,
            count(*) FILTER(WHERE s.established>=g.lo AND s.established<g.hi) AS established,
            count(*) FILTER(WHERE s.closed>=g.lo AND s.closed<g.hi) AS closed,
            count(*) FILTER(WHERE s.start<g.hi AND s.half_open_end>=g.hi) AS half_open
            FROM grid g LEFT JOIN session_lifecycle s ON s.point=g.point AND s.start<g.hi
            AND (s.start>=g.lo OR s.half_open_end>=g.hi OR s.synack>=g.lo OR s.established>=g.lo OR s.closed>=g.lo)
            GROUP BY ALL) SELECT point,bucket,lo,hi,CASE WHEN coalesce(covered,false) THEN 'covered' ELSE 'unknown' END,
            CASE WHEN covered THEN syns END,CASE WHEN covered THEN synacks END,
            CASE WHEN covered THEN established END,CASE WHEN covered THEN closed END,
            CASE WHEN covered THEN half_open END FROM stats""")
    points = rows(
        db,
        """SELECT s.point,count(*) AS syn_sent,count(synack) AS synack_seen,
        count(established) AS established,count(closed) AS closed,count(*) FILTER(WHERE rst) AS rst_closed,
        count(*) FILTER(WHERE closed IS NOT NULL AND NOT rst) AS fin_closed,
        arg_min(syn_frame,start) AS first_frame FROM session_lifecycle s GROUP BY point ORDER BY point""",
    )
    # Include points without a SYN: their session population is unknown, not zero.
    indexed = {p["point"]: p for p in points}
    points = []
    for point in topology.points:
        p = indexed.get(
            point.id,
            dict(
                point=point.id,
                syn_sent=None,
                synack_seen=None,
                established=None,
                closed=None,
                rst_closed=None,
                fin_closed=None,
                first_frame=None,
            ),
        )
        cov = bypoint.get(point.id, {})
        p.update(
            label=point.label,
            status="observed" if p["syn_sent"] is not None and cov.get("start") is not None else "unknown",
            tooltip=LIFECYCLE_NOTE,
        )
        p["evidence"] = (
            evidence(db, "o.point=? AND o.frame=?", [point.id, p["first_frame"]], 1)
            if p["first_frame"] is not None
            else []
        )
        points.append(p)
    failures = rows(
        db,
        """SELECT flow,point_a,point_b,direction,min(ts) AS time,count(*) AS attempts,
        arg_min(packet_key,ts) AS packet_key FROM events WHERE kind='handshake_blocked' OR (kind='confirmed_device_drop' AND EXISTS(SELECT 1 FROM obs o WHERE o.packet_key=events.packet_key AND (o.flags&2)>0)) GROUP BY ALL ORDER BY time LIMIT 200""",
    )
    keys = [f["packet_key"] for f in failures]
    selected = rows(
        db, "SELECT point,frame,packet_key FROM obs WHERE packet_key IN (SELECT unnest(?::VARCHAR[]))", [keys]
    )
    key_by_frame = {(r["point"], r["frame"]): r["packet_key"] for r in selected}
    refs = evidence(db, "o.packet_key IN (SELECT unnest(?::VARCHAR[]))", [keys], 1600, _expand_ranges=False)
    by_key = {}
    for ref in refs:
        by_key.setdefault(key_by_frame[(ref["point"], ref["frame"])], []).append(ref)
    for f in failures:
        f["evidence"] = by_key.get(f["packet_key"], [])
        f["reason"] = "Supported SYN or SYN/ACK stopping boundary; internal device cause unknown"
    return dict(
        points=points,
        buckets=rows(db, "SELECT * FROM session_buckets ORDER BY point,bucket LIMIT 200000"),
        failed_handshakes=failures,
        timeout_seconds=timeout,
        note=LIFECYCLE_NOTE,
        scope="Full saved analysis window; not filtered by the UI brush",
    )


SECURITY_NOTE = (
    "Heuristics describe observed traffic, never an attack or proven device capacity failure. "
    "Rates use distinct SYN-anchored sessions and completed observation deadlines; source spread "
    "is not proof of spoofing. Healthy completion elsewhere makes a local missing handshake unknown. "
    "Capture quality, matching, clock and complete coverage gate absence-based claims."
)


def finding(
    db, kind, point, start, end, summary, metrics, *, supported=True, hop=None, device=None, refs=None
):
    proof = (
        refs
        if refs is not None
        else evidence(
            db, "o.point=? AND o.corrected>=? AND o.corrected<? AND (o.flags&2)>0", [point, start, end], 16
        )
    )
    return dict(
        id=f"security:{kind}:{point}:{start}",
        type=kind,
        hop=hop or f"forward:{point}:{point}",
        device=device,
        direction="forward",
        severity="low" if supported else "unknown",
        confidence="supported" if supported else "unknown",
        time_range=[start, end],
        summary=summary,
        headline=summary,
        tooltip=SECURITY_NOTE,
        metrics=metrics,
        evidence=proof,
        cause="unknown",
        clock_caveat="Clock-corrected observations; clock uncertainty and coverage apply",
    )


def security_checks(db, topology, coverage, series, segments, clocks):
    import json

    width, origin = topology.bucket_seconds, series.get("start")
    thresholds = dict(
        syn_rate=topology.security_syn_rate,
        completion_ratio=topology.security_completion_ratio,
        sources=topology.security_min_sources,
        sustained_buckets=topology.security_sustained_buckets,
        observation_timeout_seconds=topology.session_timeout_seconds,
    )
    bypoint = {c["point"]: c for c in coverage}
    inventories = {r["id"]: json.loads(r["inventory"]) for r in rows(db, "SELECT id,inventory FROM captures")}
    points = {p.id: p for p in topology.points}
    notes = []
    usable = []
    for p in topology.points:
        cov = bypoint.get(p.id, {})
        inv = inventories[p.capture_id]
        reason = None
        if (
            cov.get("start") is None
            or cov.get("end") is None
            or clocks.get(p.capture_id, {}).get("uncertainty") is None
        ):
            reason = "Clock or complete point coverage unavailable"
        elif any(
            inv.get(k)
            for k in ("ifdrop", "osdrop", "damaged_tail", "truncated_tail", "timestamp_excluded_counts")
        ):
            reason = "Capture quality prevents absence-based security inference"
        elif any(s.get("reason") for s in segments if p.id in (s["point_a"], s["point_b"])):
            reason = "Adjacent segment matching/coverage/translation insufficient"
        if reason:
            notes.append(dict(point=p.id, status="unknown", reason=reason))
        else:
            usable.append(p.id)
    db.execute("""CREATE OR REPLACE TEMP TABLE security_sessions AS SELECT s.*,
        bool_or(established IS NOT NULL) OVER(PARTITION BY flow,seq) AS completed_elsewhere,
        bool_or(synack IS NOT NULL) OVER(PARTITION BY flow,seq) AS reply_elsewhere
        FROM session_lifecycle s""")
    db.execute(
        'CREATE OR REPLACE TABLE security_cohorts(point VARCHAR,bucket BIGINT,start DOUBLE,"end" DOUBLE,sessions BIGINT,sources BIGINT,synack_ratio DOUBLE,established_ratio DOUBLE,syn_rate DOUBLE,usable BOOLEAN)'
    )
    findings = []
    if origin is None:
        return findings, dict(note=SECURITY_NOTE, thresholds=thresholds, quality=notes)
    timeout = topology.session_timeout_seconds
    db.execute("CREATE OR REPLACE TEMP TABLE security_points(point VARCHAR,start DOUBLE,finish DOUBLE)")
    db.executemany(
        "INSERT INTO security_points VALUES (?,?,?)",
        [
            (p.id, bypoint.get(p.id, {}).get("start"), bypoint.get(p.id, {}).get("end"))
            for p in topology.points
        ],
    )
    db.execute(
        f"""INSERT INTO security_cohorts SELECT point,floor((s.start-{origin})/{width})::BIGINT AS bucket,
        {origin}+bucket*{width},{origin}+(bucket+1)*{width},count(*),count(DISTINCT src),
        count(synack)*1.0/count(*),count(established)*1.0/count(*),count(*)/{width},
        point IN (SELECT unnest(?::VARCHAR[])) AND min(s.start)>=(SELECT p.start FROM security_points p WHERE p.point=s.point)
        AND max(s.start)+{timeout}<=(SELECT finish FROM security_points p WHERE p.point=s.point)
        AND NOT bool_or((established IS NULL AND completed_elsewhere) OR (synack IS NULL AND reply_elsewhere))
        FROM security_sessions s WHERE s.start>={origin} AND s.start<{series["end"]} GROUP BY point,bucket""",
        [usable],
    )
    n = topology.security_sustained_buckets
    waves = rows(
        db,
        f"""WITH signal AS(SELECT *,bucket-row_number() OVER(PARTITION BY point ORDER BY bucket) AS run
        FROM security_cohorts WHERE usable AND syn_rate>=? AND sources>=?
        AND greatest(synack_ratio,established_ratio)<=?), runs AS(
        SELECT point,run,min(start) AS start,max("end") AS finish,count(*) AS buckets,
        sum(sessions) AS sessions,min(sources) AS sources,min(syn_rate) AS syn_rate,
        max(synack_ratio) AS synack_ratio,max(established_ratio) AS established_ratio
        FROM signal GROUP BY point,run HAVING count(*)>={n}) SELECT * FROM runs ORDER BY start,point""",
        [topology.security_syn_rate, topology.security_min_sources, topology.security_completion_ratio],
    )
    for wave in waves:
        metrics = {
            **wave,
            "count": wave["sessions"],
            "thresholds": thresholds,
            "scope": "signal observed here; not a fault attribution",
        }
        findings.append(
            finding(
                db,
                "syn_flood_like",
                wave["point"],
                wave["start"],
                wave["finish"],
                f"SYN-flood-like pattern (heuristic) at {points[wave['point']].label}: {wave['syn_rate']:.1f}+ SYN sessions/s, "
                f"{wave['sources']}+ observed sources over {wave['buckets']} buckets; SYN/ACK ratio {wave['synack_ratio']:.1%}, established ratio {wave['established_ratio']:.1%}.",
                metrics,
            )
        )
    findings.extend(scan_checks(db, topology, usable, series))
    thresholds.update(
        scan_window_seconds=topology.security_scan_window_seconds,
        scan_targets=topology.security_scan_targets,
        scan_failed_ratio=topology.security_scan_failed_ratio,
    )
    return findings, dict(note=SECURITY_NOTE, thresholds=thresholds, quality=notes)


def scan_checks(db, topology, usable, series):
    width = topology.security_scan_window_seconds
    timeout = topology.session_timeout_seconds
    db.execute(
        f"""CREATE OR REPLACE TABLE security_fanout AS SELECT a.point,a.src AS source,
        a.start-{width} AS start,a.start AS finish,count(*) AS sessions,
        count(DISTINCT struct_pack(dst:=s.dst,port:=s.dport)) AS targets,
        count(*) FILTER(WHERE s.established IS NULL)*1.0/count(*) AS failed_ratio,
        bool_and(NOT s.completed_elsewhere OR s.established IS NOT NULL) AS consistent
        FROM security_sessions a JOIN security_sessions s ON a.point=s.point AND a.src=s.src
        AND s.start>=a.start-{width} AND s.start<=a.start
        WHERE a.point IN (SELECT unnest(?::VARCHAR[])) AND a.start>={series["start"]}+{width}
        AND a.start+{timeout}<=(SELECT finish FROM security_points p WHERE p.point=a.point)
        AND a.start<{series["end"]} GROUP BY a.point,a.src,a.start""",
        [usable],
    )
    candidates = rows(
        db,
        """SELECT point,source,min(start) AS start,max(finish) AS finish,
        max(sessions) AS sessions,max(targets) AS targets,max(failed_ratio) AS failed_ratio
        FROM security_fanout WHERE consistent AND targets>=? AND failed_ratio>=?
        GROUP BY point,source ORDER BY start,point LIMIT 200""",
        [topology.security_scan_targets, topology.security_scan_failed_ratio],
    )
    findings = []
    for c in candidates:
        refs = evidence(
            db,
            "o.point=? AND o.src=? AND (o.flags&2)>0 AND o.corrected>=? AND o.corrected<=?",
            [c["point"], c["source"], c["start"], c["finish"]],
            16,
        )
        findings.append(
            finding(
                db,
                "scan_like_fanout",
                c["point"],
                c["start"],
                c["finish"],
                f"scan-like fan-out (heuristic): source {c['source']} touched {c['targets']} destinations/ports in a {width:g} s rolling window with {c['failed_ratio']:.1%} unestablished handshakes at {c['point']}.",
                {
                    **c,
                    "count": c["sessions"],
                    "thresholds": dict(
                        window_seconds=width,
                        targets=topology.security_scan_targets,
                        failed_ratio=topology.security_scan_failed_ratio,
                    ),
                    "note": "Peak rolling-window counts; displayed interval spans qualifying windows, not one aggregate count.",
                },
                refs=refs,
            )
        )
    return findings
