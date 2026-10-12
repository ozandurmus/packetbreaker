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
