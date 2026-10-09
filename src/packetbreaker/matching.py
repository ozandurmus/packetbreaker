"""Occurrence-aware packet matching. Repeated signatures are observations, not exclusions."""


def prepare_occurrences(db, duplicate_us=20):
    db.execute("ALTER TABLE obs ADD COLUMN base_key VARCHAR")
    db.execute("ALTER TABLE obs ADD COLUMN occurrence BIGINT")
    db.execute("ALTER TABLE obs ADD COLUMN excluded_reason VARCHAR")
    db.execute(
        """CREATE OR REPLACE TEMP TABLE span_duplicates AS
        SELECT point,frame FROM (
            SELECT point,frame,ts-lag(ts) OVER(PARTITION BY point,frame_hash ORDER BY ts,frame) AS gap
            FROM obs WHERE frame_hash IS NOT NULL AND caplen=wirelen)
        WHERE gap>=0 AND gap<=?""",
        [duplicate_us / 1e6 + 0.0000005],
    )
    db.execute("""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(
        o.packet_key AS base_key,coalesce(o.unsupported,'')='' AND d.frame IS NULL AS eligible,
        CASE WHEN d.frame IS NOT NULL THEN 'span_duplicate' ELSE nullif(o.unsupported,'') END AS excluded_reason)
        FROM obs o LEFT JOIN span_duplicates d ON o.point=d.point AND o.frame=d.frame""")
    # Repeated signatures may calibrate only after an independent clock fit. They remain eligible.
    db.execute("""CREATE OR REPLACE TEMP TABLE calibration AS
        SELECT point,capture_id,frame,ts,packet_key,direction,eligible FROM obs WHERE eligible
        QUALIFY count(*) OVER(PARTITION BY point,packet_key)=1""")


def match_occurrences(db, topology, table="obs"):
    if table not in ("obs", "byte_obs"):
        raise ValueError("Unknown observation table")
    import re

    def execute(sql, params=None):
        return db.execute(re.sub(r"\bobs\b", table, sql), params or [])

    execute("""CREATE OR REPLACE TEMP TABLE occurrences AS
        SELECT point,frame,base_key,corrected,direction,
            row_number() OVER(PARTITION BY point,flow,base_key ORDER BY corrected,ts,frame) AS occurrence
        FROM obs WHERE eligible""")
    execute("""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(n.occurrence AS occurrence)
        FROM obs o LEFT JOIN occurrences n ON o.point=n.point AND o.frame=n.frame""")
    execute("""CREATE OR REPLACE TEMP TABLE repeated_keys AS
        SELECT DISTINCT base_key FROM occurrences WHERE occurrence>1""")
    if not execute("SELECT count(*) FROM repeated_keys").fetchone()[0]:
        return
    # Compensate normal relative transit before comparing occurrence times, never latency itself.
    execute(
        """CREATE OR REPLACE TEMP TABLE time_shifts AS
        SELECT o.point,o.direction,median(o.corrected-r.corrected) AS shift
        FROM obs o JOIN obs r ON o.base_key=r.base_key
        JOIN calibration ca ON ca.point=o.point AND ca.frame=o.frame
        JOIN calibration cr ON cr.point=r.point AND cr.frame=r.frame
        WHERE r.point=? GROUP BY o.point,o.direction""",
        [topology.forward[0]],
    )
    execute("""CREATE OR REPLACE TEMP TABLE repeat_obs AS
        SELECT n.*,n.corrected-coalesce(s.shift,0) AS match_time
        FROM occurrences n JOIN repeated_keys USING(base_key)
        LEFT JOIN time_shifts s ON n.point=s.point AND n.direction=s.direction""")
    execute("""CREATE OR REPLACE TEMP TABLE anchor_points AS
        SELECT base_key,point FROM (SELECT base_key,point,count(*) AS n FROM repeat_obs GROUP BY base_key,point)
        QUALIFY row_number() OVER(PARTITION BY base_key ORDER BY n DESC,point)=1""")
    execute("""CREATE OR REPLACE TEMP TABLE anchors AS
        SELECT r.*,r.point || ':' || r.frame AS anchor_id FROM repeat_obs r
        JOIN anchor_points a ON r.base_key=a.base_key AND r.point=a.point""")
    execute(
        """CREATE OR REPLACE TEMP TABLE balanced_pairs AS
        WITH sizes AS (SELECT point,base_key,count(*) AS n FROM repeat_obs GROUP BY point,base_key),
        anchor_sizes AS (SELECT base_key,count(*) AS n FROM anchors GROUP BY base_key)
        SELECT r.*,a.anchor_id,a.occurrence AS anchor_order,abs(r.match_time-a.match_time) AS distance
        FROM repeat_obs r JOIN anchors a ON r.base_key=a.base_key AND r.occurrence=a.occurrence
        JOIN sizes s ON r.point=s.point AND r.base_key=s.base_key JOIN anchor_sizes z ON r.base_key=z.base_key
        WHERE s.n=z.n QUALIFY bool_and(distance<=?) OVER(PARTITION BY r.point,r.base_key)""",
        [topology.match_window_ms / 1000],
    )
    execute("""CREATE OR REPLACE TEMP TABLE unmatched_repeats AS
        SELECT r.* FROM repeat_obs r ANTI JOIN balanced_pairs b ON r.point=b.point AND r.frame=b.frame""")
    # Equal-length sequences have one monotone bijection. Unequal sequences retain time-based gaps.
    # ASOF predecessor/successor joins bound work even for millions of equal signatures.
    execute("""CREATE OR REPLACE TEMP TABLE before_candidates AS
        SELECT r.*,a.anchor_id,a.occurrence AS anchor_order,abs(r.match_time-a.match_time) AS distance
        FROM unmatched_repeats r ASOF LEFT JOIN anchors a ON r.base_key=a.base_key AND r.match_time>=a.match_time""")
    execute("""CREATE OR REPLACE TEMP TABLE after_candidates AS
        SELECT r.*,a.anchor_id,a.occurrence AS anchor_order,abs(r.match_time-a.match_time) AS distance
        FROM unmatched_repeats r ASOF LEFT JOIN anchors a ON r.base_key=a.base_key AND r.match_time<=a.match_time""")
    execute(
        """CREATE OR REPLACE TEMP TABLE nearest AS
        SELECT * FROM (SELECT * FROM before_candidates UNION ALL SELECT * FROM after_candidates)
        WHERE distance<=? QUALIFY row_number() OVER(PARTITION BY point,frame ORDER BY distance,anchor_order)=1""",
        [topology.match_window_ms / 1000],
    )
    execute("INSERT INTO nearest SELECT * FROM balanced_pairs")
    execute("""CREATE OR REPLACE TEMP TABLE assigned AS
        SELECT * FROM nearest QUALIFY row_number() OVER(PARTITION BY point,anchor_id ORDER BY distance,occurrence)=1""")
    # Distinct nearest assignments are monotone in corrected-time order; no rank shifting across gaps.
    execute("""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(
        CASE WHEN r.base_key IS NULL THEN o.packet_key ELSE coalesce(a.anchor_id,o.point || ':' || o.frame) END AS packet_key,
        CASE WHEN r.base_key IS NOT NULL AND (o.corrected IS NULL OR (n.frame IS NOT NULL AND a.frame IS NULL))
            THEN false ELSE o.eligible END AS eligible,
        CASE WHEN r.base_key IS NOT NULL AND o.corrected IS NULL THEN 'clock_alignment_unknown'
            WHEN n.frame IS NOT NULL AND a.frame IS NULL THEN 'occurrence_timing_collision'
            ELSE o.excluded_reason END AS excluded_reason)
        FROM obs o LEFT JOIN repeated_keys r USING(base_key)
        LEFT JOIN assigned a ON o.point=a.point AND o.frame=a.frame
        LEFT JOIN nearest n ON o.point=n.point AND o.frame=n.frame""")


def link_tcp_sessions(db, topology):
    """Union distinct local stream identities via shared packet occurrences, never per packet in Python."""
    sessions = db.execute(
        "SELECT DISTINCT point,stream,flow FROM obs WHERE proto='TCP' AND stream>=0"
    ).fetchall()
    parent = {s: s for s in sessions}

    def root(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    paths = (topology.forward, topology.reverse or list(reversed(topology.forward)))
    pairs = {tuple(sorted((a, b))) for path in paths for a, b in zip(path, path[1:])}
    for a, b in pairs:
        edges = db.execute(
            """SELECT DISTINCT a.point,a.stream,a.flow,b.point,b.stream,b.flow
            FROM obs a JOIN obs b ON a.packet_key=b.packet_key AND a.flow=b.flow
            WHERE a.point=? AND b.point=? AND a.proto='TCP' AND b.proto='TCP'
            AND a.stream>=0 AND b.stream>=0 AND (a.eligible OR a.translation_reason IS NOT NULL) AND (b.eligible OR b.translation_reason IS NOT NULL)""",
            [a, b],
        ).fetchall()
        for edge in edges:
            left, right = root(edge[:3]), root(edge[3:])
            if left != right:
                parent[max(left, right)] = min(left, right)
    if db.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_name='translation_links'"
    ).fetchone()[0]:
        for a, sa, b, sb, flow in db.execute("SELECT DISTINCT * FROM translation_links").fetchall():
            if (a, sa, flow) in parent and (b, sb, flow) in parent:
                left, right = root((a, sa, flow)), root((b, sb, flow))
                if left != right:
                    parent[max(left, right)] = min(left, right)
    if db.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_name='byte_calibration'"
    ).fetchone()[0]:
        links = db.execute("""SELECT x.point,x.stream,x.flow,y.point,y.stream,y.flow FROM byte_calibration a
            JOIN byte_calibration b USING(packet_key) JOIN obs x ON x.point=a.point AND x.frame=a.frame
            JOIN obs y ON y.point=b.point AND y.frame=b.frame WHERE x.flow=y.flow AND x.point<>y.point
            GROUP BY ALL HAVING count(*)>=3""").fetchall()
        for edge in links:
            left, right = root(edge[:3]), root(edge[3:])
            if left != right:
                parent[max(left, right)] = min(left, right)
    db.execute(
        "CREATE OR REPLACE TEMP TABLE session_map(point VARCHAR,stream BIGINT,old_flow VARCHAR,new_flow VARCHAR)"
    )
    if sessions:
        import hashlib

        db.executemany(
            "INSERT INTO session_map VALUES (?,?,?,?)",
            [(*s, hashlib.sha256(repr(root(s)).encode()).hexdigest()[:32]) for s in sessions],
        )
        db.execute("""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(coalesce(s.new_flow,o.flow) AS flow)
            FROM obs o LEFT JOIN session_map s ON o.point=s.point AND o.stream=s.stream AND o.flow=s.old_flow""")


def propagate_translation_unknown(db):
    if db.execute("SELECT count(*) FROM sequence_models WHERE status='unknown'").fetchone()[0]:
        db.execute("""CREATE OR REPLACE TABLE obs AS SELECT o.* REPLACE(
            coalesce(o.translation_reason,q.reason) AS translation_reason,
            CASE WHEN q.reason IS NOT NULL THEN false ELSE o.eligible END AS eligible,
            coalesce(o.excluded_reason,q.reason) AS excluded_reason)
            FROM obs o LEFT JOIN (SELECT flow,max(translation_reason) AS reason FROM obs
                WHERE translation_reason IS NOT NULL GROUP BY flow) q USING(flow)""")
