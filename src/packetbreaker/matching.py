"""Occurrence-aware packet matching. Repeated signatures are observations, not exclusions."""


def prepare_occurrences(db, duplicate_us=20):
    db.execute("ALTER TABLE obs ADD COLUMN base_key VARCHAR")
    db.execute("ALTER TABLE obs ADD COLUMN occurrence BIGINT")
    db.execute("ALTER TABLE obs ADD COLUMN excluded_reason VARCHAR")
    db.execute(
        "UPDATE obs SET base_key=packet_key, eligible=coalesce(unsupported,'')='', excluded_reason=nullif(unsupported,'')"
    )
    db.execute(
        """CREATE OR REPLACE TEMP TABLE span_duplicates AS
        SELECT point,frame FROM (
            SELECT point,frame,ts-lag(ts) OVER(PARTITION BY point,frame_hash ORDER BY ts,frame) AS gap
            FROM obs WHERE frame_hash IS NOT NULL AND caplen=wirelen)
        WHERE gap>=0 AND gap<=?""",
        [duplicate_us / 1e6 + 0.0000005],
    )
    db.execute("""UPDATE obs SET eligible=false,excluded_reason='span_duplicate'
        FROM span_duplicates d WHERE obs.point=d.point AND obs.frame=d.frame""")
    # Repeated signatures may calibrate only after an independent clock fit. They remain eligible.
    db.execute("""CREATE OR REPLACE TEMP TABLE calibration AS
        SELECT point,capture_id,frame,ts,packet_key,direction,eligible FROM obs WHERE eligible
        QUALIFY count(*) OVER(PARTITION BY point,packet_key)=1""")


def match_occurrences(db, topology):
    db.execute("""CREATE OR REPLACE TEMP TABLE occurrences AS
        SELECT point,frame,base_key,corrected,direction,
            row_number() OVER(PARTITION BY point,flow,base_key ORDER BY corrected,ts,frame) AS occurrence
        FROM obs WHERE eligible""")
    db.execute("""UPDATE obs SET occurrence=n.occurrence FROM occurrences n
        WHERE obs.point=n.point AND obs.frame=n.frame""")
    db.execute("""CREATE OR REPLACE TEMP TABLE repeated_keys AS
        SELECT DISTINCT base_key FROM occurrences WHERE occurrence>1""")
    if not db.execute("SELECT count(*) FROM repeated_keys").fetchone()[0]:
        return
    # Compensate normal relative transit before comparing occurrence times, never latency itself.
    db.execute(
        """CREATE OR REPLACE TEMP TABLE time_shifts AS
        SELECT o.point,o.direction,median(o.corrected-r.corrected) AS shift
        FROM obs o JOIN obs r ON o.base_key=r.base_key
        JOIN calibration ca ON ca.point=o.point AND ca.frame=o.frame
        JOIN calibration cr ON cr.point=r.point AND cr.frame=r.frame
        WHERE r.point=? GROUP BY o.point,o.direction""",
        [topology.forward[0]],
    )
    db.execute("""CREATE OR REPLACE TEMP TABLE repeat_obs AS
        SELECT n.*,n.corrected-coalesce(s.shift,0) AS match_time
        FROM occurrences n JOIN repeated_keys USING(base_key)
        LEFT JOIN time_shifts s ON n.point=s.point AND n.direction=s.direction""")
    db.execute("""CREATE OR REPLACE TEMP TABLE anchor_points AS
        SELECT base_key,point FROM (SELECT base_key,point,count(*) AS n FROM repeat_obs GROUP BY base_key,point)
        QUALIFY row_number() OVER(PARTITION BY base_key ORDER BY n DESC,point)=1""")
    db.execute("""CREATE OR REPLACE TEMP TABLE anchors AS
        SELECT r.*,r.point || ':' || r.frame AS anchor_id FROM repeat_obs r
        JOIN anchor_points a ON r.base_key=a.base_key AND r.point=a.point""")
    # ASOF predecessor/successor joins bound work even for millions of equal signatures.
    db.execute("""CREATE OR REPLACE TEMP TABLE before_candidates AS
        SELECT r.*,a.anchor_id,a.occurrence AS anchor_order,abs(r.match_time-a.match_time) AS distance
        FROM repeat_obs r ASOF LEFT JOIN anchors a ON r.base_key=a.base_key AND r.match_time>=a.match_time""")
    db.execute("""CREATE OR REPLACE TEMP TABLE after_candidates AS
        SELECT r.*,a.anchor_id,a.occurrence AS anchor_order,abs(r.match_time-a.match_time) AS distance
        FROM repeat_obs r ASOF LEFT JOIN anchors a ON r.base_key=a.base_key AND r.match_time<=a.match_time""")
    db.execute(
        """CREATE OR REPLACE TEMP TABLE nearest AS
        SELECT * FROM (SELECT * FROM before_candidates UNION ALL SELECT * FROM after_candidates)
        WHERE distance<=? QUALIFY row_number() OVER(PARTITION BY point,frame ORDER BY distance,anchor_order)=1""",
        [topology.match_window_ms / 1000],
    )
    db.execute("""CREATE OR REPLACE TEMP TABLE assigned AS
        SELECT * FROM nearest QUALIFY row_number() OVER(PARTITION BY point,anchor_id ORDER BY distance,occurrence)=1""")
    # Distinct nearest assignments are monotone in corrected-time order; no rank shifting across gaps.
    db.execute("""UPDATE obs SET packet_key=obs.point || ':' || obs.frame
        FROM repeated_keys r WHERE obs.base_key=r.base_key""")
    db.execute("""UPDATE obs SET packet_key=a.anchor_id FROM assigned a
        WHERE obs.point=a.point AND obs.frame=a.frame""")
    db.execute("""UPDATE obs SET eligible=false,excluded_reason='occurrence_timing_collision'
        WHERE EXISTS(SELECT 1 FROM nearest n WHERE n.point=obs.point AND n.frame=obs.frame)
        AND NOT EXISTS(SELECT 1 FROM assigned a WHERE a.point=obs.point AND a.frame=obs.frame)""")
    db.execute("""UPDATE obs SET eligible=false,excluded_reason='clock_alignment_unknown'
        WHERE base_key IN (SELECT base_key FROM repeated_keys) AND corrected IS NULL""")
