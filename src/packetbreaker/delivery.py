"""Physical-copy evidence separates transit from delivery by a later TCP retry."""

from .store import rows
from .evidence import evidence
from .rtp import media_finding


def prepare_delivery(db, topology):
    db.execute(
        "CREATE OR REPLACE TEMP TABLE delivery_edges(point_a VARCHAR,point_b VARCHAR,direction VARCHAR)"
    )
    edges = [
        (a, b, d) for d in ("forward", "reverse") for a, b in zip(topology.path(d), topology.path(d)[1:])
    ]
    if edges:
        db.executemany("INSERT INTO delivery_edges VALUES (?,?,?)", edges)
    db.execute("""CREATE OR REPLACE TEMP TABLE delivery_repeats AS SELECT point,flow,direction,seq,count(*) AS copies
        FROM obs WHERE proto='TCP' AND length>0 AND eligible GROUP BY ALL HAVING count(*)>1""")
    db.execute("""CREATE OR REPLACE TABLE delivery_candidates AS SELECT DISTINCT m.point_a,m.point_b,m.direction,
        a.flow,a.frame AS frame_a,b.frame AS frame_b,m.key_a,m.key_b,m.time_a,m.time_b,
        a.seq,a.ipid AS id_a,b.ipid AS id_b,a.src,least(a.length,b.length) AS bytes,
        a.seq=b.seq AS same_start,coalesce(r.copies,1) AS copies
        FROM observation_matches m JOIN delivery_edges USING(point_a,point_b,direction) JOIN obs a ON a.point=m.point_a AND a.packet_key=m.key_a
        JOIN obs b ON b.point=m.point_b AND b.packet_key=m.key_b
        LEFT JOIN delivery_repeats r ON r.point=a.point AND r.flow=a.flow AND r.direction=a.direction AND r.seq=a.seq
        WHERE a.proto='TCP' AND a.length>0 AND b.length>0""")
    db.execute("""CREATE OR REPLACE TABLE delivery_id_policy AS SELECT point_a,point_b,direction,flow,
        count(*)>=4 AND count(DISTINCT id_a)>1 AND avg((id_a=id_b)::INTEGER)>=.5 AS preserved_ids
        FROM delivery_candidates WHERE same_start AND NOT contains(src,':') GROUP BY ALL""")
    db.execute(
        """CREATE OR REPLACE TABLE delivery_rejections AS SELECT c.*,
        CASE WHEN p.preserved_ids AND c.same_start AND c.id_a<>c.id_b
              AND EXISTS(SELECT 1 FROM obs u WHERE u.point=c.point_a AND u.flow=c.flow AND u.direction=c.direction
                  AND u.seq=c.seq AND u.ipid=c.id_b AND u.corrected>c.time_a AND u.corrected<=c.time_b+.005)
              AND NOT EXISTS(SELECT 1 FROM obs o WHERE o.point=c.point_b AND o.flow=c.flow AND o.direction=c.direction
                  AND o.seq=c.seq AND o.ipid=c.id_a AND o.eligible)
              THEN 'retry_substitution'
             ELSE 'unknown' END AS status
        FROM delivery_candidates c LEFT JOIN delivery_id_policy p USING(point_a,point_b,direction,flow)
        WHERE (p.preserved_ids AND c.same_start AND c.id_a<>c.id_b)
           OR (c.copies>1 AND NOT coalesce(p.preserved_ids,false) AND (time_b-time_a)*1000>=?)""",
        [1.0],
    )
    db.execute("""CREATE OR REPLACE TABLE delivery_rejections AS WITH anchors AS(SELECT * FROM delivery_rejections)
        SELECT * FROM anchors UNION ALL
        SELECT DISTINCT c.*,'unknown' AS status FROM delivery_candidates c JOIN anchors r
          ON r.point_a=c.point_a AND r.point_b=c.point_b AND r.direction=c.direction AND r.key_b=c.key_b
        WHERE NOT EXISTS(SELECT 1 FROM anchors x WHERE x.point_a=c.point_a AND x.point_b=c.point_b
          AND x.direction=c.direction AND x.key_a=c.key_a)""")
    # None of a super-frame's ranges can certify original transit after its first copy contradicted it.
    definition = db.execute(
        "SELECT sql FROM duckdb_views() WHERE view_name='observation_matches'"
    ).fetchone()[0]
    db.execute(
        definition.replace("CREATE VIEW", "CREATE OR REPLACE VIEW", 1).replace(
            "observation_matches", "unfiltered_observation_matches", 1
        )
    )
    db.execute("""CREATE OR REPLACE VIEW observation_matches AS SELECT m.* FROM unfiltered_observation_matches m
        WHERE NOT EXISTS(SELECT 1 FROM delivery_rejections r WHERE r.point_a=m.point_a AND r.point_b=m.point_b
                         AND r.key_a=m.key_a AND r.direction=m.direction)""")


def delivery_report(db, topology, segments):
    points = {p.id: p for p in topology.points}
    db.execute(
        "CREATE OR REPLACE TEMP TABLE delivery_positions(point VARCHAR,direction VARCHAR,position INTEGER)"
    )
    db.executemany(
        "INSERT INTO delivery_positions VALUES (?,?,?)",
        [(p, d, i) for d in ("forward", "reverse") for i, p in enumerate(topology.path(d))],
    )
    db.execute("""CREATE OR REPLACE TABLE delivery_events AS SELECT r.*,
      CASE WHEN e.reason IS NOT NULL THEN 'unknown'
           WHEN EXISTS(SELECT 1 FROM obs o JOIN delivery_positions pos ON pos.point=o.point AND pos.direction=o.direction
             JOIN delivery_positions target ON target.point=r.point_b AND target.direction=r.direction
             WHERE o.flow=r.flow AND o.direction=r.direction AND o.seq=r.seq AND o.ipid=r.id_a
             AND o.eligible AND pos.position>target.position)
             OR EXISTS(SELECT 1 FROM obs a WHERE a.point=r.point_a AND a.flow=r.flow AND a.direction<>r.direction
               AND (a.flags&16)>0 AND a.corrected>r.time_a AND a.corrected<r.time_b
               AND ((a.ack-r.seq-r.bytes+4294967296)%4294967296)<2147483648)
             THEN 'capture_miss'
           ELSE r.status END AS classification
      FROM delivery_rejections r JOIN cycle_edges e ON e.a=r.point_a AND e.b=r.point_b AND e.direction=r.direction""")
    db.execute(
        """CREATE OR REPLACE TABLE delivery_series AS WITH data AS(
        SELECT c.point_a,c.point_b,c.direction,c.flow,c.time_a,c.frame_a,arg_max(c.frame_b,c.time_b) AS frame_b,
        CASE WHEN e.reason IS NOT NULL THEN 'unknown' WHEN max(time_b-time_a)*1000>greatest(1,2*e.uncertainty_ms) THEN 'delayed' ELSE 'matched' END AS classification,
        max(time_b-time_a)*1000 AS wait_ms FROM delivery_candidates c
        JOIN cycle_edges e ON e.a=c.point_a AND e.b=c.point_b AND e.direction=c.direction
        WHERE NOT EXISTS(SELECT 1 FROM delivery_rejections r WHERE r.point_a=c.point_a AND r.point_b=c.point_b
          AND r.key_a=c.key_a AND r.direction=c.direction)
        GROUP BY c.point_a,c.point_b,c.direction,c.flow,c.time_a,c.frame_a,c.key_a,e.reason,e.uncertainty_ms
        UNION ALL SELECT point_a,point_b,direction,flow,time_a,frame_a,frame_b,classification,(time_b-time_a)*1000 FROM delivery_events
        UNION ALL SELECT point_a,point_b,direction,flow,ts,NULL,NULL,
            CASE WHEN kind IN ('impactful_loss','recovered_loss') THEN 'dropped'
                 WHEN kind='capture_miss' THEN 'capture_miss' ELSE 'unknown' END,coalesce(recovery_ms,impact_ms)
            FROM events e WHERE is_data AND NOT EXISTS(SELECT 1 FROM delivery_rejections r
              WHERE r.point_a=e.point_a AND r.point_b=e.point_b AND r.key_a=e.packet_key))
        SELECT point_a,point_b,direction,flow,floor(time_a/?) * ? AS start,count(*) AS observations,
          count(*) FILTER(WHERE classification='delayed') AS delayed,
          count(*) FILTER(WHERE classification IN ('dropped','retry_substitution')) AS dropped,
          count(*) FILTER(WHERE classification='capture_miss') AS capture_misses,
          count(*) FILTER(WHERE classification='unknown') AS unknown,
          max(wait_ms) FILTER(WHERE classification='delayed') AS max_delay_ms,
          max(wait_ms) FILTER(WHERE classification IN ('dropped','retry_substitution')) AS max_recovery_ms,
          min(frame_a) AS evidence_frame_a,min(frame_b) AS evidence_frame_b
          FROM data WHERE (? IS NULL OR time_a>=?) AND (? IS NULL OR time_a<=?) GROUP BY ALL""",
        [
            topology.bucket_seconds,
            topology.bucket_seconds,
            topology.start,
            topology.start,
            topology.end,
            topology.end,
        ],
    )
    db.execute("""CREATE OR REPLACE TABLE adjacent_match_rates AS SELECT *,
        100.0*(observations-dropped-capture_misses-unknown)/nullif(observations,0) AS match_percent,
        CASE WHEN unknown>0 THEN NULL ELSE 100.0*dropped/nullif(observations,0) END AS missing_percent FROM delivery_series""")
    findings = []
    for row in rows(
        db,
        """SELECT point_a,point_b,direction,flow,count(*) AS count,min(time_a) AS start,max(time_b) AS stop,
        max((time_b-time_a)*1000) AS max_recovery_ms,arg_min(frame_a,time_a) AS frame_a,arg_min(frame_b,time_a) AS frame_b
        FROM delivery_events WHERE classification='retry_substitution' GROUP BY ALL ORDER BY count DESC LIMIT 100""",
    ):
        segment = next(
            s
            for s in segments
            if s["point_a"] == row["point_a"]
            and s["point_b"] == row["point_b"]
            and s["direction"] == row["direction"]
        )
        a, b = points[row["point_a"]], points[row["point_b"]]
        kind = (
            "host_transmit_path_loss"
            if a.host_capture
            else "host_receive_path_loss"
            if b.host_capture
            else "impactful_loss"
        )
        refs = evidence(
            db,
            "(o.point=? AND o.frame=?) OR(o.point=? AND o.frame=?)",
            [a.id, row["frame_a"], b.id, row["frame_b"]],
            2,
            _expand_ranges=False,
        )
        text = f"{row['count']} {kind.replace('_', ' ')} between {a.label} and {b.label}; original IP ID absent, a different-ID retry delivered (max {row['max_recovery_ms']:.1f} ms)."
        f = media_finding(db, kind, segment, row["start"], text, row, refs)
        f.update(
            severity="high",
            time_range=[row["start"], row["stop"]],
            cause="retry_delivery",
            tooltip="Physical IPv4 ID preservation is learned per flow and boundary. A seq-only retry match is excluded from transit latency. Constant IDs/IPv6 cannot provide this identity proof; ambiguous copies are unknown.",
        )
        findings.append(f)
    return dict(
        series=rows(db, "SELECT * FROM adjacent_match_rates ORDER BY start,point_a,point_b LIMIT 20000"),
        note="Delay means measured transit above max(1 ms, twice clock uncertainty), not a proven cause. Counts exclude substituted/ambiguous copies. Missing/delayed rates are per observed physical pair; erased or constant identity is not proof of original delivery.",
    ), findings
