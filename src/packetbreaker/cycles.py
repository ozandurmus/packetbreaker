"""Opaque TCP data cycles: observed turns, never invented application requests."""

from .store import rows
from .evidence import evidence

NOTE = "A cycle is a client data burst followed by the first server data burst. It is not a decoded application request. Pipelining, streaming and missing turns can be ambiguous; ACK/range consistency and coverage are required. RX/TX include network or host-boundary wait, including recovery; the delivery table separates retry evidence."


def build_cycles(db, topology, segments, host_report, onsets):
    db.execute(
        """CREATE OR REPLACE TABLE cycle_points AS
        WITH first_bytes AS (
          SELECT *,coalesce(corrected,ts) AS local_time FROM obs WHERE proto='TCP' AND length>0 AND (eligible OR excluded_reason='clock_alignment_unknown')
          QUALIFY row_number() OVER(PARTITION BY point,flow,direction,seq,length ORDER BY local_time,frame)=1),
        ordered AS(SELECT *,lag(direction) OVER(PARTITION BY point,flow ORDER BY local_time,frame) AS previous FROM first_bytes),
        numbered AS(SELECT *,sum(CASE WHEN direction IS DISTINCT FROM previous THEN 1 ELSE 0 END)
          OVER(PARTITION BY point,flow ORDER BY local_time,frame) AS turn FROM ordered),
        bursts AS(SELECT point,flow,turn,min(direction) AS direction,min(local_time) AS first_time,max(local_time) AS last_time,
          arg_min(seq,local_time) AS start_seq,arg_max((seq+length)%4294967296,local_time) AS end_seq,
          arg_min(ack,local_time) AS first_ack,arg_min(frame,local_time) AS first_frame,arg_max(frame,local_time) AS last_frame,
          min(dport) AS port,bool_and(corrected IS NOT NULL) AS clock_aligned FROM numbered GROUP BY point,flow,turn)
        SELECT md5(q.flow||':'||coalesce(r.first_ack,q.end_seq)) AS cycle_id,q.point,q.flow,q.port,q.clock_aligned,
          q.first_time AS request_first,q.last_time AS request_last,r.first_time AS response_first,
          q.first_frame AS request_frame,q.last_frame AS request_last_frame,r.first_frame AS response_frame,
          (r.first_time-q.first_time)*1000 AS cycle_ms,(r.first_time-q.last_time)*1000 AS turnaround_ms,
          (r.first_time-q.first_time)*1000>=? AS stalled,
          CASE WHEN r.first_time IS NULL THEN 'No following server data captured'
               WHEN r.first_ack<>q.end_seq THEN 'Captured burst boundary differs from response ACK; incomplete or concurrent turns'
               ELSE NULL END AS reason
        FROM bursts q LEFT JOIN bursts r ON q.point=r.point AND q.flow=r.flow AND r.turn=q.turn+1 AND r.direction='reverse'
        WHERE q.direction='forward' AND (NOT q.clock_aligned OR ? IS NULL OR q.first_time>=?) AND (NOT q.clock_aligned OR ? IS NULL OR q.first_time<=?)""",
        [topology.cycle_stall_ms, topology.start, topology.start, topology.end, topology.end],
    )
    db.execute(
        """CREATE OR REPLACE TABLE cycle_windows(flow VARCHAR,start DOUBLE,stop DOUBLE,reason VARCHAR)"""
    )
    windows = {
        s["flow"]: (s["window"]["time"], s["window"]["end"], s["window"].get("reason"))
        for s in host_report.get("streams", [])
        if s.get("window")
    }
    if windows:
        db.executemany("INSERT INTO cycle_windows VALUES (?,?,?,?)", [(f, *w) for f, w in windows.items()])
    # A measured segment onset can delimit the window for flows observed at that segment.
    for onset in onsets.get("items", []):
        if onset.get("scope") not in ("network_segment", "host_capture_boundary"):
            continue
        db.execute(
            """INSERT INTO cycle_windows SELECT DISTINCT flow,?,?,NULL FROM cycle_points
            WHERE point=? AND flow NOT IN (SELECT flow FROM cycle_windows)""",
            [onset["time"], onset["end"], onset["point_a"]],
        )
    db.execute(
        """CREATE OR REPLACE TABLE cycle_series AS SELECT point,flow,port,floor(request_first/?) * ? AS start,bool_and(clock_aligned) AS clock_aligned,
        count(*) AS cycles,count(*) FILTER(WHERE reason IS NULL) AS measured,
        count(*) FILTER(WHERE stalled AND reason IS NULL) AS stalled,
        quantile_cont(cycle_ms,.5) FILTER(WHERE reason IS NULL) AS p50_ms,
        quantile_cont(cycle_ms,.95) FILTER(WHERE reason IS NULL) AS p95_ms,
        max(cycle_ms) FILTER(WHERE reason IS NULL) AS max_ms,
        min(request_frame) AS evidence_frame FROM cycle_points GROUP BY ALL""",
        [topology.bucket_seconds] * 2,
    )
    db.execute("""CREATE OR REPLACE TABLE cycle_flow_ports AS SELECT point,flow,port,count(*) AS cycles,
        count(*) FILTER(WHERE stalled AND reason IS NULL) AS stalled,
        quantile_cont(cycle_ms,.95) FILTER(WHERE reason IS NULL) AS p95_ms,
        max(cycle_ms) FILTER(WHERE reason IS NULL) AS max_ms,
        quantile_cont(turnaround_ms,.95) FILTER(WHERE reason IS NULL) AS local_turnaround_p95_ms,
        min(request_frame) AS evidence_frame FROM cycle_points GROUP BY ALL""")
    db.execute("""CREATE OR REPLACE TABLE cycle_periods AS SELECT p.point,p.flow,p.port,
        CASE WHEN NOT p.clock_aligned OR w.reason IS NOT NULL OR w.start IS NULL THEN 'unknown'
             WHEN p.request_first<w.start THEN 'before' WHEN p.request_first<w.stop THEN 'event' ELSE 'recovery' END AS period,
        count(*) AS cycles,count(*) FILTER(WHERE stalled AND p.reason IS NULL) AS stalled,
        quantile_cont(cycle_ms,.95) FILTER(WHERE p.reason IS NULL) AS p95_ms,
        max(cycle_ms) FILTER(WHERE p.reason IS NULL) AS max_ms,
        CASE WHEN NOT p.clock_aligned THEN 'Local clock; global event period unknown' ELSE coalesce(w.reason,CASE WHEN w.start IS NULL THEN 'No supported onset/recovery window' END) END AS reason
        FROM cycle_points p LEFT JOIN cycle_windows w USING(flow) GROUP BY ALL""")
    db.execute(
        "CREATE OR REPLACE TABLE cycle_edges(hop VARCHAR,a VARCHAR,b VARCHAR,direction VARCHAR,uncertainty_ms DOUBLE,reason VARCHAR)"
    )
    if any(s["point_a"] != s["point_b"] for s in segments):
        db.executemany(
            "INSERT INTO cycle_edges VALUES (?,?,?,?,?,?)",
            [
                (
                    s["id"],
                    s["point_a"],
                    s["point_b"],
                    s["direction"],
                    s["latency_uncertainty_ms"],
                    s["reason"],
                )
                for s in segments
                if s["point_a"] != s["point_b"]
            ],
        )
    db.execute("""CREATE OR REPLACE TABLE cycle_pairs AS SELECT e.hop,e.direction,a.cycle_id,a.flow,a.port,
        a.request_first AS time,CASE WHEN e.direction='forward' THEN 'RX' ELSE 'TX' END AS component,
        CASE WHEN e.reason IS NOT NULL OR a.reason IS NOT NULL OR b.reason IS NOT NULL THEN NULL
             WHEN e.direction='forward' THEN (b.request_last-a.request_last)*1000
             ELSE (b.response_first-a.response_first)*1000 END AS added_ms,
        e.uncertainty_ms,coalesce(e.reason,a.reason,b.reason) AS reason,
        a.point AS point_a,b.point AS point_b,
        CASE WHEN e.direction='forward' THEN a.request_last_frame ELSE a.response_frame END AS frame_a,
        CASE WHEN e.direction='forward' THEN b.request_last_frame ELSE b.response_frame END AS frame_b
        FROM cycle_edges e JOIN cycle_points a ON a.point=e.a JOIN cycle_points b ON b.point=e.b AND b.cycle_id=a.cycle_id""")
    db.execute("""UPDATE cycle_pairs SET reason='Negative component exceeds relative clock uncertainty',added_ms=NULL
        WHERE added_ms < -greatest(.001,uncertainty_ms)""")
    db.execute(
        """CREATE OR REPLACE TABLE cycle_top AS SELECT cycle_id,min(flow) AS flow,max(cycle_ms) AS max_ms FROM cycle_points
        WHERE reason IS NULL GROUP BY cycle_id ORDER BY max_ms DESC,cycle_id LIMIT ?""",
        [topology.cycle_top_n],
    )
    db.execute("""CREATE OR REPLACE TABLE cycle_top_points AS SELECT p.* REPLACE(t.cycle_id AS cycle_id,
        point_names.point AS point,coalesce(p.flow,t.flow) AS flow,
        CASE WHEN p.request_frame IS NULL THEN 'No cycle observed at this point; capture/turn coverage unknown' ELSE p.reason END AS reason)
        FROM cycle_top t CROSS JOIN (SELECT a AS point FROM cycle_edges UNION SELECT b FROM cycle_edges) point_names
        LEFT JOIN cycle_points p ON p.cycle_id=t.cycle_id AND p.point=point_names.point
        ORDER BY t.max_ms DESC,t.cycle_id,point_names.point""")
    top = rows(db, "SELECT * FROM cycle_top_points")
    keys = {(r["point"], r["request_last_frame"]) for r in top if r["request_last_frame"] is not None} | {
        (r["point"], r["response_frame"]) for r in top if r["response_frame"]
    }
    if keys:
        refs = evidence(
            db,
            "(o.point,o.frame) IN (SELECT unnest(?::VARCHAR[]),unnest(?::BIGINT[]))",
            [[p for p, f in sorted(keys)], [f for p, f in sorted(keys)]],
            len(keys),
            _expand_ranges=False,
        )
        lookup = {(r["point"], r["frame"]): r for r in refs}
        for r in top:
            r["evidence"] = [
                lookup[k]
                for k in ((r["point"], r["request_last_frame"]), (r["point"], r["response_frame"]))
                if k in lookup
            ]
    hosts = [p.id for p in topology.points if p.host_capture]
    return dict(
        note=NOTE,
        scope="Saved analysis window; opaque TCP turns, not application messages",
        stall_ms=topology.cycle_stall_ms,
        top_n=topology.cycle_top_n,
        top=top,
        series=rows(db, "SELECT * FROM cycle_series ORDER BY start,point,flow LIMIT 20000"),
        flow_ports=rows(db, "SELECT * FROM cycle_flow_ports ORDER BY max_ms DESC NULLS LAST,point,flow,port LIMIT 2000"),
        periods=rows(db, "SELECT * FROM cycle_periods ORDER BY point,flow,period LIMIT 6000"),
        pairs=rows(db, "SELECT * FROM cycle_pairs ORDER BY added_ms DESC NULLS LAST,time,hop,flow,frame_a,frame_b LIMIT 2000"),
        host_local=rows(
            db,
            "SELECT * FROM cycle_flow_ports WHERE point IN (SELECT unnest(?::VARCHAR[])) ORDER BY max_ms DESC",
            [hosts],
        ),
    )


def cycle_findings(db, topology, segments):
    from .rtp import media_finding
    from .headlines import time_labels

    db.execute(
        """CREATE OR REPLACE TABLE cycle_degradations AS WITH baseline AS(
        SELECT p.hop,p.flow,median(p.added_ms) AS baseline_ms,count(*) AS samples
        FROM cycle_pairs p JOIN cycle_windows w USING(flow)
        WHERE p.reason IS NULL AND w.reason IS NULL AND p.time<w.start GROUP BY p.hop,p.flow), changed AS(
        SELECT p.*,b.baseline_ms,w.start,w.stop FROM cycle_pairs p JOIN baseline b USING(hop,flow)
        JOIN cycle_windows w USING(flow) WHERE p.reason IS NULL AND b.samples>=3 AND w.reason IS NULL
        AND p.time>=w.start AND p.time<w.stop AND p.added_ms>b.baseline_ms+greatest(1,2*p.uncertainty_ms))
        SELECT hop,flow,component,count(DISTINCT cycle_id) AS count,min(start) AS start,max(stop) AS stop,
        min(baseline_ms) AS baseline_ms,max(added_ms-baseline_ms) AS max_ms,max(uncertainty_ms) AS uncertainty_ms,
        arg_max(point_a,added_ms) AS point_a,arg_max(point_b,added_ms) AS point_b,
        arg_max(frame_a,added_ms) AS frame_a,arg_max(frame_b,added_ms) AS frame_b
        FROM changed GROUP BY hop,flow,component HAVING count(DISTINCT cycle_id)>=3 AND max_ms>=?""",
        [topology.cycle_stall_ms],
    )
    findings = []
    for r in rows(db, "SELECT * FROM cycle_degradations ORDER BY max_ms DESC NULLS LAST,hop,flow LIMIT 100"):
        s = next(s for s in segments if s["id"] == r["hop"])
        refs = evidence(
            db,
            "(o.point=? AND o.frame=?) OR(o.point=? AND o.frame=?)",
            [r["point_a"], r["frame_a"], r["point_b"], r["frame_b"]],
            2,
            _expand_ranges=False,
        )
        times = time_labels(r["start"], topology.report_timezone)
        text = f"{r['component']} TCP-cycle wait increased between {s['label'].replace(' → ', ' and ')} by up to {r['max_ms']:.2f} ms from {times['local']} / {times['utc']} (baseline {r['baseline_ms']:.3f} ms, uncertainty ±{r['uncertainty_ms']:.3f} ms). Includes holding/recovery, not a claim of packet transit or application processing."
        r["window"] = dict(start=r["start"], end=r["stop"])
        f = media_finding(db, "cycle_wait", s, r["start"], text, r, refs)
        f.update(
            severity="high", time_range=[r["start"], r["stop"]], tooltip=NOTE, cause="observed_cycle_wait"
        )
        findings.append(f)
    return findings
