"""Local capture-rate excursions; temporal loss association never proves a cause."""

from .store import rows
from .clock import ClockModel

NOTE = (
    "Rolling capture-byte rate, not physical line capacity. At least 8 packets and 4× the median "
    "nonempty fixed-window rate (floor 1 Mbps). SPAN copies are excluded. Offload, timestamp batching "
    "and incomplete coverage can obscure wire timing. Nearby loss is corroboration only; cause unknown."
)


def associations(burst, onsets, model):
    end = model.correct(burst["end"])
    if end is None or model.uncertainty is None:
        return []
    result = []
    for onset in onsets:
        if onset["point_a"] != burst["point"] or onset["metric"] != "loss_percent":
            continue
        if onset.get("clock_uncertainty_ms") is None:
            continue
        stamps = [
            r["corrected_time"]
            for r in onset.get("evidence", [])
            if r.get("point") == burst["point"]
            and r.get("corrected_time") is not None
            and onset["time"] <= r["corrected_time"] < onset["end"]
        ]
        if not stamps:
            continue
        gap = (min(stamps) - end) * 1000
        uncertainty = (model.uncertainty or 0) * 1000 + (onset.get("clock_uncertainty_ms") or 0)
        if -uncertainty <= gap <= 100 + uncertainty:
            result.append(
                dict(
                    segment=onset["segment"],
                    loss_time=min(stamps),
                    gap_ms=gap,
                    uncertainty_ms=uncertainty,
                    ordering="before" if gap > uncertainty else "unknown",
                    relation="corroboration_only",
                    cause="unknown",
                    evidence=onset.get("evidence", []),
                    reason="Capture-rate burst is near the next segment loss onset; this does not establish queue overflow or any loss cause",
                )
            )
    return result


def wire_evidence(lookup, point, frames):
    result = []
    for frame in sorted(set(frames) - {None}):
        r = lookup.get((point, frame))
        if r is None:
            continue
        result.append(
            dict(
                point=point,
                capture_id=r["capture_id"],
                file=r["file"],
                frame=r["frame"],
                observed_time=r["ts"],
                corrected_time=None,
                display_filter=f"frame.number == {r['frame']}",
                content_filter=f"frame.len == {r['wirelen']} && frame.time_epoch >= {r['ts'] - 1e-6:.9f} && frame.time_epoch <= {r['ts'] + 1e-6:.9f}",
                filter_note="Physical capture-frame rate evidence; timestamp/length filters can match simultaneous copies",
            )
        )
    return result


def build_microbursts(db, topology, models, onsets, start=None, end=None):
    width = topology.microburst_window_ms / 1000
    db.execute(
        "CREATE OR REPLACE TEMP TABLE burst_clocks(point VARCHAR,offset_s DOUBLE,drift DOUBLE,epoch DOUBLE)"
    )
    db.executemany(
        "INSERT INTO burst_clocks VALUES (?,?,?,?)",
        [
            (
                p.id,
                models.get(p.capture_id, ClockModel()).offset,
                models.get(p.capture_id, ClockModel()).drift,
                models.get(p.capture_id, ClockModel()).epoch,
            )
            for p in topology.points
        ],
    )
    db.execute(
        """CREATE OR REPLACE TEMP TABLE burst_wire AS WITH w AS (
        SELECT w.*,lag(ts) OVER(PARTITION BY point ORDER BY ts,frame) AS prev_ts,
        lag(frame_hash) OVER(PARTITION BY point ORDER BY ts,frame) AS prev_hash,
        c.epoch+(w.ts-c.epoch-c.offset_s)/(1+c.drift) AS corrected
        FROM wire_observations w JOIN burst_clocks c USING(point))
        SELECT * FROM w WHERE NOT coalesce(caplen=wirelen AND frame_hash<>'' AND frame_hash=prev_hash AND ts-prev_ts<=?,false)
        AND (corrected IS NULL OR ((? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<=?)))""",
        [topology.duplicate_us / 1e6, start, start, end, end],
    )
    db.execute(f"""CREATE OR REPLACE TABLE microburst_windows AS SELECT *,
        sum(wirelen*8) OVER w/{width} AS bps,count(*) OVER w AS packets,
        min(ts) OVER w AS lo,arg_min(frame,ts) OVER w AS first_frame,
        min((ts-prev_ts)*1000000) OVER w AS min_gap_us,
        count(*) FILTER(WHERE transport_length>9000) OVER w AS offload,
        min(ts) OVER(PARTITION BY point) AS capture_start
        FROM burst_wire WINDOW w AS(PARTITION BY point ORDER BY ts RANGE BETWEEN {width} PRECEDING AND CURRENT ROW)""")
    db.execute(f"""CREATE OR REPLACE TEMP TABLE burst_baseline AS WITH bins AS(
        SELECT point,floor(ts/{width}) AS bucket,sum(wirelen*8)/{width} AS bps FROM burst_wire GROUP BY ALL)
        SELECT point,median(bps) AS baseline_bps,greatest(1000000,4*median(bps)) AS threshold_bps FROM bins GROUP BY point""")
    db.execute(f"""CREATE OR REPLACE TEMP TABLE burst_candidates AS WITH b AS(
        SELECT w.*,b.baseline_bps,b.threshold_bps FROM microburst_windows w JOIN burst_baseline b USING(point)
        WHERE packets>=8 AND bps>=b.threshold_bps AND ts-capture_start>={width} AND offload=0),
        gaps AS(SELECT *,lag(ts) OVER(PARTITION BY point ORDER BY ts,frame) AS previous FROM b)
        SELECT *,sum(CASE WHEN previous IS NULL OR lo>previous THEN 1 ELSE 0 END)
            OVER(PARTITION BY point ORDER BY ts,frame) AS episode FROM gaps""")
    db.execute("""CREATE OR REPLACE TABLE microbursts AS SELECT point,episode,min(lo) AS start,max(ts) AS "end",
        max(bps)/1000000 AS peak_mbps,min(baseline_bps)/1000000 AS baseline_mbps,min(threshold_bps)/1000000 AS threshold_mbps,
        (max(ts)-min(lo))*1000 AS duration_ms,min(min_gap_us) AS min_interarrival_us,
        arg_min(first_frame,lo) AS first_frame,arg_max(frame,bps) AS peak_frame,arg_max(frame,ts) AS last_frame
        FROM burst_candidates GROUP BY point,episode""")
    points = rows(
        db,
        f"""SELECT w.point,min(w.ts) AS start,max(w.ts) AS "end",max(w.ts)-min(w.ts) AS observed_seconds,
        max(w.bps) FILTER(WHERE w.ts-w.capture_start>={width} AND w.offload=0)/1000000 AS peak_observed_mbps,min(b.baseline_bps)/1000000 AS baseline_mbps,
        min(b.threshold_bps)/1000000 AS threshold_mbps,max(x.n) AS burst_count,max(x.duration_ms) AS max_duration_ms,
        max(x.n)/nullif(max(w.ts)-min(w.ts),0) AS frequency_hz,
        arg_min(w.frame,w.ts) AS first_frame,arg_max(w.frame,w.ts) AS last_frame,arg_max(w.frame,w.bps) FILTER(WHERE w.ts-w.capture_start>={width} AND w.offload=0) AS peak_frame
        FROM microburst_windows w JOIN burst_baseline b USING(point)
        LEFT JOIN(SELECT point,count(*) AS n,max(duration_ms) AS duration_ms FROM microbursts GROUP BY point) x USING(point)
        GROUP BY w.point ORDER BY w.point""",
    )
    total = db.execute("SELECT count(*) FROM microbursts").fetchone()[0]
    items = rows(db, "SELECT * FROM microbursts ORDER BY peak_mbps DESC,point,start LIMIT 200")
    keys = {
        (r["point"], r[field])
        for r in points + items
        for field in ("first_frame", "peak_frame", "last_frame")
        if r[field] is not None
    }
    import json

    proof = {
        (r["point"], r["frame"]): r
        for r in rows(
            db,
            """SELECT w.*,c.name AS file FROM wire_observations w
        JOIN (SELECT unnest(from_json(?, '[{"point":"VARCHAR","frame":"BIGINT"}]')) k) refs
        ON w.point=refs.k.point AND w.frame=refs.k.frame JOIN captures c ON c.id=w.capture_id""",
            [json.dumps([dict(point=p, frame=f) for p, f in keys])],
        )
    }
    bypoint = {p.id: p for p in topology.points}
    for p in points:
        p["burst_count"] = p["burst_count"] or 0
        p["frequency_hz"] = p["frequency_hz"] or 0 if p["observed_seconds"] >= width else None
        p["label"] = bypoint[p["point"]].label
        p["window_ms"] = topology.microburst_window_ms
        p["tooltip"] = NOTE
        p["evidence"] = wire_evidence(proof, p["point"], [p["first_frame"], p["peak_frame"], p["last_frame"]])
        if p["peak_observed_mbps"] is None:
            p["burst_count"] = p["frequency_hz"] = None
            p["tooltip"] += " No complete, non-offload measurement window; rate/burst absence unknown."
    for item in items:
        model = models.get(bypoint[item["point"]].capture_id, ClockModel())
        item.update(
            cause="unknown",
            tooltip=NOTE,
            corrected_start=model.correct(item["start"]),
            corrected_end=model.correct(item["end"]),
            clock_uncertainty_ms=model.uncertainty * 1000 if model.uncertainty is not None else None,
            evidence=wire_evidence(
                proof, item["point"], [item["first_frame"], item["peak_frame"], item["last_frame"]]
            ),
        )
        item["loss_associations"] = associations(item, onsets.get("items", []), model)
        if item["duration_ms"] == 0:
            item["duration_ms"] = None
    return dict(
        window_ms=topology.microburst_window_ms,
        points=points,
        items=items,
        total=total,
        note=NOTE + " Up to 200 strongest burst episodes shown; point counts use all episodes.",
    )
