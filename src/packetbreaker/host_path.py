"""Matched boundary delay is separate from same-host request/response service time."""

from .store import rows
from .evidence import evidence
from .rtp import media_finding
from .onset import latency_window
from .headlines import time_labels

NOTE = "Delay is observed between a wire mirror and an OS host capture. It includes capture/NIC/driver/GRO/TSO timing and is not proof of application processing or a specific driver cause. Byte ranges preserve offload matching. Local service time uses separately decoded HTTP boundaries; opaque protocols remain unknown."


def host_path(db, topology, segments):
    points = {p.id: p for p in topology.points}
    selected = [
        s
        for s in segments
        if (s["direction"] == "forward" and points[s["point_b"]].host_capture)
        or (s["direction"] == "reverse" and points[s["point_a"]].host_capture)
    ]
    if not selected:
        return dict(items=[], streams=[], series=[], local_service={}, note=NOTE), []
    db.execute(
        "CREATE OR REPLACE TEMP TABLE host_edges(hop VARCHAR,a VARCHAR,b VARCHAR,direction VARCHAR,role VARCHAR,uncertainty_ms DOUBLE,reason VARCHAR)"
    )
    db.executemany(
        "INSERT INTO host_edges VALUES (?,?,?,?,?,?,?)",
        [
            (
                s["id"],
                s["point_a"],
                s["point_b"],
                s["direction"],
                "rx" if s["direction"] == "forward" else "tx",
                s["latency_uncertainty_ms"],
                s["reason"]
                or (
                    "Host boundary clock uncertainty unverified"
                    if s.get("offset_uncertainty_ms") is None
                    else None
                ),
            )
            for s in selected
        ],
    )
    db.execute(
        """CREATE OR REPLACE TABLE host_transit AS SELECT e.hop,e.role AS direction,o.flow,m.key_a,m.key_b,m.time_a AS time,
        (m.time_b-m.time_a)*1000 AS delay_ms,m.bytes,e.uncertainty_ms,e.reason
        FROM observation_matches m JOIN host_edges e ON m.point_a=e.a AND m.point_b=e.b AND m.direction=e.direction
        JOIN obs o ON o.point=m.point_a AND o.packet_key=m.key_a WHERE o.proto='TCP' AND o.length>0
        AND (? IS NULL OR m.time_a>=?) AND (? IS NULL OR m.time_a<=?)""",
        [topology.start, topology.start, topology.end, topology.end],
    )
    db.execute("""CREATE OR REPLACE TABLE host_path_series AS SELECT hop,direction,flow,floor(time) AS start,floor(time)+1 AS "end",
        count(*) AS matched_ranges,sum(bytes) AS bytes,quantile_cont(delay_ms,.5) AS p50_ms,quantile_cont(delay_ms,.95) AS p95_ms,max(delay_ms) AS max_ms,
        sum(bytes) FILTER(WHERE delay_ms>greatest(1,2*uncertainty_ms)) AS delayed_bytes,
        sum(greatest(0,delay_ms-uncertainty_ms)*bytes) AS delay_byte_ms,
        max(uncertainty_ms) AS uncertainty_ms,min(reason) AS reason,arg_max(key_a,delay_ms) AS evidence_key
        FROM host_transit GROUP BY ALL""")
    hosts = [p.id for p in topology.points if p.host_capture]
    service = rows(
        db,
        """SELECT point,flow,count(*) AS samples,quantile_cont((response-complete)*1000,.95) AS p95_ms,
        max((response-complete)*1000) AS max_ms,min(last_frame) AS request_frame,arg_min(response_frame,last_frame) AS response_frame
        FROM proxy_requests WHERE kind='http' AND ready AND response IS NOT NULL AND response>=complete AND point IN(SELECT unnest(?::VARCHAR[])) GROUP BY point,flow""",
        [hosts],
    )
    for r in service:
        r["evidence"] = evidence(
            db, "o.point=? AND o.frame IN (?,?)", [r["point"], r["request_frame"], r["response_frame"]], 2
        )
    # For opaque protocols expose the observed data-burst turnaround, never invent application boundaries.
    db.execute(
        """CREATE OR REPLACE TEMP TABLE host_bursts AS WITH ordered AS (
        SELECT *,lag(direction) OVER(PARTITION BY point,flow ORDER BY ts,frame) AS previous FROM obs
        WHERE point IN(SELECT unnest(?::VARCHAR[])) AND proto='TCP' AND length>0 AND eligible), numbered AS(
        SELECT *,sum(CASE WHEN direction IS DISTINCT FROM previous THEN 1 ELSE 0 END) OVER(PARTITION BY point,flow ORDER BY ts,frame) AS burst FROM ordered)
        SELECT point,flow,burst,min(direction) AS direction,min(ts) AS first_time,max(ts) AS last_time,
        arg_max((seq+length)%4294967296,ts) AS end_seq,arg_min(ack,ts) AS ack,
        arg_min(frame,ts) AS first_frame,arg_max(frame,ts) AS last_frame FROM numbered GROUP BY point,flow,burst""",
        [hosts],
    )
    turnaround = rows(
        db,
        """SELECT q.point,q.flow,count(*) AS samples,quantile_cont((r.first_time-q.last_time)*1000,.95) AS p95_ms,
        max((r.first_time-q.last_time)*1000) AS max_ms,min(q.last_frame) AS request_frame,arg_min(r.first_frame,q.last_frame) AS response_frame
        FROM host_bursts q JOIN host_bursts r ON q.point=r.point AND q.flow=r.flow AND r.burst=q.burst+1
        WHERE q.direction='forward' AND r.direction='reverse' AND r.ack=q.end_seq AND r.first_time>=q.last_time GROUP BY q.point,q.flow""",
    )
    for r in turnaround:
        r["evidence"] = evidence(
            db, "o.point=? AND o.frame IN (?,?)", [r["point"], r["request_frame"], r["response_frame"]], 2
        )
        r["meaning"] = "ACK-consistent local data-burst turnaround; application request boundaries unknown"
    aggregate = db.execute(
        """SELECT count(*),quantile_cont((response-complete)*1000,.95) FROM proxy_requests
        WHERE kind='http' AND ready AND response>=complete AND point IN(SELECT unnest(?::VARCHAR[]))""",
        [hosts],
    ).fetchone()
    streams = rows(
        db,
        """SELECT hop,direction,flow,count(*) AS matched_ranges,sum(bytes) AS bytes,quantile_cont(delay_ms,.95) AS p95_ms,
        max(delay_ms) AS max_ms,max(uncertainty_ms) AS uncertainty_ms,min(reason) AS reason,
        sum(bytes) FILTER(WHERE delay_ms>greatest(1,2*uncertainty_ms)) AS delayed_bytes,
        sum(greatest(0,delay_ms-uncertainty_ms)*bytes) AS delay_byte_ms,arg_max(key_a,delay_ms) AS evidence_key
        FROM host_transit GROUP BY hop,direction,flow""",
    )
    findings = []
    items = []
    for stream in streams:
        refs = evidence(db, "o.packet_key=?", [stream["evidence_key"]], 16)
        stream["evidence"] = refs
        stream["tooltip"] = NOTE
        local = next((r for r in service if r["flow"] == stream["flow"]), None)
        stream["transport_turnaround"] = next((r for r in turnaround if r["flow"] == stream["flow"]), None)
        stream["local_service"] = local or dict(
            samples=0, p95_ms=None, reason="No uniquely decoded complete request/response boundaries"
        )
        if stream["reason"] or not stream["delayed_bytes"]:
            continue
        total = sum(s["delay_byte_ms"] or 0 for s in streams if s["flow"] == stream["flow"])
        stream["delay_share_percent"] = 100 * stream["delay_byte_ms"] / total if total else None
        segment = next(s for s in selected if s["id"] == stream["hop"])
        series = rows(
            db,
            "SELECT * FROM host_path_series WHERE hop=? AND flow=? ORDER BY start",
            [stream["hop"], stream["flow"]],
        )
        for bucket in series:
            bucket["evidence"] = evidence(db, "o.packet_key=?", [bucket["evidence_key"]], 8)
        stream["series"] = series
        combined = rows(
            db,
            'SELECT start,max("end") AS "end",max(p95_ms) AS latency_p95_ms FROM host_path_series WHERE flow=? AND reason IS NULL GROUP BY start ORDER BY start',
            [stream["flow"]],
        )
        window, why = latency_window(combined, max(1, 2 * stream["uncertainty_ms"]))
        stream["window"] = window
        stream["window_reason"] = why
        if not window:
            continue
        stream["periods"] = rows(
            db,
            """SELECT CASE WHEN time<? THEN 'before' WHEN time<? THEN 'event' ELSE 'recovery' END AS period,
            count(*) AS matched_ranges,sum(bytes) AS bytes,quantile_cont(delay_ms,.95) AS p95_ms,max(delay_ms) AS max_ms
            FROM host_transit WHERE hop=? AND flow=? GROUP BY period ORDER BY min(time)""",
            [window["time"], window["end"], stream["hop"], stream["flow"]],
        )
        stream["window"]["start"] = window["time"]
        label = "receive" if stream["direction"] == "rx" else "transmit"
        local_text = (
            f"the application responds in {local['p95_ms']:.3f} ms locally (HTTP p95)"
            if local
            else f"host-local data turnaround is {stream['transport_turnaround']['p95_ms']:.3f} ms (p95); application boundaries unknown"
            if stream["transport_turnaround"]
            else "host-local application response time is unknown"
        )
        headline = f"Delay occurs between {points[segment['point_a']].label} and {points[segment['point_b']].label}; {local_text}."
        headline += f" Observed event window {time_labels(window['time'], topology.report_timezone)['local']} / {time_labels(window['time'], topology.report_timezone)['utc']} through {time_labels(window['end'], topology.report_timezone)['utc']}; recovery {'confirmed' if window['recovery_confirmed'] else 'unknown'}, boundary uncertainty ±{stream['uncertainty_ms']:.3f} ms."
        stream["headline"] = headline
        f = media_finding(
            db,
            f"host_{label}_delay",
            segment,
            window["time"],
            headline,
            {k: v for k, v in stream.items() if k not in ("evidence", "series", "tooltip")},
            refs,
        )
        f["time_range"] = [window["time"], window["end"]]
        f["tooltip"] = NOTE
        f["cause"] = "host_capture_boundary"
        findings.append(f)
        items.append(stream)
    return dict(
        items=items,
        streams=streams,
        series=rows(db, "SELECT * FROM host_path_series ORDER BY start,hop,flow LIMIT 20000"),
        local_service=dict(
            samples=aggregate[0],
            p95_ms=aggregate[1],
            flows=service,
            transport_turnaround=turnaround,
            reason=None if aggregate[0] else "No uniquely decoded application boundaries",
        ),
        note=NOTE,
        scope="Saved selected window; per-second series; RX/TX shares are byte-weighted excess delay, not CPU time",
    ), findings
