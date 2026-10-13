"""Matched boundary delay is separate from same-host request/response service time."""

from .store import rows
from .evidence import evidence
from .rtp import media_finding
from .onset import latency_window
from .headlines import time_labels

NOTE = "Delay is observed between a path capture point and an OS host capture. It includes capture/NIC/driver/GRO/TSO timing and is not proof of application processing or a specific driver cause. Byte ranges preserve offload matching. Local service time uses separately decoded HTTP boundaries; opaque protocols remain unknown."


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
    items = []
    for stream in streams:
        stream["evidence"] = evidence(db, "o.packet_key=?", [stream["evidence_key"]], 4, _expand_ranges=False)
        stream["tooltip"] = NOTE
        stream["local_service"] = next((r for r in service if r["flow"] == stream["flow"]), None)
        stream["transport_turnaround"] = next((r for r in turnaround if r["flow"] == stream["flow"]), None)
    report = dict(
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
        scope="Saved selected window; RX/TX shares are byte-weighted excess boundary delay",
    )
    return aggregate_host(db, topology, selected, report), []


def aggregate_host(db, topology, segments, report):
    """Keep flow details, but compute direction metrics from observations, not averages of p95s."""
    global_series = rows(
        db,
        'SELECT start,max("end") AS "end",max(p95_ms) AS latency_p95_ms FROM host_path_series WHERE reason IS NULL GROUP BY start ORDER BY start',
    )
    uncertainty = max((s.get("uncertainty_ms") or 0 for s in report["streams"]), default=0)
    window, why = latency_window(global_series, max(1, 2 * uncertainty))
    if window:
        window["start"] = window["time"]
    report["window"] = window
    report["window_reason"] = why
    items = []
    total = sum(s["delay_byte_ms"] or 0 for s in report["streams"] if not s["reason"])
    for direction in ("rx", "tx"):
        details = [s for s in report["streams"] if s["direction"] == direction]
        affected = [s for s in details if not s["reason"] and s["delayed_bytes"]]
        if not affected:
            continue
        # The worst boundary names the observed localisation; all flows remain in detail.
        dominant = max(affected, key=lambda s: s["max_ms"])
        segment = next(s for s in segments if s["id"] == dominant["hop"])
        item = rows(
            db,
            """SELECT count(*) AS matched_ranges,sum(bytes) AS bytes,
            quantile_cont(delay_ms,.95) AS p95_ms,max(delay_ms) AS max_ms,
            max(uncertainty_ms) AS uncertainty_ms,sum(bytes) FILTER(WHERE delay_ms>greatest(1,2*uncertainty_ms)) AS delayed_bytes,
            sum(greatest(0,delay_ms-uncertainty_ms)*bytes) AS delay_byte_ms
            FROM host_transit WHERE direction=? AND reason IS NULL""",
            [direction],
        )[0]
        series = rows(
            db,
            """SELECT floor(time) AS start,floor(time)+1 AS "end",
            quantile_cont(delay_ms,.95) AS p95_ms,max(delay_ms) AS max_ms,
            arg_max(key_a,delay_ms) AS evidence_key FROM host_transit
            WHERE direction=? AND reason IS NULL GROUP BY ALL ORDER BY start""",
            [direction],
        )
        for r in series:
            r["evidence"] = evidence(db, "o.packet_key=?", [r.pop("evidence_key")], 2, _expand_ranges=False)
        current = window
        if current is None:
            # Preserve a short-capture observation, with explicitly unknown onset.
            if len(series) >= 8 or item["p95_ms"] <= max(1, 2 * item["uncertainty_ms"]):
                continue
            current = dict(
                start=series[0]["start"],
                time=series[0]["start"],
                end=series[-1]["end"],
                status="unknown",
                reason=why,
                recovery_confirmed=False,
            )
        periods = rows(
            db,
            """SELECT CASE WHEN time<? THEN 'before' WHEN time<? THEN 'event' ELSE 'recovery' END AS period,
            count(*) AS matched_ranges,sum(bytes) AS bytes,quantile_cont(delay_ms,.95) AS p95_ms,max(delay_ms) AS max_ms
            FROM host_transit WHERE direction=? AND reason IS NULL GROUP BY period ORDER BY min(time)""",
            [current["start"], current["end"], direction],
        )
        for detail in details:
            detail["window"] = current
        item.update(
            hop=dominant["hop"],
            hops=sorted({s["hop"] for s in affected}),
            direction=direction,
            flow=None,
            affected_flow_count=len({s["flow"] for s in affected}),
            flow_details=details,
            series=series,
            window=current,
            window_reason=why,
            periods=periods,
            delay_share_percent=100 * item["delay_byte_ms"] / total if total else None,
            evidence=dominant["evidence"],
            tooltip=NOTE,
            segment_label=segment["label"],
        )
        items.append(item)
    report["items"] = items
    return report


def finish_host_summary(db, topology, segments, report):
    hosts = [p.id for p in topology.points if p.host_capture]
    aggregate = rows(
        db,
        """SELECT count(*) AS samples,quantile_cont(turnaround_ms,.95) AS p95_ms
        FROM cycle_points WHERE point IN(SELECT unnest(?::VARCHAR[])) AND reason IS NULL""",
        [hosts],
    )[0]
    report["local_service"]["cycle_aggregate"] = aggregate
    findings = []
    for item in report["items"]:
        local = report["local_service"]
        text = (
            f"the application responds in {aggregate['p95_ms']:.3f} ms locally (HTTP cycle p95 over {aggregate['samples']} cycles)"
            if local["samples"] == aggregate["samples"] and aggregate["samples"]
            else f"host-local data turnaround p95 {aggregate['p95_ms']:.3f} ms over {aggregate['samples']} cycles; application boundaries unknown"
            if aggregate["samples"]
            else "host-local turnaround unknown"
        )
        w = item["window"]
        headline = f"Delay occurs between {item['segment_label'].replace(' → ', ' and ')}; {text}. {item['affected_flow_count']} affected flow(s)."
        if w.get("status") == "unknown":
            headline += f" Onset/recovery unknown: {w.get('reason')}."
        else:
            headline += f" Global event window {time_labels(w['start'], topology.report_timezone)['local']} / {time_labels(w['start'], topology.report_timezone)['utc']} through {time_labels(w['end'], topology.report_timezone)['utc']}; recovery {'confirmed' if w['recovery_confirmed'] else 'unknown'}."
        headline += f" Clock uncertainty ±{item['uncertainty_ms']:.3f} ms."
        item["local_service"] = report["local_service"]
        item["headline"] = headline
        segment = next(s for s in segments if s["id"] == item["hop"])
        kind = "host_receive_delay" if item["direction"] == "rx" else "host_transmit_delay"
        f = media_finding(
            db,
            kind,
            segment,
            w["start"],
            headline,
            {k: v for k, v in item.items() if k not in ("evidence", "series", "flow_details", "tooltip")},
            item["evidence"],
        )
        f.update(time_range=[w["start"], w["end"]], tooltip=NOTE, cause="host_capture_boundary")
        f["metrics"]["flows"] = [
            s["flow"] for s in item["flow_details"] if s.get("delayed_bytes") and not s.get("reason")
        ]
        findings.append(f)
    return findings


def group_host_losses(findings, segments, topology):
    points = {p.id: p for p in topology.points}
    groups = []
    for s in segments:
        if not (points[s["point_a"]].host_capture or points[s["point_b"]].host_capture):
            continue
        members = [
            f
            for f in findings
            if f["hop"] == s["id"]
            and f["type"]
            in (
                "impactful_loss",
                "recovered_loss",
                "unrecovered_loss",
                "host_transmit_path_loss",
                "host_receive_path_loss",
            )
        ]
        if not members:
            continue
        counts = {}
        for f in members:
            counts[f["type"]] = counts.get(f["type"], 0) + f["metrics"].get("count", 0)
        role = "TX" if points[s["point_a"]].host_capture else "RX"
        text = f"Loss between {points[s['point_a']].label} and {points[s['point_b']].label} (host {role} path or network; no mirror point in between)"
        groups.append(
            dict(
                hop=s["id"],
                headline=text,
                counts=counts,
                finding_ids=[f["id"] for f in members],
                evidence=members[0]["evidence"],
            )
        )
        for f in members:
            f["metrics"]["boundary_loss_heading"] = text
    return groups


def host_loss_type(points, a, b, kind, recovered):
    """A host boundary label needs positive retry delivery, not absence alone."""
    if kind not in ("impactful_loss", "recovered_loss") or not recovered:
        return None
    if points[a].host_capture and not points[b].host_capture:
        return "host_transmit_path_loss"
    if points[b].host_capture and not points[a].host_capture:
        return "host_receive_path_loss"
    return None


def polish_findings(findings, segments, topology, onsets):
    points = {p.id: p for p in topology.points}
    hops = {s["id"]: s for s in segments}
    for f in findings:
        s = hops.get(f["hop"])
        if not s:
            continue
        m = f["metrics"]
        kind = host_loss_type(
            points,
            s["point_a"],
            s["point_b"],
            f["type"],
            m.get("delivered_retries", 0) == m.get("count") and m.get("data_count", 0) == m.get("count"),
        )
        if kind:
            m["recovery_class"] = f["type"]
            f["type"] = kind
            f["cause"] = "host_capture_boundary"
            f["headline"] = f["summary"] = (
                f"{m['count']} {kind.replace('_', ' ')} event(s) between {s['label'].replace(' → ', ' and ')}; "
                "original byte range absent across the boundary, later retry delivered."
            )
            f["tooltip"] = (
                "Host/wire boundary localisation, not proof of a NIC, driver or application cause. Capture-miss and uncertain events keep their original classification."
            )
    delays = [
        f
        for f in findings
        if f["type"] in ("host_receive_delay", "host_transmit_delay")
        and f["confidence"] == "supported"
        and f["metrics"].get("window")
    ]
    dominant = None
    if delays:
        candidate = max(delays, key=lambda f: f["metrics"]["max_ms"] - f["metrics"]["uncertainty_ms"])
        added = candidate["metrics"]["max_ms"] - candidate["metrics"]["uncertainty_ms"]
        competing = [
            (hops.get(i.get("segment"), {}).get("max_ms") or i.get("value", 0)) - i.get("baseline_value", 0)
            for i in onsets.get("items", [])
            if i.get("metric") == "latency_p95_ms" and i.get("scope") != "host_capture_boundary"
        ]
        if added > max(competing, default=0):
            dominant = candidate
            dominant["severity"] = "high"
            dominant["metrics"]["primary_degradation"] = True
            hops[dominant["hop"]]["severity"] = "high"
            onsets["summary"] = dominant["headline"]
            if candidate["metrics"]["window"].get("status") != "unknown":
                onsets["status"] = "detected"
                onsets["global_event_window"] = candidate["metrics"]["window"]
    rank = {"high": 0, "low": 1, "quality": 2, "unknown": 3}
    findings.sort(key=lambda f: (f is not dominant, rank[f["severity"]], f["time_range"][0]))
    return dominant


def lead_degradation(report, findings, segments):
    """Direct degradation measurements outrank diagnostic integrity hypotheses."""
    allowed = {
        "cycle_wait",
        "host_receive_delay",
        "host_transmit_delay",
        "host_transmit_path_loss",
        "host_receive_path_loss",
        "impactful_loss",
        "recovered_loss",
        "confirmed_device_drop",
    }
    candidates = [f for f in findings if f["type"] in allowed and f["confidence"] == "supported"]
    if not candidates:
        return

    def score(f):
        m = f["metrics"]
        return (
            bool(m.get("primary_degradation")),
            bool(m.get("window")),
            (m.get("max_ms") or m.get("max_recovery_ms") or m.get("max_stall_ms") or 0)
            * max(1, m.get("count", 1)),
        )

    primary = max(candidates, key=score)
    findings.sort(key=lambda f: (f is not primary, f["severity"] not in ("high", "low"), f["time_range"][0]))
    report["findings"] = findings[:200]
    report["finding_count"] = len(findings)
    if (
        primary["type"] == "cycle_wait"
        or report.get("host_path", {}).get("streams")
        or any(f["type"].startswith("host_") for f in candidates)
    ):
        report["verdict"] = primary.get("headline") or primary["summary"]
    elif report["verdict"] == "Path integrity findings observed":
        report["verdict"] = primary.get("headline") or primary["summary"]
