"""Session-behaviour findings: who closed connections, peer-side state loss, sender rate drops.

These explain incidents where the network path is healthy but connections break or slow down.
All measurements come from one observation point, the capture nearest to the client, so that
each packet is counted once. Delivered rates use the receiver's ACK progression, which capture
loss of the data segments cannot distort.
"""

from statistics import median

from .evidence import evidence
from .headlines import time_labels
from .store import rows

STORM_GAP_S = 0.05
TRIGGER_WINDOW_S = 1.0
RECONNECT_WINDOW_S = 300.0
RATE_BUCKET_S = 10.0
RATE_DROP_RATIO = 0.6
RATE_DROP_MIN_BUCKETS = 6
MIN_BASELINE_BUCKETS = 12
BULK_SHARE = 0.10
NOTE = (
    "Session behaviour observed at one capture point. Endpoint roles come from the SYN direction "
    "and the configured client CIDRs; causes outside the captures are not observed."
)


def _clock(ts, zone):
    return time_labels(ts, zone)["local"].split(" ")[1][:12]


def _finding(kind, severity, start, end, summary, metrics, refs, hop):
    return dict(
        id=f"session:{kind}:{start:.6f}",
        type=kind,
        hop=hop,
        device=None,
        direction="observed",
        severity=severity,
        confidence="supported",
        time_range=[start, end],
        summary=summary,
        headline=summary,
        tooltip=NOTE,
        metrics=metrics,
        evidence=refs,
        cause="unknown",
        clock_caveat="Observed at one capture point; clock alignment is not needed for these findings",
    )


def _prepare(db, point):
    db.execute(
        """CREATE OR REPLACE TEMP TABLE sess_obs AS SELECT frame,flow,direction,src,dst,sport,dport,
        coalesce(corrected,ts) AS t,flags,length,ipid,ttl,seq,ack,"window" AS win,retrans,zero_window,rtt
        FROM obs WHERE point=? AND proto='TCP' AND flow IS NOT NULL AND direction IN ('forward','reverse')""",
        [point],
    )
    db.execute(
        """CREATE OR REPLACE TEMP TABLE sess_flows AS SELECT flow,min(t) AS first_t,max(t) AS last_t,
        min(t) FILTER(WHERE (flags&18)=2 AND direction='forward') AS syn_t,
        any_value(src) FILTER(WHERE direction='forward') AS client_ip,
        any_value(sport) FILTER(WHERE direction='forward') AS client_port,
        any_value(dst) FILTER(WHERE direction='forward') AS server_ip,
        any_value(dport) FILTER(WHERE direction='forward') AS server_port,
        coalesce(sum(length) FILTER(WHERE direction='forward'),0) AS c2s_bytes,
        coalesce(sum(length) FILTER(WHERE direction='reverse'),0) AS s2c_bytes,
        min(t) FILTER(WHERE (flags&5)>0) AS close_t
        FROM sess_obs GROUP BY flow""",
    )


def connection_lifecycle(db, zone):
    data = rows(
        db,
        """WITH firsts AS (SELECT o.flow,arg_min(o.direction,o.t) AS closer,arg_min(o.flags,o.t) AS close_flags,
            arg_min(o.frame,o.t) AS close_frame FROM sess_obs o JOIN sess_flows f USING(flow)
            WHERE (o.flags&5)>0 AND o.t=f.close_t GROUP BY o.flow),
        final_record AS (SELECT o.flow,max(o.length) AS final_len FROM sess_obs o JOIN firsts c USING(flow)
            JOIN sess_flows f USING(flow) WHERE o.direction=c.closer AND o.length BETWEEN 1 AND 100
            AND o.t BETWEEN f.close_t-1 AND f.close_t AND (c.close_flags&1)>0 GROUP BY o.flow),
        followed_rst AS (SELECT o.flow,count(*) AS rsts FROM sess_obs o JOIN firsts c USING(flow)
            JOIN sess_flows f USING(flow) WHERE o.direction=c.closer AND (o.flags&4)>0
            AND o.t>f.close_t AND o.t<=f.close_t+5 AND (c.close_flags&1)>0 GROUP BY o.flow),
        reconnect AS (SELECT f.flow,min(n.syn_t) AS next_syn,arg_min(n.flow,n.syn_t) AS next_flow
            FROM sess_flows f JOIN sess_flows n ON n.client_ip=f.client_ip AND n.server_ip=f.server_ip
            AND n.server_port=f.server_port AND n.flow<>f.flow AND n.syn_t>f.close_t
            AND n.syn_t<=f.close_t+? WHERE f.close_t IS NOT NULL GROUP BY f.flow)
        SELECT f.*,c.closer,c.close_flags,c.close_frame,coalesce(r.final_len,0) AS final_len,
            coalesce(fr.rsts,0) AS rsts_after_fin,n.next_syn,n.next_flow
        FROM sess_flows f LEFT JOIN firsts c USING(flow) LEFT JOIN final_record r USING(flow)
        LEFT JOIN followed_rst fr USING(flow) LEFT JOIN reconnect n USING(flow) ORDER BY f.first_t""",
        [RECONNECT_WINDOW_S],
    )
    out = []
    for c in data:
        flags = c["close_flags"]
        kind = (
            None if flags is None else "fin" if flags & 1 else "rst_abort" if flags & 16 else "rst_no_socket"
        )
        out.append(
            dict(
                flow=c["flow"],
                client=f"{c['client_ip']}:{c['client_port']}" if c["client_ip"] else None,
                server=f"{c['server_ip']}:{c['server_port']}" if c["server_ip"] else None,
                opened=c["syn_t"],
                first_seen=c["first_t"],
                last_seen=c["last_t"],
                bytes_client_to_server=c["c2s_bytes"],
                bytes_server_to_client=c["s2c_bytes"],
                closed=c["close_t"],
                closed_by=None if kind is None else ("client" if c["closer"] == "forward" else "server"),
                close_kind=kind,
                tls_close_like=bool(kind == "fin" and c["final_len"]),
                rst_after_close=c["rsts_after_fin"],
                reconnect_after_s=None if c["next_syn"] is None else c["next_syn"] - c["close_t"],
                reconnect_flow=c["next_flow"],
                close_frame=c["close_frame"],
                closed_label=None if c["close_t"] is None else _clock(c["close_t"], zone),
            )
        )
    return out


def reset_storms(db, point, zone):
    """Clusters of no-socket resets on several connections from the same side.

    A no-socket reset answers a segment the peer no longer knows (RFC 793): RST without ACK whose
    seq equals the ACK of the segment that triggered it, sent promptly after that segment. When the
    resetting side had already closed that connection with FIN, the reset is the expected answer to
    the other side's late close ("late_close"); otherwise the resetting side lost the connection
    state without telling the other side ("state_loss").
    """
    resets = rows(
        db,
        f"""SELECT r.frame,r.flow,r.direction,r.t,r.ttl,r.ipid,r.seq,
            (SELECT max(f.t) FROM sess_obs f WHERE f.flow=r.flow AND f.direction=r.direction
                AND (f.flags&1)>0 AND f.t<r.t) AS own_fin
        FROM sess_obs r WHERE (r.flags&4)>0 AND (r.flags&16)=0
        AND (SELECT arg_max(p.ack,p.t) FROM sess_obs p WHERE p.flow=r.flow AND p.direction<>r.direction
            AND p.t<r.t AND p.t>=r.t-{TRIGGER_WINDOW_S}) = r.seq
        ORDER BY r.direction,r.t""",
    )
    clusters, current = [], []
    for r in resets:
        if current and (
            r["direction"] != current[-1]["direction"] or r["t"] - current[-1]["t"] > STORM_GAP_S
        ):
            clusters.append(current)
            current = []
        current.append(r)
    if current:
        clusters.append(current)
    storms, findings = [], []
    for cluster in clusters:
        flows = sorted({r["flow"] for r in cluster})
        if len(flows) < 2:
            continue
        storm, finding = _storm(db, point, zone, cluster, flows)
        storms.append(storm)
        findings.append(finding)
    return storms, findings


def _storm(db, point, zone, cluster, flows):
    direction = cluster[0]["direction"]
    side = "server" if direction == "reverse" else "client"
    other_side = "client" if side == "server" else "server"
    other = "forward" if direction == "reverse" else "reverse"
    start, end = cluster[0]["t"], cluster[-1]["t"]
    details = rows(
        db,
        """SELECT f.flow,(SELECT max(o.t) FROM sess_obs o WHERE o.flow=f.flow AND o.direction=?
            AND (o.flags&4)=0 AND o.t<?) AS side_last,
        (SELECT arg_max(o.frame,o.t) FROM sess_obs o WHERE o.flow=f.flow AND o.direction=? AND o.t<?) AS trigger_frame,
        (SELECT arg_max(o.flags,o.t) FROM sess_obs o WHERE o.flow=f.flow AND o.direction=? AND o.t<?) AS trigger_flags,
        (SELECT mode(o.ttl) FROM sess_obs o WHERE o.flow=f.flow AND o.direction=? AND (o.flags&4)=0) AS normal_ttl
        FROM (SELECT unnest(?::VARCHAR[]) AS flow) f""",
        [direction, start, other, start, other, start, direction, flows],
    )
    closed_first = {r["flow"]: start - r["own_fin"] for r in cluster if r["own_fin"] is not None}
    late = len(closed_first) * 2 >= len(flows) + 1  # most connections were closed by the resetting side first
    silences = [start - d["side_last"] for d in details if d["side_last"] is not None]
    normal_ttls = sorted({d["normal_ttl"] for d in details if d["normal_ttl"] is not None})
    rst_ttls = sorted({r["ttl"] for r in cluster})
    frames = [r["frame"] for r in cluster] + [d["trigger_frame"] for d in details if d["trigger_frame"]]
    refs = evidence(db, "o.point=? AND o.frame IN (SELECT unnest(?::BIGINT[]))", [point, frames], 64)
    span = lambda v: f"{min(v):.1f}–{max(v):.1f} s" if v else "unknown"  # noqa: E731
    ttl_text = (
        f"same TTL as normal {side} packets"
        if rst_ttls == normal_ttls
        else f"RST TTL {rst_ttls} vs normal {side} TTL {normal_ttls}"
    )
    trigger_fin = sum(1 for d in details if d["trigger_flags"] is not None and d["trigger_flags"] & 1)
    if late:
        kind, severity = "late_close", "low"
        summary = (
            f"Late close of {len(flows)} connections at {_clock(start, zone)}: the {other_side} closed "
            f"connections that the {side} had already closed with FIN {span(list(closed_first.values()))} "
            f"earlier ({trigger_fin} of {len(flows)} triggers carry FIN); the {side} answered with RSTs. "
            f"These RSTs are the expected answer, not state loss; the {other_side} reacts late to {side} closes."
        )
    else:
        kind, severity = "state_loss", "high"
        summary = (
            f"Peer-side state loss for {len(flows)} connections at {_clock(start, zone)}: the {side} side "
            f"answered with no-socket RSTs (no ACK flag) after {span(silences)} of {side} silence and "
            f"without closing first; {ttl_text}. Typical causes: LB/firewall session flush or failover, "
            f"rerouting to another backend, or a {side} restart."
        )
    storm = dict(
        kind=kind,
        time=start,
        label=_clock(start, zone),
        side=side,
        connections=len(flows),
        flows=flows,
        silence_before_s=dict(min=min(silences), max=max(silences)) if silences else None,
        closed_by_resetting_side_before_s=(
            dict(min=min(closed_first.values()), max=max(closed_first.values())) if closed_first else None
        ),
        rst_ttl=rst_ttls,
        normal_ttl=normal_ttls,
        resets=len(cluster),
        rst_times=[r["t"] for r in cluster],
    )
    finding = _finding(
        "reset_storm" if kind == "state_loss" else "late_close_resets",
        severity,
        start,
        end,
        summary,
        {k: v for k, v in storm.items() if k not in ("flows", "rst_times")},
        refs,
        f"observed:{point}:{point}",
    )
    return storm, finding


def _buckets(db, flow, data_direction, lo, hi):
    ack_direction = "forward" if data_direction == "reverse" else "reverse"
    acks = rows(
        db,
        f"""WITH a AS (SELECT t,win,rtt,zero_window,
            (ack-lag(ack) OVER (ORDER BY t,frame)+4294967296)%4294967296 AS delta
            FROM sess_obs WHERE flow=? AND direction=? AND (flags&16)>0 AND (flags&4)=0)
        SELECT floor((t-?)/{RATE_BUCKET_S})::BIGINT AS bucket,
            sum(delta) FILTER(WHERE delta<1073741824) AS delivered,
            min(win) AS min_window,median(win) AS median_window,bool_or(zero_window) AS zero_window,
            quantile_cont(rtt,0.95) AS rtt_p95
        FROM a WHERE t>=? AND t<? GROUP BY bucket ORDER BY bucket""",
        [flow, ack_direction, lo, lo, hi],
    )
    retrans = dict(
        db.execute(
            f"""SELECT floor((t-?)/{RATE_BUCKET_S})::BIGINT,count(*) FILTER(WHERE retrans)
            FROM sess_obs WHERE flow=? AND direction=? AND length>0 AND t>=? AND t<? GROUP BY 1""",
            [lo, flow, data_direction, lo, hi],
        ).fetchall()
    )
    for b in acks:
        b["retrans"] = retrans.get(b["bucket"], 0)
    return acks


def _low_runs(buckets, baseline):
    runs, run = [], []
    for b in buckets:
        low = b["delivered"] <= RATE_DROP_RATIO * baseline
        if low and run and b["bucket"] == run[-1]["bucket"] + 1:
            run.append(b)
            continue
        if len(run) >= RATE_DROP_MIN_BUCKETS:
            runs.append(run)
        run = [b] if low else []
    if len(run) >= RATE_DROP_MIN_BUCKETS:
        runs.append(run)
    return runs


def rate_drops(db, point, zone):
    flows = rows(db, "SELECT * FROM sess_flows ORDER BY greatest(c2s_bytes,s2c_bytes) DESC")
    if not flows:
        return [], []
    largest = max(flows[0]["c2s_bytes"], flows[0]["s2c_bytes"])
    drops, findings = [], []
    for f in flows:
        volume = max(f["c2s_bytes"], f["s2c_bytes"])
        if not largest or volume < BULK_SHARE * largest:
            break
        data_direction = "reverse" if f["s2c_bytes"] >= f["c2s_bytes"] else "forward"
        lo = f["first_t"]
        hi = (f["close_t"] or f["last_t"]) - RATE_BUCKET_S  # the last partial bucket is not a rate
        buckets = [b for b in _buckets(db, f["flow"], data_direction, lo, hi) if b["delivered"] is not None]
        if len(buckets) < MIN_BASELINE_BUCKETS:
            continue
        baseline = median(b["delivered"] for b in buckets)
        if not baseline:
            continue
        windows = [b["median_window"] for b in buckets if b["median_window"] is not None]
        rtts = [b["rtt_p95"] for b in buckets if b["rtt_p95"] is not None]
        base = dict(
            delivered=baseline,
            window=median(windows) if windows else None,
            rtt=median(rtts) if rtts else None,
            retrans=median(b["retrans"] for b in buckets),
        )
        for run in _low_runs(buckets, baseline):
            item, finding = _classify_drop(db, point, f, data_direction, run, lo, base, zone)
            drops.append(item)
            if finding:
                findings.append(finding)
    return drops, findings


def _classify_drop(db, point, flow, data_direction, run, lo, base, zone):
    baseline, base_window, base_rtt, base_retrans = (
        base["delivered"],
        base["window"],
        base["rtt"],
        base["retrans"],
    )
    start = lo + run[0]["bucket"] * RATE_BUCKET_S
    end = lo + (run[-1]["bucket"] + 1) * RATE_BUCKET_S
    rate = median(b["delivered"] for b in run)
    losses = db.execute(
        """SELECT count(*) FROM events WHERE flow=? AND ts>=? AND ts<?
        AND kind IN ('impactful_loss','recovered_loss','unrecovered_loss','confirmed_device_drop')""",
        [flow["flow"], start, end],
    ).fetchone()[0]
    windows = [b["min_window"] for b in run if b["min_window"] is not None]
    window_limited = any(b["zero_window"] for b in run) or (
        base_window and windows and min(windows) < 0.5 * base_window
    )
    rtts = [b["rtt_p95"] for b in run if b["rtt_p95"] is not None]
    rtt_up = bool(base_rtt and rtts and median(rtts) > 1.5 * base_rtt + 0.001)
    retrans_up = sum(b["retrans"] for b in run) > (base_retrans + 1) * len(run) * 2
    cause = "receiver_window" if window_limited else "network" if losses or rtt_up or retrans_up else "sender"
    sender = "server" if data_direction == "reverse" else "client"
    item = dict(
        flow=flow["flow"],
        start=start,
        end=end,
        label=f"{_clock(start, zone)}–{_clock(end, zone)}",
        sender=sender,
        baseline_bytes_per_s=baseline / RATE_BUCKET_S,
        drop_bytes_per_s=rate / RATE_BUCKET_S,
        drop_percent=100 * (1 - rate / baseline),
        losses=losses,
        receiver_window_limited=bool(window_limited),
        rtt_increased=rtt_up,
        retrans_increased=retrans_up,
        cause=cause,
    )
    if cause == "network":
        return item, None
    refs = evidence(
        db,
        "o.point=? AND o.flow=? AND o.corrected>=? AND o.corrected<? AND (o.flags&16)>0",
        [point, flow["flow"], start, end],
        8,
    )
    if cause == "receiver_window":
        summary = (
            f"Receiver-limited slowdown on {flow['server_ip']}:{flow['server_port']} ⇄ {flow['client_ip']}:"
            f"{flow['client_port']} from {item['label']}: delivered rate −{item['drop_percent']:.0f}% while the "
            "receiver's advertised window shrank (receiver/application slow, not the network)."
        )
        return item, _finding(
            "receiver_rate_drop", "low", start, end, summary, item, refs, f"observed:{point}:{point}"
        )
    summary = (
        f"The {sender} reduced its sending rate on {flow['server_ip']}:{flow['server_port']} ⇄ "
        f"{flow['client_ip']}:{flow['client_port']} from {item['label']}: delivered "
        f"{item['baseline_bytes_per_s'] / 1e3:.0f} → {item['drop_bytes_per_s'] / 1e3:.0f} kB/s "
        f"(−{item['drop_percent']:.0f}%, from ACK progression) with no loss, no RTT increase and no "
        "receiver-window limit (network and receiver not limiting)."
    )
    return item, _finding(
        "sender_rate_drop", "low", start, end, summary, item, refs, f"observed:{point}:{point}"
    )


def stream_reconnects(connections, point, db, zone):
    if not connections:
        return []
    largest = max(max(c["bytes_client_to_server"], c["bytes_server_to_client"]) for c in connections)
    findings = []
    for c in connections:
        volume = max(c["bytes_client_to_server"], c["bytes_server_to_client"])
        if volume < BULK_SHARE * largest or c["closed"] is None or c["reconnect_after_s"] is None:
            continue
        how = (
            "TLS-close-like final record + FIN"
            if c["tls_close_like"]
            else "FIN"
            if c["close_kind"] == "fin"
            else "RST"
        )
        summary = (
            f"The {c['closed_by']} closed the {'main' if volume == largest else 'bulk'} stream {c['server']} ⇄ "
            f"{c['client']} at {c['closed_label']} ({how}) and the client reconnected after "
            f"{c['reconnect_after_s']:.1f} s."
        )
        refs = evidence(db, "o.point=? AND o.frame=?", [point, c["close_frame"]], 4)
        findings.append(
            _finding(
                "stream_reconnect",
                "low",
                c["closed"],
                c["closed"] + c["reconnect_after_s"],
                summary,
                {
                    k: c[k]
                    for k in (
                        "closed_by",
                        "close_kind",
                        "tls_close_like",
                        "reconnect_after_s",
                        "server",
                        "client",
                        "closed_label",
                    )
                },
                refs,
                f"observed:{point}:{point}",
            )
        )
    return findings


def fold_storm_resets(findings, storms, tolerance_s=0.01):
    """Unattributed reset-origin findings for RSTs that a storm already explains move under the storm."""
    times = sorted(t for s in storms for t in s.get("rst_times", []))
    if not times:
        return findings
    kept, folded = [], 0
    for f in findings:
        start = (f.get("time_range") or [None])[0]
        explained = start is not None and any(abs(start - t) <= tolerance_s for t in times)
        if f["type"] == "reset_origin" and f["confidence"] == "unknown" and explained:
            folded += 1
            continue
        kept.append(f)
    for f in kept:
        if f["type"] in ("reset_storm", "late_close_resets"):
            f["metrics"]["unattributed_reset_origin_folded"] = folded
    return kept


def session_report(db, topology):
    point = topology.forward[0] if topology.forward else None
    if point is None:
        return dict(status="unknown", reason="No capture point"), []
    zone = topology.report_timezone
    _prepare(db, point)
    connections = connection_lifecycle(db, zone)
    storms, storm_findings = reset_storms(db, point, zone)
    drops, drop_findings = rate_drops(db, point, zone)
    reconnect_findings = stream_reconnects(connections, point, db, zone)
    closed = [c for c in connections if c["closed_by"]]
    report = dict(
        observation_point=point,
        note=NOTE,
        connections=connections[:500],
        connection_count=len(connections),
        closed_by=dict(
            client=sum(c["closed_by"] == "client" for c in closed),
            server=sum(c["closed_by"] == "server" for c in closed),
        ),
        close_kinds={
            k: sum(c["close_kind"] == k for c in closed) for k in ("fin", "rst_abort", "rst_no_socket")
        },
        storms=storms,
        rate_drops=drops,
    )
    findings = storm_findings + reconnect_findings + drop_findings
    report["summary"] = session_summary(storms, reconnect_findings, drops)
    return report, findings


def session_summary(storms, reconnect_findings, drops):
    parts = []
    loss = [s for s in storms if s["kind"] == "state_loss"]
    late = [s for s in storms if s["kind"] == "late_close"]
    if loss:
        times = ", ".join(f"{s['label'][:8]} ({s['connections']})" for s in loss)
        parts.append(f"{loss[0]['side']}-side state loss (no-socket RST storms) at {times}")
    for f in reconnect_findings:
        m = f["metrics"]
        parts.append(
            f"{m['closed_by']} closed a bulk stream at {m['closed_label'][:8]} and the client reconnected after "
            f"{m['reconnect_after_s']:.1f} s"
        )
    for d in drops:
        if d["cause"] == "sender":
            parts.append(f"{d['sender']} reduced its sending rate {d['label']} (−{d['drop_percent']:.0f}%)")
    if late:
        other = "client" if late[0]["side"] == "server" else "server"
        times = ", ".join(f"{s['label'][:8]} ({s['connections']})" for s in late)
        parts.append(f"{other} closed {late[0]['side']}-closed connections late at {times} (expected RSTs)")
    return "; ".join(parts)
