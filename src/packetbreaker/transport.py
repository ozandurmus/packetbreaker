"""Evidence-led TCP limitation profiles. Packet joins/aggregation run in DuckDB."""

from collections import defaultdict

from .evidence import evidence
from .store import rows
from .topology import Topology
from .waterfall import waterfall

MOD = 4294967296
TOOLTIP = (
    "Per-flow/direction hypothesis from negotiated receive window, demand/flight, ACK timing, "
    "matched path timing, classified loss and visible HTTP service time. Counters alone cannot prove a cause."
)


def classify(m):
    result = dict(
        classification="unknown",
        reason="No independently corroborated limitation in this window",
        tooltip=TOOLTIP,
    )
    for key, reason in [
        ("indexed", "Reattach to index transport analysis fields"),
        ("trusted", "TCP state was not decoded independently at this capture point"),
        ("handshake", "Handshake not captured completely; negotiated receive-window scale unknown"),
        ("sender_captured", "No declared sender-side capture for this TCP leg"),
    ]:
        if not m.get(key):
            return {**result, "reason": reason}
    if m.get("samples", 0) < 6:
        return {**result, "reason": "Too few data observations for a limitation profile"}
    stall = m["stall_ms"]
    receiver = (
        m["zero_windows"] >= 2
        and m["zero_span_ms"] >= stall
        and (m["blocked_samples"] >= 2 or m["probes"] >= 1)
        and (m["window_shrinks"] >= 1 or m["probes"] >= 1)
    ) or (m["window_full"] >= 3 and m["window_shrinks"] >= 2 and m["blocked_samples"] >= 3)
    open_window = m["open_samples"] >= 3 and not receiver
    prompt_ack = (
        m["ack_samples"] >= 3 and m["ack_delay_p95_ms"] is not None and m["ack_delay_p95_ms"] < stall / 4
    )
    network = (
        open_window
        and prompt_ack
        and (m["loss_count"] >= 3 and m["loss_stall_ms"] >= stall or m["rtt_degraded"] and m["path_degraded"])
    )
    healthy_path = (
        m["path_samples"] >= 3
        and m["path_p95_ms"] is not None
        and m["path_p95_ms"] < stall / 4
        and m["loss_count"] == 0
    )
    application = (
        open_window
        and prompt_ack
        and healthy_path
        and (
            m["service_samples"] >= 1
            and m["service_ms"] is not None
            and m["service_ms"] >= stall
            or m["idle_gaps"] >= 3
        )
    )
    if sum([receiver, network, application]) > 1 or receiver and m["loss_count"] >= 3:
        return {
            **result,
            "reason": "Competing receiver and path limitations; a single dominant cause is unknown",
        }
    if receiver:
        return {
            **result,
            "classification": "receiver-limited",
            "reason": "Sustained closed/shrinking advertised window with active demand (flight/probes or repeated window-full observations)",
        }
    if network:
        return {
            **result,
            "classification": "network-limited (loss/RTT)",
            "reason": "Receiver has window headroom and prompt local ACKs; repeated supported loss/stalls or corroborated RTT and matched-path delay increase",
            "hop": m.get("loss_hop"),
        }
    if application:
        return {
            **result,
            "classification": "sender/application-limited",
            "reason": "Repeated visible server service waits or sender-side idle gaps despite window headroom, prompt ACKs and a healthy monitored path; pacing/physical bandwidth cause is not measured",
        }
    return result


def prepare(db, project, topology, report):
    if project.get(db, "transport_generation") == report["generated_at"]:
        return
    db.execute("CREATE OR REPLACE TEMP TABLE transport_points(point VARCHAR,kind VARCHAR,label VARCHAR)")
    db.executemany(
        "INSERT INTO transport_points VALUES (?,?,?)", [(p.id, p.kind, p.label) for p in topology.points]
    )
    db.execute("""CREATE OR REPLACE TABLE transport_tcp AS
        SELECT o.*,p.kind,p.label,
        try_cast(json_extract_string(path_fields,'$.window_scale') AS INTEGER) AS shift,
        coalesce(try_cast(json_extract_string(path_fields,'$.transport_index') AS INTEGER)=1,false) AS indexed,
        coalesce(try_cast(json_extract_string(path_fields,'$.window_full') AS BOOLEAN),false) AS window_full,
        coalesce(try_cast(json_extract_string(path_fields,'$.duplicate_ack') AS BOOLEAN),false) AS duplicate_ack,
        coalesce(try_cast(json_extract_string(path_fields,'$.zero_probe') AS BOOLEAN),false) AS zero_probe,
        try_cast(json_extract_string(path_fields,'$.rto_seconds') AS DOUBLE) AS rto_seconds,
        try_cast(json_extract_string(path_fields,'$.sack_left') AS BIGINT) AS sack_left,
        try_cast(json_extract_string(path_fields,'$.sack_right') AS BIGINT) AS sack_right,
        (SELECT count(DISTINCT point) FROM obs x WHERE x.capture_id=o.capture_id)=1
            OR EXISTS(SELECT 1 FROM app_protocol_cache a WHERE a.point=o.point AND a.reason IS NULL) AS trusted
        FROM obs o JOIN transport_points p USING(point) WHERE proto='TCP' AND flow IS NOT NULL""")
    db.execute("""CREATE OR REPLACE TEMP TABLE transport_syn AS
        SELECT flow,point,direction,arg_min(seq,ts) AS isn,arg_min(shift,ts) AS shift,min(ts) AS ts
        FROM transport_tcp WHERE (flags&2)>0 AND eligible GROUP BY ALL""")
    db.execute("""CREATE OR REPLACE TABLE transport_handshake AS
        SELECT h.*,peer.isn AS peer_isn,
        peer.isn IS NOT NULL AND h.shift BETWEEN 0 AND 14 AND peer.shift BETWEEN 0 AND 14 AS scaled,
        peer.isn IS NOT NULL AND EXISTS(SELECT 1 FROM transport_tcp a
           WHERE a.flow=h.flow AND a.point=h.point AND (a.flags&18)=16
           AND a.ts>=greatest(h.ts,peer.ts) AND a.seq=(CASE WHEN a.direction=h.direction THEN h.isn ELSE peer.isn END+1)%4294967296
           AND a.ack=(CASE WHEN a.direction=h.direction THEN peer.isn ELSE h.isn END+1)%4294967296) AS handshake
        FROM transport_syn h LEFT JOIN transport_syn peer ON h.flow=peer.flow AND h.point=peer.point AND h.direction<>peer.direction""")
    db.execute("""CREATE OR REPLACE TABLE transport_acks AS
        SELECT o.flow,o.point,CASE WHEN o.direction='forward' THEN 'reverse' ELSE 'forward' END AS direction,
        o.frame,o.ts,o.corrected,(o.ack-h.isn+4294967296)%4294967296 AS ack_end,o.rtt,
        CASE WHEN h.handshake THEN o.window*CASE WHEN (o.flags&2)>0 OR NOT h.scaled THEN 1 ELSE pow(2,peer.shift) END END AS receive_window,
        o.zero_window,o.duplicate_ack,o.sack_left,o.sack_right
        FROM transport_tcp o JOIN transport_handshake h ON o.flow=h.flow AND o.point=h.point AND o.direction<>h.direction
        LEFT JOIN transport_handshake peer ON peer.flow=h.flow AND peer.point=h.point AND peer.direction<>h.direction
        WHERE (o.flags&16)>0""")
    db.execute("""CREATE OR REPLACE TEMP TABLE transport_ack_first AS
        SELECT flow,point,direction,ack_end,min(ts) AS ts,arg_min(frame,ts) AS frame
        FROM transport_acks GROUP BY ALL""")
    db.execute("""CREATE OR REPLACE TEMP TABLE transport_data AS
        WITH d AS(SELECT o.*,h.handshake,h.isn,(o.seq-h.isn+4294967296)%4294967296 AS relative_seq
            FROM transport_tcp o LEFT JOIN transport_handshake h USING(flow,point,direction)
            WHERE o.length>0 AND (o.flags&2)=0), s AS(
            SELECT *,relative_seq+length AS seq_end,
            max(relative_seq+length) OVER(PARTITION BY flow,point,direction ORDER BY ts,frame) AS sent_end,
            (ts-lag(ts) OVER(PARTITION BY flow,point,direction ORDER BY ts,frame))*1000 AS gap_ms FROM d)
        SELECT s.*,w.receive_window,w.ack_end,w.frame AS window_frame,
        greatest(0,s.sent_end-w.ack_end) AS bytes_in_flight,
        CASE WHEN NOT s.retrans AND NOT s.spurious AND a.ts>=s.ts AND a.ts<s.ts+60 THEN (a.ts-s.ts)*1000 END AS ack_delay_ms,
        a.frame AS ack_frame
        FROM s ASOF LEFT JOIN transport_acks w ON s.flow=w.flow AND s.point=w.point AND s.direction=w.direction AND s.ts>=w.ts
        ASOF LEFT JOIN transport_ack_first a ON s.flow=a.flow AND s.point=a.point AND s.direction=a.direction AND s.seq_end<=a.ack_end""")
    db.execute("""CREATE OR REPLACE TABLE transport_samples AS SELECT * FROM transport_data""")
    db.execute("""CREATE OR REPLACE TEMP TABLE transport_window_trace AS
        WITH w AS(SELECT *,lag(receive_window) OVER(PARTITION BY flow,point,direction ORDER BY ts,frame) AS prior_window FROM transport_acks)
        SELECT w.*,greatest(0,d.sent_end-w.ack_end) AS flight
        FROM w ASOF LEFT JOIN transport_data d ON w.flow=d.flow AND w.point=d.point AND w.direction=d.direction AND w.ts>=d.ts""")
    db.execute(
        """CREATE OR REPLACE TABLE transport_point_facts AS
        WITH a AS(SELECT flow,point,direction,count(*) FILTER(WHERE receive_window=0) AS zero_windows,
            coalesce((max(ts) FILTER(WHERE receive_window=0)-min(ts) FILTER(WHERE receive_window=0))*1000,0) AS zero_span_ms,
            count(*) FILTER(WHERE receive_window<prior_window) AS window_shrinks,
            count(*) FILTER(WHERE receive_window=0 AND flight>0) AS blocked_windows FROM transport_window_trace GROUP BY ALL),
        d AS(SELECT flow,point,direction,min(kind) AS kind,min(label) AS label,bool_and(indexed) AS indexed,bool_and(trusted) AS trusted,
            bool_and(coalesce(handshake,false)) AND max(relative_seq)<2147483648 AS handshake,count(*) AS samples,
            count(*) FILTER(WHERE ack_delay_ms IS NOT NULL) AS ack_samples,quantile_cont(ack_delay_ms,.95) AS ack_delay_p95_ms,
            count(*) FILTER(WHERE window_full) AS window_full,count(*) FILTER(WHERE zero_probe) AS probes,
            count(*) FILTER(WHERE receive_window>greatest(length*2,bytes_in_flight*2) AND receive_window>0) AS open_samples,
            count(*) FILTER(WHERE receive_window>0 AND bytes_in_flight>=receive_window*.9) AS blocked_samples,
            count(*) FILTER(WHERE gap_ms>=?) AS idle_gaps,max(bytes_in_flight) AS max_bytes_in_flight,
            max(receive_window) AS max_receive_window FROM transport_samples GROUP BY ALL)
        SELECT d.*,coalesce(a.zero_windows,0) AS zero_windows,coalesce(a.zero_span_ms,0) AS zero_span_ms,
        coalesce(a.window_shrinks,0) AS window_shrinks,coalesce(a.blocked_windows,0) AS blocked_windows
        FROM d LEFT JOIN a USING(flow,point,direction)""",
        [topology.stall_ms],
    )
    db.execute(
        "CREATE OR REPLACE TEMP TABLE transport_edges(direction VARCHAR,a VARCHAR,b VARCHAR,hop VARCHAR)"
    )
    edges = []
    for direction, path in [
        ("forward", topology.forward),
        ("reverse", topology.reverse or list(reversed(topology.forward))),
    ]:
        for a, b in zip(path, path[1:]):
            if any(
                s["id"] == f"{direction}:{a}:{b}" and s.get("loss_percent") is not None
                for s in report["segments"]
            ):
                edges.append((direction, a, b, f"{direction}:{a}:{b}"))
    if edges:
        db.executemany("INSERT INTO transport_edges VALUES (?,?,?,?)", edges)
    db.execute("""CREATE OR REPLACE TABLE transport_transit AS
        SELECT a.flow,e.direction,e.hop,a.ts,a.corrected,(b.corrected-a.corrected)*1000 AS ms,a.frame,a.point,b.frame AS peer_frame,b.point AS peer_point,
        min(a.ts) OVER(PARTITION BY a.flow,e.hop) AS first_ts,max(a.ts) OVER(PARTITION BY a.flow,e.hop) AS last_ts
        FROM transport_edges e JOIN obs a ON a.point=e.a AND a.direction=e.direction AND a.eligible AND a.length>0 AND NOT a.retrans
        JOIN obs b ON b.point=e.b AND b.direction=e.direction AND b.flow=a.flow AND b.packet_key=a.packet_key AND b.eligible
        WHERE a.corrected IS NOT NULL AND b.corrected>=a.corrected""")
    db.execute("""CREATE OR REPLACE TABLE transport_path_facts AS WITH p AS(
        SELECT flow,direction,hop,count(*) AS samples,quantile_cont(ms,.95) AS p95_ms,
        median(ms) FILTER(WHERE ts<=first_ts+(last_ts-first_ts)*.25) AS baseline,
        median(ms) FILTER(WHERE ts>first_ts+(last_ts-first_ts)*.25) AS later,
        count(*) FILTER(WHERE ts<=first_ts+(last_ts-first_ts)*.25) AS early_samples FROM transport_transit GROUP BY ALL)
        SELECT flow,direction,sum(samples) AS path_samples,max(p95_ms) AS path_p95_ms,
        bool_or(early_samples>=3 AND later>greatest(baseline*2,baseline+20)) AS path_degraded FROM p GROUP BY ALL""")
    db.execute("""CREATE OR REPLACE TABLE transport_rtt_facts AS WITH r AS(
        SELECT *,min(ts) OVER(PARTITION BY flow,point,direction) AS lo,max(ts) OVER(PARTITION BY flow,point,direction) AS hi
        FROM transport_acks WHERE rtt IS NOT NULL)
        SELECT flow,point,direction,count(*) AS rtt_samples,median(rtt)*1000 AS rtt_ms,
        count(*) FILTER(WHERE ts<=lo+(hi-lo)*.25)>=3 AND count(*) FILTER(WHERE ts>lo+(hi-lo)*.25)>=3
        AND median(rtt) FILTER(WHERE ts>lo+(hi-lo)*.25)>greatest(.1,2*median(rtt) FILTER(WHERE ts<=lo+(hi-lo)*.25)) AS rtt_degraded
        FROM r GROUP BY ALL""")
    project.set(db, "transport_generation", report["generated_at"])


def profiles(project, flow=None, include_service=True):
    with project.connect() as db:
        report = project.get(db, "report")
        raw_topology = project.get(db, "topology")
        if not report or not raw_topology:
            return {"items": [], "reason": "Run analysis first", "tooltip": TOOLTIP}
        topology = Topology.model_validate(raw_topology)
        prepare(db, project, topology, report)
        data = rows(
            db,
            """SELECT f.*,p.path_samples,p.path_p95_ms,p.path_degraded,r.rtt_ms,r.rtt_degraded
            FROM transport_point_facts f LEFT JOIN transport_path_facts p USING(flow,direction)
            LEFT JOIN transport_rtt_facts r USING(flow,point,direction) WHERE (? IS NULL OR f.flow=?) ORDER BY f.flow,f.point,f.direction""",
            [flow, flow],
        )
        groups = defaultdict(list)
        for item in data:
            groups[(item["flow"], item["direction"])].append(item)
        pointmap = {p.id: p for p in topology.points}
        losses = rows(
            db,
            """SELECT flow,direction,count(*) AS loss_count,max(coalesce(recovery_ms,impact_ms)) AS loss_stall_ms,
            arg_max(direction||':'||point_a||':'||point_b,coalesce(recovery_ms,impact_ms)) AS loss_hop
            FROM events WHERE kind IN('recovered_loss','impactful_loss','unrecovered_loss','handshake_blocked','confirmed_device_drop') GROUP BY ALL""",
        )
        lossmap = {(r["flow"], r["direction"]): r for r in losses}
        items = []
        for (fid, direction), points in groups.items():
            sender_kind = "Client" if direction == "forward" else "Server"
            receiver_kind = "Server" if direction == "forward" else "Client"
            sender = next((r for r in points if r["kind"] == sender_kind), None)
            receiver = next((r for r in points if r["kind"] == receiver_kind), None)
            if sender is None:
                sender = next(
                    (
                        r
                        for r in points
                        if pointmap[r["point"]].translation == "full_proxy"
                        and pointmap[r["point"]].side == ("egress" if direction == "forward" else "ingress")
                    ),
                    None,
                )
            if receiver is None:
                receiver = next(
                    (
                        r
                        for r in points
                        if pointmap[r["point"]].translation == "full_proxy"
                        and pointmap[r["point"]].side == ("ingress" if direction == "forward" else "egress")
                    ),
                    None,
                )
            metrics = dict(sender or points[0])
            metrics["sender_captured"] = sender is not None
            metrics["blocked_samples"] += metrics.pop("blocked_windows", 0)
            metrics["ack_samples"] = receiver["ack_samples"] if receiver else 0
            metrics["ack_delay_p95_ms"] = receiver["ack_delay_p95_ms"] if receiver else None
            metrics.update(
                loss_count=0,
                loss_stall_ms=0,
                loss_hop=None,
                service_ms=None,
                service_samples=0,
                stall_ms=topology.stall_ms,
            )
            metrics.update(lossmap.get((fid, direction), {}))
            metrics["loss_stall_ms"] = metrics["loss_stall_ms"] or 0
            metrics["path_samples"] = metrics["path_samples"] or 0
            metrics["path_degraded"] = bool(metrics["path_degraded"])
            metrics["rtt_degraded"] = bool(metrics["rtt_degraded"])
            service_refs = []
            if include_service and direction == "reverse" and flow is not None:
                # Reuse validated byte-completion/clock-aware HTTP waterfall boundaries.
                timeline = waterfall(project, fid)
                for request in timeline.get("requests", [])[:10]:
                    for item in waterfall(project, fid, request_index=request["index"]).get("items", []):
                        for bar in item["bars"]:
                            if bar["kind"] == "server_processing" and bar["duration_ms"] is not None:
                                metrics["service_ms"] = max(metrics["service_ms"] or 0, bar["duration_ms"])
                                metrics["service_samples"] += 1
                                service_refs.extend(bar["evidence"])
            decision = classify(metrics)
            refs = evidence(
                db,
                "o.flow=? AND o.proto='TCP' AND (o.point=? OR o.point=?)",
                [fid, metrics["point"], receiver["point"] if receiver else None],
                16,
            )
            # Add pressure/timing extremes, not only the first packets of the handshake.
            signal = rows(
                db,
                """SELECT point,frame,ack_frame,window_frame FROM transport_samples WHERE flow=? AND direction=?
                ORDER BY zero_probe DESC,window_full DESC,gap_ms DESC NULLS LAST,ack_delay_ms DESC NULLS LAST LIMIT 6""",
                [fid, direction],
            )
            for p in {s["point"] for s in signal}:
                frames = list(
                    {
                        int(v)
                        for s in signal
                        if s["point"] == p
                        for k in ("frame", "ack_frame", "window_frame")
                        if (v := s.get(k)) is not None
                    }
                )
                refs += evidence(
                    db,
                    "o.flow=? AND o.point=? AND o.frame IN(SELECT unnest(?::BIGINT[]))",
                    [fid, p, frames],
                    24,
                )
            items.append(
                dict(
                    flow=fid,
                    direction=direction,
                    point=metrics["point"],
                    **decision,
                    metrics=metrics,
                    evidence=refs + service_refs,
                )
            )
        return dict(
            items=items,
            point_metrics=data,
            reason=None,
            tooltip=TOOLTIP,
            note="Same-capture ACK/service timing; hop timing retains clock uncertainty. Sender pacing does not measure physical capacity. Missing/ambiguous evidence is unknown.",
        )


def export_profiles(project, limit=200):
    """Export bounded profiles; enrich visible HTTP flows with existing waterfall evidence."""
    result = profiles(project, include_service=False)
    with project.connect() as db:
        http_flows = [
            r[0]
            for r in db.execute(
                """SELECT DISTINCT flow FROM obs WHERE proto='TCP' AND
            json_extract_string(path_fields,'$.http_method') IS NOT NULL ORDER BY flow LIMIT ?""",
                [limit],
            ).fetchall()
        ]
    for fid in http_flows:
        enriched = profiles(project, fid)
        index = {(r["flow"], r["direction"]): r for r in enriched["items"]}
        result["items"] = [index.get((r["flow"], r["direction"]), r) for r in result["items"]]
    result["total"] = len(result["items"])
    result["items"] = result["items"][:limit]
    result["point_metrics"] = result.get("point_metrics", [])[: limit * 4]
    result["note"] += (
        " Export shows at most 200 directional profiles; inspect another flow locally for its full evidence."
    )
    return result
