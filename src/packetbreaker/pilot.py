"""Window-scoped topology measurements and conservative flow inventory columns."""

from .store import rows
from .analysis import findings_page, flow_page

LOSS_CLASSES = (
    "impactful_loss",
    "recovered_loss",
    "unrecovered_loss",
    "handshake_blocked",
    "confirmed_device_drop",
)


def flow_columns(db, findings, topology):
    # Measure at the client-most configured point, in its own clock domain. No cross-clock subtraction.
    if topology.forward:
        db.execute(
            """UPDATE flow_summary SET handshake_rtt_ms=h.ms FROM (
            SELECT s.flow,arg_min((sa.ts-s.ts)*1000,s.ts) AS ms FROM obs s JOIN obs sa
            ON sa.point=s.point AND sa.stream=s.stream AND sa.ack=(s.seq+1)%4294967296
            AND (sa.flags&18)=18 AND sa.ts>s.ts AND sa.ts<s.ts+60
            WHERE s.point=? AND s.proto='TCP' AND (s.flags&18)=2 GROUP BY s.flow) h
            WHERE flow_summary.flow=h.flow""",
            [topology.forward[0]],
        )
    origins = {}
    for finding in findings:
        if (
            finding["type"] not in ("reset_origin", "proxy_reset_originated", "proxy_reset_propagated")
            or finding["confidence"] != "supported"
        ):
            continue
        refs = finding.get("evidence", [])
        if not refs:
            continue
        values = [(r["capture_id"], r["frame"]) for r in refs if "capture_id" in r and "frame" in r]
        if not values:
            continue
        placeholders = ",".join("(?,?)" for _ in values)
        for (flow,) in db.execute(
            f"""SELECT DISTINCT o.flow FROM obs o JOIN
            (VALUES {placeholders}) r(capture_id,frame) USING(capture_id,frame)
            WHERE (o.flags&4)>0""",
            [v for pair in values for v in pair],
        ).fetchall():
            origins.setdefault(flow, set()).add(finding["summary"])
    if origins:
        db.executemany(
            "UPDATE flow_summary SET reset_origin=? WHERE flow=?",
            [("; ".join(sorted(labels)), flow) for flow, labels in origins.items()],
        )


def topology_overlay(project, start=None, end=None):
    with project.connect() as db:
        report = project.get(db, "report")
        topology = project.get(db, "topology", {})
        if not report:
            return dict(segments=[], nodes=[], scope=dict(start=start, end=end))
        window = report.get("window", {})
        start = window.get("start") if start is None else start
        end = window.get("end") if end is None else end
        analyzed = (window.get("start") is None or (start is not None and start >= window["start"])) and (
            window.get("end") is None or (end is not None and end <= window["end"])
        )
        observations = rows(
            db,
            """SELECT point,direction,count(*) AS packets,
            count(*) FILTER(WHERE eligible) AS eligible_packets,
            count(*) FILTER(WHERE retrans) AS retrans_observations FROM obs
            WHERE (? IS NULL OR corrected>=?) AND (? IS NULL OR corrected<?) GROUP BY point,direction""",
            [start, start, end, end],
        )
        counts = {(r["point"], r["direction"]): r for r in observations}
        losses = rows(
            db,
            """SELECT point_a,point_b,direction,kind,count(*) AS n FROM events
            WHERE (? IS NULL OR ts>=?) AND (? IS NULL OR ts<?) GROUP BY ALL""",
            [start, start, end, end],
        )
        latencies = rows(
            db,
            """SELECT point_a,point_b,direction,quantile_cont((time_b-time_a)*1000,.95) AS p95_ms
            FROM observation_matches WHERE (? IS NULL OR time_a>=?) AND (? IS NULL OR time_a<?)
            GROUP BY ALL""",
            [start, start, end, end],
        )
        latency = {(r["point_a"], r["point_b"], r["direction"]): r["p95_ms"] for r in latencies}
        selected = findings_page(project, start, end)["items"]
        device_drops = dict(
            db.execute(
                "SELECT device,count(*) FROM device_proofs WHERE status='confirmed_device_drop' AND (? IS NULL OR time>=?) AND (? IS NULL OR time<?) GROUP BY device",
                [start, start, end, end],
            ).fetchall()
        )
        coverage = {c["point"]: c for c in report.get("coverage", [])}
        segments = []
        for base in report["segments"]:
            a, b, d = base["point_a"], base["point_b"], base["direction"]
            c = counts.get((a, d), {})
            eligible = c.get("eligible_packets", 0)
            classes = {
                r["kind"]: r["n"] for r in losses if (r["point_a"], r["point_b"], r["direction"]) == (a, b, d)
            }
            ratio = eligible / c["packets"] if c.get("packets") else None
            covered = all(
                coverage.get(p, {}).get("start") is not None
                and (start is None or start >= coverage[p]["start"])
                and (end is None or end <= coverage[p]["end"])
                for p in (a, b)
            )
            valid = (
                covered
                and analyzed
                and base.get("reason") is None
                and ratio is not None
                and ratio >= topology.get("min_eligible_ratio", 0.9)
            )
            segments.append(
                dict(
                    id=base["id"],
                    point_a=a,
                    point_b=b,
                    direction=d,
                    loss_percent=100 * sum(classes.get(k, 0) for k in LOSS_CLASSES) / eligible
                    if valid and eligible
                    else None,
                    p95_ms=latency.get((a, b, d)) if valid else None,
                    classes=classes,
                    retrans_observations=c.get("retrans_observations", 0),
                    eligible_packets=eligible,
                    reason=base.get("reason")
                    or (None if valid else "No sufficient matchable observations in selected range"),
                    finding_ids=[f["id"] for f in selected if f["hop"] == base["id"]],
                )
            )
        nodes = []
        for device in dict.fromkeys(p["device"] for p in topology.get("points", [])):
            points = [p["id"] for p in topology["points"] if p["device"] == device]
            owned = [s for s in segments if s["point_a"] in points or s["point_b"] in points]
            notes = [r for r in observations if r["point"] in points]
            nodes.append(
                dict(
                    device=device,
                    confirmed_device_drops=device_drops.get(device, 0),
                    points=points,
                    observations=sum(r["packets"] for r in notes),
                    retrans_observations=sum(r["retrans_observations"] for r in notes),
                    supported_loss_events=sum(
                        sum(s["classes"].get(k, 0) for k in LOSS_CLASSES)
                        for s in owned
                        if s["loss_percent"] is not None
                    ),
                    findings=len({i for s in owned for i in s["finding_ids"]}),
                )
            )
        return dict(
            segments=segments,
            nodes=nodes,
            scope=dict(start=start, end=end),
            note="Retransmissions and node totals are capture observations, potentially counted at multiple points; they do not assign fault. Latency carries segment clock uncertainty.",
        )


def topology_inspect(project, point=None, segment=None, start=None, end=None):
    overlay = topology_overlay(project, start, end)
    start, end = overlay["scope"]["start"], overlay["scope"]["end"]
    with project.connect() as db:
        topology = project.get(db, "topology", {})
        if point:
            chosen = next((p for p in topology.get("points", []) if p["id"] == point), None)
            if chosen is None:
                raise ValueError("Unknown capture point")
            points = [p["id"] for p in topology["points"] if p["device"] == chosen["device"]]
            hops = [s["id"] for s in overlay["segments"] if s["point_a"] in points or s["point_b"] in points]
        else:
            chosen = next((s for s in overlay["segments"] if s["id"] == segment), None)
            if chosen is None:
                raise ValueError("Unknown segment")
            points, hops = [chosen["point_a"], chosen["point_b"]], [segment]
    flows = flow_page(project, start=start, end=end, points=points)
    return dict(
        findings=[f for f in findings_page(project, start, end)["items"] if f["hop"] in hops],
        flows=flows,
        points=points,
        hops=hops,
        scope=overlay["scope"],
    )
