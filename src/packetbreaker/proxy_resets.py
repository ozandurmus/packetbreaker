"""Reset causality on independently classified proxy TCP legs."""

import json
from .store import rows
from .proxy_analysis import boundaries, uncertainty
from .application_evidence import frame_refs, finding


def classify(output, triggers, uncertainty_s, covered, external_trigger=False, ambiguous=False):
    if uncertainty_s is None:
        return "unknown", "Clock uncertainty unavailable or opposite legs belong to unaligned clock domains"
    if not covered:
        return "unknown", "Capture window or leg quality insufficient to rule out an opposite-leg trigger"
    if external_trigger:
        return "unknown", "Reset trigger observed on other points but missing at proxy ingress"
    if ambiguous:
        return "unknown", "Multiple requests share this leg; reset association ambiguous"
    causal = [p for p in triggers if p["corrected"] <= output["corrected"] + uncertainty_s]
    if len(causal) > 1:
        return "unknown", "Multiple plausible opposite-leg reset triggers"
    if causal:
        return "propagated", None
    return "originated", None


def reset_checks(db, topology, segments, models, coverage):
    edges = boundaries(topology)
    if not edges:
        return [], dict(legs=[], leg_count=0, reset_notes=[])
    db.execute("CREATE OR REPLACE TEMP TABLE proxy_opaque_edges(a VARCHAR,b VARCHAR)")
    db.executemany("INSERT INTO proxy_opaque_edges VALUES (?,?)", [(a.id, b.id) for a, b in edges])
    requests = {r["id"]: r for r in rows(db, "SELECT * FROM proxy_requests")}
    pairs = [
        json.loads(p[0])
        for p in db.execute("SELECT metadata FROM proxy_pairs WHERE status='matched'").fetchall()
    ]
    resets = rows(db, "SELECT * FROM obs WHERE proto='TCP' AND (flags&4)=4 ORDER BY corrected LIMIT 501")
    cov = {c["point"]: c for c in coverage}
    findings = []
    notes = []
    window = topology.match_window_ms / 1000
    for a, b in boundaries(topology):
        u = uncertainty(models, a, b)
        segment = next(
            (
                s
                for s in segments
                if s["direction"] == "forward" and s["point_a"] == a.id and s["point_b"] == b.id
            ),
            None,
        )
        if not segment:
            continue
        for out in [r for r in resets if r["point"] in (a.id, b.id)]:
            possible = []
            for p in pairs:
                if p["device"] != a.device:
                    continue
                c, s = requests[p["client_id"]], requests[p["server_id"]]
                side = (
                    "client"
                    if out["point"] == a.id and out["flow"] == c["flow"] and out["canon"] != c["canon"]
                    else "server"
                    if out["point"] == b.id and out["flow"] == s["flow"] and out["canon"] == s["canon"]
                    else None
                )
                if (
                    side
                    and out["corrected"] is not None
                    and c["start"] is not None
                    and s["complete"] is not None
                    and max(c["complete"], s["complete"])
                    <= out["corrected"]
                    <= max(c["complete"], s["complete"]) + window
                ):
                    possible.append((c, s, side))
            if not possible:
                continue  # Incoming endpoint resets do not accuse the proxy.
            c, s, side = possible[0]
            opposite = s if side == "client" else c

            def incoming(p):
                return p["canon"] != s["canon"] if side == "client" else p["canon"] == c["canon"]

            candidates = [
                p
                for p in resets
                if p["flow"] == opposite["flow"]
                and incoming(p)
                and p["corrected"] is not None
                and out["corrected"] - window <= p["corrected"] <= out["corrected"] + (u or 0)
            ]
            triggers = [p for p in candidates if p["point"] == opposite["point"]]
            external = bool(candidates) and not triggers
            covered = all(
                cov.get(p)
                and cov[p]["start"] is not None
                and cov[p]["end"] is not None
                and cov[p]["start"] <= out["corrected"] - window
                and cov[p]["end"] >= out["corrected"] + (u or 0)
                for p in (a.id, b.id)
            )
            # A capture already flagged for missing observations cannot prove a negative trigger.
            degraded = db.execute(
                "SELECT count(*) FROM events e WHERE kind IN ('capture_miss','unknown') AND point_b IN (?,?) AND flow IN (?,?) AND ts BETWEEN ? AND ? AND NOT EXISTS(SELECT 1 FROM proxy_opaque_edges p WHERE (p.a=e.point_a AND p.b=e.point_b) OR (p.b=e.point_a AND p.a=e.point_b))",
                [a.id, b.id, c["flow"], s["flow"], out["corrected"] - window, out["corrected"] + window],
            ).fetchone()[0]
            status, reason = classify(
                out, triggers, u, covered and not degraded, external, len(possible) != 1
            )
            packets = [out, *triggers]
            if status == "unknown":
                notes.append(
                    dict(device=a.device, status=status, reason=reason, evidence=frame_refs(db, packets))
                )
                continue
            summary = f"Reset {status} by {a.device}"
            findings.append(
                finding(
                    db,
                    segment,
                    f"proxy_reset_{status}",
                    summary,
                    packets,
                    dict(
                        client_flow=c["flow"],
                        server_flow=s["flow"],
                        uncertainty_ms=u * 1000,
                        trigger_count=len(triggers),
                    ),
                    severity="quality" if status == "propagated" else "high",
                )
            )
    legs = (
        rows(
            db,
            """SELECT point,flow,count(*) AS packets,count(*) FILTER(WHERE retrans OR fast_retrans) AS retransmissions,
        count(*) FILTER(WHERE (flags&4)=4) AS resets FROM obs WHERE proto='TCP' GROUP BY point,flow ORDER BY point,flow""",
        )
        if boundaries(topology)
        else []
    )
    loss_by_leg = {}
    for flow, point, kind, count in db.execute(
        "SELECT flow,point_a,kind,count(*) FROM events WHERE kind IN ('recovered_loss','impactful_loss','unrecovered_loss') GROUP BY flow,point_a,kind"
    ).fetchall():
        loss_by_leg.setdefault((flow, point), {})[kind] = count
    for leg in legs:
        leg["loss_by_class"] = loss_by_leg.get((leg["flow"], leg["point"]), {})
    return findings, dict(legs=legs[:200], leg_count=len(legs), reset_notes=notes)
