"""A sender's retransmission is a symptom; disappearance evidence locates loss."""

LOSS_KINDS = ("recovered_loss", "impactful_loss", "unrecovered_loss", "handshake_blocked")
SYMPTOM = "symptom observed here (sender retransmits)"


def label_retransmissions(db, segments, detections, topology):
    by_id = {s["id"]: s for s in segments}
    for segment in segments:
        segment["loss_suspect"] = any(segment["classes"].get(k, 0) > 0 for k in LOSS_KINDS)
    for item in detections:
        if item["metric"] != "retrans_percent":
            continue
        segment = by_id[item["segment"]]
        direction = item["direction"]
        path = (
            topology.forward
            if direction == "forward"
            else (topology.reverse or list(reversed(topology.forward)))
        )
        index = path.index(segment["point_a"])
        found = db.execute(
            """SELECT DISTINCT e.point_a,e.point_b FROM events e WHERE e.direction=?
            AND e.kind IN ('recovered_loss','impactful_loss','unrecovered_loss','handshake_blocked')
            AND e.ts<? AND e.ts+coalesce(greatest(e.recovery_ms,e.impact_ms)/1000,60)>=?
            AND e.flow IN (SELECT DISTINCT flow FROM obs WHERE point=? AND direction=? AND retrans
                AND corrected>=? AND corrected<?)""",
            [
                direction,
                item["window_end"],
                item["window_start"],
                segment["point_a"],
                direction,
                item["window_start"],
                item["window_end"],
            ],
        ).fetchall()
        downstream = [f"{direction}:{a}:{b}" for a, b in found if a in path and path.index(a) > index]
        item["display_label"] = SYMPTOM
        item["suspect"] = False
        item["related_loss_segments"] = sorted(downstream)
        item["explanation"] = SYMPTOM + ". " + item["explanation"]
        if downstream:
            item["explanation"] += (
                " Independently supported downstream loss for contributing flows: "
                + ", ".join(sorted(downstream))
                + "."
            )
            segment["symptom_note"] = SYMPTOM
            if not segment["loss_suspect"]:
                segment["headline"] = SYMPTOM + ". " + segment.get("headline", "")
