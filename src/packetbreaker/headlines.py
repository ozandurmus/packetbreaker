"""Explain measured findings without turning uncertainty into a numeric claim."""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

LOSS_TYPES = "('recovered_loss','impactful_loss','unrecovered_loss','confirmed_device_drop')"


def time_labels(ts, zone=None):
    utc = datetime.fromtimestamp(round(ts, 3), timezone.utc)
    local = utc.astimezone(ZoneInfo(zone)) if zone else utc.astimezone()
    return dict(
        local=local.isoformat(sep=" ", timespec="milliseconds") + " local",
        utc=utc.isoformat(sep=" ", timespec="milliseconds").replace("+00:00", " UTC"),
    )


def add_headlines(db, findings, segments, topology, end):
    lookup = {s["id"]: s for s in segments}
    seen = set()
    for segment in segments:
        segment["finding_ids"] = []
    for finding in findings:
        s = lookup[finding["hop"]]
        s["finding_ids"].append(finding["id"])
        n = finding["metrics"]["count"]
        short = f"{finding['type'].replace('_', ' ').capitalize()}: {n} {'event' if n == 1 else 'events'}"
        wait = finding["metrics"].get("max_recovery_ms")
        if wait is not None:
            short += f"; max recovery {wait:.2f} ms"
        finding["headline"] = short + "."
        finding["time_labels"] = time_labels(finding["time_range"][0], topology.report_timezone)
        if finding["hop"] in seen:
            continue
        seen.add(finding["hop"])
        s["severity"] = finding["severity"]
        a, b = s["point_a"], s["point_b"]
        direction = s["direction"]
        labels = time_labels(finding["time_range"][0], topology.report_timezone)
        clock = (
            f"Clock-corrected times are estimates; offset uncertainty ±{s['offset_uncertainty_ms']:.3f} ms."
            if s["offset_uncertainty_ms"] is not None
            else "Clock uncertainty is unverified; times depend on the supplied or unavailable clock correction."
        )
        prefix = f"{labels['local']} / {labels['utc']}"
        if finding["type"] == "confirmed_device_drop":
            finding["summary"] = (
                f"{n} confirmed device drop observations at {finding['device']}; evidence stage {finding['evidence_stage']}."
            )
            text = f"From {prefix}, {n} device drop {'observation is' if n == 1 else 'observations are'} confirmed at {finding['device']} by {finding['evidence_stage']} evidence. The specific rule or policy cause is not inferred."
        elif finding["type"] == "handshake_blocked":
            text = f"Handshake blocked between {s['label'].replace(' → ', ' and ')}, first observed at {prefix}; cause unknown."
        elif finding["type"] == "capture_miss":
            text = f"From {prefix} onward, {finding['metrics']['count']} capture misses were observed between {s['label'].replace(' → ', ' and ')}. These are capture-quality findings, not network loss."
        elif finding["type"] == "unknown":
            text = f"At {prefix}, missing appearances between {s['label'].replace(' → ', ' and ')} are inconclusive: {s['reason'] or 'insufficient remaining coverage'}."
        else:
            first = db.execute(
                f"""SELECT min(ts) FROM events WHERE point_a=? AND point_b=? AND direction=?
                AND is_data AND kind IN {LOSS_TYPES}""",
                [a, b, direction],
            ).fetchone()[0]
            if first is None:
                text = f"From {prefix} onward, {finding['metrics']['count']} control-segment disappearances were observed between {s['label'].replace(' → ', ' and ')}; cause unknown."
            else:
                labels = time_labels(first, topology.report_timezone)
                prefix = f"{labels['local']} / {labels['utc']}"
                lost, quick, stalls, max_stall = db.execute(
                    f"""SELECT count(*),count(*) FILTER(WHERE kind='recovered_loss'),
                    count(*) FILTER(WHERE greatest(impact_ms,recovery_ms)>=?),
                    max(greatest(impact_ms,recovery_ms)) FILTER(WHERE greatest(impact_ms,recovery_ms)>=?)
                    FROM events WHERE point_a=? AND point_b=? AND direction=? AND is_data AND kind IN {LOSS_TYPES}
                    AND ts>=? AND (? IS NULL OR ts<=?)""",
                    [topology.stall_ms, topology.stall_ms, a, b, direction, first, end, end],
                ).fetchone()
                denominator = db.execute(
                    """SELECT count(*) FROM obs WHERE point=? AND direction=? AND eligible
                    AND length>0 AND corrected>=? AND (? IS NULL OR corrected<=?)""",
                    [a, direction, first, end, end],
                ).fetchone()[0]
                rate = 100 * lost / denominator if denominator and s["loss_percent"] is not None else None
                path = (
                    topology.forward
                    if direction == "forward"
                    else (topology.reverse or list(reversed(topology.forward)))
                )
                index = path.index(a)
                prior = [lookup[f"{direction}:{x}:{y}"] for x, y in zip(path[:index], path[1 : index + 1])]
                upstream = "No earlier capture point is available."
                status = "unavailable"
                if prior:
                    upstream = "Upstream comparison is inconclusive."
                    status = "unknown"
                    if all(p["reason"] is None and p["eligible_ratio"] == 1 for p in prior):
                        previous = db.execute(
                            f"""SELECT count(*) FROM events WHERE direction=? AND point_a IN (SELECT unnest(?::VARCHAR[]))
                            AND is_data AND kind IN {LOSS_TYPES} AND ts>=? AND (? IS NULL OR ts<=?)""",
                            [direction, path[:index], first, end, end],
                        ).fetchone()[0]
                        upstream = (
                            f"No loss was observed before {next(p.label for p in topology.points if p.id == a)} in the monitored path."
                            if previous == 0
                            else f"{previous} loss events were also observed earlier in the monitored path."
                        )
                        status = "none_observed" if previous == 0 else "loss_observed"
                rate_text = (
                    f"{rate:.2f}%"
                    if rate is not None
                    else f"an unknown proportion ({s['reason'] or 'no eligible denominator'})"
                )
                text = f"From {prefix} onward, {rate_text} of {direction} observed data packets were classified as lost between {s['label'].replace(' → ', ' and ')}. {upstream} "
                text += f"{100 * quick / lost:.1f}% recovered quickly; {100 * stalls / lost:.1f}% had measured stalls"
                text += f" (max {max_stall / 1000:.3f} s)." if max_stall is not None else "."
                other = lost - quick - stalls
                if other > 0:
                    text += f" {100 * other / lost:.1f}% remained unrecovered or had other impact."
                s["headline_metrics"] = dict(
                    start=first,
                    end=end,
                    lost=lost,
                    eligible_data_packets=denominator,
                    loss_percent=rate,
                    quickly_recovered=quick,
                    measured_stalls=stalls,
                    max_stall_ms=max_stall,
                    other_impact=other,
                    upstream_status=status,
                )
        s["time_labels"] = labels
        s["clock_caveat"] = clock
        s["headline"] = text + " " + clock
