"""Explainable, sustained departures from early loss-free observation buckets."""

from statistics import median
from collections import Counter

from .evidence import evidence
from .headlines import time_labels
from .store import rows

WINDOW_SECONDS = 15
MIN_EVENTS = 3
MIN_EVENT_BUCKETS = 2


def detect_series(values, metric, floor, baseline_count=5, multiplier=6):
    """Only an early consecutive healthy prefix may seed the rolling baseline."""
    values = [
        dict(
            v,
            loss_percent=100 * v["loss_count"] / v["eligible_packets"]
            if v.get("loss_count") is not None and v["eligible_packets"]
            else v.get("loss_percent"),
        )
        for v in values
    ]
    complete = [
        v
        for v in values
        if v["coverage"] == "capturing"
        and v["reason"] != "Outside classified common window; loss rates unknown"
    ]

    def usable(x):
        return x[metric] is not None and x.get("matchable_packets", x["eligible_packets"]) > 0

    def healthy(x):
        return usable(x) and (metric != "loss_percent" or x[metric] == 0)

    prefix = []
    after_prefix = len(complete)
    for i, row in enumerate(complete):
        if usable(row):
            prefix.append(row)
            if len(prefix) == baseline_count:
                after_prefix = i + 1
                break
    if len(prefix) < baseline_count or sum(usable(x) for x in complete[after_prefix:]) < 2:
        return None, "unknown: insufficient covered, matchable samples for baseline and confirmation"
    if not all(healthy(x) for x in prefix):
        return None, "unknown: the early measured baseline already contains network loss"
    initial = [v[metric] for v in prefix]
    center = median(initial)
    mad = median(abs(v - center) for v in initial)
    if max(initial) - min(initial) > max(floor, multiplier * 1.4826 * mad) or (
        metric == "latency_p95_ms" and mad > max(floor, abs(center) * 0.25)
    ):
        return None, "unknown: early baseline is not stable enough"
    history = prefix[:]
    candidate = None
    recent = prefix[:]
    previous = prefix[-1]["bucket"]
    gap = False
    for x in complete[after_prefix:]:
        if not usable(x) or x["bucket"] != previous + 1:
            candidate = None
            # Do not bridge a coverage/quality gap with a stale baseline.
            history = []
            recent = []
            gap = True
        previous = x["bucket"]
        if not usable(x):
            continue
        if len(history) < baseline_count:
            if healthy(x):
                history.append(x)
            else:
                history = []
            continue
        recent.append(x)
        recent = [v for v in recent if v["end"] > x["end"] - WINDOW_SECONDS]
        samples = [v[metric] for v in history[-baseline_count:]]
        baseline = median(samples)
        spread = median(abs(v - baseline) for v in samples)
        threshold = baseline + max(floor, multiplier * 1.4826 * spread)
        if metric == "loss_percent":
            count = sum(v["loss_count"] for v in recent)
            denominator = sum(v["eligible_packets"] for v in recent)
            value = 100 * count / denominator if denominator else 0
            changed = [v for v in recent if v["loss_count"] > baseline * v["eligible_packets"] / 100]
            if value > threshold and count >= MIN_EVENTS and len(changed) >= MIN_EVENT_BUCKETS:
                first = changed[0]
                return dict(
                    metric=metric,
                    baseline_value=baseline,
                    mad=spread,
                    threshold=threshold,
                    multiplier=multiplier,
                    minimum_delta=floor,
                    baseline_buckets=[v["bucket"] for v in history[-baseline_count:]],
                    bucket=first["bucket"],
                    first_event_bucket=first["bucket"],
                    first_crossing_bucket=x["bucket"],
                    confirmed_bucket=x["bucket"],
                    time=first["start"],
                    end=first["end"],
                    value=value,
                    first_bucket_value=first[metric],
                    window_start=recent[0]["start"],
                    window_end=x["end"],
                    window_seconds=WINDOW_SECONDS,
                    window_events=count,
                    window_denominator=denominator,
                    event_buckets=len(changed),
                    min_events=MIN_EVENTS,
                ), None
            if healthy(x):
                history = (history + [x])[-baseline_count:]
            continue
        if x[metric] > threshold:
            if candidate and x["bucket"] == candidate["bucket"] + 1 and x[metric] > candidate["threshold"]:
                candidate["confirmed_bucket"] = x["bucket"]
                return candidate, None
            candidate = dict(
                metric=metric,
                baseline_value=baseline,
                mad=spread,
                threshold=threshold,
                multiplier=multiplier,
                minimum_delta=floor,
                baseline_buckets=[v["bucket"] for v in history[-baseline_count:]],
                bucket=x["bucket"],
                first_crossing_bucket=x["bucket"],
                time=x["start"],
                end=x["end"],
                value=x[metric],
            )
        else:
            candidate = None
            if healthy(x):
                history.append(x)
                history = history[-baseline_count:]
    return (
        None,
        "unknown: coverage or unavailable metric samples limit onset chronology"
        if gap
        else "No sustained departure from the early healthy baseline",
    )


def status_summary(segments):
    counts = dict(Counter(s["onset_status"] for s in segments))
    valid = sum(n for status, n in counts.items() if status != "unknown")
    missing = counts.get("unknown", 0)
    if counts.get("detected"):
        return "detected", counts, ""
    if valid:
        return (
            ("partial" if missing or counts.get("partial") else "none"),
            counts,
            (
                f"No sustained onset in {valid} segment(s) with measured baselines; "
                f"{missing} segment(s) have unknown onset status. See per-segment results and quality notes."
            ),
        )
    return "unknown", counts, "Onset unknown: no segment has sufficient covered, matchable baseline samples."


def add_onsets(db, topology, segments):
    detections = []
    for s in segments:
        values = rows(db, "SELECT * FROM segment_buckets WHERE segment=? ORDER BY bucket", [s["id"]])
        quality_notes = dict(
            capture_misses=sum(v["capture_misses"] for v in values),
            unknown_events=sum(v["unknown_events"] for v in values),
            reasons=sorted({v["reason"] for v in values if v["reason"] and v["coverage"] == "capturing"}),
        )
        s["onset_quality_notes"] = quality_notes
        unknown = []
        found = []
        for metric, floor in (
            ("loss_percent", 0.0),
            ("latency_p95_ms", max(1.0, 2 * (s["offset_uncertainty_ms"] or 0))),
        ):
            item, reason = detect_series(values, metric, floor)
            if not item:
                unknown.append(
                    dict(
                        metric=metric,
                        reason=reason,
                        status="unknown" if reason.startswith("unknown:") else "none",
                    )
                )
                continue
            item.update(
                segment=s["id"],
                label=s["label"],
                direction=s["direction"],
                point_a=s["point_a"],
                point_b=s["point_b"],
                time_labels=time_labels(item["time"], topology.report_timezone),
                clock_uncertainty_ms=s["offset_uncertainty_ms"],
                quality_notes=quality_notes,
            )
            if metric == "loss_percent":
                event = db.execute(
                    """SELECT packet_key,recovery_key,support_key FROM events WHERE point_a=? AND point_b=? AND direction=?
                    AND ts>=? AND ts<? AND kind IN ('recovered_loss','impactful_loss','unrecovered_loss','handshake_blocked') ORDER BY ts LIMIT 1""",
                    [s["point_a"], s["point_b"], s["direction"], item["time"], item["end"]],
                ).fetchone()
                refs = evidence(db, "o.packet_key IN (?,?,?)", list(event)) if event else []
            else:
                pair = db.execute(
                    """SELECT a.packet_key FROM obs a JOIN obs b USING(packet_key)
                    WHERE a.point=? AND b.point=? AND a.direction=? AND a.eligible AND b.eligible
                    AND a.corrected>=? AND a.corrected<? ORDER BY b.corrected-a.corrected DESC LIMIT 1""",
                    [s["point_a"], s["point_b"], s["direction"], item["time"], item["end"]],
                ).fetchone()
                refs = evidence(db, "o.packet_key=?", [pair[0]]) if pair else []
            item["evidence"] = refs
            item["explanation"] = (
                f"{metric}: baseline {item['baseline_value']:.3f}; threshold {item['threshold']:.3f} "
                f"(median + max({floor:.3f}, 6 × 1.4826 × MAD)); first crossing bucket {item['bucket']} "
                f"has {item['value']:.3f}, confirmed in bucket {item['confirmed_bucket']}."
            )
            if "window_events" in item:
                item["explanation"] = (
                    f"{metric}: baseline {item['baseline_value']:.3f}%; threshold {item['threshold']:.3f}% "
                    f"(median + max({floor:.3f}, 6 × 1.4826 × MAD)). Rolling {WINDOW_SECONDS} s window: "
                    f"{item['window_events']} events / {item['window_denominator']} eligible packets "
                    f"= {item['value']:.3f}%; minimum {MIN_EVENTS} events in {MIN_EVENT_BUCKETS} buckets. "
                    f"First loss bucket {item['bucket']}; first crossing bucket {item['first_crossing_bucket']}."
                )
            found.append(item)
            detections.append(item)
        s["onsets"] = found
        statuses = {x["status"] for x in unknown}
        s["onset_status"] = (
            "detected" if found else "partial" if len(statuses) > 1 else next(iter(statuses), "unknown")
        )
        s["onset_reasons"] = unknown
        if found:
            first = min(found, key=lambda x: x["time"])
            labels = first["time_labels"]
            text = f" Change-point onset at {labels['local']} / {labels['utc']}; {first['explanation']} Timing uncertainty includes the {topology.bucket_seconds:g} s bucket and capture clock estimates."
            s["headline"] = s.get("headline", f"Transit degradation between {s['label']}.") + text
    directions = {}
    for d in ("forward", "reverse"):
        first_by_segment = {}
        for x in sorted(
            (x for x in detections if x["direction"] == d), key=lambda x: (x["time"], x["segment"])
        ):
            first_by_segment.setdefault(x["segment"], x)
        ordered = list(first_by_segment.values())
        groups = []
        for x in ordered:
            uncertainty = (x["clock_uncertainty_ms"] or 0) / 1000
            lower, upper = x["time"] - uncertainty, x["end"] + uncertainty
            if not groups or lower >= groups[-1]["end"]:
                groups.append(dict(time=x["time"], end=upper, segments=[x["segment"]]))
            else:
                groups[-1]["segments"].append(x["segment"])
                groups[-1]["end"] = max(groups[-1]["end"], upper)
        directions[d] = dict(
            propagation_order=groups,
            prime_suspects=groups[0]["segments"] if groups else [],
            first_time=groups[0]["time"] if groups else None,
            caveat="Temporal order is evidence, not proof of causation. Overlapping buckets are tied; clock uncertainty may further limit order.",
        )
    overall, status_counts, fallback_summary = status_summary(segments)
    earliest = min(detections, key=lambda x: x["time"]) if detections else None
    if earliest:
        tied = [x for x in detections if x["time"] < earliest["end"]]
        suspects = list(dict.fromkeys(x["label"] + " (" + x["direction"] + ")" for x in tied))
        summary = f"First detected degradation: {', '.join(suspects)} at {earliest['time_labels']['local']} / {earliest['time_labels']['utc']}. Earliest segments are prime suspects, not proven causes; same-bucket order is unresolved and clock uncertainty applies."
    else:
        summary = fallback_summary
    return dict(
        status=overall,
        status_counts=status_counts,
        items=detections,
        directions=directions,
        summary=summary,
        baseline_buckets=5,
        confirmation_buckets=2,
        count_window_seconds=WINDOW_SECONDS,
        minimum_events=MIN_EVENTS,
    )
