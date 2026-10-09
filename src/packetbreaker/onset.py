"""Explainable, sustained departures from early loss-free observation buckets."""

from statistics import median
from collections import Counter
import math

from .evidence import evidence
from .headlines import time_labels
from .store import rows
from .symptoms import label_retransmissions

WINDOW_SECONDS = 15
MIN_EVENTS = 3
MIN_EVENT_BUCKETS = 2
COUNT_SIGNALS = {
    "loss_percent": ("loss_count", "eligible_packets"),
    "retrans_percent": ("retransmissions", "tcp_packets"),
    "failed_handshakes": ("failed_handshake_count", None),
    "resets": ("resets", None),
    "zero_windows": ("zero_windows", None),
}
NETWORK_SIGNALS = {"loss_percent", "latency_p95_ms", "failed_handshakes"}


def measurement(row, metric):
    if metric not in COUNT_SIGNALS:
        return row.get(metric)
    count_key, denominator_key = COUNT_SIGNALS[metric]
    if denominator_key:
        denominator = row.get(denominator_key, 0)
        return 100 * row.get(count_key, 0) / denominator if denominator else None
    return row.get(count_key)


def detect_series(values, metric, floor, baseline_count=5, multiplier=6):
    """Only an early consecutive healthy prefix may seed the rolling baseline."""
    values = [dict(v, **{metric: measurement(v, metric)}) for v in values]
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
    if metric not in COUNT_SIGNALS and (
        max(initial) - min(initial) > max(floor, multiplier * 1.4826 * mad)
        or mad > max(floor, abs(center) * 0.25)
    ):
        return None, "unknown: early baseline is not stable enough"
    bucket_width = prefix[0]["end"] - prefix[0]["start"]
    window_buckets = max(MIN_EVENT_BUCKETS, math.ceil(WINDOW_SECONDS / bucket_width))
    window_seconds = window_buckets * bucket_width
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
        recent = [v for v in recent if v["end"] > x["end"] - window_seconds]
        samples = [v[metric] for v in history[-baseline_count:]]
        baseline = median(samples)
        spread = median(abs(v - baseline) for v in samples)
        threshold = baseline + max(floor, multiplier * 1.4826 * spread)
        if metric in COUNT_SIGNALS:
            count_key, denominator_key = COUNT_SIGNALS[metric]
            reference = history[-baseline_count:]
            exposure = sum(v[denominator_key] for v in recent) if denominator_key else len(recent)
            reference_exposure = (
                sum(v[denominator_key] for v in reference) if denominator_key else len(reference)
            )
            scale = 100 if denominator_key else 1
            baseline = scale * sum(v[count_key] for v in reference) / reference_exposure
            threshold = baseline + max(floor, multiplier * 1.4826 * spread)
            count = sum(v[count_key] for v in recent)
            value = scale * count / exposure if exposure else 0
            expected = baseline * exposure / scale
            count_threshold = max(
                MIN_EVENTS, math.ceil(expected + MIN_EVENTS), math.floor(threshold * exposure / scale) + 1
            )
            changed = [
                v
                for v in recent
                if v["bucket"] > reference[-1]["bucket"]
                and v[count_key] > baseline * (v[denominator_key] if denominator_key else 1) / scale
            ]
            if count >= count_threshold and len(changed) >= MIN_EVENT_BUCKETS:
                first = changed[0]
                return dict(
                    metric=metric,
                    baseline_value=baseline,
                    mad=spread,
                    threshold=threshold,
                    multiplier=multiplier,
                    minimum_delta=floor,
                    baseline_method="reference event count / exposure",
                    baseline_buckets=[v["bucket"] for v in reference],
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
                    window_seconds=window_seconds,
                    window_buckets=window_buckets,
                    window_events=count,
                    window_denominator=exposure,
                    expected_events=expected,
                    count_threshold=count_threshold,
                    event_buckets=len(changed),
                    min_events=MIN_EVENTS,
                ), None
            # Keep the pre-change reference; sparse event buckets must not train away the change.
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
            ("retrans_percent", 0.0),
            ("failed_handshakes", 0.0),
            ("resets", 0.0),
            ("zero_windows", 0.0),
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
                scope="network_segment" if metric in NETWORK_SIGNALS else "capture_signal",
            )
            if metric in ("loss_percent", "failed_handshakes"):
                kinds = (
                    "('handshake_blocked')"
                    if metric == "failed_handshakes"
                    else "('recovered_loss','impactful_loss','unrecovered_loss','handshake_blocked')"
                )
                event = db.execute(
                    f"""SELECT packet_key,recovery_key,support_key FROM events WHERE point_a=? AND point_b=? AND direction=?
                    AND ts>=? AND ts<? AND kind IN {kinds} ORDER BY ts LIMIT 1""",
                    [s["point_a"], s["point_b"], s["direction"], item["time"], item["end"]],
                ).fetchone()
                refs = evidence(db, "o.packet_key IN (?,?,?)", list(event)) if event else []
            elif metric in ("retrans_percent", "resets", "zero_windows"):
                condition = {
                    "retrans_percent": "o.retrans",
                    "resets": "o.proto='TCP' AND (o.flags&4)>0",
                    "zero_windows": "o.zero_window",
                }[metric]
                refs = evidence(
                    db,
                    f"o.point=? AND o.direction=? AND ({condition}) AND o.corrected>=? AND o.corrected<?",
                    [s["point_a"], s["direction"], item["time"], item["end"]],
                    8,
                )
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
                unit = "%" if COUNT_SIGNALS[metric][1] else " events/bucket"
                item["explanation"] = (
                    f"{metric}: baseline {item['baseline_value']:.3f}{unit}; robust threshold {item['threshold']:.3f}{unit} (MAD {item['mad']:.3f}, multiplier 6 × 1.4826). "
                    f"Rolling up to {item['window_seconds']:g} s window: {item['window_events']} events, expected {item['expected_events']:.3f}; "
                    f"count threshold {item['count_threshold']} (minimum {MIN_EVENTS} excess events in {MIN_EVENT_BUCKETS} buckets). "
                    f"First event bucket {item['bucket']}; first crossing bucket {item['first_crossing_bucket']}."
                )
            if metric not in NETWORK_SIGNALS:
                item["explanation"] += (
                    " Local TCP observation; not evidence that this hop caused network loss."
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
            s["headline"] = s.get("headline", f"Observed {first['metric']} change at {s['label']}.") + text
    label_retransmissions(db, segments, detections, topology)
    network_detections = [x for x in detections if x["scope"] == "network_segment"]
    directions = {}
    for d in ("forward", "reverse"):
        first_by_segment = {}
        for x in sorted(
            (x for x in network_detections if x["direction"] == d), key=lambda x: (x["time"], x["segment"])
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
    earliest = min(network_detections, key=lambda x: x["time"]) if network_detections else None
    if earliest:
        tied = [x for x in network_detections if x["time"] < earliest["end"]]
        suspects = list(dict.fromkeys(x["label"] + " (" + x["direction"] + ")" for x in tied))
        summary = f"First detected degradation: {', '.join(suspects)} at {earliest['time_labels']['local']} / {earliest['time_labels']['utc']}. Earliest segments are prime suspects, not proven causes; same-bucket order is unresolved and clock uncertainty applies."
    elif detections:
        summary = "Local TCP signal onsets observed. These do not identify a network-loss hop; see per-segment evidence and quality notes."
    else:
        summary = fallback_summary
    return dict(
        status=overall,
        status_counts=status_counts,
        items=ordered_onsets(detections, directions),
        directions=directions,
        summary=summary,
        baseline_buckets=5,
        confirmation_buckets=2,
        count_window_seconds=WINDOW_SECONDS,
        minimum_events=MIN_EVENTS,
    )


def ordered_onsets(items, directions):
    primes = {s for d in directions.values() for s in d.get("prime_suspects", [])}
    return sorted(
        items,
        key=lambda x: (
            2 if x.get("scope") == "capture_signal" else 0 if x["segment"] in primes else 1,
            x.get("time", 0),
            x["segment"],
            x["metric"],
        ),
    )
