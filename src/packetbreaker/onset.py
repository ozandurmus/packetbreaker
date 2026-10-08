"""Explainable, sustained departures from early loss-free observation buckets."""

from statistics import median

from .evidence import evidence
from .headlines import time_labels
from .store import rows


def detect_series(values, metric, floor, baseline_count=5, multiplier=6):
    """Only an early consecutive healthy prefix may seed the rolling baseline."""
    complete = [
        v
        for v in values
        if v["coverage"] == "capturing"
        and v["reason"] != "Outside classified common window; loss rates unknown"
    ]
    if len(complete) < baseline_count + 2:
        return None, "unknown: fewer than five baseline buckets and two confirmation buckets"
    prefix = complete[:baseline_count]

    def usable(x):
        return (
            x[metric] is not None
            and not x["reason"]
            and x["eligible_packets"] > 0
            and not x["capture_misses"]
            and not x["unknown_events"]
        )

    def healthy(x):
        return usable(x) and x["loss_percent"] == 0

    if not all(healthy(x) for x in prefix) or any(
        b["bucket"] != a["bucket"] + 1 for a, b in zip(prefix, prefix[1:])
    ):
        return None, "unknown: early baseline lacks consecutive covered, matchable, loss-free buckets"
    initial = [v[metric] for v in prefix]
    center = median(initial)
    mad = median(abs(v - center) for v in initial)
    if max(initial) - min(initial) > max(floor, multiplier * 1.4826 * mad) or (
        metric == "latency_p95_ms" and mad > max(floor, abs(center) * 0.25)
    ):
        return None, "unknown: early baseline is not stable enough"
    history = prefix[:]
    candidate = None
    previous = prefix[-1]["bucket"]
    gap = False
    for x in complete[baseline_count:]:
        if not usable(x) or x["bucket"] != previous + 1:
            candidate = None
            # Do not bridge a coverage/quality gap with a stale baseline.
            history = []
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
        samples = [v[metric] for v in history[-baseline_count:]]
        baseline = median(samples)
        spread = median(abs(v - baseline) for v in samples)
        threshold = baseline + max(floor, multiplier * 1.4826 * spread)
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
        "unknown: coverage or capture-quality gaps limit onset chronology"
        if gap
        else "No sustained departure from the early healthy baseline",
    )


def add_onsets(db, topology, segments):
    detections = []
    for s in segments:
        values = rows(db, "SELECT * FROM segment_buckets WHERE segment=? ORDER BY bucket", [s["id"]])
        unknown = []
        found = []
        for metric, floor in (
            ("loss_percent", 1.0),
            ("latency_p95_ms", max(1.0, 2 * (s["offset_uncertainty_ms"] or 0))),
        ):
            item, reason = detect_series(values, metric, floor)
            if not item:
                unknown.append(dict(metric=metric, reason=reason))
                continue
            item.update(
                segment=s["id"],
                label=s["label"],
                direction=s["direction"],
                point_a=s["point_a"],
                point_b=s["point_b"],
                time_labels=time_labels(item["time"], topology.report_timezone),
                clock_uncertainty_ms=s["offset_uncertainty_ms"],
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
            found.append(item)
            detections.append(item)
        s["onsets"] = found
        s["onset_status"] = (
            "detected"
            if found
            else "unknown"
            if any(x["reason"].startswith("unknown:") for x in unknown)
            else "none"
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
    earliest = min(detections, key=lambda x: x["time"]) if detections else None
    if earliest:
        tied = [x for x in detections if x["time"] < earliest["end"]]
        suspects = list(dict.fromkeys(x["label"] + " (" + x["direction"] + ")" for x in tied))
        summary = f"First detected degradation: {', '.join(suspects)} at {earliest['time_labels']['local']} / {earliest['time_labels']['utc']}. Earliest segments are prime suspects, not proven causes; same-bucket order is unresolved and clock uncertainty applies."
    else:
        summary = (
            "Onset unknown: insufficient healthy baseline or matchable coverage."
            if any(s["onset_status"] == "unknown" for s in segments)
            else "No supported sustained loss or transit-delay onset detected."
        )
    return dict(
        status="detected"
        if detections
        else "unknown"
        if any(s["onset_status"] == "unknown" for s in segments)
        else "none",
        items=detections,
        directions=directions,
        summary=summary,
        baseline_buckets=5,
        confirmation_buckets=2,
    )
