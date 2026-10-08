"""Persist bounded, coverage-aware segment buckets from matched observations."""

import math

from .store import rows

CLASSES = (
    "recovered_loss",
    "impactful_loss",
    "unrecovered_loss",
    "handshake_blocked",
    "capture_miss",
    "unknown",
)
METRICS = {
    "throughput_bps": (
        "Throughput",
        "bit/s",
        "Upstream observed wire bytes × 8 per full bucket second; includes retransmissions.",
    ),
    "pps": (
        "Packet rate",
        "packets/s",
        "All upstream observations per full bucket second, including control packets.",
    ),
    "loss_percent": (
        "Network loss",
        "%",
        "Supported recovered, impactful, unrecovered and blocked-handshake events / eligible upstream packets.",
    ),
    "retrans_percent": (
        "Retransmissions",
        "%",
        "tshark retransmissions / observed upstream TCP packets; a local TCP symptom, not hop attribution.",
    ),
    "latency_p50_ms": (
        "Transit p50",
        "ms",
        "Median corrected downstream minus upstream time for shared eligible packet occurrences.",
    ),
    "latency_p95_ms": (
        "Transit p95",
        "ms",
        "95th percentile corrected transit time; clock uncertainty applies.",
    ),
    "latency_max_ms": (
        "Transit maximum",
        "ms",
        "Maximum corrected transit time among matched packets; clock uncertainty applies.",
    ),
    "rtt_ms": (
        "RTT",
        "ms",
        "Median tshark ACK RTT at the upstream point; this is not the isolated hop delay.",
    ),
    "new_connections": (
        "New connections",
        "connections",
        "Distinct TCP sessions with an initial SYN at this upstream point in the bucket.",
    ),
    "failed_handshakes": (
        "Failed handshakes",
        "connections",
        "Distinct sessions with a supported blocked-handshake event at this segment.",
    ),
    "resets": ("Resets", "packets", "Observed upstream TCP RST packets."),
    "zero_windows": ("Zero windows", "packets", "Upstream TCP zero-window announcements reported by tshark."),
}
for _class in CLASSES:
    METRICS[_class + "_percent"] = (
        _class.replace("_", " ").capitalize(),
        "%",
        "Classified events / eligible upstream packets; capture misses and unknown appearances are not network loss.",
    )


def build_timeseries(db, topology, segments, coverage, window):
    width = topology.bucket_seconds
    valid = [c for c in coverage if c["start"] is not None and c["end"] is not None]
    lo = topology.start if topology.start is not None else min((c["start"] for c in valid), default=None)
    hi = topology.end if topology.end is not None else max((c["end"] for c in valid), default=None)
    metric_sql = ",".join(f'"{m}" DOUBLE' for m in METRICS)
    db.execute(f"""CREATE OR REPLACE TABLE segment_buckets (
        segment VARCHAR,direction VARCHAR,bucket BIGINT,start DOUBLE,"end" DOUBLE,
        coverage VARCHAR,reason VARCHAR,eligible_packets BIGINT,matched_packets BIGINT,
        capture_misses BIGINT,unknown_events BIGINT,{metric_sql})""")
    meta = dict(
        bucket_seconds=width,
        start=lo,
        end=hi,
        bucket_count=0,
        metrics={k: dict(label=v[0], unit=v[1], tooltip=v[2]) for k, v in METRICS.items()},
    )
    if lo is None or hi is None or hi <= lo:
        return meta
    origin = math.floor(lo / width) * width
    count = math.ceil((hi - origin) / width)
    # Bound both the stored grid and browser payload; ask for coarser buckets explicitly.
    if count * len(segments) > 200000:
        raise ValueError("Too many heatmap cells; increase bucket_seconds or narrow the analysis window")
    meta.update(start=origin, end=origin + count * width, bucket_count=count)
    by_point = {c["point"]: c for c in valid}
    db.execute(
        f"""CREATE OR REPLACE TEMP VIEW bucket_obs AS SELECT *,
        floor((corrected-{origin})/{width})::BIGINT AS bucket FROM obs
        WHERE corrected>={origin} AND corrected<{origin + count * width}"""
    )
    for s in segments:
        a, b, d = s["point_a"], s["point_b"], s["direction"]
        ca, cb = by_point.get(a), by_point.get(b)
        left = max(ca["start"], cb["start"]) if ca and cb else None
        right = min(ca["end"], cb["end"]) if ca and cb else None
        aggregate = {
            r["bucket"]: r
            for r in rows(
                db,
                """SELECT bucket,count(*) AS packets,
            sum(wirelen)*8 AS bits,count(*) FILTER(WHERE proto='TCP') AS tcp,
            count(*) FILTER(WHERE retrans) AS retrans,
            count(*) FILTER(WHERE eligible AND (length>0 OR (proto='TCP' AND (flags&7)>0) OR proto IN ('UDP','ICMP'))) AS eligible,
            median(rtt)*1000 AS rtt_ms,count(DISTINCT flow) FILTER(WHERE proto='TCP' AND (flags&18)=2 AND NOT retrans) AS new_connections,
            count(*) FILTER(WHERE proto='TCP' AND (flags&4)>0) AS resets,
            count(*) FILTER(WHERE zero_window) AS zero_windows
            FROM bucket_obs WHERE point=? AND direction=? GROUP BY bucket""",
                [a, d],
            )
        }
        latency = {
            r["bucket"]: r
            for r in rows(
                db,
                """SELECT a.bucket,count(*) AS matched,
            quantile_cont((b.corrected-a.corrected)*1000,.5) AS latency_p50_ms,
            quantile_cont((b.corrected-a.corrected)*1000,.95) AS latency_p95_ms,
            max((b.corrected-a.corrected)*1000) AS latency_max_ms
            FROM bucket_obs a JOIN obs b USING(packet_key) WHERE a.point=? AND b.point=?
            AND a.direction=? AND a.eligible AND b.eligible GROUP BY a.bucket""",
                [a, b, d],
            )
        }
        events = {}
        for r in rows(
            db,
            """SELECT floor((ts-?)/?)::BIGINT AS bucket,kind,count(*) AS n,
            count(DISTINCT flow) AS flows FROM events WHERE point_a=? AND point_b=? AND direction=? GROUP BY bucket,kind""",
            [origin, width, a, b, d],
        ):
            events.setdefault(r["bucket"], {})[r["kind"]] = r
        records = []
        for i in range(count):
            start, end = origin + i * width, origin + (i + 1) * width
            state = (
                "not capturing"
                if left is None or right is None or end <= left or start >= right
                else "partial coverage"
                if start < left or end > right
                else "capturing"
            )
            x, y, ev = aggregate.get(i, {}), latency.get(i, {}), events.get(i, {})
            eligible = x.get("eligible", 0)
            miss, unknown = (ev.get(k, {}).get("n", 0) for k in ("capture_miss", "unknown"))
            reason = s["reason"]
            metrics = dict.fromkeys(METRICS)
            if state == "capturing":
                metrics.update(
                    throughput_bps=x.get("bits", 0) / width,
                    pps=x.get("packets", 0) / width,
                    rtt_ms=x.get("rtt_ms"),
                    new_connections=x.get("new_connections", 0),
                    resets=x.get("resets", 0),
                    zero_windows=x.get("zero_windows", 0),
                    retrans_percent=100 * x.get("retrans", 0) / x["tcp"] if x.get("tcp") else None,
                )
                # Missing events are classified only within the selected common window.
                classified = (
                    window["start"] is not None
                    and window["end"] is not None
                    and window["common_start"] is not None
                    and window["common_end"] is not None
                    and start >= max(window["start"], window["common_start"])
                    and end <= min(window["end"], window["common_end"])
                )
                if not reason and classified:
                    for k in CLASSES:
                        metrics[k + "_percent"] = (
                            100 * ev.get(k, {}).get("n", 0) / eligible if eligible else None
                        )
                    metrics["loss_percent"] = (
                        sum(metrics[k + "_percent"] for k in CLASSES[:4]) if eligible else None
                    )
                    metrics["failed_handshakes"] = ev.get("handshake_blocked", {}).get("flows", 0)
                if not reason:
                    metrics.update(
                        {k: y.get(k) for k in ("latency_p50_ms", "latency_p95_ms", "latency_max_ms")}
                    )
                if not classified and not reason:
                    reason = "Outside classified common window; loss rates unknown"
            else:
                reason = state
            records.append(
                [
                    s["id"],
                    d,
                    i,
                    start,
                    end,
                    state,
                    reason,
                    eligible,
                    y.get("matched", 0),
                    miss,
                    unknown,
                    *metrics.values(),
                ]
            )
        if records:
            db.executemany(
                "INSERT INTO segment_buckets VALUES (" + ",".join("?" for _ in records[0]) + ")", records
            )
    return meta


def timeseries_page(project):
    with project.connect() as db:
        report = project.get(db, "report")
        if not report or "timeseries" not in report:
            return dict(items=[], metrics={})
        return dict(
            **report["timeseries"],
            items=rows(db, "SELECT * FROM segment_buckets ORDER BY direction,segment,bucket"),
        )
