import json

from ..clock import transit_quality
from ..evidence import evidence
from ..store import rows
from .classification import classify_segment_losses
from .selection import reverse_tuple


def _has_pending_nat(db, topology, pa, pb, a, b, suggestions):
    pending_nat = any(
        x["point_a"] in (a, b)
        and x["point_b"] in (a, b)
        and not any(
            (m.point_a, m.point_b) == (x["point_a"], x["point_b"])
            and (x["tuple_a"], x["tuple_b"])
            in ((m.tuple_a, m.tuple_b), (reverse_tuple(m.tuple_a), reverse_tuple(m.tuple_b)))
            for m in topology.nat_mappings
        )
        for x in suggestions
    )
    if pa.device == pb.device and "nat" in (pa.translation, pb.translation):
        confirmed = []
        for m in topology.nat_mappings:
            if {m.point_a, m.point_b} == {a, b}:
                confirmed.extend(
                    (m.tuple_a, m.tuple_b, reverse_tuple(m.tuple_a), reverse_tuple(m.tuple_b))
                )
        unresolved = db.execute(
            """SELECT count(*) FROM nat_point_tuples x WHERE x.point IN (?,?)
            AND NOT EXISTS(SELECT 1 FROM nat_point_tuples y WHERE y.point IN (?,?) AND y.point<>x.point AND y.canon=x.canon)
            AND x.canon NOT IN (SELECT canon FROM tuple_lookup WHERE tuple_key IN (SELECT unnest(?::VARCHAR[])))""",
            [a, b, a, b, confirmed],
        ).fetchone()[0]
        pending_nat = pending_nat or unresolved > 0
    return pending_nat


def _endpoint_quality_for_edge(db, points, inventories, a, b, direction, start, end):
    quality_rows = rows(
        db,
        """SELECT point,
        CASE WHEN direction='unknown' THEN 'direction_unknown'
             WHEN NOT eligible THEN coalesce(excluded_reason,'unsupported_identity') ELSE 'eligible' END AS reason,
        count(*) AS count FROM obs WHERE point IN (?,?) AND (direction=? OR direction='unknown')
        AND (? IS NULL OR coalesce(corrected,ts)>=?) AND (? IS NULL OR coalesce(corrected,ts)<=?)
        GROUP BY point,reason""",
        [a, b, direction, start, start, end, end],
    )
    endpoint_quality = {}
    excluded_counts = {}
    for endpoint in (a, b):
        q = [r for r in quality_rows if r["point"] == endpoint]
        n = sum(r["count"] for r in q)
        good = sum(r["count"] for r in q if r["reason"] == "eligible")
        excluded = {r["reason"]: r["count"] for r in q if r["reason"] != "eligible"}
        endpoint_quality[endpoint] = dict(
            total=n, eligible=good, excluded=excluded, eligible_ratio=good / n if n else None
        )
        inv = inventories[points[endpoint].capture_id]
        time_bad = inv.get("timestamp_excluded_counts", {})
        if time_bad:
            total_valid = inv.get("packet_count", 0)
            temporal_ratio = total_valid / (total_valid + sum(time_bad.values()))
            current = endpoint_quality[endpoint]["eligible_ratio"]
            endpoint_quality[endpoint]["eligible_ratio"] = (
                min(current, temporal_ratio) if current is not None else temporal_ratio
            )
            endpoint_quality[endpoint]["timestamp_quality_scope"] = (
                "whole capture; invalid times cannot be placed in the selected window"
            )
            excluded.update(time_bad)
        for key, value in excluded.items():
            excluded_counts[key] = excluded_counts.get(key, 0) + value
    ratios = [
        q["eligible_ratio"] for q in endpoint_quality.values() if q["eligible_ratio"] is not None
    ]
    eligible_ratio = min(ratios) if ratios else 0.0
    return endpoint_quality, excluded_counts, eligible_ratio


def _build_single_segment(
    db,
    topology,
    points,
    models,
    inventories,
    suggestions,
    unselected_points,
    outer_points,
    a,
    b,
    direction,
    start,
    end,
    common_start,
    common_end,
):
    pa, pb = points[a], points[b]
    segment_id = f"{direction}:{a}:{b}"
    unsupported = pa.device == pb.device and any(p.translation == "full_proxy" for p in (pa, pb))
    pending_nat = _has_pending_nat(db, topology, pa, pb, a, b, suggestions)
    ma, mb = models[pa.capture_id], models[pb.capture_id]
    shared_clock = pa.capture_id == pb.capture_id or bool(
        ma.source_domain and ma.source_domain == mb.source_domain
    )
    clocks_ok = ma.offset is not None and mb.offset is not None and ma.domain == mb.domain
    tolerance_ms = (
        (ma.uncertainty or 0) + (mb.uncertainty or 0) + ma.timestamp_jitter + mb.timestamp_jitter
    ) * 1000
    matched = rows(
        db,
        """SELECT count(*) AS matched,min(time_b-time_a)*1000 AS min_ms,
        quantile_cont((time_b-time_a)*1000,.5) AS p50_ms,
        quantile_cont((time_b-time_a)*1000,.05) AS p05_ms,
        count(*) FILTER(WHERE (time_b-time_a)*1000 < -?) AS negative_outliers,
        quantile_cont((time_b-time_a)*1000,.95) AS p95_ms,
        max((time_b-time_a)*1000) AS max_ms
        FROM observation_matches WHERE point_a=? AND point_b=? AND direction=?
        AND (? IS NULL OR time_a>=?) AND (? IS NULL OR time_a<=?)""",
        [max(0.001, tolerance_ms), a, b, direction, start, start, end, end],
    )[0]
    timing_quality = transit_quality(matched, tolerance_ms)
    clocks_ok = clocks_ok and (shared_clock or not timing_quality["systematic_negative"])
    if shared_clock and timing_quality["systematic_negative"]:
        timing_quality["quality_notes"].append(
            "Shared clock: negative transit concerns capture order/timestamp placement, not relative clock fitting"
        )
    reason = (
        "Unsupported translation boundary"
        if unsupported
        else "Tunnel matching layer undecided or unavailable; loss unknown"
        if a in unselected_points or b in unselected_points
        else "Incompatible matching layers across tunnel boundary; loss unknown"
        if (a in outer_points) != (b in outer_points)
        else "NAT mapping awaits confirmation"
        if pending_nat
        else "Clock alignment unreliable"
        if not clocks_ok
        else "No common capture coverage"
        if common_start is None
        else "Selected window is outside common coverage"
        if start is None or end is None or end < common_start or start > common_end
        else None
    )
    if pa.vendor == "checkpoint" and pb.device == pa.device:
        inv = inventories[pa.capture_id]
        if (
            not pa.inspection_complete
            or inv.get("damaged_tail")
            or inv.get("ifdrop")
            or inv.get("osdrop")
            or inv.get("timestamp_excluded_counts")
        ):
            reason = "Inspection coverage incomplete or not attested"
    classification_reason = reason
    if pa.vendor == "checkpoint" and pb.device == pa.device:
        classification_reason = (
            reason or "Inspection-stage absence has no positive device-drop proof"
        )
    endpoint_quality, excluded_counts, eligible_ratio = _endpoint_quality_for_edge(
        db, points, inventories, a, b, direction, start, end
    )
    if eligible_ratio < topology.min_eligible_ratio:
        detail = (
            ", ".join(f"{k}: {v}" for k, v in sorted(excluded_counts.items()))
            or "no observations"
        )
        reason = (
            (reason + "; " if reason else "")
            + f"Insufficient matchable packets ({100 * (1 - eligible_ratio):.1f}% excluded: {detail})"
        )
    segment = dict(
        eligible_ratio=eligible_ratio,
        excluded_counts=excluded_counts,
        endpoint_quality=endpoint_quality,
        id=segment_id,
        point_a=a,
        point_b=b,
        label=f"{pa.label} → {pb.label}",
        location="device" if pa.device == pb.device else "link",
        device=pa.device if pa.device == pb.device else None,
        direction=direction,
        reason=reason,
        latency_confidence="estimated" if not reason else "unknown",
        offset_uncertainty_ms=0.0
        if shared_clock
        else ((ma.uncertainty or 0) + (mb.uncertainty or 0)) * 1000
        if shared_clock or (ma.uncertainty is not None and mb.uncertainty is not None)
        else None,
        **matched,
        **timing_quality,
    )
    if reason:
        for key in ("min_ms", "p50_ms", "p95_ms", "max_ms"):
            segment[key] = None
    return segment, segment_id, classification_reason


def build_segments(
    db,
    topology,
    points,
    models,
    inventories,
    suggestions,
    start,
    end,
    common_start,
    common_end,
    byte_active,
    has_device_proofs,
):
    segments, findings = [], []
    outer_points = {
        r[0]
        for r in db.execute(
            "SELECT DISTINCT point FROM obs WHERE json_extract_string(path_fields,'$.tunnel.layer')='outer'"
        ).fetchall()
    }
    unselected_points = {
        r[0]
        for r in db.execute(
            "SELECT DISTINCT point FROM obs WHERE unsupported LIKE 'Tunnel encapsulation%' OR unsupported LIKE 'Capture layer decode unavailable:%'"
        ).fetchall()
    }
    for direction, path in (
        ("forward", topology.forward),
        ("reverse", topology.reverse or list(reversed(topology.forward))),
    ):
        for idx, (a, b) in enumerate(zip(path, path[1:])):
            segment, segment_id, classification_reason = _build_single_segment(
                db,
                topology,
                points,
                models,
                inventories,
                suggestions,
                unselected_points,
                outer_points,
                a,
                b,
                direction,
                start,
                end,
                common_start,
                common_end,
            )
            downstream = path[idx + 2 :]
            classify_segment_losses(
                db,
                topology,
                points[a],
                points[b],
                segment,
                segment_id,
                a,
                b,
                direction,
                downstream,
                classification_reason,
                start,
                end,
                common_start,
                common_end,
                byte_active,
                has_device_proofs,
                findings,
            )
            segments.append(segment)
    return segments, findings


def build_flow_summary_and_quality(db, points, byte_active):
    db.execute("""CREATE OR REPLACE TABLE flow_summary AS
        WITH base AS (SELECT flow,max(coalesce(translation_reason,range_reason)) AS matching_unknown_reason,min(corrected) AS start,max(corrected) AS "end",count(DISTINCT point) AS points,
            count(*) FILTER(WHERE retrans) AS retrans_observations,
            bool_or((flags&4)>0) AS has_reset, max(rtt)*1000 AS max_rtt_ms,
            min(canon) AS tuple, count(*) FILTER(WHERE (flags&2)>0 AND (flags&16)=0) AS syns,
            count(*) FILTER(WHERE (flags&18)=18) AS synacks FROM obs GROUP BY flow),
        bytes AS (SELECT flow,sum(length) AS bytes,count(packet_key) AS unique_observations FROM
            (SELECT flow,packet_key,max(length) AS length FROM obs GROUP BY flow,packet_key) GROUP BY flow),
        losses AS (SELECT flow,count(*) FILTER(WHERE kind='impactful_loss') AS impactful_loss,
            count(*) FILTER(WHERE kind='recovered_loss') AS recovered_loss,
            count(*) FILTER(WHERE kind='capture_miss') AS capture_miss,
            count(*) FILTER(WHERE kind='unrecovered_loss') AS unrecovered_loss,
            count(*) FILTER(WHERE kind='handshake_blocked') AS handshake_blocked,
            count(*) FILTER(WHERE kind='confirmed_device_drop') AS confirmed_device_drop,
            count(*) FILTER(WHERE kind='unknown') AS unknown_events,
            max(greatest(impact_ms,recovery_ms)) AS max_stall_ms
            FROM events GROUP BY flow)
        SELECT base.*,NULL::DOUBLE AS handshake_rtt_ms,NULL::VARCHAR AS reset_origin,bytes.bytes,bytes.unique_observations,coalesce(impactful_loss,0) AS impactful_loss,
            coalesce(recovered_loss,0) AS recovered_loss,coalesce(capture_miss,0) AS capture_miss,max_stall_ms,
            coalesce(unrecovered_loss,0) AS unrecovered_loss,coalesce(handshake_blocked,0) AS handshake_blocked,
            coalesce(confirmed_device_drop,0) AS confirmed_device_drop,
            coalesce(unknown_events,0) AS unknown_events,
            (syns>0 AND synacks=0) OR coalesce(handshake_blocked,0)>0 AS handshake_incomplete
        FROM base JOIN bytes USING(flow) LEFT JOIN losses USING(flow)""")
    if byte_active:
        db.execute("""UPDATE flow_summary SET bytes=x.bytes FROM (
            SELECT flow,sum(length) AS bytes FROM (
                SELECT o.flow,o.packet_key,max(o.length) AS length FROM obs o WHERE NOT
                    (o.proto='TCP' AND o.length>0 AND EXISTS(SELECT 1 FROM byte_flows f WHERE f.flow=o.flow AND f.direction=o.direction))
                    GROUP BY o.flow,o.packet_key
                UNION ALL SELECT flow,packet_key,max(range_length) FROM byte_obs WHERE is_atom AND eligible GROUP BY flow,packet_key)
            GROUP BY flow) x WHERE flow_summary.flow=x.flow""")
    quality = rows(
        db,
        """SELECT point,count(*) AS packets,count(*) FILTER(WHERE NOT eligible) AS excluded,
        count(*) FILTER(WHERE caplen<wirelen) AS truncated,count(*) FILTER(WHERE length>1500) AS possible_offload,
        count(*) FILTER(WHERE direction='unknown') AS unknown_direction FROM obs GROUP BY point""",
    )
    capture_rows = db.execute("SELECT id,name,inventory FROM captures").fetchall()
    inventories = {cid: json.loads(inv) for cid, _, inv in capture_rows}
    capture_names = {cid: name for cid, name, _ in capture_rows}
    index_counts = {
        r["point"]: r
        for r in rows(
            db,
            "SELECT *,input_frames-retained_frames AS excluded_frames,input_flows-retained_flows AS excluded_flows FROM index_scope",
        )
    }
    present = {q["point"] for q in quality}
    quality.extend(
        dict(point=p, packets=0, excluded=0, truncated=0, possible_offload=0, unknown_direction=0)
        for p in index_counts
        if p not in present
    )
    for q in quality:
        q["index_scope"] = index_counts.get(q["point"])
        cid = points[q["point"]].capture_id
        inv = inventories[cid]
        q["file"] = capture_names.get(cid, q["point"])
        q["ifdrop"], q["osdrop"] = inv.get("ifdrop"), inv.get("osdrop")
        q["prefilter_excluded"] = inv.get("prefilter_excluded", 0)
        q["prefilter_total"] = inv.get("prefilter_total")
        q["prefilter_skipped"] = bool(inv.get("prefilter_skipped"))
        q["evidence"] = evidence(
            db,
            "o.point=? AND (NOT o.eligible OR o.caplen<o.wirelen OR o.length>1500 OR o.direction='unknown')",
            [q["point"]],
            5,
        )
    return quality, inventories, capture_names
