from datetime import datetime, timezone
import json

from .. import __version__
from ..application_index import index_applications
from ..byte_ranges import prepare_byte_ranges, range_notes
from ..capture_layers import tunnel_report
from ..device_drops import add_unplaced, device_report, prepare_proofs
from ..evidence import evidence, prepare_flow_filters
from ..fragments import fragment_findings
from ..headlines import add_headlines
from ..integrity import analyze_integrity, group_downstream_findings, link_modified_payloads
from ..matching import link_tcp_sessions, match_occurrences, propagate_translation_unknown
from ..microbursts import build_microbursts
from ..onset import add_onsets
from ..proxy_analysis import correlate, restrict_onset_domains
from ..proxy_resets import reset_checks
from ..proxy_waterfall import add_dwell
from ..store import rows
from ..timeseries import build_timeseries
from ..tls_analysis import tls_checks
from ..topology.models import Topology
from ..translation import sequence_report
from ..vendors import f5_report
from .clocks import align
from .matching import prepare
from .segments import build_flow_summary_and_quality, build_segments

LIMITATIONS = [
    "Observed coverage does not prove uninterrupted capture.",
    "Full proxies link requests, never TCP packets. Ambiguous request candidates remain unknown.",
    "SNI pairs visible TLS setup only; encrypted HTTP request boundaries and TLS 1.3 certificates remain unknown.",
    "Clock domains separated by a proxy cannot establish proxy dwell or cross-domain onset order without shared clock evidence.",
    "HTTP/1.x response association requires complete SYN-anchored contiguous decoded request/response ranges; chunked or coalesced messages remain unknown.",
    "Application indexing isolates capture points, uses two tshark passes and caches at most 10,000 events per point; narrow the capture when this budget is exceeded.",
    "Latency is estimated under minimum-path symmetry; offsets include possible path asymmetry.",
    "SPAN duplicates, unresolved occurrence collisions, ambiguous/incomplete fragment observations and unsupported transports are excluded from packet matching; whole-datagram disappearance is assessed separately.",
    "TCP sessions are joined by shared occurrences; streams without a shared packet stay separate.",
    "Unrecovered disappearance cannot confirm a device drop without positive device evidence.",
]


def _select_verdict(
    primary_host,
    security_findings,
    host_findings,
    integrity_findings,
    proxy_findings,
    tls_findings,
    findings,
    inconclusive_quality,
    segments,
):
    if primary_host:
        return primary_host["headline"]
    if any(f["confidence"] == "supported" for f in security_findings):
        return "Security heuristic patterns observed; interpretation required"
    if host_findings:
        return "Host receive/transmit path delay observed; application timing reported separately"
    if any(
        f["confidence"] == "supported" and f["severity"] != "quality"
        for f in integrity_findings + proxy_findings + tls_findings
    ):
        return "Path integrity findings observed"
    if any(f["type"] == "confirmed_device_drop" for f in findings):
        return "Confirmed device drops observed"
    if any(f["type"] == "impactful_loss" for f in findings):
        return "Impactful loss observed"
    if any(f["type"] == "handshake_blocked" for f in findings):
        return "Handshake failure observed"
    if any(f["severity"] == "low" for f in findings):
        return "Loss observed"
    if (
        inconclusive_quality
        or any(s["reason"] for s in segments)
        or any(f["severity"] == "unknown" for f in findings)
    ):
        return "Inconclusive"
    return "No supported network loss in the selected window"


def _run_secondary_detectors(
    db,
    topology,
    points,
    segments,
    coverage,
    models,
    findings,
    proxies,
    start,
    end,
    common_start,
    common_end,
    byte_active,
    progress,
):
    from ..aggregates import add_aggregates
    from ..cycles import build_cycles, cycle_findings
    from ..delivery import delivery_report
    from ..hold_release import hold_release
    from ..host_path import (
        classify_chronic_losses,
        finish_host_summary,
        group_host_losses,
        host_path,
        polish_findings,
    )
    from ..incident import build_incident
    from ..pilot import flow_columns
    from ..rtp import build_rtp
    from ..security import build_lifecycle, security_checks
    from ..sip import build_sip
    from ..udp import build_udp

    rank = {"high": 0, "low": 1, "quality": 2, "unknown": 3}
    findings.sort(key=lambda f: (rank[f["severity"]], f["time_range"][0]))
    add_headlines(db, findings, segments, topology, end)
    progress(state="building time series")
    time_window = dict(start=start, end=end, common_start=common_start, common_end=common_end)
    timeseries = build_timeseries(db, topology, segments, coverage, time_window)
    sessions = build_lifecycle(db, topology, coverage, timeseries, time_window)
    onsets = add_onsets(db, topology, segments)
    restrict_onset_domains(onsets, points, models)
    microbursts = build_microbursts(db, topology, models, onsets, start, end)
    integrity_findings, integrity_notes = analyze_integrity(
        db, topology, segments, coverage, models, start, end
    )
    fragment_events, fragment_quality = fragment_findings(db, topology, segments)
    findings.extend(fragment_events)
    findings.extend(integrity_findings)
    group_downstream_findings(findings, topology)
    proxy_findings, proxy_leg_report = reset_checks(db, topology, segments, models, coverage)
    proxies.update(proxy_leg_report)
    findings.extend(proxy_findings)
    tls_findings, tls_notes = tls_checks(db, topology, segments, models, start, end)
    findings.extend(tls_findings)
    clock_json = {cid: m.json() for cid, m in models.items()}
    security_findings, security_report = security_checks(
        db, topology, coverage, timeseries, segments, clock_json
    )
    findings.extend(security_findings)
    udp_report = build_udp(db, topology, segments)
    rtp_report, rtp_findings = build_rtp(db, topology, segments, clock_json)
    findings.extend(rtp_findings)
    sip_report, sip_findings = build_sip(db, topology, segments, clock_json, rtp_findings)
    findings.extend(sip_findings)
    host_report, host_findings = host_path(db, topology, segments)
    findings.extend(host_findings)
    engine_topology = topology.model_copy(update={"start": start, "end": end})
    cycle_report = build_cycles(db, engine_topology, segments, host_report, onsets)
    findings.extend(finish_host_summary(db, topology, segments, host_report))
    primary_host = polish_findings(findings, segments, topology, onsets)
    classify_chronic_losses(db, topology, segments, findings, host_report, onsets, start, end)
    findings.extend(cycle_findings(db, topology, segments))
    delivery, delivery_findings = delivery_report(db, engine_topology, segments)
    findings.extend(delivery_findings)
    findings.extend(hold_release(db, segments))
    host_report["loss_groups"] = group_host_losses(findings, segments, topology)
    add_aggregates(db, engine_topology, segments, host_report, cycle_report, onsets, models, byte_active)
    incident = build_incident(db, topology, host_report, cycle_report, delivery, findings)
    flow_columns(db, findings, topology)
    return dict(
        timeseries=timeseries,
        sessions=sessions,
        onsets=onsets,
        microbursts=microbursts,
        integrity_findings=integrity_findings,
        integrity_notes=integrity_notes,
        fragment_quality=fragment_quality,
        proxy_findings=proxy_findings,
        tls_findings=tls_findings,
        tls_notes=tls_notes,
        security_findings=security_findings,
        security_report=security_report,
        udp_report=udp_report,
        rtp_report=rtp_report,
        sip_report=sip_report,
        host_report=host_report,
        host_findings=host_findings,
        cycle_report=cycle_report,
        primary_host=primary_host,
        delivery=delivery,
        incident=incident,
    )


def _assemble_report_dict(
    db,
    topology,
    models,
    coverage,
    quality,
    inventories,
    capture_names,
    suggestions,
    segments,
    findings,
    application_status,
    proxies,
    det,
    start,
    end,
    common_start,
    common_end,
    byte_active,
):
    total_findings = len(findings)
    order_scores = rows(
        db,
        """SELECT point,median(ttl) AS median_ttl,median(corrected) AS median_time,count(*) AS samples
        FROM obs o WHERE direction='forward' AND eligible AND EXISTS(
            SELECT 1 FROM obs b WHERE b.packet_key=o.packet_key AND b.point<>o.point AND b.eligible)
        GROUP BY point ORDER BY median_ttl DESC,median_time,point""",
    )
    auto_order = dict(
        points=[p["point"] for p in order_scores],
        scores=order_scores,
        reason="Suggestion from median TTL and corrected timestamps of shared packets. Your saved drawing remains authoritative.",
    )
    inconclusive_quality = any(
        q["unknown_direction"] == q["packets"] or q["excluded"] == q["packets"] for q in quality
    )
    return dict(
        schema_version=2,
        prefilter_excluded={
            capture_names[cid]: inv.get("prefilter_excluded", 0) for cid, inv in inventories.items()
        },
        analysis_scope=rows(db, "SELECT * FROM analysis_scope"),
        tunnel_points=tunnel_report(db),
        fragment_points=det["fragment_quality"],
        microbursts=det["microbursts"],
        sessions=det["sessions"],
        security=det["security_report"],
        udp=det["udp_report"],
        rtp=det["rtp_report"],
        sip=det["sip_report"],
        host_path=det["host_report"],
        cycles=det["cycle_report"],
        incident=det["incident"],
        delivery=det["delivery"],
        application_status=application_status,
        proxies=proxies,
        tls=det["tls_notes"],
        integrity_notes=det["integrity_notes"],
        f5=f5_report(db, topology),
        **device_report(db),
        sequence_translations=sequence_report(db),
        offload_points=range_notes(db) if byte_active else [],
        timeseries=det["timeseries"],
        onsets=det["onsets"],
        engine_version=__version__,
        generated_at=datetime.now(timezone.utc).isoformat(),
        verdict=_select_verdict(
            det["primary_host"],
            det["security_findings"],
            det["host_findings"],
            det["integrity_findings"],
            det["proxy_findings"],
            det["tls_findings"],
            findings,
            inconclusive_quality,
            segments,
        ),
        scope="Pilot diagnostics; stage clocks, host boundary delay and evidence-led path analysis",
        window=dict(start=start, end=end, common_start=common_start, common_end=common_end),
        clocks={cid: model.json() for cid, model in models.items()},
        coverage=coverage,
        quality=quality,
        auto_order_suggestion=auto_order,
        nat_suggestions=suggestions,
        segments=segments,
        findings=findings[:200],
        finding_count=total_findings,
        flow_count=db.execute("SELECT count(*) FROM flow_summary").fetchone()[0],
        limitations=list(LIMITATIONS),
    )


def analyze(project, topology: Topology | dict, progress=None, cancel=None):
    from ..delivery import prepare_delivery
    from ..host_path import lead_degradation

    topology = topology if isinstance(topology, Topology) else Topology.model_validate(topology)
    if len(topology.forward) < 2:
        drops = [p.id for p in topology.points if p.vendor == "paloalto" and p.vendor_stage == "drop"]
        if not drops:
            raise ValueError("Connect at least two capture points in a forward path")
        if not topology.forward:
            topology = topology.model_copy(update={"forward": [drops[0]]})
    progress = progress or (lambda **kw: None)
    with project.connect() as db:
        db.execute("SET preserve_insertion_order=false")
        project.set(db, "report", None)
        progress(state="matching")
        suggestions = prepare(db, topology, project, cancel)
        application_status = index_applications(project, db, topology, cancel, progress)
        progress(state="aligning clocks")
        models = align(db, topology)
        match_occurrences(db, topology)
        link_modified_payloads(db, topology, models)
        link_tcp_sessions(db, topology)
        propagate_translation_unknown(db)
        byte_active = prepare_byte_ranges(db, topology)
        prepare_delivery(db, topology)
        prepare_flow_filters(db)
        proxies = correlate(db, topology, models, application_status)
        add_dwell(db, topology, models, proxies)
        for suggestion in suggestions:
            suggestion["evidence"] = evidence(
                db,
                "(o.point=? AND o.frame=?) OR (o.point=? AND o.frame=?)",
                [suggestion["point_a"], suggestion["frame_a"], suggestion["point_b"], suggestion["frame_b"]],
            )
        points = {p.id: p for p in topology.points}
        coverage = rows(
            db,
            'SELECT point,min(corrected) AS start,max(corrected) AS "end",count(*) AS packets FROM obs WHERE point IN (SELECT unnest(?::VARCHAR[])) GROUP BY point',
            [list(set(topology.forward + topology.reverse))],
        )
        known = all(x["start"] is not None for x in coverage) and len(coverage) == len(
            set(topology.forward + topology.reverse)
        )
        common_start = max(x["start"] for x in coverage) if known else None
        common_end = min(x["end"] for x in coverage) if known else None
        if common_start is not None and common_start >= common_end:
            common_start = common_end = None
        start = topology.start if topology.start is not None else common_start
        end = topology.end if topology.end is not None else common_end
        db.execute("""CREATE OR REPLACE TABLE events (
            id VARCHAR, point_a VARCHAR,point_b VARCHAR,direction VARCHAR,kind VARCHAR,reason VARCHAR,
            packet_key VARCHAR,flow VARCHAR,ts DOUBLE,recovery_ms DOUBLE,recovery_key VARCHAR,
            support_key VARCHAR,impact_ms DOUBLE,is_data BOOLEAN,missing_bytes BIGINT,byte_ranges VARCHAR)""")
        inventories = {
            cid: json.loads(inv) for cid, inv in db.execute("SELECT id,inventory FROM captures").fetchall()
        }
        has_device_proofs = prepare_proofs(db, topology, start, end)
        progress(state="classifying")
        segments, findings = build_segments(
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
        )
        progress(state="summarizing")
        if has_device_proofs:
            add_unplaced(db, topology, segments, findings)
        quality, inventories, capture_names = build_flow_summary_and_quality(db, points, byte_active)
        det = _run_secondary_detectors(
            db,
            topology,
            points,
            segments,
            coverage,
            models,
            findings,
            proxies,
            start,
            end,
            common_start,
            common_end,
            byte_active,
            progress,
        )
        report = _assemble_report_dict(
            db,
            topology,
            models,
            coverage,
            quality,
            inventories,
            capture_names,
            suggestions,
            segments,
            findings,
            application_status,
            proxies,
            det,
            start,
            end,
            common_start,
            common_end,
            byte_active,
        )
        lead_degradation(report, findings, segments)
        project.set(db, "topology", topology.model_dump())
        project.set(db, "export_findings", findings)
        project.set(db, "report", report)
        return report
