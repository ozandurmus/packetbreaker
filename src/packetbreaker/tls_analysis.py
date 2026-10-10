"""Visible TLS chain comparisons with conservative device attribution."""

import json
from .store import rows
from .proxy_analysis import uncertainty
from .application_evidence import frame_refs, frame_lookup, finding


def tls_checks(db, topology, segments, models, start, end):
    if not db.execute("SELECT count(*) FROM proxy_requests WHERE kind='tls_setup'").fetchone()[0]:
        return [], []
    facts = rows(
        db,
        """SELECT r.*,try_cast(json_extract_string(s.metadata,'$.version') AS INTEGER) AS version,
        json_extract(c.metadata,'$.chain') AS chain,c.frame AS cert_frame
        FROM proxy_requests r LEFT JOIN LATERAL (SELECT p.* FROM app_protocol p JOIN obs e ON e.point=p.point AND e.frame=p.frame WHERE p.point=r.point AND e.canon<>r.canon
            AND p.protocol_stream=r.protocol_stream AND p.kind='tls_server' AND p.frame>=r.last_frame
            AND NOT EXISTS(SELECT 1 FROM app_protocol n WHERE n.point=r.point AND n.protocol_stream=r.protocol_stream AND n.kind='tls_setup' AND n.frame>r.last_frame AND n.frame<p.frame)
            ORDER BY p.frame LIMIT 1) s ON true
        LEFT JOIN LATERAL (SELECT p.* FROM app_protocol p JOIN obs e ON e.point=p.point AND e.frame=p.frame WHERE p.point=r.point AND e.canon<>r.canon AND p.protocol_stream=r.protocol_stream
            AND p.kind='tls_certificate' AND p.frame>=s.frame AND e.eligible
            AND NOT EXISTS(SELECT 1 FROM app_protocol n WHERE n.point=r.point AND n.protocol_stream=r.protocol_stream AND n.kind='tls_setup' AND n.frame>r.last_frame AND n.frame<p.frame)
            ORDER BY p.frame LIMIT 1) c ON true WHERE r.kind='tls_setup' """,
    )
    reference_lookup = frame_lookup(
        db, {(r["point"], r[k]) for r in facts for k in ("last_frame", "cert_frame") if r.get(k)}
    )

    def refs(packets):
        return frame_refs(db, packets, reference_lookup)

    points = {p.id: p for p in topology.points}
    byid = {r["id"]: r for r in facts}
    notes = []
    findings = []

    def key(r):
        return r["flow"], r["start_seq"], r["sni"]

    inconsistent = set()
    for r in facts:
        r["chain"] = json.loads(r["chain"]) if r["chain"] else []
        r["fingerprints"] = tuple(c["fingerprint"] for c in r["chain"])
        r["unknown"] = (
            "TLS 1.3 certificates encrypted; interception unknown"
            if r["version"] == 0x304
            else "Certificate chain absent/incomplete; interception unknown"
            if not r["chain"] or any(not c.get("subject") or not c.get("issuer") for c in r["chain"])
            else r["reason"]
            if not r["ready"]
            else None
        )
        if r["unknown"]:
            notes.append(
                dict(
                    status="unknown",
                    point=r["point"],
                    sni=r["sni"],
                    reason=r["unknown"],
                    evidence=refs([dict(point=r["point"], frame=r["last_frame"])]),
                )
            )
    groups = {}
    by_point = {}
    by_point_key = {}
    for r in facts:
        groups.setdefault(key(r), []).append(r)
        by_point.setdefault(r["point"], []).append(r)
        by_point_key.setdefault((r["point"], key(r)), []).append(r)
    for k, group in groups.items():
        if len({r["fingerprints"] for r in group if r["fingerprints"]}) > 1:
            inconsistent.add(k)

    def compare(a, b, segment, proxy=False):
        if a is None or b is None:
            return
        if (
            a["start"] is None
            or start is not None
            and a["start"] < start
            or end is not None
            and a["start"] > end
        ):
            return
        reason = a["unknown"] or b["unknown"]
        if uncertainty(models, points[a["point"]], points[b["point"]]) is None:
            reason = (
                reason or "Clock evidence insufficient to associate certificate handshakes at these points"
            )
        if proxy and (key(a) in inconsistent or key(b) in inconsistent):
            reason = reason or "Certificate observations disagree inside a TCP leg; proxy attribution unknown"
        if reason:
            notes.append(
                dict(
                    status="unknown",
                    device=segment.get("device"),
                    sni=a["sni"],
                    reason=reason,
                    evidence=frame_refs(
                        db, [dict(point=r["point"], frame=r["cert_frame"] or r["last_frame"]) for r in (a, b)]
                    ),
                )
            )
            return
        packets = [dict(point=r["point"], frame=r["cert_frame"], corrected=r["response"]) for r in (a, b)]
        if a["fingerprints"] == b["fingerprints"]:
            notes.append(
                dict(
                    status="consistent",
                    device=segment.get("device"),
                    sni=a["sni"],
                    reason="Observed certificate chains agree for this visible handshake",
                    evidence=refs(packets),
                )
            )
            return
        declared = any(
            points[p].payload_transform == "ssl_inspection" for p in (segment["point_a"], segment["point_b"])
        )
        device = segment.get("device")
        summary = (
            f"TLS intercepted by {device} (not declared)"
            if device
            else f"Certificate chain changed on link between {points[a['point']].label} and {points[b['point']].label}; device unknown"
        )
        if declared:
            summary = f"Certificate chain changed at declared SSL inspection device {device}"
        findings.append(
            finding(
                db,
                segment,
                "tls_interception",
                summary,
                packets,
                dict(
                    sni=a["sni"],
                    before_chain=a["chain"],
                    after_chain=b["chain"],
                    declared=declared,
                    uncertainty_ms=None
                    if uncertainty(models, points[a["point"]], points[b["point"]]) is None
                    else uncertainty(models, points[a["point"]], points[b["point"]]) * 1000,
                ),
                supported=bool(device),
                severity="quality" if declared else "high",
                lookup=reference_lookup,
            )
        )

    for segment in segments:
        if segment["direction"] != "forward":
            continue
        a, b = segment["point_a"], segment["point_b"]
        if points[a].device == points[b].device and "full_proxy" in (
            points[a].translation,
            points[b].translation,
        ):
            continue
        for ra in by_point.get(a, []):
            matches = by_point_key.get((b, key(ra)), [])
            if len(matches) == 1:
                compare(ra, matches[0], segment)
    for device, cid, sid in db.execute(
        "SELECT device,client_id,server_id FROM proxy_pairs WHERE status='matched'"
    ).fetchall():
        a, b = byid.get(cid), byid.get(sid)
        if not a or not b:
            continue
        segment = next(
            (
                s
                for s in segments
                if s["direction"] == "forward" and s["point_a"] == a["point"] and s["point_b"] == b["point"]
            ),
            None,
        )
        if segment:
            compare(a, b, segment, True)
    return findings, notes
