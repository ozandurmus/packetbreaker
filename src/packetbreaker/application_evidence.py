"""Evidence-backed TLS chain changes and cross-leg reset provenance."""

from .evidence import evidence


def frame_lookup(db, keys):
    if not keys:
        return {}
    data = evidence(
        db,
        "o.point||':'||o.frame::VARCHAR IN (SELECT unnest(?::VARCHAR[]))",
        [[f"{p}:{f}" for p, f in keys]],
        limit=len(keys),
        _expand_ranges=False,
    )
    return {(r["point"], r["frame"]): r for r in data}


def frame_refs(db, packets, lookup=None):
    keys = sorted({(p["point"], p["frame"]) for p in packets if p and p.get("frame")})
    if lookup is not None:
        return [lookup[k] for k in keys if k in lookup]
    return (
        evidence(
            db,
            " OR ".join("(o.point=? AND o.frame=?)" for _ in keys),
            [v for k in keys for v in k],
            limit=len(keys),
            _expand_ranges=False,
        )
        if keys
        else []
    )


def finding(db, segment, kind, summary, packets, metrics, supported=True, severity="high", lookup=None):
    stamps = [p.get("corrected") for p in packets if p and p.get("corrected") is not None]
    return dict(
        id=f"proxy:{kind}:{segment['id']}:{packets[0]['frame']}",
        type=kind,
        hop=segment["id"],
        device=segment.get("device"),
        direction=segment["direction"],
        time_range=[min(stamps), max(stamps)] if stamps else [None, None],
        severity=severity if supported else "unknown",
        confidence="supported" if supported else "unknown",
        summary=summary,
        tooltip="Evidence describes observed request/certificate/reset events. Missing capture coverage and ambiguous candidates cannot establish origin.",
        metrics={"count": 1, **metrics},
        evidence=frame_refs(db, packets, lookup),
        cause="unknown",
        clock_caveat="Clock-corrected estimates; see uncertainty in metrics.",
    )
