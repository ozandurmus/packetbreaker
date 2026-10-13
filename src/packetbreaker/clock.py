"""Bidirectional minimum-delay envelopes; all offsets are estimates."""

from dataclasses import asdict, dataclass, field
from statistics import median, quantiles


@dataclass
class ClockModel:
    offset: float | None = None
    drift: float = 0.0
    epoch: float = 0.0
    uncertainty: float | None = None
    confidence: str = "unknown"
    reason: str = "Bidirectional matched packets are required"
    samples: int = 0
    evidence: list = field(default_factory=list)
    domain: str | None = None
    source_domain: str | None = None
    timestamp_jitter: float = 0.0

    def correct(self, timestamp):
        if self.offset is None:
            return None
        return self.epoch + (timestamp - self.epoch - self.offset) / (1 + self.drift)

    def json(self):
        return {**asdict(self), "drift_ppm": self.drift * 1e6}


def fit_clock(samples):
    """Samples are (reference_time, other_time, forward_bool), already bounded."""
    if not samples:
        return ClockModel()
    epoch = min(x[0] for x in samples)
    span = max(x[0] for x in samples) - epoch
    forward = [b - a for a, b, f in samples if f]
    reverse = [b - a for a, b, f in samples if not f]
    if min(len(forward), len(reverse)) < 3:
        return ClockModel(epoch=epoch, samples=len(samples))
    buckets = {}
    for a, b, f in samples:
        bucket = min(19, int((a - epoch) / max(span, 0.001) * 20))
        buckets.setdefault(bucket, []).append((a, b - a, f))
    envelopes = []
    for points in buckets.values():
        fw = [d for _, d, f in points if f]
        rv = [d for _, d, f in points if not f]
        if len(fw) >= 2 and len(rv) >= 2:
            upper = quantiles(fw, n=100, method="inclusive")[0]
            lower = quantiles(rv, n=100, method="inclusive")[-1]
            # Long captures can have crossing raw bounds before drift is removed.
            envelopes.append((median([a for a, _, _ in points]) - epoch, (upper + lower) / 2))
    drift = 0.0
    if span >= 10 and len(envelopes) >= 4:
        slopes = [
            (b[1] - a[1]) / (b[0] - a[0])
            for i, a in enumerate(envelopes)
            for b in envelopes[i + 1 :]
            if abs(b[0] - a[0]) > span / 5
        ]
        if slopes:
            drift = median(slopes)
    if abs(drift) > 0.005:
        return ClockModel(epoch=epoch, samples=len(samples), reason="Estimated drift exceeds 5000 ppm")
    fw = [b - a - drift * (a - epoch) for a, b, f in samples if f]
    rv = [b - a - drift * (a - epoch) for a, b, f in samples if not f]
    upper = quantiles(fw, n=100, method="inclusive")[0]
    lower = quantiles(rv, n=100, method="inclusive")[-1]
    # Pool detrended samples: per-bin estimates undercount correlated timestamp
    # jitter when many copies share the same timestamp error.
    fq = quantiles(fw, n=100, method="inclusive")
    rq = quantiles(rv, n=100, method="inclusive")
    jitter = min(0.002, median([3 * (fq[24] - fq[0]), 3 * (rq[98] - rq[74])]))
    if lower > upper + max(2 * jitter, 1e-6):
        return ClockModel(
            epoch=epoch,
            samples=len(samples),
            timestamp_jitter=jitter,
            reason="No feasible jitter-bounded bidirectional percentile envelope",
        )
    return ClockModel(
        offset=(upper + lower) / 2,
        drift=drift,
        epoch=epoch,
        uncertainty=abs(upper - lower) / 2 + jitter,
        confidence="estimated",
        samples=len(samples),
        timestamp_jitter=jitter,
        reason="Bidirectional p1/p99 delay envelope; minimum-path symmetry assumed; timestamp jitter and envelope infeasibility are included in uncertainty"
        + ("; drift fitted" if drift else "; offset-only fit"),
    )


def infer_shared_clock(samples):
    """Near-zero stable, positive transit in both directional orders is bounded evidence, not proof."""
    from statistics import quantiles

    if not samples or max(a for a, _, _ in samples) - min(a for a, _, _ in samples) < 5:
        return None
    groups = [[b - a if f else a - b for a, b, f in samples if f == direction] for direction in (True, False)]
    if min(map(len, groups)) < 8:
        return None
    centers = [median(g) for g in groups]
    if min(centers) < 0 or max(centers) > 0.00025:
        return None
    residuals = [abs(x) for g in groups for x in g]
    bound = quantiles(residuals, n=20, method="inclusive")[-1]
    return bound if bound <= 0.0005 else None


def transit_quality(stats, tolerance_ms):
    tolerance_ms = max(0.001, tolerance_ms)
    systematic = bool(stats.get("p50_ms") is not None and stats["p50_ms"] < -tolerance_ms)
    outliers = stats.get("negative_outliers") or 0
    return dict(
        systematic_negative=systematic,
        latency_uncertainty_ms=tolerance_ms,
        quality_notes=(
            [
                f"{outliers} negative transit outlier(s) exceed ±{tolerance_ms:.3f} ms timestamp/offset uncertainty; retained as quality evidence"
            ]
            if outliers
            else []
        ),
    )
