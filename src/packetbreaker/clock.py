"""Bidirectional minimum-delay envelopes; all offsets are estimates."""

from dataclasses import asdict, dataclass, field
from statistics import median


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
            upper, lower = min(fw), max(rv)
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
    upper, lower = min(fw), max(rv)
    if lower > upper + 1e-6:
        return ClockModel(
            epoch=epoch, samples=len(samples), reason="No feasible non-negative bidirectional delay envelope"
        )
    return ClockModel(
        offset=(upper + lower) / 2,
        drift=drift,
        epoch=epoch,
        uncertainty=max(0, (upper - lower) / 2),
        confidence="estimated",
        samples=len(samples),
        reason="Minimum-path symmetry assumed; path asymmetry is included in offset uncertainty"
        + ("; drift fitted" if drift else "; offset-only fit"),
    )
