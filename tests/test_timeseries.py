from packetbreaker.analysis import analyze
from packetbreaker.timeseries import timeseries_page


def test_coverage_and_exact_bucket_rates(scenarios):
    project, truth, topology, _ = scenarios("healthy", rounds=30)
    start = truth["reference_epoch"]
    report = analyze(project, {**topology, "start": start - 3, "end": start + 17, "bucket_seconds": 2})
    data = timeseries_page(project)
    outside = [r for r in data["items"] if r["coverage"] == "not capturing"]
    assert outside and all(r[m] is None for r in outside for m in data["metrics"])
    # With an explicit wider interval the classifier is conservative; throughput remains observed.
    inside = next(
        r for r in data["items"] if r["segment"] == "forward:p0:p1" and r["coverage"] == "capturing"
    )
    with project.connect() as db:
        packets, bits = db.execute(
            "SELECT count(*),sum(wirelen)*8 FROM obs WHERE point='p0' AND direction='forward' AND corrected>=? AND corrected<?",
            [inside["start"], inside["end"]],
        ).fetchone()
        assert db.execute("SELECT count(*) FROM segment_buckets").fetchone()[0] == len(data["items"])
    assert inside["pps"] == packets / 2 and inside["throughput_bps"] == bits / 2
    assert report["timeseries"]["bucket_seconds"] == 2
    assert all(m["tooltip"] for m in data["metrics"].values())


def test_transient_unmatchability_is_not_zero_loss(scenarios):
    project, truth, topology, _ = scenarios("healthy", rounds=40)
    with project.connect() as db:
        cid = topology["points"][2]["capture_id"]
        start = truth["reference_epoch"] + 8 - 0.08
        db.execute(
            "UPDATE packets SET unsupported='unsupported_identity' WHERE capture_id=? AND ts>=? AND ts<?",
            [cid, start, start + 1],
        )
    report = analyze(project, topology)
    segment = next(s for s in report["segments"] if s["id"] == "forward:p1:p2")
    assert segment["eligible_ratio"] >= 0.9
    bucket = next(
        r for r in timeseries_page(project)["items"] if r["segment"] == segment["id"] and r["bucket"] == 8
    )
    assert bucket["loss_percent"] is None and bucket["latency_p95_ms"] is None
    assert "Insufficient matchable" in bucket["reason"]
