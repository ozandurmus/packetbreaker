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
