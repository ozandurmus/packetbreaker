import pytest
from fastapi.testclient import TestClient
from packetbreaker.analysis import analyze, findings_page, flow_page, ladder
from packetbreaker.app import create_app
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


def test_loss_rates_and_brush_filters(scenarios):
    project, truth, topology, report = scenarios("onset_loss", ip_id="zero", loss_hop=1)
    onset = truth["onsets"][0]["time"]
    early = findings_page(project, onset - 6, onset)
    late = findings_page(project, onset, onset + 2)
    assert not early["items"] and late["items"]
    assert all(onset <= f["time_range"][0] < onset + 2 for f in late["items"])
    data = timeseries_page(project)
    bucket = next(r for r in data["items"] if r["segment"] == "forward:p1:p2" and r["start"] == onset)
    with project.connect() as db:
        n = db.execute(
            "SELECT count(*) FROM events WHERE point_a='p1' AND point_b='p2' AND kind='recovered_loss' AND ts>=? AND ts<?",
            [onset, onset + 1],
        ).fetchone()[0]
    assert bucket["recovered_loss_percent"] == pytest.approx(100 * n / bucket["eligible_packets"])
    assert flow_page(project, start=onset + 100, end=onset + 101)["total"] == 0
    flow = flow_page(project, start=onset, end=onset + 2)["items"][0]["flow"]
    view = ladder(project, flow, start=onset, end=onset + 2)
    assert view["items"] and all(onset <= p["ts"] < onset + 2 for p in view["items"])
    assert view["total"] < ladder(project, flow, limit=1)["total"]
    with TestClient(create_app(project.path), base_url="http://127.0.0.1") as client:
        assert client.get("/api/timeseries").json()["items"]
        assert client.get(f"/api/findings?start={onset - 6}&end={onset}").json()["items"] == []
        assert client.get(f"/api/flows?start={onset + 100}&end={onset + 101}").json()["total"] == 0
        assert (
            client.get(f"/api/flows/{flow}/ladder?limit=1&start={onset}&end={onset + 2}").json()["total"]
            == view["total"]
        )
        assert client.get("/api/flows?start=nan").status_code == 422


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


def test_unaligned_clock_coverage_is_unknown_not_not_capturing(scenarios):
    project, _, topology, _ = scenarios("healthy", rounds=16)
    with project.connect() as db:
        db.execute("DELETE FROM packets WHERE sport=443")
    analyze(project, topology)
    data = timeseries_page(project)
    assert data["items"]
    assert all(r["coverage"] == "unknown coverage" for r in data["items"])
    assert all(r[m] is None for r in data["items"] for m in data["metrics"])


def test_handshake_retries_do_not_count_as_new_failed_connections():
    import duckdb
    from packetbreaker.timeseries import event_buckets

    with duckdb.connect() as db:
        db.execute(
            "CREATE TABLE events(point_a VARCHAR,point_b VARCHAR,direction VARCHAR,kind VARCHAR,flow VARCHAR,ts DOUBLE)"
        )
        db.executemany(
            "INSERT INTO events VALUES ('a','b','forward','handshake_blocked',?,?)",
            [("one", 8), ("one", 11), ("one", 14), ("two", 17)],
        )
        buckets = event_buckets(db, 0, 1, "a", "b", "forward")
    assert sum(r["n"] for r in buckets) == 4
    assert sum(r["flows"] for r in buckets) == 2
    assert {r["bucket"] for r in buckets if r["flows"]} == {8, 17}
