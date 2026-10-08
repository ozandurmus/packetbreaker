from packetbreaker.analysis import analyze


def test_low_eligible_ratio_never_claims_zero_loss(scenarios):
    project, _, topology, _ = scenarios("healthy", rounds=31)
    with project.connect() as db:
        db.execute("UPDATE packets SET unsupported='unsupported_test_transport' WHERE frame%4=0")
    report = analyze(project, topology)
    assert report["verdict"] == "Inconclusive"
    assert all(s["loss_percent"] is None for s in report["segments"])
    assert all(s["eligible_ratio"] < 0.9 for s in report["segments"])
    assert all("unsupported_test_transport" in s["excluded_counts"] for s in report["segments"])
    assert all(s["reason"].startswith("Insufficient matchable packets (") for s in report["segments"])
    allowed = analyze(project, {**topology, "min_eligible_ratio": 0.5})
    assert all(s["loss_percent"] == 0 for s in allowed["segments"])


def test_span_exclusions_are_reported_separately(scenarios):
    _, _, _, report = scenarios("duplicate", rounds=25)
    degraded = [s for s in report["segments"] if s["eligible_ratio"] < 0.9]
    assert degraded
    assert all(s["excluded_counts"].get("span_duplicate", 0) > 0 for s in degraded)
    assert all(s["loss_percent"] is None for s in degraded)
    assert report["verdict"] == "Inconclusive"


def test_source_cidr_filter_uses_distinct_address_lookup(scenarios):
    project, _, topology, baseline = scenarios("healthy", rounds=18)
    topology = {
        **topology,
        "points": [{**p, "source_cidr": "10.0.0.0/8"} if p["id"] == "p0" else p for p in topology["points"]],
        "clock_overrides": {
            cid: {"offset_ms": m["offset"] * 1000, "drift_ppm": m["drift_ppm"]}
            for cid, m in baseline["clocks"].items()
        },
    }
    analyze(project, topology)
    with project.connect() as db:
        assert (
            db.execute("SELECT count(*) FROM obs WHERE point='p0' AND src NOT LIKE '10.%'").fetchone()[0] == 0
        )
        assert (
            db.execute("SELECT count(*) FROM obs WHERE point='p0' AND direction='forward'").fetchone()[0] > 0
        )


def test_unlearned_nat_remains_unknown_even_with_known_clocks(scenarios):
    project, truth, topology, _ = scenarios("nat", rounds=1)
    topology = {
        **topology,
        "clock_overrides": {
            p["capture_id"]: {"offset_ms": truth["offsets"][i] * 1000, "drift_ppm": truth["drifts_ppm"][i]}
            for i, p in enumerate(topology["points"])
        },
    }
    report = analyze(project, topology)
    nat = next(s for s in report["segments"] if s["id"] == "forward:p1:p2")
    assert nat["loss_percent"] is None
    assert nat["reason"] == "NAT mapping awaits confirmation"
    assert all(f["type"] == "unknown" for f in report["findings"])
