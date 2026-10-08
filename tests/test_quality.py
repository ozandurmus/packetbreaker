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
