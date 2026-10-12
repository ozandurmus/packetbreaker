from packetbreaker.security import security_checks
from packetbreaker.topology import Topology


def test_flash_crowd_is_not_flood(scenarios):
    _, truth, _, report = scenarios("security", ip_id="zero", fault_location="FW2")
    floods = [f for f in report["findings"] if f["type"] == "syn_flood_like"]
    assert floods
    assert all(f["time_range"][0] >= truth["base"] + 12 for f in floods)
    assert all(f["summary"].startswith("SYN-flood-like pattern (heuristic)") for f in floods)
    assert all(f["metrics"]["syn_rate"] >= f["metrics"]["thresholds"]["syn_rate"] for f in floods)


def test_missing_coverage_cannot_support_flood(scenarios, clone_project):
    shared, _, topology, report = scenarios("security", ip_id="zero", fault_location="FW2")
    project = clone_project(shared)
    with project.connect() as db:
        findings, _ = security_checks(
            db, Topology(**topology), [], report["timeseries"], report["segments"], report["clocks"]
        )
    assert not any(f["type"] == "syn_flood_like" and f["confidence"] == "supported" for f in findings)
