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


def test_healthy_checker_nat_pool_and_endpoint_closure_are_not_scans(scenarios):
    _, truth, _, report = scenarios("security", ip_id="zero", fault_location="FW2")
    scans = [f for f in report["findings"] if f["type"] == "scan_like_fanout"]
    assert scans
    excluded = {p["src"] for group in (1, 2, 5, 6, 7, 8) for p in truth["populations"][group]}
    assert all(f["metrics"]["source"] not in excluded for f in scans)
    assert all(f["metrics"]["source"] == truth["populations"][4][0]["src"] for f in scans)
    assert all(f["summary"].startswith("scan-like fan-out (heuristic)") for f in scans)


def test_capture_miss_does_not_turn_healthy_fanout_into_scan(scenarios, clone_project):
    shared, truth, topology, report = scenarios("security", ip_id="zero", fault_location="FW2")
    project = clone_project(shared)
    with project.connect() as db:
        # Simulate missing final ACKs at one point, while healthy completion remains downstream.
        src = truth["populations"][5][0]["src"]
        db.execute(
            "UPDATE session_lifecycle SET established=NULL,synack=NULL WHERE point='fw1_in' AND src=?", [src]
        )
        findings, _ = security_checks(
            db,
            Topology(**topology),
            report["coverage"],
            report["timeseries"],
            report["segments"],
            report["clocks"],
        )
    assert not any(
        f["type"] == "scan_like_fanout" and f["metrics"]["source"] == src and f["confidence"] == "supported"
        for f in findings
    )
