from copy import deepcopy
import pytest
from packetbreaker.topology import Topology


def test_byte_budget_is_per_work_unit_not_entire_capture(scenarios, clone_project, monkeypatch):
    import packetbreaker.byte_ranges as ranges

    source, _, topology, _ = scenarios("offload")
    project = clone_project(source)
    monkeypatch.setattr(ranges, "MAX_ATOMS", 10)
    from packetbreaker.analysis import analyze
    before = source.inventory()
    report = analyze(project, topology)
    assert report["findings"]
    with project.connect() as db:
        assert db.execute("SELECT sum(atoms) FROM byte_work_units").fetchone()[0] > 10
        assert db.execute("SELECT count(*) FROM byte_links").fetchone()[0] > 0
    assert len(before) == len(project.inventory())


def test_shared_clock_short_negative_transit_is_not_clock_failure(scenarios, clone_project):
    from packetbreaker.analysis import analyze

    source, _, topology, _ = scenarios("pilot", ip_id="zero")
    project = clone_project(source)
    topology = deepcopy(topology)
    topology["forward"] = ["b_rx", "b_tx", "host"]
    topology["reverse"] = ["host", "b_rx", "b_tx"]
    topology["points"] = [p for p in topology["points"] if p["id"] in topology["forward"]]
    report = analyze(project, topology)
    host_id = next(p["capture_id"] for p in topology["points"] if p["id"] == "host")
    assert report["clocks"][host_id]["samples"] > 0
    assert report["clocks"][host_id]["offset"] is not None
    assert report["host_path"]["items"]
    assert not any("Clock alignment unreliable" in (s["reason"] or "") for s in report["segments"])
