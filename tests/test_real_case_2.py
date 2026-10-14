from copy import deepcopy
import pytest
from packetbreaker.topology import Topology


def test_byte_budget_is_per_work_unit_not_entire_capture(scenarios, clone_project, monkeypatch):
    import packetbreaker.byte_ranges as ranges

    source, _, topology, _ = scenarios("offload")
    project = clone_project(source)
    monkeypatch.setattr(ranges, "MAX_ATOMS", 10, raising=False)
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


@pytest.mark.parametrize("missing_bytes", [16, 84])
def test_small_missing_ranges_are_not_mtu(scenarios, clone_project, missing_bytes):
    from packetbreaker.integrity import Checks
    from packetbreaker.clock import ClockModel

    source, _, topology, report = scenarios("integrity_multi", fault_location="all", ip_id="zero", ipv6=False)
    project = clone_project(source)
    models = {
        k: ClockModel(**{x: y for x, y in v.items() if x != "drift_ppm"}) for k, v in report["clocks"].items()
    }
    with project.connect() as db:
        db.execute("UPDATE events SET missing_bytes=?", [missing_bytes])
        checks = Checks(
            db, Topology.model_validate(topology), report["segments"], report["coverage"], models, None, None
        )
        checks.mtu()
        assert not any(f["type"] == "mtu_black_hole" for f in checks.findings)


def test_cycles_exports_and_short_shared_host(scenarios, clone_project):
    import io
    import zipfile
    import xml.etree.ElementTree as ET
    from packetbreaker.analysis import analyze
    from packetbreaker.engine_export import export_tables

    source, truth, topology, report = scenarios("pilot", ip_id="zero")
    cycle = report["cycles"]
    assert cycle["top"] and all(r["evidence"] for r in cycle["top"])
    assert {r["component"] for r in cycle["pairs"]} == {"RX", "TX"}
    assert max(r["local_turnaround_p95_ms"] for r in cycle["host_local"]) < 1
    assert {"before", "event", "recovery"} <= {r["period"] for r in cycle["periods"]}
    for format in ("csv", "xlsx"):
        with zipfile.ZipFile(io.BytesIO(export_tables(source, format))) as archive:
            assert len(archive.namelist()) >= 6
            if format == "xlsx":
                for name in archive.namelist():
                    if name.endswith(".xml"):
                        ET.fromstring(archive.read(name))
            else:
                assert "top_cycles.csv" in archive.namelist()
    project = clone_project(source)
    with project.connect() as db:
        host = next(p["capture_id"] for p in topology["points"] if p["id"] == "host")
        db.execute("UPDATE packets SET ts=ts-.04 WHERE capture_id=?", [host])
    changed = deepcopy(topology)
    for p in changed["points"]:
        p["clock_domain"] = "one-appliance"
    changed.update(start=truth["start"] + 4, end=truth["start"] + 7)
    short = analyze(project, changed)
    assert not any("Clock alignment unreliable" in (s["reason"] or "") for s in short["segments"])
    assert short["host_path"]["items"] and "Delay occurs between" in short["verdict"]


@pytest.mark.slow  # 50 concurrent offloaded flows across six real-tshark captures, including an unfiltered host.
def test_fifty_flow_real_case_replica(tmp_path, tshark):
    from pathlib import Path
    from packetbreaker.pilot_synthetic import make_pilot
    from packetbreaker.batch_ingest import ingest_many
    from packetbreaker.store import Project
    from packetbreaker.synthetic import bind_capture_ids
    from packetbreaker.analysis import analyze
    from packetbreaker.topology_suggest import suggest_topology, assemble_topology

    truth, topology = make_pilot(tmp_path / "wire", flows=50, real_case=True, ip_id="increment")
    project = Project(tmp_path / "project")
    ids = ingest_many(project, truth["files"], tshark=tshark, workers=4)
    bind_capture_ids(topology, {Path(f).name: c for f, c in zip(truth["files"], ids)})
    assembled = assemble_topology(project)
    assert not assembled["ambiguous"]
    assert assembled["badge"] == "Suggested topology — review & confirm"
    assert assembled["topology"]["forward"] == topology["forward"]
    assert assembled["topology"]["reverse"] == topology["reverse"]
    assert assembled["topology"]["client_cidrs"] == topology["client_cidrs"]
    report = analyze(project, assembled["topology"])
    assert report["flow_count"] == 50
    assert report["cycles"]["host_local"]
    assert all(r["local_turnaround_p95_ms"] < 1 for r in report["cycles"]["host_local"])
    holds = [f for f in report["findings"] if f["type"] == "hold_release"]
    assert holds and all(f["hop"] == "forward:mirror:host" for f in holds)
    reverse = [s for s in report["delivery"]["series"] if s["point_a"] == "host" and s["point_b"] == "mirror"]
    assert sum(s["dropped"] for s in reverse) == 4
    assert sum(s["delayed"] for s in reverse) == 0
    assert all(
        abs(i["window"]["start"] - truth["start"]) <= 1 and abs(i["window"]["end"] - truth["end"]) <= 1
        for i in report["host_path"]["items"]
    )
    assert report["verdict"].startswith("Delay occurs between")
    assert all(max(f["metrics"]["receive_spacing_ms"]) < 10 for f in holds)
    assert not any(
        f["type"] in ("mtu_black_hole", "asymmetric_routing", "ttl_path") and f["severity"] == "high"
        for f in report["findings"]
    )
    suggestions = suggest_topology(project)
    assert suggestions["requires_confirmation"]
    assert {"stage_pair", "shared_clock", "host_capture"} <= {s["kind"] for s in suggestions["items"]}
    with project.connect() as db:
        assert db.execute("SELECT count(*) FROM byte_work_units").fetchone()[0] == 50
        assert (
            db.execute("SELECT count(*) FROM cycle_flow_ports WHERE point='host' AND stalled=0").fetchone()[0]
            >= 49
        )


@pytest.mark.parametrize("ip_id,ipv6", [("zero", False), ("constant", True)])
@pytest.mark.parametrize(
    "fault,hop",
    [("a_tx", "forward:a_rx:a_tx"), ("b_tx", "forward:b_rx:b_tx"), ("mirror", "forward:b_tx:mirror")],
)
@pytest.mark.slow  # Six real-tshark device/link and ID/IP-family replica cells; fast unit guards remain below.
def test_hold_release_exact_device_or_link(tmp_path, tshark, ip_id, ipv6, fault, hop):
    from pathlib import Path
    from packetbreaker.pilot_synthetic import make_pilot
    from packetbreaker.store import Project
    from packetbreaker.batch_ingest import ingest_many
    from packetbreaker.synthetic import bind_capture_ids
    from packetbreaker.analysis import analyze

    truth, topology = make_pilot(
        tmp_path / "wire", real_case=True, flows=2, ip_id=ip_id, ipv6=ipv6, fault=fault
    )
    project = Project(tmp_path / "project")
    ids = ingest_many(project, truth["files"], tshark=tshark, workers=4)
    bind_capture_ids(topology, {Path(f).name: c for f, c in zip(truth["files"], ids)})
    report = analyze(project, topology)
    found = [f for f in report["findings"] if f["type"] == "hold_release"]
    assert found and all(f["hop"] == hop for f in found)
    assert all(
        f["evidence"] and f["metrics"]["wire_spacing_ms"] and f["metrics"]["receive_spacing_ms"]
        for f in found
    )
    assert not any(f["hop"] == "forward:mirror:host" for f in found)


def test_capture_miss_and_healthy_patterns_do_not_become_hold_or_drop(scenarios):
    _, _, _, report = scenarios("pilot_healthy", ip_id="zero")
    assert not any(f["type"] == "hold_release" for f in report["findings"])
    assert all(r["dropped"] == 0 and r["delayed"] == 0 for r in report["delivery"]["series"])
    assert all(r["stalled"] == 0 for r in report["cycles"]["flow_ports"])


def test_id_change_without_upstream_retry_is_unknown_not_drop(scenarios, clone_project):
    from packetbreaker.byte_ranges import make_matches_view
    from packetbreaker.delivery import prepare_delivery

    source, _, topology, _ = scenarios("pilot", ip_id="zero")
    project = clone_project(source)
    with project.connect() as db:
        db.execute("UPDATE obs SET ipid=(seq//800)%5000")
        frame = db.execute(
            "SELECT b.frame FROM byte_links m JOIN obs a ON a.point=m.point_a AND a.frame=m.frame_a JOIN obs b ON b.point=m.point_b AND b.frame=m.frame_b WHERE m.point_a='mirror' AND m.point_b='host' AND a.seq=b.seq AND m.time_b-m.time_a>.1 LIMIT 1"
        ).fetchone()[0]
        db.execute("UPDATE obs SET ipid=ipid+5000 WHERE point='host' AND frame=?", [frame])
        make_matches_view(db, True)
        prepare_delivery(db, Topology.model_validate(topology))
        assert db.execute(
            "SELECT DISTINCT status FROM delivery_rejections WHERE point_a='mirror' AND point_b='host' AND frame_b=?",
            [frame],
        ).fetchall() == [("unknown",)]
        assert not db.execute(
            "SELECT count(*) FROM observation_matches m JOIN obs b ON b.point=m.point_b AND b.packet_key=m.key_b WHERE m.point_a='mirror' AND m.point_b='host' AND b.frame=?",
            [frame],
        ).fetchone()[0]
