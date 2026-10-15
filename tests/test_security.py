import pytest
from packetbreaker.analysis import findings_page
from packetbreaker.export import FindingsExport, export_data, html_report
from packetbreaker.security import security_checks
from packetbreaker.topology import Topology


def test_flash_crowd_is_not_flood(scenarios):
    project, truth, _, report = scenarios("security", ip_id="zero", fault_location="FW2")
    with project.connect() as db:
        assert (
            db.execute("SELECT half_open FROM session_buckets WHERE point='client' AND bucket=16").fetchone()[
                0
            ]
            == 260
        )
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


def test_pressure_never_blames_upstream_device(scenarios):
    _, truth, _, report = scenarios("security", ip_id="zero", fault_location="FW2")
    pressure = [
        f
        for f in report["findings"]
        if f["type"] == "session_table_pressure" and f["confidence"] == "supported"
    ]
    assert pressure and {f["device"] for f in pressure} == {"FW2"}
    assert all(
        f["summary"] == "possible session-table pressure at FW2 (corroboration, not proof)" for f in pressure
    )
    assert all(f["metrics"]["drop_onset"] >= truth["base"] + 12 and f["evidence"] for f in pressure)


def test_generic_disappearance_cannot_prove_session_pressure(scenarios, clone_project):
    shared, _, topology, report = scenarios("security", ip_id="zero", fault_location="FW2")
    project = clone_project(shared)
    with project.connect() as db:
        db.execute("DELETE FROM device_proofs")
        db.execute("UPDATE events SET kind='handshake_blocked' WHERE kind='confirmed_device_drop'")
        findings, _ = security_checks(
            db,
            Topology(**topology),
            report["coverage"],
            report["timeseries"],
            report["segments"],
            report["clocks"],
        )
    pressure = [f for f in findings if f["type"] == "session_table_pressure"]
    assert pressure and all(f["confidence"] == "unknown" for f in pressure)
    assert all("device evidence" in f["summary"] for f in pressure)


@pytest.mark.parametrize("fault_location", ["FW1", "FW2", "link"])
@pytest.mark.parametrize("ip_id,ipv6", [("zero", False), ("constant", False), ("zero", True)])
def test_exact_security_location_and_variants(scenarios, fault_location, ip_id, ipv6):
    project, truth, topology, report = scenarios(
        "security", fault_location=fault_location, ip_id=ip_id, ipv6=ipv6, rounds=20
    )
    supported = [
        f
        for f in report["findings"]
        if f["type"] == "session_table_pressure" and f["confidence"] == "supported"
    ]
    if fault_location == "link":
        assert supported == []
        unknown = [f for f in report["findings"] if f["type"] == "session_table_pressure"]
        assert unknown and {f["hop"] for f in unknown} == {"forward:fw1_out:fw2_in"}
        assert all(f.get("device") is None and f["confidence"] == "unknown" for f in unknown)
    else:
        assert supported and {f["device"] for f in supported} == {fault_location}
        assert {f["hop"] for f in supported} == {
            f"forward:{fault_location.lower()}_in:{fault_location.lower()}_out"
        }
        assert all(
            f["metrics"]["device_evidence"]
            and {e["device"] for e in f["metrics"]["device_evidence"]} == {fault_location}
            for f in supported
        )
    patterns = [f for f in report["findings"] if f["type"] in ("syn_flood_like", "scan_like_fanout")]
    assert {f["type"] for f in patterns} == {"syn_flood_like", "scan_like_fanout"}
    assert all(
        f["evidence"]
        and f["tooltip"]
        and all(e["display_filter"] and e["content_filter"] for e in f["evidence"])
        for f in patterns + supported
    )
    assert all(f["time_range"][0] >= truth["base"] + 12 for f in patterns if f["type"] == "syn_flood_like")
    assert all(
        f["metrics"]["source"] == truth["populations"][4][0]["src"]
        for f in patterns
        if f["type"] == "scan_like_fanout"
    )
    pool_targets = {
        p["src"]: {q["dport"] for q in truth["populations"][6] if q["src"] == p["src"]}
        for p in truth["populations"][6]
    }
    assert all(len(targets) >= topology["security_scan_targets"] for targets in pool_targets.values())
    # Ground truth occupancy is one per distinct SYN, never count copies at every hop together.
    with project.connect() as db:
        occupancy = db.execute(
            "SELECT half_open FROM session_buckets WHERE point='client' AND bucket=16"
        ).fetchone()[0]
        assert occupancy == truth["half_open_bucket16"]
        assert (
            db.execute(
                "SELECT count(*) FROM session_lifecycle WHERE point='client' AND src LIKE ?",
                ["2001:db8:1:3:%" if ipv6 else "10.3.%"],
            ).fetchone()[0]
            == truth["half_open_bucket16"]
        )
    data = export_data(project)
    assert FindingsExport.model_validate(data).schema_version == 11
    assert "TCP session lifecycle" in html_report(data)
    after = findings_page(project, truth["base"] + 11, truth["base"] + 17)["items"]
    assert any(f["type"] == "syn_flood_like" for f in after)
    before = findings_page(project, truth["base"] + 1, truth["base"] + 6)["items"]
    assert not any(f["id"].startswith("security:") for f in before)


@pytest.mark.parametrize("defect", ["missing_endpoint", "clock", "capture_drop", "translation"])
def test_quality_guards_no_supported_absence_heuristic(scenarios, clone_project, defect):
    shared, _, topology, report = scenarios("security", ip_id="zero", fault_location="FW2")
    project = clone_project(shared)
    import copy
    import json

    coverage = copy.deepcopy(report["coverage"])
    clocks = copy.deepcopy(report["clocks"])
    segments = copy.deepcopy(report["segments"])
    point = "fw2_in"
    capture = next(p["capture_id"] for p in topology["points"] if p["id"] == point)
    with project.connect() as db:
        if defect == "missing_endpoint":
            coverage = [c for c in coverage if c["point"] != point]
        elif defect == "clock":
            clocks[capture]["uncertainty"] = None
        elif defect == "capture_drop":
            inv = json.loads(db.execute("SELECT inventory FROM captures WHERE id=?", [capture]).fetchone()[0])
            inv["ifdrop"] = 17
            db.execute("UPDATE captures SET inventory=? WHERE id=?", [json.dumps(inv), capture])
        else:
            for s in segments:
                if s["point_a"] == point or s["point_b"] == point:
                    s["reason"] = "NAT mapping unknown"
        findings, notes = security_checks(
            db, Topology(**topology), coverage, report["timeseries"], segments, clocks
        )
    assert any(n["point"] == point and n["status"] == "unknown" for n in notes["quality"])
    assert not any(f["hop"].split(":")[1] == point and f["confidence"] == "supported" for f in findings)


def test_naive_heuristics_are_rejected_by_same_fixture(scenarios):
    project, truth, topology, report = scenarios("security", ip_id="zero", fault_location="FW2")
    # Execute simplified detector queries on the identical population, then apply the acceptance contracts.
    with project.connect() as db:
        rate_only = db.execute("SELECT start FROM security_cohorts WHERE syn_rate>=50").fetchall()
        destinations_only = db.execute("SELECT source FROM security_fanout WHERE targets>=20").fetchall()
        spikes = {p[0] for p in db.execute("SELECT DISTINCT point FROM pressure_spikes").fetchall()}
        any_drop = (
            db.execute("SELECT count(*) FROM device_proofs WHERE status='confirmed_device_drop'").fetchone()[
                0
            ]
            > 0
        )
    with pytest.raises(AssertionError):
        assert all(t[0] >= truth["base"] + 12 for t in rate_only)
    with pytest.raises(AssertionError):
        assert all(s[0] == truth["populations"][4][0]["src"] for s in destinations_only)
    global_pressure = {
        p["device"] for p in topology["points"] if p["id"] in spikes and p["kind"] == "Firewall" and any_drop
    }
    with pytest.raises(AssertionError):
        assert global_pressure == {
            f["device"]
            for f in report["findings"]
            if f["type"] == "session_table_pressure" and f["confidence"] == "supported"
        }


def test_event_floor_shortcut_cannot_hide_an_eligible_pattern(scenarios, clone_project):
    shared, _, topology, report = scenarios("healthy")
    project = clone_project(shared)
    with project.connect() as db:
        findings, notes = security_checks(
            db,
            Topology(**topology),
            report["coverage"],
            report["timeseries"],
            report["segments"],
            report["clocks"],
        )
        assert findings == [] and notes["status"] == "Below all heuristic event floors"
        assert notes["max_observed_syn_sessions_per_point"] < min(
            notes["thresholds"]["scan_targets"],
            notes["thresholds"]["half_open_floor"],
            notes["thresholds"]["syn_rate"],
        )
        # Lowering a floor disables the shortcut; it must execute the full detector population.
        settings = Topology(**topology)
        settings.security_syn_rate = 1
        findings, notes = security_checks(
            db, settings, report["coverage"], report["timeseries"], report["segments"], report["clocks"]
        )
        assert notes.get("status") != "Below all heuristic event floors"
        assert db.execute("SELECT count(*) FROM security_cohorts").fetchone()[0] > 0


@pytest.mark.parametrize("mode", ["increment", "random"])
def test_generator_ip_id_mode_is_decoded_as_requested(tmp_path, tshark, mode):
    import random
    import subprocess
    from packetbreaker.security_synthetic import generate

    truth, _ = generate(tmp_path, "link", mode, False, rounds=20)
    decoded = subprocess.run(
        [tshark, "-n", "-r", truth["files"][0], "-c", "8", "-T", "fields", "-e", "ip.id"],
        check=True,
        capture_output=True,
        text=True,
    )
    ids = [int(value, 0) for value in decoded.stdout.split()]
    if mode == "increment":
        assert ids == list(range(1, 9))
    else:
        rng = random.Random(44)
        expected = []
        for count in (5, 3):
            rng.random()  # calibration arrival jitter precedes each connection's packets
            expected.extend(rng.randrange(65536) for _ in range(count))
        assert ids == expected and ids != list(range(1, 9))


def test_synack_without_final_ack_is_also_a_sustained_flood_like_pattern(scenarios):
    _, _, _, report = scenarios("security_reply", fault_location="FW2", ip_id="zero", rounds=20)
    floods = [f for f in report["findings"] if f["type"] == "syn_flood_like"]
    assert floods and any(
        f["metrics"]["synack_ratio"] > 0.9 and f["metrics"]["established_ratio"] <= 0.2 for f in floods
    )


def test_syn_threshold_cannot_call_complete_handshakes_low_completion():
    with pytest.raises(ValueError):
        Topology(security_completion_ratio=1)
