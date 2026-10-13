import pytest
from packetbreaker.topology import Topology


def stage_topology():
    points = []
    for name, device, side in [
        ("a_rx", "A", "ingress"),
        ("a_tx", "A", "egress"),
        ("b_rx", "B", "ingress"),
        ("b_tx", "B", "egress"),
        ("mirror", "Switch", "both"),
        ("host", "Server", "both"),
    ]:
        points.append(
            dict(id=name, label=name, device=device, side=side, capture_id=name, stage_capture=side != "both")
        )
    return dict(points=points, forward=[p["id"] for p in points])


def test_stage_order_is_rx_then_tx_in_both_directions():
    topology = Topology.model_validate(stage_topology())
    assert topology.forward == ["a_rx", "a_tx", "b_rx", "b_tx", "mirror", "host"]
    assert topology.reverse == ["host", "mirror", "b_rx", "b_tx", "a_rx", "a_tx"]
    assert topology.precedes("b_rx", "b_tx", "reverse")
    assert not topology.precedes("a_rx", "b_rx", "reverse")


def test_wire_interface_order_is_unchanged_and_stage_declaration_is_per_device():
    wire = stage_topology()
    for p in wire["points"]:
        p["stage_capture"] = False
    t = Topology.model_validate(wire)
    assert t.path("reverse") == list(reversed(t.forward))
    wire["points"][0]["stage_capture"] = True
    t = Topology.model_validate(wire)
    assert t.points[1].stage_capture
    assert t.path("reverse")[-2:] == ["a_rx", "a_tx"]


def test_shared_clock_inference_rejects_offset_delay_and_one_way():
    from packetbreaker.clock import infer_shared_clock

    samples = [(float(i), i + (0.00002 if f else -0.00002), f) for i in range(30) for f in (True, False)]
    assert infer_shared_clock(samples) is not None
    assert infer_shared_clock([(a, b + 0.1, f) for a, b, f in samples]) is None
    assert infer_shared_clock([(a, b, f) for a, b, f in samples if f]) is None
    assert infer_shared_clock([(a, a + (0.1 if f else -0.1), f) for a, b, f in samples]) is None


def test_declared_clock_domain_cannot_conflict_for_one_file():
    import pytest

    t = stage_topology()
    t["points"][0].update(clock_domain="x")
    t["points"][1].update(capture_id="a_rx", clock_domain="y")
    with pytest.raises(ValueError, match="clock domain"):
        Topology.model_validate(t)
    t = stage_topology()
    t["points"][0]["clock_domain"] = t["points"][1]["clock_domain"] = "appliance"
    t["clock_overrides"] = {"a_rx": {"offset_ms": 0}, "a_tx": {"offset_ms": 10}}
    with pytest.raises(ValueError, match="conflicting clock corrections"):
        Topology.model_validate(t)


def test_span_jitter_and_isolated_outliers_do_not_invalidate_transit():
    from packetbreaker.clock import fit_clock, transit_quality

    samples = [
        (i * 0.1, i * 0.1 + 0.03 + (1 if f else -1) * 0.00004 + ((i % 7) - 3) * 0.00005, f)
        for i in range(200)
        for f in (True, False)
    ]
    model = fit_clock(samples)
    assert model.offset is not None and abs(model.offset - 0.03) < 0.0003
    normal = transit_quality(
        dict(matched=1000, min_ms=-20, p50_ms=0.04, p05_ms=-0.1, negative_outliers=1), 0.3
    )
    assert not normal["systematic_negative"] and normal["quality_notes"]
    biased = transit_quality(
        dict(matched=1000, min_ms=-20, p50_ms=-10, p05_ms=-11, negative_outliers=900), 0.3
    )
    assert biased["systematic_negative"]


def test_pilot_wire_replica(scenarios):
    project, truth, topology, report = scenarios("pilot", ip_id="zero")
    assert all(s["reason"] is None for s in report["segments"])
    assert not any(
        f["type"]
        in {"recovered_loss", "impactful_loss", "unrecovered_loss", "asymmetric_routing", "ttl_path"}
        and f["confidence"] == "supported"
        for f in report["findings"]
    )
    host = report["host_path"]
    assert host["items"] and host["local_service"]["p95_ms"] < 1
    assert {r["direction"] for r in host["items"]} == {"rx", "tx"}
    expected_share = 100 * sum(truth["rx"]) / (sum(truth["rx"]) + sum(truth["tx"]))
    import pytest

    for item in host["items"]:
        assert item["max_ms"] == pytest.approx(max(truth[item["direction"]]), abs=1)
        assert item["delay_share_percent"] == pytest.approx(
            expected_share if item["direction"] == "rx" else 100 - expected_share, abs=0.2
        )
        assert {p["period"] for p in item["periods"]} == {"before", "event", "recovery"}
    assert report["onsets"]["status"] == "detected"
    assert "application responds" in report["onsets"]["summary"]
    assert any(i["scope"] == "host_capture_boundary" and i["evidence"] for i in report["onsets"]["items"])
    with project.connect() as db:
        assert (
            db.execute(
                "SELECT excluded_single_point_frames FROM analysis_scope WHERE point='host'"
            ).fetchone()[0]
            == 2000
        )
    assert all(
        abs(r["window"]["start"] - truth["start"]) <= 1 and abs(r["window"]["end"] - truth["end"]) <= 1
        for r in host["items"]
    )


def test_memory_failure_is_actionable_and_keeps_project(tmp_path):
    import pytest
    from packetbreaker.store import Project

    project = Project(tmp_path / "project")
    with pytest.raises(ValueError, match="memory budget.*spill"):
        with project.connect() as db:
            db.execute("SET memory_limit='1MB'")
            db.execute("SELECT list(i) FROM range(1000000) r(i)").fetchone()
    assert project.inventory() == []


def test_latency_window_keeps_recovery_and_rejects_single_outlier():
    from packetbreaker.onset import latency_window

    values = [
        dict(
            start=float(i),
            end=i + 1,
            latency_p95_ms=(500 if 20 <= i < 45 and i % 3 == 0 else 0.04),
            bucket=i,
            coverage="capturing",
            reason=None,
            eligible_packets=10,
        )
        for i in range(70)
    ]
    event, reason = latency_window(values, 1)
    assert reason is None and event["time"] == 21 and event["end"] == 43
    assert event["recovery_confirmed"]
    isolated = [{**v, "latency_p95_ms": 500 if v["bucket"] == 21 else 0.04} for v in values]
    assert latency_window(isolated, 1)[0] is None


def test_pilot_ipv6_auto_clock_and_healthy_distractor(scenarios):
    project, truth, topology, report = scenarios("pilot", ip_id="zero", ipv6=True, pilot_shared=False)
    assert all(s["reason"] is None for s in report["segments"])
    assert any(c["confidence"] == "inferred_shared" and c["evidence"] for c in report["clocks"].values())
    assert len(report["host_path"]["items"]) == 2
    assert report["host_path"]["local_service"]["p95_ms"] < 1
    with project.connect() as db:
        healthy = db.execute("SELECT flow FROM obs WHERE point='host' AND sport=41001 LIMIT 1").fetchone()[0]
    assert not any(
        f["type"].startswith("host_") and f["metrics"]["flow"] == healthy for f in report["findings"]
    )
    assert not any(
        f["type"]
        in {"impactful_loss", "unrecovered_loss", "recovered_loss", "ttl_path", "asymmetric_routing"}
        and f["confidence"] == "supported"
        for f in report["findings"]
    )


def test_host_unknown_clock_has_no_supported_delay(scenarios, clone_project):
    from copy import deepcopy
    from packetbreaker.host_path import host_path
    from packetbreaker.topology import Topology

    project, _, topology, report = scenarios("pilot", ip_id="zero")
    clone = clone_project(project)
    segments = deepcopy(report["segments"])
    for s in segments:
        s["offset_uncertainty_ms"] = None
    with clone.connect() as db:
        host, findings = host_path(db, Topology.model_validate(topology), segments)
    assert not findings and not host["items"]
    assert all(s["reason"] for s in host["streams"])


def test_naive_reverse_any_negative_and_before_after_averages_fail(scenarios):
    import pytest

    _, truth, topology, report = scenarios("pilot", ip_id="zero")
    canonical = Topology.model_validate(topology)
    with pytest.raises(AssertionError):
        assert canonical.reverse == canonical.forward[::-1]
    with pytest.raises(AssertionError):
        assert all(s["min_ms"] >= -0.001 for s in report["segments"])
    for item in report["host_path"]["items"]:
        quiet = [p["p95_ms"] for p in item["periods"] if p["period"] != "event"]
        with pytest.raises(AssertionError):
            assert max(quiet) > 100
        assert item["max_ms"] > 100 and item["local_service"]["p95_ms"] < 1
        assert item["evidence"] and all(r["content_filter"] for r in item["evidence"])


@pytest.mark.slow  # 12 six-file real-tshark replicas cross location, IP family and ID mode.
@pytest.mark.parametrize("fault", ["a_tx", "b_tx", "mirror", "healthy"])
@pytest.mark.parametrize("mode", [("zero", False), ("constant", False), ("zero", True)])
def test_pilot_device_link_and_healthy_matrix(scenarios, fault, mode):
    project, truth, topology, report = scenarios(
        "pilot_healthy" if fault == "healthy" else "pilot",
        fault_location="host" if fault == "healthy" else fault,
        ip_id=mode[0],
        ipv6=mode[1],
    )
    assert not report["host_path"]["items"]
    assert not any(
        f["type"]
        in {"recovered_loss", "impactful_loss", "unrecovered_loss", "ttl_path", "asymmetric_routing"}
        and f["confidence"] == "supported"
        for f in report["findings"]
    )
    assert report["host_path"]["local_service"]["p95_ms"] < 1
    if fault != "healthy":
        expected = {
            "a_tx": "forward:a_rx:a_tx",
            "b_tx": "forward:b_rx:b_tx",
            "mirror": "forward:b_tx:mirror",
        }[fault]
        detected = [
            o
            for o in report["onsets"]["items"]
            if o["metric"] == "latency_p95_ms" and o["direction"] == "forward"
        ]
        assert detected and {o["segment"] for o in detected} == {expected}
        assert abs(detected[0]["time"] - truth["start"]) <= 1


@pytest.mark.slow  # One million generated host frames exercises real ingest and bounded analysis memory.
def test_unfiltered_million_frame_host_capture(tmp_path, tshark):
    from packetbreaker.pilot_synthetic import make_pilot
    from packetbreaker.store import Project
    from packetbreaker.batch_ingest import ingest_many
    from packetbreaker.synthetic import bind_capture_ids
    from packetbreaker.analysis import analyze
    from pathlib import Path
    import time

    truth, topology = make_pilot(tmp_path / "wire", noise=1_000_000)
    project = Project(tmp_path / "project")
    t = time.monotonic()
    ids = ingest_many(project, truth["files"], tshark=tshark, workers=1)
    ingest_seconds = time.monotonic() - t
    bind_capture_ids(topology, {Path(f).name: c for f, c in zip(truth["files"], ids)})
    t = time.monotonic()
    report = analyze(project, topology)
    analysis_seconds = time.monotonic() - t
    host = next(s for s in report["analysis_scope"] if s["point"] == "host")
    assert host["input_frames"] >= 1_000_000 and host["excluded_single_point_frames"] == 1_000_000
    assert host["retained_frames"] < 1000 and len(report["host_path"]["items"]) == 2
    assert report["host_path"]["local_service"]["p95_ms"] < 1
    assert not any(
        f["type"]
        in {"impactful_loss", "unrecovered_loss", "recovered_loss", "ttl_path", "asymmetric_routing"}
        and f["confidence"] == "supported"
        for f in report["findings"]
    )
    print(
        f"PILOT_SCALE ingest_s={ingest_seconds:.3f} analysis_s={analysis_seconds:.3f} input_frames={host['input_frames']} retained={host['retained_frames']}"
    )


def test_confirmed_latency_onset_survives_uncaptured_trailing_bucket():
    from packetbreaker.onset import latency_window

    values = [
        dict(
            start=i,
            end=i + 1,
            bucket=i,
            coverage="capturing",
            reason=None,
            latency_p95_ms=0.04 if i < 10 else 100,
        )
        for i in range(20)
    ]
    values.append(
        dict(
            start=20,
            end=21,
            bucket=20,
            coverage="not capturing",
            reason="Outside classified common window; loss rates unknown",
            latency_p95_ms=None,
        )
    )
    event, reason = latency_window(values, 1)
    assert reason is None and event["time"] == 10 and event["end"] == 20
    assert not event["recovery_confirmed"]
