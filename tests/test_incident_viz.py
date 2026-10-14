from pathlib import Path
import pytest


@pytest.fixture(scope="module")
def incident_replica(tmp_path_factory, tshark):
    from packetbreaker.pilot_synthetic import make_pilot
    from packetbreaker.batch_ingest import ingest_many
    from packetbreaker.store import Project
    from packetbreaker.synthetic import bind_capture_ids
    from packetbreaker.analysis import analyze

    root = tmp_path_factory.mktemp("incident-viz")
    truth, topology = make_pilot(
        root / "wire",
        flows=50,
        affected_flows=25,
        slow_local_flow=True,
        host_jitter_us=150,
        ip_id="increment",
    )
    topology["forward"] = [p for p in topology["forward"] if p != "mirror"]
    topology["reverse"] = [p for p in topology["reverse"] if p != "mirror"]
    topology["points"] = [p for p in topology["points"] if p["id"] != "mirror"]
    project = Project(root / "project")
    ids = ingest_many(project, truth["files"], tshark=tshark, workers=4)
    bind_capture_ids(topology, {Path(f).name: c for f, c in zip(truth["files"], ids)})
    report = analyze(project, topology)
    return project, truth, topology, report


def test_global_host_summary_and_flow_distractor(incident_replica):
    project, truth, topology, report = incident_replica
    items = report["host_path"]["items"]
    assert {r["direction"] for r in items} == {"rx", "tx"}
    assert len(items) == 2
    assert report["flow_count"] == 50
    assert all(r["affected_flow_count"] == 25 for r in items)
    assert len([f for f in report["findings"] if f["type"] == "host_receive_delay"]) == 1
    assert len([f for f in report["findings"] if f["type"] == "host_transmit_delay"]) == 1
    assert report["host_path"]["local_service"]["cycle_aggregate"]["p95_ms"] < 1
    assert max(r["p95_ms"] for r in report["host_path"]["local_service"]["transport_turnaround"]) > 180
    assert "188" not in report["verdict"] and "Onset unknown" not in report["verdict"]
    assert "Global event window" in report["verdict"]
    for r in items:
        assert abs(r["window"]["start"] - truth["start"]) <= 1
        assert abs(r["window"]["end"] - truth["end"]) <= 1
        assert len(r["flow_details"]) == 50
    with project.connect() as db:
        expected = db.execute(
            "SELECT quantile_cont(turnaround_ms,.95) FROM cycle_points WHERE point='host' AND reason IS NULL"
        ).fetchone()[0]
    assert report["host_path"]["local_service"]["cycle_aggregate"]["p95_ms"] == expected


def test_visualisations_and_existing_exports_have_evidence(incident_replica):
    import io
    import zipfile
    from packetbreaker.engine_export import export_tables
    from packetbreaker.export import export_report

    project, _, _, report = incident_replica
    incident = report["incident"]
    assert incident["timeline"] and incident["quality"] and incident["delivery"] and incident["cycle_bars"]
    assert any(r["evidence"] for r in incident["timeline"] if r["rx_max_ms"] and r["rx_max_ms"] > 100)
    assert all(r["evidence"] for r in incident["quality"])
    assert all("period" in r for r in report["cycles"]["top"])
    assert all("before_p95_ms" in r and "per_hop_added" in r for r in report["cycles"]["flow_ports"])
    with zipfile.ZipFile(io.BytesIO(export_tables(project, "csv"))) as z:
        assert "before_p95_ms" in z.read("flow_port.csv").decode().splitlines()[0]
        assert "period" in z.read("top_cycles.csv").decode().splitlines()[0]
    html = export_report(project, "html")
    assert "Incident timeline" in html and "Where was the time added" in html
    assert "Hold and release" in html and "Capture quality" in html
    assert "https://cdn" not in html


def test_host_chart_evidence_contains_both_boundary_points(scenarios):
    _, _, _, report = scenarios("pilot", ip_id="zero")
    for item in report["host_path"]["items"]:
        segment = next(s for s in report["segments"] if s["id"] == item["hop"])
        expected = {segment["point_a"], segment["point_b"]}
        assert {e["point"] for e in item["evidence"]} == expected
        assert all({e["point"] for e in r["evidence"]} == expected for r in item["series"])


def test_mixed_host_losses_keep_subtypes_under_one_heading():
    from packetbreaker.host_path import group_host_losses
    from packetbreaker.topology import Topology

    t = Topology.model_validate(
        dict(
            points=[
                dict(id="host", capture_id="h", label="Server capture", device="server", host_capture=True),
                dict(id="fw", capture_id="f", label="FW rx", device="FW", stage_capture=True, side="ingress"),
            ],
            forward=["fw", "host"],
        )
    )
    segment = dict(id="reverse:host:fw", point_a="host", point_b="fw")
    findings = [
        dict(id="generic", type="impactful_loss", hop=segment["id"], metrics={"count": 284}, evidence=[]),
        dict(
            id="physical",
            type="host_transmit_path_loss",
            hop=segment["id"],
            metrics={"count": 14},
            evidence=[],
        ),
    ]
    groups = group_host_losses(findings, [segment], t)
    assert len(groups) == 1 and groups[0]["counts"] == {"impactful_loss": 284, "host_transmit_path_loss": 14}
    assert "no mirror point in between" in groups[0]["headline"]
    assert all(f["metrics"]["boundary_loss_heading"] == groups[0]["headline"] for f in findings)


def test_reference_aggregates_on_fifty_flow_replica(incident_replica):
    project, truth, _, report = incident_replica
    c, h = report["cycles"], report["host_path"]
    assert c["total"] == 50 * 27
    assert c["stalled_total"] == 25 * 13 + 27  # One app-only 188 ms distractor remains a stalled cycle.
    assert 1299 < c["max_added_ms"] < 1302
    assert c["max_added"]["port"] == 8080  # Existing engine port is the request service port.
    assert {e["point"] for e in c["max_added"]["evidence"]} == {"b_tx", "host", "b_rx"}
    assert 648 <= c["event"]["total"] <= 651  # Window edges carry <=1 s uncertainty and timestamp jitter.
    expected = 100 * sum(truth["rx"]) / (sum(truth["rx"]) + sum(truth["tx"]))
    assert h["event"]["rx_share"] == pytest.approx(expected, abs=3)
    assert 0 < h["max_silence_ms"] < 2000
    assert all(
        i["affected_flows_ge_stall"] == 25 and i["affected_flows_ge_stall_event"] == 25 for i in h["items"]
    )
    assert c["repeat_groups"] == {
        "forward": 0,
        "reverse": 0,
    }  # Seeing a packet at many points is not a repeat.
    with project.connect() as db:
        client_port = db.execute(
            "SELECT min(sport) FROM obs WHERE flow=? AND direction='forward'", [c["max_added"]["flow"]]
        ).fetchone()[0]
        assert 41000 <= client_port < 41025  # Never select the app-only distractor.
        silence = h["event"]["silence"][0]
        frames = [e["frame"] for e in silence["evidence"]]
        times = db.execute(
            "SELECT ts FROM packets WHERE capture_id=? AND frame IN(SELECT unnest(?::BIGINT[])) ORDER BY ts",
            [silence["evidence"][0]["capture_id"], frames],
        ).fetchall()
        clock = report["clocks"][silence["evidence"][0]["capture_id"]]
        assert (times[1][0] - times[0][0]) * 1000 / (1 + clock["drift_ppm"] / 1e6) == pytest.approx(
            h["max_silence_ms"], abs=0.001
        )


def test_chronic_low_rate_loss_vs_event_correlated_loss():
    import duckdb
    from packetbreaker.host_path import classify_chronic_losses
    from packetbreaker.topology import Topology

    db = duckdb.connect()
    try:
        db.execute(
            """CREATE TABLE obs(
                point VARCHAR, direction VARCHAR, eligible BOOLEAN,
                length BIGINT, proto VARCHAR, flags BIGINT, corrected DOUBLE, ts DOUBLE
            )"""
        )
        db.execute(
            """CREATE TABLE events(
                point_a VARCHAR, point_b VARCHAR, direction VARCHAR,
                kind VARCHAR, ts DOUBLE, recovery_ms DOUBLE
            )"""
        )
        # 200,000 eligible forward packets across [0, 60] for both fw_rx (chronic) and sw_rx (event burst)
        db.execute(
            """INSERT INTO obs
            SELECT 'fw_rx', 'forward', true, 1400, 'TCP', 24, (i % 60000) * 0.001, (i % 60000) * 0.001
            FROM range(200000) t(i)"""
        )
        db.execute(
            """INSERT INTO obs
            SELECT 'sw_rx', 'forward', true, 1400, 'TCP', 24, (i % 60000) * 0.001, (i % 60000) * 0.001
            FROM range(200000) t(i)"""
        )
        # Positive: fw_rx -> fw_tx has 26 drops spread across before (<20s: 8), during (20..45s: 11), after (>=45s: 7)
        chronic_times = (
            [2.0 + i * 2.0 for i in range(8)]
            + [21.0 + i * 2.0 for i in range(11)]
            + [46.0 + i * 2.0 for i in range(7)]
        )
        for ts in chronic_times:
            db.execute(
                "INSERT INTO events VALUES ('fw_rx', 'fw_tx', 'forward', 'impactful_loss', ?, 205.0)",
                [ts],
            )
        # Negative (distractor): sw_rx -> sw_tx has 1 drop before, 24 drops during event, 1 drop after
        burst_times = [5.0] + [21.0 + i * 0.8 for i in range(24)] + [55.0]
        for ts in burst_times:
            db.execute(
                "INSERT INTO events VALUES ('sw_rx', 'sw_tx', 'forward', 'impactful_loss', ?, 205.0)",
                [ts],
            )

        topology = Topology.model_validate(
            dict(
                points=[
                    dict(id="fw_rx", label="FW in", device="FW", capture_id="c1"),
                    dict(id="fw_tx", label="FW out", device="FW", capture_id="c2"),
                    dict(id="sw_rx", label="SW in", device="SW", capture_id="c3"),
                    dict(id="sw_tx", label="SW out", device="SW", capture_id="c4"),
                ],
                forward=["fw_rx", "fw_tx", "sw_rx", "sw_tx"],
            )
        )
        segments = [
            dict(
                id="forward:fw_rx:fw_tx",
                point_a="fw_rx",
                point_b="fw_tx",
                direction="forward",
                label="FW in → FW out",
                reason=None,
                eligible_packets=200000,
                loss_percent=26 * 100.0 / 200000,
                p95_ms=0.02,
                max_ms=0.15,
                offset_uncertainty_ms=0.01,
            ),
            dict(
                id="forward:sw_rx:sw_tx",
                point_a="sw_rx",
                point_b="sw_tx",
                direction="forward",
                label="SW in → SW out",
                reason=None,
                eligible_packets=200000,
                loss_percent=26 * 100.0 / 200000,
                p95_ms=0.02,
                max_ms=0.15,
                offset_uncertainty_ms=0.01,
            ),
        ]
        findings = [
            dict(
                id="forward:fw_rx:fw_tx:impactful_loss",
                type="impactful_loss",
                hop="forward:fw_rx:fw_tx",
                direction="forward",
                severity="high",
                time_range=[2.0, 58.0],
                metrics={"count": 26},
                summary="26 impactful loss event(s) between FW in and FW out.",
                evidence=[],
            ),
            dict(
                id="forward:sw_rx:sw_tx:impactful_loss",
                type="impactful_loss",
                hop="forward:sw_rx:sw_tx",
                direction="forward",
                severity="high",
                time_range=[5.0, 55.0],
                metrics={"count": 26},
                summary="26 impactful loss event(s) between SW in and SW out.",
                evidence=[],
            ),
        ]
        host_report = {"window": {"start": 20.0, "end": 45.0, "status": "detected"}}
        classify_chronic_losses(db, topology, segments, findings, host_report, {}, 0.0, 60.0)

        fw_seg, sw_seg = segments
        fw_find, sw_find = findings
        # Positive: FW is labeled chronic low-rate loss (not event-correlated)
        assert fw_seg.get("chronic_loss") is True
        assert fw_seg.get("chronic_loss_summary") == "transit clean; chronic loss 0.013%"
        assert fw_find.get("chronic_loss") is True
        assert "chronic low-rate loss (not event-correlated)" in fw_find["summary"]
        assert "26 drops, ~205 ms RTO each" in fw_find["summary"]
        assert fw_find["metrics"]["period_rates"]["before_loss_percent"] > 0
        assert fw_find["metrics"]["period_rates"]["during_loss_percent"] > 0
        assert fw_find["metrics"]["period_rates"]["after_loss_percent"] > 0
        # Negative: SW has event-concentrated burst loss and is NOT labeled chronic
        assert not sw_seg.get("chronic_loss")
        assert not sw_find.get("chronic_loss")
        assert "chronic low-rate loss" not in sw_find["summary"]
    finally:
        db.close()
