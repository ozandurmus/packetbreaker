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
