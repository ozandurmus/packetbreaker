import pytest
from fastapi.testclient import TestClient
from packetbreaker.app import create_app
from packetbreaker.analysis import flow_page
from packetbreaker.pilot import topology_overlay, topology_inspect


def test_overlay_outside_coverage_is_unknown_and_inspector_rejects_wrong_point(scenarios):
    project, truth, _, _ = scenarios("healthy")
    data = topology_overlay(project, truth["reference_epoch"] + 1000, truth["reference_epoch"] + 1001)
    assert data["segments"] and all(
        s["loss_percent"] is None and s["p95_ms"] is None for s in data["segments"]
    )
    assert all(n["observations"] == 0 for n in data["nodes"])
    with pytest.raises(ValueError, match="Unknown"):
        topology_inspect(project, point="wrong")
    with TestClient(create_app(project.path), base_url="http://127.0.0.1") as client:
        assert client.get("/api/topology/overlay?start=nan").status_code == 422
        assert client.get("/api/topology/inspect?point=p0&segment=forward:p0:p1").status_code == 422


def test_overlay_brush_metrics_and_exact_inspection(scenarios):
    project, truth, topology, report = scenarios("onset_loss", ip_id="zero", loss_hop=1)
    start = truth["onsets"][0]["time"]
    data = topology_overlay(project, start, start + 2)
    fault = next(s for s in data["segments"] if s["id"] == "forward:p1:p2")
    upstream = next(s for s in data["segments"] if s["id"] == "forward:p0:p1")
    assert fault["classes"]["recovered_loss"] > 0 and fault["loss_percent"] > 0
    assert upstream["loss_percent"] == 0
    with project.connect() as db:
        pps, n = db.execute(
            "SELECT count(*) FILTER(WHERE eligible),count(*) FILTER(WHERE retrans) FROM obs WHERE point='p1' AND direction='forward' AND corrected>=? AND corrected<?",
            [start, start + 2],
        ).fetchone()
        delay = db.execute(
            "SELECT quantile_cont((time_b-time_a)*1000,.95) FROM observation_matches WHERE point_a='p1' AND point_b='p2' AND direction='forward' AND time_a>=? AND time_a<?",
            [start, start + 2],
        ).fetchone()[0]
    assert fault["eligible_packets"] == pps and fault["retrans_observations"] == n
    assert fault["p95_ms"] == pytest.approx(delay)
    inspect = topology_inspect(project, segment=fault["id"], start=start, end=start + 2)
    assert inspect["findings"] and all(f["hop"] == fault["id"] for f in inspect["findings"])
    assert inspect["flows"]["total"] > 0
    assert all(start <= f["time_range"][0] < start + 2 for f in inspect["findings"])
    with TestClient(create_app(project.path), base_url="http://127.0.0.1") as client:
        response = client.get(f"/api/topology/inspect?segment={fault['id']}&start={start}&end={start + 2}")
        assert response.status_code == 200 and response.json()["flows"]["items"]


def test_handshake_column_matches_same_point_evidence_and_missing_is_unknown(scenarios):
    project, _, topology, _ = scenarios("healthy")
    flows = flow_page(project, sort="handshake_rtt_ms")["items"]
    assert any(f["handshake_rtt_ms"] is not None for f in flows)
    with project.connect() as db:
        f = next(f for f in flows if f["handshake_rtt_ms"] is not None)
        ms = db.execute(
            """SELECT (sa.ts-s.ts)*1000 FROM obs s JOIN obs sa ON
            sa.point=s.point AND sa.stream=s.stream AND sa.ack=(s.seq+1)%4294967296
            AND (sa.flags&18)=18 AND sa.ts>s.ts AND sa.ts<s.ts+60
            WHERE s.point=? AND s.flow=? AND (s.flags&18)=2 ORDER BY s.ts LIMIT 1""",
            [topology["forward"][0], f["flow"]],
        ).fetchone()[0]
    assert f["handshake_rtt_ms"] == pytest.approx(ms)
    assert all(f["reset_origin"] is None for f in flows)
    project, _, _, _ = scenarios("syn_blocked")
    assert all(
        f["handshake_rtt_ms"] is None for f in flow_page(project)["items"] if f["handshake_incomplete"]
    )


def test_reset_column_uses_supported_attribution_only(multi, clone_project):
    project, _, _, report = multi("FW", ("zero", False))
    expected = [
        f for f in report["findings"] if f["type"] == "reset_origin" and f["confidence"] == "supported"
    ]
    origins = [
        f["reset_origin"]
        for f in flow_page(project, limit=200, sort="reset_origin")["items"]
        if f["reset_origin"]
    ]
    assert expected and origins
    assert all(any(f["summary"] in origin for f in expected) for origin in origins)
    from copy import deepcopy
    from packetbreaker.analysis import analyze

    source, _, topology, _ = multi("FW", ("zero", False), no_endpoint=True)
    unknown = clone_project(source)
    topology = deepcopy(topology)
    # Remove BOTH endpoints: the no-server fixture still has supported client-side injections.
    topology["points"] = [p for p in topology["points"] if p["id"] != "client"]
    for direction in ("forward", "reverse"):
        topology[direction] = [p for p in topology[direction] if p != "client"]
    analyze(unknown, topology)
    assert not any(f["reset_origin"] for f in flow_page(unknown, limit=200)["items"])


def test_default_overlay_uses_analyzed_window_not_entire_capture(scenarios, clone_project):
    from copy import deepcopy

    original, truth, _, saved = scenarios("healthy")
    project = clone_project(original)
    report = deepcopy(saved)
    start = truth["reference_epoch"] + 3
    report["window"].update(start=start, end=start + 1)
    with project.connect() as db:
        project.set(db, "report", report)
        eligible = db.execute(
            "SELECT count(*) FROM obs WHERE point='p0' AND direction='forward' AND eligible AND corrected>=? AND corrected<?",
            [start, start + 1],
        ).fetchone()[0]
        total = db.execute(
            "SELECT count(*) FROM obs WHERE point='p0' AND direction='forward' AND eligible"
        ).fetchone()[0]
    overlay = topology_overlay(project)
    segment = next(s for s in overlay["segments"] if s["id"] == "forward:p0:p1")
    assert overlay["scope"] == dict(start=start, end=start + 1)
    assert segment["eligible_packets"] == eligible and 0 < eligible < total
    outside = topology_overlay(project, start + 5, start + 6)
    assert all(s["loss_percent"] is None for s in outside["segments"])
