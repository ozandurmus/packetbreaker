"""Wire-decode contract: original multi-interface HTTP/TLS, with unrelated router."""

from copy import deepcopy

import pytest
from packetbreaker.analysis import analyze
from packetbreaker.ingest import ingest
from packetbreaker.store import Project, rows
from packetbreaker.synthetic import bind_capture_ids
from packetbreaker.topology import Topology
from packetbreaker.clock import ClockModel
from packetbreaker.proxy_analysis import correlate
from proxy_fixtures import make_fixture


@pytest.fixture(scope="module", params=[("zero", False), ("constant", False), ("zero", True)])
def proxy_capture(request, tmp_path_factory, tshark):
    directory = tmp_path_factory.mktemp("proxy_wire")
    f, t, truth = make_fixture(directory, ipv6=request.param[1], ip_id=request.param[0])
    project = Project(directory / "project")
    cid = ingest(project, f, tshark=tshark)
    bind_capture_ids(t, {f.name: cid})
    report = analyze(project, t)
    return project, Topology.model_validate(t), truth, report


@pytest.mark.parametrize("negative", ["clock", "missing_point", "capture_miss"])
def test_wire_negative_first(proxy_capture, negative):
    project, topology, _, report = proxy_capture
    with project.connect() as db:
        db.execute("BEGIN TRANSACTION")
        try:
            models = {
                k: ClockModel(**{n: v for n, v in m.items() if n != "drift_ppm"})
                for k, m in report["clocks"].items()
            }
            statuses = deepcopy(report["application_status"])
            if negative == "clock":
                for m in models.values():
                    m.uncertainty = None
            else:
                db.execute("DELETE FROM app_protocol WHERE point IN ('a_out','b_out')")
                if negative == "capture_miss":
                    statuses += [
                        dict(point=p, reason="Incomplete application capture") for p in ("a_out", "b_out")
                    ]
            found = correlate(db, topology, models, statuses)
            assert found["transactions"]
            assert all(p["status"] == "unknown" and p["reason"] for p in found["transactions"])
        finally:
            db.execute("ROLLBACK")


def test_wire_pooling_and_ambiguity(proxy_capture):
    project, _, _, report = proxy_capture
    assert all(s["reason"] is None for s in report["application_status"])
    with project.connect() as db:
        for device in ("Proxy A", "Proxy B"):
            pairs = report["proxies"]["transactions"]
            matched = [
                p for p in pairs if p["device"] == device and p["status"] == "matched" and p["kind"] == "http"
            ]
            assert len(matched) == 4
            assert any(
                p["status"] == "unknown" and p["kind"] == "http" and p["device"] == device for p in pairs
            )
            # The first two simultaneous requests share one outgoing connection.
            first = sorted(matched, key=lambda p: p["time"])[:2]
            assert len({p["server_flow"] for p in first}) == 1
            assert len({p["client_id"] for p in first}) == 2
            assert all(p["xff_confirmed"] and p["evidence_rank"] == "HTTP request line + Host" for p in first)
            assert all(e["content_filter"] and e["frame"] > 0 for p in matched for e in p["evidence"])
        assert not any(p["device"] == "Router" for p in report["proxies"]["transactions"])
        assert (
            db.execute(
                "SELECT count(*) FROM observation_matches WHERE (point_a='a_in' AND point_b='a_out') OR (point_a='b_in' AND point_b='b_out')"
            ).fetchone()[0]
            == 0
        )
        assert (
            db.execute(
                "SELECT count(DISTINCT flow) FROM proxy_requests WHERE kind='http' AND point IN ('a_in','a_out')"
            ).fetchone()[0]
            >= 3
        )


def test_tshark_original_frame_mapping(proxy_capture):
    project, _, _, _ = proxy_capture
    with project.connect() as db:
        requests = rows(db, "SELECT * FROM proxy_requests WHERE kind='http' AND line LIKE 'POST %'")
        assert requests and all(r["first_frame"] < r["last_frame"] for r in requests)
        assert all(r["complete"] >= r["start"] for r in requests)
        chains = rows(db, "SELECT metadata FROM app_protocol WHERE kind='tls_certificate'")
        assert chains and all("fingerprint" in r["metadata"] and "2.5.4.3=" in r["metadata"] for r in chains)


def test_exact_request_dwell_and_waterfall(proxy_capture):
    from packetbreaker.waterfall import waterfall

    project, _, truth, report = proxy_capture
    with project.connect() as db:
        lookup = {r["id"]: r for r in rows(db, "SELECT * FROM proxy_requests")}
        for device, expect in truth["pool"].items():
            pairs = sorted(
                [
                    p
                    for p in report["proxies"]["transactions"]
                    if p["device"] == device and p["status"] == "matched" and p["kind"] == "http"
                ],
                key=lambda p: p["time"],
            )[:2]
            for p in pairs:
                client = lookup[p["client_id"]]
                forward, back = expect[client["origin_ip"]]
                assert p["request_dwell"]["duration_ms"] == pytest.approx(forward, abs=0.001)
                assert p["response_dwell"]["duration_ms"] == pytest.approx(back, abs=0.001)
                assert p["request_dwell"]["uncertainty_ms"] == 0
                assert p["response_dwell"]["reason"] is None
        flow = next(
            r["flow"]
            for r in lookup.values()
            if r["point"] == "client" and r["line"] == "POST /shared HTTP/1.1"
        )
    w = waterfall(project, flow)
    assert len([i for i in w["items"] if i["kind"].startswith("handshake:")]) == 3
    http = next(i for i in w["items"] if i["kind"] == "http")
    assert len(http["bars"]) == 15
    assert all(b["duration_ms"] is not None and b["evidence"] for b in http["bars"])
    assert {b["point_a"] for b in http["bars"] if b["kind"] == "proxy_dwell"} == {
        "a_in",
        "a_out",
        "b_in",
        "b_out",
    }


def test_dwell_never_invents_missing_clock_or_streaming_duration():
    from packetbreaker.proxy_waterfall import interval

    for a, b, u in [(1, 2, None), (None, 2, 0), (2, 1, 0)]:
        value = interval(a, b, u)
        assert value["duration_ms"] is None and value["reason"]


def test_missing_pooled_response_never_shifts_request_pairing(proxy_capture):
    from packetbreaker.proxy_analysis import prepare_requests

    project, _, _, _ = proxy_capture
    with project.connect() as db:
        db.execute("BEGIN TRANSACTION")
        try:
            db.execute(
                "DELETE FROM app_protocol WHERE point='a_out' AND kind='http_response' AND frame=(SELECT min(frame) FROM app_protocol WHERE point='a_out' AND kind='http_response')"
            )
            prepare_requests(db)
            assert (
                db.execute(
                    "SELECT count(*) FROM proxy_requests WHERE point='a_out' AND line LIKE 'POST%' AND response IS NOT NULL"
                ).fetchone()[0]
                == 0
            )
        finally:
            db.execute("ROLLBACK")
