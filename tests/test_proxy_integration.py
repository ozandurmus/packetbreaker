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
