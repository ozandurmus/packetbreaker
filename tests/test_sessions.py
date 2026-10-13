from packetbreaker.security import build_lifecycle
from packetbreaker.topology import Topology


def test_capture_miss_and_retry_do_not_invent_sessions(scenarios):
    project, truth, topology, report = scenarios("security", ip_id="zero", fault_location="FW2")
    with project.connect() as db:
        sessions = db.execute("SELECT * FROM session_lifecycle WHERE point='client'").description
        assert sessions
        retry = db.execute(
            "SELECT syn_attempts,status FROM session_lifecycle WHERE point='client' AND src=?",
            [truth["populations"][8][0]["src"]],
        ).fetchall()
        assert retry == [(2, "closed")]
        miss = db.execute(
            "SELECT status FROM session_lifecycle WHERE point='fw2_in' AND src=?",
            [truth["populations"][7][0]["src"]],
        ).fetchall()
        assert miss == []  # no guessed SYN or session state
    assert report["sessions"]["failed_handshakes"]
    assert all(f["evidence"] for f in report["sessions"]["failed_handshakes"])


def test_unknown_clock_is_not_zero_occupancy(scenarios, clone_project):
    project, _, topology, report = scenarios("security", ip_id="zero", fault_location="FW2")
    project = clone_project(project)
    # Existing bucket metadata + missing coverage, without mutating shared packet state.
    with project.connect() as db:
        data = build_lifecycle(db, Topology(**topology), [], report["timeseries"], report["window"])
        assert data["points"]
        assert all(p["status"] == "unknown" for p in data["points"])
        assert all(b["half_open"] is None for b in data["buckets"])


def test_ack_flag_alone_does_not_establish_and_counts_match_wire(scenarios, clone_project):
    shared, truth, topology, report = scenarios("security", ip_id="zero", fault_location="FW2")
    project = clone_project(shared)
    client = truth["populations"][1][0]["src"]
    with project.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM session_lifecycle WHERE point='client' AND established IS NOT NULL"
            ).fetchone()[0]
            == len(truth["populations"][1])
            + len(truth["populations"][2])
            + len(truth["populations"][5])
            + len(truth["populations"][6])
            + 2
        )
        db.execute("UPDATE obs SET ack=ack+7 WHERE point='client' AND src=? AND flags=16", [client])
        build_lifecycle(db, Topology(**topology), report["coverage"], report["timeseries"], report["window"])
        assert (
            db.execute(
                "SELECT established FROM session_lifecycle WHERE point='client' AND src=?", [client]
            ).fetchone()[0]
            is None
        )


def test_synack_stopping_hop_reuses_reverse_evidence(scenarios):
    _, truth, _, report = scenarios("security", ip_id="zero", fault_location="FW2")
    failures = [f for f in report["sessions"]["failed_handshakes"] if f["direction"] == "reverse"]
    assert failures and {(f["point_a"], f["point_b"]) for f in failures} == {("fw2_out", "fw2_in")}
    assert all(any(e["point"] == "drop" for e in f["evidence"]) for f in failures)


def test_bucket_evidence_api_and_input_validation(scenarios):
    from fastapi.testclient import TestClient
    from packetbreaker.app import create_app

    project, truth, _, _ = scenarios("security", ip_id="zero", fault_location="FW2")
    with TestClient(create_app(project.path), base_url="http://127.0.0.1") as client:
        result = client.get(
            f"/api/sessions/evidence?point=client&start={truth['base'] + 16}&end={truth['base'] + 17}"
        )
        assert result.status_code == 200
        assert result.json()["evidence"] and all(e["content_filter"] for e in result.json()["evidence"])
        assert client.get("/api/sessions/evidence?point=wrong&start=1&end=2").status_code == 422
        assert client.get("/api/sessions/evidence?point=client&start=nan&end=2").status_code == 422
        assert client.get("/api/sessions/evidence?point=client&start=3&end=2").status_code == 422


def test_established_session_closes_after_observation_timeout(scenarios, clone_project):
    shared, truth, topology, report = scenarios("security", ip_id="zero", fault_location="FW2")
    project = clone_project(shared)
    src = truth["populations"][1][0]["src"]
    with project.connect() as db:
        db.execute(
            "UPDATE obs SET corrected=corrected+12 WHERE point='client' AND (src=? OR dst=?) AND (flags&1)>0",
            [src, src],
        )
        build_lifecycle(db, Topology(**topology), report["coverage"], report["timeseries"], report["window"])
        assert (
            db.execute(
                "SELECT status FROM session_lifecycle WHERE point='client' AND src=?", [src]
            ).fetchone()[0]
            == "closed"
        )


def test_no_syn_never_invents_empty_established_or_half_open_state(scenarios, clone_project):
    shared, _, topology, report = scenarios("healthy")
    project = clone_project(shared)
    with project.connect() as db:
        db.execute("DELETE FROM obs WHERE (flags&2)>0")
        data = build_lifecycle(
            db, Topology(**topology), report["coverage"], report["timeseries"], report["window"]
        )
        assert db.execute("SELECT count(*) FROM session_lifecycle").fetchone()[0] == 0
        assert all(p["status"] == "unknown" and p["syn_sent"] is None for p in data["points"])
        assert all(b["half_open"] is None for b in data["buckets"])


def test_late_healthy_handshake_is_counted_after_half_open_expiry(scenarios, clone_project):
    shared, truth, topology, report = scenarios("security", ip_id="zero", fault_location="FW2")
    project = clone_project(shared)
    src = truth["populations"][1][0]["src"]
    with project.connect() as db:
        db.execute(
            "UPDATE obs SET corrected=corrected+12 WHERE point='client' AND (src=? OR dst=?) AND flags<>2",
            [src, src],
        )
        build_lifecycle(db, Topology(**topology), report["coverage"], report["timeseries"], report["window"])
        assert db.execute(
            "SELECT established>start+10,synack>start+10 FROM session_lifecycle WHERE point='client' AND src=?",
            [src],
        ).fetchone() == (True, True)
