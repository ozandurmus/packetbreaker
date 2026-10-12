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
