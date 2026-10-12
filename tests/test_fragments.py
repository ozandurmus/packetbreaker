from capture_realism_fixtures import fragment_path
import pytest
from packetbreaker.fragments import FRAGMENT_STATUS
import duckdb


def test_fragment_quality_precedes_matching():
    cases = [
        (1, 1, 1, 0, 1, "unknown"),
        (0, 0, 1, 0, 0, "unknown"),
        (0, 1, 1, 1, 0, "incomplete"),
        (0, 1, 1, 0, 1, "complete"),
    ]
    with duckdb.connect() as db:
        db.execute(
            "CREATE TABLE g(invalid INTEGER,starts INTEGER,tails INTEGER,gaps INTEGER,decoded INTEGER)"
        )
        for invalid, starts, tails, gaps, decoded, expected in cases:
            db.execute("DELETE FROM g")
            db.execute("INSERT INTO g VALUES (?,?,?,?,?)", [invalid, starts, tails, gaps, decoded])
            assert db.execute("SELECT " + FRAGMENT_STATUS + " FROM g").fetchone()[0] == expected


@pytest.fixture(
    scope="module", params=[(False, "zero"), (False, "constant"), (True, "zero"), (True, "constant")]
)
def fragment_capture(request, tmp_path_factory, scenarios):
    from conftest import _fragment_futures
    from packetbreaker.store import Project

    future = _fragment_futures.get(request.param)
    if future:
        path, truth, topology, report = future.result()
        return Project(path), truth, topology, report
    return fragment_path(tmp_path_factory.mktemp("fragments"), *request.param)


def test_wire_unknown_overlaps_and_capture_miss_first(fragment_capture):
    project, truth, _, report = fragment_capture
    with project.connect() as db:
        flow = db.execute(
            "SELECT flow FROM obs WHERE sport=? LIMIT 1", [truth["overlap"]["port"]]
        ).fetchone()[0]
        events = db.execute("SELECT kind,reason FROM events WHERE flow=?", [flow]).fetchall()
        assert events and all(kind == "unknown" for kind, reason in events), events
        assert db.execute("SELECT count(*) FROM fragment_groups WHERE status='unknown'").fetchone()[0] > 0
        flow = db.execute(
            "SELECT flow FROM obs WHERE sport=? LIMIT 1", [truth["capture_miss"]["port"]]
        ).fetchone()[0]
        kinds = db.execute("SELECT kind FROM events WHERE flow=?", [flow]).fetchall()
        assert kinds and set(k for (k,) in kinds) == {"capture_miss"}, kinds


def test_wire_complete_datagrams_exact_first_hop_and_single_loss(fragment_capture):
    project, truth, _, report = fragment_capture
    for case in ("FW", "LB", "link"):
        with project.connect() as db:
            flow = db.execute("SELECT flow FROM obs WHERE sport=? LIMIT 1", [truth[case]["port"]]).fetchone()[
                0
            ]
            counts = db.execute(
                "SELECT point,count(*) FROM obs WHERE flow=? AND raw_seq=? AND length>0 GROUP BY point",
                [flow, truth[case]["seq"]],
            ).fetchall()
            assert len(counts) == 6 and all(n == 1 for p, n in counts), counts
        found = [f for f in report["findings"] if f["type"] == "fragmentation" and f["flow"] == flow]
        assert len(found) == 1, found
        assert (
            found[0]["hop"]
            == {"FW": "forward:fw_in:fw_out", "LB": "forward:lb_in:lb_out", "link": "forward:fw_out:lb_in"}[
                case
            ]
        )
        assert found[0]["device"] == (case if case != "link" else None)
        assert len(found[0]["evidence"]) >= 4 and all(r["content_filter"] for r in found[0]["evidence"])
    with project.connect() as db:
        flow = db.execute(
            "SELECT flow FROM obs WHERE sport=? LIMIT 1", [truth["lost_middle"]["port"]]
        ).fetchone()[0]
        events = db.execute("SELECT point_a,point_b,kind FROM events WHERE flow=?", [flow]).fetchall()
        assert events == [("lb_in", "lb_out", "unrecovered_loss")], events


def test_fragment_evidence_filters_and_unknown_clocks(fragment_capture, tshark):
    import subprocess
    from collections import defaultdict
    from packetbreaker.fragments import fragment_findings

    project, _, topology, report = fragment_capture
    refs = next(f["evidence"] for f in report["findings"] if f["type"] == "fragmentation")
    files = defaultdict(list)
    for ref in refs:
        files[ref["capture_id"]].append(ref)
    with project.connect() as db:
        for cid, group in files.items():
            path = db.execute("SELECT path FROM captures WHERE id=?", [cid]).fetchone()[0]
            filt = " || ".join("(" + ref["content_filter"] + ")" for ref in group)
            result = subprocess.run(
                [tshark, "-n", "-2", "-r", path, "-Y", filt, "-T", "fields", "-e", "frame.number"],
                check=True,
                capture_output=True,
                text=True,
            )
            assert {int(n) for n in result.stdout.split()} == {r["frame"] for r in group}
        from packetbreaker.topology import Topology

        missing_clock = [{**s, "loss_percent": None} for s in report["segments"]]
        assert fragment_findings(db, Topology.model_validate(topology), missing_clock)[0] == []
