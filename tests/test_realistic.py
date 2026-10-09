from collections import Counter
import pytest

SCENARIOS = ["realistic_healthy", "realistic_capture_miss", "realistic_loss", "realistic_syn_blocked"]


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("mode", ["increment", "zero", "constant", "random"])
@pytest.mark.slow
def test_concurrent_protocols_and_asymmetric_path(scenarios, scenario, mode):
    project, truth, topology, report = scenarios(scenario, ip_id=mode, rounds=20)
    expected = Counter((e["type"], e["direction"], e["point_a"], e["point_b"]) for e in truth["events"])
    actual = Counter()
    for f in report["findings"]:
        direction, a, b = f["hop"].split(":")
        actual[(f["type"], direction, a, b)] += f["metrics"]["count"]
    assert actual == expected
    assert topology["reverse"] == ["p4", "p5", "p2", "p1", "p0"]
    with project.connect() as db:
        assert (
            db.execute("SELECT count(DISTINCT flow) FROM obs WHERE proto='TCP'").fetchone()[0]
            == truth["tcp_sessions"]
        )
        assert (
            db.execute(
                "SELECT count(DISTINCT src) FROM obs WHERE proto='TCP' AND direction='forward'"
            ).fetchone()[0]
            >= 50
        )
        assert db.execute("SELECT count(*) FROM obs WHERE proto='TCP' AND src LIKE '%:%'").fetchone()[0] > 0
        assert (
            db.execute("SELECT count(*) FROM obs WHERE proto='UDP' AND dns_id IS NOT NULL").fetchone()[0] > 0
        )
        assert db.execute("SELECT count(*) FROM obs WHERE proto='ICMP' AND icmp_type=8").fetchone()[0] > 0
        # An occurrence cannot join packets belonging to different directional tuples.
        assert (
            db.execute(
                "SELECT count(*) FROM (SELECT packet_key FROM obs WHERE eligible GROUP BY packet_key HAVING count(DISTINCT canon)>1)"
            ).fetchone()[0]
            == 0
        )
        assert (
            db.execute("SELECT count(*) FROM obs WHERE point='p3' AND direction='reverse'").fetchone()[0] == 0
        )
        assert (
            db.execute("SELECT count(*) FROM obs WHERE point='p5' AND direction='forward'").fetchone()[0] == 0
        )
    isb = next(c for c in project.inventory() if c["name"].endswith(".pcapng"))["inventory"]
    assert (isb["ifdrop"], isb["osdrop"]) == (7, 2)
    if scenario == "realistic_capture_miss":
        assert all(f["type"] == "capture_miss" for f in report["findings"])
        assert all(s["loss_percent"] == 0 for s in report["segments"])


@pytest.mark.slow
def test_all_clients_ipv6_variant(scenarios):
    project, truth, _, report = scenarios("realistic_capture_miss", ip_id="zero", ipv6=True, rounds=20)
    assert sum(f["metrics"]["count"] for f in report["findings"]) == len(truth["events"])
    assert all(f["type"] == "capture_miss" for f in report["findings"])
    with project.connect() as db:
        assert (
            db.execute("SELECT count(*) FROM obs WHERE proto='TCP' AND src NOT LIKE '%:%'").fetchone()[0] == 0
        )
