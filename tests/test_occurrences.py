from collections import Counter
import pytest
from packetbreaker.analysis import analyze

MODES = ["increment", "zero", "constant", "random"]
SCENARIOS = [
    "healthy",
    "demo",
    "capture_miss",
    "recovered_loss",
    "impactful_loss",
    "nat",
    "delay",
    "truncation",
    "duplicate",
    "acked_unseen",
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("ipv6", [False, True], ids=["IPv4", "IPv6"])
@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.slow
def test_every_scenario_every_ip_id_mode(scenarios, scenario, mode, ipv6):
    project, truth, topology, report = scenarios(scenario, ip_id=mode, ipv6=ipv6)
    if report["nat_suggestions"]:
        topology = {
            **topology,
            "nat_mappings": [
                {k: s[k] for k in ("point_a", "point_b", "tuple_a", "tuple_b")}
                for s in report["nat_suggestions"]
            ],
        }
        report = analyze(project, topology)
    expected = Counter(e["type"] for e in truth["events"])
    actual = Counter()
    for f in report["findings"]:
        if f["id"].startswith("integrity:"):
            assert scenario == "duplicate" and f["type"] == "capture_duplicate"
            continue
        actual[f["type"]] += f["metrics"]["count"]
    assert actual == expected
    if scenario != "duplicate":
        assert all(s["loss_percent"] is not None for s in report["segments"])
    if scenario in ("recovered_loss", "impactful_loss"):
        assert sum(actual.values()) == 10
        assert {f["hop"] for f in report["findings"]} == {"forward:p2:p3"}
        with project.connect() as db:
            counts = db.execute(
                "SELECT point,count(*) FROM obs WHERE eligible AND length>0 GROUP BY point"
            ).fetchall()
            assert all(n >= 200 for _, n in counts)


def test_balanced_occurrences_preserve_order_when_delay_changes():
    import duckdb
    from packetbreaker.matching import match_occurrences
    from packetbreaker.topology import Topology

    with duckdb.connect() as db:
        db.execute("""CREATE TABLE obs(point VARCHAR,frame BIGINT,base_key VARCHAR,flow VARCHAR,
            corrected DOUBLE,ts DOUBLE,direction VARCHAR,eligible BOOLEAN,packet_key VARCHAR,
            occurrence BIGINT,excluded_reason VARCHAR)""")
        for point, times in (("a", [0.0, 0.04]), ("b", [0.037, 0.044])):
            for frame, t in enumerate(times, 1):
                db.execute(
                    "INSERT INTO obs VALUES (?,?,'same','flow',?,?,'forward',true,'same',NULL,NULL)",
                    [point, frame, t, t],
                )
        db.execute("CREATE TEMP TABLE calibration AS SELECT * FROM obs WHERE false")
        topology = Topology(
            points=[dict(id=p, label=p, device=p, capture_id=p) for p in ("a", "b")], forward=["a", "b"]
        )
        match_occurrences(db, topology)
        assert db.execute("SELECT count(*) FROM obs WHERE NOT eligible").fetchone()[0] == 0
        assert (
            db.execute("""SELECT count(*) FROM obs a JOIN obs b USING(frame)
            WHERE a.point='a' AND b.point='b' AND a.packet_key=b.packet_key""").fetchone()[0]
            == 2
        )
