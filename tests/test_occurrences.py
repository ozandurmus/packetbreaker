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
        actual[f["type"]] += f["metrics"]["count"]
    assert actual == expected
    assert all(s["loss_percent"] is not None for s in report["segments"])
    if scenario in ("recovered_loss", "impactful_loss"):
        assert sum(actual.values()) == 10
        assert {f["hop"] for f in report["findings"]} == {"forward:p2:p3"}
        with project.connect() as db:
            counts = db.execute(
                "SELECT point,count(*) FROM obs WHERE eligible AND length>0 GROUP BY point"
            ).fetchall()
            assert all(n >= 200 for _, n in counts)
