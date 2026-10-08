from collections import Counter
import pytest


@pytest.mark.parametrize(
    "scenario", ["syn_blocked", "unrecovered_reset", "unrecovered_stall", "control_capture_miss"]
)
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("mode", ["increment", "zero", "constant", "random"])
def test_control_and_unrecovered_outcomes(scenarios, scenario, ipv6, mode):
    _, truth, _, report = scenarios(scenario, ip_id=mode, ipv6=ipv6)
    expected = Counter(e["type"] for e in truth["events"])
    actual = Counter()
    for f in report["findings"]:
        actual[f["type"]] += f["metrics"]["count"]
        if f["type"] == "handshake_blocked":
            assert f["summary"] == "Handshake blocked between FW egress and LB ingress; cause unknown."
            assert f["severity"] == "high" and f["cause"] == "unknown"
        if scenario in ("unrecovered_reset", "unrecovered_stall") and f["type"] == "impactful_loss":
            assert len(f["evidence"]) > 3
            assert f["metrics"]["max_stall_ms"] is not None
    assert actual == expected


def test_control_capture_miss_direction_and_hop(scenarios):
    _, truth, _, report = scenarios("control_capture_miss")
    expected = Counter(
        (e["type"], e.get("direction", "forward"), e["point_a"], e["point_b"]) for e in truth["events"]
    )
    actual = Counter()
    for f in report["findings"]:
        direction, a, b = f["hop"].split(":")
        actual[(f["type"], direction, a, b)] += f["metrics"]["count"]
    assert actual == expected
