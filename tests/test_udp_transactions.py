import pytest


@pytest.mark.parametrize("fault_location", ["FW1", "FW2", "link"])
@pytest.mark.parametrize("ip_id,ipv6", [("zero", False), ("constant", False), ("zero", True)])
def test_udp_identity_ambiguity_capture_miss_and_oneway_first(scenarios, fault_location, ip_id, ipv6):
    project, truth, _, report = scenarios(
        "udp_transactions", fault_location=fault_location, ip_id=ip_id, ipv6=ipv6
    )
    with project.connect() as db:
        rows = db.execute(
            "SELECT protocol,status,latency_ms,hop FROM udp_transactions WHERE point='client' ORDER BY ts"
        ).fetchall()
    assert [r[1] for r in rows[:7]] == [
        "answered",
        "answered",
        "answered",
        "no_response_expected",
        "answered",
        "unknown",
        "unknown",
    ]
    assert [r[0] for r in rows[:4]] == ["NTP", "SNMP", "RADIUS", "SYSLOG"]
    assert rows[0][2] == pytest.approx(47.1, abs=0.01)
    assert rows[1][2] == pytest.approx(73.1, abs=0.01)
    assert rows[7][1] == "answered" and rows[7][3] is None  # intermediate capture miss, not network loss
    assert rows[8][1] == "unanswered" and rows[8][3] == truth["expected_response_hop"]
    assert rows[9][1] == "answered" and rows[9][3] is None
    assert report["udp"]["items"] and all(i["evidence"] and i["tooltip"] for i in report["udp"]["items"])
