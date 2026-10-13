import pytest


@pytest.mark.parametrize("fault_location", ["FW1", "FW2", "link"])
@pytest.mark.parametrize("ip_id,ipv6", [("zero", False), ("constant", False), ("zero", True)])
def test_rtp_capture_miss_collision_and_exact_loss_jitter(scenarios, fault_location, ip_id, ipv6):
    project, truth, _, report = scenarios(
        "udp_transactions", fault_location=fault_location, ip_id=ip_id, ipv6=ipv6
    )
    rtp = report["rtp"]
    loss = [f for f in report["findings"] if f["type"] == "rtp_loss" and f["confidence"] == "supported"]
    assert loss and {f["hop"] for f in loss} == {truth["rtp_loss_hop"], truth["expected_response_hop"]}
    assert all(
        f.get("device") == ("FW1" if fault_location == "FW1" else "FW2" if fault_location == "FW2" else None)
        for f in loss
    )
    jitter = [f for f in report["findings"] if f["type"] == "rtp_jitter" and f["confidence"] == "supported"]
    assert jitter and {f["device"] for f in jitter} == {"LB"}
    with project.connect() as db:
        healthy_flow = db.execute(
            "SELECT flow FROM obs WHERE point='client' AND proto='UDP' AND sport=40000 AND src=? LIMIT 1",
            ["2001:db8:1::2" if ipv6 else "10.1.0.2"],
        ).fetchone()[0]
    assert not any(
        f["type"] == "rtp_loss" and f["direction"] == "forward" and f["metrics"]["flow"] == healthy_flow
        for f in report["findings"]
    )
    with project.connect() as db:
        healthy = db.execute(
            "SELECT gaps FROM rtp_streams WHERE point='client' AND direction='forward' ORDER BY flow"
        ).fetchall()
        assert healthy == [(0,), (0,)]
        counts = db.execute(
            "SELECT count(DISTINCT flow) FROM rtp_streams WHERE point='client' AND ssrc=286331153 AND direction='forward'"
        ).fetchone()[0]
        assert counts == 2  # SSRC and ports collide across the two calls; tuple ownership is still distinct
    assert rtp["streams"] and all(s["evidence"] for s in rtp["streams"])
