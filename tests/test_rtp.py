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


def test_jitter_matches_header_oracle_and_missing_dynamic_clock_is_unknown(scenarios, clone_project):
    from packetbreaker.rtp import build_rtp
    from packetbreaker.topology import Topology

    project, _, topology, report = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    with project.connect() as db:
        packets = db.execute(
            "SELECT ts,stamp,jitter_ms FROM rtp_packets WHERE point='client' AND direction='forward' AND ssrc=286331153 ORDER BY flow,rn"
        ).fetchall()
        flow_packets = db.execute(
            "SELECT ts,stamp,jitter_ms FROM rtp_packets WHERE point='client' AND direction='forward' AND flow=(SELECT min(flow) FROM rtp_packets WHERE point='client' AND direction='forward') ORDER BY rn"
        ).fetchall()
    jitter = 0
    for i, (arrival, stamp, measured) in enumerate(flow_packets):
        if i:
            previous = flow_packets[i - 1]
            delta = ((stamp - previous[1] + 2**31) % 2**32) - 2**31
            jitter += (abs((arrival - previous[0]) * 8000 - delta) - jitter) / 16
        assert measured == pytest.approx(jitter / 8, abs=1e-9)
    assert packets
    clone = clone_project(project)
    with clone.connect() as db:
        db.execute('UPDATE udp_decoded SET "rtp.p_type"=\'96\',"sdp.media_attr"=NULL')
        rtp, _ = build_rtp(db, Topology.model_validate(topology), report["segments"], report["clocks"])
        assert rtp["streams"] and all(
            s["jitter_p95_ms"] is None and "clock rate unknown" in s["reason"] for s in rtp["streams"]
        )


def test_rtp_selected_window_and_uncertain_clock_do_not_blame_receiver(scenarios, clone_project):
    from copy import deepcopy
    from packetbreaker.rtp import build_rtp
    from packetbreaker.topology import Topology

    shared, _, topology, report = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    clone = clone_project(shared)
    clocks = deepcopy(report["clocks"])
    for c in clocks.values():
        c["uncertainty"] = None
    with clone.connect() as db:
        rtp, findings = build_rtp(
            db,
            Topology.model_validate({**topology, "start": 1700000020.2, "end": 1700000020.4}),
            report["segments"],
            clocks,
        )
        assert not findings
        assert rtp["streams"]
        assert db.execute(
            "SELECT min(corrected)>=1700000020.2 AND max(corrected)<=1700000020.4 FROM rtp_input"
        ).fetchone()[0]


def test_media_content_filters_are_tshark_decodable(scenarios, tshark):
    import subprocess

    project, truth, topology, report = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    kinds = ("rtp_loss", "sdp_media_mismatch")
    refs = [next(f for f in report["findings"] if f["type"] == kind)["evidence"][0] for kind in kinds]
    assert all(r.get("protocol_identity") and r["flow_filter"] and r["display_filter"] for r in refs)
    expr = " || ".join("(" + r["content_filter"] + ")" for r in refs)
    cmd = [tshark, "-n", "-r", truth["files"][0], "-Y", expr, "-T", "fields", "-e", "frame.number"]
    for a, b in topology["rtp_port_ranges"]:
        cmd += ["-d", f"udp.port=={a}-{b},rtp"]
    output = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    frames = {int(v) for v in output.split()}
    assert {r["frame"] for r in refs} <= frames


def test_sdp_ports_enable_decode_without_explicit_range(scenarios, clone_project):
    from packetbreaker.udp_index import index_udp
    from packetbreaker.topology import Topology
    from copy import deepcopy

    shared, _, topology, _ = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    topo = deepcopy(topology)
    topo["points"] = topo["points"][:1]
    topo["forward"] = ["client"]
    topo["reverse"] = []
    topo["nat_mappings"] = []
    topo["rtp_port_ranges"] = []
    clone = clone_project(shared)
    with clone.connect() as db:
        statuses = index_udp(clone, db, Topology.model_validate(topo))
        assert statuses and all(s["reason"] is None for s in statuses)
        assert (
            db.execute(
                "SELECT count(*) FROM udp_decoded WHERE point='client' AND \"rtp.version\"='2'"
            ).fetchone()[0]
            > 0
        )
