import pytest
from packetbreaker.analysis import analyze


@pytest.mark.parametrize("fault_location", ["FW1", "FW2", "link"])
@pytest.mark.parametrize("ip_id,ipv6", [("zero", False), ("constant", False), ("zero", True)])
def test_expected_rewrite_is_not_alg_bug_and_wrong_sdp_is_exact(scenarios, fault_location, ip_id, ipv6):
    _, truth, _, report = scenarios("udp_transactions", fault_location=fault_location, ip_id=ip_id, ipv6=ipv6)
    rows = report["sip"]["comparisons"]
    changes = [c for c in rows if c["changes"]]
    assert changes and all(
        c["device"] == (fault_location if fault_location != "link" else None) for c in changes
    )
    mismatch = [
        f for f in report["findings"] if f["type"] == "sdp_media_mismatch" and f["confidence"] == "supported"
    ]
    assert mismatch and {f["device"] for f in mismatch} == {
        fault_location if fault_location != "link" else None
    }
    assert all(f["metrics"]["call_id"] == truth["bad_call"] for f in mismatch)
    assert not any(
        f["type"] == "sdp_media_mismatch" and f["metrics"]["call_id"] == truth["healthy_call"]
        for f in report["findings"]
    )
    one_way = [
        f for f in report["findings"] if f["type"] == "one_way_audio" and f["confidence"] == "supported"
    ]
    assert {f["metrics"]["call_id"] for f in one_way} == {truth["bad_call"], truth["healthy_call"]}
    assert all(f["evidence"] and f["tooltip"] for f in mismatch + one_way)


def test_undeclared_rewrite_names_actual_fw_not_other_fw(scenarios, clone_project):
    shared, _, topology, _ = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    from copy import deepcopy

    topology = deepcopy(topology)
    project = clone_project(shared)
    for p in topology["points"]:
        if p["device"] == "FW2":
            p["payload_transform"] = "none"
    report = analyze(project, topology)
    rewritten = [
        f for f in report["findings"] if f["type"] == "sip_rewritten" and f["confidence"] == "supported"
    ]
    assert rewritten and {f["device"] for f in rewritten} == {"FW2"}
    assert all(f["summary"] == "SIP rewritten by FW2 (not declared)" for f in rewritten)


def test_missing_endpoint_and_uncertain_clocks_never_claim_media_failure(scenarios, clone_project):
    from copy import deepcopy
    from packetbreaker.sip import build_sip
    from packetbreaker.topology import Topology

    shared, _, topology, report = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    project = clone_project(shared)
    with project.connect() as db:
        db.execute("DELETE FROM sip_messages WHERE point='client'")
        db.execute("DELETE FROM udp_decoded WHERE point='client' AND \"sip.Call-ID\" IS NOT NULL")
        sip, findings = build_sip(
            db, Topology.model_validate(topology), report["segments"], report["clocks"], []
        )
        assert not any(f["type"] == "sdp_media_mismatch" and f["direction"] == "forward" for f in findings)
        assert not sip["one_way"]
    clocks = deepcopy(report["clocks"])
    for c in clocks.values():
        c["uncertainty"] = None
    with shared.connect() as db:
        _, findings = build_sip(
            db,
            Topology.model_validate(topology),
            report["segments"],
            clocks,
            [f for f in report["findings"] if f["type"] == "rtp_loss"],
        )
        assert not findings


def test_sendonly_is_legitimate_not_one_way_failure(scenarios, clone_project):
    from packetbreaker.sip import build_sip
    from packetbreaker.topology import Topology

    shared, _, topology, report = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    project = clone_project(shared)
    with project.connect() as db:
        db.execute('UPDATE udp_decoded SET "sdp.media_attr"=\'sendonly\' WHERE "sip.Call-ID" IS NOT NULL')
        losses = [f for f in report["findings"] if f["type"] == "rtp_loss"]
        sip, findings = build_sip(
            db, Topology.model_validate(topology), report["segments"], report["clocks"], losses
        )
        assert not sip["one_way"] and not any(f["type"] == "one_way_audio" for f in findings)


@pytest.mark.parametrize("media_mode", ["healthy", "capture_miss"])
def test_healthy_rewriting_and_capture_misses_are_not_audio_failure(scenarios, media_mode):
    _, _, _, report = scenarios("udp_transactions", fault_location="FW2", ip_id="zero", media_mode=media_mode)
    media_types = {"rtp_loss", "rtp_jitter", "sdp_media_mismatch", "one_way_audio", "sip_rewritten"}
    assert not any(f["type"] in media_types and f["confidence"] == "supported" for f in report["findings"])
    assert not report["sip"]["one_way"]
    assert report["rtp"]["streams"]


def test_video_sdp_does_not_become_one_way_audio(scenarios, clone_project):
    from packetbreaker.sip import build_sip
    from packetbreaker.topology import Topology

    shared, _, topology, report = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    clone = clone_project(shared)
    with clone.connect() as db:
        db.execute('UPDATE udp_decoded SET "sdp.media.media"=\'video\' WHERE "sip.Call-ID" IS NOT NULL')
        _, findings = build_sip(
            db,
            Topology.model_validate(topology),
            report["segments"],
            report["clocks"],
            [f for f in report["findings"] if f["type"] == "rtp_loss"],
        )
        assert not any(f["type"] == "one_way_audio" for f in findings)
