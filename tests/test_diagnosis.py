from packetbreaker.transport import classify


def facts(**changes):
    result = dict(
        handshake=True,
        indexed=True,
        trusted=True,
        samples=20,
        ack_samples=12,
        zero_windows=0,
        zero_span_ms=0,
        window_shrinks=0,
        window_full=0,
        blocked_samples=0,
        probes=0,
        open_samples=16,
        idle_gaps=0,
        ack_delay_p95_ms=5,
        loss_count=0,
        loss_stall_ms=0,
        loss_hop=None,
        path_p95_ms=2,
        path_samples=20,
        path_complete=True,
        rtt_degraded=False,
        path_degraded=False,
        service_ms=None,
        service_samples=0,
        stall_ms=200,
        sender_captured=True,
        receiver_captured=True,
        receiver_window_evidence=True,
    )
    return {**result, **changes}


def test_single_counter_and_quality_guards_first():
    for values in [
        dict(zero_windows=1),
        dict(rtt_degraded=True),
        dict(zero_windows=5, zero_span_ms=600),
        dict(handshake=False, zero_windows=5, zero_span_ms=600, blocked_samples=5),
        dict(trusted=False, loss_count=5, loss_stall_ms=1200),
        dict(indexed=False),
        dict(sender_captured=False, idle_gaps=8),
        dict(path_complete=False, idle_gaps=8),
    ]:
        result = classify(facts(**values))
        assert result["classification"] == "unknown", result
        assert result["reason"]


def test_independent_evidence_and_competing_causes():
    receiver = facts(zero_windows=3, zero_span_ms=500, window_shrinks=2, blocked_samples=4, probes=1)
    assert classify(receiver)["classification"] == "receiver-limited"
    assert classify(facts(idle_gaps=4))["classification"] == "sender/application-limited"
    assert (
        classify(facts(service_ms=800, service_samples=2))["classification"] == "sender/application-limited"
    )
    assert (
        classify(facts(loss_count=3, loss_stall_ms=1200, loss_hop="forward:fw_out:lb_in"))["classification"]
        == "network-limited (loss/RTT)"
    )
    assert (
        classify(facts(rtt_degraded=True, path_degraded=True))["classification"]
        == "network-limited (loss/RTT)"
    )
    assert classify({**receiver, "loss_count": 5, "loss_stall_ms": 1200})["classification"] == "unknown"
    # A slow ACK at the receiver cannot be reassigned to a link from RTT alone.
    assert (
        classify(facts(rtt_degraded=True, path_degraded=True, ack_delay_p95_ms=180))["classification"]
        == "unknown"
    )


def test_real_index_profile_without_inventing_limitation(scenarios):
    from packetbreaker.transport import profiles

    project, _, _, report = scenarios("healthy")
    from packetbreaker.analysis import flow_page

    flow = flow_page(project)["items"][0]["flow"]
    result = profiles(project, flow)
    assert {p["classification"] for p in result["items"]} == {"unknown"}
    assert all(p["metrics"]["handshake"] for p in result["items"])
    assert all(p["evidence"] for p in result["items"])
    assert report["findings"] == []
