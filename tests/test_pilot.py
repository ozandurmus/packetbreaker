from packetbreaker.topology import Topology


def stage_topology():
    points = []
    for name, device, side in [
        ("a_rx", "A", "ingress"),
        ("a_tx", "A", "egress"),
        ("b_rx", "B", "ingress"),
        ("b_tx", "B", "egress"),
        ("mirror", "Switch", "both"),
        ("host", "Server", "both"),
    ]:
        points.append(
            dict(id=name, label=name, device=device, side=side, capture_id=name, stage_capture=side != "both")
        )
    return dict(points=points, forward=[p["id"] for p in points])


def test_stage_order_is_rx_then_tx_in_both_directions():
    topology = Topology.model_validate(stage_topology())
    assert topology.forward == ["a_rx", "a_tx", "b_rx", "b_tx", "mirror", "host"]
    assert topology.reverse == ["host", "mirror", "b_rx", "b_tx", "a_rx", "a_tx"]
    assert topology.precedes("b_rx", "b_tx", "reverse")
    assert not topology.precedes("a_rx", "b_rx", "reverse")


def test_wire_interface_order_is_unchanged_and_stage_declaration_is_per_device():
    wire = stage_topology()
    for p in wire["points"]:
        p["stage_capture"] = False
    t = Topology.model_validate(wire)
    assert t.path("reverse") == list(reversed(t.forward))
    wire["points"][0]["stage_capture"] = True
    t = Topology.model_validate(wire)
    assert t.points[1].stage_capture
    assert t.path("reverse")[-2:] == ["a_rx", "a_tx"]


def test_shared_clock_inference_rejects_offset_delay_and_one_way():
    from packetbreaker.clock import infer_shared_clock

    samples = [(float(i), i + (0.00002 if f else -0.00002), f) for i in range(30) for f in (True, False)]
    assert infer_shared_clock(samples) is not None
    assert infer_shared_clock([(a, b + 0.1, f) for a, b, f in samples]) is None
    assert infer_shared_clock([(a, b, f) for a, b, f in samples if f]) is None
    assert infer_shared_clock([(a, a + (0.1 if f else -0.1), f) for a, b, f in samples]) is None


def test_declared_clock_domain_cannot_conflict_for_one_file():
    import pytest

    t = stage_topology()
    t["points"][0].update(clock_domain="x")
    t["points"][1].update(capture_id="a_rx", clock_domain="y")
    with pytest.raises(ValueError, match="clock domain"):
        Topology.model_validate(t)
