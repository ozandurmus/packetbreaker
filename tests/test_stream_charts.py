from packetbreaker.stream_charts import charts, frame_evidence
import pytest


def test_chart_bounds_handshake_scale_rates_and_evidence(scenarios):
    from packetbreaker.analysis import flow_page

    project, _, _, _ = scenarios("healthy")
    flow = flow_page(project)["items"][0]["flow"]
    result = charts(project, flow, point="p0", limit=20)
    assert len(result["packets"]) == 20 and result["total"] > 20
    assert any(p["receive_window"] is not None for p in result["packets"] if p["kind"] == "ack")
    assert any(b["throughput_bps"] for b in result["buckets"])
    frames = [p["frame"] for p in result["packets"][:3]]
    assert len(frame_evidence(project, flow, "p0", frames)) == 3
    start = result["packets"][2]["time"]
    end = result["packets"][8]["time"]
    brushed = charts(project, flow, point="p0", start=start, end=end)
    assert all(start <= p["time"] < end for p in brushed["packets"])
    assert any(b["throughput_bps"] is None for b in brushed["buckets"] if b["coverage"] != "capturing")
    with pytest.raises(ValueError):
        charts(project, flow, point="foreign")
