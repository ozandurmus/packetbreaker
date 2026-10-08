import pytest
from packetbreaker.onset import detect_series
from packetbreaker.timeseries import timeseries_page


@pytest.mark.parametrize("scenario", ["onset_loss", "onset_delay", "onset_propagation", "onset_capture_miss"])
@pytest.mark.parametrize(
    "ip_id,ipv6", [("zero", False), ("constant", False), ("zero", True), ("constant", True)]
)
def test_ground_truth_onsets(scenarios, scenario, ip_id, ipv6):
    project, truth, topology, report = scenarios(scenario, ip_id=ip_id, ipv6=ipv6, loss_hop=1)
    detected = report["onsets"]["items"]
    forward = [x for x in detected if x["direction"] == "forward"]
    assert {(x["segment"], x["metric"]) for x in forward} == {
        (x["segment"], x["metric"]) for x in truth["onsets"]
    }
    for expected in truth["onsets"]:
        actual = next(
            x for x in detected if x["segment"] == expected["segment"] and x["metric"] == expected["metric"]
        )
        assert abs(actual["time"] - expected["time"]) <= report["timeseries"]["bucket_seconds"]
        assert actual["value"] > actual["threshold"] >= actual["baseline_value"]
        assert actual["evidence"] and all(e["frame"] > 0 for e in actual["evidence"])
        assert "first crossing bucket" in actual["explanation"]
        assert (
            "Change-point onset"
            in next(s for s in report["segments"] if s["id"] == actual["segment"])["headline"]
        )
    if scenario == "onset_capture_miss":
        assert not detected
        assert all(f["type"] == "capture_miss" for f in report["findings"])
    if scenario == "onset_propagation":
        order = report["onsets"]["directions"]["forward"]["propagation_order"]
        assert [g["segments"] for g in order] == [["forward:p1:p2"], ["forward:p2:p3"]]
        assert report["onsets"]["directions"]["forward"]["prime_suspects"] == ["forward:p1:p2"]
    data = timeseries_page(project)
    assert len(data["items"]) == 8 * data["bucket_count"]


def series(values):
    return [
        dict(
            bucket=i,
            start=i,
            end=i + 1,
            coverage="capturing",
            reason=None,
            eligible_packets=20,
            capture_misses=0,
            unknown_events=0,
            loss_percent=v,
        )
        for i, v in enumerate(values)
    ]


def test_detector_insufficient_and_unhealthy_baselines():
    for values in ([0] * 5, [5] * 20):
        onset, reason = detect_series(series(values), "loss_percent", 1)
        assert onset is None and reason.startswith("unknown:")


def test_detector_explains_first_crossing_and_rejects_isolated_spike():
    onset, _ = detect_series(series([0] * 6 + [20, 20, 20]), "loss_percent", 1)
    assert onset["bucket"] == 6 and onset["confirmed_bucket"] == 7
    assert onset["baseline_value"] == 0 and onset["threshold"] == 1
    assert detect_series(series([0] * 6 + [20, 0, 0]), "loss_percent", 1)[0] is None
    capture = series([0] * 6 + [30] * 3)
    for row in capture[6:]:
        row["capture_misses"] = 2
    assert detect_series(capture, "loss_percent", 1)[0] is None


@pytest.mark.parametrize("width", [0.5, 2.0])
def test_adjustable_bucket_onset_and_propagation(scenarios, width):
    from packetbreaker.analysis import analyze

    project, truth, topology, _ = scenarios("onset_propagation", ip_id="constant", ipv6=True, loss_hop=1)
    report = analyze(project, {**topology, "bucket_seconds": width})
    for expected in truth["onsets"]:
        actual = next(
            o
            for o in report["onsets"]["items"]
            if o["segment"] == expected["segment"] and o["metric"] == expected["metric"]
        )
        assert abs(actual["time"] - expected["time"]) <= width
    assert report["onsets"]["directions"]["forward"]["prime_suspects"] == ["forward:p1:p2"]
