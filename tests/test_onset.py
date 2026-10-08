from packetbreaker.onset import detect_series


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
