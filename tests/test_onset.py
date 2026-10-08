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
    forward = [x for x in detected if x["direction"] == "forward" and x["scope"] == "network_segment"]
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
            loss_count=round(v * 20 / 100),
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
    assert detect_series(capture, "loss_percent", 1)[0]["bucket"] == 6


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


@pytest.mark.parametrize("interval", [2, 3, 4, 5])
def test_rolling_loss_keeps_first_intermitttent_bucket(interval):
    values = series([0] * 45)
    for row in values[8::interval]:
        row.update(loss_count=1, loss_percent=5)
    onset, _ = detect_series(values, "loss_percent", 0)
    assert onset["bucket"] == 8
    assert onset["confirmed_bucket"] == 8 + interval * 2
    assert onset["window_events"] == 3


@pytest.mark.parametrize("scenario", ["demo", "recovered_loss", "impactful_loss"])
def test_readme_and_existing_loss_onsets(scenarios, scenario):
    from packetbreaker.analysis import analyze

    project, truth, topology, report = scenarios(scenario)
    if scenario == "demo":
        topology = {
            **topology,
            "nat_mappings": [
                {k: s[k] for k in ("point_a", "point_b", "tuple_a", "tuple_b")}
                for s in report["nat_suggestions"]
            ],
        }
        report = analyze(project, topology)
    first = min(e["time"] for e in truth["events"] if e["type"] in ("recovered_loss", "impactful_loss"))
    onset = next(
        o
        for o in report["onsets"]["items"]
        if o["segment"] == "forward:p2:p3" and o["metric"] == "loss_percent"
    )
    assert abs(onset["time"] - first) <= 1
    assert onset["evidence"] and onset["window_events"] >= 3


@pytest.mark.parametrize(
    "scenario", [f"onset_intermittent_{n}" for n in (2, 3, 4, 5)] + ["onset_random_loss"]
)
@pytest.mark.parametrize("ipv6", [False, True])
def test_sparse_capture_fixtures(scenarios, scenario, ipv6):
    _, truth, _, report = scenarios(scenario, ipv6=ipv6, ip_id="zero", loss_hop=1)
    expected = truth["onsets"][0]
    onset = next(
        o
        for o in report["onsets"]["items"]
        if o["segment"] == expected["segment"] and o["metric"] == "loss_percent"
    )
    assert abs(onset["time"] - expected["time"]) <= 1
    assert onset["evidence"]


def test_quality_notes_do_not_poison_baseline_or_invent_loss():
    values = series([0] * 8 + [20, 20, 20])
    for row in values:
        row.update(capture_misses=2, unknown_events=1, reason="capture quality note")
    onset, _ = detect_series(values, "loss_percent", 0)
    assert onset["bucket"] == 8
    for row in values:
        row.update(loss_count=0, loss_percent=0)
    onset, reason = detect_series(values, "loss_percent", 0)
    assert onset is None and not reason.startswith("unknown:")


def test_unknown_segments_do_not_overrule_valid_results():
    from packetbreaker.onset import status_summary

    status, counts, summary = status_summary([{"onset_status": "none"}, {"onset_status": "unknown"}])
    assert status == "partial" and counts == {"none": 1, "unknown": 1}
    assert not summary.startswith("Onset unknown") and "1 segment(s) have unknown" in summary
    assert status_summary([{"onset_status": "unknown"}])[0] == "unknown"


@pytest.mark.parametrize(
    "metric,count_key,denominator",
    [
        ("retrans_percent", "retransmissions", "tcp_packets"),
        ("failed_handshakes", "failed_handshake_count", None),
        ("resets", "resets", None),
        ("zero_windows", "zero_windows", None),
    ],
)
def test_count_signals_require_multiple_excess_events(metric, count_key, denominator):
    values = series([0] * 40)
    for row in values:
        row[count_key] = 0
        if denominator:
            row[denominator] = 100
    values[8][count_key] = 1
    assert detect_series(values, metric, 0)[0] is None
    values[8][count_key] = 10  # A single bucket spike is not sustained.
    assert detect_series(values, metric, 0)[0] is None
    values[8][count_key] = 1
    values[12][count_key] = 1
    values[16][count_key] = 1
    onset, _ = detect_series(values, metric, 0)
    assert onset["bucket"] == 8 and onset["window_events"] == 3
    assert onset["count_threshold"] == 3 and onset["event_buckets"] == 3


def test_counter_reference_is_not_backdated_into_baseline():
    values = series([0] * 20)
    for row, count in zip(values, [1, 0, 1, 0, 1, 3, 3] + [0] * 13):
        row["resets"] = count
    onset, _ = detect_series(values, "resets", 0)
    assert onset["bucket"] == 5 and onset["baseline_value"] == pytest.approx(0.6)


def test_tcp_signal_counts_and_frame_evidence(scenarios):
    _, truth, _, report = scenarios("onset_signals", ip_id="zero", ipv6=True, loss_hop=1)
    expected = {"retrans_percent", "failed_handshakes", "resets", "zero_windows"}
    for metric in expected:
        onset = next(o for o in report["onsets"]["items"] if o["metric"] == metric)
        assert abs(onset["time"] - (truth["reference_epoch"] + 12.1)) <= 1
        assert onset["window_events"] >= 3 and onset["evidence"]
        if metric != "failed_handshakes":
            assert onset["scope"] == "capture_signal"
            assert "not evidence that this hop" in onset["explanation"]
    assert report["onsets"]["directions"]["forward"]["prime_suspects"] == ["forward:p1:p2"]
