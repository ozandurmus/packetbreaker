import pytest
from capture_realism_fixtures import burst_path


from packetbreaker.microbursts import associations
from packetbreaker.clock import ClockModel


def test_burst_is_never_a_proven_loss_cause_and_clock_order_is_unknown():
    burst = dict(point="fw_out", end=12.0)
    onset = dict(
        point_a="fw_out",
        metric="loss_percent",
        segment="forward:fw_out:lb_in",
        time=12.0,
        end=13.0,
        clock_uncertainty_ms=0,
        evidence=[dict(point="fw_out", corrected_time=12.01, frame=10)],
    )
    assert associations(burst, [], ClockModel(offset=0, uncertainty=0)) == []
    assert associations(burst, [onset], ClockModel()) == []
    assert associations(burst, [onset], ClockModel(offset=0)) == []
    assert associations(burst, [{**onset, "point_a": "lb_in"}], ClockModel(offset=0, uncertainty=0)) == []
    found = associations(burst, [onset], ClockModel(offset=0, uncertainty=0))
    assert found[0]["cause"] == "unknown" and found[0]["relation"] == "corroboration_only"
    uncertain = associations(burst, [onset], ClockModel(offset=0, uncertainty=0.02))
    assert uncertain[0]["ordering"] == "unknown"


@pytest.fixture(scope="module", params=[(False, "zero"), (True, "constant")])
def burst_capture(request, tmp_path_factory):
    return burst_path(tmp_path_factory.mktemp("bursts"), *request.param)


def test_wire_no_loss_bursts_are_not_causes(burst_capture):
    _, truth, _, report = burst_capture
    burst = report["microbursts"]
    assert burst["total"] == 12 and len(burst["points"]) == 6, burst
    early = [b for b in burst["items"] if b["start"] < 1700000010]
    assert len(early) == 6 and all(not b["loss_associations"] and b["cause"] == "unknown" for b in early)
    near = [b for b in burst["items"] if b["start"] > 1700000010]
    associations = [a for b in near for a in b["loss_associations"]]
    assert {a["segment"] for a in associations} == set(truth["loss_hops"]), report["onsets"]
    assert all(a["relation"] == "corroboration_only" and a["cause"] == "unknown" for a in associations)
    assert all(
        b["evidence"] and b["duration_ms"] > 0 and b["min_interarrival_us"] > 0 for b in burst["items"]
    )


def test_peak_matches_tshark_frame_lengths_and_timestamps(burst_capture, tshark):
    import subprocess
    from collections import deque

    project, _, _, report = burst_capture
    with project.connect() as db:
        file = db.execute(
            "SELECT c.path FROM captures c JOIN wire_observations w ON w.capture_id=c.id WHERE point='fw_out' LIMIT 1"
        ).fetchone()[0]
    decoded = subprocess.run(
        [tshark, "-n", "-r", file, "-T", "fields", "-e", "frame.time_epoch", "-e", "frame.len"],
        capture_output=True,
        text=True,
        check=True,
    )
    records = [(float(ts), int(size)) for ts, size in (line.split() for line in decoded.stdout.splitlines())]
    selected = [r for r in records if report["window"]["start"] <= r[0] <= report["window"]["end"]]
    q = deque()
    bits = 0
    peak = 0
    for ts, size in selected:
        q.append((ts, size))
        bits += size * 8
        while q and q[0][0] < ts - 0.001:
            bits -= q.popleft()[1] * 8
        peak = max(peak, bits / 0.001 / 1e6)
    observed = next(p for p in report["microbursts"]["points"] if p["point"] == "fw_out")
    assert observed["peak_observed_mbps"] == pytest.approx(peak, rel=1e-6)
    assert observed["frequency_hz"] == pytest.approx(2 / observed["observed_seconds"])


def test_window_is_configurable_and_span_copies_do_not_create_bursts(burst_capture):
    from packetbreaker.microbursts import build_microbursts
    from packetbreaker.topology import Topology

    project, _, raw, report = burst_capture
    models = {
        cid: ClockModel(**{k: v for k, v in m.items() if k in ClockModel.__dataclass_fields__})
        for cid, m in report["clocks"].items()
    }
    with project.connect() as db:
        wide = build_microbursts(
            db, Topology.model_validate({**raw, "microburst_window_ms": 10}), models, report["onsets"]
        )
        assert wide["window_ms"] == 10 and wide["total"] > 0
        assert max(p["peak_observed_mbps"] for p in wide["points"]) < max(
            p["peak_observed_mbps"] for p in report["microbursts"]["points"]
        )
        # These are physical SPAN copies, not a traffic burst: same bytes within 20 us.
        db.execute("CREATE OR REPLACE TABLE saved_wire AS SELECT * FROM wire_observations")
        try:
            db.execute(
                "UPDATE wire_observations SET frame_hash='same-full-frame',ts=1700000000+frame*0.000001,wirelen=caplen"
            )
            repeated = build_microbursts(db, Topology.model_validate(raw), models, report["onsets"])
            assert repeated["total"] == 0
        finally:
            db.execute("CREATE OR REPLACE TABLE wire_observations AS SELECT * FROM saved_wire")
