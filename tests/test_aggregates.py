from pathlib import Path
from packetbreaker.reference import compare_reference


def test_missing_event_and_host_are_not_computed(scenarios):
    _, _, _, r = scenarios("healthy")
    assert r["cycles"]["total"] > 0
    assert r["cycles"]["event"]["total"] is None
    assert r["host_path"]["rx_share"] is None
    assert r["host_path"]["max_silence_ms"] is None
    result = compare_reference(
        r,
        dict(
            items=[
                dict(
                    id="gap",
                    description="No host capture",
                    metric="$.host_path.max_silence_ms",
                    expected=0,
                    check={"max": 0},
                )
            ]
        ),
    )
    assert result["items"][0]["status"] == "not-computed"


def test_rto_repeat_groups_and_peak_use_one_point(tmp_path, tshark):
    from packetbreaker.pilot_synthetic import make_pilot
    from packetbreaker.batch_ingest import ingest_many
    from packetbreaker.synthetic import bind_capture_ids
    from packetbreaker.store import Project
    from packetbreaker.analysis import analyze

    truth, t = make_pilot(tmp_path / "wire", flows=2, real_case=True, ip_id="increment", host_jitter_us=150)
    p = Project(tmp_path / "project")
    ids = ingest_many(p, truth["files"], tshark=tshark, workers=4)
    bind_capture_ids(t, {Path(f).name: c for f, c in zip(truth["files"], ids)})
    r = analyze(p, t)
    assert r["cycles"]["repeat_groups"]["forward"] >= 4 and r["cycles"]["repeat_groups"]["reverse"] >= 4
    peak = r["onsets"]["analysis"]["retrans_peak"]
    assert (
        peak["point"] == "host"
        and truth["start"] - 1 <= peak["time"] <= truth["end"] + 1
        and peak["count"] > 0
    )
    with p.connect() as db:
        measured = db.execute(
            "SELECT count(*) FROM obs WHERE point='host' AND retrans AND eligible AND floor(corrected)=?",
            [peak["time"]],
        ).fetchone()[0]
    assert peak["count"] == measured
    assert peak["evidence"] and r["cycles"]["max_added"]["evidence"]
