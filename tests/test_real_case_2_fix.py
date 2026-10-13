import random
import pytest
from packetbreaker.clock import fit_clock


def test_real_infeasibility_is_not_hidden_by_jitter():
    samples = [(float(i), i + (0.02 if f else 0.06), f) for i in range(100) for f in (True, False)]
    assert fit_clock(samples).offset is None
    assert fit_clock([s for s in samples if s[2]]).offset is None


def test_correlated_host_jitter_keeps_robust_clock_offset():
    rng = random.Random(923)
    samples = []
    for i in range(2000):
        if i % 20 == 0:
            jitter = rng.uniform(-0.00015, 0.00015)
        for forward in (True, False):
            t = 1700000000 + i * 0.02
            delay = (0.1 + (i % 4) * 0.3) if 600 < i < 1225 and i % 7 == 0 else 0.00002
            samples.append((t, t + 0.04 + jitter + (delay if forward else -delay), forward))
    model = fit_clock(samples)
    assert model.offset is not None
    assert abs(model.offset - 0.04) < 0.0001
    assert model.timestamp_jitter > 0 and model.uncertainty > 0


@pytest.mark.parametrize("ip_id,ipv6", [("zero", False), ("constant", True)])
def test_host_jitter_without_adjacent_mirror(tmp_path, tshark, ip_id, ipv6):
    from pathlib import Path
    from packetbreaker.pilot_synthetic import make_pilot
    from packetbreaker.batch_ingest import ingest_many
    from packetbreaker.store import Project
    from packetbreaker.synthetic import bind_capture_ids
    from packetbreaker.analysis import analyze

    truth, topology = make_pilot(tmp_path / "wire", host_jitter_us=150, ip_id=ip_id, ipv6=ipv6)
    project = Project(tmp_path / "project")
    ids = ingest_many(project, truth["files"], tshark=tshark, workers=4)
    bind_capture_ids(topology, {Path(f).name: c for f, c in zip(truth["files"], ids)})
    topology["forward"] = ["a_rx", "a_tx", "host"]
    topology["reverse"] = ["host", "a_rx", "a_tx"]
    topology["points"] = [p for p in topology["points"] if p["id"] in topology["forward"]]
    report = analyze(project, topology)
    clock = report["clocks"][ids[-1]]
    assert clock["offset"] is not None and abs(clock["offset"] - 0.04) < 0.0001
    assert {r["direction"] for r in report["host_path"]["items"]} == {"rx", "tx"}
    assert report["verdict"].startswith("Delay occurs between")
    for r in report["host_path"]["items"]:
        assert abs(r["window"]["start"] - truth["start"]) <= 1
        assert abs(r["window"]["end"] - truth["end"]) <= 1
    assert report["host_path"]["local_service"]["p95_ms"] < 1
