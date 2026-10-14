"""Synthetic >=586k-frame acceptance under forced and adaptive memory budgets."""

import json
from pathlib import Path
import sys
import time
from packetbreaker.pilot_synthetic import make_pilot
from packetbreaker.batch_ingest import ingest_many
from packetbreaker.synthetic import bind_capture_ids
from packetbreaker.store import Project, memory_budget_mb
from packetbreaker.analysis import analyze

root = Path(sys.argv[1])
if "--reuse" in sys.argv:
    truth = json.loads((root / "wire" / "ground-truth.json").read_text(encoding="utf-8"))
    topology = json.loads((root / "wire" / "topology.json").read_text(encoding="utf-8"))
else:
    truth, topology = make_pilot(
        root / "wire",
        flows=56,
        rounds=200,
        host_jitter_us=150,
        real_case=True,
        ip_id="increment",
        opaque=True,
    )
p = Project(root / "project", memory_limit_mb=512)
t = time.monotonic()
ids = ingest_many(p, truth["files"], workers=4)
bind_capture_ids(topology, {Path(f).name: c for f, c in zip(truth["files"], ids)})
with p.connect() as db:
    frames = db.execute("SELECT count(*) FROM packets").fetchone()[0]
assert frames >= 586000, frames
print(json.dumps(dict(frames=frames, ingest_s=time.monotonic() - t)), flush=True)
for limit in (512, None):
    p.memory_limit_mb = limit
    t = time.monotonic()
    report = analyze(p, topology, progress=lambda **v: print(v, flush=True))
    assert report["flow_count"] == 56
    assert report["host_path"]["items"]
    assert all(s["reason"] is None for s in report["application_status"]), report["application_status"]
    with p.connect() as db:
        indexed = db.execute("SELECT count(*) FROM tcp_point_analysis").fetchone()[0]
    assert indexed > 0
    print(
        json.dumps(
            dict(
                memory_limit_mb=memory_budget_mb(limit),
                analysis_s=time.monotonic() - t,
                flows=report["flow_count"],
                indexed_tcp_frames=indexed,
                host_findings=len(report["host_path"]["items"]),
            )
        ),
        flush=True,
    )
