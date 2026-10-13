"""Requested >=2M-frame synthetic regression; run with /usr/bin/time -l."""

import json
from pathlib import Path
import sys
import time
from packetbreaker.pilot_synthetic import make_pilot
from packetbreaker.batch_ingest import ingest_many
from packetbreaker.store import Project
from packetbreaker.synthetic import bind_capture_ids
from packetbreaker.analysis import analyze

root = Path(sys.argv[1])
t = time.monotonic()
truth, topology = make_pilot(
    root / "wire", flows=50, rounds=750, real_case=True, ip_id="increment", host_jitter_us=150
)
print("generated", time.monotonic() - t, flush=True)
project = Project(root / "project")
t = time.monotonic()
ids = ingest_many(project, truth["files"], workers=4)
print("ingest_seconds", time.monotonic() - t, flush=True)
bind_capture_ids(topology, {Path(f).name: c for f, c in zip(truth["files"], ids)})
with project.connect() as db:
    frames = db.execute("SELECT count(*) FROM packets").fetchone()[0]
assert frames >= 2000000, frames
print("frames", frames, flush=True)
t = time.monotonic()
report = analyze(project, topology)
clock = report["clocks"][ids[-1]]
assert clock["offset"] is not None and abs(clock["offset"] - 0.04) < 0.0001, clock
assert report["host_path"]["items"]
assert report["verdict"].startswith("Delay occurs between")
with project.connect() as db:
    work = db.execute("SELECT count(*),sum(atoms) FROM byte_work_units").fetchone()
print(
    json.dumps(
        dict(
            analysis_seconds=time.monotonic() - t,
            frames=frames,
            work=work,
            clock={k: v for k, v in clock.items() if k != "evidence"},
            verdict=report["verdict"],
            host_path=[
                {k: r[k] for k in ("direction", "max_ms", "window")} for r in report["host_path"]["items"]
            ],
        )
    ),
    flush=True,
)
