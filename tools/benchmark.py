"""Reproducible synthetic scale check; reports measured local results only."""

import argparse
import json
from pathlib import Path
import platform
import time

from packetbreaker.analysis import analyze
from packetbreaker.ingest import ingest
from packetbreaker.store import Project
from packetbreaker.synthetic import generate

parser = argparse.ArgumentParser()
parser.add_argument("directory", type=Path)
parser.add_argument("--hops", type=int, default=10)
parser.add_argument("--rounds", type=int, default=10000)
args = parser.parse_args()
truth, topology = generate(
    args.directory / "captures", hops=args.hops, rounds=args.rounds, scenario="healthy"
)
project = Project(args.directory / "project")
start = time.monotonic()
for point, path in zip(topology["points"], truth["files"]):
    point["capture_id"] = ingest(project, path)
ingest_seconds = time.monotonic() - start
start = time.monotonic()
report = analyze(project, topology)
analysis_seconds = time.monotonic() - start
result = dict(
    platform=platform.platform(),
    files=args.hops,
    input_bytes=sum(Path(p).stat().st_size for p in truth["files"]),
    frames=sum(c["inventory"]["packet_count"] for c in project.inventory()),
    ingest_seconds=ingest_seconds,
    analysis_seconds=analysis_seconds,
    verdict=report["verdict"],
    matched_segments=sum(s["matched"] > 0 for s in report["segments"]),
    unknown_latency_segments=sum(s["p95_ms"] is None for s in report["segments"]),
)
print(json.dumps(result, indent=2))
(args.directory / "benchmark.json").write_text(json.dumps(result, indent=2))
