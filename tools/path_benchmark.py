"""Same-input serial ingest/analysis regression measurement; prefix with time -l."""

import argparse
import json
from pathlib import Path
import time

from packetbreaker.analysis import analyze
from packetbreaker.batch_ingest import ingest_many
from packetbreaker.store import Project


def run(stage, source, output):
    output.mkdir(parents=True, exist_ok=True)
    project_path = output / "project"
    if stage == "ingest" and (project_path / "project.duckdb").exists():
        raise ValueError("Use a fresh output directory, not a cached ingest")
    project = Project(project_path)
    paths = [source / "captures" / f"point-{i}.pcap" for i in range(5)]
    start = time.monotonic()
    if stage == "ingest":
        ids = ingest_many(project, paths, workers=1)
        topology = json.loads((source / "config.json").read_text())["topology"]
        for point, cid in zip(topology["points"], ids):
            point["capture_id"] = cid
        with project.connect() as db:
            project.set(db, "topology", topology)
        frames = sum(c["inventory"]["packet_count"] for c in project.inventory())
        result = dict(frames=frames, input_bytes=sum(p.stat().st_size for p in paths), files=5)
    else:
        with project.connect() as db:
            topology = project.get(db, "topology")
        report = analyze(project, topology)
        result = dict(
            findings=report["finding_count"],
            classes={f["type"] for f in report["findings"]},
            flows=report["flow_count"],
        )
        result["classes"] = sorted(result["classes"])
    result.update(stage=stage, seconds=time.monotonic() - start)
    if stage == "ingest":
        result["frames_per_second"] = result["frames"] / result["seconds"]
    (output / f"{stage}.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("stage", choices=["ingest", "analyze"])
    p.add_argument("source", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    run(a.stage, a.source, a.output)
