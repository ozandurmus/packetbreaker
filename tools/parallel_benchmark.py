"""Compare sequential and resource-bounded ingestion of existing synthetic inputs."""

import argparse
import json
import os
from pathlib import Path
import threading
import time

import psutil

from packetbreaker.batch_ingest import ingest_many
from packetbreaker.store import Project


def run(source, output, mode):
    paths = [source / "captures" / f"point-{i}.pcap" for i in range(5)]
    assert all(p.is_file() for p in paths)
    output.mkdir(parents=True, exist_ok=True)
    project_path = output / f"{mode}-project"
    if (project_path / "project.duckdb").exists():
        raise ValueError("Choose a fresh output directory; cached inputs are not a benchmark")
    project = Project(project_path)
    process = psutil.Process()
    stop = threading.Event()
    peak = 0

    def memory():
        nonlocal peak
        while not stop.is_set():
            total = process.memory_info().rss
            for child in process.children(recursive=True):
                try:
                    total += child.memory_info().rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            peak = max(peak, total)
            stop.wait(0.1)

    monitor = threading.Thread(target=memory, daemon=True)
    monitor.start()
    available = psutil.virtual_memory().available
    workers = 1
    last = 0

    def progress(**status):
        nonlocal workers, last
        workers = status["workers"]
        if status["frames"] >= last + 500000:
            last = status["frames"]
            print(f"{mode}: {last} records processed, {workers} workers", flush=True)

    start = time.monotonic()
    try:
        ingest_many(project, paths, workers=1 if mode == "serial" else None, progress=progress)
    finally:
        elapsed = time.monotonic() - start
        stop.set()
        monitor.join()
    captures = project.inventory()
    frames = sum(c["inventory"]["packet_count"] for c in captures)
    result = dict(
        mode=mode,
        files=len(paths),
        frames=frames,
        input_bytes=sum(p.stat().st_size for p in paths),
        seconds=elapsed,
        frames_per_second=frames / elapsed,
        workers=workers,
        cpu_cores=os.cpu_count(),
        available_ram_bytes_at_start=available,
        process_tree_peak_rss_bytes=peak,
        capture_counts=[c["inventory"]["packet_count"] for c in captures],
    )
    (output / f"{mode}.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["serial", "parallel"])
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    run(args.source, args.output, args.mode)
