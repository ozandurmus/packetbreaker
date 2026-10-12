"""Run every fast test in two isolated Windows processes; budget is actual elapsed wall time."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


def partition(nodeids, count):
    weights = {}
    for node in nodeids:
        file = node.split("::")[0]
        weights[file] = weights.get(file, 0) + 1
    groups = [[] for _ in range(count)]
    totals = [0] * count
    for file, n in sorted(weights.items(), key=lambda item: (-item[1], item[0])):
        i = min(range(count), key=lambda i: totals[i])
        groups[i].append(file)
        totals[i] += n
    return groups


def junit_counts(paths):
    result = dict(tests=0, failures=0, errors=0, skipped=0)
    for path in paths:
        for suite in ET.parse(path).getroot().iter("testsuite"):
            for key in result:
                result[key] += int(suite.attrib.get(key, 0))
    return result


def main():
    start = time.perf_counter()
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-m", "not slow"],
        capture_output=True,
        text=True,
        check=True,
    )
    ids = [s for s in collected.stdout.splitlines() if s.startswith("tests/") and ".py::" in s]
    if not ids:
        raise RuntimeError("No fast tests collected; cannot certify an empty suite")
    groups = partition(ids, 2 if (os.cpu_count() or 1) >= 4 else 1)
    workers = []
    outputs = []
    try:
        for i, files in enumerate(groups):
            out = Path(f"fast-shard-{i}.log").open("w", encoding="utf-8")
            outputs.append(out)
            cmd = [
                sys.executable,
                "-m",
                "pytest",
                "-m",
                "not slow",
                "-q",
                "--durations=20",
                f"--junitxml=fast-suite-{i}.xml",
                f"--basetemp=.fast-temp-{i}",
                *files,
            ]
            workers.append(
                subprocess.Popen(
                    cmd,
                    stdout=out,
                    stderr=subprocess.STDOUT,
                    env={**os.environ, "PACKETBREAKER_TEST_WORKERS": "1"},
                )
            )
        codes = [p.wait() for p in workers]
    finally:
        for p in workers:
            if p.poll() is None:
                p.terminate()
                p.wait()
        for out in outputs:
            out.close()
    elapsed = time.perf_counter() - start
    for i in range(len(groups)):
        print(f"\nShard {i}:\n" + Path(f"fast-shard-{i}.log").read_text(encoding="utf-8"))
    counts = junit_counts([f"fast-suite-{i}.xml" for i in range(len(groups))])
    result = dict(wall_seconds=elapsed, shards=len(groups), collected=len(ids), **counts)
    Path("fast-suite-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    if any(codes) or counts["tests"] != len(ids) or counts["errors"] or counts["failures"]:
        raise RuntimeError("Fast suite failed or collection coverage differs; no gate certified")


if __name__ == "__main__":
    main()
