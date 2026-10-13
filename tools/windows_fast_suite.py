"""Run every fast test in resource-bounded isolated Windows processes; budget is actual elapsed wall time."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import psutil


def partition(nodeids, count, costs=None):
    weights = {}
    for node in nodeids:
        file = node.split("::")[0]
        weights[file] = weights.get(file, 0) + 1
    shared_media = {
        "tests/test_udp_transactions.py",
        "tests/test_rtp.py",
        "tests/test_sip.py",
        "tests/test_media_mutants.py",
    }
    shared_proxy = {
        "tests/test_tls_interception.py",
        "tests/test_proxy_pairing.py",
        "tests/test_proxy_integration.py",
        "tests/test_proxy_resets.py",
        "tests/test_proxy_clocks.py",
    }
    units = {}
    for file in weights:
        units.setdefault(
            "voip" if file in shared_media else "proxy" if file in shared_proxy else file, []
        ).append(file)

    # Measured elapsed costs, not number of assertions. VoIP's repeated tshark startup
    # is slower on hosted Windows; reserve extra scheduling weight, not a relaxed gate.
    def cost(files):
        return sum((costs or {}).get(f, weights[f]) for f in files) * (
            1.5 if costs and any(f in shared_media for f in files) else 1
        )

    groups = [[] for _ in range(count)]
    totals = [0] * count
    for files in sorted(units.values(), key=lambda files: (-cost(files), sorted(files))):
        i = min(range(count), key=lambda i: totals[i])
        groups[i].extend(sorted(files))
        totals[i] += cost(files)
    return groups


def junit_counts(paths):
    result = dict(tests=0, failures=0, errors=0, skipped=0)
    for path in paths:
        for suite in ET.parse(path).getroot().iter("testsuite"):
            for key in result:
                result[key] += int(suite.attrib.get(key, 0))
    return result


def file_timings(paths):
    result = {}
    for path in paths:
        for case in ET.parse(path).getroot().iter("testcase"):
            parts = case.attrib.get("classname", "").split(".")
            if len(parts) >= 2 and parts[0] == "tests":
                file = "/".join(parts[:2]) + ".py"
                result[file] = result.get(file, 0) + float(case.attrib.get("time", 0))
    return result


def shard_count(cores, available_bytes):
    # One fixture producer per shard; leave a CPU free and budget 1.5 GiB per parent/producer pair.
    return min(3, max(1, cores - 1), max(1, available_bytes // (3 * 1024**3 // 2)))


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
    cost_file = Path(__file__).with_name("windows_test_costs.json")
    costs = json.loads(cost_file.read_text()) if cost_file.exists() else {}
    cores = os.cpu_count() or 1
    available = psutil.virtual_memory().available
    # Three-way execution was slower on hosted four-core runners; retain the measured two-process cap.
    groups = [g for g in partition(ids, min(2, shard_count(cores, available)), costs) if g]
    print(json.dumps(dict(cpu_cores=cores, available_ram_bytes=available, shards=len(groups))), flush=True)
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
    result = dict(
        wall_seconds=elapsed,
        shards=len(groups),
        collected=len(ids),
        file_seconds=file_timings([f"fast-suite-{i}.xml" for i in range(len(groups))]),
        **counts,
    )
    Path("fast-suite-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    if any(codes) or counts["tests"] != len(ids) or counts["errors"] or counts["failures"]:
        raise RuntimeError("Fast suite failed or collection coverage differs; no gate certified")


if __name__ == "__main__":
    main()
