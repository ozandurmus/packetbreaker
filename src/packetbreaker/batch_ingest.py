"""One dissector per file; bounded parallelism and serialized project commits."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
import threading

import psutil

from .ingest import ingest
from .metadata import metadata

RAM_PER_WORKER = 1.6 * 1024**3


def normalize_paths(paths):
    return list(dict.fromkeys(str(Path(p).expanduser().resolve()) for p in paths))


def worker_budget(files, cpu_cores=None, available_ram=None):
    cores = cpu_cores if cpu_cores is not None else (os.cpu_count() or 1)
    ram = available_ram if available_ram is not None else psutil.virtual_memory().available
    workers = min(files, max(0, cores - 1), max(0, int(ram / RAM_PER_WORKER)))
    if files and workers < 1:
        raise ValueError("No ingest worker budget: need a spare CPU core and 1.6 GiB available RAM")
    return workers


class Cancellation:
    def __init__(self, global_event, file_event):
        self.global_event = global_event
        self.file_event = file_event

    def is_set(self):
        return self.global_event.is_set() or self.file_event.is_set()


def _ip_pair_filter(pairs):
    clauses = []
    for a, b in pairs:
        field = "ipv6" if (":" in a or ":" in b) else "ip"
        if a == b:
            clauses.append(f"({field}.src == {a} && {field}.dst == {b})")
        else:
            clauses.append(f"({field}.addr == {a} && {field}.addr == {b})")
    return " || ".join(clauses)


def _prefilter_candidates(paths, cancel=None):
    counts = {}
    for i, p in enumerate(paths):
        try:
            info = metadata(Path(p), cancel)
            total = (
                info["frame_limit"]
                if info.get("frame_limit") is not None
                else info.get("complete_records", 0)
            )
            if total and total > 0:
                counts[i] = total
        except Exception:
            continue
    ordered = sorted((c, i) for i, c in counts.items())
    if len(ordered) < 2:
        return counts, set()
    baseline_max = ordered[0][0]
    for c, _ in ordered:
        if c <= 5 * baseline_max:
            baseline_max = c
    large = {i for c, i in ordered if c > 5 * baseline_max}
    return counts, large


def ingest_many(
    project,
    paths,
    *,
    cancel=None,
    file_cancels=None,
    progress=None,
    workers=None,
    parallel=False,
    prefilter=False,
    **settings,
):
    paths = normalize_paths(paths)
    if not paths:
        return []
    count = worker_budget(len(paths))
    if not parallel and workers is None:
        count = min(count, 1)
    if workers is not None:
        if workers < 1:
            raise ValueError("Worker override must be positive")
        count = min(count, workers)
    cancel = cancel or threading.Event()
    progress = progress or (lambda **_: None)
    file_cancels = file_cancels if file_cancels is not None else {}
    for i in range(len(paths)):
        file_cancels.setdefault(str(i), threading.Event())
    lock = threading.RLock()
    states = [
        dict(file_id=str(i), file=Path(p).name, path=p, state="queued", frames=0) for i, p in enumerate(paths)
    ]

    def update(i, **values):
        with lock:
            states[i].update(values)
            progress(
                state="ingesting",
                workers=count,
                files=[s.copy() for s in states],
                frames=sum(s.get("frames", 0) for s in states),
                file_count=len(paths),
            )

    def run(i, path, extra=None):
        token = Cancellation(cancel, file_cancels[str(i)])
        try:
            if token.is_set():
                raise InterruptedError("File ingest cancelled")
            call_settings = {**settings, **(extra or {})}
            cid = ingest(project, path, **call_settings, cancel=token, progress=lambda **v: update(i, **v))
            update(i, capture_id=cid)
            return cid
        except BaseException as exc:
            update(i, state="cancelled" if isinstance(exc, InterruptedError) else "error", error=str(exc))
            raise

    counts, large = _prefilter_candidates(paths, cancel) if prefilter and len(paths) >= 2 else ({}, set())
    first_indices = [i for i in range(len(paths)) if i not in large]
    second_indices = [i for i in range(len(paths)) if i in large]

    result = [None] * len(paths)
    errors = []
    cancelled = []

    def execute_batch(indices, extra_for=None):
        if not indices:
            return
        with ThreadPoolExecutor(
            max_workers=min(count, len(indices)), thread_name_prefix="capture-ingest"
        ) as pool:
            futures = {pool.submit(run, i, paths[i], extra_for(i) if extra_for else None): i for i in indices}
            try:
                for f in as_completed(futures):
                    i = futures[f]
                    try:
                        result[i] = f.result()
                    except InterruptedError:
                        cancelled.append(i)
                    except Exception:
                        errors.append(i)
            except KeyboardInterrupt:
                cancel.set()
                raise

    execute_batch(first_indices)
    if second_indices and not cancel.is_set():
        first_cids = [result[i] for i in first_indices if result[i]]
        read_filter = None
        if first_cids:
            with project.connect() as db:
                placeholders = ",".join("?" for _ in first_cids)
                pairs = db.execute(
                    f"SELECT DISTINCT least(src, dst), greatest(src, dst) FROM packets "
                    f"WHERE capture_id IN ({placeholders}) "
                    f"AND src IS NOT NULL AND dst IS NOT NULL AND src <> '' AND dst <> '' "
                    f"ORDER BY 1, 2",
                    first_cids,
                ).fetchall()
            if pairs:
                read_filter = _ip_pair_filter(pairs)
        execute_batch(
            second_indices,
            lambda i: dict(read_filter=read_filter, prefilter_total=counts.get(i)) if read_filter else None,
        )

    if errors:
        raise ValueError(
            f"{len(errors)} file(s) failed; see per-file status. Completed captures are retained."
        )
    if cancelled:
        raise InterruptedError(f"{len(cancelled)} file(s) cancelled; completed captures are retained.")
    return result
