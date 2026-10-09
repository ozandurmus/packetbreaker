"""One dissector per file; bounded parallelism and serialized project commits."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
import threading

import psutil

from .ingest import ingest

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


def ingest_many(
    project, paths, *, cancel=None, file_cancels=None, progress=None, workers=None, parallel=False, **settings
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

    def run(i, path):
        token = Cancellation(cancel, file_cancels[str(i)])
        try:
            if token.is_set():
                raise InterruptedError("File ingest cancelled")
            cid = ingest(project, path, **settings, cancel=token, progress=lambda **v: update(i, **v))
            update(i, capture_id=cid)
            return cid
        except BaseException as exc:
            update(i, state="cancelled" if isinstance(exc, InterruptedError) else "error", error=str(exc))
            raise

    result = [None] * len(paths)
    errors = []
    cancelled = []
    with ThreadPoolExecutor(max_workers=count, thread_name_prefix="capture-ingest") as pool:
        futures = {pool.submit(run, i, p): i for i, p in enumerate(paths)}
        for f in as_completed(futures):
            i = futures[f]
            try:
                result[i] = f.result()
            except InterruptedError:
                cancelled.append(i)
            except Exception:
                errors.append(i)
    if errors:
        raise ValueError(
            f"{len(errors)} file(s) failed; see per-file status. Completed captures are retained."
        )
    if cancelled:
        raise InterruptedError(f"{len(cancelled)} file(s) cancelled; completed captures are retained.")
    return result
