import threading
import time
from pathlib import Path
from unittest.mock import patch
import pytest

from packetbreaker.batch_ingest import RAM_PER_WORKER, ingest_many, worker_budget
from packetbreaker.ingest import ingest
from packetbreaker.store import Project
from packetbreaker.synthetic import generate


def test_worker_formula():
    assert worker_budget(10, 8, 5 * RAM_PER_WORKER) == 5
    assert worker_budget(10, 3, 10 * RAM_PER_WORKER) == 2
    assert worker_budget(2, 8, 10 * RAM_PER_WORKER) == 2
    with pytest.raises(ValueError):
        worker_budget(1, 2, RAM_PER_WORKER - 1)


def test_files_run_concurrently_with_individual_cancel(tmp_path):
    local = {"0": threading.Event(), "1": threading.Event()}
    entered = threading.Barrier(2)
    seen = []
    states = []

    def fake(project, path, cancel, progress, **kw):
        entered.wait(timeout=5)
        seen.append(Path(path).name)
        if Path(path).name == "a":
            local["0"].set()
            if cancel.is_set():
                raise InterruptedError("cancelled")
        time.sleep(0.03)
        progress(state="ready", frames=5)
        return "done"

    with (
        patch("packetbreaker.batch_ingest.worker_budget", return_value=2),
        patch("packetbreaker.batch_ingest.ingest", fake),
    ):
        with pytest.raises(InterruptedError):
            ingest_many(
                None,
                [tmp_path / "a", tmp_path / "b"],
                file_cancels=local,
                progress=lambda **s: states.append(s),
            )
    assert sorted(seen) == ["a", "b"]
    assert {s["file_id"]: s["state"] for s in states[-1]["files"]} == {"0": "cancelled", "1": "ready"}


def test_parallel_real_tshark_cancel_and_resume(tmp_path, tshark):
    truth, _ = generate(tmp_path / "input", scenario="healthy", rounds=50)
    project = Project(tmp_path / "project")
    tokens = {"0": threading.Event()}
    states = []

    def progress(**status):
        states.append(status)
        if status["files"][0].get("frames", 0) >= 25:
            tokens["0"].set()

    with pytest.raises(InterruptedError):
        ingest_many(
            project,
            truth["files"],
            tshark=tshark,
            workers=2,
            file_cancels=tokens,
            progress=progress,
            batch_size=25,
        )
    inventory = project.inventory()
    assert sum(c["state"] == "ready" for c in inventory) == 4
    assert next(c for c in inventory if c["name"].startswith("00"))["state"] == "cancelled"
    ingest(project, truth["files"][0], tshark=tshark)
    assert all(c["state"] == "ready" and c["inventory"]["packet_count"] == 155 for c in project.inventory())
    with project.connect() as db:
        assert db.execute("SELECT count(*) FROM packets").fetchone()[0] == 775
