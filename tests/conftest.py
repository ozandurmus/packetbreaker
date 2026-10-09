from pathlib import Path

import pytest

from packetbreaker.analysis import analyze
from packetbreaker.ingest import find_tshark
from packetbreaker.batch_ingest import ingest_many
from packetbreaker.store import Project
from packetbreaker.synthetic import generate, bind_capture_ids


@pytest.fixture(scope="session")
def tshark():
    # Missing tshark is a failed acceptance gate, not a silent skip.
    return find_tshark()


@pytest.fixture(scope="session")
def scenarios(tmp_path_factory, tshark):
    cache = {}

    def run(name, **kwargs):
        key = (name, repr(kwargs))
        if key not in cache:
            directory = tmp_path_factory.mktemp(name)
            truth, topology = generate(directory, scenario=name, **kwargs)
            project = Project(directory / "project")
            # Independent tiny captures overlap tshark startup; production serial defaults have separate tests.
            ids = ingest_many(project, truth["files"], tshark=tshark, workers=2)
            names = {Path(path).name: cid for path, cid in zip(truth["files"], ids)}
            bind_capture_ids(topology, names)
            report = analyze(project, topology)
            cache[key] = (project, truth, topology, report)
        return cache[key]

    return run
