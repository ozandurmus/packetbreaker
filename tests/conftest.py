from pathlib import Path

import pytest

from packetbreaker.analysis import analyze
from packetbreaker.ingest import find_tshark, ingest
from packetbreaker.store import Project
from packetbreaker.synthetic import generate


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
            for point, path in zip(topology["points"], truth["files"]):
                point["capture_id"] = ingest(project, Path(path), tshark=tshark)
            report = analyze(project, topology)
            cache[key] = (project, truth, topology, report)
        return cache[key]

    return run
