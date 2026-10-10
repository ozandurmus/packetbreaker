from copy import deepcopy
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


@pytest.fixture(scope="session")
def multi(scenarios, clone_project):
    cache = {}

    def run(location, mode, asymmetric=False, no_endpoint=False):
        key = (location, mode, asymmetric, no_endpoint)
        if key not in cache:
            project, truth, topology, report = scenarios(
                "integrity_multi_asym" if asymmetric else "integrity_multi",
                fault_location=location if asymmetric else "all",
                ip_id=mode[0],
                ipv6=mode[1],
            )
            if no_endpoint:
                modified = deepcopy(topology)
                modified["points"] = [p for p in modified["points"] if p["id"] != "server"]
                for direction in ("forward", "reverse"):
                    modified[direction] = [p for p in modified[direction] if p != "server"]
                project = clone_project(project)
                report = analyze(project, modified)
                topology = modified
            truth = {**truth, "findings": [f for f in truth["findings"] if f["fault_location"] == location]}
            cache[key] = (project, truth, topology, report)
        return cache[key]

    return run


@pytest.fixture(scope="session")
def clone_project(tmp_path_factory):
    def clone(project):
        from shutil import copyfile

        destination = tmp_path_factory.mktemp("integrity_view")
        # The fixture database is closed/checkpointed; source captures remain shared read-only.
        copyfile(project.path / "project.duckdb", destination / "project.duckdb")
        return Project(destination)

    return clone


_proxy_wire_cache = {}


@pytest.fixture(scope="session", params=[("zero", False), ("constant", False), ("zero", True)])
def proxy_capture(request, tmp_path_factory, tshark):
    from concurrent.futures import ThreadPoolExecutor
    from packetbreaker.ingest import ingest
    from packetbreaker.topology import Topology
    from proxy_fixtures import make_fixture

    def build(mode):
        directory = tmp_path_factory.mktemp("proxy_wire")
        file, topology, truth = make_fixture(directory, ipv6=mode[1], ip_id=mode[0])
        project = Project(directory / "project")
        capture_id = ingest(project, file, tshark=tshark)
        bind_capture_ids(topology, {file.name: capture_id})
        report = analyze(project, topology)
        return project, Topology.model_validate(topology), truth, report

    if not _proxy_wire_cache:
        # Independent tiny files; amortize tshark startup, without a large matrix or shared DB writers.
        modes = [("zero", False), ("constant", False), ("zero", True)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            _proxy_wire_cache.update(zip(modes, pool.map(build, modes)))
    return _proxy_wire_cache[request.param]
