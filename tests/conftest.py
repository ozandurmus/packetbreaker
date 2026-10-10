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


def build_scenario_fixture(name, kwargs, directory, tshark):
    truth, topology = generate(directory, scenario=name, **kwargs)
    project = Project(directory / "project")
    # Tiny fixture files use the existing CPU/RAM worker budget; production stays serial.
    ids = ingest_many(project, truth["files"], tshark=tshark, workers=4)
    names = {Path(path).name: cid for path, cid in zip(truth["files"], ids)}
    bind_capture_ids(topology, names)
    report = analyze(project, topology)
    return str(project.path), truth, topology, report


@pytest.fixture(scope="session")
def scenarios(tmp_path_factory, tshark, request):
    from concurrent.futures import ProcessPoolExecutor
    from multiprocessing import get_context

    cache = {}
    futures = {}

    # Prefetch only selected multi-device datasets, with two background processes.
    # It overlaps independent synthetic fixture preparation with other tests, without new dependencies.
    planned = {}
    for item in request.session.items:
        params = getattr(getattr(item, "callspec", None), "params", {})
        if item.originalname != "test_exact_integrity_location":
            continue
        mode, location = params["mode"], params["location"]
        asymmetric = params["case"] == "asymmetric_return"
        name = "integrity_multi_asym" if asymmetric else "integrity_multi"
        kwargs = dict(fault_location=location if asymmetric else "all", ip_id=mode[0], ipv6=mode[1])
        planned[(name, repr(kwargs))] = (name, kwargs)
    directories = {key: tmp_path_factory.mktemp(name) for key, (name, _) in planned.items()}
    pool = ProcessPoolExecutor(max_workers=2, mp_context=get_context("spawn")) if planned else None
    if pool:
        futures = {
            key: pool.submit(build_scenario_fixture, name, kwargs, directories[key], tshark)
            for key, (name, kwargs) in planned.items()
        }

    def run(name, **kwargs):
        key = (name, repr(kwargs))
        if key not in cache:
            result = (
                futures[key].result()
                if key in futures
                else build_scenario_fixture(name, kwargs, tmp_path_factory.mktemp(name), tshark)
            )
            project_path, truth, topology, report = result
            cache[key] = Project(project_path), truth, topology, report
        return cache[key]

    try:
        yield run
    finally:
        if pool:
            pool.shutdown(wait=True, cancel_futures=True)


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

    modes = [("zero", False), ("constant", False), ("zero", True)]
    directories = (
        {mode: tmp_path_factory.mktemp("proxy_wire") for mode in modes} if not _proxy_wire_cache else {}
    )

    def build(mode):
        directory = directories[mode]
        file, topology, truth = make_fixture(directory, ipv6=mode[1], ip_id=mode[0])
        project = Project(directory / "project")
        capture_id = ingest(project, file, tshark=tshark)
        bind_capture_ids(topology, {file.name: capture_id})
        report = analyze(project, topology)
        return project, Topology.model_validate(topology), truth, report

    if not _proxy_wire_cache:
        # Independent tiny files; amortize tshark startup, without a large matrix or shared DB writers.
        with ThreadPoolExecutor(max_workers=2) as pool:
            built = list(pool.map(build, modes))
        _proxy_wire_cache.update(zip(modes, built))
    return _proxy_wire_cache[request.param]
