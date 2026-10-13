"""Shared real-tshark anonymization fixture; scheduled in the existing session pool."""

from pathlib import Path
import ipaddress
from packetbreaker.anonymize import Mapper

KEY = bytes(range(32))


def build_anonymize_fixture(mode_tuple, directory, tshark):
    mode, ip_id, ipv6 = mode_tuple[:3]
    scenario = mode_tuple[3] if len(mode_tuple) > 3 else "recovered_loss"
    tmp_path = Path(directory)
    from copy import deepcopy
    from packetbreaker.analysis import analyze
    from packetbreaker.batch_ingest import ingest_many
    from packetbreaker.store import Project
    from packetbreaker.anonymize import anonymize_files

    from conftest import build_scenario_fixture

    original = build_scenario_fixture(scenario, dict(ip_id=ip_id, ipv6=ipv6), tmp_path / "source", tshark)
    _, truth, topology, before = original
    inputs = [Path(f) for f in truth["files"]]
    destination = tmp_path / "sanitized"
    anonymize_files(inputs, destination, mode=mode, key=KEY, map_ips=True, tshark=tshark)
    files = sorted(destination.glob("*.pcap"))
    project = Project(tmp_path / "project")
    ids = ingest_many(project, files, tshark=tshark, workers=4)
    changed = deepcopy(topology)
    mapping = {p["capture_id"]: ids[i] for i, p in enumerate(topology["points"])}
    for p in changed["points"]:
        p["capture_id"] = mapping[p["capture_id"]]
    mapper = Mapper(KEY)
    changed["client_cidrs"] = [
        str(
            ipaddress.ip_network(
                (
                    int.from_bytes(mapper.ip(ipaddress.ip_network(c).network_address.packed), "big"),
                    ipaddress.ip_network(c).prefixlen,
                ),
                strict=False,
            )
        )
        for c in topology["client_cidrs"]
    ]
    changed["clock_overrides"] = {mapping[c]: v for c, v in topology.get("clock_overrides", {}).items()}
    after = analyze(project, changed)
    return original, (before, after, str(destination))
