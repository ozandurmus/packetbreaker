import duckdb
from packetbreaker.dns import OUTCOME


def status(**changes):
    row = dict(
        complete=True,
        unique_response=False,
        candidates=0,
        ambiguous=False,
        covered=True,
        query_hop=None,
        response_hop=None,
        far_responses=0,
        resolver_seen=True,
        resolver_covered=True,
    )
    row.update(changes)
    with duckdb.connect() as db:
        db.execute(
            "CREATE TABLE d("
            + ",".join(
                k
                + " "
                + ("BOOLEAN" if isinstance(v, bool) else "VARCHAR" if k.endswith("hop") else "INTEGER")
                for k, v in row.items()
            )
            + ")"
        )
        db.execute("INSERT INTO d VALUES(" + ",".join("?" for _ in row) + ")", list(row.values()))
        return db.execute("SELECT " + OUTCOME + " FROM d").fetchone()[0]


def test_dns_unknown_before_positive_attribution():
    assert status(covered=False) == "unknown"
    assert status(resolver_seen=False) == "unknown"
    assert status(complete=False) == "unknown"
    assert status(ambiguous=True, candidates=2) == "unknown"
    assert status(far_responses=1) == "unknown"
    assert status(far_responses=2, response_hop="reverse:lb_out:lb_in") == "unknown"


def test_dns_resolver_and_network_are_different():
    assert status(unique_response=True, candidates=1) == "answered"
    assert status() == "resolver_timeout"
    assert status(query_hop="forward:fw_in:fw_out") == "query_disappeared"
    assert status(far_responses=1, response_hop="reverse:fw_out:fw_in") == "response_disappeared"


def test_native_dns_tuple_scope_latency_and_export(tmp_path, tshark):
    import struct
    from pathlib import Path
    from packetbreaker.synthetic import write_pcap
    from packetbreaker.realistic import datagram
    from packetbreaker.batch_ingest import ingest_many
    from packetbreaker.store import Project
    from packetbreaker.analysis import analyze
    from packetbreaker.dns import dns_page
    from packetbreaker.export import export_data, html_report

    name = b"\x04same\x07example\x04test\0"
    body = struct.pack("!HHHHHH", 77, 0x100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    response = struct.pack("!HHHHHH", 77, 0x8180, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)

    def packet(client, response_flag=False):
        payload = response if response_flag else body
        return datagram(
            "203.0.113.53" if response_flag else client,
            client if response_flag else "203.0.113.53",
            17,
            struct.pack(
                "!HHHH", 53 if response_flag else 40000, 40000 if response_flag else 53, len(payload) + 8, 0
            )
            + payload,
            0,
        )

    frames = [
        (1700000000.1, packet("10.0.0.1")),
        (1700000000.12, packet("10.0.0.2")),
        (1700000000.15, packet("10.0.0.1", True)),
        (
            1700000004,
            datagram("10.0.0.1", "203.0.113.53", 17, struct.pack("!HHHH", 45000, 45001, 12, 0) + b"noop", 0),
        ),
    ]
    paths = []
    for i in range(2):
        path = tmp_path / f"point{i}.pcap"
        write_pcap(path, frames)
        paths.append(str(path))
    project = Project(tmp_path / "project")
    ids = ingest_many(project, paths, tshark=tshark)
    topology = dict(
        points=[
            dict(
                id=f"p{i}",
                label=Path(path).stem,
                device=f"endpoint{i}",
                kind="Client" if i == 0 else "Server",
                capture_id=ids[i],
            )
            for i, path in enumerate(paths)
        ],
        forward=["p0", "p1"],
    )
    analyze(project, topology)
    result = dns_page(project, point="p0")
    assert result["total"] == 2
    first = next(q for q in result["items"] if q["src"] == "10.0.0.1")
    second = next(q for q in result["items"] if q["src"] == "10.0.0.2")
    import pytest

    assert first["status"] == "answered" and first["latency_ms"] == pytest.approx(50, abs=0.001)
    assert second["latency_ms"] is None and second["status"] != "answered"
    assert all(q["evidence"] for q in result["items"])
    exported = export_data(project)
    assert exported["report"]["dns"]["total"] == 4
    assert "DNS turnaround" in html_report(exported)
