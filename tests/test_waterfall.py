from copy import deepcopy

import pytest
from packetbreaker.analysis import analyze

from packetbreaker.waterfall import completion, request_size, waterfall


def test_handshake_http_and_uncertainty(scenarios):
    project, _, topology, _ = scenarios("healthy")
    report = analyze(project, topology)
    with project.connect() as db:
        flow = db.execute("SELECT flow FROM flow_summary LIMIT 1").fetchone()[0]
    result = waterfall(project, flow)
    handshake, http = result["items"]
    assert len(handshake["bars"]) == 3 * (len(topology["forward"]) - 1) + 2
    assert all(
        b["duration_ms"] is not None and b["evidence"] and b["uncertainty_ms"] is not None
        for b in handshake["bars"]
    )
    processing = next(b for b in http["bars"] if b["kind"] == "server_processing")
    assert processing["duration_ms"] == pytest.approx(16, abs=0.05)
    assert sum(b["duration_ms"] for b in handshake["bars"]) == pytest.approx(44, abs=0.05)
    assert all(b["evidence"] for b in http["bars"])
    assert {b["kind"] for b in http["bars"]} >= {"link", "device_dwell", "server_processing"}
    modified = deepcopy(report)
    modified["clocks"][topology["points"][2]["capture_id"]]["uncertainty"] = None
    try:
        with project.connect() as db:
            project.set(db, "report", modified)
        assert any(
            b["duration_ms"] is None and "Clock" in (b["reason"] or "")
            for b in waterfall(project, flow)["items"][0]["bars"]
        )
    finally:
        with project.connect() as db:
            project.set(db, "report", report)


def test_request_completion_reordering_prefix_gap_and_chunked():
    header = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n"
    seed = dict(seq=100, prefix=header.hex(), ts=1, frame=1, length=len(header), eligible=True)
    last = dict(seq=100 + len(header) + 2, prefix=b"cd".hex(), ts=2, frame=2, length=2, eligible=True)
    gap = dict(seq=100 + len(header), prefix=b"ab".hex(), ts=3, frame=3, length=2, eligible=True)
    size, reason = request_size(seed, [seed, last, gap])
    assert reason is None and size == len(header) + 4
    assert completion([seed, last], seed, size, 4) is None
    assert completion([seed, last, gap], seed, size, 4) == gap
    short = {**seed, "prefix": header[:10].hex()}
    assert request_size(short, [short, last])[0] is None
    chunked = {**seed, "prefix": b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".hex()}
    assert "chunk" in request_size(chunked, [chunked])[1]


def test_translated_flow_and_proxy(scenarios):
    project, _, topology, report = scenarios("sequence_randomization", ip_id="zero", ipv6=True)
    with project.connect() as db:
        flow = db.execute("SELECT flow FROM flow_summary LIMIT 1").fetchone()[0]
    result = waterfall(project, flow)
    assert all(b["duration_ms"] is not None for b in result["items"][0]["bars"])
    assert any(
        e.get("sequence_translation") for item in result["items"] for b in item["bars"] for e in b["evidence"]
    )
    proxy = deepcopy(topology)
    proxy["points"][2]["translation"] = "full_proxy"
    try:
        with project.connect() as db:
            project.set(db, "topology", proxy)
        unknown = [
            b for b in waterfall(project, flow)["items"][0]["bars"] if "full proxy" in (b["reason"] or "")
        ]
        assert unknown and all(b["duration_ms"] is None for b in unknown)
    finally:
        with project.connect() as db:
            project.set(db, "topology", topology)


def test_confirmed_nat_and_explicit_return_path(scenarios):
    from packetbreaker.analysis import analyze

    project, _, topology, report = scenarios("nat")
    confirmed = {
        **topology,
        "nat_mappings": [
            {k: s[k] for k in ("point_a", "point_b", "tuple_a", "tuple_b")} for s in report["nat_suggestions"]
        ],
    }
    analyze(project, confirmed)
    with project.connect() as db:
        flow = db.execute("SELECT flow FROM flow_summary LIMIT 1").fetchone()[0]
        saved = project.get(db, "topology")
        alternate = {**saved, "reverse": [saved["forward"][-1], saved["forward"][2], saved["forward"][0]]}
        project.set(db, "topology", alternate)
    try:
        result = waterfall(project, flow)
        bars = result["items"][1]["bars"]
        assert all(b["duration_ms"] is not None for b in bars)
        returns = [b for b in bars if b["label"].startswith("First response byte")]
        assert [(b["point_a"], b["point_b"]) for b in returns] == [("p4", "p2"), ("p2", "p0")]
        filters = {e["flow_filter"] for b in bars for e in b["evidence"]}
        assert len(filters) > 1  # Original, per-file post-NAT tuples are retained.
    finally:
        with project.connect() as db:
            project.set(db, "topology", saved)
