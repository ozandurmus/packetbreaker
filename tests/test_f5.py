import json

import pytest

from packetbreaker.analysis import analyze
from packetbreaker.ingest import ingest
from packetbreaker.store import Project
from packetbreaker.vendors import F5_FIELDS, HTTP_FIELDS
from vendor_fixtures import f5_capture, tshark_fields


def test_f5_decode_pair_request_dwell_and_reset(tmp_path, tshark):
    path = f5_capture(tmp_path / "f5.pcap")
    fields = F5_FIELDS + HTTP_FIELDS
    expected = tshark_fields(
        tshark, path, ["frame.number", "frame.time_epoch", *fields], ["--enable-protocol", "f5ethtrailer"]
    )
    assert any(e["f5ethtrailer.flowid"] for e in expected) and any(e["http.request.method"] for e in expected)
    project = Project(tmp_path / "project")
    cid = ingest(project, path, tshark=tshark)
    with project.connect() as db:
        actual = [
            json.loads(v) for (v,) in db.execute("SELECT vendor FROM packets ORDER BY frame").fetchall()
        ]
    assert [{k: v.get(k, "") for k in fields} for v in actual] == [
        {k: e[k] for k in fields} for e in expected
    ]
    points = [
        dict(id=role, device="BIG-IP", label=role, capture_id=cid, vendor="f5", vendor_stage=role)
        for role in ("client", "server")
    ]
    topology = dict(points=points, forward=["client", "server"], client_cidrs=["10.0.0.1/32"])
    report = analyze(project, topology)
    assert report["flow_count"] == 2  # TCP proxy legs remain separate conversations.
    assert {p["role"] for p in report["f5"]["pairs"]} == {"client", "server"}
    requests = report["f5"]["requests"]
    assert len(requests) == 2 and all(r["client_flow"] != r["server_flow"] for r in requests)
    decoded = [e for e in expected if e["http.request.method"]]
    for r in requests:
        a, b = r["evidence"]
        first = next(e for e in decoded if int(e["frame.number"]) == a["frame"])
        second = next(e for e in decoded if int(e["frame.number"]) == b["frame"])
        assert r["request_dwell_ms"] == pytest.approx(
            (float(second["frame.time_epoch"]) - float(first["frame.time_epoch"])) * 1000
        )
    assert report["f5"]["resets"][0]["reason"] == next(
        e["f5ethtrailer.rstcausetxt"] for e in expected if e["f5ethtrailer.rstcausetxt"]
    )
    assert all(s["reason"] == "Unsupported translation boundary" for s in report["segments"])

    unknown = analyze(project, {**topology, "client_cidrs": ["0.0.0.0/0"]})
    assert unknown["verdict"] == "Inconclusive"
    assert all(p["role"] == "unknown" and p["reason"] for p in unknown["f5"]["pairs"])
    assert not unknown["f5"]["requests"]
