import json
import os
from pathlib import Path

import pytest

from packetbreaker.analysis import analyze
from packetbreaker.ingest import ingest
from packetbreaker.device_drops import prepare_proofs
from packetbreaker.topology import Topology
from packetbreaker.store import Project
from packetbreaker.vendors import CHECKPOINT_FIELDS
from vendor_fixtures import snoop, tshark_fields

OPTIONS = [
    "-o",
    "eth.interpret_as_fw1_monitor:TRUE",
    "-o",
    "fw1.iflist_with_chain:TRUE",
    "-o",
    "fw1.with_uuid:TRUE",
]


@pytest.mark.parametrize("delayed", [False, True])
def test_snoop_adapter_matches_tshark_and_stage_drop(tmp_path, tshark, delayed):
    path = snoop(tmp_path / "synthetic.snoop", delayed)
    expected = tshark_fields(tshark, path, CHECKPOINT_FIELDS, OPTIONS)
    project = Project(tmp_path / "project")
    cid = ingest(project, path, tshark=tshark, checkpoint_uuid=True)
    with project.connect() as db:
        actual = [
            json.loads(v) for (v,) in db.execute("SELECT vendor FROM packets ORDER BY frame").fetchall()
        ]
    assert [{k: v.get(k, "") for k in CHECKPOINT_FIELDS} for v in actual] == expected
    assert {v["stage"] for v in actual} == {"i", "I", "o", "O", "e", "E", "oe", "OE"}
    points = [
        dict(
            id=f"p{n}",
            label=stage,
            device="FW",
            kind="Firewall",
            capture_id=cid,
            vendor="checkpoint",
            vendor_interface=expected[0]["fw1.interface"],
            vendor_stage=stage,
            inspection_complete=True,
        )
        for n, stage in enumerate(("i", "I", "o", "O", "e", "E", "oe", "OE"))
    ]
    topology = dict(points=points, forward=[p["id"] for p in points], client_cidrs=["10.0.0.0/8"])
    report = analyze(project, topology)
    if delayed:
        assert report["confirmed_device_drop_count"] == 0
        assert len(report["vendor_device_events"]) == 2
        assert all(
            e["status"] == "unknown" and "Unpaired later-stage" in e["reason"]
            for e in report["vendor_device_events"]
        )
        return
    assert report["confirmed_device_drop_count"] == 1
    finding = next(f for f in report["findings"] if f["type"] == "confirmed_device_drop")
    assert finding["device"] == "FW" and finding["evidence_stage"] == "i → no I/o"
    assert finding["metrics"]["count"] == 1
    drops = report["vendor_device_events"]
    assert len(drops) == 1 and drops[0]["status"] == "confirmed_device_drop"
    assert drops[0]["device"] == "FW" and drops[0]["stage"] == "i → no I/o"
    assert drops[0]["evidence"][0]["vendor"]["fw1.uuid"] == expected[8]["fw1.uuid"]
    points[0]["inspection_complete"] = False
    report = analyze(project, topology)
    assert all(e["status"] == "unknown" for e in report["vendor_device_events"])
    assert report["confirmed_device_drop_count"] == 0
    assert not any(
        f["type"] in ("confirmed_device_drop", "impactful_loss", "recovered_loss", "unrecovered_loss")
        for f in report["findings"]
    )
    inv = project.inventory()[0]["inventory"]
    assert inv["format"] == "snoop" and inv["packet_count"] == len(expected)
    points[0]["inspection_complete"] = True
    inv["damaged_tail"] = True
    with project.connect() as db:
        db.execute("UPDATE captures SET inventory=? WHERE id=?", [json.dumps(inv), cid])
        prepare_proofs(db, Topology.model_validate(topology), None, None)
        assert (
            db.execute("SELECT count(*) FROM device_proofs WHERE status='confirmed_device_drop'").fetchone()[
                0
            ]
            == 0
        )


SAMPLE = Path(__file__).parents[1] / "demo" / "samples" / "fw1_mon2018.cap"


@pytest.mark.skipif(
    bool(os.environ.get("CI")) or not SAMPLE.exists(),
    reason="Optional local Wireshark sample; never a CI fixture",
)
def test_local_fw1_sample(tmp_path, tshark):
    expected = tshark_fields(tshark, SAMPLE, CHECKPOINT_FIELDS, OPTIONS[:-2])
    project = Project(tmp_path / "sample-project")
    ingest(project, SAMPLE, tshark=tshark)
    with project.connect() as db:
        actual = [
            json.loads(v) for (v,) in db.execute("SELECT vendor FROM packets ORDER BY frame").fetchall()
        ]
    assert [{k: v.get(k, "") for k in CHECKPOINT_FIELDS} for v in actual] == expected
