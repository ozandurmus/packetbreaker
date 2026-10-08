from pathlib import Path
import struct
from unittest.mock import patch
import pytest

from packetbreaker.ingest import ingest
from packetbreaker.realistic import write_pcapng
from packetbreaker.store import Project
from packetbreaker.synthetic import tcp_packet, write_pcap


def fixture(path, kind, packets=3):
    frame = tcp_packet("10.0.0.1", "203.0.113.1", 50000, 443, 1, 1, 24, b"payload" * 10, 42)
    data = [(1700000000 + i, frame) for i in range(packets)]
    (write_pcap if kind == "pcap" else write_pcapng)(path, data)
    return frame


def append_partial(path, kind, frame):
    with path.open("ab") as f:
        if kind == "pcap":
            f.write(struct.pack("<IIII", 1700000005, 0, len(frame), len(frame)) + frame[:12])
        else:
            size = 32 + (len(frame) + 3) // 4 * 4
            f.write(struct.pack("<IIIIIII", 6, size, 0, 0, 123456, len(frame), len(frame)) + frame[:12])


@pytest.mark.parametrize("kind", ["pcap", "pcapng"])
def test_cut_short_keeps_frames_and_caches_warning(tmp_path, tshark, kind):
    path = tmp_path / f"cut.{kind}"
    frame = fixture(path, kind)
    append_partial(path, kind, frame)
    project = Project(tmp_path / "project")
    cid = ingest(project, path, tshark=tshark, batch_size=2)
    c = project.inventory()[0]
    assert c["state"] == "ready" and c["inventory"]["packet_count"] == 3
    assert c["inventory"]["warnings"] == [
        "File ends mid-packet; last partial record ignored; 3 packets usable"
    ]
    with patch(
        "packetbreaker.ingest.subprocess.Popen",
        side_effect=AssertionError("Ready damaged-tail file reparsed"),
    ):
        assert ingest(project, path, tshark=tshark) == cid


@pytest.mark.parametrize("kind", ["pcap", "pcapng"])
def test_zero_usable_frames_still_fails(tmp_path, tshark, kind):
    path = tmp_path / f"empty.{kind}"
    frame = fixture(path, kind, packets=0)
    append_partial(path, kind, frame)
    with pytest.raises(ValueError):
        ingest(Project(tmp_path / "project"), path, tshark=tshark)


@pytest.mark.parametrize("kind", ["pcap", "pcapng"])
@pytest.mark.parametrize("variant", ["zero_tail", "zero_mid", "both", "future_mid"])
def test_padding_and_invalid_timestamps(tmp_path, tshark, kind, variant):
    import time
    from packetbreaker.metadata import metadata

    path = tmp_path / f"capture.{kind}"
    frame = fixture(path, kind, packets=5)
    data = bytearray(path.read_bytes())
    if variant in ("zero_mid", "both", "future_mid"):
        ts = int(time.time() + 2 * 86400) if variant == "future_mid" else 0
        if kind == "pcap":
            start = 24 + 2 * (16 + len(frame))
            struct.pack_into("<II", data, start, ts, 0)
        else:
            block_size = 32 + (len(frame) + 3) // 4 * 4
            start = 48 + 2 * block_size
            us = ts * 1_000_000
            struct.pack_into("<II", data, start + 12, us >> 32, us & 0xFFFFFFFF)
    padding = (16 if kind == "pcap" else 12) * 25 + (7 if variant == "both" else 0)
    if variant in ("zero_tail", "both"):
        data.extend(b"\0" * padding)
    path.write_bytes(data)
    info = metadata(path)
    if variant in ("zero_tail", "both"):
        assert info["frame_limit"] == 5 and info["zero_tail_bytes"] == padding
        assert info["zero_tail_records"] == 25
    project = Project(tmp_path / "project")
    ingest(project, path, tshark=tshark, batch_size=2)
    c = project.inventory()[0]
    i = c["inventory"]
    assert c["state"] == "ready"
    assert i["packet_count"] == (5 if variant == "zero_tail" else 4)
    assert (i["start"], i["end"]) == (1700000000, 1700000004)
    assert i["timestamps_validated"]
    with project.connect() as db:
        assert db.execute("SELECT min(ts),max(ts) FROM packets").fetchone() == (1700000000, 1700000004)
        if variant != "zero_tail":
            excluded = db.execute("SELECT frame,reason FROM excluded_frames").fetchall()
            assert excluded == [
                (
                    3,
                    "timestamp_after_now_plus_one_day"
                    if variant == "future_mid"
                    else "timestamp_before_2000",
                )
            ]
    if variant in ("zero_tail", "both"):
        assert any(w.startswith("Zero-filled tail ignored: 25 records / ") for w in i["warnings"])


def test_old_ready_inventory_is_not_used_until_timestamp_upgrade(tmp_path):
    import json

    project = Project(tmp_path / "project")
    with project.connect() as db:
        project.set(db, "schema_version", 3)
        db.execute(
            "INSERT INTO captures VALUES ('old','source','source','identity','ready',1,?,NULL)",
            [json.dumps({"start": 0, "end": 1700000000})],
        )
    reopened = Project(project.path)
    assert reopened.inventory()[0]["state"] == "stale"


def test_clock_fit_and_coverage_never_receive_invalid_times(tmp_path, tshark):
    from packetbreaker.synthetic import generate, bind_capture_ids
    from packetbreaker.analysis import analyze

    truth, topology = generate(tmp_path / "input", scenario="healthy", rounds=30)
    path = Path(truth["files"][1])
    data = bytearray(path.read_bytes())
    pos = 24
    frame = 0
    while pos < len(data):
        frame += 1
        caplen = struct.unpack_from("<I", data, pos + 8)[0]
        if frame % 4 == 0:
            struct.pack_into("<II", data, pos, 0, 0)
        pos += 16 + caplen
    path.write_bytes(data)
    project = Project(tmp_path / "project")
    bind_capture_ids(topology, {Path(p).name: ingest(project, p, tshark=tshark) for p in truth["files"]})
    report = analyze(project, topology)
    assert all(c["start"] > 946684800 for c in report["coverage"])
    assert all(c["epoch"] > 946684800 for c in report["clocks"].values())
    assert any(s["excluded_counts"].get("timestamp_before_2000") for s in report["segments"])
    assert report["verdict"] == "Inconclusive"
    with project.connect() as db:
        assert db.execute("SELECT min(ts) FROM obs").fetchone()[0] > 946684800
