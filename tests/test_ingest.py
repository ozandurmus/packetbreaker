import json
from pathlib import Path
import struct
import subprocess
import threading
from unittest.mock import patch

import pytest

from packetbreaker.ingest import ingest
from packetbreaker.metadata import metadata
from packetbreaker.store import Project
from packetbreaker.synthetic import generate


def test_cache_does_not_launch_tshark(scenarios):
    project, truth, _, _ = scenarios("healthy")
    with patch("packetbreaker.ingest.subprocess.Popen", side_effect=AssertionError("Cache launched tshark")):
        cid = ingest(project, truth["files"][0])
    assert cid == project.inventory()[0]["id"]


def test_cancel_resume_is_exact(tmp_path, tshark):
    truth, _ = generate(tmp_path / "input", rounds=60, scenario="healthy")
    project = Project(tmp_path / "project")
    stop = threading.Event()

    def progress(**values):
        if values.get("frames", 0) >= 25:
            stop.set()

    with pytest.raises(InterruptedError):
        ingest(project, truth["files"][0], tshark=tshark, cancel=stop, progress=progress, batch_size=25)
    c = project.inventory()[0]
    assert c["state"] == "cancelled" and c["checkpoint"] == 25
    ingest(project, truth["files"][0], tshark=tshark)
    with project.connect() as db:
        count, unique = db.execute("SELECT count(*),count(DISTINCT frame) FROM packets").fetchone()
    assert count == unique == 185
    assert project.inventory()[0]["state"] == "ready"


def test_pcapng_inventory_and_real_tshark(tmp_path, tshark):
    truth, _ = generate(tmp_path / "input", scenario="healthy", rounds=3)
    out = tmp_path / "sample.pcapng"
    editcap = Path(tshark).with_name("editcap.exe" if Path(tshark).suffix == ".exe" else "editcap")
    subprocess.run(
        [str(editcap), "-F", "pcapng", truth["files"][0], str(out)], check=True, capture_output=True
    )
    data = metadata(out)
    assert data["format"] == "pcapng"
    assert data["interfaces"][0]["link_type"] == 1
    assert data["ifdrop"] is None
    project = Project(tmp_path / "project")
    ingest(project, out, tshark=tshark)
    assert project.inventory()[0]["inventory"]["packet_count"] == 14


def test_isb_cumulative_drop_counters(tmp_path):
    def block(kind, body):
        size = 12 + len(body)
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)

    def option(code, n):
        return struct.pack("<HHQ", code, 8, n)

    data = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    data += block(1, struct.pack("<HHI", 1, 0, 96))
    for drops in (4, 7):
        data += block(5, struct.pack("<III", 0, 0, 0) + option(5, drops) + option(7, 2) + b"\0" * 4)
    path = tmp_path / "stats.pcapng"
    path.write_bytes(data)
    result = metadata(path)
    assert result["ifdrop"] == 7 and result["osdrop"] == 2
    assert result["interfaces"][0]["snaplen"] == 96


def test_file_change_invalidates_cache(tmp_path, tshark):
    truth, _ = generate(tmp_path / "input", scenario="healthy", rounds=3)
    project = Project(tmp_path / "project")
    cid = ingest(project, truth["files"][0], tshark=tshark)
    generate(tmp_path / "input", scenario="healthy", rounds=4)
    assert ingest(project, truth["files"][0], tshark=tshark) == cid
    assert project.inventory()[0]["inventory"]["packet_count"] == 17
    with project.connect() as db:
        assert json.loads(db.execute("SELECT identity FROM captures").fetchone()[0])[1] > 0


def test_invalid_container_is_rejected(tmp_path):
    path = tmp_path / "bad.pcapng"
    path.write_bytes(b"not a capture")
    with pytest.raises(ValueError, match="pcap"):
        metadata(path)


@pytest.mark.parametrize("link_type", [1, 101, 113, 276, 9001])
def test_common_link_types_and_vlan(tmp_path, tshark, link_type):
    from packetbreaker.synthetic import tcp_packet

    frame = tcp_packet("10.0.0.10", "203.0.113.20", 50000, 443, 1234, 9001, 24, b"payload-for-link-test", 42)
    if link_type == 101:
        frame = frame[14:]
    elif link_type == 113:
        frame = struct.pack("!HHH8sH", 0, 1, 6, b"\x11" * 8, 0x0800) + frame[14:]
    elif link_type == 276:
        frame = struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 0, 6, b"\x11" * 8) + frame[14:]
    elif link_type == 9001:
        frame = frame[:12] + b"\x88\xa8\x00\x01\x81\x00\x00\x02\x08\x00" + frame[14:]
    path = tmp_path / "link.pcap"
    path.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1 if link_type == 9001 else link_type)
        + struct.pack("<IIII", 1700000000, 0, len(frame), len(frame))
        + frame
    )
    project = Project(tmp_path / "project")
    ingest(project, path, tshark=tshark)
    with project.connect() as db:
        assert db.execute("SELECT proto,src,seq,length FROM packets").fetchone() == (
            "TCP",
            "10.0.0.10",
            1234,
            21,
        )


def test_duckdb_external_access_disabled_by_default(tmp_path):
    project = Project(tmp_path / "project")
    with project.connect() as db:
        with pytest.raises(Exception, match="disabled|Permission"):
            db.execute("SELECT * FROM read_csv('/etc/hosts')")


def test_tunnel_identity_is_not_mixed_with_inner_transport():
    from packetbreaker.ingest import FIELDS, parse_packet
    from packetbreaker.store import PACKET_COLUMNS

    values = {
        "frame.number": "1",
        "frame.time_epoch": "1700000000",
        "frame.protocols": "eth:ip:udp:vxlan:eth:ip:tcp",
        "tcp.srcport": "50000",
        "tcp.dstport": "443",
        "ip.src": "10.0.0.1",
        "ip.dst": "10.0.0.2",
    }
    row = dict(zip(PACKET_COLUMNS, parse_packet([values.get(f, "") for f in FIELDS], "test", 64)))
    assert "Tunnel encapsulation" in row["unsupported"]


def test_superframe_ingests_for_byte_range_matching(tmp_path, tshark):
    from packetbreaker.synthetic import tcp_packet, write_pcap

    path = tmp_path / "offload.pcap"
    write_pcap(
        path, [(1700000000, tcp_packet("10.0.0.1", "203.0.113.1", 50000, 443, 123, 456, 24, b"x" * 64000, 2))]
    )
    project = Project(tmp_path / "project")
    ingest(project, path, tshark=tshark)
    with project.connect() as db:
        length, reason, prefix = db.execute("SELECT length,unsupported,prefix FROM packets").fetchone()
    assert length == 64000
    assert reason is None
    assert len(prefix) == 128
    with project.connect() as db:
        db.execute("UPDATE packets SET unsupported='Possible offload super-frame; legacy parser'")
    reopened = Project(project.path)
    assert reopened.inventory()[0]["state"] == "stale"
    ingest(reopened, path, tshark=tshark)
    assert reopened.inventory()[0]["state"] == "ready"
    with reopened.connect() as db:
        assert db.execute("SELECT unsupported FROM packets").fetchone()[0] is None


def test_engine_upgrade_invalidates_report_but_keeps_current_index(tmp_path, tshark):
    from packetbreaker import __version__

    truth, _ = generate(tmp_path / "input", scenario="healthy", rounds=1)
    project = Project(tmp_path / "project")
    ingest(project, truth["files"][0], tshark=tshark)
    with project.connect() as db:
        project.set(db, "analysis_version", "0.1.0")
        project.set(db, "report", {"verdict": "stale report"})
    reopened = Project(project.path)
    with reopened.connect() as db:
        assert reopened.get(db, "report") is None
        assert reopened.get(db, "analysis_version") == __version__
        assert db.execute("SELECT count(*) FROM packets").fetchone()[0] == 8
    assert reopened.inventory()[0]["state"] == "ready"
