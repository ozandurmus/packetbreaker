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
