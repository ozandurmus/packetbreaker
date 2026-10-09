from pathlib import Path
import struct

from packetbreaker.analysis import analyze
from packetbreaker.ingest import ingest
from packetbreaker.store import Project
from packetbreaker.synthetic import tcp_packet
from vendor_fixtures import tshark_fields


def test_paloalto_drop_is_positive_without_path_coverage(tmp_path, tshark):
    project = Project(tmp_path / "project")
    points = []
    expected_drop = None
    for stage in ("receive", "firewall", "transmit", "drop"):
        path = tmp_path / (stage + ".pcap")
        data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for n in range(5):
            if (stage == "drop" and n != 2) or (stage == "transmit" and n == 2):
                continue
            reverse = n in (1, 3)
            frame = tcp_packet(
                "203.0.113.1" if reverse else "10.0.0.1",
                "10.0.0.1" if reverse else "203.0.113.1",
                443 if reverse else 50000,
                50000 if reverse else 443,
                1000 + n * 20,
                9000,
                24,
                b"x" * 20,
                n,
            )
            data += struct.pack("<IIII", 1700000000 + n * 3, 0, len(frame), len(frame)) + frame
        path.write_bytes(data)
        cid = ingest(project, path, tshark=tshark)
        if stage == "drop":
            expected_drop = tshark_fields(tshark, path, ["frame.number", "tcp.seq_raw"])
        points.append(
            dict(id=stage, label=stage, device="PA", capture_id=cid, vendor="paloalto", vendor_stage=stage)
        )
    report = analyze(
        project, dict(points=points, forward=["receive", "firewall", "transmit"], client_cidrs=["10.0.0.0/8"])
    )
    drops = report["vendor_device_events"]
    assert len(drops) == len(expected_drop) == 1
    assert drops[0]["status"] == "confirmed_device_drop" and drops[0]["device"] == "PA"
    ref = drops[0]["evidence"][0]
    assert ref["vendor"]["stage"] == "drop" and ref["file"] == Path("drop.pcap").name
    assert ref["frame"] == int(expected_drop[0]["frame.number"])
    assert f"tcp.seq_raw == {expected_drop[0]['tcp.seq_raw']}" in ref["content_filter"]
    assert len(report["coverage"]) == 3  # Drop-only file does not collapse common path coverage.

    standalone = analyze(project, dict(points=[points[-1]], forward=[], client_cidrs=["10.0.0.0/8"]))
    assert len(standalone["vendor_device_events"]) == len(expected_drop)
    assert standalone["vendor_device_events"][0]["status"] == "confirmed_device_drop"
