from datetime import datetime, timezone
from pathlib import Path
import struct

import pytest

from packetbreaker.analysis import analyze
from packetbreaker.fortinet import convert_text, import_text
from packetbreaker.ingest import ingest
from packetbreaker.store import Project
from packetbreaker.synthetic import tcp_packet
from vendor_fixtures import tshark_fields


def records(path):
    data = Path(path).read_bytes()
    pos, result = 24, []
    while pos < len(data):
        sec, ns, size, wire = struct.unpack_from("<IIII", data, pos)
        result.append((sec * 10**9 + ns, data[pos + 16 : pos + 16 + size]))
        pos += 16 + size
    return result


def pcap_and_text(tmp_path, relative=False):
    original = tmp_path / "source.pcap"
    data = bytearray(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
    for i in range(4):
        seq = i // 2
        frame = tcp_packet(
            "10.0.0.1", "203.0.113.1", 50000, 80, 1000 + seq * 32, 9000, 24, bytes(range(32)), seq
        )
        sec, nano = 1700000001 + seq * 3, 123 + (i % 2) * 1000000
        data += struct.pack("<IIII", sec, nano, len(frame), len(frame)) + frame
    original.write_bytes(data)
    lines = ["FGT # diagnose sniffer packet any none 6 0 a", "interfaces=[any]", "filters=[none]"]
    for i, (ns, frame) in enumerate(records(original)):
        sec, nano = divmod(ns, 10**9)
        stamp = (
            f"{(ns - 1700000000000000123) / 1e9:.9f}"
            if relative
            else datetime.fromtimestamp(sec, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + f".{nano:09d}"
        )
        lines.append(f"{stamp} port{i % 2 + 1} in synthetic packet")
        for offset in range(0, len(frame), 16):
            chunk = frame[offset : offset + 16]
            if len(chunk) > 8:
                lines += [
                    f"0x{offset:04x}  " + chunk[:8].hex(" ", 2),
                    "        " + chunk[8:].hex(" ", 2) + "    ........",
                ]
            else:
                lines.append(f"0x{offset:04x}  " + chunk.hex(" ", 2) + "    ....")
    text = tmp_path / "sniffer.txt"
    text.write_bytes(("\r\n".join(lines) + "\r\n").encode())
    return original, text


def test_fortinet_round_trip_exact_bytes_and_tshark_decode(tmp_path, tshark):
    original, text = pcap_and_text(tmp_path)
    result = convert_text(text, tmp_path / "converted")
    assert {f["interface"] for f in result["files"]} == {"port1", "port2"}
    assert result["skipped_lines"] == 3 and result["skipped_packets"] == 0
    fields = ["frame.time_epoch", "frame.cap_len", "ip.src", "ip.dst", "tcp.seq_raw"]
    expected = tshark_fields(tshark, original, fields)
    for i, item in enumerate(result["files"]):
        assert records(item["path"]) == records(original)[i::2]
        assert tshark_fields(tshark, item["path"], fields) == expected[i::2]


def test_relative_requires_anchor_and_remains_low_confidence_after_cache(tmp_path, tshark):
    original, text = pcap_and_text(tmp_path, relative=True)
    with pytest.raises(ValueError, match="start time"):
        convert_text(text, tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()
    with pytest.raises(ValueError, match="timezone"):
        convert_text(text, tmp_path / "no-zone", "2023-11-14T22:13:20")
    project = Project(tmp_path / "project")
    result = import_text(project, text, "2023-11-14T22:13:20.000000123Z")
    for i, item in enumerate(result["files"]):
        assert records(item["path"]) == records(original)[i::2]
        ingest(project, item["path"], tshark=tshark)  # Reattach preserves conversion provenance.
    assert all(c["inventory"]["source_metadata"]["clock_confidence"] == "low" for c in project.inventory())
    with project.connect() as db:
        topology = project.get(db, "topology")
    assert {p["label"] for p in topology["points"]} == {"port1", "port2"}
    topology["forward"] = [p["id"] for p in topology["points"]]
    report = analyze(project, topology)
    assert all(m["confidence"] == "low" for m in report["clocks"].values())


def test_truncated_hex_console_noise_and_cooked_frames_are_reported(tmp_path):
    _, text = pcap_and_text(tmp_path)
    text.write_text(
        text.read_text()
        + """2023-11-14 22:13:30.000001 port1 -- incomplete
0x0000  0011 2233 4455 6677 8899 aabb 0800 45
0x0010  a
console prompt
2023-11-14 22:13:31.000001 port1 in cooked
linux cooked capture, packet type: 0x1
0x0000  0011 2233 4455 6677 8899 aabb 0800 4500
"""
    )
    result = convert_text(text, tmp_path / "tolerant")
    assert result["packets"] == 4 and result["skipped_packets"] == 2
    assert result["skipped_reasons"]["invalid_or_truncated_hex"] == 1
    assert result["skipped_reasons"]["unsupported_cooked_link_header"] == 1
    assert result["skipped_lines"] >= 6
