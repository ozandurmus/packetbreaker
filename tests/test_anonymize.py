"""Generated secrets only; tshark is the oracle for retained fields and byte offsets."""

import ipaddress
import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest
from packetbreaker.anonymize import Mapper, anonymize, local_key
from packetbreaker.synthetic import tcp_packet, write_pcap
from packetbreaker.realistic import datagram
from capture_realism_fixtures import tunnel

SECRET = b"PLANTED-private-host-secret"
KEY = bytes(range(32))


def option(code, value, endian="<"):
    return struct.pack(endian + "HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def block(kind, body, endian="<"):
    size = len(body) + 12
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def planted(path, pcapng=False, ipv6=False, endian="<"):
    src, dst = ("2001:db8:1::123", "2001:db8:2::321") if ipv6 else ("192.0.2.123", "198.51.100.231")
    packet = tcp_packet(
        src,
        dst,
        41000,
        443,
        123456,
        654321,
        24,
        SECRET,
        0,
        options=b"\x01\x01\x08\x0a" + b"\x01\x02\x03\x04" * 2,
    )
    frames = [packet] + [
        tunnel(packet, k, outer6=ipv6) for k in ("erspan2", "erspan3", "gre", "vxlan", "geneve")
    ]
    # ICMP unreachable quotes contain another IP + TCP header + planted data.
    frames.append(
        datagram(
            src, dst, 58 if ipv6 else 1, bytes([1 if ipv6 else 3, 0, 0, 0]) + b"\0" * 4 + packet[14:], 777
        )
    )
    if pcapng:
        body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
        body += b"".join(option(c, SECRET, endian) for c in (1, 2, 3, 4))
        data = block(0x0A0D0D0A, body, endian)
        data += block(
            1,
            struct.pack(endian + "HHI", 1, 0, 65535)
            + b"".join(option(c, SECRET, endian) for c in (1, 2, 3, 12))
            + option(9, b"\x06", endian),
            endian,
        )
        for i, frame in enumerate(frames):
            stamp = 1700000000000000 + i * 1000
            body = (
                struct.pack(endian + "5I", 0, stamp >> 32, stamp & 0xFFFFFFFF, len(frame), len(frame))
                + frame
                + b"\0" * (-len(frame) % 4)
                + option(1, SECRET, endian)
            )
            data += block(6, body, endian)
        rawip = ipaddress.ip_address(src).packed
        data += block(4, option(2 if ipv6 else 1, rawip + SECRET + b"\0", endian) + b"\0" * 4, endian)
        data += block(
            10,
            struct.pack(endian + "II", 0x544C534B, len(SECRET)) + SECRET + b"\0" * (-len(SECRET) % 4),
            endian,
        )
        path.write_bytes(data)
    else:
        write_pcap(path, [(1700000000 + i * 0.001, f) for i, f in enumerate(frames)])
    return frames, [
        src,
        dst,
        "2001:db8:ffff::1" if ipv6 else "192.0.2.10",
        "2001:db8:ffff::2" if ipv6 else "192.0.2.20",
    ]


def fields(tshark, path, names):
    result = subprocess.run(
        [tshark, "-n", "-r", str(path), "-T", "fields", *[x for n in names for x in ("-e", n)]],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line.split("\t") for line in result.stdout.splitlines()]


@pytest.mark.parametrize(
    "pcapng,endian,ipv6,mode",
    [
        (False, "<", False, "zero"),
        (False, "<", True, "headers-only"),
        (True, "<", False, "zero"),
        (True, ">", True, "headers-only"),
    ],
)
def test_planted_secrets_nested_headers_and_metadata(tmp_path, tshark, pcapng, endian, ipv6, mode):
    source = tmp_path / "original.cap"
    out = tmp_path / "safe.cap"
    frames, ips = planted(source, pcapng, ipv6, endian)
    before = source.read_bytes()
    result = anonymize(source, out, mode=mode, key=KEY, map_ips=True, tshark=tshark)
    assert result["packets"] == len(frames) and source.read_bytes() == before
    data = out.read_bytes()
    assert SECRET not in data
    for address in ips:
        assert ipaddress.ip_address(address).packed not in data
        assert address.encode() not in data
    assert bytes.fromhex("001122334455") not in data and bytes.fromhex("66778899aabb") not in data
    names = [
        "frame.time_epoch",
        "frame.len",
        "ip.id",
        "ip.ttl",
        "ipv6.hlim",
        "tcp.seq_raw",
        "tcp.ack_raw",
        "tcp.flags",
        "tcp.window_size_value",
        "tcp.options",
        "tcp.len",
        "ip.len",
        "ipv6.plen",
    ]
    addrfields = ["ip.src", "ipv6.src", "ip.dst", "ipv6.dst"]
    before_rows = fields(tshark, source, names + addrfields + ["frame.cap_len"])
    after_rows = fields(tshark, out, names + addrfields + ["frame.cap_len"])
    assert len(before_rows) == len(after_rows) == len(frames)
    mapper = Mapper(KEY)
    for before_row, after_row in zip(before_rows, after_rows):
        assert before_row[: len(names)] == after_row[: len(names)]
        expected = [
            ",".join(
                str(ipaddress.ip_address(mapper.ip(ipaddress.ip_address(a).packed))) for a in value.split(",")
            )
            if value
            else ""
            for value in before_row[len(names) : -1]
        ]
        assert after_row[len(names) : -1] == expected
        if mode == "zero":
            assert before_row[-1] == after_row[-1]
        else:
            assert int(after_row[-1]) < int(before_row[-1])


def test_prefix_preserving_key_consistency_and_default_ip_retention(tmp_path, tshark):
    mapper = Mapper(KEY)
    for family in (4, 16):
        addresses = [bytes([10]) + bytes(family - 2) + bytes([i]) for i in range(16)]
        for a, b in zip(addresses, addresses[1:]):

            def xor(x, y):
                return (int.from_bytes(x, "big") ^ int.from_bytes(y, "big")).bit_length()

            assert xor(a, b) == xor(mapper.ip(a), mapper.ip(b))
            assert Mapper(KEY).ip(a) == mapper.ip(a)
            assert Mapper(KEY[::-1]).ip(a) != mapper.ip(a)
    assert local_key(tmp_path / "key") == local_key(tmp_path / "key")
    p = tmp_path / "in.pcap"
    write_pcap(p, [(1700000000, tcp_packet("192.0.2.1", "198.51.100.2", 1, 2, 3, 4, 24, SECRET, 0))])
    out = tmp_path / "out.pcap"
    anonymize(p, out, tshark=tshark)
    assert fields(tshark, p, ["ip.src", "ip.dst"]) == fields(tshark, out, ["ip.src", "ip.dst"])


def test_fail_closed_no_overwrite_no_partial_output(tmp_path, tshark):
    p = tmp_path / "bad.pcap"
    write_pcap(p, [(1700000000, b"\0" * 60 + SECRET)])
    with pytest.raises(ValueError, match="Unsupported|Unknown"):
        anonymize(p, tmp_path / "out.pcap", tshark=tshark)
    assert not (tmp_path / "out.pcap").exists()
    with pytest.raises(ValueError, match="new file"):
        anonymize(p, p, tshark=tshark)
    with pytest.raises(ValueError, match="local key"):
        anonymize(p, tmp_path / "out.pcap", map_ips=True, tshark=tshark)
    assert not list(tmp_path.glob(".anonymize-*"))


def test_cli(tmp_path, monkeypatch, capsys):
    from packetbreaker.cli import main

    source = tmp_path / "in.pcap"
    write_pcap(source, [(1700000000, tcp_packet("192.0.2.1", "198.51.100.2", 1, 2, 3, 4, 24, SECRET, 0))])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "packetbreaker",
            "anonymize",
            str(source),
            str(tmp_path / "out.pcap"),
            "--map-ips",
            "--key",
            str(tmp_path / "private.key"),
        ],
    )
    main()
    assert json.loads(capsys.readouterr().out)["packets"] == 1
    assert (tmp_path / "private.key").stat().st_size == 32


@pytest.mark.parametrize(
    "anonymized_capture",
    [("zero", "zero", False), ("headers-only", "constant", True), ("headers-only", "zero", False, "pilot")],
    indirect=True,
)
def test_tcp_analysis_equivalence(anonymized_capture, scenarios, request):
    before, after, destination = anonymized_capture
    mode = request.param if hasattr(request, "param") else request.node.callspec.params["anonymized_capture"]
    scenario = mode[3] if len(mode) > 3 else "recovered_loss"
    assert scenarios(scenario, ip_id=mode[1], ipv6=mode[2])[3] is before
    destination = Path(destination)
    if before["host_path"]["items"]:
        assert before["host_path"]["local_service"]["samples"] > 0
        assert after["host_path"]["local_service"]["samples"] == 0
        assert after["host_path"]["local_service"]["reason"]
        assert [
            (s["hop"], s["direction"], s["max_ms"], s["window"]) for s in before["host_path"]["items"]
        ] == [(s["hop"], s["direction"], s["max_ms"], s["window"]) for s in after["host_path"]["items"]]
    else:
        assert before["verdict"] == after["verdict"]

    def counts(report):
        return [
            (
                s["id"],
                s["classes"],
                s["loss_percent"],
                s["eligible_packets"],
                {k: s[k] for k in ("p50_ms", "p95_ms", "max_ms", "latency_uncertainty_ms")},
            )
            for s in report["segments"]
        ]

    assert counts(before) == counts(after)
    assert [
        (f["type"], f["hop"], f["time_range"], f["severity"], f["confidence"]) for f in before["findings"]
    ] == [(f["type"], f["hop"], f["time_range"], f["severity"], f["confidence"]) for f in after["findings"]]
    assert before["onsets"]["status"] == after["onsets"]["status"]
    assert [(i["segment"], i["metric"], i["time"]) for i in before["onsets"]["items"]] == [
        (i["segment"], i["metric"], i["time"]) for i in after["onsets"]["items"]
    ]
    assert KEY not in (destination / "README.json").read_bytes()


def test_ui_archive_has_no_key_or_original_names(tmp_path, tshark):
    import io
    import zipfile
    from fastapi.testclient import TestClient
    from packetbreaker.app import create_app
    from packetbreaker.store import Project
    from packetbreaker.ingest import ingest

    path = tmp_path / "private-customer-name.pcap"
    write_pcap(path, [(1700000000, tcp_packet("192.0.2.1", "198.51.100.2", 1, 2, 3, 4, 24, SECRET, 0))])
    project = Project(tmp_path / "project")
    ingest(project, path, tshark=tshark)
    with TestClient(create_app(project.path), base_url="http://127.0.0.1") as client:
        response = client.post(
            "/api/anonymize?map_ips=true", headers={"Origin": "http://127.0.0.1", "X-PacketBreaker": "local"}
        )
    assert response.status_code == 200, response.text
    key = (project.path / ".anonymize.key").read_bytes()
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert set(archive.namelist()) == {"capture-001.pcap", "README.json"}
        for name in archive.namelist():
            data = archive.read(name)
            assert SECRET not in data and key not in data and path.name.encode() not in data


def test_host_boundary_retry_delivery_end_to_end(scenarios):
    from packetbreaker.analysis import event_page, findings_page

    project, truth, topology, report = scenarios("pilot_boundary_loss")
    losses = [f for f in report["findings"] if f["type"].endswith("path_loss")]
    assert {(f["type"], f["hop"]) for f in losses} == {
        ("host_transmit_path_loss", "reverse:host:mirror"),
        ("host_receive_path_loss", "forward:mirror:host"),
    }
    assert report["findings"][0]["type"] in ("host_receive_delay", "host_transmit_delay")
    assert report["findings"][0]["severity"] == "high"
    primary = report["findings"][0]
    assert (
        findings_page(project, primary["time_range"][0] - 30, primary["time_range"][1] + 1)["items"][0]["id"]
        == primary["id"]
    )
    for f in losses:
        assert f["confidence"] == "supported" and f["evidence"]
        direction, a, b = f["hop"].split(":")
        assert any(
            e["kind"] == f["type"] and e["recovery_class"] == "impactful_loss"
            for e in event_page(project, a, b, direction)["items"]
        )
        assert any(
            e["type"] == f["type"]
            for e in findings_page(project, f["time_range"][0] - 0.1, f["time_range"][1] + 0.1)["items"]
        )
    assert not any(
        f["type"] in ("impactful_loss", "unrecovered_loss", "recovered_loss") for f in report["findings"]
    )


def test_short_icmp_quote_and_checksums(tmp_path, tshark):
    # An ICMP quote normally has just eight transport bytes, not a full TCP header.
    original = tcp_packet("192.0.2.123", "198.51.100.231", 12345, 443, 1234, 5555, 24, SECRET, 0)
    quote = datagram("192.0.2.10", "192.0.2.20", 1, b"\x03\x01\0\0" + b"\0" * 4 + original[14:42], 7)
    source = tmp_path / "quote.pcap"
    out = tmp_path / "safe.pcap"
    write_pcap(source, [(1700000000, quote)])
    anonymize(source, out, key=KEY, map_ips=True, tshark=tshark)
    assert ipaddress.ip_address("192.0.2.123").packed not in out.read_bytes()
    assert fields(tshark, source, ["tcp.seq_raw", "icmp.type", "icmp.code"]) == fields(
        tshark, out, ["tcp.seq_raw", "icmp.type", "icmp.code"]
    )
    # Complete valid IPv4 and TCP checksums remain valid after payload/IP rewriting.
    source = tmp_path / "tcp.pcap"
    out = tmp_path / "safe-tcp.pcap"
    write_pcap(source, [(1700000000, original)])
    anonymize(source, out, key=KEY, map_ips=True, tshark=tshark)
    result = subprocess.run(
        [
            tshark,
            "-n",
            "-r",
            str(out),
            "-o",
            "ip.check_checksum:TRUE",
            "-o",
            "tcp.check_checksum:TRUE",
            "-T",
            "fields",
            "-e",
            "ip.checksum.status",
            "-e",
            "tcp.checksum.status",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "1\t1"


def test_damaged_input_cannot_publish_a_partial_capture(tmp_path, tshark):
    p = tmp_path / "tail.pcap"
    out = tmp_path / "safe.pcap"
    write_pcap(p, [(1700000000, tcp_packet("192.0.2.1", "198.51.100.2", 1, 2, 3, 4, 24, SECRET, 0))])
    with p.open("ab") as f:
        f.write(b"partial")
    with pytest.raises(ValueError):
        anonymize(p, out, tshark=tshark)
    assert not out.exists() and not list(tmp_path.glob(".anonymize-*"))


def test_erased_udp_identity_is_unknown_not_a_guessed_transaction(tmp_path, tshark):
    from packetbreaker.ingest import FIELDS, parse_packet

    source = tmp_path / "udp.pcap"
    out = tmp_path / "safe.pcap"
    udp = struct.pack("!HHHH", 42000, 42001, len(SECRET) + 8, 0) + SECRET
    write_pcap(source, [(1700000000, datagram("192.0.2.1", "198.51.100.2", 17, udp, 0))])
    anonymize(source, out, tshark=tshark)
    from packetbreaker.store import PACKET_COLUMNS

    packet = dict(zip(PACKET_COLUMNS, parse_packet(fields(tshark, out, FIELDS)[0], "fixture", 64)))
    assert "identity is insufficient" in packet["unsupported"]
    assert not json.loads(packet["path_fields"])["payload_complete"]


def test_changed_source_is_not_published(tmp_path, tshark, monkeypatch):
    from contextlib import contextmanager
    import packetbreaker.anonymize as module

    source = tmp_path / "changing.pcap"
    out = tmp_path / "safe.pcap"
    write_pcap(source, [(1700000000, tcp_packet("192.0.2.1", "198.51.100.2", 1, 2, 3, 4, 24, SECRET, 0))])
    original = module.decoded_packets

    @contextmanager
    def changed(*args, **kwargs):
        with original(*args, **kwargs) as packets:
            yield packets
        with source.open("ab") as f:
            f.write(b"still being copied")

    monkeypatch.setattr(module, "decoded_packets", changed)
    with pytest.raises(ValueError, match="Input changed"):
        anonymize(source, out, tshark=tshark)
    assert not out.exists()


def test_header_projection_equals_full_tshark_tree(tmp_path, tshark, monkeypatch):
    import packetbreaker.anonymize as module

    source = tmp_path / "input.pcap"
    planted(source)
    projected = tmp_path / "projected.pcap"
    complete = tmp_path / "complete.pcap"
    anonymize(source, projected, key=KEY, map_ips=True, tshark=tshark)
    original = module.subprocess.Popen

    def full_tree(command, **kwargs):
        command = list(command)
        index = command.index("-J")
        del command[index : index + 2]
        return original(command, **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", full_tree)
    anonymize(source, complete, key=KEY, map_ips=True, tshark=tshark)
    assert projected.read_bytes() == complete.read_bytes()
