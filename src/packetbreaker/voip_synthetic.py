"""Original small eight-point fixtures, with different FW/link faults and concurrent distractors."""

import json
from pathlib import Path
import random
import struct

from .synthetic import tcp_packet
from .realistic import datagram

BASE = 1700000000.0
PATH = ["client", "fw1_in", "fw1_out", "fw2_in", "fw2_out", "lb_in", "lb_out", "server"]


def write_points(path, captures):
    def block(kind, body):
        size = len(body) + 12
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)

    with path.open("wb") as f:
        f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        for _ in captures:
            f.write(block(1, struct.pack("<HHI", 1, 0, 65535)))
        for i, t, pkt in sorted((i, t, pkt) for i, packets in enumerate(captures) for t, pkt in packets):
            us = round(t * 1e6)
            f.write(
                block(
                    6,
                    struct.pack("<IIIII", i, us >> 32, us & 0xFFFFFFFF, len(pkt), len(pkt))
                    + pkt
                    + b"\0" * (-len(pkt) % 4),
                )
            )


def ber(tag, value):
    return bytes([tag, len(value)]) + value


def snmp(ident, response=False):
    bindings = ber(0x30, ber(0x30, ber(6, b"\x2b\x06\x01\x02\x01\x01\x01\x00") + ber(5, b"")))
    pdu = ber(0xA2 if response else 0xA0, ber(2, bytes([ident])) + ber(2, b"\0") + ber(2, b"\0") + bindings)
    return ber(0x30, ber(2, b"\1") + ber(4, b"fixture") + pdu)


def generate(directory, location="FW2", ip_id="zero", ipv6=False, scenario="udp"):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    location = "FW2" if location == "FW" else location
    boundary = {"FW1": 2, "FW2": 4, "link": 3}.get(location, 4)
    captures = [[] for _ in PATH]
    rng = random.Random(45)
    identity = 0
    client, server = ("2001:db8:1::1", "2001:db8:2::1") if ipv6 else ("10.1.0.1", "192.0.2.1")

    def emit(t, payload, sport, dport, reverse=False, missing=(), src=None, dst=None):
        nonlocal identity
        identity += 1
        ident = (
            0
            if ip_id == "zero"
            else 42
            if ip_id == "constant"
            else rng.randrange(65536)
            if ip_id == "random"
            else identity
        )
        src = src or client
        dst = dst or server
        for i in range(8):
            if i in missing:
                continue
            a, b = (dst, src) if reverse else (src, dst)
            sp, dp = (dport, sport) if reverse else (sport, dport)
            body = struct.pack("!HHHH", sp, dp, len(payload) + 8, 0) + payload
            captures[i].append(
                (
                    BASE + t + (7 - i if reverse else i) * 0.0003,
                    datagram(a, b, 17, body, ident, 64 - (7 - i if reverse else i)),
                )
            )

    for n in range(46):
        for reverse in (False, True):
            for i in range(8):
                pkt = tcp_packet(
                    server if reverse else client,
                    client if reverse else server,
                    80 if reverse else 20000,
                    20000 if reverse else 80,
                    1000 + n * 40,
                    1,
                    24,
                    b"calibration" + bytes([n]),
                    0 if ip_id == "zero" else 42,
                    ttl=64 - (7 - i if reverse else i),
                )
                captures[i].append(
                    (BASE + n + 0.08 + (7 - i if reverse else i) * 0.0003 + (0.04 if reverse else 0), pkt)
                )
    xmt = struct.pack("!II", 3900000001, 12345)
    q = b"\x23" + b"\0" * 39 + xmt
    r = b"\x24" + b"\0" * 23 + xmt + b"\0" * 16
    emit(8, q, 41000, 123)
    emit(8.045, r, 41000, 123, True)
    emit(9, snmp(17), 41001, 161)
    emit(9.071, snmp(17, True), 41001, 161, True)
    emit(10, bytes([1, 7, 0, 20]) + b"R" * 16, 41002, 1812)
    emit(10.036, bytes([2, 7, 0, 20]) + b"S" * 16, 41002, 1812, True)
    emit(11, b"<134>1 2023-11-14T22:13:31Z fixture app - - - synthetic", 41003, 514)
    # One unique unknown pair, then an ambiguous request ownership graph.
    emit(12, b"unknown-query", 41004, 55000)
    emit(12.083, b"unknown-reply", 41004, 55000, True)
    emit(13, b"query-a", 41005, 55001)
    emit(13.04, b"query-b", 41005, 55001)
    emit(13.08, b"reply", 41005, 55001, True)
    # Missing query at one point with downstream reappearance is only a capture miss.
    emit(14, q, 41006, 123, missing=(3,))
    emit(14.061, r, 41006, 123, True)
    # A response really stops at the selected FW/link; a healthy concurrent exchange is a distractor.
    emit(16, q, 41007, 123)
    emit(16.049, r, 41007, 123, True, missing=tuple(range(boundary)))
    q2 = b"\x23" + b"\0" * 39 + struct.pack("!II", 3900000002, 23456)
    r2 = b"\x24" + b"\0" * 23 + struct.pack("!II", 3900000002, 23456) + b"\0" * 16
    emit(16.01, q2, 41008, 123)
    emit(16.074, r2, 41008, 123, True)
    file = directory / "points.pcapng"
    write_points(file, captures)
    topology = dict(
        points=[],
        forward=PATH,
        reverse=PATH[::-1],
        client_cidrs=["2001:db8:1::/48"] if ipv6 else ["10.0.0.0/8"],
    )
    for i, p in enumerate(PATH):
        device = (
            "FW1"
            if p.startswith("fw1")
            else "FW2"
            if p.startswith("fw2")
            else "LB"
            if p.startswith("lb")
            else p.title()
        )
        topology["points"].append(
            dict(
                id=p,
                label=p.replace("_in", " ingress").replace("_out", " egress").upper()
                if p.startswith("fw")
                else p,
                device=device,
                kind="Firewall"
                if device.startswith("FW")
                else "Load Balancer"
                if device == "LB"
                else p.title(),
                capture_id=file.name,
                interface=i,
                side="ingress" if p.endswith("in") else "egress" if p.endswith("out") else "both",
            )
        )
    truth = dict(
        files=[str(file)],
        base=BASE,
        location=location,
        expected_response_hop=f"reverse:{PATH[boundary]}:{PATH[boundary - 1]}",
        ipv6=ipv6,
        ip_id=ip_id,
    )
    (directory / "topology.json").write_text(json.dumps(topology, indent=2))
    (directory / "ground-truth.json").write_text(json.dumps(truth, indent=2))
    return truth, topology
