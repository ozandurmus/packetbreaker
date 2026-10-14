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


def generate(directory, location="FW2", ip_id="zero", ipv6=False, media_mode="faults"):
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
    maps, media_truth = add_media(captures, ipv6, location, ip_id, media_mode)
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
    # Every unchanged conversation crossing this declared NAT boundary is explicitly transparent.
    for proto, sport, dport in [
        ("TCP", 20000, 80),
        ("UDP", 41000, 123),
        ("UDP", 41001, 161),
        ("UDP", 41002, 1812),
        ("UDP", 41003, 514),
        ("UDP", 41004, 55000),
        ("UDP", 41005, 55001),
        ("UDP", 41006, 123),
        ("UDP", 41007, 123),
        ("UDP", 41008, 123),
    ]:
        key = json.dumps([proto, client, sport, server, dport], separators=(",", ":"))
        maps.append(dict(point_a="fw2_in", point_b="fw2_out", tuple_a=key, tuple_b=key))
    bad = "2001:db8:3::250" if ipv6 else "198.51.100.250"
    key = json.dumps(["UDP", bad, 41000, server, 50000], separators=(",", ":"))
    maps.append(dict(point_a="fw2_in", point_b="fw2_out", tuple_a=key, tuple_b=key))
    topology["nat_mappings"] = maps
    topology["rtp_port_ranges"] = [[40000, 40000], [44000, 44000], [50000, 50000]]
    if location != "link":
        for p in topology["points"]:
            if p["device"] == location:
                p["payload_transform"] = "alg"
    for p in topology["points"]:
        if p["id"] == "fw2_out":
            p["translation"] = "nat"
    topology["client_cidrs"] += ["2001:db8:3::/48"] if ipv6 else ["198.51.100.0/24"]
    truth = dict(
        files=[str(file)],
        base=BASE,
        location=location,
        expected_response_hop=f"reverse:{PATH[boundary]}:{PATH[boundary - 1]}",
        ipv6=ipv6,
        ip_id=ip_id,
    )
    truth.update(media_truth)
    (directory / "topology.json").write_text(json.dumps(topology, indent=2), encoding="utf-8")
    (directory / "ground-truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    return truth, topology


def sip_message(call, src, dst, addr, port, answer=False):
    family = "IP6" if ":" in addr else "IP4"
    body = f"v=0\r\no=fixture 1 1 IN {family} {addr}\r\ns=synthetic\r\nc=IN {family} {addr}\r\nt=0 0\r\nm=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
    host = f"[{src}]" if ":" in src else src
    start = "SIP/2.0 200 OK" if answer else f"INVITE sip:bob@{dst} SIP/2.0"
    return (
        f"{start}\r\nVia: SIP/2.0/UDP {host}:5060;branch=z9hG4bK-fixture-{call}\r\nFrom: <sip:alice@{host}>;tag=f{call}\r\nTo: <sip:bob@{dst}>\r\nCall-ID: call-{call}@fixture\r\nCSeq: 17 INVITE\r\nContact: <sip:alice@{host}:5060>\r\nContent-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    ).encode()


def add_media(captures, ipv6, location, ip_id, media_mode="faults"):
    rng = random.Random(451)
    maps = []
    rewrite = {"FW1": 2, "FW2": 4, "link": 3}[location]
    loss = rewrite
    clients = ["2001:db8:1::1", "2001:db8:1::2"] if ipv6 else ["10.1.0.1", "10.1.0.2"]
    peers = ["2001:db8:2::1", "2001:db8:2::2"] if ipv6 else ["192.0.2.1", "192.0.2.2"]
    pools = ["2001:db8:3::11", "2001:db8:3::12"] if ipv6 else ["198.51.100.11", "198.51.100.12"]
    bad = "2001:db8:3::250" if ipv6 else "198.51.100.250"
    for call in range(2):
        for sport, dport, mapped in [(5060, 5060, 5060), (40000, 50000, 44000)]:
            a = json.dumps(["UDP", clients[call], sport, peers[call], dport], separators=(",", ":"))
            b = json.dumps(["UDP", pools[call], mapped, peers[call], dport], separators=(",", ":"))
            maps.append(dict(point_a="fw2_in", point_b="fw2_out", tuple_a=a, tuple_b=b))
        for reverse in (False, True):
            for i in range(8):
                src = pools[call] if i >= 4 else clients[call]
                addr = (
                    peers[call]
                    if reverse
                    else (bad if call == 0 and media_mode == "faults" else pools[call])
                    if i >= rewrite
                    else clients[call]
                )
                port = (
                    50000
                    if reverse
                    else (41000 if call == 0 and media_mode == "faults" else 44000)
                    if i >= rewrite
                    else 40000
                )
                payload = sip_message(
                    call,
                    peers[call] if reverse else pools[call] if i >= rewrite else src,
                    src if reverse else peers[call],
                    addr,
                    port,
                    reverse,
                )
                a, b = (peers[call], src) if reverse else (src, peers[call])
                wire = datagram(
                    a,
                    b,
                    17,
                    struct.pack("!HHHH", 5060, 5060, len(payload) + 8, 0) + payload,
                    0 if ip_id == "zero" else 42,
                    64 - (7 - i if reverse else i),
                )
                captures[i].append(
                    (BASE + 18 + 0.06 * call + 0.04 * reverse + (7 - i if reverse else i) * 0.0003, wire)
                )
        for reverse in (False, True):
            for n in range(36):
                stamp = 20 + call * 0.004 + n * 0.02 + rng.uniform(0, 0.0004)
                seq = (65530 + n) % 65536
                rt = (4294967000 + n * 160) % 4294967296
                payload = (
                    struct.pack("!BBHII", 0x80, 0, seq, rt, 0x22222222 if reverse else 0x11111111)
                    + b"\x7f" * 20
                )
                for i in range(8):
                    if media_mode == "capture_miss" and n == 5 and i == 3:
                        continue
                    # Pure capture miss on a healthy stream reappears downstream.
                    if call == 1 and not reverse and n == 5 and i == 3:
                        continue
                    # One actual forward datagram loss after the selected FW/link.
                    if media_mode == "faults" and call == 0 and not reverse and n == 10 and i >= loss:
                        continue
                    # Wrong-SDP return for call 0; policy-drop return for call 1.
                    if media_mode == "faults" and reverse and i < loss:
                        continue
                    local = pools[call] if i >= 4 else clients[call]
                    local_port = 44000 if i >= 4 else 40000
                    if media_mode == "faults" and reverse and call == 0:
                        local = bad
                        local_port = 41000
                    a, b = (peers[call], local) if reverse else (local, peers[call])
                    sp, dp = (50000, local_port) if reverse else (local_port, 50000)
                    wire = datagram(
                        a,
                        b,
                        17,
                        struct.pack("!HHHH", sp, dp, len(payload) + 8, 0) + payload,
                        0 if ip_id == "zero" else 42,
                        64 - (7 - i if reverse else i),
                    )
                    delay = (
                        (0, 6, 1, 9, 4)[n % 5] / 1000
                        if media_mode == "faults" and i >= 6 and not reverse
                        else 0
                    )
                    if media_mode == "faults" and i >= 6 and not reverse and n == 12:
                        delay += 0.035
                    t = BASE + stamp + (7 - i if reverse else i) * 0.0003 + delay
                    captures[i].append((t, wire))
                    if call == 1 and not reverse and n == 8 and i >= 6:
                        captures[i].append((t + 0.009, wire))
    return maps, dict(
        rtp_loss_hop=f"forward:{PATH[loss - 1]}:{PATH[loss]}",
        bad_call="call-0@fixture",
        healthy_call="call-1@fixture",
    )
