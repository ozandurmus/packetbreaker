"""Concurrent, multi-protocol ground-truth fixtures. Packet construction only."""

import json
from pathlib import Path
import random
import socket
import struct

from .synthetic import checksum, tcp_packet, write_pcap


def datagram(src, dst, proto, payload, ipid, ttl=64):
    v6 = ":" in src
    family = socket.AF_INET6 if v6 else socket.AF_INET
    a, b = socket.inet_pton(family, src), socket.inet_pton(family, dst)
    if proto == 17:
        pseudo = (
            a
            + b
            + (struct.pack("!I3xB", len(payload), 17) if v6 else struct.pack("!BBH", 0, 17, len(payload)))
        )
        payload = payload[:6] + struct.pack("!H", checksum(pseudo + payload) or 0xFFFF) + payload[8:]
    if v6:
        ip = struct.pack("!IHBB16s16s", 0x60012345, len(payload), proto, ttl, a, b)
    else:
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ipid % 65536, 0x4000, ttl, proto, 0, a, b
        )
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return (
        b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb"
        + (b"\x86\xdd" if v6 else b"\x08\x00")
        + ip
        + payload
    )


def write_pcapng(path, packets, ifdrop=7, osdrop=2):
    def block(kind, body):
        size = len(body) + 12
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)

    with Path(path).open("wb") as f:
        f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        f.write(block(1, struct.pack("<HHI", 1, 0, 65535)))
        for ts, packet in sorted(packets):
            us = round(ts * 1e6)
            f.write(
                block(
                    6,
                    struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(packet), len(packet))
                    + packet
                    + b"\0" * ((-len(packet)) % 4),
                )
            )
        body = (
            struct.pack("<III", 0, 0, 0)
            + struct.pack("<HHQ", 5, 8, ifdrop)
            + struct.pack("<HHQ", 7, 8, osdrop)
            + b"\0" * 4
        )
        f.write(block(5, body))


def generate_realistic(directory, scenario="realistic_healthy", rounds=20, ip_id="increment", ipv6=False):
    if rounds < 12:
        raise ValueError("Realistic scenarios need at least 12 rounds")
    if ip_id not in ("increment", "zero", "constant", "random"):
        raise ValueError("Unknown ip_id mode")
    if scenario not in (
        "realistic_healthy",
        "realistic_capture_miss",
        "realistic_loss",
        "realistic_syn_blocked",
    ):
        raise ValueError("Unknown realistic scenario")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    base = 1700000000.0
    offsets = [0, 0.12, -0.08, 0.25, -0.04, 0.18]
    drifts = [0, 20, -12, 8, -4, 10]
    forward = [0, 1, 2, 3, 4]
    reverse = [4, 5, 2, 1, 0]
    captures = [[] for _ in range(6)]
    events = []
    rng = random.Random(42)
    counter = 0
    clients = {i: (f"fd00:1::{i + 1:x}" if ipv6 or i % 2 else f"10.1.0.{i + 1}") for i in range(50)}

    def emit(t, direction, builder, missing=()):
        nonlocal counter
        counter += 1
        ident = {"increment": counter, "zero": 0, "constant": 42, "random": rng.randrange(65536)}[ip_id]
        path = forward if direction == "forward" else reverse
        for pos, h in enumerate(path):
            if h in missing:
                continue
            elapsed = t + pos * 0.001
            captures[h].append(
                (base + elapsed + offsets[h] + elapsed * drifts[h] * 1e-6, builder(ident, 64 - pos))
            )

    def tcp(i, t, fw, seq, ack, flags=16, payload=b"", missing=()):
        client = clients[i]
        server = "2001:db8::20" if ":" in client else "203.0.113.20"
        src, dst, sp, dp = (client, server, 50000, 443) if fw else (server, client, 443, 50000)
        emit(
            t,
            "forward" if fw else "reverse",
            lambda ident, ttl: tcp_packet(src, dst, sp, dp, seq, ack, flags, payload, ident, ttl),
            missing,
        )

    def event(kind, t, a, b, direction="forward", flow=None):
        events.append(
            dict(
                type=kind,
                time=base + t,
                point_a=f"p{a}",
                point_b=f"p{b}",
                direction=direction,
                flow_fixture=flow,
            )
        )

    def handshake(i, t):
        tcp(i, t, True, 1000, 0, 2)
        tcp(i, t + 0.02, False, 9000, 1001, 18)
        tcp(i, t + 0.04, True, 1001, 9001)

    def close(i, t, seq, ack):
        tcp(i, t, True, seq, ack, 17)
        tcp(i, t + 0.02, False, ack, seq + 1, 17)
        tcp(i, t + 0.04, True, seq + 1, ack + 1)

    for i in range(50):
        handshake(i, 0.1 + i * 0.0005)
        seq, ack = 1001, 9001
        n = rounds // 2 if i == 0 else rounds
        for r in range(n):
            t = 1 + r * 0.4 + i * 0.0003
            payload = (b"common-content-" + str(r).zfill(6).encode()).ljust(160, b"x")
            missing = []
            recovery = 0
            if scenario == "realistic_loss" and i in (2, 17) and r >= 7 and r % 7 == 0:
                missing = [3, 4]
                recovery = 0.04 if i == 2 else 0.3
                event("recovered_loss" if recovery < 0.2 else "impactful_loss", t, 2, 3, flow=i)
            if scenario == "realistic_capture_miss" and i % 9 == 0 and r % 11 == 4:
                missing = [1]
                event("capture_miss", t, 0, 1, flow=i)
            tcp(i, t, True, seq, ack, 24, payload, missing)
            if recovery:
                tcp(i, t + recovery, True, seq, ack, 24, payload)
            return_gap = [5] if scenario == "realistic_capture_miss" and i % 9 == 0 and r % 11 == 4 else []
            tcp(
                i,
                t + recovery + 0.02,
                False,
                ack,
                seq + len(payload),
                24,
                b"response".ljust(80, b"y"),
                return_gap,
            )
            if return_gap:
                event("capture_miss", t + recovery + 0.02, 4, 5, "reverse", i)
            seq += 160
            ack += 80
            tcp(i, t + recovery + 0.035, True, seq, ack)
        close(i, 1 + n * 0.4, seq, ack)
    # Reuse the complete tuple and ISNs after clean closure, while 49 other sessions continue.
    reuse = 1 + (rounds // 2) * 0.4 + 0.2
    handshake(0, reuse)
    tcp(0, reuse + 0.1, True, 1001, 9001, 24, b"common-content-000000".ljust(160, b"x"))
    tcp(0, reuse + 0.12, False, 9001, 1161, 24, b"response".ljust(80, b"y"))
    tcp(0, reuse + 0.135, True, 1161, 9081)
    close(0, reuse + 0.3, 1161, 9081)
    # DNS over IPv4 and IPv6; responses positively prove request delivery through capture gaps.
    question = b"\x04demo\x07example\0" + struct.pack("!HH", 1, 1)
    for v6 in (False, True):
        client, server = ("fd00:99::1", "2001:db8::53") if v6 else ("10.99.0.1", "203.0.113.53")
        for r in range(12):
            t = 2 + r * 0.4
            txid = 500 + r
            query = struct.pack("!HHHHHH", txid, 0x100, 1, 0, 0, 0) + question
            reply = (
                struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
                + question
                + struct.pack("!HHHIH4s", 0xC00C, 1, 1, 60, 4, socket.inet_aton("192.0.2.123"))
            )
            missing = [3, 4] if scenario == "realistic_capture_miss" and r == 4 else []
            emit(
                t,
                "forward",
                lambda ident, ttl, q=query: datagram(
                    client, server, 17, struct.pack("!HHHH", 54000, 53, 8 + len(q), 0) + q, ident, ttl
                ),
                missing,
            )
            emit(
                t + 0.02,
                "reverse",
                lambda ident, ttl, q=reply: datagram(
                    server, client, 17, struct.pack("!HHHH", 53, 54000, 8 + len(q), 0) + q, ident, ttl
                ),
            )
            if missing:
                event("capture_miss", t, 2, 3, flow="dns6" if v6 else "dns4")
    for r in range(12):
        t = 2.1 + r * 0.4

        def echo(ident, ttl, reply=False, seq=r):
            body = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, 1234, seq) + b"echo-payload"
            body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
            return datagram(
                "203.0.113.8" if reply else "10.99.0.8",
                "10.99.0.8" if reply else "203.0.113.8",
                1,
                body,
                ident,
                ttl,
            )

        missing = [3, 4] if scenario == "realistic_capture_miss" and r == 4 else []
        emit(t, "forward", echo, missing)
        emit(t + 0.02, "reverse", lambda ident, ttl, fn=echo: fn(ident, ttl, True))
        if missing:
            event("capture_miss", t, 2, 3, flow="icmp")
    if scenario == "realistic_syn_blocked":
        client = "fd00:99::200" if ipv6 else "10.99.0.200"
        server = "2001:db8::20" if ipv6 else "203.0.113.20"
        emit(
            4,
            "forward",
            lambda ident, ttl: tcp_packet(client, server, 61000, 443, 777, 0, 2, b"", ident, ttl),
            [3, 4],
        )
        event("handshake_blocked", 4, 2, 3, flow="blocked")
    points = []
    files = []
    labels = ["Client", "FW ingress", "FW egress", "LB ingress", "Server", "Return router"]
    for h in range(6):
        path = directory / f"{h:02d}-{labels[h].lower().replace(' ', '-')}.{'pcapng' if h == 5 else 'pcap'}"
        (write_pcapng if h == 5 else write_pcap)(path, captures[h])
        files.append(str(path.resolve()))
        points.append(
            dict(
                id=f"p{h}",
                label=labels[h],
                device="FW" if h in (1, 2) else labels[h],
                capture_id=path.name,
                x=h * 200,
                y=200 if h == 5 else 0,
            )
        )
    topology = dict(
        points=points,
        forward=[f"p{i}" for i in forward],
        reverse=[f"p{i}" for i in reverse],
        client_cidrs=["10.0.0.0/8", "fc00::/7"],
        clock_overrides={
            points[h]["capture_id"]: dict(
                offset_ms=(offsets[h] + 0.1 * drifts[h] * 1e-6) * 1000, drift_ppm=drifts[h]
            )
            for h in (3, 5)
        },
    )
    truth = dict(
        scenario=scenario,
        ip_id=ip_id,
        ipv6=ipv6,
        reference_epoch=base,
        files=files,
        events=events,
        tcp_clients=50,
        tcp_sessions=51 + (scenario == "realistic_syn_blocked"),
        port_reuse_client=clients[0],
        offsets=offsets,
        drifts_ppm=drifts,
        reported_drops={"p5": dict(ifdrop=7, osdrop=2)},
        clock_note="One-way-only points use ground-truth clock overrides, never an invented offset estimate.",
    )
    (directory / "ground-truth.json").write_text(json.dumps(truth, indent=2))
    (directory / "topology.json").write_text(json.dumps(topology, indent=2))
    return truth, topology
