"""Small deterministic PCAP writer for test fixtures, never a production dissector."""

import json
from pathlib import Path
import socket
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack("!" + str(len(data) // 2) + "H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def tcp_packet(src, dst, sport, dport, seq, ack, flags, payload, ipid, ttl=64):
    a, b = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = a + b + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ipid % 65536, 0x4000, ttl, 6, 0, a, b)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip + tcp


def write_pcap(path, packets, snaplen=65535):
    with Path(path).open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))
        for ts, packet in sorted(packets, key=lambda x: x[0]):
            sec = int(ts)
            usec = round((ts - sec) * 1e6)
            if usec == 1000000:
                sec, usec = sec + 1, 0
            captured = packet[:snaplen]
            f.write(struct.pack("<IIII", sec, usec, len(captured), len(packet)))
            f.write(captured)


def generate(
    directory,
    hops=5,
    scenario="demo",
    rounds=100,
    offsets=None,
    drifts=None,
    loss_hop=2,
    onset=12.0,
    nat_hop=2,
    delay_ms=30,
    capture_miss_hop=1,
):
    if hops < 3 or hops > 32:
        raise ValueError("Synthetic scenarios require 3–32 capture points")
    if not 0 <= loss_hop < hops - 1:
        raise ValueError("Loss hop must identify an adjacent pair")
    if not 1 <= nat_hop < hops or not 1 <= capture_miss_hop < hops - 1 or rounds < 1:
        raise ValueError("Use an interior capture-miss point, a valid NAT boundary, and positive rounds")
    supported = (
        "healthy",
        "demo",
        "capture_miss",
        "recovered_loss",
        "impactful_loss",
        "nat",
        "delay",
        "truncation",
        "duplicate",
        "acked_unseen",
    )
    if scenario not in supported:
        raise ValueError("Unknown Phase 1 scenario: " + scenario)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    offsets = offsets or [0, 0.12, -0.08, 0.25, -0.04] + [0.01 * i for i in range(max(0, hops - 5))]
    drifts = drifts or [0, 20, -12, 8, -4] + [0] * max(0, hops - 5)
    if len(offsets) < hops or len(drifts) < hops:
        raise ValueError("Provide one clock offset/drift per point")
    base = 1700000000.0
    captures = [[] for _ in range(hops)]
    events = []
    ipid = 1
    use_nat = scenario in ("demo", "nat")

    def emit(t, forward, seq, ack, flags=16, payload=b"", missing=(), repeat_id=None):
        nonlocal ipid
        identity = repeat_id or ipid
        ipid += 1
        for h in range(hops):
            if h in missing:
                continue
            client = "198.51.100.10" if use_nat and h >= nat_hop else "10.0.0.10"
            sport = 51000 if use_nat and h >= nat_hop else 50000
            src, dst, sp, dp = (
                (client, "203.0.113.20", sport, 443) if forward else ("203.0.113.20", client, 443, sport)
            )
            elapsed = t + (h if forward else hops - 1 - h) * 0.001
            if (
                scenario == "delay"
                and t >= onset
                and ((forward and h > loss_hop) or (not forward and h <= loss_hop))
            ):
                elapsed += delay_ms / 1000
            timestamp = base + elapsed + offsets[h] + elapsed * drifts[h] * 1e-6
            packet = tcp_packet(
                src, dst, sp, dp, seq, ack, flags, payload, identity, 64 - (h if forward else hops - 1 - h)
            )
            captures[h].append((timestamp, packet))
            if scenario == "duplicate" and h == capture_miss_hop and payload:
                captures[h].append((timestamp + 0.00001, packet))
        return identity

    emit(0, True, 1000, 0, 2)
    emit(0.020, False, 9000, 1001, 18)
    emit(0.040, True, 1001, 9001)
    seq, ack = 1001, 9001
    for i in range(rounds):
        t = 0.1 + i * 0.4
        payload = (f"GET /synthetic/{i:05d} HTTP/1.0\r\n\r\n".encode() + bytes([i % 256]) * 160)[:120]
        missing = []
        recovery = None
        if scenario in ("demo", "recovered_loss", "impactful_loss") and t >= onset and i % 7 == 0:
            missing = list(range(loss_hop + 1, hops))
            recovery = 0.3 if scenario == "impactful_loss" or (scenario == "demo" and i % 2 == 0) else 0.04
            events.append(
                dict(
                    type="impactful_loss" if recovery >= 0.2 else "recovered_loss",
                    point_a=f"p{loss_hop}",
                    point_b=f"p{loss_hop + 1}",
                    time=base + t,
                    recovery_ms=recovery * 1000,
                )
            )
        if scenario in ("demo", "capture_miss") and i % 13 == 5:
            missing = [capture_miss_hop]
            recovery = None
            events.append(
                dict(
                    type="capture_miss",
                    point_a=f"p{capture_miss_hop - 1}",
                    point_b=f"p{capture_miss_hop}",
                    time=base + t,
                )
            )
        if scenario == "acked_unseen" and i % 13 == 5:
            missing = list(range(loss_hop + 1, hops))
            events.append(
                dict(type="capture_miss", point_a=f"p{loss_hop}", point_b=f"p{loss_hop + 1}", time=base + t)
            )
        emit(t, True, seq, ack, 24, payload, missing)
        if recovery:
            emit(t + recovery, True, seq, ack, 24, payload)
        response_time = t + (recovery or 0) + 0.02
        emit(response_time, False, ack, seq + len(payload), 24, b"HTTP/1.0 200 OK\r\n\r\n" + b"x" * 40)
        ack += 59
        seq += len(payload)
        emit(response_time + 0.015, True, seq, ack)
    emit(rounds * 0.4 + 0.5, True, seq, ack, 17)
    emit(rounds * 0.4 + 0.52, False, ack, seq + 1, 17)
    names = ["Client", "FW ingress", "FW egress", "LB ingress", "Server"] + [
        f"Point {i}" for i in range(5, hops)
    ]
    files = []
    points = []
    for h in range(hops):
        path = directory / f"{h:02d}-{names[h].lower().replace(' ', '-')}.pcap"
        write_pcap(path, captures[h], snaplen=90 if scenario == "truncation" and h == 2 else 65535)
        files.append(str(path.resolve()))
        points.append(
            dict(
                id=f"p{h}",
                label=names[h],
                device=(
                    "NAT device"
                    if use_nat and nat_hop != 2 and h in (nat_hop - 1, nat_hop)
                    else "FW"
                    if h in (1, 2)
                    else names[h]
                ),
                kind="Firewall"
                if h in (1, 2)
                else "Client"
                if h == 0
                else "Server"
                if h == hops - 1
                else "Generic",
                side="ingress" if h == 1 else "egress" if h == 2 else "both",
                capture_id=path.name,
                translation="nat" if use_nat and h in (nat_hop - 1, nat_hop) else "none",
                x=h * 230,
                y=150,
            )
        )
    topology = dict(
        points=points,
        forward=[p["id"] for p in points],
        reverse=[],
        client_cidrs=["10.0.0.0/8", "198.51.100.10/32"],
    )
    truth = dict(
        scenario=scenario,
        reference_epoch=base,
        offsets=offsets[:hops],
        drifts_ppm=drifts[:hops],
        events=events,
        onset=base + onset if events else None,
        files=files,
    )
    (directory / "topology.json").write_text(json.dumps(topology, indent=2))
    (directory / "ground-truth.json").write_text(json.dumps(truth, indent=2))
    return truth, topology
