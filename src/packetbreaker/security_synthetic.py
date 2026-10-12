"""Original irregular lifecycle/security traffic with healthy concurrent distractors."""

import json
import random
from pathlib import Path
from .synthetic import tcp_packet, write_pcap


def generate(directory, location="FW2", ip_id="zero", ipv6=False, rounds=100, reply_wave=False):
    location = "FW2" if location == "FW" else location
    compact = rounds < 100
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = ["client", "fw1_in", "fw1_out", "fw2_in", "fw2_out", "server"]
    captures = {p: [] for p in path}
    boundary = {"FW1": 2, "FW2": 4, "link": 3}[location]
    drop = location != "link"
    if drop:
        captures["drop"] = []
    base, rng, identity = 1700000000.0, random.Random(44), 0
    server = "2001:db8:2::2" if ipv6 else "192.0.2.2"
    populations = {}

    def address(group, n):
        return f"2001:db8:1:{group}::{n + 1:x}" if ipv6 else f"10.{group}.{n // 250}.{n % 250 + 1}"

    def packet(t, src, port, seq, ack, flags, reverse=False, stop=False, miss=False, dport=443):
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
        for i, p in enumerate(path):
            if stop and ((reverse and i < boundary) or (not reverse and i >= boundary)) or miss and i == 3:
                continue
            wire = tcp_packet(
                server if reverse else src,
                src if reverse else server,
                dport if reverse else port,
                port if reverse else dport,
                seq,
                ack,
                flags,
                b"",
                ident,
                ttl=64 - (5 - i if reverse else i),
            )
            captures[p].append((base + t + (5 - i if reverse else i) * 0.0003, wire))
            if stop and drop and i == (boundary if reverse else boundary - 1):
                captures["drop"].append((base + t + i * 0.0003, wire))

    def connection(group, n, t, healthy=True, stop=False, miss=False, dport=443, reset=False):
        src, port, seq = address(group, n), 20000 + n, 10000 + n * 100
        populations.setdefault(group, []).append(dict(src=src, port=port, time=base + t, dport=dport))
        packet(t, src, port, seq, 0, 2, stop=stop, miss=miss, dport=dport)
        if healthy or reset:
            packet(t + 0.02, src, port, 90000 + n, seq + 1, 20 if reset else 18, True, dport=dport)
        if healthy:
            packet(t + 0.025, src, port, seq + 1, 90001 + n, 16, dport=dport)
            packet(t + 0.08, src, port, seq + 1, 90001 + n, 17, dport=dport)
            packet(t + 0.09, src, port, 90001 + n, seq + 2, 17, True, dport=dport)

    # Continuous healthy calibration/coverage, including retransmitted SYN (same session).
    for n in range(34):
        connection(1, n, n + 0.1 + rng.random() * 0.03)
    # Flash crowd exceeds the flood rate but completes every handshake.
    for b in range(3, 6):
        crowd = 13 if compact else 65
        for n in range(crowd):
            connection(2, (b - 3) * crowd + n, b + 0.1 + rng.random() * 0.65)
    # Intermittent source-spread SYN wave; no replies. Drops have positive PA stage evidence.
    first_source = 0
    for b, count in zip((12, 13, 14, 15), (11, 15, 9, 13) if compact else (61, 79, 57, 63)):
        for n in range(count):
            idx = first_source + n
            stamp = b + 0.1 + rng.random() * 0.65
            connection(3, idx, stamp, healthy=False, stop=not reply_wave)
            if reply_wave:
                packet(
                    stamp + 0.02,
                    address(3, idx),
                    20000 + idx,
                    90000 + idx,
                    10001 + idx * 100,
                    18,
                    reverse=True,
                )
        first_source += count
    # One source fans out to failed destination ports. Reset handshakes are failures too.
    for n in range(8 if compact else 28):
        connection(4, 0, 21 + rng.random() * 2, healthy=False, dport=1000 + n, reset=n % 3 == 0)
        # distinct TCP tuples despite identical source port
    # Healthy health-check and NAT-pool fan-out, interleaved with the scan.
    for n in range(8 if compact else 28):
        connection(5, 0, 21 + rng.random() * 2, dport=2000 + n)
        for pool in range(4):
            connection(6, pool, 21 + rng.random() * 2, dport=3000 + n)
    # SYN missing at one capture only: established again downstream.
    connection(7, 0, 26.2, miss=True)
    # Pure SYN retry: one occupancy, two attempts, then valid three-way handshake.
    connection(8, 0, 28.2)
    packet(28.205, address(8, 0), 20000, 10000, 0, 2)
    # A SYN/ACK returning from the server stops at the selected boundary (not a forward SYN).
    connection(9, 0, 27.2, healthy=False)
    packet(27.22, address(9, 0), 20000, 90000, 10001, 18, reverse=True, stop=True)
    topology = dict(
        points=[],
        forward=path,
        reverse=path[::-1],
        client_cidrs=["2001:db8:1::/48"] if ipv6 else ["10.0.0.0/8"],
    )
    if compact:
        topology.update(
            security_syn_rate=8, security_min_sources=5, security_scan_targets=8, security_half_open_floor=5
        )
    files = []
    for p, frames in captures.items():
        file = directory / f"{p}.pcap"
        write_pcap(file, frames)
        files.append(str(file))
        device = (
            location
            if p == "drop"
            else "FW1"
            if p.startswith("fw1")
            else "FW2"
            if p.startswith("fw2")
            else p.title()
        )
        topology["points"].append(
            dict(
                id=p,
                label={
                    "fw1_in": "FW1 ingress",
                    "fw1_out": "FW1 egress",
                    "fw2_in": "FW2 ingress",
                    "fw2_out": "FW2 egress",
                }.get(p, p.title()),
                device=device,
                kind="Firewall" if device in ("FW1", "FW2") else "Client" if p == "client" else "Server",
                side="ingress" if p.endswith("in") else "egress" if p.endswith("out") else "both",
                capture_id=file.name,
                **(
                    dict(
                        vendor="paloalto",
                        vendor_stage="drop" if p == "drop" else "receive" if p.endswith("in") else "transmit",
                    )
                    if device == location and drop
                    else {}
                ),
            )
        )
    truth = dict(files=files, location=location, populations=populations, base=base, ipv6=ipv6, ip_id=ip_id)
    truth["half_open_bucket16"] = 48 if compact else 260
    (directory / "topology.json").write_text(json.dumps(topology, indent=2))
    (directory / "ground-truth.json").write_text(json.dumps(truth, indent=2))
    return truth, topology
