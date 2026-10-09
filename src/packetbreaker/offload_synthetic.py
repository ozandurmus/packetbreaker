"""GSO at sender, GRO at receiver, one wire loss and one capture-only miss."""

import json
from pathlib import Path
from .synthetic import tcp_packet, write_pcap


def generate_offload(directory):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    captures = [[] for _ in range(4)]
    base = 1700000000.0
    initial = 2**32 - 1000
    mss = 1460
    size = 64000
    client, server = "10.0.0.10", "203.0.113.20"

    def add(h, t, seq, ack, flags, payload=b"", ipid=0, forward=True, bad_checksum=False):
        src, dst, sp, dp = (client, server, 50000, 443) if forward else (server, client, 443, 50000)
        packet = tcp_packet(
            src, dst, sp, dp, seq % 2**32, ack % 2**32, flags, payload, ipid, 64 - h if forward else 61 + h
        )
        if bad_checksum:
            packet = packet[:50] + b"\0\0" + packet[52:]
        captures[h].append((base + t + (h if forward else 3 - h) * 0.001, packet))

    for h in range(4):
        add(h, 0, initial, 0, 2, ipid=1)
        add(h, 0.02, 9000, initial + 1, 18, ipid=2, forward=False)
        add(h, 0.04, initial + 1, 9001, 16, ipid=3)
    events = []
    for round in range(4):
        seq = initial + 1 + round * size
        t = 1 + round * 2
        payload = (f"offload-{round:04d}:".encode() + bytes(range(256)) * 251)[:size]
        assert len(payload) == size
        slices = [(off, min(mss, size - off)) for off in range(0, size, mss)]
        lost = 12 if round == 1 else None
        capture_miss = 20 if round == 2 else None
        add(0, t, seq, 9001, 17 if round == 3 else 24, payload, 100 + round, bad_checksum=True)
        for h in (1, 2):
            for i, (off, n) in enumerate(slices):
                if h == 2 and i in (lost, capture_miss):
                    continue
                add(
                    h,
                    t + i * 0.00001,
                    seq + off,
                    9001,
                    (17 if round == 3 else 24) if off + n == size else 16,
                    payload[off : off + n],
                    1000 + round * 100 + i,
                )
        ranges = [(0, size)] if lost is None else [(0, lost * mss), ((lost + 1) * mss, size)]
        for lo, hi in ranges:
            add(
                3,
                t + (hi - 1) // mss * 0.00001,
                seq + lo,
                9001,
                17 if round == 3 else 24,
                payload[lo:hi],
                200 + round,
                bad_checksum=True,
            )
        if lost is not None:
            off = lost * mss
            for h in range(4):
                add(h, t + 0.3, seq + off, 9001, 24, payload[off : off + mss], 900 + round)
            events.append(
                dict(
                    type="impactful_loss",
                    point_a="p1",
                    point_b="p2",
                    time=base + t + 0.001 + lost * 0.00001,
                    bytes=mss,
                )
            )
        if capture_miss is not None:
            events.append(
                dict(
                    type="capture_miss",
                    point_a="p1",
                    point_b="p2",
                    time=base + t + 0.001 + capture_miss * 0.00001,
                    bytes=mss,
                )
            )
        for h in range(4):
            add(
                h,
                t + (0.32 if lost is not None else 0.02),
                9001,
                seq + size,
                16,
                ipid=50 + round,
                forward=False,
            )
    for h in range(4):
        add(h, 9.5, initial + 1 + 4 * size, 9001, 17, ipid=80)
        add(h, 9.52, 9001, initial + 2 + 4 * size, 17, ipid=81, forward=False)
    points = []
    files = []
    for h, packets in enumerate(captures):
        p = root / f"point-{h}.pcap"
        write_pcap(p, packets)
        files.append(str(p.resolve()))
        label = ["Server (GSO)", "FW", "LB", "Receiver (GRO)"][h]
        points.append(dict(id=f"p{h}", label=label, device=label, capture_id=p.name, x=h * 230, y=150))
    topology = dict(points=points, forward=[p["id"] for p in points], reverse=[], client_cidrs=["10.0.0.0/8"])
    truth = dict(
        scenario="offload",
        files=files,
        events=events,
        data_bytes=4 * size + mss,
        superframe_payload=size,
        mss=mss,
        reference_epoch=base,
    )
    (root / "ground-truth.json").write_text(json.dumps(truth, indent=2))
    (root / "topology.json").write_text(json.dumps(topology, indent=2))
    return truth, topology
