"""Sustained changes with explicit hop/time ground truth; synthetic addresses only."""

import json
from pathlib import Path
import random

from .synthetic import tcp_packet, write_pcap


def generate_onset(directory, scenario, ip_id="increment", ipv6=False, loss_hop=1, onset=12.0):
    if scenario not in (
        "onset_loss",
        "onset_delay",
        "onset_propagation",
        "onset_capture_miss",
        "onset_intermittent_2",
        "onset_intermittent_3",
        "onset_intermittent_4",
        "onset_intermittent_5",
        "onset_random_loss",
        "onset_signals",
    ):
        raise ValueError("Unknown onset scenario")
    if ip_id not in ("increment", "zero", "constant", "random") or not 0 <= loss_hop < 3:
        raise ValueError("Invalid synthetic identity mode or onset hop")
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    base = 1700000000.0
    captures = [[] for _ in range(5)]
    events = []
    identifier = 0
    rng = random.Random(42)
    client, server = ("fd00::10", "2001:db8::20") if ipv6 else ("10.0.0.10", "203.0.113.20")
    offsets = [0, 0.12, -0.08, 0.25, -0.04]

    def emit(t, forward, seq, ack, flags=16, payload=b"", missing=(), port=50000, window=65535):
        nonlocal identifier
        identifier += 1
        identity = {"increment": identifier, "zero": 0, "constant": 42, "random": rng.randrange(65536)}[ip_id]
        for h in range(5):
            if h in missing:
                continue
            delay = (h if forward else 4 - h) * 0.001
            if (
                scenario == "onset_delay"
                and t >= onset
                and ((forward and h > loss_hop) or (not forward and h <= loss_hop))
            ):
                delay += 0.030
            if (
                scenario == "onset_propagation"
                and t >= onset + 8
                and ((forward and h > loss_hop + 1) or (not forward and h <= loss_hop + 1))
            ):
                delay += 0.025
            a, b, sp, dp = (client, server, port, 443) if forward else (server, client, 443, port)
            captures[h].append(
                (
                    base + t + delay + offsets[h],
                    tcp_packet(
                        a,
                        b,
                        sp,
                        dp,
                        seq,
                        ack,
                        flags,
                        payload,
                        identity,
                        64 - h if forward else 60 + h,
                        window,
                    ),
                )
            )

    emit(0, True, 1000, 0, 2)
    emit(0.02, False, 9000, 1001, 18)
    emit(0.04, True, 1001, 9001)
    if scenario == "onset_signals":
        for n in range(3):
            port = 61000 + n
            emit(2 + n * 0.1, True, 7000, 0, 2, port=port)
            emit(2.02 + n * 0.1, False, 8000, 7001, 18, port=port)
            emit(2.04 + n * 0.1, True, 7001, 8001, 16, port=port)
    seq, ack = 1001, 9001
    loss_rng = random.Random(9)
    interval = int(scenario.rsplit("_", 1)[1]) if scenario.startswith("onset_intermittent_") else None
    for i in range(600 if interval or scenario == "onset_random_loss" else 400):
        t = 0.1 + i * 0.1
        missing = []
        retry = None
        lose = (
            i % (interval * 10) == 0
            if interval
            else loss_rng.random() < 0.02
            if scenario == "onset_random_loss"
            else i % 3 == 0
        )
        if t >= onset and lose:
            if scenario in ("onset_loss", "onset_propagation", "onset_random_loss") or interval:
                missing = list(range(loss_hop + 1, 5))
                retry = 0.04
                events.append(
                    dict(
                        type="recovered_loss",
                        point_a=f"p{loss_hop}",
                        point_b=f"p{loss_hop + 1}",
                        time=base + t,
                    )
                )
            elif scenario == "onset_capture_miss":
                missing = [loss_hop + 1]
                events.append(
                    dict(
                        type="capture_miss", point_a=f"p{loss_hop}", point_b=f"p{loss_hop + 1}", time=base + t
                    )
                )
        body = f"payload-{i:04d}".encode().ljust(100, b"x")
        emit(t, True, seq, ack, 24, body, missing)
        if retry:
            emit(t + retry, True, seq, ack, 24, body)
        if scenario == "onset_signals" and i in (120, 150, 180):
            n = (i - 120) // 30
            emit(t + 0.04, True, seq, ack, 24, body)
            emit(t + 0.05, False, ack + 60, seq + 100, 16, window=0)
            emit(t + 0.06, True, 7001, 8001, 4, port=61000 + n)
            emit(t + 0.07, True, 123000 + n, 0, 2, port=62000 + n, missing=list(range(loss_hop + 1, 5)))
            events.append(
                dict(
                    type="handshake_blocked",
                    point_a=f"p{loss_hop}",
                    point_b=f"p{loss_hop + 1}",
                    time=base + t + 0.07,
                )
            )
        emit(t + (retry or 0) + 0.015, False, ack, seq + 100, 24, b"r" * 60)
        seq += 100
        ack += 60
        emit(t + (retry or 0) + 0.03, True, seq, ack)
    duration = 60 if interval or scenario == "onset_random_loss" else 40
    emit(duration + 0.5, True, seq, ack, 17)
    emit(duration + 0.52, False, ack, seq + 1, 17)
    files = []
    points = []
    for h, packets in enumerate(captures):
        path = root / f"point-{h}.pcap"
        write_pcap(path, packets)
        files.append(str(path.resolve()))
        points.append(
            dict(id=f"p{h}", label=f"Point {h}", device=f"Device {h}", capture_id=path.name, x=h * 230, y=150)
        )
    expected = []
    if scenario != "onset_capture_miss":
        expected.append(
            dict(
                direction="forward",
                segment=f"forward:p{loss_hop}:p{loss_hop + 1}",
                time=events[0]["time"] if events else base + onset,
                metric="latency_p95_ms" if scenario == "onset_delay" else "loss_percent",
            )
        )
    if scenario == "onset_propagation":
        expected.append(
            dict(
                direction="forward",
                segment=f"forward:p{loss_hop + 1}:p{loss_hop + 2}",
                time=base + onset + 8,
                metric="latency_p95_ms",
            )
        )
    topology = dict(
        points=points,
        forward=[p["id"] for p in points],
        reverse=[],
        client_cidrs=["fc00::/7"] if ipv6 else ["10.0.0.0/8"],
    )
    truth = dict(
        scenario=scenario,
        ip_id=ip_id,
        ipv6=ipv6,
        files=files,
        events=events,
        onsets=expected,
        reference_epoch=base,
        loss_probability=0.02 if scenario == "onset_random_loss" else None,
        loss_seed=9 if scenario == "onset_random_loss" else None,
    )
    (root / "ground-truth.json").write_text(json.dumps(truth, indent=2))
    (root / "topology.json").write_text(json.dumps(topology, indent=2))
    return truth, topology
