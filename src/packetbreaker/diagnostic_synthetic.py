"""Mixed concurrent transport/DNS corpus; all packets constructed here, never imported."""

import json
from pathlib import Path
import random
import struct

from .synthetic import tcp_packet, write_pcap
from .realistic import datagram

POINTS = ["client", "fw_in", "fw_out", "lb_in", "lb_out", "server"]


def generate(directory, ip_id="zero", ipv6=False):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    captures = [[] for _ in POINTS]
    rng = random.Random(919)
    epoch = 1700000000

    def clients(n):
        return f"2001:db8:1::{n:x}" if ipv6 else f"10.4.0.{n}"

    server = "2001:db8:2::2" if ipv6 else "203.0.113.2"
    pid = 0 if ip_id == "zero" else 777
    cases = {}
    counter = 0

    def emit(
        time,
        forward,
        src,
        sport,
        seq,
        ack,
        flags,
        payload=b"",
        window=8192,
        options=b"",
        missing=(),
        delay_from=None,
        delay=0,
        dst=None,
    ):
        for i in range(6):
            if i in missing:
                continue
            extra = delay if forward and delay_from is not None and i >= delay_from else 0
            arrival = time + (i if forward else 5 - i) * 0.001 + extra
            packet = tcp_packet(
                src if forward else (dst or server),
                (dst or server) if forward else src,
                sport if forward else 8080,
                8080 if forward else sport,
                seq,
                ack,
                flags,
                payload,
                pid,
                ttl=64 - (i if forward else 5 - i),
                window=window,
                options=options,
            )
            captures[i].append((epoch + arrival, packet))

    def options(shift):
        return b"\x02\x04\x05\xb4\x03\x03" + bytes([shift]) + b"\x04\x02\x01\x01\x01"

    def flow(name, kind="healthy", location=None):
        nonlocal counter
        counter += 1
        src = clients(counter + 10)
        port = 41000 + counter
        isn = 1000 + counter * 100
        ssn = 9000 + counter * 100
        cases[name] = dict(
            client=src,
            port=port,
            kind=kind,
            location=location,
            expected=(
                "receiver-limited"
                if kind == "receiver"
                else "sender/application-limited"
                if kind in ("paced", "think")
                else "network-limited (loss/RTT)"
                if kind == "loss"
                else "unknown"
            ),
        )
        if kind != "no_handshake":
            emit(0.02, True, src, port, isn, 0, 2, options=options(2))
            emit(0.029, False, src, port, ssn, isn + 1, 18, options=options(3))
            emit(0.038, True, src, port, isn + 1, ssn + 1, 16)
        seq = isn + 1
        sseq = ssn + 1
        received = []
        expected = seq
        deliveries = []
        target = {"FW": 2, "LB": 4, "link": 3}.get(location)
        losses = {5, 13, 20} if kind == "loss" else {5} if kind in ("fast", "sack") else set()
        count = 24 if kind in ("loss", "delayed_ack") else 12
        echoes = (
            [] if kind == "delayed_ack" else [0.55 + k * 0.18 + rng.uniform(-0.005, 0.005) for k in range(8)]
        )

        def server_seq_at(t):
            return ssn + 1 + 79 * sum(e <= t for e in echoes)

        def receive_window_at(t):
            if kind in ("receiver", "idle_zero"):
                return (
                    0 if 1.35 <= t < 2.02 else 128 if 1.25 <= t < 1.35 else 1024 if 1.15 <= t < 1.25 else 8192
                )
            return 8192

        transmissions = []
        history = []
        if kind == "think":
            for k in range(6):
                wait = [0.08, 0.57, 0.44, 0.72, 0.38, 0.61][k]
                req = f"GET /think/{k} HTTP/1.1\r\nHost: app.test\r\n\r\n".encode()
                t = 0.6 + k * 1.05 + rng.uniform(-0.02, 0.02)
                emit(t, True, src, port, seq, sseq, 24, req)
                emit(t + 0.009, False, src, port, sseq, seq + len(req), 16)
                response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"
                emit(t + 0.005 + wait, False, src, port, sseq, seq + len(req), 24, response)
                emit(t + 0.014 + wait, True, src, port, seq + len(req), sseq + len(response), 16)
                seq += len(req)
                sseq += len(response)
            cases[name]["service_ms"] = 720
        else:
            for k in range(count):
                t = (
                    0.5
                    + k * (0.57 if kind == "paced" else 0.008 if kind in ("fast", "sack") else 0.048)
                    + rng.uniform(-0.0003, 0.0003)
                )
                if kind == "reorder":
                    t = 0.5 + k * 0.1 if k != 6 else 1.0008
                payload = (f"{name}:{k}|".encode() + b"x" * 160)[:128]
                if kind == "receiver" and k >= 8:
                    t = 2.1 + (k - 8) * 0.05
                missing = (
                    (2,)
                    if kind == "capture_miss" and k == 4
                    else tuple(range(target, 6))
                    if k in losses
                    else ()
                )
                delay = 0.002 if kind == "reorder" and k == 5 else 0
                emit(
                    t,
                    True,
                    src,
                    port,
                    seq,
                    server_seq_at(t - 0.005),
                    24,
                    payload,
                    missing=missing,
                    delay_from=target if delay else None,
                    delay=delay,
                )
                transmissions.append((t, seq + len(payload)))
                if not missing or kind == "capture_miss":
                    deliveries.append((t + 0.005 + delay, seq, payload))
                else:
                    retry = t + (1.2 if kind == "loss" else 0.065)
                    emit(retry, True, src, port, seq, server_seq_at(retry - 0.005), 24, payload)
                    transmissions.append((retry, seq + len(payload)))
                    deliveries.append((retry + 0.005, seq, payload))
                seq += len(payload)
            if kind in ("fast", "sack"):
                # Retries follow duplicate ACKs; without SACK the native fast flag remains distinct.
                cases[name]["expected"] = "unknown"
            for arrival, start, payload in sorted(deliveries):
                received.append((start, start + len(payload)))
                end = expected
                for a, b in sorted(received):
                    if a <= end:
                        end = max(end, b)
                expected = end
                history.append((arrival, expected))
                ackopts = b""
                holes = [(a, b) for a, b in received if a > expected]
                if holes and kind in ("loss", "sack", "reorder"):
                    ackopts = (
                        b"\x05\x0a"
                        + struct.pack("!II", min(a for a, b in holes), max(b for a, b in holes))
                        + b"\x01\x01"
                    )
                delay_ack = 0.25 if kind == "delayed_ack" and arrival > 1.0 else 0.004
                emit(
                    arrival + delay_ack,
                    False,
                    src,
                    port,
                    server_seq_at(arrival + delay_ack),
                    expected,
                    16,
                    options=ackopts,
                )
            for k, t in enumerate(echoes):
                known_ack = max((a for stamp, a in history if stamp <= t), default=isn + 1)
                echo_seq = ssn + 1 + 79 * k
                emit(
                    t,
                    False,
                    src,
                    port,
                    echo_seq,
                    known_ack,
                    24,
                    b"response-" + bytes([k]) * 70,
                    window=receive_window_at(t),
                )
                client_seq = max((a for stamp, a in transmissions if stamp <= t + 0.009), default=isn + 1)
                emit(t + 0.009, True, src, port, client_seq, echo_seq + 79, 16)
            sseq = ssn + 1 + 79 * len(echoes)
            if kind in ("receiver", "idle_zero"):
                for t, w in [(1.15, 1024), (1.25, 128), (1.35, 0), (1.67, 0), (1.93, 0), (2.02, 8192)]:
                    emit(
                        t,
                        False,
                        src,
                        port,
                        server_seq_at(t),
                        isn + 1 + 8 * 128 if kind == "receiver" else seq,
                        16,
                        window=w,
                    )
                if kind == "receiver":
                    # An out-of-window attempt remains in flight until the receiver reopens.
                    pending = (f"{name}:8|".encode() + b"x" * 160)[:128]
                    emit(1.40, True, src, port, isn + 1 + 8 * 128, server_seq_at(1.395), 24, pending)
                    emit(1.58, True, src, port, isn + 8 * 128, server_seq_at(1.575), 16, b"x")
                    emit(1.589, False, src, port, server_seq_at(1.589), isn + 1 + 8 * 128, 16, window=0)
            if kind == "spurious":
                emit(3.0, True, src, port, isn + 1, sseq, 24, (f"{name}:0|".encode() + b"x" * 160)[:128])
        emit(12.8, True, src, port, seq, sseq, 17)
        emit(12.81, False, src, port, sseq, seq + 1, 17)
        return src, port

    flow("receiver", "receiver")
    flow("slow_server", "think")
    flow("paced_sender", "paced")
    flow("idle_zero", "idle_zero")
    flow("high_rtt_ack_delay", "delayed_ack")
    flow("healthy")
    flow("capture_miss", "capture_miss")
    flow("missing_handshake", "no_handshake")
    flow("spurious", "spurious")
    flow("fast_recovery", "fast", "FW")
    flow("sack_recovery", "sack", "FW")
    for location in ("FW", "LB", "link"):
        flow("loss_" + location, "loss", location)
        flow("reorder_" + location, "reorder", location)
    # DNS peers reuse ID/name/type; scope by client/resolver/tuple must separate them.
    dns_cases = []
    qname = b"\x04same\x07example\x04test\0"
    qtype = 28 if ipv6 else 1
    for location in ("FW", "LB", "link"):
        for mode in ("timeout", "response_loss", "healthy"):
            src = clients(90 + len(dns_cases))
            resolver = "2001:db8:2::53" if ipv6 else "203.0.113.53"
            port = 43000 + len(dns_cases)
            t = 1.0 + len(dns_cases) * 0.071 + rng.uniform(-0.004, 0.004)
            body = struct.pack("!HHHHHH", 77, 0x100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)
            response = struct.pack("!HHHHHH", 77, 0x8180, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)
            for i in range(6):
                packet = datagram(
                    src,
                    resolver,
                    17,
                    struct.pack("!HHHH", port, 53, len(body) + 8, 0) + body,
                    pid,
                    ttl=64 - i,
                )
                captures[i].append((epoch + t + i * 0.001, packet))
                if mode != "timeout":
                    boundary = {"FW": 1, "LB": 3, "link": 2}[location]
                    if mode == "response_loss" and i <= boundary:
                        continue
                    packet = datagram(
                        resolver,
                        src,
                        17,
                        struct.pack("!HHHH", 53, port, len(response) + 8, 0) + response,
                        pid,
                        ttl=64 - (5 - i),
                    )
                    captures[i].append((epoch + t + 0.045 + (5 - i) * 0.001, packet))
            dns_cases.append(
                dict(
                    client=src,
                    port=port,
                    mode=mode,
                    location=location,
                    latency_ms=50 if mode == "healthy" else None,
                )
            )
    files = []
    points = []
    for i, name in enumerate(POINTS):
        path = directory / (name + ".pcap")
        write_pcap(path, sorted(captures[i]))
        files.append(str(path.resolve()))
        device = "FW" if name.startswith("fw_") else "LB" if name.startswith("lb_") else name.title()
        kind = "Client" if i == 0 else "Server" if i == 5 else "Firewall" if i in (1, 2) else "Load Balancer"
        points.append(
            dict(
                id=name,
                label=name.replace("_", " ").title(),
                device=device,
                kind=kind,
                side="ingress" if name.endswith("_in") else "egress" if name.endswith("_out") else "both",
                capture_id=path.name,
            )
        )
    topology = dict(
        points=points,
        forward=POINTS,
        client_cidrs=["2001:db8:1::/64"] if ipv6 else ["10.4.0.0/24"],
        dns_timeout_ms=2000,
    )
    truth = dict(files=files, cases=cases, dns=dns_cases, ip_id=ip_id, ipv6=ipv6, events=[])
    (directory / "ground-truth.json").write_text(json.dumps(truth, indent=2))
    (directory / "topology.json").write_text(json.dumps(topology, indent=2))
    return truth, topology
