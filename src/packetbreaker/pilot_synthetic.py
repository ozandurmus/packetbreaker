"""Original six-file pilot replica; no bytes or identifiers from a real incident."""

from pathlib import Path
import random
import struct
import json
from packetbreaker.synthetic import tcp_packet, write_pcap

BASE = 1700000000.0
PATH = ["a_rx", "a_tx", "b_rx", "b_tx", "mirror", "host"]
RETURN = ["host", "mirror", "b_rx", "b_tx", "a_rx", "a_tx"]


def make_pilot(
    directory,
    *,
    healthy=False,
    ipv6=False,
    fault="host",
    noise=2000,
    shared=True,
    ip_id="zero",
    boundary_loss=False,
    flows=2,
    real_case=False,
    host_jitter_us=1,
    rounds=27,
    affected_flows=1,
    slow_local_flow=False,
    opaque=False,
):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    rng = random.Random(177)
    captures = {p: [] for p in PATH}
    client = "2001:db8:1::1" if ipv6 else "10.40.0.1"
    server = "2001:db8:2::1" if ipv6 else "192.0.2.20"
    truth = dict(start=BASE + 20, end=BASE + 45, rx=[], tx=[], local_ms=0.5, fault=fault)

    def emit(point, t, reverse, port, seq, ack, flags, payload=b"", identity=None):
        src, dst = (server, client) if reverse else (client, server)
        sp, dp = (8080, port) if reverse else (port, 8080)
        # A stage hook may see post-routing TTL already at rx; it is not a wire interface.
        ttl = 61 if point.endswith("rx") else 64
        if real_case:
            levels = (
                {"a_rx": 0, "a_tx": 1, "b_rx": 1, "b_tx": 2, "mirror": 2, "host": 2}
                if not reverse
                else {"host": 0, "mirror": 0, "b_rx": 0, "b_tx": 1, "a_rx": 1, "a_tx": 2}
            )
            ttl = 64 - levels[point]
        pid = (
            0
            if ip_id == "zero"
            else 42
            if ip_id == "constant"
            else ((identity if identity is not None else seq + ack + flags) % 65536)
        )
        packet = tcp_packet(src, dst, sp, dp, seq, ack, flags, payload, pid, ttl=ttl)
        jitter = (
            rng.uniform(-0.0002, 0.0002)
            if point == "mirror"
            else rng.uniform(-host_jitter_us * 1e-6, host_jitter_us * 1e-6)
            if point == "host"
            else rng.uniform(-0.000001, 0.000001)
        )
        captures[point].append((BASE + t + jitter + (0.04 if point == "host" else 0), packet))

    for call, port in enumerate(range(41000, 41000 + flows)):
        sq, rq = 1000 + call * 100000, 9000 + call * 100000
        for point in PATH:
            emit(point, 0, False, port, sq, 0, 2)
            emit(point, 0.001, True, port, rq, sq + 1, 18)
            emit(point, 0.002, False, port, sq + 1, rq + 1, 16)
        sq += 1
        rq += 1
        for n in range(rounds):
            t = 4 + n * 2 + call * 0.02
            active = not healthy and call < affected_flows and 20 <= t < 45
            rx = [0.1, 0.35, 0.85, 1.3][n % 4] if active and n % 3 != 1 else 0
            tx = [0.1, 0.45, 0.85, 1.3][n % 4] if active and n % 3 == 1 else 0
            if active:
                truth["rx"].append(rx * 1000)
                truth["tx"].append(tx * 1000)
            req_header = b"POST /pilot HTTP/1.1\r\nHost: fixture\r\nContent-Length: 3125\r\n\r\n"
            req = (req_header + b"x" * 3200)[:3200]
            # Exact body length for tshark reassembly.
            req_header = f"POST /pilot HTTP/1.1\r\nHost: fixture\r\nContent-Length: {3200 - len(req_header)}\r\n\r\n".encode()
            req = (req_header + b"x" * 3200)[:3200]
            res_header = b"HTTP/1.1 200 OK\r\nContent-Length: 3159\r\n\r\n"
            res_header = f"HTTP/1.1 200 OK\r\nContent-Length: {3200 - len(res_header)}\r\n\r\n".encode()
            response = (res_header + b"y" * 3200)[:3200]
            if opaque:
                req, response = b"Q" * 3200, b"R" * 3200
            host_receive = t + 0.00008 + (rx if fault == "host" else rx + tx)
            if boundary_loss and call == 0 and n == 3:
                host_receive += 0.3
            response_time = host_receive + (0.188 if slow_local_flow and call == flows - 1 else 0.0005)
            for reverse, path, payload, base_seq, ack in [
                (False, PATH, req, sq, rq),
                (True, RETURN, response, rq, sq + 3200),
            ]:
                for i, point in enumerate(path):
                    if reverse:
                        origin = response_time + (tx if fault == "host" and point != "host" else 0)
                    else:
                        origin = t + (rx if fault == "host" and point == "host" else 0)
                    if (
                        fault != "host"
                        and active
                        and i >= path.index("b_rx" if reverse and fault == "mirror" else fault)
                    ):
                        origin += rx + tx
                    if real_case and reverse and fault == "host":
                        origin = response_time
                    chunks = (
                        [(0, payload)]
                        if point == "host"
                        else [(j, payload[j : j + 800]) for j in range(0, 3200, 800)]
                    )
                    for offset, chunk in chunks:
                        if point.endswith(("rx", "tx")) and rng.random() < 0.01:
                            continue
                        lost = (
                            boundary_loss and call == 0 and ((n == 3 and not reverse) or (n == 4 and reverse))
                        )
                        stamp = origin + i * 0.000016 + offset / 800 * 0.000002
                        identity = (base_seq // 800 + offset // 800 + port) % 5000
                        if real_case and active and reverse and tx > 0:
                            # Original is captured at the host, absent on every downstream wire point.
                            if point == "host":
                                emit(point, stamp, reverse, port, base_seq + offset, ack, 24, chunk, identity)
                            emit(
                                point,
                                stamp + 0.2,
                                reverse,
                                port,
                                base_seq + offset,
                                ack,
                                24,
                                chunk,
                                identity + 5000,
                            )
                            continue
                        if real_case and active and not reverse and rx >= 0.85:
                            compressed = i >= path.index(fault)
                            for retry, gap in enumerate((0, 0.2, 0.6)):
                                when = stamp + (retry * 0.001 if compressed else gap)
                                emit(
                                    point,
                                    when,
                                    reverse,
                                    port,
                                    base_seq + offset,
                                    ack,
                                    24,
                                    chunk,
                                    identity + retry * 5000,
                                )
                            continue
                        if lost:
                            if (reverse and point != "host") or (not reverse and point == "host"):
                                stamp += 0.3
                            else:
                                emit(point, stamp + 0.3, reverse, port, base_seq + offset, ack, 24, chunk)
                        emit(
                            point,
                            stamp,
                            reverse,
                            port,
                            base_seq + offset,
                            ack,
                            24,
                            chunk,
                            identity if real_case else None,
                        )
            sq += 3200
            rq += 3200
            # Unique ACK anchors are unaffected by selective data-path timestamp delays.
            for point in PATH:
                emit(point, t + 1.7, False, port, sq, rq, 16)
                emit(point, t + 1.701, True, port, rq, sq, 16)
    for point in PATH:
        write_pcap(directory / (point + ".pcap"), captures[point])
    # Stream unrelated traffic into the host file with bounded generator memory.
    noise_packets = [
        tcp_packet("10.99.0.1", "198.18.0.1", 45000 + i, 443, 1, 1, 24, b"n" * 400, i) for i in range(1000)
    ]
    with (directory / "host.pcap").open("ab") as f:
        for i in range(noise):
            packet = noise_packets[i % 1000]
            t = BASE + 1 + (i % 600000) * 0.0001
            f.write(struct.pack("<IIII", int(t), round((t - int(t)) * 1e6), len(packet), len(packet)))
            f.write(packet)
    points = []
    for point in PATH:
        device = "A" if point.startswith("a_") else "B" if point.startswith("b_") else point
        points.append(
            dict(
                id=point,
                label=point,
                device=device,
                side="ingress" if point.endswith("rx") else "egress" if point.endswith("tx") else "both",
                capture_id=point + ".pcap",
                stage_capture="_" in point,
                host_capture=point == "host",
                clock_domain="appliance" if shared and point != "host" else None,
                kind="Server" if point == "host" else "Firewall" if "_" in point else "Router/Switch",
            )
        )
    topology = dict(
        points=points, forward=PATH, reverse=RETURN, client_cidrs=[client + ("/128" if ipv6 else "/32")]
    )
    truth["files"] = [str(directory / (p + ".pcap")) for p in PATH]
    truth.update(
        scenario="real_case_2" if real_case else "pilot",
        expected_local_p95_ms=0.5,
        host_noise_frames=noise,
        flows=flows,
    )
    (directory / "ground-truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    (directory / "topology.json").write_text(json.dumps(topology, indent=2), encoding="utf-8")
    return truth, topology
