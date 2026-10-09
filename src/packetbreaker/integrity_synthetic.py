"""Original tiny path-integrity fixtures; no external capture data."""

import json
import struct
from pathlib import Path
from .synthetic import tcp_packet, write_pcap

CASES = (
    "reset_origin",
    "mtu_black_hole",
    "mss_clamping",
    "option_stripping",
    "dscp_remark",
    "payload_modified",
    "ttl_path",
)


def generate_integrity(directory, scenario="integrity_all", ipv6=False, ip_id="increment"):
    case = scenario.removeprefix("integrity_")
    if case not in (*CASES, "all", "asymmetric_return", "capture_miss"):
        raise ValueError("Unknown integrity fixture")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    points = ["client", "fw_in", "fw_out", "server"]
    if case == "asymmetric_return":
        points.append("alternate")
    captures = {point: [] for point in points}
    base = 1700000000.0
    client, server = ("2001:db8:1::1", "2001:db8:2::2") if ipv6 else ("10.1.0.1", "192.0.2.2")
    cases = CASES if case == "all" else (case,)
    expected = []
    identity = 0

    def emit(t, index, seq, payload=b"x" * 80, flags=24, reverse=False, omit=(), change=None, options=b""):
        nonlocal identity
        identity += 1
        ident = (
            0
            if ip_id == "zero"
            else 42
            if ip_id == "constant"
            else (identity * 7919) % 65536
            if ip_id == "random"
            else identity
        )
        for hop, point in enumerate(points):
            if point in omit:
                continue
            if case == "asymmetric_return":
                if reverse and point in ("fw_in", "fw_out"):
                    continue
                # Alternate point sees calibration traffic in both directions on a separate flow.
                if not reverse and point == "alternate" and index == 0:
                    continue
            elif point == "alternate":
                continue
            body = payload
            opts = options
            ttl = 64 - (3 - hop if reverse else hop)
            dscp = 0
            if hop >= 2 and change:
                if change == "mss_clamping":
                    opts = struct.pack("!BBH", 2, 4, 1200)
                if change == "option_stripping":
                    opts = struct.pack("!BBH", 2, 4, 1460)
                if change == "dscp_remark":
                    dscp = 46
                if change == "ttl_path":
                    ttl -= 4
                if change == "payload_modified":
                    body = b"z" + payload[1:]
            packet = tcp_packet(
                server if reverse else client,
                client if reverse else server,
                80 if reverse else 40000 + index,
                40000 + index if reverse else 80,
                seq,
                1,
                flags,
                body,
                ident,
                ttl=ttl,
                options=opts,
                dscp=dscp,
            )
            delay = (3 - hop if reverse else hop) * 0.001 if hop < 4 else 0.0015
            captures[point].append((base + t + delay, packet))

    for index, kind in enumerate(cases):
        for n in range(31):
            if kind == "reset_origin" and n >= 10:
                continue
            emit(n, index, 1000 + n * 80)
            emit(n + 0.1, index, 5000 + n * 80, reverse=True)
        if kind == "reset_origin":
            emit(10, index, 99999, payload=b"", flags=20, omit=("client", "fw_in"))
        elif kind == "mtu_black_hole":
            for n in range(3):
                emit(10 + n, index, 100000 + n * 1400, payload=b"L" * 1400, omit=("fw_out", "server"))
            emit(18, index, 888888, payload=b"", flags=4)
        elif kind in ("mss_clamping", "option_stripping"):
            options = struct.pack("!BBH", 2, 4, 1460)
            if kind == "option_stripping":
                options += b"\x03\x03\x07\x04\x02\x08\x0a" + struct.pack("!II", 1234, 0)
            emit(10.4, index, 99999, payload=b"", flags=2, options=options, change=kind)
        elif kind == "capture_miss":
            emit(10.4, index, 99999, omit=("fw_in",))
        elif kind != "asymmetric_return":
            emit(10.4, index, 99999, change=kind)
        if kind not in ("capture_miss", "asymmetric_return"):
            expected.append(dict(type=kind, device="Firewall", point_a="fw_in", point_b="fw_out"))
    if case in ("asymmetric_return", "reset_origin"):
        for n in range(31):
            emit(n, 99, 200000 + n * 80)
            emit(n + 0.1, 99, 300000 + n * 80, reverse=True)
    if case == "asymmetric_return":
        expected.append(dict(type="asymmetric_routing", device="Firewall"))
    files = []
    topology = dict(
        points=[],
        forward=points[:4],
        reverse=["server", "alternate", "client"] if case == "asymmetric_return" else points[:4][::-1],
        client_cidrs=["2001:db8:1::/64"] if ipv6 else ["10.0.0.0/8"],
    )
    for point in points:
        path = directory / f"{point}.pcap"
        write_pcap(path, captures[point])
        files.append(str(path))
        topology["points"].append(
            dict(
                id=point,
                label=point,
                device="Firewall" if point.startswith("fw_") else point,
                kind="Firewall" if point.startswith("fw_") else "Generic",
                capture_id=path.name,
                side="ingress" if point == "fw_in" else "egress" if point == "fw_out" else "both",
            )
        )
    truth = dict(scenario=scenario, files=files, findings=expected)
    (directory / "ground_truth.json").write_text(json.dumps(truth, indent=2))
    return truth, topology
