"""Multi-device attribution truth in separate pcapng interfaces (one shared, exact clock)."""

import json
import struct
from pathlib import Path
from .synthetic import tcp_packet

CASES = (
    "reset_origin",
    "mtu_black_hole",
    "mss_clamping",
    "option_stripping",
    "dscp_remark",
    "payload_modified",
)
BOUNDARIES = {"FW": ("fw_in", "fw_out"), "LB": ("lb_in", "lb_out"), "link": ("fw_out", "lb_in")}
LABELS = dict(
    client="Client",
    fw_in="FW ingress",
    fw_out="FW egress",
    lb_in="LB ingress",
    lb_out="LB egress",
    server="Server",
    alternate="Alternate return",
)
GUARDS = (
    "server_gap",
    "server_gap_inside_lb",
    "no_endpoint",
    "equal_ttl_supported",
    "equal_ttl_unknown",
    "mtu_capture_miss",
)


def generate_attribution(directory, asymmetric=False, fault_location="FW", ip_id="zero", ipv6=False):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = ["client", "fw_in", "fw_out", "lb_in", "lb_out", "server"]
    points = path + (["alternate"] if asymmetric else [])
    a, b = BOUNDARIES["FW" if fault_location == "all" else fault_location]
    boundary = path.index(b)
    reverse = list(reversed(path))
    if asymmetric:
        reverse = {
            "FW": ["server", "lb_out", "lb_in", "alternate", "client"],
            "LB": ["server", "alternate", "fw_out", "fw_in", "client"],
            "link": ["server", "lb_out", "lb_in", "alternate", "fw_out", "fw_in", "client"],
        }[fault_location]
    captures = {p: [] for p in points}
    client, server = ("2001:db8:1::1", "2001:db8:2::2") if ipv6 else ("10.1.0.1", "192.0.2.2")
    identity = 0

    def emit(
        t,
        port,
        seq,
        payload=b"x" * 80,
        flags=24,
        back=False,
        omit=(),
        change=None,
        options=b"",
        origin=None,
        ttl_override=None,
    ):
        nonlocal identity
        identity += 1
        ident = 0 if ip_id == "zero" else 42 if ip_id == "constant" else identity
        route = reverse if back else path
        for step, point in enumerate(route):
            if point in omit or origin is not None and step < route.index(origin):
                continue
            body, opts, dscp = payload, options, 0
            ttl = ttl_override - (step - route.index(origin)) if ttl_override is not None else 64 - step
            if not back and path.index(point) >= boundary and change:
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
                server if back else client,
                client if back else server,
                80 if back else port,
                port if back else 80,
                seq,
                1,
                flags,
                body,
                ident,
                ttl=ttl,
                options=opts,
                dscp=dscp,
            )
            captures[point].append((1700000000 + t + step * 0.001, packet))

    cases = [
        (location, case)
        for location in (BOUNDARIES if fault_location == "all" else [fault_location])
        for case in (("asymmetric_return",) if asymmetric else (*CASES, "ttl_path"))
    ]
    expected = []
    for index, (location, case) in enumerate(cases):
        a, b = BOUNDARIES[location]
        boundary = path.index(b)
        port = 40000 + index
        for n in range(12):
            emit(n, port, 1000 + n * 80)
            emit(n + 0.1, port, 5000 + n * 80, back=True)
        if case == "reset_origin":
            emit(8.4, port, 99999, payload=b"", flags=20, origin=b, ttl_override=128)
        elif case == "mtu_black_hole":
            for n in range(3):
                emit(8 + n, port, 100000 + n * 1400, payload=b"L" * 1400, omit=path[boundary:])
            emit(15, port, 888888, payload=b"", flags=4)
        elif case in ("mss_clamping", "option_stripping"):
            options = struct.pack("!BBH", 2, 4, 1460)
            if case == "option_stripping":
                options += b"\x03\x03\x07\x04\x02\x08\x0a" + struct.pack("!II", 1234, 0)
            emit(8.4, port, 99999, payload=b"", flags=2, options=options, change=case)
        elif case != "asymmetric_return":
            emit(8.4, port, 99999, change=case)
        expected.append(
            dict(
                type="asymmetric_routing" if asymmetric else case,
                port=port,
                device=None if location == "link" else location,
                fault_location=location,
                point_a=a,
                point_b=b,
                location="link between FW egress and LB ingress" if location == "link" else location,
            )
        )
    guards = {}
    if not asymmetric and fault_location in ("FW", "all"):
        for index, case in enumerate(GUARDS):
            port = 50000 + index
            guards[case] = port
            for n in range(12):
                emit(n, port, 1000 + n * 80)
                emit(n + 0.1, port, 5000 + n * 80, back=True)
            if case == "mtu_capture_miss":
                for n in range(3):
                    emit(8 + n, port, 100000 + n * 1400, payload=b"L" * 1400, omit=["fw_out"])
            elif case.startswith("equal_ttl"):
                emit(8.4, port, 99999, payload=b"", flags=20, back=True, origin="fw_in", ttl_override=64)
            else:
                emit(
                    8.4,
                    port,
                    99999,
                    payload=b"",
                    flags=20,
                    back=True,
                    omit=["server", "lb_out"]
                    if case == "server_gap_inside_lb"
                    else ["server"]
                    if case == "server_gap"
                    else [],
                )
    file = directory / "points.pcapng"

    def block(kind, body):
        body += b"\0" * (-len(body) % 4)
        size = 12 + len(body)
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)

    with file.open("wb") as stream:
        stream.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        for point in points:
            stream.write(block(1, struct.pack("<HHI", 1, 0, 65535)))
        for ts, interface, packet in sorted(
            (ts, i, packet) for i, p in enumerate(points) for ts, packet in captures[p]
        ):
            tick = round(ts * 1e6)
            stream.write(
                block(
                    6,
                    struct.pack("<IIIII", interface, tick >> 32, tick & 0xFFFFFFFF, len(packet), len(packet))
                    + packet,
                )
            )
    topology = dict(
        points=[], forward=path, reverse=reverse, client_cidrs=["2001:db8:1::/64"] if ipv6 else ["10.0.0.0/8"]
    )
    for interface, p in enumerate(points):
        device = "FW" if p.startswith("fw_") else "LB" if p.startswith("lb_") else LABELS[p]
        kind = (
            "Client"
            if p == "client"
            else "Server"
            if p == "server"
            else "Firewall"
            if device == "FW"
            else "Load Balancer"
            if device == "LB"
            else "Generic"
        )
        topology["points"].append(
            dict(
                id=p,
                label=LABELS[p],
                device=device,
                kind=kind,
                capture_id=file.name,
                interface=interface,
                side="ingress" if p.endswith("_in") else "egress" if p.endswith("_out") else "both",
            )
        )
    truth = dict(files=[str(file)], findings=expected, guards=guards, fault_location=fault_location)
    (directory / "ground_truth.json").write_text(json.dumps(truth, indent=2))
    return truth, topology
