"""Synthetic wire construction only; tshark is the decoder in all assertions."""

import struct
from packetbreaker.synthetic import checksum, tcp_packet, write_pcap
from packetbreaker.realistic import datagram


def tunnel(packet, kind, truncated=False, outer6=False):
    src, dst = ("2001:db8:ffff::1", "2001:db8:ffff::2") if outer6 else ("192.0.2.10", "192.0.2.20")
    if kind in ("vxlan", "geneve"):
        port = 4789 if kind == "vxlan" else 6081
        header = b"\x08\0\0\0" if kind == "vxlan" else b"\0\0\x65\x58"
        body = header + b"\0\0\x2a\0" + packet
        return datagram(src, dst, 17, struct.pack("!HHHH", 32000, port, len(body) + 8, 0) + body, 555)
    if kind == "gre":
        return datagram(
            src, dst, 47, struct.pack("!HH", 0, int.from_bytes(packet[12:14], "big")) + packet[14:], 555
        )
    header = struct.pack("!HH", 0x1000 if kind == "erspan2" else 0x2000, 77 | (0x400 if truncated else 0))
    header += struct.pack("!I", 0) if kind == "erspan2" else struct.pack("!IHH", 0, 0, 0)
    return datagram(
        src,
        dst,
        47,
        struct.pack("!HHI", 0x1000, 0x88BE if kind == "erspan2" else 0x22EB, 7) + header + packet,
        555,
    )


def fragments(packet, fragment_id=777, overlap=False):
    ipv6 = packet[12:14] == b"\x86\xdd"
    size = 40 if ipv6 else 20
    payload = packet[14 + size :]
    chunks = [
        (0, payload[:64], True),
        (56 if overlap else 64, payload[64:128], True),
        (128, payload[128:], False),
    ]
    result = []
    for offset, body, more in chunks:
        header = bytearray(packet[14 : 14 + size])
        if ipv6:
            protocol = header[6]
            header[6] = 44
            header[4:6] = struct.pack("!H", len(body) + 8)
            body = struct.pack("!BBHI", protocol, 0, offset | int(more), fragment_id) + body
        else:
            header[2:4] = struct.pack("!H", len(body) + 20)
            header[4:6] = struct.pack("!H", fragment_id)
            header[6:8] = struct.pack("!H", (offset // 8) | (0x2000 if more else 0))
            header[10:12] = b"\0\0"
            header[10:12] = struct.pack("!H", checksum(header))
        result.append(packet[:14] + header + body)
    return result


def sample(path):
    p = tcp_packet("10.1.0.1", "10.2.0.2", 41001, 80, 1001, 2001, 24, b"x" * 180, 777)
    p6 = tcp_packet("2001:db8:1::1", "2001:db8:2::2", 41001, 80, 1001, 2001, 24, b"y" * 180, 0)
    packets = [tunnel(p, k) for k in ("erspan2", "erspan3", "gre", "vxlan", "geneve")]
    packets += fragments(p) + fragments(p6)
    write_pcap(path, [(1700000000 + i * 0.01, packet) for i, packet in enumerate(packets)])


def fragment_path(directory, ipv6=False, ip_id="zero"):
    from packetbreaker.ingest import ingest
    from packetbreaker.store import Project
    from packetbreaker.analysis import analyze

    directory.mkdir(parents=True, exist_ok=True)
    names = ["client", "fw_in", "fw_out", "lb_in", "lb_out", "server"]
    captures = [[] for _ in names]
    truth = {}
    modes = [
        ("FW", 2, None),
        ("LB", 4, None),
        ("link", 3, None),
        ("lost_middle", 2, "loss"),
        ("overlap", 2, "overlap"),
        ("capture_miss", 2, "capture_miss"),
        ("healthy", 6, None),
    ]
    for n, (name, start, fault) in enumerate(modes):
        client = f"2001:db8:1::{n + 1}" if ipv6 else f"10.1.0.{n + 1}"
        server = "2001:db8:2::2" if ipv6 else "10.2.0.2"
        port = 42000 + n
        seq = 1000 + n * 10000
        pid = 0 if ip_id == "zero" else 777
        truth[name] = dict(port=port, start=start, seq=seq + 1 + 6 * 180)

        def emit(t, forward, s, a, flags, body=b"", target=False):
            packet = tcp_packet(
                client if forward else server,
                server if forward else client,
                port if forward else 80,
                80 if forward else port,
                s,
                a,
                flags,
                body,
                pid,
            )
            for i in range(6):
                stamp = 1700000000 + t + (i if forward else 5 - i) * 0.001
                if target and i >= start:
                    parts = fragments(
                        packet, fragment_id=pid, overlap=fault == "overlap"
                    )
                    for j, part in enumerate(parts):
                        if j == 1 and ((fault == "loss" and i >= 4) or (fault == "capture_miss" and i == 3)):
                            continue
                        captures[i].append((stamp + j * 0.00007, part))
                else:
                    captures[i].append((stamp, packet))

        t = n * 0.003
        emit(0.05 + t, True, seq, 0, 2)
        emit(0.07 + t, False, 9000, seq + 1, 18)
        emit(0.09 + t, True, seq + 1, 9001, 16)
        for k in range(7):
            t = 0.2 + k * 0.19 + n * 0.002 + (k % 3) * 0.0004
            emit(t, True, seq + 1 + k * 180, 9001, 24, bytes([65 + n]) * 180, target=k == 6)
            if k != 6 or fault not in ("loss", "overlap"):
                emit(t + 0.02, False, 9001, seq + 1 + (k + 1) * 180, 16)
        if name == "healthy":
            for k in range(8):
                emit(2 + k * 0.25, True, seq + 1 + (7 + k) * 180, 9001, 24, b"h" * 180)
                emit(2.02 + k * 0.25, False, 9001, seq + 1 + (8 + k) * 180, 16)
    project = Project(directory / "project")
    points = []
    for i, name in enumerate(names):
        path = directory / (name + ".pcap")
        write_pcap(path, captures[i])
        cid = ingest(project, path)
        points.append(
            dict(
                id=name,
                label=name,
                device="FW" if name.startswith("fw") else "LB" if name.startswith("lb") else name,
                kind="Generic",
                capture_id=cid,
            )
        )
    topology = dict(
        points=points,
        forward=names,
        client_cidrs=["2001:db8:1::/64"] if ipv6 else ["10.1.0.0/24"],
        clock_overrides={p["capture_id"]: dict(offset_ms=0) for p in points},
    )
    return project, truth, topology, analyze(project, topology)


def burst_path(directory, ipv6=False, ip_id="zero"):
    import random
    from packetbreaker.ingest import ingest
    from packetbreaker.store import Project
    from packetbreaker.analysis import analyze

    rng = random.Random(713)
    directory.mkdir(parents=True, exist_ok=True)
    names = ["client", "fw_in", "fw_out", "lb_in", "lb_out", "server"]
    captures = [[] for _ in names]
    server = "2001:db8:2::2" if ipv6 else "10.2.0.2"
    pid = 0 if ip_id == "zero" else 777

    def emit(t, src, port, body, stop=6, reverse=False):
        packet = datagram(
            server if reverse else src,
            src if reverse else server,
            17,
            struct.pack("!HHHH", 5000 if reverse else port, port if reverse else 5000, len(body) + 8, 0)
            + body,
            pid,
        )
        for point in range(stop):
            captures[point].append((1700000000 + t + (5 - point if reverse else point) * 0.001, packet))

    for n, stop in enumerate([2, 4, 3, 6]):
        src = f"2001:db8:1::{n + 1}" if ipv6 else f"10.1.0.{n + 1}"
        for k in range(120):
            t = 0.2 + k * 0.25 + n * 0.003 + rng.uniform(-0.0002, 0.0002)
            lost = stop < 6 and k >= 48 and k % 4 == 0
            body = struct.pack("!II", n, k) + b"p" * 184
            emit(t, src, 44000 + n, body, stop if lost else 6)
            if not lost:
                emit(t + 0.012, src, 44000 + n, b"r" + body, reverse=True)
    src = "2001:db8:1::99" if ipv6 else "10.1.0.99"
    for t in (6.795, 12.196):
        for k in range(24):
            emit(
                t + k * 0.00002 + rng.uniform(-0.000002, 0.000002),
                src,
                45000,
                struct.pack("!I", k) + b"b" * 796,
            )
    project = Project(directory / "project")
    points = []
    for i, name in enumerate(names):
        path = directory / (name + ".pcap")
        write_pcap(path, captures[i])
        cid = ingest(project, path)
        points.append(
            dict(
                id=name,
                label=name,
                device="FW" if name.startswith("fw") else "LB" if name.startswith("lb") else name,
                kind="Generic",
                capture_id=cid,
            )
        )
    topology = dict(
        points=points,
        forward=names,
        client_cidrs=["2001:db8:1::/64"] if ipv6 else ["10.1.0.0/24"],
    )
    truth = dict(
        bursts=[1700000006.795, 1700000012.196],
        loss_hops=["forward:fw_in:fw_out", "forward:fw_out:lb_in", "forward:lb_in:lb_out"],
    )
    return project, truth, topology, analyze(project, topology)
