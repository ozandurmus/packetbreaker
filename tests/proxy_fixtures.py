"""Original HTTP/TLS wire fixtures: two full proxies, a router, and link distractors."""

import random
import struct
from pathlib import Path
from packetbreaker.synthetic import tcp_packet

POINTS = ["client", "a_in", "a_out", "r_in", "r_out", "b_in", "b_out", "server"]
LEGS = [POINTS[:2], POINTS[2:6], POINTS[6:]]


def der(tag, value):
    size = len(value)
    length = (
        bytes([size])
        if size < 128
        else bytes([0x80 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    )
    return bytes([tag]) + length + value


def certificate(name):
    def sequence(value):
        return der(0x30, value)

    alg = sequence(der(6, bytes.fromhex("2a864886f70d01010b")) + der(5, b""))

    def dn(text):
        return sequence(der(0x31, sequence(der(6, b"\x55\x04\x03") + der(12, text.encode()))))

    rsa = sequence(der(2, b"\0" + b"\xab" * 256) + der(2, b"\x01\0\x01"))
    public = sequence(
        sequence(der(6, bytes.fromhex("2a864886f70d010101")) + der(5, b"")) + der(3, b"\0" + rsa)
    )
    tbs = sequence(
        der(0xA0, der(2, b"\x02"))
        + der(2, b"\x01")
        + alg
        + dn(name + " CA")
        + sequence(der(23, b"240101000000Z") + der(23, b"300101000000Z"))
        + dn(name)
        + public
    )
    # Synthetic signature bytes; trust/signature verification is outside this detector.
    return sequence(tbs + alg + der(3, b"\0" + b"\x11" * 256))


def tls_record(kind, body):
    return bytes([kind]) + b"\x03\x03" + struct.pack("!H", len(body)) + body


def handshake(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def client_hello(sni, tls13=False):
    name = sni.encode()
    entry = b"\0" + struct.pack("!H", len(name)) + name
    data = struct.pack("!H", len(entry)) + entry
    extensions = struct.pack("!HH", 0, len(data)) + data
    if tls13:
        extensions += b"\0\x2b\0\x03\x02\x03\x04"
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\0"
        + b"\0\x02"
        + (b"\x13\x01" if tls13 else b"\0\x2f")
        + b"\x01\0"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return tls_record(22, handshake(1, body))


def server_hello(chain_name, tls13=False):
    ext = b"\0\x2b\0\x02\x03\x04" if tls13 else b""
    hello = (
        b"\x03\x03"
        + b"\x22" * 32
        + b"\0"
        + (b"\x13\x01" if tls13 else b"\0\x2f")
        + b"\0"
        + struct.pack("!H", len(ext))
        + ext
    )
    messages = handshake(2, hello)
    if not tls13:
        cert = certificate(chain_name)
        entry = len(cert).to_bytes(3, "big") + cert
        messages += handshake(11, len(entry).to_bytes(3, "big") + entry) + handshake(14, b"")
    return tls_record(22, messages) + (tls_record(23, b"\x33" * 48) if tls13 else b"")


def make_fixture(directory, ipv6=False, ip_id="zero"):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    frames = []
    ids = 0
    rng = random.Random(7332)
    client_ips = ["2001:db8:1::1", "2001:db8:1::2"] if ipv6 else ["10.1.0.1", "10.1.0.2"]
    nodes = (
        ["2001:db8:2::10", "2001:db8:2::11", "2001:db8:2::20", "2001:db8:2::21", "2001:db8:2::30"]
        if ipv6
        else ["192.0.2.10", "192.0.2.11", "192.0.2.20", "192.0.2.21", "203.0.113.2"]
    )

    def endpoints(leg, group, client=0, slot=0, tls=False):
        a, b = (
            (client_ips[client], nodes[0])
            if leg == 0
            else (nodes[1], nodes[2])
            if leg == 1
            else (nodes[3], nodes[4])
        )
        return (
            a,
            b,
            (50000 if leg == 0 else 41000 if leg == 1 else 42000) + group * 20 + client
            if leg == 0
            else (41000 if leg == 1 else 42000) + group * 20 + slot,
            443 if tls else 80,
        )

    def emit(
        leg,
        group,
        t,
        seq,
        ack,
        flags=24,
        payload=b"",
        back=False,
        client=0,
        slot=0,
        tls=False,
        omit=(),
        times=None,
        changed=None,
    ):
        nonlocal ids
        ids += 1
        identity = 0 if ip_id == "zero" else 42 if ip_id == "constant" else ids
        a, b, port, service = endpoints(leg, group, client, slot, tls)
        route = LEGS[leg][::-1] if back else LEGS[leg]
        for hop, point in enumerate(route):
            if point in omit:
                continue
            body = changed.get(point, payload) if changed else payload
            ts = times.get(point, t + hop * 0.001) if times else t + hop * 0.001
            packet = tcp_packet(
                b if back else a,
                a if back else b,
                service if back else port,
                port if back else service,
                seq,
                ack,
                flags,
                body,
                identity,
                ttl=64 - hop,
            )
            frames.append((1700000000 + ts, POINTS.index(point), packet))

    def open_leg(leg, group, client=0, slot=0, tls=False):
        base = 1000 if leg == 0 else 10000 if leg == 1 else 20000
        emit(leg, group, 0.01 + client * 0.007, base, 0, flags=2, client=client, slot=slot, tls=tls)
        emit(
            leg,
            group,
            0.03 + client * 0.011,
            9000,
            base + 1,
            flags=18,
            back=True,
            client=client,
            slot=slot,
            tls=tls,
        )
        emit(leg, group, 0.052 + client * 0.003, base + 1, 9001, flags=16, client=client, slot=slot, tls=tls)
        for at in (7.17, 13.31, 18.43):
            emit(
                leg,
                group,
                at + rng.random() * 0.02,
                base + 1,
                9001,
                flags=16,
                client=client,
                slot=slot,
                tls=tls,
            )
            emit(
                leg,
                group,
                at + 0.05 + rng.random() * 0.02,
                9001,
                base + 1,
                flags=16,
                back=True,
                client=client,
                slot=slot,
                tls=tls,
            )

    truth = {"pool": {}, "tls": {}}
    # Two concurrent identical requests, backwards arrival order into pooled server legs.
    group = 0
    for c in (0, 1):
        open_leg(0, group, client=c)
    for leg in (1, 2):
        open_leg(leg, group)
    requests = {}
    for leg in range(3):
        seq = 1001 if leg == 0 else 10001 if leg == 1 else 20001
        order = [0, 1] if leg == 0 else [1, 0]
        for c in order:
            xff = "" if leg == 0 else f"X-Forwarded-For: {client_ips[c]}\r\n"
            request = f"POST /shared HTTP/1.1\r\nHost: same.example\r\n{xff}Content-Length: 8\r\n\r\n12345678".encode()
            at, last = (
                ([1.137, 1.147] if c == 0 else [1.151, 1.159])
                if leg == 0
                else ([1.240, 1.244] if c == 0 else [1.180, 1.183])
                if leg == 1
                else ([1.300, 1.304] if c == 0 else [1.270, 1.274])
            )
            current_seq = 1001 if leg == 0 else seq
            emit(leg, group, at, current_seq, 9001, payload=request[:-4], client=c if leg == 0 else 0)
            emit(
                leg,
                group,
                last,
                current_seq + len(request) - 4,
                9001,
                payload=request[-4:],
                client=c if leg == 0 else 0,
            )
            requests[(leg, c)] = (current_seq, len(request))
            seq += len(request)
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        for i, c in enumerate((1, 0)):
            at = ([1.430, 1.410][c]) if leg == 0 else ([1.400, 1.380][c]) if leg == 1 else ([1.360, 1.350][c])
            emit(
                leg,
                group,
                at,
                9001 if leg == 0 else 9001 + i * len(response),
                requests[(leg, c)][0] + requests[(leg, c)][1],
                payload=response,
                back=True,
                client=c if leg == 0 else 0,
            )
    truth["pool"] = {
        "Proxy A": {client_ips[0]: [92, 27], client_ips[1]: [20, 27]},
        "Proxy B": {client_ips[0]: [53, 39], client_ips[1]: [84, 29]},
    }
    # Ambiguity at either proxy; the other boundary has positive causal ordering.
    for group, target in ((1, "Proxy A"), (2, "Proxy B")):
        for c in (0, 1):
            open_leg(0, group, client=c)
        for leg in (1, 2):
            open_leg(leg, group)
        for leg in range(3):
            seq = 1001 if leg == 0 else 10001 if leg == 1 else 20001
            for c in (0, 1):
                xff = f"X-Forwarded-For: {client_ips[c]}\r\n" if target == "Proxy B" and leg == 1 else ""
                payload = f"GET /ambiguous-{group} HTTP/1.1\r\nHost: same.example\r\n{xff}Content-Length: 0\r\n\r\n".encode()
                at = (
                    (2.137 + group)
                    if leg == 0 and target == "Proxy A"
                    else (2.137 + group + c * 0.020)
                    if leg == 0
                    else (2.300 + group)
                    if leg == 1 and target == "Proxy A"
                    else (2.300 + group + c * 0.020)
                    if leg == 1
                    else (2.500 + group)
                )
                override = None
                if target == "Proxy A" and leg == 1:
                    override = {
                        p: at + i * 0.001 + (c * 0.020 if p == "b_in" else 0) for i, p in enumerate(LEGS[1])
                    }
                if target == "Proxy B" and leg == 1:
                    override = {p: at + i * 0.001 for i, p in enumerate(LEGS[1])}
                    override["b_in"] = 2.400 + group
                if target == "Proxy A" and leg == 2:
                    at = 2.310 + group + c * 0.030
                emit(
                    leg,
                    group,
                    at,
                    1001 if leg == 0 else seq,
                    9001,
                    payload=payload,
                    client=c if leg == 0 else 0,
                    times=override,
                )
                seq += len(payload)
    cases = ["consistent", "Proxy A", "Proxy B", "Router", "link", "tls13"]
    for group, case in enumerate(cases, start=4):
        for leg in range(3):
            open_leg(leg, group, tls=True)
        sni = f"tls-{group}.example"
        truth["tls"][case] = sni
        at = 5 + group * 0.173 + rng.random() * 0.013
        for leg in range(3):
            hello = client_hello(sni, case == "tls13")
            emit(
                leg,
                group,
                at + leg * 0.05,
                1001 if leg == 0 else 10001 if leg == 1 else 20001,
                9001,
                payload=hello,
                tls=True,
            )
        chain2 = "Origin"
        chain1 = "ProxyB" if case == "Proxy B" else "Origin"
        chain0 = "ProxyA" if case == "Proxy A" else chain1
        for leg, chain in ((2, chain2), (1, chain1), (0, chain0)):
            payload = server_hello(chain, case == "tls13")
            changed = {}
            if leg == 1 and case == "Router":
                changed = {p: server_hello("Router") for p in ("r_in", "a_out")}
            if leg == 1 and case == "link":
                changed = {"a_out": server_hello("Link")}
            emit(
                leg,
                group,
                at + 0.3 + (2 - leg) * 0.05,
                9001,
                (1001 if leg == 0 else 10001 if leg == 1 else 20001)
                + len(client_hello(sni, case == "tls13")),
                payload=payload,
                back=True,
                tls=True,
                changed=changed,
            )
    file = directory / "proxy-points.pcapng"

    def block(kind, body):
        body += b"\0" * (-len(body) % 4)
        size = len(body) + 12
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)

    with file.open("wb") as out:
        out.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        for _ in POINTS:
            out.write(block(1, struct.pack("<HHI", 1, 0, 65535)))
        for ts, iface, packet in sorted(frames):
            tick = round(ts * 1e6)
            out.write(
                block(
                    6,
                    struct.pack("<IIIII", iface, tick >> 32, tick & 0xFFFFFFFF, len(packet), len(packet))
                    + packet,
                )
            )
    topology = dict(
        points=[],
        forward=POINTS,
        reverse=POINTS[::-1],
        client_cidrs=(
            ["2001:db8:1::/64", nodes[1] + "/128", nodes[3] + "/128"]
            if ipv6
            else ["10.1.0.0/16", nodes[1] + "/32", nodes[3] + "/32"]
        ),
    )
    for i, p in enumerate(POINTS):
        device = (
            "Proxy A"
            if p.startswith("a_")
            else "Proxy B"
            if p.startswith("b_")
            else "Router"
            if p.startswith("r_")
            else p.title()
        )
        kind = "Proxy" if device.startswith("Proxy") else "Router/Switch" if device == "Router" else device
        topology["points"].append(
            dict(
                id=p,
                label=p,
                device=device,
                kind=kind,
                side="ingress" if p.endswith("_in") else "egress" if p.endswith("_out") else "both",
                capture_id=file.name,
                interface=i,
                translation="full_proxy" if device.startswith("Proxy") else "none",
            )
        )
    return file, topology, truth
