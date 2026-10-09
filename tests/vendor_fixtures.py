"""Original synthetic frame/container writers, never production dissectors."""

import csv
import io
import struct
import subprocess
from pathlib import Path

from packetbreaker.synthetic import tcp_packet


def tshark_fields(tshark, path, fields, options=()):
    args = [tshark, "-n", "-r", str(path), *options, "-T", "fields", "-E", "separator=/t", "-E", "quote=d"]
    args += ["-E", "occurrence=a"]
    for field in fields:
        args += ["-e", field]
    out = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    return [dict(zip(fields, r)) for r in csv.reader(io.StringIO(out), delimiter="\t")]


def snoop(path, delayed=False):
    data = bytearray(b"snoop\0\0\0" + struct.pack(">II", 2, 4))
    for index, sec in enumerate((0, 5, 10, 20)):
        frame = tcp_packet(
            "10.0.0.1", "203.0.113.1", 50000, 443, 1000 + 20 * index, 9000, 24, b"x" * 20, index
        )
        stages = ["i"] if index == 1 else ["i", "I", "o", "O", "e", "E", "oe", "OE"]
        if index == 1 and delayed:
            stages = ["i", "i", "I", "o", "O"]
        if index == 2:
            stages = ["i", "O"]  # A later appearance contradicts an intermediate capture miss.
        for step, stage in enumerate(stages):
            wire = (
                stage[0].encode()
                + (stage[1:2] or " ").encode()
                + b"eth0\0\0"
                + struct.pack(">I", 42)
                + frame[12:]
            )
            padding = (-len(wire)) % 4
            ts = 1700000000 + (
                5 + [0, 0.5, 3, 3.001, 3.002][step] if index == 1 and delayed else sec + step / 1000
            )
            whole = int(ts)
            data += struct.pack(
                ">6I", len(wire), len(wire), 24 + len(wire) + padding, 0, whole, round((ts - whole) * 1000000)
            )
            data += wire + b"\0" * padding
    Path(path).write_bytes(data)
    return path


def f5_capture(path, peer_reuse=False):
    import ipaddress

    def trailer(flow, peer, incoming, reason=""):
        vip = b"/Common/synthetic"
        low = bytes([1, 5 + len(vip), 1, incoming, 0, 2, len(vip)]) + vip
        cause = b"\0" + struct.pack(">Q", 0x12340002) + reason.encode() if reason else b""
        medium = (
            bytes([2, 28 + len(cause), 1])
            + struct.pack(">QQIBBI", flow, peer, 0, 0, 0, 0)
            + bytes([len(cause)])
            + cause
        )

        def addr(value):
            return b"\0" * 10 + b"\xff\xff" + ipaddress.ip_address(value).packed

        high = (
            bytes([3, 40, 0, 6])
            + struct.pack(">H", 100)
            + addr("203.0.113.2" if flow != 200 else "10.0.0.1" if peer == 100 else "10.0.0.2")
            + addr("198.51.100.2" if flow != 200 else "198.51.100.1")
            + struct.pack(
                ">HH", 80 if flow != 200 else 50000 if peer == 100 else 50001, 41000 if flow != 200 else 80
            )
        )
        return low + medium + high

    frames = []

    def emit(t, leg, reverse, seq, ack, flags, payload=b"", reason=""):
        a, b, port = (
            ("10.0.0.2", "198.51.100.1", 50001)
            if leg == "client_b"
            else ("10.0.0.1", "198.51.100.1", 50000)
            if leg == "client"
            else ("198.51.100.2", "203.0.113.2", 41000)
        )
        frame = tcp_packet(
            b if reverse else a,
            a if reverse else b,
            80 if reverse else port,
            port if reverse else 80,
            seq,
            ack,
            flags,
            payload,
            len(frames),
        )
        flow, peer = (
            (300, 200)
            if leg == "client_b"
            else (200, 300)
            if leg == "server_b"
            else (100, 200)
            if leg == "client"
            else (200, 100)
        )
        frames.append(
            (1700000000 + t, frame + trailer(flow, peer, int(leg.startswith("client") != reverse), reason))
        )

    for leg, seq in [("client", 1000), ("server", 8000)]:
        emit(0, leg, False, seq, 0, 2)
        emit(0.01, leg, True, 9000, seq + 1, 18)
        emit(0.02, leg, False, seq + 1, 9001, 16)
    if peer_reuse:
        emit(2.8, "client_b", False, 1000, 0, 2)
        emit(2.81, "client_b", True, 9000, 1001, 18)
        emit(2.82, "client_b", False, 1001, 9001, 16)
    for i, (at, delay) in enumerate([(1, 0.24), (3, 0.1)]):
        request = f"GET /synthetic/{i} HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n".encode()
        for leg, seq, when in [
            (
                "client_b" if peer_reuse and i else "client",
                1001 if peer_reuse and i else 1001 + i * len(request),
                at,
            ),
            ("server_b" if peer_reuse and i else "server", 8001 + i * len(request), at + delay),
        ]:
            emit(when, leg, False, seq, 9001, 24, request)
            emit(
                (at + delay + 0.02) if leg.startswith("client") else when + 0.01,
                leg,
                True,
                9001 if leg == "client_b" else 9001 + i * 38,
                seq + len(request),
                24,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )
    emit(4, "client", False, 1200, 9100, 20, reason="Synthetic policy reset")
    frames.sort(key=lambda f: f[0])
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, frame in frames:
        sec = int(ts)
        data += struct.pack("<IIII", sec, round((ts - sec) * 1e6), len(frame), len(frame)) + frame
    Path(path).write_bytes(data)
    return path
