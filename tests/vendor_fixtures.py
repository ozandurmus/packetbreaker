"""Original synthetic frame/container writers, never production dissectors."""

import csv
import io
import struct
import subprocess
from pathlib import Path

from packetbreaker.synthetic import tcp_packet


def tshark_fields(tshark, path, fields, options=()):
    args = [tshark, "-n", "-r", str(path), *options, "-T", "fields", "-E", "separator=/t", "-E", "quote=d"]
    for field in fields:
        args += ["-e", field]
    out = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    return [dict(zip(fields, r)) for r in csv.reader(io.StringIO(out), delimiter="\t")]


def snoop(path):
    data = bytearray(b"snoop\0\0\0" + struct.pack(">II", 2, 4))
    for index, sec in enumerate((0, 5, 10, 20)):
        frame = tcp_packet(
            "10.0.0.1", "203.0.113.1", 50000, 443, 1000 + 20 * index, 9000, 24, b"x" * 20, index
        )
        stages = ["i"] if index == 1 else ["i", "I", "o", "O", "e", "E", "oe", "OE"]
        if index == 2:
            stages = ["i", "O"]  # A later appearance contradicts an intermediate capture miss.
        for step, stage in enumerate(stages):
            wire = (
                stage[0].encode()
                + (stage[1:2] or " ").encode()
                + b"eth0\0\0"
                + struct.pack(">I", index + 42)
                + frame[12:]
            )
            padding = (-len(wire)) % 4
            data += struct.pack(
                ">6I", len(wire), len(wire), 24 + len(wire) + padding, 0, 1700000000 + sec, step * 1000
            )
            data += wire + b"\0" * padding
    Path(path).write_bytes(data)
    return path
