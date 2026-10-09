"""Synthetic, concurrent translated TCP sessions; no real captures."""

import json
from pathlib import Path
import random
import socket
import struct

from .synthetic import generate, tcp_packet, write_pcap


def generate_translation(directory, inconsistent=False, ip_id="zero", ipv6=False):
    truth, topology = generate(
        directory, scenario="recovered_loss", rounds=70, ip_id=ip_id, ipv6=ipv6, loss_hop=2
    )
    rng = random.Random(20261009)
    offsets = {
        50000: (rng.randrange(4294963296, 4294967296), rng.randrange(1, 2**32)),
        50001: (rng.randrange(1, 2**32), rng.randrange(1, 2**32)),
    }
    for h, name in enumerate(truth["files"]):
        raw = Path(name).read_bytes()
        position = 24
        packets = []
        while position < len(raw):
            sec, usec, caplen, _ = struct.unpack_from("<IIII", raw, position)
            position += 16
            packet = raw[position : position + caplen]
            position += caplen
            ip = 14
            v6 = packet[12:14] == b"\x86\xdd"
            tcp = ip + (40 if v6 else 20)
            src = socket.inet_ntop(
                socket.AF_INET6 if v6 else socket.AF_INET,
                packet[ip + 8 : ip + 24] if v6 else packet[ip + 12 : ip + 16],
            )
            dst = socket.inet_ntop(
                socket.AF_INET6 if v6 else socket.AF_INET,
                packet[ip + 24 : ip + 40] if v6 else packet[ip + 16 : ip + 20],
            )
            sp, dp, seq, ack = struct.unpack_from("!HHII", packet, tcp)
            flags = packet[tcp + 13]
            payload = packet[tcp + 20 :]
            ipid = 0 if v6 else struct.unpack_from("!H", packet, ip + 4)[0]
            ttl = packet[ip + 7 if v6 else ip + 8]
            forward = sp != 443
            for port, (f, r) in offsets.items():
                delta = f + (
                    777
                    if inconsistent and port == 50000 and sec + usec / 1e6 - truth["reference_epoch"] >= 18
                    else 0
                )
                qseq, qack = seq, ack
                if h >= 2:
                    qseq = (seq + (delta if forward else r)) % 2**32
                    if (
                        inconsistent == "reverse_once"
                        and port == 50000
                        and not forward
                        and seq == 9591
                        and len(payload) == 59
                    ):
                        qseq = (qseq + 777) % 2**32
                    if flags & 16:
                        qack = (ack + (r if forward else delta)) % 2**32
                packets.append(
                    (
                        sec + usec / 1e6 + (port - 50000) * 0.002,
                        tcp_packet(
                            src,
                            dst,
                            port if forward else sp,
                            dp if forward else port,
                            qseq,
                            qack,
                            flags,
                            payload,
                            ipid,
                            ttl,
                        ),
                    )
                )
        write_pcap(name, packets)
    for h in (1, 2):
        topology["points"][h].update(device="Sequence randomizer", translation="seq_randomization")
    truth["scenario"] = "sequence_inconsistent" if inconsistent else "sequence_randomization"
    truth["sequence_offsets"] = {str(port): dict(forward=f, reverse=r) for port, (f, r) in offsets.items()}
    truth["events"] = [dict(e, client_port=port) for e in truth["events"] for port in offsets]
    Path(directory, "ground-truth.json").write_text(json.dumps(truth, indent=2))
    Path(directory, "topology.json").write_text(json.dumps(topology, indent=2))
    return truth, topology
