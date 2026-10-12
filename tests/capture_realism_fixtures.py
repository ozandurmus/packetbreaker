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
