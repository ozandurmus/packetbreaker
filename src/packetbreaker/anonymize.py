"""Offline capture sanitization. tshark supplies all protocol spans and identities.

Only the capture container is parsed here. Unknown encapsulations fail closed.
"""

from contextlib import contextmanager
from functools import lru_cache
import hashlib
import hmac
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from .ingest import find_tshark
from .metadata import options

MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
HEADERS = {
    "eth",
    "ethertype",
    "vlan",
    "ip",
    "ipv6",
    "ipv6.hopopts",
    "ipv6.dstopts",
    "ipv6.routing",
    "ipv6.fraghdr",
    "gre",
    "erspan",
    "vxlan",
    "geneve",
    "sll",
    "sll2",
    "null",
    "loop",
    "arp",
}
IP_FIELDS = {"ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "arp.src.proto_ipv4", "arp.dst.proto_ipv4"}
MAC_FIELDS = {"eth.src", "eth.dst", "arp.src.hw_mac", "arp.dst.hw_mac", "sll.src.eth"}


class Mapper:
    def __init__(self, key):
        if len(key) < 32:
            raise ValueError("Anonymization key must contain at least 32 random bytes")
        self.key = key

    @lru_cache(maxsize=65536)
    def ip(self, raw):
        # Keyed binary prefix tree permutation. No address map needs to be stored.
        bits = len(raw) * 8
        original = int.from_bytes(raw, "big")
        result = 0
        for n in range(bits):
            prefix = (original >> (bits - n)) << (bits - n)
            mask = (
                hmac.digest(
                    self.key, b"ip" + bytes([len(raw), n]) + prefix.to_bytes(len(raw), "big"), "sha256"
                )[0]
                >> 7
            )
            result = (result << 1) | (((original >> (bits - n - 1)) & 1) ^ mask)
        return result.to_bytes(len(raw), "big")

    @lru_cache(maxsize=65536)
    def mac(self, raw):
        digest = bytearray(hmac.digest(self.key, b"mac" + raw, "sha256")[:6])
        digest[0] = (digest[0] & 252) | 2 | (raw[0] & 1)
        return bytes(digest)


def local_key(path):
    path = Path(path)
    if not path.exists():
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as output:
                output.write(os.urandom(32))
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("Local key must be exactly 32 bytes")
    return key


@contextmanager
def decoded_packets(path, tshark=None):
    command = [
        find_tshark(tshark),
        "-n",
        "-r",
        str(path),
        "-T",
        "pdml",
        "-o",
        "tcp.desegment_tcp_streams:FALSE",
        "-o",
        "ip.defragment:FALSE",
        "-o",
        "ipv6.defragment:FALSE",
        "-o",
        "tcp.analyze_sequence_numbers:FALSE",
    ]
    with tempfile.TemporaryFile() as errors:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors)

        def packets():
            iterator = ET.iterparse(proc.stdout, events=("start", "end"))
            _, root = next(iterator)
            for event, element in iterator:
                if event == "end" and element.tag == "packet":
                    yield element
                    root.clear()
            if proc.wait():
                raise ValueError(
                    "tshark could not decode the complete capture; no anonymized output published"
                )

        try:
            yield iter(packets())
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.wait()
            proc.stdout.close()


def span(element):
    return int(element.get("pos", "0")), int(element.get("size", "0"))


def adjust_checksum(old, new, pos, start, end, pseudo=()):
    if pos + 2 > len(new):
        return
    value = (~int.from_bytes(old[pos : pos + 2], "big")) & 65535
    # RFC 1624 differential update also preserves the syndrome of a bad/offload checksum.
    for a, b in [(start, min(end, len(old))), *pseudo]:
        for i in range(a, b, 2):
            if i == pos:
                continue
            before = int.from_bytes(old[i : min(i + 2, b)].ljust(2, b"\0"), "big")
            after = int.from_bytes(new[i : min(i + 2, b)].ljust(2, b"\0"), "big")
            value += (~before & 65535) + after
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    new[pos : pos + 2] = ((~value) & 65535).to_bytes(2, "big")


def sanitize_packet(raw, packet, mode, mapper, map_ips):
    if mode not in ("zero", "headers-only"):
        raise ValueError("Payload mode must be zero or headers-only")
    protocols = [p for p in packet.iter("proto") if p.get("name") not in ("geninfo", "frame")]
    keep = []
    checksums = []
    network = None
    transport = False
    for index, p in enumerate(protocols):
        name = p.get("name")
        pos, size = span(p)
        if name in HEADERS:
            # Some tshark protocol items (ERSPAN) cover their entire encapsulated body.
            # The next protocol start, not that enclosing extent, ends the header.
            following = [span(q)[0] for q in protocols[index + 1 :] if span(q)[0] > pos]
            if following:
                size = min(size, min(following) - pos)
            if name == "ip":
                field = p.find("field[@name='ip.hdr_len']")
                size = int(field.get("show")) if field is not None else size
                network = p
            elif name == "ipv6":
                size = 40
                network = p
            elif name == "arp":
                network = p
                transport = True
            keep.append((pos, pos + size))
        elif name in ("tcp", "udp", "icmp", "icmpv6"):
            if name == "tcp":
                field = p.find("field[@name='tcp.hdr_len']")
                if field is None:
                    quoted = any(
                        q.get("name") in ("icmp", "icmpv6") and span(q)[0] < pos for q in protocols[:index]
                    )
                    if not quoted or size < 8:
                        raise ValueError("Incomplete TCP header; cannot safely anonymize")
                    size = 8  # RFC ICMP quote: only ports and sequence may be captured.
                else:
                    size = int(field.get("show"))
            else:
                size = 8
            keep.append((pos, pos + size))
            transport = True
        else:
            # Remaining application fields are erased, never copied as headers.
            continue
        checksum = next((f for f in p.iter("field") if f.get("name") == name + ".checksum"), None)
        if checksum is not None:
            checksums.append((name, p, network, span(checksum)[0]))
    if not keep or network is None or not transport:
        raise ValueError("Unsupported or incomplete L4/tunnel header; cannot safely anonymize this frame")
    end = max(b for _, b in keep)
    if end > len(raw):
        raise ValueError("Truncated protocol header; cannot safely anonymize this frame")
    # Header spans must form a contiguous prefix: unknown wrappers cannot slip through.
    covered = bytearray(len(raw))
    output = bytearray(len(raw))
    for a, b in keep:
        covered[a:b] = b"\1" * (b - a)
        output[a:b] = raw[a:b]
    if not all(covered[:end]):
        raise ValueError("Unknown bytes between decoded headers; anonymization refused")
    for f in packet.iter("field"):
        name = f.get("name", "")
        pos, size = span(f)
        if not size or pos + size > end or not all(covered[pos : pos + size]):
            continue
        if name in MAC_FIELDS and size == 6:
            output[pos : pos + size] = mapper.mac(raw[pos : pos + size])
        elif map_ips and (name in IP_FIELDS or name.endswith((".addr", ".address"))) and size in (4, 16):
            # Only tshark-declared address fields in retained headers are eligible.
            if name in IP_FIELDS or f.get("show", "").count(".") == 3 or ":" in f.get("show", ""):
                output[pos : pos + size] = mapper.ip(raw[pos : pos + size])
    for name, p, net, checksum in reversed(checksums):
        start, size = span(p)
        pseudo = []
        last = len(raw)
        if name == "ip":
            last = start + int(p.find("field[@name='ip.hdr_len']").get("show"))
        elif net is not None:
            npos, _ = span(net)
            if net.get("name") == "ip":
                last = npos + int(net.find("field[@name='ip.len']").get("show"))
                if name in ("tcp", "udp"):
                    pseudo = [(npos + 12, npos + 20)]
            else:
                last = npos + 40 + int(net.find("field[@name='ipv6.plen']").get("show"))
                if name in ("tcp", "udp", "icmpv6"):
                    pseudo = [(npos + 8, npos + 40)]
        if name == "udp" and raw[checksum : checksum + 2] == b"\0\0":
            continue
        adjust_checksum(raw, output, checksum, start, last, pseudo)
        if name == "udp" and output[checksum : checksum + 2] == b"\0\0":
            output[checksum : checksum + 2] = b"\xff\xff"
    return bytes(output[:end] if mode == "headers-only" else output)


def safe_options(data, endian, allowed):
    result = bytearray()
    for code, value in options(data, endian):
        if code in allowed:
            if len(value) != allowed[code]:
                raise ValueError("Invalid numeric pcapng option length")
            result.extend(struct.pack(endian + "HH", code, len(value)) + value + b"\0" * (-len(value) % 4))
    return bytes(result) + b"\0" * 4


def read_exact(source, size):
    if size < 0 or size > 64 * 1024 * 1024:
        raise ValueError("Invalid or oversized capture record")
    data = source.read(size)
    if len(data) != size:
        raise ValueError("Damaged capture record; no output published")
    return data


def rewrite(source, output, packets, mode, mapper, map_ips):
    magic = read_exact(source, 4)
    count = 0

    def packet(raw):
        nonlocal count
        decoded = next(packets, None)
        if decoded is None:
            raise ValueError("tshark/container frame count mismatch")
        length = decoded.find("proto[@name='geninfo']/field[@name='caplen']")
        if length is None or int(length.get("show")) != len(raw):
            raise ValueError("tshark/container frame length mismatch")
        count += 1
        return sanitize_packet(raw, decoded, mode, mapper, map_ips)

    if magic in MAGICS:
        endian = MAGICS[magic]
        output.write(magic + read_exact(source, 20))
        while header := source.read(16):
            if len(header) != 16:
                raise ValueError("Damaged pcap record")
            sec, frac, caplen, wirelen = struct.unpack(endian + "4I", header)
            raw = packet(read_exact(source, caplen))
            output.write(struct.pack(endian + "4I", sec, frac, len(raw), wirelen) + raw)
    elif magic == b"\x0a\x0d\x0d\x0a":
        source.seek(0)
        endian = "<"
        while header := source.read(8):
            if len(header) != 8:
                raise ValueError("Damaged pcapng block")
            if header[:4] == magic:
                bom = read_exact(source, 4)
                endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
                if not endian:
                    raise ValueError("Invalid pcapng byte order")
                size = struct.unpack(endian + "I", header[4:])[0]
                body = bom + read_exact(source, size - 12)
            else:
                size = struct.unpack(endian + "I", header[4:])[0]
                body = read_exact(source, size - 8)
            if size < 12 or size % 4 or body[-4:] != struct.pack(endian + "I", size):
                raise ValueError("Invalid pcapng block length")
            kind = struct.unpack(endian + "I", header[:4])[0]
            body = body[:-4]
            if kind == 0x0A0D0D0A:
                body = body[:8] + struct.pack(endian + "q", -1)
            elif kind == 1:
                body = body[:8] + safe_options(body[8:], endian, {9: 1, 14: 8, 13: 1})
            elif kind in (6, 2):
                fixed = 20
                caplen, wirelen = struct.unpack(endian + "II", body[12:20])
                raw = packet(body[fixed : fixed + caplen])
                body = (
                    body[:12] + struct.pack(endian + "II", len(raw), wirelen) + raw + b"\0" * (-len(raw) % 4)
                )
            elif kind == 5:
                body = body[:12] + safe_options(body[12:], endian, {k: 8 for k in (2, 3, 4, 5, 6, 7, 8)})
            elif kind == 3:
                raise ValueError(
                    "Untimestamped pcapng simple packet blocks are unsupported; convert to EPB first"
                )
            else:
                # NRB, DSB, custom blocks, unknown vendor metadata: drop entirely.
                continue
            size = len(body) + 12
            output.write(struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size))
    else:
        raise ValueError("Only classic pcap and pcapng are supported")
    if next(packets, None) is not None:
        raise ValueError("tshark/container frame count mismatch")
    if not count:
        raise ValueError("No usable packets")
    return count


def anonymize(source, destination, *, mode="zero", key=None, map_ips=False, tshark=None):
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve() or destination.exists():
        raise ValueError("Output must be a new file, different from the input")
    if map_ips and key is None:
        raise ValueError("IP mapping requires a local key; reuse it across every project file")
    mapper = Mapper(key or hashlib.sha256(b"PacketBreaker MAC masking v1").digest())
    fd, temporary = tempfile.mkstemp(prefix=".anonymize-", dir=destination.parent)
    try:
        with (
            os.fdopen(fd, "wb") as output,
            source.open("rb") as input_file,
            decoded_packets(source, tshark) as packets,
        ):
            count = rewrite(input_file, output, packets, mode, mapper, map_ips)
        # Publish without replacing an existing output, including a race with another writer.
        os.link(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return dict(
        packets=count,
        mode=mode,
        mapped_ips=map_ips,
        note="Payload removed; application/content-derived analysis is unavailable. Key stays local.",
    )


def anonymize_files(paths, destination, *, mode="zero", key=None, map_ips=False, tshark=None):
    """One shared key for a set; neutral filenames, no source paths or key in export."""
    import json

    destination = Path(destination)
    destination.mkdir()
    try:
        results = []
        for index, path in enumerate(paths, 1):
            with Path(path).open("rb") as f:
                suffix = ".pcapng" if f.read(4) == b"\x0a\x0d\x0d\x0a" else ".pcap"
            name = f"capture-{index:03}{suffix}"
            result = anonymize(path, destination / name, mode=mode, key=key, map_ips=map_ips, tshark=tshark)
            results.append(dict(file=name, **result))
        (destination / "README.json").write_text(
            json.dumps(
                dict(
                    files=results,
                    note="Payload removed. Content-dependent HTTP/TLS/SIP/DNS/RTP results are unknown. "
                    "Headers, timing and traffic patterns remain visible. Apply the same local key to topology CIDRs. "
                    "Header options are retained; review sensitive custom options before sharing.",
                ),
                indent=2,
            ),
            encoding="utf-8",
        )
        return results
    except BaseException:
        import shutil

        shutil.rmtree(destination)
        raise
