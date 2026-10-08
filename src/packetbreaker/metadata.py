"""Read capture container metadata only; packet dissection belongs to tshark."""

import struct


def options(data, endian):
    pos = 0
    while pos + 4 <= len(data):
        code, size = struct.unpack_from(endian + "HH", data, pos)
        pos += 4
        if code == 0:
            break
        if pos + size > len(data):
            raise ValueError("Malformed pcapng option")
        yield code, data[pos : pos + size]
        pos += (size + 3) & ~3


def metadata(path, cancel=None):
    result = {"format": "unknown", "interfaces": [], "ifdrop": None, "osdrop": None}
    with open(path, "rb") as f:
        magic = f.read(4)
        formats = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }
        if magic in formats:
            rest = f.read(20)
            if len(rest) != 20:
                raise ValueError("Truncated pcap header")
            _, _, _, _, snaplen, link = struct.unpack(formats[magic] + "HHIIII", rest)
            result.update(
                format="pcap",
                interfaces=[dict(id=0, section=0, snaplen=snaplen, link_type=link & 0xFFFF, name=None)],
            )
            return result
        if magic != b"\x0a\x0d\x0d\x0a":
            raise ValueError("Phase 1 accepts pcap and pcapng files only")
        result["format"] = "pcapng"
        f.seek(0)
        endian, section, local = "<", -1, []
        counters = {}
        packet_count = 0
        size = path.stat().st_size
        while f.tell() < size:
            if cancel and cancel.is_set():
                raise InterruptedError("Ingest cancelled")
            start = f.tell()
            head = f.read(12)
            if len(head) != 12:
                result["damaged_tail"] = True
                break
            if head[:4] == b"\x0a\x0d\x0d\x0a":
                if head[8:12] not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                    raise ValueError("Invalid pcapng byte order")
                endian = "<" if head[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
                section += 1
                local = []
            kind, length = struct.unpack(endian + "II", head[:8])
            if start + length > size:
                result["damaged_tail"] = True
                break
            if length < 12 or length % 4:
                raise ValueError("Invalid pcapng block length")
            # Packet blocks are skipped by seeking, including very large payloads.
            if kind in (1, 5):
                if length > 1024 * 1024:
                    raise ValueError("Metadata block exceeds 1 MiB safety limit")
                f.seek(start + 8)
                body = f.read(length - 12)
                if kind == 1:
                    if len(body) < 8:
                        raise ValueError("Truncated interface description")
                    link, _, snaplen = struct.unpack_from(endian + "HHI", body)
                    item = dict(id=len(local), section=section, snaplen=snaplen, link_type=link, name=None)
                    for code, value in options(body[8:], endian):
                        if code == 2:
                            item["name"] = value.decode("utf-8", "replace")
                    local.append(item)
                    result["interfaces"].append(item)
                else:
                    if len(body) < 12:
                        raise ValueError("Truncated interface statistics")
                    iface = struct.unpack_from(endian + "I", body)[0]
                    for code, value in options(body[12:], endian):
                        if code in (5, 7) and len(value) == 8:
                            # ISB counters are cumulative; do not sum snapshots.
                            key = (section, iface, code)
                            counters[key] = max(counters.get(key, 0), struct.unpack(endian + "Q", value)[0])
            f.seek(start + length - 4)
            if struct.unpack(endian + "I", f.read(4))[0] != length:
                if start + length == size:
                    result["damaged_tail"] = True
                    break
                raise ValueError("Mismatched pcapng block trailer")
            if kind in (2, 3, 6):
                packet_count += 1
        for code, name in ((5, "ifdrop"), (7, "osdrop")):
            values = [v for k, v in counters.items() if k[2] == code]
            if values:
                result[name] = sum(values)
        result["multiple_sections"] = section > 0
        result["complete_records"] = packet_count
    return result
