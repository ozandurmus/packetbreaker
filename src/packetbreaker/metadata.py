"""Read container framing only. Protocol dissection always belongs to tshark."""

import struct
from pathlib import Path


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


def zero_suffix_start(f, size, cancel):
    """One backwards scan avoids rescanning long zero runs in the middle of a file."""
    end = size
    while end:
        if cancel and cancel.is_set():
            raise InterruptedError("Ingest cancelled")
        start = max(0, end - 1024 * 1024)
        f.seek(start)
        data = f.read(end - start)
        nonzero = data.rstrip(b"\0")
        if nonzero:
            return start + len(nonzero)
        end = start
    return 0


def metadata(path, cancel=None):
    path = Path(path)
    size = path.stat().st_size
    result = dict(format="unknown", interfaces=[], ifdrop=None, osdrop=None, complete_records=0)
    with path.open("rb") as f:
        zero_start = zero_suffix_start(f, size, cancel)
        f.seek(0)
        magic = f.read(4)
        formats = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }

        def zero_tail(start, record_size):
            if start < zero_start or start >= size:
                return False
            count = (size - start) // record_size
            result.update(
                zero_tail_bytes=size - start,
                zero_tail_records=count,
                zero_tail_record_size=record_size,
                frame_limit=result["complete_records"],
            )
            if (size - start) % record_size:
                result["damaged_tail"] = True
            return True

        if magic in formats:
            endian = formats[magic]
            rest = f.read(20)
            if len(rest) != 20:
                raise ValueError("Truncated pcap header")
            _, _, _, _, snaplen, link = struct.unpack(endian + "HHIIII", rest)
            result.update(
                format="pcap",
                interfaces=[dict(id=0, section=0, snaplen=snaplen, link_type=link & 0xFFFF, name=None)],
            )
            while f.tell() < size:
                if cancel and cancel.is_set():
                    raise InterruptedError("Ingest cancelled")
                start = f.tell()
                if zero_tail(start, 16):
                    break
                header = f.read(16)
                if len(header) < 16:
                    result["damaged_tail"] = True
                    break
                _, _, caplen, _ = struct.unpack(endian + "IIII", header)
                if start + 16 + caplen > size:
                    result["damaged_tail"] = True
                    break
                f.seek(caplen, 1)
                result["complete_records"] += 1
            return result
        if magic != b"\x0a\x0d\x0d\x0a":
            raise ValueError("Only pcap and pcapng containers are supported")
        result["format"] = "pcapng"
        f.seek(0)
        endian = "<"
        section = -1
        local = []
        counters = {}
        while f.tell() < size:
            if cancel and cancel.is_set():
                raise InterruptedError("Ingest cancelled")
            start = f.tell()
            if zero_tail(start, 12):
                break
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
            f.seek(start + length - 4)
            if struct.unpack(endian + "I", f.read(4))[0] != length:
                if start + length == size:
                    result["damaged_tail"] = True
                    break
                raise ValueError("Mismatched pcapng block trailer")
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
                            key = (section, iface, code)
                            counters[key] = max(counters.get(key, 0), struct.unpack(endian + "Q", value)[0])
            if kind in (2, 3, 6):
                result["complete_records"] += 1
            f.seek(start + length)
        for code, name in ((5, "ifdrop"), (7, "osdrop")):
            values = [v for k, v in counters.items() if k[2] == code]
            if values:
                result[name] = sum(values)
        result["multiple_sections"] = section > 0
    return result
