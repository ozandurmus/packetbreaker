"""Original FortiOS verbose-6 text-to-pcap converter; no packet protocol parsing.

Format reference: Fortinet's built-in packet-sniffer KB (absolute 'a' is UTC).
Only explicitly formatted hex bytes are copied. tshark dissects the result.
"""

from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import uuid

STAMP = r"(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})?|\d+(?:\.\d{1,9})?)"
HEADER = re.compile(r"^\s*(" + STAMP + r")\s+(\S+)\s+(?:in|out|--)(?:\s+|$)")
HEX = re.compile(r"^\s*0x([0-9a-fA-F]{4,8})\s+(.*)$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def absolute_ns(value, require_zone=False):
    fraction = re.search(r"\.(\d+)", value)
    nano = int((fraction[1] + "0" * 9)[:9]) if fraction else 0
    whole = value[: fraction.start()] + value[fraction.end() :] if fraction else value
    dt = datetime.fromisoformat(whole.replace("Z", "+00:00"))
    if require_zone and dt.tzinfo is None:
        raise ValueError("Relative start time must include Z or a numeric timezone offset")
    return (
        int(dt.replace(tzinfo=timezone.utc).timestamp() if dt.tzinfo is None else dt.timestamp()) * 10**9
        + nano
    )


def cooked_link_type(frame, description, tshark=None):
    """Ask tshark which container link type agrees with explicit sniffer metadata."""
    from .ingest import find_tshark

    proto = re.search(r"protocol type:\s*(0x[0-9a-fA-F]+|[0-9]+)", description)
    packet_type = re.search(r"packet type:\s*(0x[0-9a-fA-F]+|[0-9]+)", description)
    hardware = re.search(r"address type:\s*(0x[0-9a-fA-F]+|[0-9]+)", description)
    if not proto:
        return None
    expected = int(proto[1], 0)
    candidates = []
    with tempfile.TemporaryDirectory(prefix="fortinet-link-") as directory:
        probe = Path(directory) / "probe.pcap"
        for link in (1, 113, 276):
            probe.write_bytes(
                struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 16777216, link)
                + struct.pack("<IIII", 1700000000, 0, len(frame), len(frame))
                + frame
            )
            decoded = (
                subprocess.run(
                    [
                        find_tshark(tshark),
                        "-n",
                        "-r",
                        str(probe),
                        "-T",
                        "fields",
                        "-E",
                        "occurrence=f",
                        "-e",
                        "eth.type",
                        "-e",
                        "sll.etype",
                        "-e",
                        "sll.pkttype",
                        "-e",
                        "sll.hatype",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                .stdout.rstrip("\r\n")
                .split("\t")
            )
            decoded += [""] * (4 - len(decoded))
            field = decoded[0] if link == 1 else decoded[1]
            if not field or int(field, 0) != expected:
                continue
            if link != 1 and (
                (packet_type and (not decoded[2] or int(decoded[2], 0) != int(packet_type[1], 0)))
                or (hardware and (not decoded[3] or int(decoded[3], 0) != int(hardware[1], 0)))
            ):
                continue
            candidates.append(link)
    return candidates[0] if len(candidates) == 1 else None


def convert_text(source, output_dir, start_time=None, cancel=None, progress=None, tshark=None):
    source, output = Path(source), Path(output_dir)
    cancel = cancel or threading.Event()
    progress = progress or (lambda **_: None)
    progress(state="converting Fortinet text", file=source.name, frames=0)
    anchor = absolute_ns(start_time, True) if start_time else None
    output.mkdir(parents=True, exist_ok=False)
    files, skipped, counters = {}, Counter(), Counter()
    current = None
    total_lines = 0

    def finish():
        nonlocal current
        if not current:
            return
        if current["bad"] or len(current["bytes"]) < 14:
            counters["skipped_packets"] += 1
        else:
            name = current["interface"]
            previous = files.get(name)
            link = previous["link_type"] if previous else 1
            if current.get("cooked") and not (previous and previous["cooked_checked"]):
                link = cooked_link_type(current["bytes"], current["cooked"], tshark)
                if link is None or (previous and previous["link_type"] != link):
                    counters["skipped_packets"] += 1
                    skipped["unsupported_cooked_link_header"] += 1
                    current = None
                    return
            if name not in files:
                if len(files) >= 64:
                    raise ValueError("More than 64 interfaces; split the source text")
                safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:64]
                path = output / f"interface-{len(files):02d}-{safe}.pcap"
                handle = path.open("xb")
                handle.write(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 16777216, link))
                files[name] = dict(
                    path=str(path.resolve()),
                    handle=handle,
                    packets=0,
                    relative=False,
                    link_type=link,
                    cooked_checked=False,
                )
            item = files[name]
            item["cooked_checked"] |= bool(current.get("cooked"))
            sec, nano = divmod(current["time_ns"], 10**9)
            if not 0 <= sec <= 0xFFFFFFFF:
                counters["skipped_packets"] += 1
                skipped["timestamp_outside_pcap_range"] += 1
            else:
                frame = current["bytes"]
                item["handle"].write(struct.pack("<IIII", sec, nano, len(frame), len(frame)) + frame)
                item["packets"] += 1
                item["relative"] |= current["relative"]
                counters["packets"] += 1
        current = None

    def read_hex(text):
        # The ASCII gutter is separated by a larger whitespace gap, unlike hex words.
        column = re.split(r"\s{2,}", text.strip(), maxsplit=1)[0]
        tokens = column.split()
        if not tokens or any(not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,2}", word) for word in tokens):
            return None
        return bytes.fromhex("".join(tokens))

    try:
        with source.open("r", encoding="utf-8-sig", errors="replace") as src:
            for total_lines, raw in enumerate(src, 1):
                if total_lines % 1000 == 0:
                    progress(state="converting Fortinet text", file=source.name, frames=counters["packets"])
                if cancel.is_set():
                    raise InterruptedError("Fortinet conversion cancelled")
                line = ANSI.sub("", raw.rstrip("\r\n")).replace("\u00a0", " ")
                if not line.strip():
                    continue
                header = HEADER.match(line)
                if header:
                    finish()
                    stamp, interface = header.groups()
                    relative = not re.match(r"\d{4}-", stamp)
                    if relative and anchor is None:
                        raise ValueError("Relative Fortinet timestamps require a user-supplied start time")
                    try:
                        ns = anchor + int(Decimal(stamp) * 10**9) if relative else absolute_ns(stamp)
                    except (ValueError, ArithmeticError):
                        skipped["invalid_timestamp"] += 1
                        counters["skipped_packets"] += 1
                        continue
                    current = dict(
                        interface=interface,
                        time_ns=ns,
                        bytes=bytearray(),
                        relative=relative,
                        bad=False,
                        row_bytes=0,
                    )
                    continue
                if "linux cooked capture" in line.lower():
                    if current:
                        current["cooked"] = line
                    else:
                        skipped["cooked_metadata_without_header"] += 1
                    continue
                match = HEX.match(line)
                continuation = bool(
                    current and 0 < current["row_bytes"] < 16 and len(line) - len(line.lstrip()) >= 4
                )
                if current and (match or continuation):
                    chunk = read_hex(match[2] if match else line)
                    if chunk is None:
                        if match:
                            current["bad"] = True
                            skipped["invalid_or_truncated_hex"] += 1
                        else:
                            skipped["console_noise"] += 1
                        continue
                    offset = int(match[1], 16) if match else len(current["bytes"])
                    if offset != len(current["bytes"]) or len(current["bytes"]) + len(chunk) > 16777216:
                        current["bad"] = True
                        skipped["hex_gap_or_overlap"] += 1
                        continue
                    current["bytes"].extend(chunk)
                    current["row_bytes"] = len(chunk) if match else current["row_bytes"] + len(chunk)
                else:
                    skipped["console_noise" if not match else "hex_without_packet_header"] += 1
            finish()
        if not counters["packets"]:
            raise ValueError(
                f"No complete packets found in Fortinet text; {sum(skipped.values())} skipped lines, {counters['skipped_packets']} skipped packets: {dict(skipped)}"
            )
        result = dict(
            source=source.name,
            packets=counters["packets"],
            skipped_packets=counters["skipped_packets"],
            skipped_lines=sum(skipped.values()),
            skipped_reasons=dict(skipped),
            lines=total_lines,
            files=[],
        )
        for interface, item in files.items():
            item["handle"].close()
            result["files"].append(
                dict(
                    path=item["path"],
                    interface=interface,
                    packets=item["packets"],
                    adapter="fortinet",
                    link_type=item["link_type"],
                    cooked_metadata=item["cooked_checked"],
                    clock_group=output.name,
                    clock_confidence="low" if item["relative"] else "source",
                    relative_timestamps=item["relative"],
                    start_time=start_time if item["relative"] else None,
                )
            )
        return result
    except BaseException:
        for item in files.values():
            item["handle"].close()
        shutil.rmtree(output)  # Only the exclusively created conversion directory is removed.
        raise


def import_text(project, path, start_time=None, device="FortiGate", cancel=None, progress=None):
    from .ingest import ingest
    from .topology import Topology

    destination = project.path / "captures" / ("fortinet-" + uuid.uuid4().hex)
    with project.connect() as db:
        preferences = project.get(db, "preferences", {})
    result = convert_text(path, destination, start_time, cancel, progress, preferences.get("tshark"))
    with project.connect() as db:
        topology = project.get(db, "topology", Topology().model_dump())
    added = []
    for item in result["files"]:
        provenance = {
            **item,
            "source": result["source"],
            "skipped_lines": result["skipped_lines"],
            "skipped_packets": result["skipped_packets"],
            "skipped_reasons": result["skipped_reasons"],
        }
        provenance.pop("path")
        cid = ingest(
            project,
            item["path"],
            tshark=preferences.get("tshark"),
            prefix_bytes=preferences.get("prefix_bytes", 64),
            cancel=cancel,
            progress=progress,
            source_metadata=provenance,
        )
        added.append(
            dict(
                id="forti-" + cid[:12],
                label=item["interface"],
                device=device,
                capture_id=cid,
                vendor="fortinet",
                vendor_stage=item["interface"],
                kind="Firewall",
                x=120 + 240 * (len(topology["points"]) + len(added)),
                y=160,
            )
        )
        item["capture_id"] = cid
    if len(topology["points"]) + len(added) > 64:
        raise ValueError(
            "Import exceeds 64 topology points; converted captures are retained for a separate project"
        )
    topology["points"].extend(added)
    topology = Topology.model_validate(topology).model_dump()
    with project.connect() as db:
        project.set(db, "topology", topology)
        project.set(db, "report", None)
        project.set(db, "fortinet_conversion", result)
    return result
