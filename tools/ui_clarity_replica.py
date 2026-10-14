import struct
import json
from pathlib import Path
from packetbreaker.pilot_synthetic import make_pilot
from packetbreaker.synthetic import write_pcap, bind_capture_ids
from packetbreaker.batch_ingest import ingest_many
from packetbreaker.store import Project
from packetbreaker.analysis import analyze

root = Path("demo/ui-clarity")
truth, t = make_pilot(
    root / "captures",
    flows=50,
    affected_flows=25,
    slow_local_flow=True,
    real_case=True,
    host_jitter_us=150,
    ip_id="increment",
)
# One application-only outlier, while the other 49 concurrent flows continue normally.
for f in truth["files"]:
    raw = Path(f).read_bytes()
    at = 24
    records = []
    while at < len(raw):
        sec, usec, n, wire = struct.unpack_from("<IIII", raw, at)
        packet = raw[at + 16 : at + 16 + n]
        at += 16 + n
        sport, dport, seq, ack = struct.unpack_from("!HHII", packet, 34)
        stamp = sec + usec / 1e6
        if 41049 in (sport, dport):
            length = len(packet) - 54
            if length:
                start = 4901001 if sport == 41049 else 4909001
                if not start <= seq < start + 3200:
                    continue
                stamp += 16 if sport == 41049 else 32
            elif stamp > 1700000001:
                if stamp > 1700000007:
                    continue
                stamp += 32
        records.append((stamp, packet))
    write_pcap(f, records)
p = Project(root / "project")
ids = ingest_many(p, truth["files"], workers=4)
bind_capture_ids(t, {Path(f).name: c for f, c in zip(truth["files"], ids)})
r = analyze(p, t)
assert r["flow_count"] == 50
assert len(r["incident"]["hold_release"]) > 1
assert max(b["total_ms"] for b in r["incident"]["cycle_bars"]) > 16000
print(
    json.dumps(
        {
            "project": str(p.path),
            "flows": r["flow_count"],
            "hold_findings": len(r["incident"]["hold_release"]),
            "max_cycle_ms": max(b["total_ms"] for b in r["incident"]["cycle_bars"]),
        }
    ),
    flush=True,
)
