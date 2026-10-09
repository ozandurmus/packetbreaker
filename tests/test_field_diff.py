import hashlib
import json

from packetbreaker.field_diff import packet_diff, values
from packetbreaker.ingest import parse_packet
from packetbreaker.store import PACKET_COLUMNS


def test_field_diff_full_hash_not_prefix_and_truncation():
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.len",
        "tcp.payload",
        "frame.len",
        "frame.cap_len",
        "tcp.options.wscale.shift",
    ]
    payload = b"a" * 64 + b"changed past prefix"
    data = [
        "1",
        "1700000000",
        "10.0.0.1",
        "10.0.0.2",
        "50000",
        "80",
        str(len(payload)),
        payload.hex(),
        "140",
        "140",
        "0",
    ]
    packet = dict(zip(PACKET_COLUMNS, parse_packet(data, "capture", 64, fields)))
    decoded = json.loads(packet["path_fields"])
    assert decoded["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert decoded["window_scale"] == 0 and decoded["payload_complete"]
    data[-2] = "100"
    packet = dict(zip(PACKET_COLUMNS, parse_packet(data, "capture", 64, fields)))
    assert values({**packet, "raw_seq": 0})["payload_sha256"] is None


def test_matched_field_diff_evidence(scenarios):
    project, _, _, _ = scenarios("capture_miss")
    with project.connect() as db:
        key = db.execute(
            "SELECT packet_key FROM obs WHERE eligible GROUP BY packet_key HAVING count(*)>2 LIMIT 1"
        ).fetchone()[0]
    result = packet_diff(project, key)
    assert result["items"]
    for item in result["items"]:
        assert item["fields"]["src"]["status"] == "unchanged"
        assert item["tooltip"] and len(item["evidence"]) == 2
        assert all(ref["content_filter"] for ref in item["evidence"])
