import gzip
import os
import json
from pathlib import Path
import re
import uuid

from packetbreaker.analysis import analyze
from packetbreaker.batch_ingest import ingest_many
from packetbreaker.case_setup import create_case
from packetbreaker.dns import dns_page
from packetbreaker.pilot_synthetic import make_pilot
from packetbreaker.store import Project
from packetbreaker.synthetic import bind_capture_ids, tcp_packet, write_pcap
from packetbreaker.transport import profiles

GOLDEN_DIR = Path(__file__).parent / "golden"
VOLATILE_KEYS = {"generated_at", "exported_at"}


def _capture_id_map(project: Project) -> dict[str, str]:
    with project.connect() as db:
        return {cid: f"<capture:{name}>" for cid, name in db.execute("SELECT id, name FROM captures").fetchall()}


def _normalize_str(val: str, cid_map: dict[str, str]) -> str:
    if val in cid_map:
        return cid_map[val]
    for cid, token in cid_map.items():
        if cid in val:
            val = val.replace(cid, token)
    return val


def _strip_volatile(obj, cid_map: dict[str, str]):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in VOLATILE_KEYS:
                continue
            nk = _normalize_str(k, cid_map) if isinstance(k, str) else k
            out[nk] = _strip_volatile(v, cid_map)
        return out
    if isinstance(obj, list):
        return [_strip_volatile(x, cid_map) for x in obj]
    if isinstance(obj, str):
        return _normalize_str(obj, cid_map)
    return obj


HEX_ID = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")
# Local-time renderings depend on the runner's time zone; the UTC renderings are kept.
LOCAL_TIME = re.compile(
    r"(?:\d{4}-\d\d-\d\d )?\d\d:\d\d:\d\d(?:\.\d+)?[+-]\d\d:\d\d(?: local)?"
)


def _canonical(obj):
    """Platform-independent form: the decision content is kept, run-to-run noise is removed.

    Float sums from parallel SQL aggregation differ in the last digits, unordered SQL results
    and hash-ordered samples differ in order, and md5/uuid identifiers depend on run state.
    """
    if isinstance(obj, dict):
        return {HEX_ID.sub("<id>", k): _canonical(v) for k, v in obj.items()}
    if isinstance(obj, list):
        items = [_canonical(v) for v in obj]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True, ensure_ascii=False))
    if isinstance(obj, float):
        return float(f"{obj:.9g}")
    if isinstance(obj, str):
        stripped = obj.strip()
        if stripped[:1] in "[{" and stripped[-1:] in "]}":
            try:
                return _canonical(json.loads(stripped))
            except ValueError:
                pass
        return LOCAL_TIME.sub("<local time>", HEX_ID.sub("<id>", obj.replace("\\", "/")))
    return obj


def serialize_golden(payload: dict, project: Project) -> bytes:
    cid_map = _capture_id_map(project)
    cleaned = _canonical(_strip_volatile(payload, cid_map))
    return json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _differences(expected, actual, path="$", out=None, limit=20):
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    if type(expected) is not type(actual):
        out.append(f"{path}: {str(expected)[:80]!r} != {str(actual)[:80]!r}")
    elif isinstance(expected, dict):
        for key in sorted(set(expected) | set(actual)):
            if key not in expected or key not in actual:
                out.append(f"{path}.{key}: {'missing' if key not in expected else 'present'} in golden")
            else:
                _differences(expected[key], actual[key], f"{path}.{key}", out, limit)
    elif isinstance(expected, list):
        if len(expected) != len(actual):
            out.append(f"{path}: {len(expected)} items in golden, {len(actual)} now")
        for i, (e, a) in enumerate(zip(expected, actual)):
            _differences(e, a, f"{path}[{i}]", out, limit)
    elif expected != actual:
        out.append(f"{path}: {str(expected)[:80]!r} != {str(actual)[:80]!r}")
    return out


def assert_golden_bytes(name: str, payload: dict, project: Project) -> None:
    actual = serialize_golden(payload, project)
    path = GOLDEN_DIR / f"{name}.json.gz"
    if os.environ.get("PB_UPDATE_GOLDEN") == "1":
        path.write_bytes(gzip.compress(actual, mtime=0))
    expected = gzip.decompress(path.read_bytes())
    if actual != expected:
        diffs = _differences(json.loads(expected), json.loads(actual))
        raise AssertionError(f"Golden {name} differs:\n" + "\n".join(diffs))


def _deterministic_uuids(monkeypatch):
    import packetbreaker.ingest as ingest_mod

    counter = iter(range(1, 10000))
    monkeypatch.setattr(ingest_mod.uuid, "uuid4", lambda: uuid.UUID(int=next(counter)))


def _build_folder_b(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    gen1, gen2, lb, segin, segout, host = [], [], [], [], [], []
    for i in range(12):
        t = 1700000100.0 + i * 0.5
        flags_fwd = 2 if i == 0 else 24
        flags_rev = 18 if i == 0 else 24
        pay_fwd = b"" if i == 0 else f"req_x_{i:02d}_".encode() + b"x" * 60
        pay_rev = b"" if i == 0 else f"rsp_x_{i:02d}_".encode() + b"y" * 60
        gen1.append(
            (
                t,
                tcp_packet(
                    "10.1.0.10",
                    "203.0.113.20",
                    42100,
                    443,
                    1 + i * 100,
                    1 + i * 100,
                    flags_fwd,
                    pay_fwd,
                    100 + i,
                    ttl=62,
                ),
            )
        )
        gen2.append(
            (
                t + 0.000025,
                tcp_packet(
                    "10.1.0.10",
                    "203.0.113.20",
                    42100,
                    443,
                    1 + i * 100,
                    1 + i * 100,
                    flags_fwd,
                    pay_fwd,
                    100 + i,
                    ttl=61,
                ),
            )
        )
        host.append(
            (
                t + 0.00005,
                tcp_packet(
                    "10.1.0.10",
                    "203.0.113.20",
                    42100,
                    443,
                    1 + i * 100,
                    1 + i * 100,
                    flags_fwd,
                    pay_fwd,
                    100 + i,
                    ttl=60,
                ),
            )
        )
        t_rev = t + 0.002
        host_pay_rev = b"S" * 2400 if i == 1 else pay_rev
        host.append(
            (
                t_rev,
                tcp_packet(
                    "203.0.113.20",
                    "10.1.0.10",
                    443,
                    42100,
                    500 + i * 100,
                    50 + i * 100,
                    flags_rev,
                    host_pay_rev,
                    300 + i,
                    ttl=64,
                ),
            )
        )
        gen2.append(
            (
                t_rev + 0.00002,
                tcp_packet(
                    "203.0.113.20",
                    "10.1.0.10",
                    443,
                    42100,
                    500 + i * 100,
                    50 + i * 100,
                    flags_rev,
                    pay_rev,
                    300 + i,
                    ttl=61,
                ),
            )
        )
        gen1.append(
            (
                t_rev + 0.000045,
                tcp_packet(
                    "203.0.113.20",
                    "10.1.0.10",
                    443,
                    42100,
                    500 + i * 100,
                    50 + i * 100,
                    flags_rev,
                    pay_rev,
                    300 + i,
                    ttl=60,
                ),
            )
        )

    lb_clock_offset = -0.000120
    for i in range(4):
        t = 1700000100.005 + i * 2.0
        flags_fwd = 2 if i == 0 else 24
        flags_rev = 18 if i == 0 else 24
        pay_fwd = b"" if i == 0 else f"req_y_{i:02d}_".encode() + b"a" * 50
        pay_rev = b"" if i == 0 else f"rsp_y_{i:02d}_".encode() + b"b" * 50
        lb.append(
            (
                t + lb_clock_offset,
                tcp_packet(
                    "198.51.100.10",
                    "203.0.113.20",
                    43100,
                    443,
                    1 + i * 80,
                    1 + i * 80,
                    flags_fwd,
                    pay_fwd,
                    500 + i,
                    ttl=63,
                ),
            )
        )
        segin.append(
            (
                t + 0.000028,
                tcp_packet(
                    "198.51.100.10",
                    "203.0.113.20",
                    43100,
                    443,
                    1 + i * 80,
                    1 + i * 80,
                    flags_fwd,
                    pay_fwd,
                    500 + i,
                    ttl=55,
                ),
            )
        )
        segout.append(
            (
                t + 0.000048,
                tcp_packet(
                    "198.51.100.10",
                    "203.0.113.20",
                    43100,
                    443,
                    1 + i * 80,
                    1 + i * 80,
                    flags_fwd,
                    pay_fwd,
                    500 + i,
                    ttl=54,
                ),
            )
        )
        host.append(
            (
                t + 0.000070,
                tcp_packet(
                    "198.51.100.10",
                    "203.0.113.20",
                    43100,
                    443,
                    1 + i * 80,
                    1 + i * 80,
                    flags_fwd,
                    pay_fwd,
                    500 + i,
                    ttl=53,
                ),
            )
        )
        t_rev = t + 0.002
        host_pay_rev = b"T" * 2200 if i == 1 else pay_rev
        host.append(
            (
                t_rev,
                tcp_packet(
                    "203.0.113.20",
                    "198.51.100.10",
                    443,
                    43100,
                    800 + i * 80,
                    40 + i * 80,
                    flags_rev,
                    host_pay_rev,
                    700 + i,
                    ttl=64,
                ),
            )
        )
        segout.append(
            (
                t_rev + 0.000020,
                tcp_packet(
                    "203.0.113.20",
                    "198.51.100.10",
                    443,
                    43100,
                    800 + i * 80,
                    40 + i * 80,
                    flags_rev,
                    pay_rev,
                    700 + i,
                    ttl=63,
                ),
            )
        )
        segin.append(
            (
                t_rev + 0.000036,
                tcp_packet(
                    "203.0.113.20",
                    "198.51.100.10",
                    443,
                    43100,
                    800 + i * 80,
                    40 + i * 80,
                    flags_rev,
                    pay_rev,
                    700 + i,
                    ttl=62,
                ),
            )
        )
        lb.append(
            (
                t_rev + 0.000064 + lb_clock_offset,
                tcp_packet(
                    "203.0.113.20",
                    "198.51.100.10",
                    443,
                    43100,
                    800 + i * 80,
                    40 + i * 80,
                    flags_rev,
                    pay_rev,
                    700 + i,
                    ttl=54,
                ),
            )
        )

    for i in range(15):
        host.append(
            (
                1700000100.2 + i * 0.001,
                tcp_packet(
                    f"192.0.2.{(i % 20) + 1}",
                    "198.51.100.250",
                    54000 + i,
                    80,
                    10 + i,
                    1,
                    16,
                    b"n" * 20,
                    900 + i,
                    ttl=60,
                ),
            )
        )

    write_pcap(folder / "GenisSegment1.pcap", gen1)
    write_pcap(folder / "GenisSegment2.pcap", gen2)
    write_pcap(folder / "LB.pcap", lb)
    write_pcap(folder / "Segin.pcap", segin)
    write_pcap(folder / "Segout.pcap", segout)
    write_pcap(folder / "host.pcap", host)


def test_golden_fifty_flow_replica(tmp_path, tshark):
    truth, topology = make_pilot(
        tmp_path / "wire",
        flows=50,
        affected_flows=25,
        slow_local_flow=True,
        host_jitter_us=150,
        ip_id="increment",
    )
    topology["forward"] = [p for p in topology["forward"] if p != "mirror"]
    topology["reverse"] = [p for p in topology["reverse"] if p != "mirror"]
    topology["points"] = [p for p in topology["points"] if p["id"] != "mirror"]
    project = Project(tmp_path / "project")
    ids = ingest_many(project, truth["files"], tshark=tshark, workers=4)
    bind_capture_ids(topology, {Path(f).name: c for f, c in zip(truth["files"], ids)})
    report = analyze(project, topology)
    assert_golden_bytes("fifty_flow_replica", {"report": report}, project)


def test_golden_folder_b_two_path_replica(tmp_path, tshark, monkeypatch):
    _deterministic_uuids(monkeypatch)
    folder = tmp_path / "folder_b"
    _build_folder_b(folder)
    project = create_case(folder, tshark=tshark)
    with project.connect() as db:
        report = project.get(db, "report")
        suggested = project.get(db, "suggested_topology")
    assert_golden_bytes(
        "folder_b_replica",
        {"report": report, "suggested_topology": suggested},
        project,
    )


def test_golden_oct8_stage_shared_clock_host_replica(tmp_path, tshark, monkeypatch):
    _deterministic_uuids(monkeypatch)
    wire_dir = tmp_path / "oct8_case"
    make_pilot(wire_dir, flows=2, rounds=12, real_case=True, noise=200, ip_id="increment")
    for meta_file in ("ground-truth.json", "topology.json"):
        (wire_dir / meta_file).unlink(missing_ok=True)
    project = create_case(wire_dir, tshark=tshark)
    with project.connect() as db:
        report = project.get(db, "report")
        suggested = project.get(db, "suggested_topology")
    assert_golden_bytes(
        "oct8_replica",
        {"report": report, "suggested_topology": suggested},
        project,
    )


def test_golden_demo(scenarios):
    project, _, _, report = scenarios("demo")
    assert_golden_bytes("demo", {"report": report}, project)


def test_golden_nat(scenarios):
    project, _, _, report = scenarios("nat")
    assert_golden_bytes("nat", {"report": report}, project)


def test_golden_offload(scenarios):
    project, _, _, report = scenarios("offload")
    assert_golden_bytes("offload", {"report": report}, project)


def test_golden_integrity_all(scenarios):
    project, _, _, report = scenarios("integrity_multi", fault_location="all", ip_id="zero", ipv6=False)
    assert_golden_bytes("integrity_all", {"report": report}, project)


def test_golden_dns_diagnosis(scenarios):
    project, truth, _, report = scenarios("diagnostics", ip_id="zero", ipv6=False)
    ports = {}
    with project.connect() as db:
        for case, expected in sorted(truth["cases"].items()):
            fid = db.execute("SELECT min(flow) FROM obs WHERE sport=?", [expected["port"]]).fetchone()[0]
            ports[case] = fid
    diag_profiles = {}
    for case, fid in sorted(ports.items()):
        prof = profiles(project, fid)
        for item in prof["items"]:
            item["evidence"] = sorted(item["evidence"], key=lambda e: (e.get("point", ""), e.get("frame", 0)))
        diag_profiles[case] = prof
    dns = dns_page(project, point="client")
    assert_golden_bytes(
        "dns_diagnosis",
        {"report": report, "dns": dns, "profiles": diag_profiles},
        project,
    )
