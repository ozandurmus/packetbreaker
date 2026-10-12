import pytest
from packetbreaker.capture_layers import decoded_layers


import json
import subprocess
import struct
from packetbreaker.capture_layers import layer_rows
from packetbreaker.ingest import ingest
from packetbreaker.store import Project, PACKET_COLUMNS
from packetbreaker.synthetic import tcp_packet, write_pcap
from packetbreaker.analysis import analyze
from capture_realism_fixtures import tunnel


def test_mixed_or_missing_layer_is_unknown_first():
    assert decoded_layers({"frame": {"frame.protocols": "eth:ip:gre:ip:tcp"}, "ip": {"ip.src": "192.0.2.1"}})[
        "reason"
    ]


@pytest.mark.parametrize(
    "kind,ipv6", [("erspan2", False), ("erspan3", True), ("gre", True), ("vxlan", False), ("geneve", True)]
)
def test_inner_outer_fields_and_content_filter_against_tshark(tmp_path, tshark, kind, ipv6):
    src, dst = ("2001:db8:1::1", "2001:db8:2::2") if ipv6 else ("10.1.0.1", "10.2.0.2")
    plain = tcp_packet(src, dst, 41001, 80, 1001, 2001, 24, b"x" * 180, 0)
    path = tmp_path / "wrapped.pcap"
    original = tmp_path / "plain.pcap"
    write_pcap(path, [(1700000000, tunnel(plain, kind, outer6=not ipv6))])
    write_pcap(original, [(1700000000, plain)])
    result = subprocess.run(
        [tshark, "-n", "-r", str(path), "-T", "json", "-x", "--no-duplicate-keys"],
        capture_output=True,
        text=True,
        check=True,
    )
    records, reason = layer_rows(json.loads(result.stdout)[0]["_source"]["layers"], "test", 64)
    assert reason is None
    inner = next(r["packet"] for r in records if r["layer"] == "inner")
    outer = next(r["packet"] for r in records if r["layer"] == "outer")
    project = Project(tmp_path / "project")
    ingest(project, original, tshark=tshark)
    with project.connect() as db:
        expected = dict(zip(PACKET_COLUMNS, db.execute("SELECT * FROM packets").fetchone()))
    for field in (
        "src",
        "dst",
        "proto",
        "sport",
        "dport",
        "seq",
        "ack",
        "length",
        "ipid",
        "prefix",
        "signature",
    ):
        assert inner[field] == expected[field], (kind, field, inner[field], expected[field])
    assert outer["proto"] == ("UDP" if kind in ("vxlan", "geneve") else "GRE")
    assert outer["sport"] != (41001) and outer["src"] != inner["src"]
    from packetbreaker.evidence import content_filter

    filt = content_filter(inner)
    decoded = subprocess.run(
        [tshark, "-n", "-r", str(path), "-Y", filt, "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert decoded.stdout.strip() == "1"


def test_erspan_default_vxlan_opt_in_and_collision_guard(tmp_path, tshark):
    # The outer addresses/IP ID deliberately collide with an unrelated plain TCP flow.
    plain = tcp_packet("10.1.0.1", "10.2.0.2", 41001, 80, 1001, 2001, 24, b"x" * 180, 0)
    decoy = tcp_packet("192.0.2.10", "192.0.2.20", 41001, 80, 1001, 2001, 24, b"x" * 180, 555)
    project = Project(tmp_path / "project")
    points = []
    for name, packets in [
        ("client", [plain, decoy]),
        ("fw_in", [tunnel(plain, "erspan2", truncated=True), decoy]),
        ("fw_out", [plain, decoy]),
        ("lb_in", [tunnel(plain, "vxlan"), decoy]),
        ("lb_out", [plain, decoy]),
        ("server", [plain, decoy]),
    ]:
        path = tmp_path / (name + ".pcap")
        write_pcap(path, [(1700000000 + i * 0.1, p) for i, p in enumerate(packets)])
        if name == "fw_in":
            with path.open("wb") as output:
                output.write(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
                for i, packet in enumerate(packets):
                    output.write(
                        struct.pack("<IIII", 1700000000, i * 100000000 + 789, len(packet), len(packet))
                    )
                    output.write(packet)

        cid = ingest(project, path, tshark=tshark)
        points.append(
            dict(
                id=name,
                label=name,
                device="FW" if name.startswith("fw") else "LB" if name.startswith("lb") else name,
                kind="Generic",
                capture_id=cid,
            )
        )
    topology = dict(
        points=points, forward=[p["id"] for p in points], client_cidrs=["10.1.0.0/16", "192.0.2.10/32"]
    )
    report = analyze(project, topology)
    with project.connect() as db:
        original = db.execute(
            "SELECT signature,tuple_key FROM obs WHERE point='client' AND frame=1"
        ).fetchone()
        wrapped = db.execute("SELECT signature,tuple_key FROM obs WHERE point='fw_in' AND frame=1").fetchone()
        assert original == wrapped
        assert db.execute(
            "SELECT bool_and(o.ts=p.ts AND o.frame_hash=p.frame_hash) FROM obs o JOIN packets p ON o.capture_id=p.capture_id AND o.frame=p.frame WHERE o.point='fw_in'"
        ).fetchone()[0]

        assert db.execute("SELECT unsupported FROM obs WHERE point='lb_in' AND frame=1").fetchone()[0]
    assert all(
        s["loss_percent"] is None and "Tunnel matching layer" in s["reason"]
        for s in report["segments"]
        if "lb_in" in (s["point_a"], s["point_b"])
    )
    assert any(p["point"] == "fw_in" and p["truncated_inner"] == 1 for p in report["tunnel_points"])
    topology["points"][3]["matching_layer"] = "inner"
    analyze(project, topology)
    with project.connect() as db:
        assert (
            db.execute("SELECT signature,tuple_key FROM obs WHERE point='lb_in' AND frame=1").fetchone()
            == original
        )
        a, b = db.execute("SELECT tuple_key FROM obs WHERE point='lb_in' ORDER BY frame").fetchall()
        assert a != b
    topology["points"][3]["matching_layer"] = "outer"
    changed = analyze(project, topology)
    adjacent = [s for s in changed["segments"] if "lb_in" in (s["point_a"], s["point_b"])]
    assert adjacent and all("matching layers" in s["reason"] and s["loss_percent"] is None for s in adjacent)
    with project.connect() as db:
        assert not db.execute("SELECT unsupported FROM obs WHERE point='lb_in' AND frame=1").fetchone()[0]
        assert db.execute("SELECT proto,sport FROM obs WHERE point='lb_in' AND frame=1").fetchone() == (
            "UDP",
            32000,
        )
