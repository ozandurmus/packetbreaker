import json

import pytest

from packetbreaker.analysis import analyze, flow_page, ladder
from packetbreaker.clock import fit_clock
from packetbreaker.store import Project


def classes(report):
    return {f["type"] for f in report["findings"]}


def test_healthy_five_file_e2e_and_reopen(scenarios):
    project, truth, topology, report = scenarios("healthy")
    assert len(project.inventory()) == 5
    assert classes(report) == set()
    assert report["flow_count"] == 1
    assert all(s["matched"] > 90 for s in report["segments"])
    assert all(s["p95_ms"] == pytest.approx(1, abs=0.025) for s in report["segments"])
    for i, p in enumerate(topology["points"]):
        model = report["clocks"][p["capture_id"]]
        assert model["offset"] == pytest.approx(truth["offsets"][i], abs=0.0001)
        assert model["drift_ppm"] == pytest.approx(truth["drifts_ppm"][i], abs=0.6)
    reopened = Project(project.path)
    with reopened.connect() as db:
        assert reopened.get(db, "report")["verdict"] == report["verdict"]
        assert (
            reopened.get(db, "topology") == topology
            or reopened.get(db, "topology")["forward"] == topology["forward"]
        )
    page = flow_page(project)
    assert page["total"] == 1
    trace = ladder(project, page["items"][0]["flow"])
    assert trace["total"] > 300
    assert len(trace["items"][0]["evidence"]) == 5
    # JSON contract must not contain nonfinite numbers or Python-only values.
    json.dumps(report, allow_nan=False)


@pytest.mark.parametrize("scenario", ["capture_miss", "acked_unseen"])
def test_capture_miss_never_network_loss(scenarios, scenario):
    _, truth, _, report = scenarios(scenario)
    assert classes(report) == {"capture_miss"}
    assert sum(f["metrics"]["count"] for f in report["findings"]) == len(truth["events"])
    assert all(s["loss_percent"] == 0 for s in report["segments"])


@pytest.mark.parametrize("scenario", ["recovered_loss", "impactful_loss"])
def test_loss_has_correct_hop_time_and_recovery(scenarios, scenario):
    _, truth, _, report = scenarios(scenario)
    loss = [f for f in report["findings"] if f["type"] == scenario]
    assert len(loss) == 1
    assert loss[0]["hop"] == "forward:p2:p3"
    assert loss[0]["time_range"][0] == pytest.approx(truth["events"][0]["time"], abs=1)
    assert loss[0]["metrics"]["count"] == len(truth["events"])
    assert loss[0]["metrics"]["max_recovery_ms"] == pytest.approx(
        truth["events"][0]["recovery_ms"] + 1, abs=0.05
    )
    assert len(loss[0]["evidence"]) >= 5
    assert all("frame.number ==" in e["display_filter"] for e in loss[0]["evidence"])


def test_nat_must_be_confirmed_then_collapses_logical_flow(scenarios):
    project, _, topology, report = scenarios("nat")
    assert len(report["nat_suggestions"]) >= 1
    assert all(f["type"] == "unknown" for f in report["findings"])
    assert any(s["reason"] == "NAT mapping awaits confirmation" for s in report["segments"])
    topology = {
        **topology,
        "nat_mappings": [
            {k: s[k] for k in ("point_a", "point_b", "tuple_a", "tuple_b")}
            for s in report["nat_suggestions"][:1]
        ],
    }
    confirmed = analyze(project, topology)
    assert classes(confirmed) == set()
    assert confirmed["flow_count"] == 1
    assert all(s["p95_ms"] == pytest.approx(1, abs=0.05) for s in confirmed["segments"])


def test_truncated_payload_prefixes_still_match(scenarios):
    _, _, _, report = scenarios("truncation")
    assert classes(report) == set()
    assert sum(q["truncated"] for q in report["quality"]) > 100
    assert all(s["matched"] > 90 for s in report["segments"])


def test_repeated_signatures_fail_closed(scenarios):
    _, _, _, report = scenarios("duplicate")
    assert not {"impactful_loss", "recovered_loss"} & classes(report)
    assert sum(q["excluded"] for q in report["quality"]) > 0


def test_delay_is_on_correct_segment(scenarios):
    _, _, _, report = scenarios("delay")
    delayed = [s for s in report["segments"] if s["p95_ms"] and s["p95_ms"] > 20]
    assert {s["id"] for s in delayed} == {"forward:p2:p3", "reverse:p3:p2"}
    assert all(s["p95_ms"] == pytest.approx(31, abs=0.05) for s in delayed)


def test_one_way_clock_unknown():
    model = fit_clock([(float(i), i + 0.25, True) for i in range(100)])
    assert model.offset is None
    assert model.correct(10) is None


def test_clock_offset_drift_and_inconsistent_envelope():
    data = []
    for i in range(200):
        t = i * 0.5
        for forward in (True, False):
            jitter = 0.0002 * (i % 3)
            data.append((t, t + 0.4 + t * 30e-6 + (1 if forward else -1) * (0.002 + jitter), forward))
    model = fit_clock(data)
    assert model.offset == pytest.approx(0.4, abs=0.00001)
    assert model.drift * 1e6 == pytest.approx(30, abs=1)
    assert model.uncertainty == pytest.approx(0.002, abs=0.00001)
    bad = fit_clock([(i, i + (0.1 if f else 0.2), f) for i in range(8) for f in (True, False)])
    assert bad.offset is None


def test_bad_override_suppresses_negative_latency(scenarios):
    project, _, topology, _ = scenarios("healthy")
    topology = {
        **topology,
        "clock_overrides": {topology["points"][1]["capture_id"]: {"offset_ms": 1000, "drift_ppm": 0}},
    }
    report = analyze(project, topology)
    hop = next(s for s in report["segments"] if s["id"] == "forward:p0:p1")
    assert hop["p95_ms"] is None
    assert hop["reason"] == "Clock alignment unreliable"


def test_overlap_and_unsupported_boundaries_do_not_blame_network(scenarios):
    project, _, topology, _ = scenarios("impactful_loss")
    topology = {
        **topology,
        "points": [
            {**p, "translation": "full_proxy" if p["id"] == "p2" else p["translation"]}
            for p in topology["points"]
        ],
    }
    report = analyze(project, topology)
    assert "impactful_loss" not in classes(report)
    assert any(s["reason"] == "Unsupported translation boundary" for s in report["segments"])


def test_empty_selected_window_is_unknown_not_zero_loss(scenarios):
    project, truth, topology, _ = scenarios("healthy")
    topology = {**topology, "start": truth["reference_epoch"] + 1000, "end": truth["reference_epoch"] + 1001}
    report = analyze(project, topology)
    assert all(s["loss_percent"] is None for s in report["segments"])
    assert report["verdict"] == "Inconclusive"


def test_nat_tuple_validation_and_normalization():
    from packetbreaker.topology import NatMapping
    from pydantic import ValidationError

    m = NatMapping(
        point_a="a",
        point_b="b",
        tuple_a='["TCP", "10.0.0.1", 40, "10.0.0.2", 50]',
        tuple_b='["TCP","10.0.0.1",40,"10.0.0.2",50]',
    )
    assert m.tuple_a == m.tuple_b
    with pytest.raises(ValidationError):
        NatMapping(point_a="a", point_b="b", tuple_a="[]", tuple_b="[]")


def test_clock_drift_over_hour_long_window():
    samples = [
        (float(i * 40), i * 40 + 0.12 + i * 40 * 40e-6 + (0.001 if forward else -0.001), forward)
        for i in range(100)
        for forward in (True, False)
    ]
    model = fit_clock(samples)
    assert model.offset == pytest.approx(0.12, abs=1e-5)
    assert model.drift * 1e6 == pytest.approx(40, abs=0.1)


def test_udp_payload_disambiguates_reused_zero_ip_id(tmp_path, tshark):
    import socket
    import struct
    from packetbreaker.synthetic import checksum, write_pcap
    from packetbreaker.ingest import ingest

    captures = [[] for _ in range(3)]
    for i in range(30):
        for forward in (True, False):
            src, dst = ("10.0.0.1", "203.0.113.1") if forward else ("203.0.113.1", "10.0.0.1")
            payload = b"common-header-" + str(i).zfill(5).encode()
            udp = struct.pack("!HHHH", 50000, 50001, len(payload) + 8, 0) + payload
            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                len(udp) + 20,
                0,
                0x4000,
                64,
                17,
                0,
                socket.inet_aton(src),
                socket.inet_aton(dst),
            )
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
            frame = b"\0" * 12 + b"\x08\x00" + ip + udp
            for h in range(3):
                if i == 5 and forward and h == 1:
                    continue
                t = (
                    1700000000
                    + i * 0.4
                    + (0.1 if not forward else 0)
                    + (h if forward else 2 - h) * 0.001
                    + h * 0.12
                )
                captures[h].append((t, frame))
    project = Project(tmp_path / "project")
    points = []
    for h, packets in enumerate(captures):
        path = tmp_path / f"{h}.pcap"
        write_pcap(path, packets)
        points.append(
            dict(id=f"p{h}", label=f"P{h}", device=f"P{h}", capture_id=ingest(project, path, tshark=tshark))
        )
    report = analyze(project, dict(points=points, forward=["p0", "p1", "p2"], client_cidrs=["10.0.0.0/8"]))
    assert classes(report) == {"capture_miss"}
    assert sum(f["metrics"]["count"] for f in report["findings"]) == 1
    assert all(s["matched"] >= 28 for s in report["segments"])


def test_configurable_nat_hop_suggestions(scenarios):
    _, _, _, report = scenarios("nat", nat_hop=3, rounds=20)
    assert report["nat_suggestions"]
    assert all((m["point_a"], m["point_b"]) == ("p2", "p3") for m in report["nat_suggestions"])


def test_short_repeated_loss_is_impactful(scenarios):
    import hashlib
    from packetbreaker.store import PACKET_COLUMNS, rows

    project, _, topology, _ = scenarios("recovered_loss", rounds=60)
    # Unit fixture: add two local retransmission attempts, both absent downstream.
    with project.connect() as db:
        key = db.execute(
            "SELECT packet_key FROM events WHERE kind='recovered_loss' ORDER BY ts LIMIT 1"
        ).fetchone()[0]
        originals = rows(
            db, "SELECT p.* FROM packets p JOIN obs o USING(capture_id,frame) WHERE o.packet_key=?", [key]
        )
        for attempt, wait in enumerate((0.01, 0.02), 1):
            for packet in originals:
                packet = {
                    **packet,
                    "frame": packet["frame"] + attempt * 1000000,
                    "ts": packet["ts"] + wait,
                    "signature": hashlib.sha256((packet["signature"] + str(attempt)).encode()).hexdigest(),
                    "retrans": True,
                }
                db.execute(
                    "INSERT INTO packets VALUES (" + ",".join("?" for _ in PACKET_COLUMNS) + ")",
                    [packet[k] for k in PACKET_COLUMNS],
                )
    report = analyze(project, topology)
    impactful = [f for f in report["findings"] if f["type"] == "impactful_loss"]
    assert impactful and impactful[0]["hop"] == "forward:p2:p3"
    assert impactful[0]["metrics"]["max_recovery_ms"] < 200


def test_ack_from_reused_tuple_session_does_not_prove_capture_miss(scenarios):
    project, _, topology, _ = scenarios("acked_unseen", rounds=40)
    with project.connect() as db:
        # Separate local stream identity models a reused 5-tuple with unrelated ACKs.
        db.execute("UPDATE packets SET stream=stream+100 WHERE src='203.0.113.20'")
    report = analyze(project, topology)
    assert classes(report) == {"unrecovered_loss"}
