import pytest
from packetbreaker.case_setup import capture_paths, inventory_overview, create_case


def test_empty_or_missing_folder_has_no_project_side_effect(tmp_path):
    folder = tmp_path / "captures"
    folder.mkdir()
    with pytest.raises(ValueError, match="capture"):
        create_case(folder)
    assert not folder.with_name("captures.packetbreaker").exists()
    with pytest.raises(ValueError):
        capture_paths(tmp_path / "missing")


def test_time_overlap_warning_is_observed_not_a_clock_guess():
    captures = [
        dict(state="ready", name="FW1", inventory=dict(start=1, end=2)),
        dict(state="ready", name="FW2", inventory=dict(start=3, end=4)),
    ]
    data = inventory_overview(captures)
    assert data["overlap"]["status"] == "none" and "clock" in data["overlap"]["reason"].lower()
    captures[1]["inventory"]["start"] = 1.5
    assert inventory_overview(captures)["overlap"]["status"] == "overlap"


def test_case_ingests_recursively_without_copying_and_cached_reopen(tmp_path, tshark, monkeypatch):
    from packetbreaker.synthetic import tcp_packet, write_pcap

    folder = tmp_path / "incident captures"
    (folder / "FW1").mkdir(parents=True)
    (folder / "FW2").mkdir()
    packet = tcp_packet("10.1.0.1", "203.0.113.2", 41000, 80, 100, 0, 2, b"", 0)
    paths = [folder / "FW1" / "capture.data", folder / "FW2" / "capture.pcapng"]
    from capture_realism_fixtures import tunnel

    for i, path in enumerate(paths):
        write_pcap(path, [(1700000000, tunnel(packet, "erspan2") if i == 0 else packet)])
    (folder / "notes.txt").write_text("not a capture")
    before = {p: p.read_bytes() for p in paths}
    project = create_case(folder, tshark=tshark)
    assert project.path == folder.with_name(folder.name + ".packetbreaker").resolve()
    assert len(project.inventory()) == 2 and all(c["state"] == "ready" for c in project.inventory())
    assert any(c["inventory"].get("tunnel_counts", {}).get("erspan") == 1 for c in project.inventory())
    with project.connect() as db:
        topology = project.get(db, "topology")
        assert not topology["forward"] and len(topology["points"]) == 2
        assert {p["label"] for p in topology["points"]} == {"FW1/capture.data", "FW2/capture.pcapng"}
        topology["forward"] = [p["id"] for p in topology["points"]]
        topology["points"][0]["device"] = "Engineer-selected FW1"
        project.set(db, "topology", topology)
    from unittest.mock import patch

    with patch("packetbreaker.ingest.subprocess.Popen", side_effect=AssertionError("cached case re-parsed")):
        again = create_case(folder, tshark=tshark)
    with again.connect() as db:
        assert again.get(db, "topology") == topology
    assert all(p.read_bytes() == before[p] for p in paths)


def test_case_preflight_preserves_tail_drop_and_tunnel_warnings():
    data = inventory_overview(
        [
            dict(
                id="a",
                name="synthetic",
                state="ready",
                inventory=dict(
                    start=1700000000,
                    end=1700000002,
                    truncated=4,
                    ifdrop=3,
                    osdrop=2,
                    warnings=["File ends mid-packet; last partial record ignored; 10 packets usable"],
                    tunnel_counts={"erspan": 5},
                    interfaces=[dict(snaplen=65535)],
                    observed_max_caplen=500,
                ),
            )
        ]
    )
    file = data["files"][0]
    assert any("mid-packet" in w for w in file["warnings"])
    assert any("truncated" in w for w in file["warnings"])
    assert any("drops" in w for w in file["warnings"])
    assert any("matching layer" in w for w in file["warnings"])
    assert file["header_snaplen"] == 65535 and file["observed_max_caplen"] == 500


def test_case_cli_opens_sibling_project_and_path_without_network(tmp_path, monkeypatch):
    import sys
    from packetbreaker.cli import main
    from packetbreaker.store import Project
    import packetbreaker.case_setup as setup
    from unittest.mock import Mock

    folder = tmp_path / "captures"
    folder.mkdir()
    project = Project(tmp_path / "captures.packetbreaker")
    monkeypatch.setattr(setup, "create_case", lambda *a, **k: project)
    monkeypatch.setattr(sys, "argv", ["packetbreaker", "case", str(folder), "--no-browser", "--port", "9876"])
    import uvicorn

    run = Mock()
    import packetbreaker.app as app_module

    make_app = Mock(return_value=object())
    monkeypatch.setattr(app_module, "create_app", make_app)
    monkeypatch.setattr(uvicorn, "run", run)
    import socket

    sock = Mock()
    monkeypatch.setattr(socket, "socket", lambda: sock)
    main()
    assert run.call_args.kwargs["host"] == "127.0.0.1" and run.call_args.kwargs["port"] == 9876
    assert make_app.call_args.args == (str(project.path),)
    assert run.call_args.args == (make_app.return_value,)


def test_keyboard_interrupt_signals_workers_before_join(monkeypatch, tmp_path):
    import threading
    import packetbreaker.batch_ingest as batch

    cancel = threading.Event()
    entered = threading.Event()

    def ingest(*a, cancel, **kwargs):
        entered.set()
        assert cancel.global_event.wait(2), "executor waited without signalling cancellation"
        raise InterruptedError("cancelled")

    def interrupt(futures):
        assert entered.wait(2)
        raise KeyboardInterrupt()

    monkeypatch.setattr(batch, "ingest", ingest)
    monkeypatch.setattr(batch, "as_completed", interrupt)
    monkeypatch.setattr(batch, "worker_budget", lambda _: 1)
    with pytest.raises(KeyboardInterrupt):
        batch.ingest_many(object(), [tmp_path / "a.pcap"], cancel=cancel)
    assert cancel.is_set()


def test_ingest_prefilter_excludes_unshared_ip_pairs_only_above_5x_threshold(tmp_path, tshark):
    from packetbreaker.synthetic import tcp_packet, write_pcap

    # Negative case: 2 frames vs 10 frames (exactly 5x, not >5x) -> no pre-filter applied
    neg_folder = tmp_path / "below_threshold"
    neg_folder.mkdir()
    shared = [
        (1700000000.0, tcp_packet("198.51.100.10", "203.0.113.20", 41000, 443, 1, 0, 2, b"", 10, ttl=63)),
        (
            1700000000.001,
            tcp_packet("203.0.113.20", "198.51.100.10", 443, 41000, 500, 2, 18, b"", 11, ttl=63),
        ),
    ]
    noise = [
        (
            1700000000.01 + i * 0.001,
            tcp_packet(
                f"192.0.2.{(i % 20) + 1}", "198.51.100.250", 50000 + i, 80, 100 + i, 1, 16, b"x" * 20, 100 + i
            ),
        )
        for i in range(8)
    ]
    write_pcap(neg_folder / "hop_a.pcap", shared)
    write_pcap(neg_folder / "hop_b.pcap", shared + noise)  # 10 frames == 5 * 2 (not >5x)
    neg_project = create_case(neg_folder, tshark=tshark)
    neg_overview = inventory_overview(neg_project.inventory())
    assert not neg_overview["prefilter_excluded"]
    by_name_neg = {f["name"]: f for f in neg_overview["files"]}
    assert by_name_neg["hop_b.pcap"]["packet_count"] == 10
    assert by_name_neg["hop_b.pcap"]["prefilter_excluded"] == 0

    # Positive case: 2 captures with 2 frames each, 1 capture with 15 frames (>5x) containing 13 distractor frames
    pos_folder = tmp_path / "above_threshold"
    pos_folder.mkdir()
    more_noise = [
        (
            1700000000.01 + i * 0.001,
            tcp_packet(
                f"192.0.2.{(i % 20) + 1}", "198.51.100.250", 50000 + i, 80, 100 + i, 1, 16, b"x" * 20, 200 + i
            ),
        )
        for i in range(13)
    ]
    write_pcap(pos_folder / "fw_in.pcap", shared)
    write_pcap(pos_folder / "fw_out.pcap", shared)
    write_pcap(pos_folder / "host_noisy.pcap", shared + more_noise)  # 15 frames > 5 * 2

    pos_project = create_case(pos_folder, tshark=tshark)
    pos_overview = inventory_overview(pos_project.inventory())
    assert pos_overview["prefilter_excluded"] == {"host_noisy.pcap": 13}
    by_name = {f["name"]: f for f in pos_overview["files"]}
    assert by_name["host_noisy.pcap"]["packet_count"] == 2
    assert by_name["host_noisy.pcap"]["prefilter_total"] == 15
    assert by_name["host_noisy.pcap"]["prefilter_retained"] == 2
    assert by_name["host_noisy.pcap"]["prefilter_excluded"] == 13
    assert any("13 excluded" in w for w in by_name["host_noisy.pcap"]["warnings"])

    # Disabling prefilter retains all 15 frames
    unfiltered_project = create_case(pos_folder, tshark=tshark, prefilter=False)
    unfiltered_overview = inventory_overview(unfiltered_project.inventory())
    assert not unfiltered_overview["prefilter_excluded"]
    by_name_unfiltered = {f["name"]: f for f in unfiltered_overview["files"]}
    assert by_name_unfiltered["host_noisy.pcap"]["packet_count"] == 15


def test_prefilter_union_all_other_captures_10_percent_guard_and_case_summary(tmp_path, tshark):
    from packetbreaker.synthetic import tcp_packet, write_pcap

    # 1. Negative case: never filter a capture below 10% of its frames; skip the filter and warn instead
    skip_folder = tmp_path / "below_10_pct"
    skip_folder.mkdir()
    client_y = [
        (1700000000.0, tcp_packet("198.51.100.10", "203.0.113.20", 41000, 443, 1, 0, 2, b"", 10, ttl=63)),
        (1700000000.001, tcp_packet("203.0.113.20", "198.51.100.10", 443, 41000, 500, 2, 18, b"", 11, ttl=63)),
    ]
    heavy_noise = [
        (
            1700000000.01 + i * 0.001,
            tcp_packet(f"192.0.2.{(i % 20) + 1}", "198.51.100.250", 50000 + i, 80, 100 + i, 1, 16, b"x" * 20, 300 + i),
        )
        for i in range(20)
    ]
    write_pcap(skip_folder / "small_1.pcap", client_y)
    write_pcap(skip_folder / "small_2.pcap", client_y)
    # 1 matching frame out of 21 (<10%) -> filter must be skipped with a warning
    write_pcap(skip_folder / "mostly_unshared.pcap", client_y[:1] + heavy_noise)

    skip_proj = create_case(skip_folder, tshark=tshark, auto_assemble=False)
    skip_ov = inventory_overview(skip_proj.inventory())
    skip_by_name = {f["name"]: f for f in skip_ov["files"]}
    assert skip_by_name["mostly_unshared.pcap"]["packet_count"] == 21
    assert skip_by_name["mostly_unshared.pcap"]["prefilter_excluded"] == 0
    assert skip_by_name["mostly_unshared.pcap"]["prefilter_skipped"] is True
    assert any("skipped" in w.lower() and "<10%" in w for w in skip_by_name["mostly_unshared.pcap"]["warnings"])

    # 2. A capture whose IP pairs appear only in a same-size peer (>5x of smaller captures) is untouched,
    #    and a two-path folder keeps every point's flows while filtering only unrelated host noise.
    two_path = tmp_path / "folder_b_prefilter"
    two_path.mkdir()
    client_x = [
        (
            1700000000.0 + i * 0.002,
            tcp_packet("10.1.0.10", "203.0.113.20", 42000 + (i % 2), 443, 1 + i * 50, 1, 24, b"a" * 30, 400 + i, ttl=61),
        )
        for i in range(14)
    ]
    host_noise = [
        (
            1700000000.1 + i * 0.002,
            tcp_packet(f"192.0.2.{(i % 25) + 1}", "198.51.100.250", 52000 + i, 80, 1 + i * 20, 1, 16, b"z" * 20, 700 + i),
        )
        for i in range(16)
    ]
    write_pcap(two_path / "LB.pcap", client_y)
    write_pcap(two_path / "Segin.pcap", client_y)
    write_pcap(two_path / "Segout.pcap", client_y)
    write_pcap(two_path / "GenisSegment1.pcap", client_x)  # 14 frames (>5 * 2), IP pairs in GenisSegment2 & host
    write_pcap(two_path / "GenisSegment2.pcap", client_x)  # 14 frames (same size as GenisSegment1)
    write_pcap(two_path / "host.pcap", client_x[:4] + client_y + host_noise)  # 22 frames: 6 shared (27.3%), 16 noise

    tp_proj = create_case(two_path, tshark=tshark, auto_assemble=False)
    tp_ov = inventory_overview(tp_proj.inventory())
    tp_by_name = {f["name"]: f for f in tp_ov["files"]}
    # GenisSegment1 & GenisSegment2 are untouched (14 frames kept, 0 excluded)
    assert tp_by_name["GenisSegment1.pcap"]["packet_count"] == 14
    assert tp_by_name["GenisSegment1.pcap"]["prefilter_excluded"] == 0
    assert not any("excluded" in w for w in tp_by_name["GenisSegment1.pcap"]["warnings"])
    assert tp_by_name["GenisSegment2.pcap"]["packet_count"] == 14
    assert tp_by_name["GenisSegment2.pcap"]["prefilter_excluded"] == 0
    # Host keeps both client X (4 frames) and client Y (2 frames) = 6 frames, excludes 16 noise frames
    assert tp_by_name["host.pcap"]["packet_count"] == 6
    assert tp_by_name["host.pcap"]["prefilter_excluded"] == 16
    with tp_proj.connect() as db:
        host_cid = tp_by_name["host.pcap"]["id"]
        host_srcs = {
            r[0] for r in db.execute("SELECT DISTINCT src FROM packets WHERE capture_id=?", [host_cid]).fetchall()
        }
        assert {"10.1.0.10", "198.51.100.10"} <= host_srcs
        ctx = tp_proj.get(db, "case_context")
    # Case summary includes excluded count per file for every file
    expected_per_file = {
        "GenisSegment1.pcap": 0,
        "GenisSegment2.pcap": 0,
        "LB.pcap": 0,
        "Segin.pcap": 0,
        "Segout.pcap": 0,
        "host.pcap": 16,
    }
    assert ctx["prefilter_excluded"] == expected_per_file
    assert ctx["summary"]["prefilter_excluded"] == expected_per_file
    assert tp_ov["summary"]["prefilter_excluded"] == expected_per_file



def test_auto_assemble_stops_on_ambiguous_order_or_direction(tmp_path, tshark):
    from packetbreaker.synthetic import tcp_packet, write_pcap
    from packetbreaker.topology_suggest import assemble_topology

    # 1. Equal TTL and unaligned clock -> ambiguous path order, must not guess
    amb_order = tmp_path / "amb_order"
    amb_order.mkdir()
    records_a, records_b = [], []
    for i in range(4):
        t = 1700000000.0 + i * 0.01
        fwd = tcp_packet(
            "198.51.100.10",
            "203.0.113.20",
            42000,
            443,
            1 + i * 100,
            1,
            2 if i == 0 else 24,
            b"a" * 50,
            10 + i,
            ttl=60,
        )
        rev = tcp_packet(
            "203.0.113.20",
            "198.51.100.10",
            443,
            42000,
            500 + i * 100,
            51,
            18 if i == 0 else 24,
            b"b" * 50,
            50 + i,
            ttl=60,
        )
        records_a.extend([(t, fwd), (t + 0.001, rev)])
        records_b.extend([(t + 2.5, fwd), (t + 2.501, rev)])
    write_pcap(amb_order / "tap_1.pcap", records_a)
    write_pcap(amb_order / "tap_2.pcap", records_b)
    proj_order = create_case(amb_order, tshark=tshark)
    res_order = assemble_topology(proj_order)
    assert res_order["ambiguous"] and res_order["status"] == "ambiguous"
    assert "Ambiguous path order" in res_order["reason"]
    with proj_order.connect() as db:
        assert proj_order.get(db, "report") is None
        assert proj_order.get(db, "topology")["forward"] == []

    # 2. Mid-stream capture with two high ephemeral ports and no SYN -> ambiguous client_cidrs
    amb_dir = tmp_path / "amb_dir"
    amb_dir.mkdir()
    dir_a, dir_b = [], []
    for i in range(4):
        t = 1700000000.0 + i * 0.01
        p1 = tcp_packet(
            "198.51.100.10", "203.0.113.20", 45000, 45001, 100 + i * 100, 200, 24, b"a" * 50, 10 + i, ttl=64
        )
        p2 = tcp_packet(
            "203.0.113.20", "198.51.100.10", 45001, 45000, 200 + i * 100, 150, 24, b"b" * 50, 50 + i, ttl=62
        )
        dir_a.extend([(t, p1), (t + 0.001, p2)])
        dir_b.extend(
            [
                (
                    t + 0.00002,
                    tcp_packet(
                        "198.51.100.10",
                        "203.0.113.20",
                        45000,
                        45001,
                        100 + i * 100,
                        200,
                        24,
                        b"a" * 50,
                        10 + i,
                        ttl=63,
                    ),
                ),
                (
                    t + 0.00098,
                    tcp_packet(
                        "203.0.113.20",
                        "198.51.100.10",
                        45001,
                        45000,
                        200 + i * 100,
                        150,
                        24,
                        b"b" * 50,
                        50 + i,
                        ttl=63,
                    ),
                ),
            ]
        )
    write_pcap(amb_dir / "hop_1.pcap", dir_a)
    write_pcap(amb_dir / "hop_2.pcap", dir_b)
    proj_dir = create_case(amb_dir, tshark=tshark)
    res_dir = assemble_topology(proj_dir)
    assert res_dir["ambiguous"]
    assert "Ambiguous client direction" in res_dir["reason"]

    # 3. Truthful ambiguity reason when a capture is empty or mostly excluded
    excl_dir = tmp_path / "amb_excluded"
    excl_dir.mkdir()
    hop1, hop2 = [], []
    for i in range(4):
        t = 1700000000.0 + i * 0.01
        f1 = tcp_packet("198.51.100.10", "203.0.113.20", 43000, 443, 1 + i * 100, 1, 2 if i == 0 else 24, b"a" * 40, 10 + i, ttl=64)
        r1 = tcp_packet("203.0.113.20", "198.51.100.10", 443, 43000, 500 + i * 100, 41, 18 if i == 0 else 24, b"b" * 40, 50 + i, ttl=62)
        f2 = tcp_packet("198.51.100.10", "203.0.113.20", 43000, 443, 1 + i * 100, 1, 2 if i == 0 else 24, b"a" * 40, 10 + i, ttl=63)
        r2 = tcp_packet("203.0.113.20", "198.51.100.10", 443, 43000, 500 + i * 100, 41, 18 if i == 0 else 24, b"b" * 40, 50 + i, ttl=63)
        hop1.extend([(t, f1), (t + 0.001, r1)])
        hop2.extend([(t + 0.00002, f2), (t + 0.00098, r2)])
    # Third capture has 15 frames (>10% but >50% pre-filter excluded: 2 matching unrelated IP pair in hop4 or 18 excluded)
    # Specifically: 2 frames on a separate IP pair (shared with hop1's noise IP pair, not the client-server TCP flow) + 14 excluded noise frames
    noise_pair_pkt = (
        1700000000.5,
        tcp_packet("192.0.2.55", "198.51.100.99", 51000, 80, 10, 1, 16, b"", 90, ttl=60),
    )
    write_pcap(excl_dir / "hop_1.pcap", hop1 + [noise_pair_pkt])  # 9 frames
    write_pcap(excl_dir / "hop_2.pcap", hop2)  # 8 frames
    # hop_mostly_excluded has 2 frames matching noise_pair_pkt (12.5% >= 10%) + 14 excluded frames = 16 frames total (<5x, so test via unsupported/prefilter)
    from capture_realism_fixtures import tunnel

    mostly_excl_records = [noise_pair_pkt] + [
        (1700000001.0 + i * 0.001, tunnel(hop1[0][1], "erspan2")) for i in range(9)
    ]
    write_pcap(excl_dir / "hop_mostly_excluded.pcap", mostly_excl_records)
    proj_excl = create_case(excl_dir, tshark=tshark)
    res_excl = assemble_topology(proj_excl)
    assert res_excl["ambiguous"]
    assert "mostly excluded" in res_excl["reason"]
    assert "hop_mostly_excluded.pcap" in res_excl["reason"]
    assert "share no directional TCP traffic" not in res_excl["reason"]

    # Empty capture (0 usable frames in packets table) reports "is empty"
    with proj_excl.connect() as db:
        cid_empty = db.execute("SELECT id FROM captures WHERE name='hop_mostly_excluded.pcap'").fetchone()[0]
        db.execute("DELETE FROM packets WHERE capture_id=?", [cid_empty])
    res_empty = assemble_topology(proj_excl)
    assert res_empty["ambiguous"]
    assert "hop_mostly_excluded.pcap is empty" in res_empty["reason"]
    assert "share no directional TCP traffic" not in res_empty["reason"]



def test_name_order_mismatch_warning_and_stage_pair_shared_clock_host_auto_assemble(tmp_path, tshark):
    import shutil
    from fastapi.testclient import TestClient
    from packetbreaker.app import create_app
    from packetbreaker.pilot_synthetic import make_pilot
    from packetbreaker.topology_suggest import suggest_topology, assemble_topology

    wire_dir = tmp_path / "pilot_case"
    truth, expected_topo = make_pilot(
        wire_dir, flows=2, rounds=12, real_case=True, noise=200, ip_id="increment"
    )
    for meta_file in ("ground-truth.json", "topology.json"):
        (wire_dir / meta_file).unlink(missing_ok=True)

    # 1. Stage-pair + shared-clock + host replica assembles with zero manual input
    project = create_case(wire_dir, tshark=tshark)
    with project.connect() as db:
        topo = project.get(db, "topology")
        report = project.get(db, "report")
        suggested = project.get(db, "suggested_topology")

    assert not suggested["ambiguous"]
    assert not suggested["confirmed"]
    assert suggested["badge"] == "Suggested topology — review & confirm"
    assert topo["forward"] == expected_topo["forward"]
    assert topo["reverse"] == expected_topo["reverse"]
    assert topo["client_cidrs"] == expected_topo["client_cidrs"]
    pts = {p["id"]: p for p in topo["points"]}
    assert pts["a_rx"]["stage_capture"] and pts["a_rx"]["side"] == "ingress"
    assert pts["a_tx"]["stage_capture"] and pts["a_tx"]["side"] == "egress"
    assert pts["a_rx"]["device"] == pts["a_tx"]["device"]
    assert pts["b_rx"]["stage_capture"] and pts["b_rx"]["side"] == "ingress"
    assert pts["b_tx"]["stage_capture"] and pts["b_tx"]["side"] == "egress"
    assert pts["b_rx"]["device"] == pts["b_tx"]["device"]
    assert pts["a_rx"]["clock_domain"] == pts["mirror"]["clock_domain"]
    assert pts["host"]["host_capture"] and pts["host"]["clock_domain"] is None
    assert {"client_cidrs", "stage_pair", "shared_clock", "host_capture", "path_order"} <= {
        inf["kind"] for inf in suggested["inferences"]
    }
    assert all(inf["evidence"] for inf in suggested["inferences"])
    assert report is not None and report["verdict"].startswith("Delay occurs between")
    assert report["suggested_topology"]["badge"] == "Suggested topology — review & confirm"

    # Verify UI/API endpoints: one click confirms, and any edit re-runs
    client = TestClient(create_app(project.path))
    headers = {"host": "127.0.0.1:8765", "x-packetbreaker": "local"}
    confirm_res = client.post("/api/topology/confirm", headers=headers)
    assert confirm_res.status_code == 200 and confirm_res.json()["confirmed"] is True
    assemble_res = client.post("/api/topology/assemble", headers=headers)
    assert assemble_res.status_code == 200
    assert assemble_res.json()["suggested_topology"]["confirmed"] is False

    # 2. Name/order mismatch warning when file names say in/rx on the egress side
    swapped_dir = tmp_path / "swapped_names"
    swapped_dir.mkdir()
    shutil.copy2(wire_dir / "a_rx.pcap", swapped_dir / "ark_fw_out.pcap")  # Actually ingress (first)
    shutil.copy2(wire_dir / "a_tx.pcap", swapped_dir / "ark_fw_in.pcap")  # Actually egress (second)
    shutil.copy2(wire_dir / "b_rx.pcap", swapped_dir / "b_rx.pcap")
    shutil.copy2(wire_dir / "b_tx.pcap", swapped_dir / "b_tx.pcap")
    shutil.copy2(wire_dir / "mirror.pcap", swapped_dir / "mirror.pcap")
    shutil.copy2(wire_dir / "host.pcap", swapped_dir / "host.pcap")

    swapped_project = create_case(swapped_dir, tshark=tshark)
    sugg = suggest_topology(swapped_project)
    expected_warn = (
        "File names suggest ark_fw_in.pcap -> ark_fw_out.pcap, "
        "packets show ark_fw_out.pcap -> ark_fw_in.pcap "
        "(names may describe interfaces, not direction)"
    )
    assert expected_warn in sugg["warnings"]
    assembled_swapped = assemble_topology(swapped_project)
    assert expected_warn in assembled_swapped["warnings"]
    # Order comes from packets (ark_fw_out -> ark_fw_in), not file names
    assert assembled_swapped["topology"]["forward"] == [
        "ark_fw_out",
        "ark_fw_in",
        "b_rx",
        "b_tx",
        "mirror",
        "host",
    ]


def test_multi_path_folder_b_replica_assembles_both_paths_and_stops_when_group_ambiguous(tmp_path, tshark):
    from fastapi.testclient import TestClient
    from packetbreaker.app import create_app
    from packetbreaker.synthetic import tcp_packet, write_pcap
    from packetbreaker.topology_suggest import assemble_topology

    def build_folder_b(folder, *, ambiguous_group_x: bool = False):
        folder.mkdir()
        gen1, gen2, lb, segin, segout, host = [], [], [], [], [], []
        # Group X: GenisSegment1 -> GenisSegment2 -> host (Client X: 10.1.0.10/32, Server: 203.0.113.20:443)
        # Uses 12 rounds (24 frames per GenisSegment capture, >5x of Group Y's 4 frames -> exercises pre-filter too)
        for i in range(12):
            t = 1700000100.0 + i * 0.01
            flags_fwd = 2 if i == 0 else 24
            flags_rev = 18 if i == 0 else 24
            pay_fwd = b"" if i == 0 else f"req_x_{i:02d}_".encode() + b"x" * 60
            pay_rev = b"" if i == 0 else f"rsp_x_{i:02d}_".encode() + b"y" * 60
            ttl_g1_f = 62
            ttl_g2_f = 62 if ambiguous_group_x else 61
            ttl_g1_r = 61 if ambiguous_group_x else 60
            ttl_g2_r = 61
            dt_g2 = 1.5 if ambiguous_group_x else 0.000025
            gen1.append(
                (t, tcp_packet("10.1.0.10", "203.0.113.20", 42100, 443, 1 + i * 100, 1 + i * 100, flags_fwd, pay_fwd, 100 + i, ttl=ttl_g1_f))
            )
            gen2.append(
                (t + dt_g2, tcp_packet("10.1.0.10", "203.0.113.20", 42100, 443, 1 + i * 100, 1 + i * 100, flags_fwd, pay_fwd, 100 + i, ttl=ttl_g2_f))
            )
            host.append(
                (t + 0.00005, tcp_packet("10.1.0.10", "203.0.113.20", 42100, 443, 1 + i * 100, 1 + i * 100, flags_fwd, pay_fwd, 100 + i, ttl=60))
            )
            # Server reply (with TSO superframe on host for i == 1)
            t_rev = t + 0.002
            host_pay_rev = b"S" * 2400 if i == 1 else pay_rev
            host.append(
                (t_rev, tcp_packet("203.0.113.20", "10.1.0.10", 443, 42100, 500 + i * 100, 50 + i * 100, flags_rev, host_pay_rev, 300 + i, ttl=64))
            )
            gen2.append(
                (t_rev + 0.00002, tcp_packet("203.0.113.20", "10.1.0.10", 443, 42100, 500 + i * 100, 50 + i * 100, flags_rev, pay_rev, 300 + i, ttl=ttl_g2_r))
            )
            gen1.append(
                (t_rev + dt_g2 + 0.00002, tcp_packet("203.0.113.20", "10.1.0.10", 443, 42100, 500 + i * 100, 50 + i * 100, flags_rev, pay_rev, 300 + i, ttl=ttl_g1_r))
            )

        # Group Y: LB -> Segin -> Segout -> host (Client Y: 198.51.100.10/32, Server: 203.0.113.20:443)
        for i in range(4):
            t = 1700000100.005 + i * 0.015
            flags_fwd = 2 if i == 0 else 24
            flags_rev = 18 if i == 0 else 24
            pay_fwd = b"" if i == 0 else f"req_y_{i:02d}_".encode() + b"a" * 50
            pay_rev = b"" if i == 0 else f"rsp_y_{i:02d}_".encode() + b"b" * 50
            lb.append(
                (t, tcp_packet("198.51.100.10", "203.0.113.20", 43100, 443, 1 + i * 80, 1 + i * 80, flags_fwd, pay_fwd, 500 + i, ttl=63))
            )
            segin.append(
                (t + 0.00002, tcp_packet("198.51.100.10", "203.0.113.20", 43100, 443, 1 + i * 80, 1 + i * 80, flags_fwd, pay_fwd, 500 + i, ttl=62))
            )
            segout.append(
                (t + 0.00004, tcp_packet("198.51.100.10", "203.0.113.20", 43100, 443, 1 + i * 80, 1 + i * 80, flags_fwd, pay_fwd, 500 + i, ttl=61))
            )
            host.append(
                (t + 0.00006, tcp_packet("198.51.100.10", "203.0.113.20", 43100, 443, 1 + i * 80, 1 + i * 80, flags_fwd, pay_fwd, 500 + i, ttl=60))
            )
            t_rev = t + 0.002
            host_pay_rev = b"T" * 2200 if i == 1 else pay_rev
            host.append(
                (t_rev, tcp_packet("203.0.113.20", "198.51.100.10", 443, 43100, 800 + i * 80, 40 + i * 80, flags_rev, host_pay_rev, 700 + i, ttl=64))
            )
            segout.append(
                (t_rev + 0.00002, tcp_packet("203.0.113.20", "198.51.100.10", 443, 43100, 800 + i * 80, 40 + i * 80, flags_rev, pay_rev, 700 + i, ttl=63))
            )
            segin.append(
                (t_rev + 0.00004, tcp_packet("203.0.113.20", "198.51.100.10", 443, 43100, 800 + i * 80, 40 + i * 80, flags_rev, pay_rev, 700 + i, ttl=62))
            )
            lb.append(
                (t_rev + 0.00006, tcp_packet("203.0.113.20", "198.51.100.10", 443, 43100, 800 + i * 80, 40 + i * 80, flags_rev, pay_rev, 700 + i, ttl=61))
            )

        # Unrelated host noise (filtered out by pre-filter without losing either client X or client Y)
        for i in range(15):
            host.append(
                (
                    1700000100.2 + i * 0.001,
                    tcp_packet(f"192.0.2.{(i % 20) + 1}", "198.51.100.250", 54000 + i, 80, 10 + i, 1, 16, b"n" * 20, 900 + i, ttl=60),
                )
            )

        write_pcap(folder / "GenisSegment1.pcap", gen1)
        write_pcap(folder / "GenisSegment2.pcap", gen2)
        write_pcap(folder / "LB.pcap", lb)
        write_pcap(folder / "Segin.pcap", segin)
        write_pcap(folder / "Segout.pcap", segout)
        write_pcap(folder / "host.pcap", host)

    # 1. Negative case: when one group itself is ambiguous, stop as ambiguous
    amb_folder = tmp_path / "folder_b_ambiguous"
    build_folder_b(amb_folder, ambiguous_group_x=True)
    amb_proj = create_case(amb_folder, tshark=tshark)
    amb_res = assemble_topology(amb_proj)
    assert amb_res["ambiguous"] is True
    assert "Ambiguous path order" in amb_res["reason"]

    # 2. Acceptance case: Folder B 2-path replica assembles both paths with zero input
    ok_folder = tmp_path / "folder_b_ok"
    build_folder_b(ok_folder, ambiguous_group_x=False)
    ok_proj = create_case(ok_folder, tshark=tshark)
    with ok_proj.connect() as db:
        suggested = ok_proj.get(db, "suggested_topology")
        report = ok_proj.get(db, "report")

    assert not suggested["ambiguous"]
    assert suggested["multi_path"] is True
    assert len(suggested["groups"]) == 2
    groups_by_name = {g["name"]: g for g in suggested["groups"]}
    assert set(groups_by_name) == {"10.1.0.10/32", "198.51.100.10/32"}

    gx = groups_by_name["10.1.0.10/32"]
    gy = groups_by_name["198.51.100.10/32"]
    assert gx["topology"]["forward"] == ["GenisSegment1", "GenisSegment2", "host"]
    assert gx["topology"]["reverse"] == ["host", "GenisSegment2", "GenisSegment1"]
    assert gy["topology"]["forward"] == ["LB", "Segin", "Segout", "host"]
    assert gy["topology"]["reverse"] == ["host", "Segout", "Segin", "LB"]
    # Both groups include the shared host capture and have separate analyses and review & confirm states
    assert gx["report"] is not None and gy["report"] is not None
    assert set(report["group_reports"]) == {"10.1.0.10/32", "198.51.100.10/32"}
    assert gx["confirmed"] is False and gy["confirmed"] is False
    assert gx["badge"] == "Suggested topology — review & confirm"
    assert gy["badge"] == "Suggested topology — review & confirm"

    # Confirming one group leaves the other unconfirmed until confirmed independently
    client = TestClient(create_app(ok_proj.path))
    headers = {"host": "127.0.0.1:8765", "x-packetbreaker": "local"}
    c1 = client.post("/api/topology/confirm", json={"group": "10.1.0.10/32"}, headers=headers)
    assert c1.status_code == 200
    c1_data = c1.json()
    assert c1_data["group_confirmed"] is True
    assert c1_data["confirmed"] is False
    g_after_1 = {g["name"]: g for g in c1_data["suggested_topology"]["groups"]}
    assert g_after_1["10.1.0.10/32"]["confirmed"] is True
    assert g_after_1["198.51.100.10/32"]["confirmed"] is False

    c2 = client.post("/api/topology/confirm", json={"group": "198.51.100.10/32"}, headers=headers)
    assert c2.status_code == 200
    c2_data = c2.json()
    assert c2_data["confirmed"] is True
    assert c2_data["topology"]["forward"] == ["LB", "Segin", "Segout", "host"]

