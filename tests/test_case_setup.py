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
