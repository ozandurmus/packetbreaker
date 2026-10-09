from pathlib import Path
import subprocess
import pytest
from packetbreaker.analysis import analyze, flow_page, ladder, event_page


def filter_frames(tshark, path, expression):
    result = subprocess.run(
        [
            tshark,
            "-n",
            "-r",
            str(path),
            "-Y",
            expression,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return [
        (int(line.split("\t")[0]), float(line.split("\t")[1])) for line in result.stdout.splitlines() if line
    ]


@pytest.mark.slow
@pytest.mark.parametrize("ipv6", [False, True])
def test_content_filters_survive_merge_and_resave(scenarios, tshark, tmp_path, ipv6):
    _, truth, _, report = scenarios("recovered_loss", ip_id="zero", ipv6=ipv6)
    finding = report["findings"][0]
    ref = next(e for e in finding["evidence"] if e["point"] == "p0")
    source = next(p for p in truth["files"] if Path(p).name == ref["file"])
    matches = filter_frames(tshark, source, ref["content_filter"])
    assert ref["frame"] in [frame for frame, _ in matches]
    assert len(matches) >= 2  # Identical retransmission is intentionally not hidden by a content selector.
    mergecap = Path(tshark).with_name("mergecap.exe" if Path(tshark).suffix == ".exe" else "mergecap")
    merged = tmp_path / "merged.pcapng"
    subprocess.run(
        [str(mergecap), "-w", str(merged), truth["files"][0], truth["files"][1]],
        check=True,
        capture_output=True,
    )
    remapped = filter_frames(tshark, merged, ref["content_filter"])
    assert any(abs(ts - ref["observed_time"]) < 1e-6 for _, ts in remapped)
    assert any(frame != ref["frame"] for frame, ts in remapped if abs(ts - ref["observed_time"]) < 1e-6)


@pytest.mark.slow
def test_flow_filter_uses_post_nat_tuple_per_file(scenarios, tshark):
    project, truth, topology, report = scenarios("nat", rounds=25)
    topology = {
        **topology,
        "nat_mappings": [
            {k: s[k] for k in ("point_a", "point_b", "tuple_a", "tuple_b")} for s in report["nat_suggestions"]
        ],
    }
    analyze(project, topology)
    flow = flow_page(project)["items"][0]["flow"]
    trace = ladder(project, flow, limit=1)
    assert len(trace["flow_filters"]) == 5
    for f in trace["flow_filters"]:
        path = next(p for p in truth["files"] if Path(p).name == f["file"])
        assert len(filter_frames(tshark, path, f["display_filter"])) == 80
    translated = next(f["display_filter"] for f in trace["flow_filters"] if "egress" in f["file"])
    assert "198.51.100.10" in translated and "10.0.0.10" not in translated


@pytest.mark.slow
def test_dns_and_icmp_content_filters_use_identifiers(scenarios, tshark):
    project, truth, _, report = scenarios("realistic_capture_miss", ip_id="zero", rounds=20)
    refs = [e for f in event_page(project, "p2", "p3", "forward")["items"] for e in f["evidence"]]
    expressions = [
        e
        for e in refs
        if "dns.id" in (e["content_filter"] or "") or "icmp.seq" in (e["content_filter"] or "")
    ]
    assert any("dns.id" in e["content_filter"] for e in expressions)
    assert any("icmp.seq" in e["content_filter"] for e in expressions)
    selected = {
        (
            "ipv6" if "ipv6.src" in e["content_filter"] else "ip",
            "dns" if "dns.id" in e["content_filter"] else "icmp",
        ): e
        for e in expressions
    }
    for e in selected.values():
        path = next(p for p in truth["files"] if Path(p).name == e["file"])
        assert e["frame"] in [frame for frame, _ in filter_frames(tshark, path, e["content_filter"])]


def test_flow_outcomes_include_blocked_and_unrecovered_classes(scenarios):
    project, _, _, _ = scenarios("syn_blocked", rounds=50)
    flows = flow_page(project, filter_by="handshakes")["items"]
    assert any(f["handshake_blocked"] == 1 for f in flows)
    assert all("unrecovered_loss" in f and "unknown_events" in f for f in flows)
