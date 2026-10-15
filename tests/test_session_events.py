"""Session-behaviour findings on a two-point L2 replica with heavy capture loss at one point.

Naive implementations these tests reject:
- "every no-socket RST storm is state loss" -> RSTs answering a late close of connections the
  server had already closed with FIN are the expected answer (the real-case pattern);
- "a segment missing at B is lost" -> the storm trigger missing at B must be a capture miss;
- "any cluster of RSTs without ACK is a storm" -> client aborts without a trigger, a single
  no-socket RST and an application RST|ACK are not storms;
- "a halved delivery rate means the sender slowed down" -> the receiver-window-limited stream
  must be classified as receiver-limited, not as a sender drop.
"""

import pytest

from packetbreaker.case_setup import create_case
from packetbreaker.session_synthetic import make_session_case


@pytest.fixture(scope="module", params=[False, True], ids=["ipv4", "ipv6"])
def session_case(request, tmp_path_factory, tshark):
    folder = tmp_path_factory.mktemp("session") / "case"
    truth = make_session_case(folder, ipv6=request.param)
    (folder / "ground-truth.json").unlink()
    project = create_case(folder, tshark=tshark)
    with project.connect() as db:
        report = project.get(db, "report")
        suggested = project.get(db, "suggested_topology")
    return project, truth, report, suggested


def _ports(report, flows):
    by_flow = {c["flow"]: c for c in report["session_events"]["connections"]}
    return sorted(int(by_flow[f]["client"].rsplit(":", 1)[1]) for f in flows)


def test_zero_input_topology(session_case):
    _, truth, _, suggested = session_case
    assert suggested["status"] == "ready"
    assert suggested["topology"]["forward"] == ["client_side", "server_side"]
    assert suggested["topology"]["client_cidrs"] == [
        truth["client"] + ("/128" if ":" in truth["client"] else "/32")
    ]


def test_reset_storms_match_ground_truth(session_case):
    project, truth, report, _ = session_case
    storms = [s for s in report["session_events"]["storms"] if s["kind"] == "state_loss"]
    assert len(storms) == len(truth["storms"])
    for storm, expected in zip(storms, truth["storms"]):
        assert storm["side"] == "server"
        assert abs(storm["time"] - expected["time"]) < 0.01
        assert _ports(report, storm["flows"]) == sorted(expected["ports"])
        assert storm["rst_ttl"] == storm["normal_ttl"]
        assert storm["silence_before_s"]["min"] > 25
    findings = [f for f in report["findings"] if f["type"] == "reset_storm"]
    assert len(findings) == 2 and all(f["severity"] == "high" for f in findings)
    assert all(f["evidence"] and "state loss" in f["summary"] for f in findings)
    assert findings[0] is report["findings"][0]


def test_late_close_is_not_state_loss(session_case):
    _, truth, report, _ = session_case
    late = [s for s in report["session_events"]["storms"] if s["kind"] == "late_close"]
    assert len(late) == 1
    assert abs(late[0]["time"] - truth["late_close"]["time"]) < 0.01
    assert _ports(report, late[0]["flows"]) == sorted(truth["late_close"]["ports"])
    assert (
        18
        < late[0]["closed_by_resetting_side_before_s"]["min"]
        <= late[0]["closed_by_resetting_side_before_s"]["max"]
        < 27
    )
    finding = [f for f in report["findings"] if f["type"] == "late_close_resets"]
    assert len(finding) == 1 and finding[0]["severity"] == "low"
    assert "not state loss" in finding[0]["summary"]
    assert "state loss" not in report["verdict"].split("late at")[-1]
    assert "closed server-closed connections late" in report["verdict"]


def test_reset_distractors_are_not_storms(session_case):
    _, truth, report, _ = session_case
    storm_ports = {p for s in report["session_events"]["storms"] for p in _ports(report, s["flows"])}
    d = truth["distractors"]
    excluded = {d["single_no_socket_rst"]["port"], d["application_abort"]["port"], d["server_fin"]["port"]}
    excluded |= set(d["client_abort_cluster"]["ports"])
    assert not storm_ports & excluded
    assert all(
        abs(s["time"] - d["client_abort_cluster"]["time"]) > 1 for s in report["session_events"]["storms"]
    )


def test_storm_trigger_missing_at_b_is_capture_miss(session_case):
    project, truth, report, _ = session_case
    forward = next(s for s in report["segments"] if s["id"].startswith("forward:"))
    assert not {"impactful_loss", "unrecovered_loss", "recovered_loss"} & set(forward["classes"])
    trigger = truth["capture_miss_trigger"]
    with project.connect() as db:
        kind, reason = db.execute(
            """SELECT e.kind,e.reason FROM events e JOIN obs o ON o.packet_key=e.packet_key
            WHERE o.sport=? AND abs(o.ts-?)<0.001 AND e.direction='forward'""",
            [trigger["port"], trigger["time"]],
        ).fetchone()
    assert kind == "capture_miss" and "no-socket RST" in reason
    assert not report["verdict"].startswith("Impactful loss")


def test_client_close_and_reconnect(session_case):
    _, truth, report, _ = session_case
    found = [f for f in report["findings"] if f["type"] == "stream_reconnect"]
    assert len(found) == 1
    m = found[0]["metrics"]
    assert m["closed_by"] == "client" and m["close_kind"] == "fin" and m["tls_close_like"]
    assert abs(m["reconnect_after_s"] - truth["reconnect"]["gap_s"]) < 0.1
    assert m["client"].endswith(f":{truth['reconnect']['old_port']}")


def test_sender_drop_vs_receiver_limited(session_case):
    _, truth, report, _ = session_case
    drops = report["session_events"]["rate_drops"]
    by_port = {}
    for d in drops:
        conn = next(c for c in report["session_events"]["connections"] if c["flow"] == d["flow"])
        by_port.setdefault(int(conn["client"].rsplit(":", 1)[1]), []).append(d)
    sender = by_port[truth["sender_drop"]["port"]]
    assert [d["cause"] for d in sender] == ["sender"]
    assert abs(sender[0]["start"] - truth["sender_drop"]["start"]) <= 10
    assert abs(sender[0]["end"] - truth["sender_drop"]["end"]) <= 10
    assert 35 <= sender[0]["drop_percent"] <= 65 and sender[0]["losses"] == 0
    limited = by_port[truth["distractors"]["receiver_limited"]["port"]]
    assert [d["cause"] for d in limited] == ["receiver_window"]
    kinds = {f["type"] for f in report["findings"]}
    assert {"sender_rate_drop", "receiver_rate_drop"} <= kinds


def test_verdict_leads_with_session_timeline(session_case):
    _, _, report, _ = session_case
    verdict = report["verdict"]
    assert verdict.startswith("Session events (no network path degradation)")
    assert "state loss" in verdict and "reconnected after 13.6 s" in verdict
    assert "server reduced its sending rate" in verdict
    assert not any(
        f["type"] == "reset_origin"
        and f["confidence"] == "unknown"
        and any(abs(f["time_range"][0] - s["time"]) < 0.01 for s in report["session_events"]["storms"])
        for f in report["findings"]
    )
