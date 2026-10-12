from functools import lru_cache
import pytest
from packetbreaker.transport import profiles
from packetbreaker.dns import dns_page
from packetbreaker.stream_charts import charts

MODES = [("zero", False), ("constant", False), ("zero", True), ("constant", True)]


@pytest.fixture(scope="session")
def diagnostic_wire(scenarios):
    @lru_cache(None)
    def get(mode):
        project, truth, topology, report = scenarios("diagnostics", ip_id=mode[0], ipv6=mode[1])
        ports = {}
        with project.connect() as db:
            for case, expected in truth["cases"].items():
                fid = db.execute("SELECT min(flow) FROM obs WHERE sport=?", [expected["port"]]).fetchone()[0]
                ports[case] = fid
        return project, truth, topology, report, ports

    return get


@pytest.mark.parametrize("mode", MODES)
def test_wire_negative_first_and_naive_rules(diagnostic_wire, mode):
    p, truth, _, _, flows = diagnostic_wire(mode)
    for case in ("idle_zero", "high_rtt_ack_delay", "missing_handshake", "healthy", "capture_miss"):
        result = profiles(p, flows[case])
        assert all(d["classification"] == "unknown" for d in result["items"]), (case, result)
        assert not result["retransmissions"]["reordering"], case
        assert all(d["metrics"]["loss_count"] == 0 for d in result["items"]), case
    idle = profiles(p, flows["idle_zero"])["items"][0]
    assert idle["metrics"]["zero_windows"] >= 2
    # A zero-window-only mutant falsely diagnoses this idle, fully acknowledged stream.
    naive = "receiver-limited" if idle["metrics"]["zero_windows"] else "unknown"
    assert naive != idle["classification"]
    with p.connect() as db:
        misses = db.execute(
            "SELECT count(*) FROM events WHERE flow=? AND kind='capture_miss'", [flows["capture_miss"]]
        ).fetchone()[0]
    assert misses > 0


@pytest.mark.parametrize("mode", MODES)
def test_wire_limitation_exact_flow_direction_and_evidence(diagnostic_wire, mode):
    p, truth, _, _, flows = diagnostic_wire(mode)
    expected = {
        "receiver": ("forward", "receiver-limited"),
        "slow_server": ("reverse", "sender/application-limited"),
        "paced_sender": ("forward", "sender/application-limited"),
    }
    expected.update(
        {f"loss_{loc}": ("forward", "network-limited (loss/RTT)") for loc in ("FW", "LB", "link")}
    )
    for case, (direction, classification) in expected.items():
        result = profiles(p, flows[case])
        observed = next(d for d in result["items"] if d["direction"] == direction)
        assert observed["classification"] == classification, (case, observed)
        assert observed["evidence"] and all(
            e["frame"] > 0 and e["content_filter"] for e in observed["evidence"]
        )
        if case == "slow_server":
            assert observed["metrics"]["service_ms"] == pytest.approx(
                truth["cases"][case]["service_ms"], abs=0.001
            )
        if case.startswith("loss_"):
            assert observed["metrics"]["loss_count"] == 3
            hop = {
                "FW": "forward:fw_in:fw_out",
                "LB": "forward:lb_in:lb_out",
                "link": "forward:fw_out:lb_in",
            }[truth["cases"][case]["location"]]
            assert observed["hop"] == hop
    window = charts(p, flows["receiver"], point="client")
    assert any(q["receive_window"] == 0 for q in window["packets"])


@pytest.mark.parametrize("mode", MODES)
def test_wire_reorder_and_recovery_exact_attribution(diagnostic_wire, mode):
    p, truth, _, _, flows = diagnostic_wire(mode)
    for location in ("FW", "LB", "link"):
        result = profiles(p, flows["reorder_" + location])["retransmissions"]["reordering"]
        assert len(result) == 1, result
        r = result[0]
        assert r["device"] == (location if location != "link" else None)
        assert (
            r["hop"]
            == {"FW": "forward:fw_in:fw_out", "LB": "forward:lb_in:lb_out", "link": "forward:fw_out:lb_in"}[
                location
            ]
        )
        assert len(r["evidence"]) == 4 and r["confidence"] == "supported"
    for case, kind, count in [
        ("loss_FW", "rto", 3),
        ("fast_recovery", "fast", 1),
        ("sack_recovery", "sack", 1),
        ("spurious", "spurious", 1),
    ]:
        result = profiles(p, flows[case])["retransmissions"]
        events = [e for e in result["events"] if e["point"] == "client"]
        assert len([e for e in events if e["retry_kind"] == kind]) == count, (case, events)
        assert all(e["evidence"] for e in events)
        assert any(row["hop"] == "forward:client:fw_in" for row in result["segments"])


@pytest.mark.parametrize("mode", MODES)
def test_wire_dns_timeout_vs_response_disappearance(diagnostic_wire, mode):
    p, truth, _, _, _ = diagnostic_wire(mode)
    data = dns_page(p, point="client")
    byport = {q["sport"]: q for q in data["items"]}
    for expected in truth["dns"]:
        q = byport[expected["port"]]
        assert q["evidence"] and q["tooltip"]
        if expected["mode"] == "timeout":
            assert q["status"] == "resolver_timeout" and q["hop"] is None and q["device"] is None
        elif expected["mode"] == "response_loss":
            assert q["status"] == "response_disappeared", q
            assert q["device"] == (expected["location"] if expected["location"] != "link" else None)
            assert (
                q["hop"]
                == {
                    "FW": "reverse:fw_out:fw_in",
                    "LB": "reverse:lb_out:lb_in",
                    "link": "reverse:lb_in:fw_out",
                }[expected["location"]]
            )
        else:
            assert q["status"] == "answered" and q["latency_ms"] == pytest.approx(50, abs=0.001)
    assert sum(s["timed_out_queries"] for s in data["summary"]) == 6


def test_missing_clock_endpoint_and_deadline_stay_unknown(diagnostic_wire, clone_project):
    from copy import deepcopy

    source, _, topology, report, flows = diagnostic_wire(("zero", False))
    p = clone_project(source)
    with p.connect() as db:
        changed = deepcopy(report)
        changed["generated_at"] += "-no-clock"
        for value in changed["clocks"].values():
            value["offset"] = None
        for segment in changed["segments"]:
            segment["loss_percent"] = None
        p.set(db, "report", changed)
        db.execute("UPDATE obs SET corrected=NULL")
    assert all(d["classification"] == "unknown" for d in profiles(p, flows["loss_FW"])["items"])
    assert all(q["status"] != "resolver_timeout" for q in dns_page(p, point="client")["items"])
    local = charts(p, flows["healthy"], point="client")
    assert local["aligned"] is False and local["packets"]
    p = clone_project(source)
    with p.connect() as db:
        changed = deepcopy(report)
        changed["generated_at"] += "-no-endpoint"
        modified = deepcopy(topology)
        for point in modified["points"]:
            if point["kind"] == "Server":
                point["kind"] = "Generic"
        p.set(db, "topology", modified)
        p.set(db, "report", changed)
    assert all(d["classification"] == "unknown" for d in profiles(p, flows["receiver"])["items"])
    assert all(q["status"] != "resolver_timeout" for q in dns_page(p, point="client")["items"])
    p = clone_project(source)
    with p.connect() as db:
        changed = deepcopy(report)
        changed["generated_at"] += "-coverage-short"
        p.set(db, "report", changed)
        db.execute("DELETE FROM obs WHERE ts>1700000002.8")
    unanswered = [q for q in dns_page(p, point="client")["items"] if q["response_frame"] is None]
    assert unanswered and all(q["status"] == "unknown" and q["timeout_observed"] is None for q in unanswered)
