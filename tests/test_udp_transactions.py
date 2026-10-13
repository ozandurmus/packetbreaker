import pytest


@pytest.mark.parametrize("fault_location", ["FW1", "FW2", "link"])
@pytest.mark.parametrize("ip_id,ipv6", [("zero", False), ("constant", False), ("zero", True)])
def test_udp_identity_ambiguity_capture_miss_and_oneway_first(scenarios, fault_location, ip_id, ipv6):
    project, truth, _, report = scenarios(
        "udp_transactions", fault_location=fault_location, ip_id=ip_id, ipv6=ipv6
    )
    with project.connect() as db:
        rows = db.execute(
            "SELECT protocol,status,latency_ms,hop FROM udp_transactions WHERE point='client' ORDER BY ts"
        ).fetchall()
    assert [r[1] for r in rows[:7]] == [
        "answered",
        "answered",
        "answered",
        "no_response_expected",
        "answered",
        "unknown",
        "unknown",
    ]
    assert [r[0] for r in rows[:4]] == ["NTP", "SNMP", "RADIUS", "SYSLOG"]
    assert rows[0][2] == pytest.approx(47.1, abs=0.01)
    assert rows[1][2] == pytest.approx(73.1, abs=0.01)
    assert rows[7][1] == "answered" and rows[7][3] is None  # intermediate capture miss, not network loss
    assert rows[8][1] == "unanswered" and rows[8][3] == truth["expected_response_hop"]
    assert rows[9][1] == "answered" and rows[9][3] is None
    assert report["udp"]["items"] and all(i["evidence"] and i["tooltip"] for i in report["udp"]["items"])


def test_udp_incomplete_response_drop_inventory_and_selected_window_are_unknown(scenarios, clone_project):
    from packetbreaker.udp import build_udp
    from packetbreaker.topology import Topology
    import json

    shared, _, topology, report = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    clone = clone_project(shared)
    with clone.connect() as db:
        db.execute("UPDATE obs SET caplen=wirelen-1 WHERE point='client' AND sport=123 AND dport=41000")
        udp = build_udp(db, Topology.model_validate(topology), report["segments"])
        assert (
            next(i for i in udp["items"] if i["point"] == "client" and i["protocol"] == "NTP")["status"]
            == "unknown"
        )
        inventory = json.loads(db.execute("SELECT inventory FROM captures LIMIT 1").fetchone()[0])
        inventory["ifdrop"] = 5
        db.execute("UPDATE captures SET inventory=?", [json.dumps(inventory)])
        udp = build_udp(db, Topology.model_validate(topology), report["segments"])
        assert not any(i["status"] == "unanswered" for i in udp["items"])
        narrowed = Topology.model_validate({**topology, "start": 1700000010.0, "end": 1700000012.0})
        build_udp(db, narrowed, report["segments"])
        assert db.execute(
            "SELECT min(corrected),max(corrected) FROM udp_transactions"
        ).fetchone() == pytest.approx((1700000010.0, 1700000012.0), abs=0.01)


def test_snmp_context_mismatch_cannot_answer_another_community(scenarios, clone_project):
    from packetbreaker.udp import build_udp
    from packetbreaker.topology import Topology

    shared, _, topology, report = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    clone = clone_project(shared)
    with clone.connect() as db:
        db.execute(
            "UPDATE udp_decoded SET \"snmp.community\"='other' WHERE point='client' AND \"snmp.data\"='2'"
        )
        build_udp(db, Topology.model_validate(topology), report["segments"])
        assert (
            db.execute(
                "SELECT status FROM udp_transactions WHERE point='client' AND protocol='SNMP'"
            ).fetchone()[0]
            != "answered"
        )


def test_batched_udp_headers_equal_isolated_tshark_fields(scenarios, clone_project, monkeypatch):
    from packetbreaker import udp_index
    from packetbreaker.topology import Topology

    shared, _, topology, _ = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    clone = clone_project(shared)
    calls = []
    running = udp_index.running

    def counted(*args, **kwargs):
        calls.append(args[0])
        return running(*args, **kwargs)

    monkeypatch.setattr(udp_index, "running", counted)
    fields = ",".join('"' + f + '"' for f in udp_index.FIELDS if f != "frame.number")
    with clone.connect() as db:
        db.execute("DELETE FROM udp_decode_cache")
        statuses = udp_index.index_udp(clone, db, Topology.model_validate(topology), batch_headers=True)
        assert all(s["reason"] is None for s in statuses)
        batch = db.execute(
            "SELECT point,frame," + fields + " FROM udp_decoded ORDER BY point,frame"
        ).fetchall()
        assert len(calls) == 1
        calls.clear()
        statuses = udp_index.index_udp(clone, db, Topology.model_validate(topology), batch_headers=False)
        assert all(s["reason"] is None for s in statuses)
        isolated = db.execute(
            "SELECT point,frame," + fields + " FROM udp_decoded ORDER BY point,frame"
        ).fetchall()
        assert len(calls) == 16 and batch == isolated
        db.execute(
            "UPDATE obs SET path_fields=json_merge_patch(path_fields, '{\"sip_probe\":\"1\"}') WHERE point='server' AND proto='TCP'"
        )

        def require_isolation(cmd, *args, **kwargs):
            assert "-w" in cmd
            raise RuntimeError("TCP SIP isolation requested")

        monkeypatch.setattr(udp_index, "running", require_isolation)
        with pytest.raises(RuntimeError, match="TCP SIP isolation requested"):
            udp_index.index_udp(clone, db, Topology.model_validate(topology), batch_headers=True)
