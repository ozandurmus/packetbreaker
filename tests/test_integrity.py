import pytest

from packetbreaker.integrity import endpoint_pattern


def test_origin_patterns_are_not_authentication():
    packet = dict(src="10.0.0.1", ttl=64, ipid=0)
    assert endpoint_pattern([packet] * 2, packet)["status"] == "unknown"
    result = endpoint_pattern([packet] * 3, packet)
    assert result["ip_id_pattern"] == "constant"
    assert "cannot authenticate" in result["ip_id_note"]
    assert endpoint_pattern([packet] * 3, {**packet, "src": "2001:db8::1"})["candidate_ip_id"] is None


def test_integrity_ground_truth_devices_evidence_and_exports(scenarios):
    from packetbreaker.export import export_data, html_report

    project, truth, _, report = scenarios("integrity_all")
    for expected in truth["findings"]:
        found = [
            f for f in report["findings"] if f["type"] == expected["type"] and f["severity"] != "quality"
        ]
        assert found, (expected, [(f["type"], f["summary"]) for f in report["findings"]])
        assert all(f["device"] == "Firewall" and f["confidence"] == "supported" for f in found), found
        assert all(f["tooltip"] and all(e["content_filter"] for e in f["evidence"]) for f in found)
    modified = next(f for f in report["findings"] if f["type"] == "payload_modified")
    with project.connect() as db:
        ref = modified["evidence"][0]
        key = db.execute(
            "SELECT packet_key FROM obs WHERE point=? AND frame=?", [ref["point"], ref["frame"]]
        ).fetchone()[0]
        assert (
            db.execute(
                "SELECT count(*) FROM events WHERE packet_key=? AND kind IN ('impactful_loss','unrecovered_loss','recovered_loss')",
                [key],
            ).fetchone()[0]
            == 0
        )
    data = export_data(project)
    assert data["schema_version"] == 3 and data["report"]["field_diffs"]["items"]
    assert "Payload changed across Firewall" in html_report(data)


def test_asymmetric_ground_truth(scenarios):
    _, _, _, report = scenarios("integrity_asymmetric_return")
    found = [f for f in report["findings"] if f["type"] == "asymmetric_routing"]
    assert found and any("Firewall" in f["summary"] for f in found)
    assert all(f["evidence"] for f in found)


def test_integrity_capture_miss_never_injection(scenarios):
    _, _, _, report = scenarios("integrity_capture_miss")
    assert not any(
        f["type"] in ("reset_origin", "payload_modified", "mtu_black_hole", "downstream_packet")
        for f in report["findings"]
    )


def test_declared_alg_and_unknown_clock_do_not_claim_modification(scenarios):
    from packetbreaker.analysis import analyze
    from copy import deepcopy

    project, _, topology, _ = scenarios("integrity_all")
    declared = deepcopy(topology)
    for point in declared["points"]:
        if point["device"] == "Firewall":
            point["payload_transform"] = "alg"
    report = analyze(project, declared)
    assert not any(f["type"] == "payload_modified" for f in report["findings"])
    uncertain = deepcopy(topology)
    uncertain["clock_overrides"] = {p["capture_id"]: dict(offset_ms=0) for p in topology["points"]}
    report = analyze(project, uncertain)
    assert not any(
        f["type"] in ("reset_origin", "payload_modified", "mtu_black_hole")
        and f["confidence"] == "supported"
        and f["severity"] != "quality"
        for f in report["findings"]
    )
    # Restore the shared fixture's saved report for other tests.
    analyze(project, topology)


@pytest.mark.parametrize("ip_id,ipv6", [("zero", False), ("constant", True)])
def test_integrity_zero_id_and_ipv6(scenarios, ip_id, ipv6):
    _, truth, _, report = scenarios("integrity_all", ip_id=ip_id, ipv6=ipv6)
    for expected in truth["findings"]:
        assert any(
            f["type"] == expected["type"] and f["device"] == "Firewall" and f["confidence"] == "supported"
            for f in report["findings"]
        ), expected


def test_long_repeat_stream_uses_adjacent_evidence():
    import duckdb
    from packetbreaker.integrity import duplicate_pairs

    db = duckdb.connect()
    try:
        db.execute("""CREATE TABLE obs AS SELECT 'p' AS point,i AS frame,'flow' AS canon,
            'signature' AS signature,'payload' AS payload_hash,'bytes'||(i//10000)::VARCHAR AS frame_hash,
            1700000000.0+i*.0002 AS ts,64-(i//10000)::INTEGER AS ttl,true AS eligible,
            'TCP' AS proto,80 AS length,134 AS caplen,134 AS wirelen FROM range(1,20001) t(i)""")
        db.execute("CREATE VIEW integrity_obs AS SELECT * FROM obs")
        identical = duplicate_pairs(db, "p", 20, "identical")[0]
        assert (identical["first_packet"]["frame"], identical["repeat_packet"]["frame"]) == (1, 2)
        loop = duplicate_pairs(db, "p", 20, "loop")[0]
        assert (loop["first_packet"]["frame"], loop["repeat_packet"]["frame"]) == (9999, 10000)
        assert not duplicate_pairs(db, "p", 500, "identical")
    finally:
        db.close()
