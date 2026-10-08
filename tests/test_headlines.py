import pytest
from packetbreaker.analysis import analyze
from packetbreaker.headlines import time_labels


def test_headline_counts_denominators_and_both_timezones(scenarios):
    project, truth, topology, _ = scenarios("demo", ip_id="zero")
    with project.connect() as db:
        previous = project.get(db, "report")
    topology = {
        **topology,
        "nat_mappings": [
            {k: s[k] for k in ("point_a", "point_b", "tuple_a", "tuple_b")}
            for s in previous["nat_suggestions"]
        ],
        "report_timezone": "Europe/Istanbul",
    }
    report = analyze(project, topology)
    finding = next(f for f in report["findings"] if f["type"] == "impactful_loss")
    m = finding["headline_metrics"]
    assert m["lost"] == 9 and m["quickly_recovered"] == 5 and m["measured_stalls"] == 4
    assert m["loss_percent"] == pytest.approx(100 * m["lost"] / m["eligible_data_packets"])
    assert m["upstream_status"] == "none_observed"
    assert "local" in finding["headline"] and " UTC" in finding["headline"]
    assert "+03:00" in finding["time_labels"]["local"]
    assert (
        "uncertainty" in finding["headline"]
        and "No loss was observed before FW egress" in finding["headline"]
    )


def test_does_not_claim_no_upstream_loss_without_complete_evidence(scenarios):
    project, _, topology, _ = scenarios("recovered_loss", rounds=45)
    with project.connect() as db:
        cid = topology["points"][0]["capture_id"]
        db.execute(
            "UPDATE packets SET unsupported='unknown_transport' WHERE capture_id=? AND frame%4=0", [cid]
        )
    report = analyze(project, topology)
    finding = next(f for f in report["findings"] if f["type"] == "recovered_loss")
    assert "No loss was observed before" not in finding["headline"]
    assert finding["headline_metrics"]["upstream_status"] == "unknown"


def test_dst_time_conversion_uses_event_date():
    winter = time_labels(1700000000, "America/New_York")
    summer = time_labels(1719792000, "America/New_York")
    assert "-05:00" in winter["local"] and "-04:00" in summer["local"]


def test_later_reset_does_not_turn_quick_recovery_into_a_stall(scenarios):
    from packetbreaker.store import PACKET_COLUMNS, rows

    project, _, topology, _ = scenarios("recovered_loss", rounds=63)
    with project.connect() as db:
        originals = rows(db, "SELECT * FROM packets WHERE frame=1")
        for p in originals:
            p.update(
                frame=1000001,
                ts=p["ts"] + 24.5,
                seq=99999,
                ack=0,
                flags=4,
                length=0,
                prefix=None,
                payload_hash=None,
                signature="late-reset",
                frame_hash="late-reset",
            )
            db.execute(
                "INSERT INTO packets VALUES (" + ",".join("?" for _ in PACKET_COLUMNS) + ")",
                [p[k] for k in PACKET_COLUMNS],
            )
    report = analyze(project, topology)
    finding = next(f for f in report["findings"] if f["type"] == "recovered_loss")
    assert finding["headline_metrics"]["measured_stalls"] == 0
    assert finding["headline_metrics"]["max_stall_ms"] is None
