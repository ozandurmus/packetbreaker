def test_sequence_offsets_wrap_and_post_device_loss(scenarios):
    project, truth, topology, report = scenarios("sequence_randomization", ip_id="zero", ipv6=True)
    learned = report["sequence_translations"]
    assert len(learned) == 2 and all(m["status"] == "learned" for m in learned)
    expected = {(v["forward"], v["reverse"]) for v in truth["sequence_offsets"].values()}
    assert {(m["boundary_forward_offset"], m["boundary_reverse_offset"]) for m in learned} == expected
    assert sum(f["metrics"]["count"] for f in report["findings"] if f["type"] == "recovered_loss") == len(
        truth["events"]
    )
    assert {f["hop"] for f in report["findings"]} == {"forward:p2:p3"}
    refs = [e for f in report["findings"] for e in f["evidence"] if e.get("sequence_translation")]
    assert refs and all(
        f"tcp.seq_raw == {e['sequence_translation']['observed_seq']}" in e["content_filter"] for e in refs
    )
    with project.connect() as db:
        assert db.execute("SELECT count(*) FROM flow_summary").fetchone()[0] == 2
        assert not db.execute(
            "SELECT count(*) FROM obs WHERE seq<0 OR seq>=4294967296 OR ack<0 OR ack>=4294967296"
        ).fetchone()[0]


def test_inconsistent_offset_marks_only_affected_connection_unknown(scenarios):
    project, truth, topology, report = scenarios("sequence_inconsistent", ip_id="constant")
    models = report["sequence_translations"]
    assert {m["status"] for m in models} == {"learned", "unknown"}
    assert "Inconsistent" in next(m["reason"] for m in models if m["status"] == "unknown")
    with project.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM flow_summary WHERE matching_unknown_reason IS NOT NULL"
            ).fetchone()[0]
            == 1
        )
    assert (
        sum(f["metrics"]["count"] for f in report["findings"] if f["type"] == "recovered_loss")
        == len(truth["events"]) // 2
    )
    assert all("Unsupported translation" not in (s["reason"] or "") for s in report["segments"])
