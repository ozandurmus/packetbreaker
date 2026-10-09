from packetbreaker.analysis import event_page


def test_gso_gro_wrap_loss_and_capture_miss_are_not_multiplied(scenarios):
    project, truth, _, report = scenarios("offload")
    classes = {f["type"]: f for f in report["findings"]}
    assert set(classes) == {"impactful_loss", "capture_miss"}
    assert all(f["metrics"]["count"] == 1 and f["hop"] == "forward:p1:p2" for f in classes.values())
    assert classes["impactful_loss"]["metrics"]["missing_bytes"] == truth["mss"]
    assert all(
        s["classes"].get("impactful_loss", 0) == 0 for s in report["segments"] if s["id"] != "forward:p1:p2"
    )
    assert {p["point"] for p in report["offload_points"] if p["large_frames"]} == {"p0", "p3"}
    assert all("checksum" in p["note"] for p in report["offload_points"])
    events = event_page(project, "p1", "p2", "forward")["items"]
    lost = next(e for e in events if e["kind"] == "impactful_loss")
    assert sum(r["bytes"] for r in lost["byte_ranges"]) == truth["mss"]
    assert lost["evidence"] and all(e["frame"] > 0 for e in lost["evidence"])
    with project.connect() as db:
        assert db.execute("SELECT count(*) FROM flow_summary").fetchone()[0] == 1
        assert db.execute("SELECT bytes FROM flow_summary").fetchone()[0] == truth["data_bytes"]
        assert db.execute("SELECT max(length) FROM packets").fetchone()[0] == 64000
        assert db.execute("SELECT count(*) FROM obs WHERE NOT eligible").fetchone()[0] == 0


def test_partial_byte_delivery_is_unknown_not_whole_frame_network_loss():
    import duckdb
    from packetbreaker.byte_ranges import range_later_seen

    with duckdb.connect() as db:
        db.execute("CREATE TABLE missing(packet_key VARCHAR,later_seen BOOLEAN,range_unknown VARCHAR)")
        db.execute("INSERT INTO missing VALUES ('source',false,NULL)")
        db.execute(
            "CREATE TABLE byte_missing_atoms(source_packet_key VARCHAR,packet_key VARCHAR,point_a VARCHAR,point_b VARCHAR,direction VARCHAR)"
        )
        db.execute(
            "INSERT INTO byte_missing_atoms VALUES ('source','one','a','b','forward'),('source','two','a','b','forward')"
        )
        db.execute("CREATE TABLE byte_obs(packet_key VARCHAR,is_atom BOOLEAN,eligible BOOLEAN,point VARCHAR)")
        db.execute("INSERT INTO byte_obs VALUES ('one',true,true,'c')")
        range_later_seen(db, "a", "b", "forward", ["c"])
        seen, reason = db.execute("SELECT later_seen,range_unknown FROM missing").fetchone()
        assert not seen and "Mixed byte-range" in reason
        db.execute("INSERT INTO byte_obs VALUES ('two',true,true,'c')")
        range_later_seen(db, "a", "b", "forward", ["c"])
        assert db.execute("SELECT later_seen,range_unknown FROM missing").fetchone() == (True, None)
