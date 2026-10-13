def test_ack_guard_preserves_original_delivery_and_isolates_flows():
    import duckdb
    from packetbreaker.byte_ranges import range_ack_guard

    with duckdb.connect() as db:
        db.execute("CREATE TABLE acked(packet_key VARCHAR,ack_key VARCHAR)")
        db.execute(
            "CREATE TABLE byte_missing_atoms(point_a VARCHAR,point_b VARCHAR,source_packet_key VARCHAR,base_key VARCHAR,flow VARCHAR,corrected DOUBLE)"
        )
        db.execute("CREATE TABLE obs(point VARCHAR,packet_key VARCHAR,flow VARCHAR,corrected DOUBLE)")
        db.execute(
            "CREATE TABLE byte_obs(point VARCHAR,base_key VARCHAR,flow VARCHAR,is_atom BOOLEAN,eligible BOOLEAN,corrected DOUBLE)"
        )
        for n in range(3):
            db.execute("INSERT INTO acked VALUES (?,?)", [f"p{n}", f"a{n}"])
            db.execute(
                "INSERT INTO byte_missing_atoms VALUES ('fw','lb',?,'same-seq',?,0)", [f"p{n}", f"f{n}"]
            )
            db.execute("INSERT INTO obs VALUES ('fw',?,?,?)", [f"a{n}", f"f{n}", 0.1 if n == 1 else 0.4])
        db.execute("INSERT INTO byte_obs VALUES ('fw','same-seq','f0',true,true,.2)")
        range_ack_guard(db, "fw", "lb")
        assert db.execute("SELECT packet_key FROM acked ORDER BY packet_key").fetchall() == [("p1",), ("p2",)]
