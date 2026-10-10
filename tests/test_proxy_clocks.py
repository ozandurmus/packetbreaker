import duckdb
from packetbreaker.analysis import align
from packetbreaker.proxy_analysis import uncertainty
from packetbreaker.topology import Topology


def test_independent_leg_clocks_never_imply_cross_proxy_timing(monkeypatch):
    from proxy_fixtures import POINTS, LEGS

    topology = Topology.model_validate(
        dict(
            points=[
                dict(
                    id=p,
                    label=p,
                    device="Proxy A"
                    if p.startswith("a_")
                    else "Proxy B"
                    if p.startswith("b_")
                    else "Router"
                    if p.startswith("r_")
                    else p,
                    capture_id=p,
                    translation="full_proxy" if p.startswith(("a_", "b_")) else "none",
                )
                for p in POINTS
            ],
            forward=POINTS,
            reverse=POINTS[::-1],
        )
    )
    db = duckdb.connect()
    try:
        db.execute("CREATE TABLE obs(capture_id VARCHAR,ts DOUBLE,corrected DOUBLE)")
        db.execute("CREATE TABLE captures(id VARCHAR,inventory VARCHAR)")
        db.execute(
            "CREATE TABLE calibration(point VARCHAR,ts DOUBLE,packet_key VARCHAR,eligible BOOLEAN,direction VARCHAR,frame BIGINT)"
        )
        for leg, points in enumerate(LEGS):
            for hop, p in enumerate(points):
                db.execute("INSERT INTO captures VALUES (?,?)", [p, "{}"])
                for n in range(8):
                    forward = n % 2 == 0
                    ts = 1000 + n + leg * 2 + (hop * 0.001 if forward else -hop * 0.001)
                    db.execute("INSERT INTO obs VALUES (?,?,NULL)", [p, ts])
                    db.execute(
                        "INSERT INTO calibration VALUES (?,?,?,?,?,?)",
                        [p, ts, f"{leg}:{n}", True, "forward" if forward else "reverse", n + 1],
                    )
        # This is a clock-algorithm unit fixture; wire fixtures separately check real frame provenance.
        monkeypatch.setattr("packetbreaker.analysis.evidence", lambda *args, **kwargs: [])
        models = align(db, topology)
        pts = {p.id: p for p in topology.points}
        assert len({m.domain for m in models.values()}) == 3
        for leg in LEGS:
            assert len({models[p].domain for p in leg}) == 1
            assert all(models[p].offset is not None for p in leg)
            assert uncertainty(models, pts[leg[0]], pts[leg[-1]]) is not None
        assert uncertainty(models, pts["a_in"], pts["a_out"]) is None
        assert uncertainty(models, pts["b_in"], pts["b_out"]) is None
        from packetbreaker.topology import Override

        corrected = topology.model_copy(update={"clock_overrides": {"r_in": Override(offset_ms=2000)}})
        models = align(db, corrected)
        assert models["r_in"].domain == models["client"].domain
        assert models["r_in"].uncertainty is None
        assert models["r_out"].uncertainty is None
        assert models["r_out"].domain == models["client"].domain
        assert uncertainty(models, pts["a_in"], pts["a_out"]) is None
    finally:
        db.close()


def test_cross_domain_onset_order_is_unknown_but_segment_status_survives():
    from packetbreaker.clock import ClockModel
    from packetbreaker.proxy_analysis import restrict_onset_domains
    from packetbreaker.topology import Point

    points = {p: Point(id=p, label=p, device=p, capture_id=p) for p in ["a", "b"]}
    models = {p: ClockModel(domain=p) for p in points}
    onsets = dict(
        items=[
            dict(
                segment=f"forward:{p}:other",
                direction="forward",
                scope="network_segment",
                metric="loss_percent",
                time=t,
            )
            for p, t in [("a", 1), ("b", 2)]
        ],
        directions=dict(
            forward=dict(prime_suspects=["forward:a:other"], propagation_order=[1], first_time=1)
        ),
        status="detected",
        summary="First a",
    )
    restrict_onset_domains(onsets, points, models)
    assert onsets["status"] == "detected" and len(onsets["items"]) == 2
    assert onsets["directions"]["forward"]["prime_suspects"] == []
    assert onsets["directions"]["forward"]["first_time"] is None
    assert "unaligned" in onsets["summary"]
