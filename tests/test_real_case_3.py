from pathlib import Path
from types import SimpleNamespace
import pytest
from packetbreaker.store import Project, memory_budget_mb


def test_adaptive_budget_and_overrides(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "packetbreaker.store.psutil.virtual_memory", lambda: SimpleNamespace(total=2 * 1024**3)
    )
    assert memory_budget_mb() == 1024
    monkeypatch.setattr(
        "packetbreaker.store.psutil.virtual_memory", lambda: SimpleNamespace(total=16 * 1024**3)
    )
    assert memory_budget_mb() == 4096
    monkeypatch.setattr(
        "packetbreaker.store.psutil.virtual_memory", lambda: SimpleNamespace(total=128 * 1024**3)
    )
    assert memory_budget_mb() == 8192
    with pytest.raises(ValueError):
        memory_budget_mb(-1)
    p = Project(tmp_path / "p")
    with p.connect() as db:
        p.set(db, "preferences", {"memory_limit_mb": 512})
    with p.connect() as db:
        assert db.execute("SELECT current_setting('memory_limit')").fetchone()[0] == "512.0 MiB"
    p.memory_limit_mb = 768
    with p.connect() as db:
        assert db.execute("SELECT current_setting('memory_limit')").fetchone()[0] == "768.0 MiB"


def test_state_ctas_resets_only_selected_point_and_preserves_metadata(tmp_path):
    from packetbreaker.application_index import apply_tcp_analysis

    p = Project(tmp_path / "p", memory_limit_mb=512)
    with p.connect() as db:
        db.execute(
            "CREATE TABLE obs(point VARCHAR,frame BIGINT,retrans BOOLEAN,fast_retrans BOOLEAN,spurious BOOLEAN,out_of_order BOOLEAN,zero_window BOOLEAN,rtt DOUBLE,path_fields VARCHAR)"
        )
        db.execute(
            "INSERT INTO obs VALUES ('a',1,true,true,true,true,true,9,'{\"ttl\":64,\"bytes_in_flight\":900}'),('a',2,true,true,true,true,true,9,'{}'),('b',1,true,true,true,true,true,9,'{}')"
        )
        db.execute("CREATE TABLE tcp_point_analysis(point VARCHAR,frame BIGINT,metadata VARCHAR)")
        db.execute(
            'INSERT INTO tcp_point_analysis VALUES (\'a\',1,\'{"retrans":false,"rtt":0.1,"bytes_in_flight":100}\')'
        )
        apply_tcp_analysis(db, "a")
        assert db.execute(
            "SELECT retrans,rtt,json_extract(path_fields,'$.ttl'),json_extract(path_fields,'$.bytes_in_flight') FROM obs WHERE point='a' AND frame=1"
        ).fetchone() == (False, 0.1, "64", "100")
        assert db.execute("SELECT retrans,rtt FROM obs WHERE point='a' AND frame=2").fetchone() == (
            False,
            None,
        )
        assert db.execute("SELECT retrans,rtt FROM obs WHERE point='b'").fetchone() == (True, 9)


@pytest.mark.parametrize("ip_id,ipv6", [("zero", False), ("constant", True)])
def test_incident_start_still_reports_absolute_host_delay(tmp_path, tshark, ip_id, ipv6):
    from packetbreaker.pilot_synthetic import make_pilot
    from packetbreaker.synthetic import bind_capture_ids
    from packetbreaker.batch_ingest import ingest_many
    from packetbreaker.analysis import analyze

    truth, t = make_pilot(tmp_path / "wire", start_at_event=True, host_jitter_us=150, ip_id=ip_id, ipv6=ipv6)
    p = Project(tmp_path / "p", memory_limit_mb=512)
    ids = ingest_many(p, truth["files"], tshark=tshark, workers=4)
    bind_capture_ids(t, {Path(f).name: c for f, c in zip(truth["files"], ids)})
    r = analyze(p, t)
    assert r["verdict"].startswith("Delay occurs between")
    assert "no pre-event coverage" in r["verdict"]
    assert {i["direction"] for i in r["host_path"]["items"]} == {"rx", "tx"}
    assert max(i["max_ms"] for i in r["host_path"]["items"]) > 1200
    assert all(i["window"]["status"] == "unknown" for i in r["host_path"]["items"])
    assert r["findings"][0]["severity"] == "high"
    quality = next(q for q in r["quality"] if q["point"] == "host")["index_scope"]
    assert quality["excluded_frames"] == 2000 and quality["excluded_flows"] == 1000
    with p.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM tcp_point_analysis a JOIN packets p ON p.frame=a.frame AND p.capture_id=? WHERE a.point='host' AND p.src='10.99.0.1'",
                [ids[-1]],
            ).fetchone()[0]
            == 0
        )


def test_scope_keeps_shared_and_explicit_clients_but_drops_unrelated(tmp_path):
    from packetbreaker.analysis import restrict_index_scope
    from packetbreaker.topology import Topology

    p = Project(tmp_path / "p")
    with p.connect() as db:
        db.execute("CREATE TABLE obs(point VARCHAR,flow VARCHAR,direction VARCHAR,canon VARCHAR)")
        db.execute(
            "INSERT INTO obs VALUES ('a','shared','unknown','[]'),('b','shared','unknown','[]'),('a','chosen','forward','[\"TCP\",\"10.0.0.1\",123,\"10.0.0.1\",456]'),('b','noise','unknown','[]')"
        )
        db.execute(
            "CREATE TABLE analysis_scope(point VARCHAR,input_frames BIGINT,retained_frames BIGINT,excluded_single_point_frames BIGINT,excluded_single_point_flows BIGINT)"
        )
        db.execute("INSERT INTO analysis_scope VALUES ('a',2,2,0,0),('b',2,2,0,0)")
        restrict_index_scope(db, Topology(client_cidrs=["10.0.0.1/32"]))
        assert db.execute("SELECT flow FROM obs ORDER BY flow").fetchall() == [
            ("chosen",),
            ("shared",),
            ("shared",),
        ]
        assert db.execute(
            "SELECT input_flows-retained_flows,input_frames-retained_frames FROM index_scope WHERE point='b'"
        ).fetchone() == (1, 1)
