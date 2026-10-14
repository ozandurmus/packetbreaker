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


