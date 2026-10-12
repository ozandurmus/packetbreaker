import sys
from types import ModuleType
from packetbreaker.store import cache_missing_pandas


def test_existing_pandas_is_never_replaced(monkeypatch):
    present = ModuleType("pandas")
    monkeypatch.setitem(sys.modules, "pandas", present)
    cache_missing_pandas()
    assert sys.modules["pandas"] is present


def test_absent_optional_import_is_not_repeated_per_sql_parameter(monkeypatch):
    import duckdb
    import importlib.util

    monkeypatch.delitem(sys.modules, "pandas", raising=False)
    original = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda name: None if name == "pandas" else original(name)
    )
    cache_missing_pandas()
    calls = []

    class Probe:
        def find_spec(self, name, path=None, target=None):
            if name == "pandas":
                calls.append(name)

    probe = Probe()
    sys.meta_path.insert(0, probe)
    try:
        with duckdb.connect() as db:
            for n in range(20):
                assert db.execute("SELECT ?::VARCHAR,?::BIGINT", [str(n), n]).fetchone() == (str(n), n)
        assert calls == []
    finally:
        sys.meta_path.remove(probe)
