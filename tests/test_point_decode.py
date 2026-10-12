import pytest
from packetbreaker.application_index import can_decode_source
from packetbreaker.topology import Point


def test_subset_or_damaged_capture_still_requires_isolation():
    point = Point(id="a", label="a", device="FW", capture_id="capture")
    inventory = dict(packet_count=10, records_read=10, timestamps_validated=True, interfaces=[{}])
    assert can_decode_source(point, inventory, 10)
    for change in [
        dict(interface=0),
        dict(source_cidr="10.0.0.0/8"),
        dict(vendor="checkpoint", vendor_stage="i"),
    ]:
        assert not can_decode_source(point.model_copy(update=change), inventory, 10)
    for change in [
        dict(damaged_tail=True),
        dict(frame_limit=10),
        dict(records_read=11),
        dict(interfaces=[{}, {}]),
        dict(timestamps_validated=False),
    ]:
        assert not can_decode_source(point, {**inventory, **change}, 10)
    assert not can_decode_source(point, inventory, 9)


@pytest.mark.parametrize(
    "metadata,proxy,required",
    [
        ({"transport_index": 1}, False, False),  # JSON merge removed a known-null TLS field.
        ({"tls_record_type": None}, False, False),
        ({}, False, True),  # Legacy index has no probe completeness evidence.
        ({"transport_index": 1, "tls_record_type": 22}, False, True),
        ({"transport_index": 1}, True, True),
    ],
)
def test_application_probe_completeness_never_suppresses_tls_or_proxy(metadata, proxy, required, monkeypatch):
    import duckdb
    import json
    import packetbreaker.application_index as index
    from packetbreaker.topology import Topology
    from types import SimpleNamespace

    def required_decode(*a):
        raise RuntimeError("decode required")

    monkeypatch.setattr(index, "find_tshark", required_decode)
    topology = Topology(
        points=[Point(id="a", label="a", device="proxy", capture_id="a", translation="full_proxy")]
        if proxy
        else []
    )
    with duckdb.connect() as db:
        db.execute("CREATE TABLE obs(proto VARCHAR,path_fields VARCHAR)")
        db.execute("INSERT INTO obs VALUES ('TCP',?)", [json.dumps(metadata)])
        project = SimpleNamespace(get=lambda *a: {})
        if required:
            with pytest.raises(RuntimeError, match="decode required"):
                index.index_applications(project, db, topology)
        else:
            assert index.index_applications(project, db, topology) == []


def test_no_tls_probe_discards_previous_application_generation():
    import duckdb
    from types import SimpleNamespace
    from packetbreaker.application_index import index_applications
    from packetbreaker.topology import Topology

    with duckdb.connect() as db:
        db.execute("CREATE TABLE obs(proto VARCHAR,path_fields VARCHAR)")
        db.execute("INSERT INTO obs VALUES ('TCP','{\"transport_index\":1}')")
        project = SimpleNamespace(get=lambda *a: {})
        assert index_applications(project, db, Topology()) == []
        db.execute("INSERT INTO app_protocol VALUES ('old','old',1,'tls_certificate','[]',1,'{}')")
        db.execute("INSERT INTO app_protocol_cache VALUES ('old','previous-capture',NULL)")
        db.execute("INSERT INTO tcp_point_analysis VALUES ('old',1,'{}')")
        assert index_applications(project, db, Topology()) == []
        for table in ("app_protocol", "app_protocol_cache", "tcp_point_analysis"):
            assert db.execute("SELECT count(*) FROM " + table).fetchone()[0] == 0
