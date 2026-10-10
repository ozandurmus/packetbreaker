"""Contract tests: two declared proxies plus a router/link distractor, with independent legs."""

import pytest
from packetbreaker.proxy_matching import pair_requests

LOCATIONS = ["Proxy A", "Proxy B", "link"]


def messages(location):
    def row(name, flow, ip, t, xff=()):
        return dict(
            id=f"{location}:{name}",
            flow=flow,
            origin_ip=ip,
            line="GET /shared HTTP/1.1",
            host="same.example",
            xff=list(xff),
            sni="same.example",
            start=t,
            complete=t + 0.003,
            ready=True,
            kind="http",
        )

    clients = [row("a", "client-a", "10.1.0.1", 1.137), row("b", "client-b", "10.1.0.2", 1.151)]
    servers = [
        row("sb", "pooled", "172.16.0.1", 1.170, ["10.1.0.2"]),
        row("sa", "pooled", "172.16.0.1", 1.240, ["10.1.0.1"]),
    ]
    return clients, servers


def contract(engine, location):
    clients, servers = messages(location)
    found = engine(clients, servers, 2, 0, location != "link")
    matched = [p for p in found if p["status"] == "matched"]
    if location == "link":
        assert not matched
        assert all(p["reason"] for p in found)
    else:
        assert {(p["client_id"], p["server_id"]) for p in matched} == {
            (clients[0]["id"], servers[1]["id"]),
            (clients[1]["id"], servers[0]["id"]),
        }
        assert len({p["server_id"] for p in matched}) == 2


@pytest.mark.parametrize("location", LOCATIONS)
@pytest.mark.parametrize(
    "negative",
    [
        "capture_miss",
        "missing_point",
        "clock",
        "same_leg",
        "contradictory_identity",
        "ambiguous",
        "streaming",
    ],
)
def test_negative_pairing_first(location, negative):
    clients, servers = messages(location)
    uncertainty = 0
    if negative == "capture_miss":
        clients = []
    if negative == "missing_point":
        servers = []
    if negative == "clock":
        uncertainty = None
    if negative == "same_leg":
        for s in servers:
            s["flow"] = clients[0]["flow"]
        clients = clients[:1]
    if negative == "contradictory_identity":
        for s in servers:
            s["line"] = "GET /different HTTP/1.1"
    if negative == "ambiguous":
        for s in servers:
            s.update(start=1.2, complete=1.203, xff=[])
    if negative == "streaming":
        for c in clients:
            c["ready"] = False
            c["reason"] = "Request byte boundary unavailable"
    found = pair_requests(clients, servers, 2, uncertainty, location != "link")
    assert found and all(p["status"] == "unknown" and p["reason"] for p in found), found


@pytest.mark.parametrize("location", LOCATIONS)
def test_request_pooling_and_xff_beat_nearest_time(location):
    contract(pair_requests, location)


def nearest_only(clients, servers, window, uncertainty, declared):
    available = servers[:]
    found = []
    for c in clients:
        s = min(available, key=lambda s: abs(s["start"] - c["start"]))
        available.remove(s)
        found.append(dict(status="matched", client_id=c["id"], server_id=s["id"]))
    return found


@pytest.mark.parametrize("location", LOCATIONS)
def test_naive_nearest_only_is_rejected(location):
    with pytest.raises(AssertionError):
        contract(nearest_only, location)


def test_sni_only_is_explicit_tls_setup_not_an_application_request():
    clients, servers = messages("Proxy B")
    for r in [*clients, *servers]:
        r.update(line=None, host=None, xff=[], kind="tls_setup")
    found = pair_requests(clients[:1], servers[:1], 2, 0)
    assert found[0]["status"] == "matched" and found[0]["evidence_rank"] == "TLS SNI"
