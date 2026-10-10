import json
import socket
from urllib import request

from fastapi.testclient import TestClient

from packetbreaker.app import create_app
from packetbreaker.assistant import redact_findings
from packetbreaker.export import export_data


def test_disabled_and_no_analysis_preview(tmp_path):
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1") as client:
        assert not client.get("/api/state").json()["settings"].get("assistant_enabled", False)
        assert client.get("/api/assistant/preview").status_code == 403
        client.post("/api/settings", headers={"X-PacketBreaker": "local"}, json={"assistant_enabled": True})
        assert client.get("/api/assistant/preview").status_code == 400


def test_token_consistency_and_filter_structure():
    original = {
        "schema_name": "packetbreaker.findings",
        "schema_version": 4,
        "findings": [
            {
                "src": "192.0.2.5",
                "dst": "2001:db8::5",
                "host": "APPLIANCE:443",
                "sni": "Api.Example.test",
                "subject": "CN=appliance, O=Example",
                "summary": "192.0.2.5. 2001:DB8:0:0:0:0:0:5. API.EXAMPLE.TEST.",
                "filter": "ip.src == 192.0.2.5 && ipv6.dst == 2001:db8::5 && frame.number == 5",
                "cidr": "192.0.2.5/24",
                "peer": "::ffff:192.0.2.5",
                "url": "https://api.example.test/resource",
                "metrics": {"count": 5, "rate": 2.1},
                "192.0.2.5": "appliance",
            }
        ],
    }
    before = json.dumps(original)
    result = redact_findings(original)
    assert json.dumps(original) == before
    assert result["schema_name"] == original["schema_name"]
    f = result["findings"][0]
    assert f["filter"] == f"ip.src == {f['src']} && ipv6.dst == {f['dst']} && frame.number == 5"
    assert f["summary"] == f"{f['src']}. {f['dst']}. {f['sni']}."
    assert f["cidr"] == f["src"] + "/24"
    assert f["src"] in f and f[f["src"]] == f["host"].removesuffix(":443")
    assert f["host"].removesuffix(":443") in f["subject"]
    assert f["url"] == f"https://{f['sni']}/resource"
    assert f["metrics"] == {"count": 5, "rate": 2.1}
    assert f["peer"] not in (f["src"], f["dst"])
    for raw in ("192.0.2.5", "2001:db8", "example.test", "appliance", "::ffff"):
        assert raw not in json.dumps(result).casefold()
    assert redact_findings(original) == result


def test_enabling_and_preview_make_no_outbound_connection(scenarios, monkeypatch):
    project, _, _, _ = scenarios("recovered_loss")
    expected = export_data(project, findings_only=True)

    def prohibited(*args, **kwargs):
        raise AssertionError("Assistant placeholder attempted an outbound connection")

    with TestClient(create_app(project.path), base_url="http://127.0.0.1") as client:
        monkeypatch.setattr(socket.socket, "connect", prohibited)
        monkeypatch.setattr(socket.socket, "connect_ex", prohibited)
        monkeypatch.setattr(socket, "create_connection", prohibited)
        monkeypatch.setattr(socket, "getaddrinfo", prohibited)
        monkeypatch.setattr(request, "urlopen", prohibited)
        assert (
            client.post(
                "/api/settings", headers={"X-PacketBreaker": "local"}, json={"assistant_enabled": True}
            ).status_code
            == 200
        )
        assert client.get("/api/state").json()["settings"]["assistant_enabled"]
        response = client.get("/api/assistant/preview")
        assert response.status_code == 200, response.text
        assert response.json() == redact_findings(expected)
        assert set(response.json()) == {"schema_name", "schema_version", "engine_version", "findings"}
        assert len(response.json()["findings"]) == len(expected["findings"])
        assert (
            client.get("/api/assistant/preview", headers={"Origin": "https://evil.example"}).status_code
            == 403
        )
        assert (
            client.post(
                "/api/settings", headers={"X-PacketBreaker": "local"}, json={"assistant_enabled": False}
            ).status_code
            == 200
        )
        assert client.get("/api/assistant/preview").status_code == 403
