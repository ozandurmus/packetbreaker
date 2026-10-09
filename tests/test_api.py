import time

from fastapi.testclient import TestClient

from packetbreaker.app import create_app
from packetbreaker.synthetic import generate

HEADERS = {"X-PacketBreaker": "local"}


def test_local_security_and_project_roundtrip(tmp_path):
    app = create_app(tmp_path / "project")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/api/state").status_code == 200
        assert client.get("/api/state", headers={"Host": "evil.example"}).status_code == 403
        assert client.get("/api/state", headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.post("/api/project", json={"path": str(tmp_path / "other")}).status_code == 403
        assert (
            client.post(
                "/api/project",
                headers={**HEADERS, "Origin": "http://evil.example"},
                json={"path": str(tmp_path / "other")},
            ).status_code
            == 403
        )
        r = client.post("/api/project", headers=HEADERS, json={"path": str(tmp_path / "other")})
        assert r.status_code == 200
        assert client.get("/api/state").json()["project"] == str((tmp_path / "other").resolve())
        assert "connect-src 'self'" in client.get("/").headers["content-security-policy"]


def test_api_ingest_analysis_report(tmp_path):
    truth, topology = generate(tmp_path / "input", scenario="capture_miss", rounds=20)
    with TestClient(create_app(tmp_path / "project"), base_url="http://127.0.0.1") as client:

        def wait():
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                result = client.get("/api/jobs").json()
                if not result["busy"]:
                    assert result["state"] == "done", result
                    return
                time.sleep(0.1)
            raise AssertionError("Job did not complete")

        assert (
            client.post("/api/captures/attach", headers=HEADERS, json={"paths": truth["files"]}).status_code
            == 200
        )
        wait()
        state = client.get("/api/state").json()
        lookup = {c["name"]: c["id"] for c in state["captures"]}
        for p in topology["points"]:
            p["capture_id"] = lookup[p["capture_id"]]
        saved = client.put("/api/topology", headers=HEADERS, json=topology)
        assert saved.status_code == 200, saved.text
        assert client.post("/api/analyze", headers=HEADERS, json=topology).status_code == 200
        wait()
        report = client.get("/api/report").json()
        assert report["findings"] and all(f["type"] == "capture_miss" for f in report["findings"])
        flows = client.get("/api/flows").json()
        trace = client.get("/api/flows/" + flows["items"][0]["flow"] + "/ladder").json()
        assert len(trace["items"][0]["evidence"]) == 5
        timeline = client.get("/api/flows/" + flows["items"][0]["flow"] + "/waterfall").json()
        assert {item["kind"] for item in timeline["items"]} == {"handshake", "http"}
        assert client.get("/api/flows?limit=100000").status_code == 422
        assert client.get("/api/events?a=p0&b=p1&direction=forward").json()["total"] > 0
        assert (
            client.put(
                "/api/topology", headers=HEADERS, json={**topology, "forward": ["p0", "p0"]}
            ).status_code
            == 422
        )


def test_upload_path_and_bad_settings(tmp_path):
    with TestClient(create_app(tmp_path / "project"), base_url="http://127.0.0.1") as client:
        r = client.post("/api/captures/upload?name=script.py", headers=HEADERS, content=b"bad")
        assert r.status_code == 400
        assert client.post("/api/settings", headers=HEADERS, json={"prefix_bytes": 1}).status_code == 422
        assert (
            client.post("/api/settings", headers=HEADERS, json={"tshark": "/missing/tshark"}).status_code
            == 400
        )
        assert client.post("/api/jobs/cancel", headers=HEADERS).status_code == 409
