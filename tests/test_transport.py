import subprocess
import sys


def test_testclient_uses_supported_transport_without_suppression():
    result = subprocess.run(
        [
            sys.executable,
            "-W",
            "error",
            "-c",
            """
import httpx2
import starlette.testclient
from fastapi import FastAPI
from fastapi.testclient import TestClient
assert starlette.testclient.httpx is httpx2
app=FastAPI()
app.add_api_route('/',lambda:{'ok':True})
with TestClient(app) as client:
    assert client.get('/').json()=={'ok':True}
""",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert not result.stderr
