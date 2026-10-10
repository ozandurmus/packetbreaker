"""Exercise only the frozen executable, outside the checkout, with synthetic captures."""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="packetbreaker-binary-") as directory:
        scratch = Path(directory)
        demo = scratch / "demo"
        subprocess.run(
            [
                str(binary),
                "demo",
                str(demo),
                "--scenario",
                "recovered_loss",
                "--ip-id",
                "zero",
                "--rounds",
                "100",
            ],
            cwd=scratch,
            check=True,
            timeout=120,
        )
        report = json.loads((demo / "report.json").read_text(encoding="utf-8"))
        truth = json.loads((demo / "ground-truth.json").read_text(encoding="utf-8"))
        losses = [f for f in report["findings"] if f["type"] == "recovered_loss"]
        assert losses and all(f["hop"] == "forward:p2:p3" for f in losses), report["verdict"]
        assert sum(f["metrics"]["count"] for f in losses) == len(truth["events"])
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        with (scratch / "server.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(binary), "--project", str(demo / "project"), "--port", str(port), "--no-browser"],
                cwd=scratch,
                stdout=log,
                stderr=log,
            )
            try:
                deadline = time.monotonic() + 60
                while True:
                    if process.poll() is not None:
                        raise AssertionError("Frozen server exited before readiness")
                    try:
                        with urlopen(base + "/api/health", timeout=2) as response:
                            health = json.load(response)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise AssertionError("Frozen server did not become ready") from None
                        time.sleep(0.2)
                assert health["status"] == "ok" and health["version"]
                with urlopen(base + "/api/state", timeout=10) as response:
                    state = json.load(response)
                assert state["tshark"]["path"] and not state["tshark"]["error"]
                assert len(state["captures"]) == 5
                with urlopen(base, timeout=10) as response:
                    html = response.read().decode()
                assets = re.findall(r'(?:src|href)="(/assets/[^" ]+)"', html)
                assert assets, "No bundled UI assets"
                for asset in assets:
                    with urlopen(base + asset, timeout=10) as response:
                        assert response.status == 200 and len(response.read()) > 100
                with urlopen(base + "/api/report", timeout=10) as response:
                    assert json.load(response)["verdict"] == report["verdict"]
                with urlopen(
                    Request(
                        base + "/api/settings",
                        data=b'{"assistant_enabled":true}',
                        headers={"Content-Type": "application/json", "X-PacketBreaker": "local"},
                        method="POST",
                    ),
                    timeout=10,
                ) as response:
                    assert json.load(response)["assistant_enabled"]
                with urlopen(base + "/api/assistant/preview", timeout=10) as response:
                    preview = json.load(response)
                assert preview["schema_name"] == "packetbreaker.findings" and preview["findings"]
                assert set(preview) == {"schema_name", "schema_version", "engine_version", "findings"}
            except BaseException:
                log.flush()
                print((scratch / "server.log").read_text(encoding="utf-8", errors="replace"))
                raise
            finally:
                if os.name == "nt" and process.poll() is None:
                    # One-file Windows has a bootloader parent and a server child.
                    # Terminating only the parent leaves the child holding the project/log.
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT,
                        timeout=15,
                    )
                elif process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                with socket.socket() as sock:
                    sock.settimeout(1)
                    assert sock.connect_ex(("127.0.0.1", port)) != 0, (
                        "Frozen server still listening after exit"
                    )
        print(
            json.dumps(
                {
                    "binary": str(binary),
                    "health": health,
                    "files": 5,
                    "recovered_loss": len(truth["events"]),
                    "ui_assets": len(assets),
                }
            )
        )


if __name__ == "__main__":
    main()
