"""Build a native single executable. Run after npm run build and installing .[packaging]."""

from pathlib import Path
import os
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    if not (root / "src/packetbreaker/static/index.html").is_file():
        raise SystemExit("Build the frontend before packaging")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onefile",
            "--name",
            "packetbreaker",
            "--console",
            "--collect-data",
            "packetbreaker",
            "--collect-data",
            "tzdata",
            "--collect-submodules",
            "uvicorn",
            "--hidden-import",
            "anyio._backends._asyncio",
            "--distpath",
            str(root / "dist/binary"),
            "--workpath",
            str(root / "build/binary"),
            "--specpath",
            str(root / "build"),
            str(root / "tools/frozen_entry.py"),
        ],
        cwd=root,
        env={**os.environ, "PYINSTALLER_CONFIG_DIR": str(root / "build/pyinstaller-cache")},
        check=True,
    )


if __name__ == "__main__":
    main()
