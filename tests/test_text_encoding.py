import ast
from pathlib import Path
import pytest
from packetbreaker.export import html_report


def test_text_io_declares_encoding():
    failures = []
    for source in (Path(__file__).parents[1] / "src" / "packetbreaker").glob("*.py"):
        for n in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if not isinstance(n, ast.Call) or not isinstance(n.func, ast.Attribute):
                continue
            name = n.func.attr
            if name not in ("read_text", "write_text", "open"):
                continue
            if name == "open":
                if isinstance(n.func.value, ast.Name) and n.func.value.id in ("os", "archive", "webbrowser"):
                    continue
                mode = next(
                    (k.value for k in n.keywords if k.arg == "mode"),
                    n.args[0] if n.args else ast.Constant("r"),
                )
                if not isinstance(mode, ast.Constant) or not isinstance(mode.value, str) or "b" in mode.value:
                    continue
            if not any(k.arg == "encoding" for k in n.keywords):
                failures.append(f"{source.name}:{n.lineno}")
    assert not failures, failures


def test_offline_html_with_cp1252_default(monkeypatch):
    library = Path(__file__).parents[1] / "src" / "packetbreaker" / "static" / "echarts-offline.js"
    # Prove this asset reproduces the Windows default-encoding failure.
    with pytest.raises(UnicodeDecodeError):
        library.read_bytes().decode("cp1252")
    original = Path.read_text
    reads = []

    def legacy_read(path, *args, **kwargs):
        assert kwargs.get("encoding") == "utf-8"
        reads.append(path.name)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", legacy_read)
    report = dict(
        verdict="Unicode fixture: ağ → ✓", segments=[], window={}, clocks={}, incident={}, onsets={}
    )
    report["incident"] = {"timeline": []}
    data = dict(
        report=report,
        findings=[],
        flow_filters=[],
        engine_version="fixture",
        schema_version=11,
        exported_at="fixture",
    )
    html = html_report(data)
    assert "ağ → ✓" in html and reads == ["echarts-offline.js", "incident-offline.js"]
