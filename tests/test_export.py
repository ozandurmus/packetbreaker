from copy import deepcopy
from html.parser import HTMLParser
import json
import sys

import pytest

from packetbreaker.cli import main
from packetbreaker.export import FindingsExport, export_data, html_report
from packetbreaker.store import Project


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        self.references += [v for k, v in attrs if k in ("src", "href")]
        if tag == "script":
            self.scripts.append(values)


def test_offline_export_schema_escape_and_all_findings(scenarios):
    project, _, _, report = scenarios("capture_miss")
    data = export_data(project)
    assert FindingsExport.model_validate(data).schema_version == 2
    assert {"type", "hop", "time_range", "metrics", "evidence_refs", "confidence"} <= data["findings"][
        0
    ].keys()
    assert data["timeseries"]["items"] and data["flow_filters"]
    assert '"prefix":' not in json.dumps(data)
    malicious = '</script><img src="https://invalid.example/steal">&'
    data["report"]["segments"][0]["label"] = malicious
    data["report"]["onsets"]["items"] = [
        dict(
            segment="sender",
            metric="retrans_percent",
            scope="capture_signal",
            time=1,
            explanation="symptom observed here",
        ),
        dict(
            segment="suspect",
            metric="loss_percent",
            scope="network_segment",
            time=2,
            explanation="prime loss",
        ),
    ]
    data["report"]["onsets"]["directions"] = {"forward": {"prime_suspects": ["suspect"]}}
    html = html_report(data)
    assert html.index("<h3>suspect") < html.index("<h3>sender")
    assert "article class='symptom'" in html
    parser = Assets()
    parser.feed(html)
    assert len(parser.scripts) == 2  # Fixed code and escaped inert JSON only.
    assert all(not r.startswith(("http://", "https://", "//")) for r in parser.references)
    assert all(r.startswith("#") for r in parser.references)
    assert malicious not in html and "&lt;/script&gt;" in html
    assert "connect-src 'none'" in html
    assert "r.coverage==='not capturing'" in html
    with project.connect() as db:
        saved = project.get(db, "export_findings")
        many = [dict(deepcopy(data["findings"][0]), id=str(i)) for i in range(201)]
        for f in many:
            f["evidence"] = f.pop("evidence_refs")
        project.set(db, "export_findings", many)
    try:
        assert len(export_data(project)["findings"]) == 201
    finally:
        with project.connect() as db:
            project.set(db, "export_findings", saved)


def test_cli_exports_and_missing_analysis(scenarios, tmp_path, monkeypatch, capsys):
    project, _, _, _ = scenarios("healthy")
    output = tmp_path / "report.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["packetbreaker", "--project", str(project.path), "export", "--format", "json", "-o", str(output)],
    )
    main()
    assert json.loads(output.read_text())["schema_version"] == 2
    before = output.read_bytes()
    with pytest.raises(SystemExit):
        main()  # Existing output is not overwritten.
    assert output.read_bytes() == before
    monkeypatch.setattr(
        sys, "argv", ["packetbreaker", "--project", str(project.path), "export", "--format", "html"]
    )
    capsys.readouterr()
    main()
    assert '<canvas id="map"' in capsys.readouterr().out
    with pytest.raises(ValueError, match="Run analysis"):
        export_data(Project(tmp_path / "empty"))
