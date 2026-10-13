import json
import pytest
from packetbreaker.reference import compare_reference, compare_runs, reference_template, Reference


def item(check, expected=10, metric="$.value"):
    return dict(id="one", description="Fixture metric", metric=metric, expected=expected, check=check)


@pytest.mark.parametrize(
    "check,expected,value,status",
    [
        ({"abs_tol": 1}, 10, 11, "pass"),
        ({"abs_tol": 1}, 10, 12, "fail"),
        ({"rel_tol_pct": 5}, 100, 104, "pass"),
        ({"rel_tol_pct": 1}, 0, 1, "fail"),
        ({"max": 10}, 10, 11, "fail"),
        ({"min": 10}, 10, 10, "pass"),
        ({"equals": "done"}, "done", "done", "pass"),
        ({"window_tol_s": 1}, [20, 45], {"start": 19, "end": 46}, "pass"),
        ({"window_tol_s": 1}, [20, 45], {"start": 18, "end": 46}, "fail"),
    ],
)
def test_reference_checks(check, expected, value, status):
    r = compare_reference({"value": value}, {"items": [item(check, expected)]})
    assert r["items"][0]["status"] == status
    assert r["items"][0]["value"] == value


@pytest.mark.parametrize("data", [{}, {"value": None}])
def test_missing_is_not_computed_never_fail(data):
    assert compare_reference(data, {"items": [item({"max": 1})]})["counts"]["not-computed"] == 1


@pytest.mark.parametrize(
    "check,metric",
    [
        ({"abs_tol": -1}, "$.value"),
        ({"max": 1, "min": 2}, "$.value"),
        ({"eval": "bad"}, "$.value"),
        ({"max": 1}, "$..value"),
        ({"max": 1}, "$.items[*]"),
    ],
)
def test_invalid_reference_rejected(check, metric):
    with pytest.raises(ValueError):
        Reference.model_validate({"items": [item(check, metric=metric)]})


def test_paths_template_and_semantic_diff():
    report = {
        "flow_count": 50,
        "window": {"common_start": 20, "common_end": 45},
        "findings": [{"id": "a", "type": "loss", "hop": "B", "metrics": {"count": 2}, "evidence": []}],
        "generated_at": "a",
    }
    before = {**report, "generated_at": "b", "findings": [{**report["findings"][0], "id": "b"}]}
    assert not compare_runs({"report": before}, report)["metrics"]
    assert not compare_runs(before, report)["findings"]
    after = {**report, "flow_count": 51, "findings": [{**report["findings"][0], "metrics": {"count": 3}}]}
    diff = compare_runs(before, after)
    assert diff["metrics"][0]["metric"] == "$.flow_count"
    assert diff["findings"][0]["status"] == "changed"
    template = reference_template(report)
    Reference.model_validate(template)
    assert (
        compare_reference(report, {"items": [item({"equals": 3}, 3, "$.a[0]['b']")]})["counts"][
            "not-computed"
        ]
        == 1
    )


def test_compare_cli_and_api(tmp_path, monkeypatch, capsys):
    from packetbreaker.cli import main
    from packetbreaker.app import create_app
    from packetbreaker.store import Project
    from starlette.testclient import TestClient

    report = {"flow_count": 50, "findings": []}
    p = Project(tmp_path / "project")
    with p.connect() as db:
        p.set(db, "report", report)
    ref = tmp_path / "ref.json"
    ref.write_text(json.dumps({"items": [item({"max": 60}, 50, "$.flow_count")]}))
    monkeypatch.setattr(
        "sys.argv", ["packetbreaker", "--project", str(p.path), "compare", "--reference", str(ref)]
    )
    main()
    assert json.loads(capsys.readouterr().out)["counts"]["pass"] == 1
    with TestClient(create_app(p.path), base_url="http://127.0.0.1") as client:
        r = client.post(
            "/api/compare",
            json={"reference": json.loads(ref.read_text()), "against": report},
            headers={"X-PacketBreaker": "local"},
        )
        assert r.status_code == 200 and r.json()["counts"]["pass"] == 1
        assert r.json()["diff"]["metric_difference_count"] == 0
        assert client.get("/api/reference/template").status_code == 200
        invalid = client.post(
            "/api/compare",
            json={"reference": {"items": [item({"max": 1}, metric="$..bad")]}},
            headers={"X-PacketBreaker": "local"},
        )
        assert invalid.status_code == 400
