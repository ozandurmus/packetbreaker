import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "windows_suite", Path(__file__).parents[1] / "tools/windows_fast_suite.py"
)
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)


def test_partition_keeps_every_file_once_and_all_parametrized_cases():
    ids = [
        "tests/a.py::one",
        "tests/a.py::two[x]",
        "tests/a.py::two[y]",
        "tests/b.py::one",
        "tests/c.py::one",
    ]
    groups = suite.partition(ids, 2)
    assert sorted(file for group in groups for file in group) == ["tests/a.py", "tests/b.py", "tests/c.py"]
    assert groups == [["tests/a.py"], ["tests/b.py", "tests/c.py"]]


def test_junit_coverage_includes_skips_and_failures(tmp_path):
    paths = []
    for i, attrs in enumerate(
        ['tests="3" failures="1" errors="0" skipped="1"', 'tests="2" failures="0" errors="0" skipped="0"']
    ):
        p = tmp_path / f"{i}.xml"
        p.write_text(f"<testsuites><testsuite {attrs}/></testsuites>")
        paths.append(p)
    assert suite.junit_counts(paths) == dict(tests=5, failures=1, errors=0, skipped=1)
