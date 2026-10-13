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


def test_shared_voip_fixture_family_stays_in_one_shard():
    files = [
        "tests/test_udp_transactions.py",
        "tests/test_rtp.py",
        "tests/test_sip.py",
        "tests/test_media_mutants.py",
    ]
    ids = [f + "::case" for f in files] + ["tests/other.py::one"]
    groups = suite.partition(ids, 2)
    assert sum(any(f in group for f in files) for group in groups) == 1
    assert sorted(f for group in groups for f in group) == sorted(files + ["tests/other.py"])


def test_proxy_fixture_family_stays_in_one_shard():
    files = [
        "tests/test_tls_interception.py",
        "tests/test_proxy_pairing.py",
        "tests/test_proxy_integration.py",
        "tests/test_proxy_resets.py",
        "tests/test_proxy_clocks.py",
    ]
    groups = suite.partition([f + "::case" for f in files] + ["tests/other.py::one"], 2)
    assert sum(any(f in group for f in files) for group in groups) == 1
    assert sorted(f for group in groups for f in group) == sorted(files + ["tests/other.py"])


def test_file_timings_sum_all_cases_without_using_pass_count_as_cost(tmp_path):
    p = tmp_path / "cases.xml"
    p.write_text(
        '<testsuites><testsuite><testcase classname="tests.test_a" time="2"/><testcase classname="tests.test_a" time="3"/><testcase classname="tests.test_b.TestCases" time="7"/></testsuite></testsuites>'
    )
    assert suite.file_timings([p]) == {"tests/test_a.py": 5.0, "tests/test_b.py": 7.0}


def test_measured_costs_balance_expensive_files_instead_of_equal_case_counts():
    ids = ["tests/a.py::one", "tests/b.py::one", "tests/c.py::one"]
    assert suite.partition(ids, 2, {"tests/a.py": 1, "tests/b.py": 40, "tests/c.py": 35}) == [
        ["tests/b.py"],
        ["tests/c.py", "tests/a.py"],
    ]
