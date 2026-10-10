import pytest
from packetbreaker.attribution_synthetic import CASES

MODES = [("zero", False), ("constant", False), ("zero", True), ("constant", True)]
LOCATIONS = ["FW", "LB", "link"]


def for_port(report, port, kind):
    return [
        f
        for f in report["findings"]
        if f["type"] == kind
        and any(
            f"tcp.srcport == {port}" in (e.get("content_filter") or "")
            or f"tcp.dstport == {port}" in (e.get("content_filter") or "")
            for e in f["evidence"]
        )
    ]


@pytest.mark.parametrize("mode", MODES, ids=["ipv4-zero", "ipv4-constant", "ipv6-zero", "ipv6-constant"])
@pytest.mark.parametrize("location", LOCATIONS)
@pytest.mark.parametrize("case", [*CASES, "asymmetric_return"])
def test_exact_integrity_location(multi, mode, location, case):
    _, truth, _, report = multi(location, mode, asymmetric=case == "asymmetric_return")
    expected = next(
        f
        for f in truth["findings"]
        if f["type"] == ("asymmetric_routing" if case == "asymmetric_return" else case)
    )
    found = for_port(report, expected["port"], expected["type"])
    relevant = [f for f in found if f["severity"] != "quality" or case == "asymmetric_return"]
    assert relevant, (expected, found)
    hop = f"forward:{expected['point_a']}:{expected['point_b']}"
    assert all(f["hop"] == hop and f["device"] == expected["device"] for f in relevant), relevant
    assert all(expected["location"] in f["summary"] for f in relevant), relevant
    assert (
        all(f["confidence"] == "supported" for f in relevant)
        if not (case == "reset_origin" and location == "link")
        else all(f["confidence"] == "unknown" for f in relevant)
    )
    assert not [f for f in found if f["confidence"] == "supported" and f["device"] != expected["device"]], (
        found
    )
    assert all(
        f["tooltip"] and f["evidence"] and all(e.get("content_filter") for e in f["evidence"])
        for f in relevant
    )


@pytest.mark.parametrize("mode", MODES, ids=["ipv4-zero", "ipv4-constant", "ipv6-zero", "ipv6-constant"])
@pytest.mark.parametrize(
    "case",
    [
        "server_gap",
        "server_gap_inside_lb",
        "no_endpoint",
        "equal_ttl_supported",
        "equal_ttl_unknown",
        "mtu_capture_miss",
    ],
)
def test_false_positive_guards(multi, mode, case):
    absent = case in ("no_endpoint", "equal_ttl_unknown")
    _, truth, _, report = multi("FW", mode, no_endpoint=absent)
    found = for_port(
        report, truth["guards"][case], "mtu_black_hole" if case == "mtu_capture_miss" else "reset_origin"
    )
    if case == "mtu_capture_miss":
        assert not found, found
        return
    assert found, case
    injected = [f for f in found if f["confidence"] == "supported" and "injected by" in f["summary"]]
    if case == "equal_ttl_supported":
        assert (
            len(injected) == 1
            and injected[0]["device"] == "FW"
            and injected[0]["hop"] == "reverse:fw_out:fw_in"
        ), found
    else:
        assert not injected, found
    if absent:
        assert all(
            f["confidence"] == "unknown" and "no endpoint-side capture" in f["summary"] for f in found
        ), found
