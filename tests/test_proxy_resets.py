import pytest
from packetbreaker.proxy_resets import classify


@pytest.mark.parametrize("device", ["Proxy A", "Proxy B", "link"])
@pytest.mark.parametrize(
    "negative", ["clock", "coverage", "uncaptured_trigger", "ambiguity", "multiple_triggers"]
)
def test_negative_reset_first(device, negative):
    output = dict(corrected=10.3)
    trigger = dict(corrected=10.2)
    status, reason = classify(
        output,
        [trigger, trigger] if negative == "multiple_triggers" else [],
        None if negative == "clock" else 0,
        negative != "coverage",
        negative == "uncaptured_trigger",
        negative == "ambiguity",
    )
    assert status == "unknown" and reason


@pytest.mark.parametrize("device", ["Proxy A", "Proxy B"])
def test_reset_positive_classification(device):
    assert classify(dict(corrected=10.3), [dict(corrected=10.2)], 0, True) == ("propagated", None)
    assert classify(dict(corrected=10.3), [], 0, True) == ("originated", None)
