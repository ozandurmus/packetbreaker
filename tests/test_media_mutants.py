"""Execute naive alternatives on the same ground truth, then reject their outputs."""

import pytest


def test_nearest_udp_ssrc_only_receiver_blame_and_any_sdp_change_mutants(scenarios):
    project, truth, _, report = scenarios("udp_transactions", fault_location="FW2", ip_id="zero")
    with project.connect() as db:
        nearest = db.execute("""SELECT q.frame,arg_min(r.frame,abs(r.ts-q.ts)) FROM udp_protocol q JOIN udp_protocol r
            ON q.point=r.point AND q.tuple_key=r.reverse_tuple AND r.ts BETWEEN q.ts AND q.ts+2
            WHERE q.point='client' AND q.sport=41005 AND q.role='request' AND r.role='response' GROUP BY q.frame""").fetchall()
        naive_ssrc = db.execute(
            "SELECT count(DISTINCT ssrc) FROM rtp_streams WHERE point='client' AND direction='forward'"
        ).fetchone()[0]
        actual_streams = db.execute(
            "SELECT count(*) FROM rtp_streams WHERE point='client' AND direction='forward'"
        ).fetchone()[0]
        # A receiver-only detector attributes every elevated server jitter to the endpoint.
        receiver_blame = (
            {"server"}
            if db.execute(
                "SELECT count(*) FROM rtp_streams WHERE point='server' AND jitter_max_ms>2"
            ).fetchone()[0]
            else set()
        )
    with pytest.raises(AssertionError):
        assert not nearest  # This ambiguous pair must remain unknown, even with a closest candidate.
    with pytest.raises(AssertionError):
        assert naive_ssrc == actual_streams
    supported_jitter = {
        f["device"]
        for f in report["findings"]
        if f["type"] == "rtp_jitter" and f["confidence"] == "supported"
    }
    with pytest.raises(AssertionError):
        assert receiver_blame == supported_jitter
    any_rewrite_bug = {c["call_id"] for c in report["sip"]["comparisons"] if c["changes"]}
    with pytest.raises(AssertionError):
        assert any_rewrite_bug == {truth["bad_call"]}
    # A hard-coded first firewall would fail exact FW2/link attribution.
    with pytest.raises(AssertionError):
        assert all(f["device"] == "FW1" for f in report["findings"] if f["type"] == "sdp_media_mismatch")
