import duckdb
from packetbreaker.retransmissions import RETRY_KIND


def retry(**changes):
    values = dict(
        trusted=True,
        original_range=True,
        indexed=True,
        spurious=False,
        delivered=False,
        sack_hole=False,
        fast_retrans=False,
        rto_seconds=None,
        prior_rtts=0,
        rto_bound=1.0,
        duplicate_acks=0,
    )
    values.update(changes)
    with duckdb.connect() as db:
        db.execute(
            "CREATE TABLE r("
            + ",".join(k + " " + ("BOOLEAN" if isinstance(v, bool) else "DOUBLE") for k, v in values.items())
            + ")"
        )
        db.execute("INSERT INTO r VALUES(" + ",".join("?" for _ in values) + ")", list(values.values()))
        return db.execute("SELECT " + RETRY_KIND + " FROM r").fetchone()[0]


def test_unknown_timer_and_untrusted_state_first():
    assert retry(original_range=False, rto_seconds=2, prior_rtts=8) == "unknown"
    assert retry(rto_seconds=0.4, prior_rtts=8) == "unknown"
    assert retry(rto_seconds=2, prior_rtts=0) == "unknown"
    assert retry(trusted=False, fast_retrans=True) == "unknown"
    assert retry(spurious=True, delivered=False) == "unknown"
    assert retry(rto_seconds=2, prior_rtts=8, duplicate_acks=3) == "unknown"


def test_independent_recovery_evidence():
    assert retry(fast_retrans=True) == "fast"
    assert retry(fast_retrans=True, sack_hole=True, duplicate_acks=3) == "sack"
    assert retry(spurious=True, delivered=True) == "spurious"
    assert retry(rto_seconds=1.2, prior_rtts=4) == "rto"
