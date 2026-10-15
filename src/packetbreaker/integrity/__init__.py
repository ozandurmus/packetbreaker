"""Bounded path checks package. Positive field changes and absence-based hypotheses stay distinct."""

from .common import LIMIT, ORIGIN_TIP, BaseChecks, duplicate_pairs, endpoint_pattern, metadata
from .grouping import group_downstream_findings
from .origins import OriginChecksMixin
from .path_checks import PathChecksMixin
from .payloads import PayloadChecksMixin, link_modified_payloads


class Checks(BaseChecks, OriginChecksMixin, PayloadChecksMixin, PathChecksMixin):
    pass


def analyze_integrity(db, topology, segments, coverage, models, start, end):
    checks = Checks(db, topology, segments, coverage, models, start, end)
    checks.origins()
    checks.endpoint_origins()
    checks.payload_changes()
    checks.downstream_only()
    checks.mtu()
    checks.path_checks()
    return checks.findings, checks.notes


__all__ = [
    "Checks",
    "LIMIT",
    "ORIGIN_TIP",
    "analyze_integrity",
    "duplicate_pairs",
    "endpoint_pattern",
    "group_downstream_findings",
    "link_modified_payloads",
    "metadata",
]
