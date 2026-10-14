"""Local reference checks and semantic run diffs; no evaluation or network access."""

import math
import re
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ReferenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=200)
    description: str = Field(max_length=2000)
    metric: str = Field(min_length=2, max_length=2000)
    expected: Any
    check: dict[str, Any] = Field(
        json_schema_extra={
            "oneOf": [
                {
                    "type": "object",
                    "required": [k],
                    "properties": {
                        k: (
                            {}
                            if k == "equals"
                            else {"type": "number", **({"minimum": 0} if k not in ("min", "max") else {})}
                        )
                    },
                    "additionalProperties": False,
                }
                for k in ("abs_tol", "rel_tol_pct", "max", "min", "equals", "window_tol_s")
            ]
        }
    )

    @model_validator(mode="after")
    def valid_check(self):
        if len(self.check) != 1 or next(iter(self.check)) not in (
            "abs_tol",
            "rel_tol_pct",
            "max",
            "min",
            "equals",
            "window_tol_s",
        ):
            raise ValueError("Choose exactly one supported check")
        kind, value = next(iter(self.check.items()))
        if kind != "equals" and (
            isinstance(value, bool)
            or not isinstance(value, (float, int))
            or not math.isfinite(value)
            or (kind not in ("min", "max") and value < 0)
        ):
            raise ValueError("Tolerance must be a finite non-negative number; bounds must be finite")
        parse_path(self.metric)
        return self


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = Field(default=1, ge=1, le=1)
    items: list[ReferenceItem] = Field(max_length=10000)

    @model_validator(mode="after")
    def unique_ids(self):
        if len({i.id for i in self.items}) != len(self.items):
            raise ValueError("Reference item IDs must be unique")
        return self


def parse_path(path):
    if not path.startswith("$"):
        raise ValueError("JSONPath must start with $")
    tokens = []
    position = 1
    pattern = re.compile(r"\.([A-Za-z_][A-Za-z0-9_-]*)|\[(\d+)\]|\['([^']+)'\]|\[\"([^\"]+)\"\]")
    while position < len(path):
        match = pattern.match(path, position)
        if not match:
            raise ValueError("Supported JSONPath: object fields and explicit array indices")
        tokens.append(int(match[2]) if match[2] is not None else match[1] or match[3] or match[4])
        position = match.end()
    return tokens


MISSING = object()


def resolve(data, path):
    value = data
    for key in parse_path(path):
        try:
            value = value[key]
        except (KeyError, IndexError, TypeError):
            return MISSING
    return value


def number(value):
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


def window_values(value):
    if isinstance(value, dict):
        return [value.get("start"), value.get("end")]
    return value if isinstance(value, list) and len(value) == 2 else [None, None]


def compare_reference(data, reference):
    ref = Reference.model_validate(reference)
    results = []
    for item in ref.items:
        value = resolve(data, item.metric)
        kind, threshold = next(iter(item.check.items()))
        reason = None
        passed = None
        if value is MISSING or value is None:
            reason = "Metric path missing or value not computed"
        elif kind == "equals":
            passed = value == threshold
        elif kind == "window_tol_s":
            actual, expected = window_values(value), window_values(item.expected)
            if not all(number(v) for v in actual + expected):
                reason = "Window endpoints not computed or expected window invalid"
            else:
                passed = all(abs(a - b) <= threshold for a, b in zip(actual, expected))
        elif not number(value):
            reason = "Metric is not a finite numeric value"
        elif kind in ("max", "min"):
            passed = value <= threshold if kind == "max" else value >= threshold
        elif not number(item.expected):
            reason = "Expected value is not numeric"
        elif kind == "abs_tol":
            passed = abs(value - item.expected) <= threshold
        else:
            passed = abs(value - item.expected) <= abs(item.expected) * threshold / 100
        results.append(
            dict(
                **item.model_dump(),
                value=None if value is MISSING else value,
                status="not-computed" if passed is None else "pass" if passed else "fail",
                reason=reason,
            )
        )
    return dict(
        items=results,
        counts={s: sum(r["status"] == s for r in results) for s in ("pass", "fail", "not-computed")},
    )


def reference_template(report):
    paths = [
        "$.flow_count",
        "$.window.common_start",
        "$.window.common_end",
        "$.host_path.window",
        "$.host_path.local_service.cycle_aggregate.p95_ms",
        "$.host_path.local_service.cycle_aggregate.samples",
        "$.host_path.items[0].affected_flow_count",
        "$.host_path.items[0].max_ms",
        "$.finding_count",
        "$.cycles.total",
        "$.cycles.stalled_total",
        "$.cycles.max_added_ms",
        "$.cycles.event.total",
        "$.cycles.event.stalled_total",
        "$.cycles.event.max_added_ms",
        "$.cycles.repeat_groups.forward",
        "$.cycles.repeat_groups.reverse",
        "$.host_path.rx_share",
        "$.host_path.max_silence_ms",
        "$.host_path.event.rx_share",
        "$.host_path.event.max_silence_ms",
        "$.onsets.retrans_peak_time",
        "$.onsets.retrans_peak_count",
        "$.host_path.items[0].affected_flows_ge_stall",
    ]
    return dict(
        schema_version=1,
        items=[
            dict(
                id=f"metric-{n}",
                description=path,
                metric=path,
                expected=None if (v := resolve(report, path)) is MISSING else v,
                check={"window_tol_s": 1} if path.endswith(".window") else {"abs_tol": 0},
            )
            for n, path in enumerate(paths)
        ],
    )


def unwrap(data):
    if not isinstance(data, dict) or not isinstance(data.get("report", data), dict):
        raise ValueError("Analysis report/export must be an object")
    return data.get("report", data)


def compare_runs(before, after):
    before, after = unwrap(before), unwrap(after)
    changes = []
    total = 0
    ignored = {
        "generated_at",
        "exported_at",
        "id",
        "capture_id",
        "evidence",
        "evidence_refs",
        "frame",
        "evidence_key",
        "request_frame",
        "response_frame",
        "request_last_frame",
        "evidence_frame",
        "evidence_frame_a",
        "evidence_frame_b",
    }

    def walk(a, b, path):
        nonlocal total
        if isinstance(a, dict) and isinstance(b, dict):
            for k in sorted(a.keys() | b.keys()):
                if k not in ignored and k != "findings":
                    walk(a.get(k, MISSING), b.get(k, MISSING), path + "." + k)
        elif isinstance(a, list) and isinstance(b, list):
            for i in range(max(len(a), len(b))):
                walk(a[i] if i < len(a) else MISSING, b[i] if i < len(b) else MISSING, path + f"[{i}]")
        elif a != b:
            total += 1
            if len(changes) < 1000:
                changes.append(
                    dict(
                        metric=path,
                        before=None if a is MISSING else a,
                        after=None if b is MISSING else b,
                        status="missing" if a is MISSING or b is MISSING else "changed",
                    )
                )

    walk(before, after, "$")

    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in ignored}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value

    def group(report):
        result = {}
        for f in report.get("findings", []):
            key = (f.get("type"), f.get("hop"), f.get("direction"))
            value = clean(
                {k: v for k, v in f.items() if k not in ignored and k not in ("headline", "summary")}
            )
            result.setdefault(key, []).append(value)
        return result

    a, b = group(before), group(after)
    findings = []
    for key in sorted(a.keys() | b.keys(), key=str):
        if a.get(key) != b.get(key):
            findings.append(
                dict(
                    type=key[0],
                    hop=key[1],
                    direction=key[2],
                    status="added" if key not in a else "removed" if key not in b else "changed",
                    before=a.get(key),
                    after=b.get(key),
                )
            )
    return dict(
        metrics=changes,
        metric_difference_count=total,
        truncated=total > len(changes),
        findings=findings,
        note="Generated timestamps, IDs and frame-reference metadata are ignored; analysis values and finding metrics are compared. List order remains significant.",
    )
