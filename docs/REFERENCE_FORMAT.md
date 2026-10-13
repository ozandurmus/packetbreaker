# Local analysis references (schema version 1)

A reference is a UTF-8 JSON object with `schema_version: 1` and `items` (at most 10,000).
The machine-readable schema is [reference.schema.json](reference.schema.json).
Every item has a unique `id`, `description`, `metric`, `expected` and exactly one `check`.
Values and tolerances use the report metric's units; report times are Unix seconds.

```json
{"schema_version":1,"items":[
  {"id":"flows","description":"Expected incident flows","metric":"$.flow_count","expected":148,"check":{"abs_tol":0}},
  {"id":"event","description":"Global event bounds","metric":"$.host_path.window","expected":{"start":1700000020,"end":1700000045},"check":{"window_tol_s":1}},
  {"id":"local","description":"Server-local cycle p95 (ms)","metric":"$.host_path.local_service.cycle_aggregate.p95_ms","expected":1,"check":{"max":1}}
]}
```

JSONPath supports `$`, `.field`, `[0]`, `['field']` and `["field"]`, including combinations.
Recursive descent, wildcards, slices, filters and executable expressions are rejected.
The CLI/UI check paths against the **analysis report** (exports unwrap their `report` field).
For example `$.window.common_start` and `$.host_path.items[0].affected_flow_count`.
Arrays have report order; prefer stable aggregate paths to positional flow references.

| Check | Pass condition |
|---|---|
| `abs_tol: x` | `abs(product - expected) <= x` |
| `rel_tol_pct: x` | `abs(product - expected) <= abs(expected) * x / 100`; expected zero requires exact zero |
| `max: x` | `product <= x` |
| `min: x` | `product >= x` |
| `equals: v` | Product equals `v`; `expected` remains the displayed reference value |
| `window_tol_s: x` | Both start/end differ by at most `x` seconds; expected/product can be `[start,end]` or `{start,end}` |

Missing/null metrics, invalid numeric values, and unknown window endpoints are
**not-computed**, never fail. An actual comparison outside tolerance is **fail**.
Malformed references (including multiple checks or negative tolerances) are rejected.
`max`/`min` and `equals` use their explicit check value; keep displayed `expected` in sync.

Overview → Reference and run comparison accepts a reference and/or a previous JSON export.
It runs locally with no outgoing connection. Export reference template copies current key
metrics as starting expected values; a reviewer edits them before using the template as an
independent reference. A template is not proof against independent ground truth.

```sh
packetbreaker --project /path/to/project compare --reference ref.json
packetbreaker --project /path/to/project compare --template current-reference.json
packetbreaker --project /path/to/project compare --against previous-report.json
packetbreaker compare --report after.json --against before.json --reference ref.json
```

CLI prints JSON with pass/fail/not-computed per item and both values. Run diffs ignore
export/generated timestamps, finding IDs and frame-reference metadata, but retain finding
classes/hops, confidence, time windows and metrics. Findings are grouped by type/hop/direction;
list ordering remains significant. Address mapping is a real reported difference, not silently
ignored. The first 1,000 metric changes are displayed with the full difference count.
The UI/API accepts at most 64 MiB per comparison; large reports can be compared using the CLI.
