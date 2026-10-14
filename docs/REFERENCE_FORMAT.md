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

## Stable engine aggregates (0.3.9)

The scalar paths below are in the analysis report and in JSON export `report`.
`cycles.analysis`, `host_path.analysis`, and `onsets.analysis` hold whole-analysis details;
`.event` holds the corresponding half-open global host event window `[start,end)`.
Without a supported global window, event metrics are null with a reason.
Whole-analysis convenience scalars use `.analysis`, except `max_silence_ms`, which explicitly
uses `.event` because it describes silence **during the incident**.

| Stable metric | Units / definition |
|---|---|
| `$.cycles.total` | Distinct measured opaque cycle IDs across all capture points; no hop multiplication |
| `$.cycles.stalled_total` | Distinct cycles with at least one measured point at or above configured `stall_ms`; application-only waiting also counts as a stalled cycle |
| `$.cycles.max_added_ms` | Largest complete clock-valid RX + TX host-boundary added time for one cycle, ms; server-local time excluded |
| `$.cycles.max_added` | Winning cycle ID, flow/port, host, time, RX/TX ms, uncertainty and boundary frame evidence |
| `$.host_path.rx_share` | Percentage (0–100): sum of positive RX cycle components / sum of complete RX+TX added time; not byte-weighted |
| `$.host_path.max_silence_ms` | Longest observed host inter-packet gap clipped to the global event window, ms; all valid capture frames/flows included |
| `$.cycles.repeat_groups.forward` / `.reverse` | Distinct repeated TCP data ranges at any one point, deduplicated across points; SPAN copies excluded, offload uses existing canonical byte ranges |
| `$.onsets.retrans_peak_time` | Earliest UTC epoch-second bucket attaining the largest retransmission count at one host point (first path point if no host) |
| `$.onsets.retrans_peak_count` | Retransmission count in that bucket; observations from multiple hops are not summed |
| `$.host_path.items[0].affected_flows_ge_stall` | Distinct flows with at least one clock-valid same-copy host-boundary sample `>= stall_ms`, alongside `affected_flow_count` |

For global-event equivalents use `$.cycles.event.total`, `.stalled_total`, `.max_added_ms`,
`.repeat_groups`, `$.host_path.event.rx_share`, `.max_silence_ms`, and
`$.onsets.event.retrans_peak_time` / `.retrans_peak_count`. Each host item also has
`affected_flows_ge_stall_event`. Item order is not a stable direction identity: inspect
`direction` (`rx` / `tx`) before choosing its explicit array index in a reference.

Repeat groups need two observations at the **same point**; seeing one packet at five hops
is not repetition. An event repeat group has at least one copy in the event, while its
original can precede the event. Counts describe canonical matching ranges, not an assertion
that offload capture units equal wire packet counts. Delay shares and added-time components
include observed retry recovery wait and retain clock uncertainty; they are not proof of
physical transit or a device cause. Missing components make added time unknown.

Silence requires a known clock and capture endpoints bracketing the requested scope. No
packet does not prove an application stall or continuous capture. Evidence contains the
bracketing host frames. No host, unknown clock or insufficient coverage yields null. No
observed retransmissions yields count zero and peak time null. Templates include these key
metrics for editing against an independent reference.
