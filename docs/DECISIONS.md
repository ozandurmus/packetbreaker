# Decisions

The initial numbered decisions record Phase 1.1. Later sections explicitly extend
that scope through Phase 2 / Part 3; no later-phase work is included.

1. Deliver Phase 1.1 correctness hardening only. Onset detector, vendor adapters, sequence translation,
   offload byte ranges, full proxy, export UI, security attribution and AI panel
   remain Phase 2/3. JSON analysis is available to the CLI/API and tests.
2. Use tshark subprocess field export; no Scapy and no custom protocol parser.
   Metadata block reading and synthetic packet construction are not dissection.
3. Conservative certainty: absence alone cannot confirm a device drop. Capture
   first/last packet timestamps bound observed coverage, not continuous capture
   availability. Unknown drop counters must not be displayed as zero.
4. Clock offset and path asymmetry are not independently identifiable from packet
   timestamps. Display the feasible offset envelope and suppress unreliable
   latency, including one-way-only calibration without an override.
5. NAT suggestions require confirmation. No automatic claim that two proxy legs
   are the same connection. Unsupported boundaries fail closed for attribution.
6. Persist partial ingest checkpoints; tshark replays prior frames on resume for
   correct TCP state. Cache reopening does not launch tshark. Batches and SQL are
   bounded; no claim of multi-GB throughput until measured on representative data.
7. Loopback is necessary but not sufficient: reject foreign Host/Origin values,
   require a same-origin custom header on mutations, disable CORS and external
   DuckDB access after data loading. Never serve arbitrary source paths.
8. Bundle all UI assets; no CDN fonts/scripts or runtime outbound calls. Keep
   packet prefixes local. DuckDB contains sensitive metadata and is not encrypted.
9. References reviewed: [Malcolm](https://github.com/cisagov/malcolm) illustrates
   ingest/normalize/session drilldown but its container architecture is not reused.
   [Networking](https://github.com/Chanduporalla/Networking) offers simple file and
   packet navigation; its Scapy/Tkinter/AI stack does not fit this architecture.
   [Wireshark TCP analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)
   supplies TCP flag semantics, not proof of cross-hop loss. Original implementation.

## Delivery validation
See [VALIDATION.md](VALIDATION.md) for passing local gates, measured scale and unverified platforms. Only the later explicitly scoped Phase 2 / Part 1 work is included.

## Phase 1.1 decisions

- Repeated signatures are packet occurrences, not intrinsically unmatchable data.
  Match corrected-time occurrences monotonically; do not equate bare ordinal k
  when an earlier original is absent downstream. A nearest-time gap belongs to
  the missing original, not to the delivered retransmission.
- Full captured-frame hashes and a small time threshold isolate potential SPAN
  copies without suppressing later byte-identical retransmissions.
- No Phase 2 functionality is introduced.
- Matchability is an explicit denominator, separate from observed loss. A low
  denominator suppresses aggregate rates, not frame-backed individual events.
- Control-byte acknowledgements are evidence of delivery, while a reset is
  evidence of failure, never mislabeled as a successful retransmission. A
  `handshake_blocked` finding locates the observed boundary, not the policy cause.
- `unrecovered_loss` describes a covered disappearance with unknown cause. It is
  not a confirmed device drop. Late observations without enough remaining
  coverage still remain unknown.
- Local tshark stream numbers are never assumed equal across files. Shared
  packet occurrences connect stream components; reused tuples stay separate.
- DNS responses and ICMP echo replies provide positive delivery evidence, but a
  response after an intervening retry cannot retroactively prove original delivery.
- Headline percentages use data packets, not TCP control packets, and start at
  the first observed loss. Controls have their own blocked-handshake sentence.
- Quick recovery, measured stalls and other unrecovered/impactful outcomes are
  distinct buckets; repeated short retries are not falsely called long stalls.
- Use event-date IANA timezone rules (tzdata on Windows), retaining UTC alongside
  local time. All timestamp conclusions retain a clock uncertainty caveat.
- Keep the 512 MB SQL budget and use spillable CTAS transforms. Raising the limit
  would hide the whole-table UPDATE allocation problem rather than bound it.
- Retain tshark-only production ingest. dpkt's raw first pass was 1.66x faster;
  including mandatory tshark TCP analysis enrichment gave only 1.07x. All 40 fields
  matched, but the required 2x speed gate was not met.
- Portable content filters do not depend on frame numbers or relative TCP
  sequence numbering. They are not advertised as unique for byte-identical retries.
- Flow filters include a timestamp window to keep reused-port sessions separate;
  merged/re-saved files with preserved timestamps retain that scope. Retimed files
  can still use the timestamp-independent content filter.

- Use the supported httpx2 TestClient transport and promote Starlette deprecation
  warnings to test failures. Keep test transport requirements compatible with
  the tested FastAPI/Starlette versions; do not silence the warning.
- Invalidate cached reports when the engine version changes so a pre-hardening
  false-negative report cannot be presented as a current result.

## Phase 2 / Part 1 scope

Only ingest robustness, resource-bounded parallel ingestion, inventory fidelity,
headline deduplication and repository/CI setup are authorized in this part.
No onset detection, sequence randomization, vendor adapters or other Phase 2
features are included. Capture fixtures are generated synthetically; real inputs
stay local and gitignored. Push CI is one macOS/Python job; pull requests and
manual dispatch use all six supported OS/Python combinations. No auto-merge.

The measured five-file workload is highly skewed and showed no concurrency speedup
(293.49 s serial versus 302.45 s with four workers). Keep parallelism for independent
files and per-file controls without claiming a measured throughput gain. The RAM
ratio is a worker scheduling estimate, not a hard aggregate memory cap.

## Phase 2 / Part 2 — ingest default

The equal-file benchmark reached 1.34× initially and 1.48× after bounded tuple and
signature memoization. It did not reach 1.5× even with five instead of four allowed
workers. Keep the measured serial path as default; opt into parallel via Settings,
`parallel: true` in preferences, or `demo --parallel-ingest`. Independent tshark
processes still feed Python row/CSV work under the GIL and serialized DuckDB writes.
A process/shard rewrite is not justified by this bounded request; do not claim an
unmeasured speedup. Exact packet-field equality was verified on all 5,000,750 rows.

## Phase 2 / Part 2 onset semantics

- Baseline usability depends on observed coverage, matchable observations and the
  requested metric's availability. Capture-miss and unknown-event counts remain
  quality notes and do not poison other measured signals or the overall summary.
  Per-segment/per-metric unknown status remains explicit. A stable but already-slow
  capture cannot prove historical health; an initially lossy loss reference is unknown.
- Replace adjacent loss crossings with rolling event evidence: a 15-second window,
  rounded up to whole buckets and at least two buckets, needs three excess events
  in two event buckets. Backdate to the first event of the sustained run and expose
  the later confirmation. A single spike/event is not a sustained onset.
- Counter references use event count/exposure from five initial usable samples.
  The robust rate threshold is baseline + 6 × 1.4826 × per-bucket MAD; count thresholds
  additionally require at least three events above baseline expectation. References
  remain fixed for counters so sparse changes are not absorbed into the baseline.
  Latency keeps median + max(1 ms, twice clock uncertainty, 6 × 1.4826 × MAD) and two
  consecutive crossings. Quality annotations do not reset an otherwise usable window.
- Detect retransmission, failed-handshake, reset and zero-window changes as well.
  Count a failed session only at its first blocked attempt, not once per SYN retry.
  Retransmission/reset/window events are local TCP symptoms; they cannot nominate
  a network-loss hop without segment-backed evidence. Frame refs use the first event
  bucket's actual SYN, retransmission, RST or zero-window announcement.
- Propagation order is temporal evidence, not proof of device causation. Tied
  buckets are unresolved; clock uncertainty may further limit ordering. Earliest
  observed segments are prime suspects, never confirmed root causes.
- Brushing filters evidence views without refitting the baseline. Packet evidence
  may include the same packet at another point just outside the brush, preserving
  its cross-hop context. All fixtures and performance inputs are synthetic.

## Review validation cost and publication

Keep default pytest below two minutes with explicit `slow` markers on exhaustive
real-tshark identity/scenario matrices. Fast checks run on every PR/manual OS/Python
combination; the slow matrix runs once on macos-14/Python 3.12. Push checks are fast
only. Both suites must pass locally for this review. The user requested no CI for
these pushes, so commit-local `[skip ci]` is used; the workflow remains active.
The user explicitly requested public visibility; capture/secret file history checks
preceded that change. No real captures or new Part 3 features were added.

## Part 3 sequence-translation boundary

Only explicitly declared same-device ingress/egress boundaries are learned.
Canonical tuples still require confirmed NAT mappings when addresses change.
Offsets are per TCP session, direction-aware and modulo 2³², including SYN/ACK
semantics and wrap. Constant offsets do not license matching across a full proxy.
Insufficient/ambiguous anchors and inconsistent offsets produce a per-flow unknown
reason. Original capture filters never use normalized SEQ/ACK values.

## Part 3 byte-range decisions

- Keep physical observations and local counters; derive sequence coverage separately
  instead of treating GSO/GRO packet-count differences as loss. Count affected source
  frames and expose missing bytes/ranges explicitly; do not infer an unseen wire
  packet count from a coalesced frame.
- Reuse monotone occurrence matching for byte intervals. A delivered retry must be
  present upstream and downstream, and a later ACK after a retry is not proof that
  the original was delivered. SYN/FIN sequence consumption and wrap remain explicit.
- Use captured payload prefixes to reject contradictions; absent middle-frame bytes
  are not invented or reported as fully compared. Mixed partial delivery evidence
  is unknown. Large-frame checksum artifacts do not produce error findings.
- Retain original frame/header evidence and bound derived range expansion. Cached
  old superframe exclusion markers lack sufficient fragment metadata, so rebuild
  those indexes once rather than silently trusting an obsolete classification.

## Part 3 retransmission attribution

Retransmission onsets describe a sender symptom, never independent proof of a
fault at the observing segment. The UI labels them "symptom observed here
(sender retransmits)". Related downstream loss boundaries require supported
loss events for the same contributing flows and overlapping event time. Only
segments with those loss events receive the loss-suspect badge; capture misses,
unknown events and retransmissions alone cannot create it.

## Part 3 performance acceptance

Keep serial ingest as the default chosen in Part 2. The same-input 5.4M-frame
regression check measured 2.89% less ingest time and 0.62% more analysis time.
Ingest maximum RSS increased 20.04%; report this regression rather than claiming
no cost. The single-run result does not isolate its cause. The ordinary packet
path avoids constructing a byte-range table unless differing large TCP frames
require it; range expansion has an explicit budget. No speculative parser or
concurrency rewrite is included in this phase.

## Part 4 waterfall boundaries

Use existing NAT/SEQ normalization and frame/byte occurrence identities; never
correlate full-proxy legs by timing alone. Mark that boundary `unknown (full
proxy, Phase 3)`. A supported HTTP processing interval needs complete request byte
coverage and an identifiable final response. Cleartext request lines alone do not
prove the request's end. Incomplete saved header prefixes, request transfer
encoding and pipelining stay unknown; HTTP payload reassembly is deliberately
bounded. Response-body download time is outside the first-byte waterfall.

Use ECharts for the live timeline and a parallel evidence table for every bar,
including unknown durations. Capture-point offsets cancel for same-capture
intervals; timestamp precision and residual drift remain approximate. Cross-file
bars carry the sum of their endpoint clock uncertainty bounds.
