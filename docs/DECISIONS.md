# Decisions

The initial numbered decisions record Phase 1.1. Later sections explicitly extend
that scope through Phase 2 / Part 5; no later-phase work is included.

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
See [VALIDATION.md](VALIDATION.md) for passing local gates, measured scale and unverified platforms. Later sections record the explicitly scoped Phase 2 additions.

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

## Part 4 export contract

Use a versioned Pydantic metadata envelope and publish its generated JSON Schema.
Keep raw payloads and source file contents out of exports; addresses and evidence
filters remain investigation metadata and are not automatically redacted. Export
all grouped findings, not only the UI's summary slice. Require a current analysis
and reject export during an active job.

Use a small inline canvas renderer for the offline heatmap rather than embedding
the full application or relying on a CDN. Escape all capture-derived content;
use textContent for tooltip labels. CLI exports to stdout or a new output file;
an existing output file is never silently overwritten. UI downloads are explicit
HTML/JSON buttons and always describe the complete saved analysis window.

Default-test runtime is a local acceptance gate. Reuse the existing resource-
bounded two-worker ingest path only for preparing independent small synthetic
fixtures, overlapping tshark startup without removing tests. Keep the product's
serial ingest default and its dedicated serial/parallel/cancel-resume tests.
The last measured fast selection is 108.24 seconds; hosted-runner times vary.

## Part 5 adapter boundary

Keep tshark as the only protocol dissector. Adapters select options, retain decoded
vendor fields and select capture points. Synthetic fixture construction belongs in
tests; expected field values come from a separate tshark decode. Check Point's
UUID flag is user supplied because treating a non-UUID header as UUID changes the
interface-name interpretation. Continuous inspection coverage is explicit; missing
stages alone cannot prove a device drop in a filtered or incomplete monitor capture.

F5 positive flow/peer identifiers permit connection pairing but do not permit
merging proxy TCP sequence spaces. Use explicit client/server points and narrow
client CIDRs. Preserve tshark's HTTP decode for request markers; never implement
a proprietary trailer parser in production. Names, IDs and reset text remain
untrusted display data and use the existing escaped evidence/export paths.

Palo Alto stage names are explicit user file tags, retained as provenance in frame
evidence. A file cannot be tagged with conflicting nodes/stages. No proprietary
Palo Alto protocol decoder is introduced. Positive drop-stage evidence does not
require absence inference or uninterrupted network-path coverage. Allow one file
with multiple distinct capture points (fw monitor/TMM) and standalone drop-stage
analysis; file count is not the minimum evidence-point count.

Write the Fortinet converter from the vendor's documented text layout; no code
from FortiGate-PCAP or other converters was copied. `a` means absolute UTC, not
local time. A timezone-bearing anchor is mandatory for relative timestamps; it
does not create high-confidence wall-clock evidence. Preserve shown bytes and
skip damaged dumps instead of repairing or guessing protocol headers. Explicit cooked-link variants are validated by tshark under candidate link types;
ambiguous or incomplete link metadata is counted as a skip. No link header is invented.

## Part 5 classification and validation cost

Device certainty is separate from knowing the device's policy/rule. A PA drop tag
is positive stage evidence; Check Point disappearance requires explicit complete
inspection coverage and a supported packet identity. Arbitrary missing inspection
stages, crypto transformations and unobserved return paths must not manufacture
network loss. A connection UUID is not an individual packet identity.

Keep all device proof rows in DuckDB and bound report evidence, rather than opening
a Python/SQL query per dropped packet. Positive proof replaces a matched inferred
event; unmatched proof remains visible with no percentage denominator. Preserve
observed/associated timestamp provenance when a stage clock is not aligned.

Export schema v2 makes the new class and its device/stage provenance explicit.
Normal packet dissection bypasses vendor-dictionary work when no vendor markers
exist. F5/HTTP fields are requested only in the explicit F5 ingest mode; generic
pcaps keep the lightweight field projection. Three-worker fixture preparation did
not help locally, so the existing two-worker resource-bounded setting is retained; production serial defaults and the CI matrix policy are unchanged.

## Phase 3 origin attribution

First appearance is ordered by the configured path, not raw timestamps. Device-origin findings
require an ingress/egress pair of the same node and bracketed coverage, reliable clocks and
endpoint references. TTL and IP ID are corroborating observations, never authentication.
Constant/zero IDs and IPv6 have no usable IP-ID fingerprint. Missing references remain unknown;
policy/IPS intent is unknown unless vendor evidence explains the reset. Findings schema v3 adds
path-integrity classes and tooltips without putting them in loss-rate numerators.

Payload modification uses unique canonical tuple/SEQ/ACK/flags/length pairs inside the matching
window, including candidates whose changed prefix prevented ordinary matching. Both payloads
must be complete. Repeated ambiguous identities and offload splits are not compared. Users can
declare proxy/ALG/SSL inspection in the path editor; these nodes are exempt from unexpected
payload-modification findings. A downstream-only observation remains origin-unknown because
absence alone cannot distinguish injection from capture loss.

Path checks compare matched observations: DSCP remarking, MSS reduction, SACK/window-scale/
timestamp removal and unexpected TTL steps. A falling-TTL repeat is a loop/duplication hypothesis,
not proof. Microsecond-identical SPAN copies remain capture-quality findings; later exact repeats
remain cause-unknown. Asymmetric routing requires an explicitly different return path and
same-flow return evidence there; it does not blame a device for traffic it was never meant to see.

The integrity extension initially pushed the fast suite beyond two minutes. Candidate and field
change queries are now grouped across path edges, and checks with no relevant observed fields
are skipped using a single aggregate. Existing tests remain in their fast/slow suites; no new
integrity test is marked slow. Synthetic fixtures share one multi-flow capture set for the
independent mutation cases. Payload re-linking is explicitly tested not to create false loss.

Profiling identified a pre-existing bucket-write cost: DuckDB repeatedly probes the absent
optional pandas module during Python cell binding (23,338 probes in one healthy analysis).
Typed JSON bulk insertion replaces `executemany` for bucket records without adding pandas or
changing metric/null types. The same saved synthetic healthy analysis fell from 2.925 s to
0.731 s in the local probe. Coverage, bucket metrics and onset tests remain the acceptance gate.


Duplicate/loop candidates use window `lag` over each identity and compare adjacent observations;
they never form all pairs of a long constant-ID stream. Asymmetry selects the first observed
forward/return frame per flow before pairing, avoiding a many-to-many evidence join. These bounds
are independent of the number of identical retransmissions and do not turn repeats into losses.

### PR #6 review: adversarial attribution fixtures

A one-middlebox fixture cannot reject a detector that always names that middlebox. The new
fixtures contain Client -> FW ingress/egress -> LB ingress/egress -> Server, with a distinct
pcapng interface for each point and a separate alternate return interface where needed.
Each case/location uses a distinct TCP tuple. Assertions identify the case by its evidence
filters, require the exact hop/device (or explicit link with no device), and reject supported
attribution to any other device for that same case. Sharing indexed fixtures avoids redundant
tshark launches; it does not share expected answers with the detector. The common synthetic
clock is exact; independent-clock behavior remains covered by the existing tests.

All seven requested cases run at FW, LB and their connecting link, under IPv4/IPv6 with
zero/constant IDs. Negative controls include a server capture miss, an additional server+LB-side
capture gap that fooled the old detector, no endpoint-side capture, equal raw TTL with and without
sufficient first-appearance evidence, and a pure MTU-sized capture miss. Four weaker standalone
acceptance cases were replaced by this matrix; no new test was marked slow.

Reset attribution remains conservative: consistent endpoint TTL at the candidate's observation
point is compatible with a missed endpoint packet. Unknown endpoint identity/coverage cannot
become a device claim merely because a RST first appears on a device-adjacent capture.

## Phase 3 / Part 2

- Generic full proxies are explicit TCP boundaries. Request correlation never creates cross-proxy packet
  identity or a packet-loss percentage inside the proxy. Existing F5 trailer handling remains separate.
- Pair individual decoded requests, with lexicographic content evidence and mutual one-to-one selection.
  A backend connection may serve many frontend requests. Nearest-time-only pairing is rejected by XFF
  fixtures; equal candidates and contradictory visible HTTP identities remain unknown.
- SNI alone supports a visible TLS-setup association. Encrypted HTTP request boundaries are unavailable,
  so SNI cannot manufacture per-request dwell on pooled encrypted connections. HTTP/2, HTTP/3, chunked
  requests, unsupported/coalesced message boundaries and incomplete response sequences are conservative
  unknown cases, rather than new parsers.
- Use tshark for every protocol field. Isolate capture points before reassembly, because discarded tap
  copies still affect tshark state. Cache the bounded decoded event index, preserve original frame IDs,
  and reuse native DuckDB joins for PDU ranges and candidate generation.
- Use continuous SYN-anchored HTTP/1.x PDU order for pooled response association. tshark's request reference
  can select the last pipelined request; a missing earlier response must never shift attribution.
- Local clock domains allow separate-leg classification. They do not imply a shared proxy clock. Dwell,
  cross-domain propagation and uncertain TLS association remain unknown without alignment evidence.
- Attribute a TLS chain change to the directly supported device first. A chain already inconsistent
  within a leg cannot justify blaming its adjacent full proxy. Server-direction chains only; no trust,
  signature, SAN or certificate-policy validation is claimed. TLS 1.3/resumption without a visible chain
  stays unknown. Expected changes at declared SSL inspection are quality observations.
- Keep every new fixture in the fast suite. Reuse the original tiny multi-interface corpus across test
  cases and overlap independent synthetic preparations; this changes neither production ingest defaults
  nor test selection. Do not add a test runner dependency or move these tests into the slow matrix.

## Phase 3 / Part 3 — packaging

- Reuse the CLI, app and tshark discovery in a single-file console executable. Bundle the UI
  and timezone database; do not redistribute Wireshark or create a second ingest implementation.
- Build natively on three runners rather than cross-compile or require universal native wheels.
  Pin PyInstaller 6.22.3; keep its cache in the ignored build directory.
- Keep packaging off push events to preserve the single cheap push check. PR/manual jobs build
  and smoke all native targets; archive before artifact upload to preserve macOS execute bits.
- Unsigned first-run instructions are per executable. Do not disable Gatekeeper/SmartScreen or
  bypass organization policy. PyInstaller's ad-hoc macOS signature is not publisher signing.

### Assistant placeholder

- Keep the setting off by default and per project. Enabling it only unlocks a local preview;
  no network/provider SDK, prompt execution, API keys or persisted identity dictionary.
- Reuse findings schema 4 and the existing export validation. Do not include packets, report
  snapshots, topology, field diffs or time series in the preview. Preserve metrics and tokenize
  sensitive address/hostname occurrences in nested fields and filter strings consistently.
- This preview is not complete anonymization. Local paths, organizations and arbitrary free-text
  single-label names can remain identifying. Do not offer a send action or automatically copy it.

### Brief audit

- Publish a source/test-backed done/partial/missing inventory, rather than claim the entire brief
  from phase completion. Record partial UI brush/table/graph and transport/security semantics.
- Keep audit gaps report-only. The owner chooses the next independent objective from
  `BRIEF_COVERAGE.md`; no next phase, signing service, provider or detector is started here.

## Phase 4 / Part 1

- Diagnose each flow/direction independently using multiple signals. Do not promote an idle
  zero window, isolated high RTT or pacing gap into a cause. Keep competing limitations unknown.
- Require captured handshake negotiation for scaled windows; retain SYN windows unscaled.
  Use tshark's bytes-in-flight estimate; retain canonical unacknowledged span separately, not a congestion-window guess.
- Use receiver-side local ACK timing to separate it from matched path transit and sender RTT.
  Reuse existing validated HTTP waterfall completion/clock bounds for service time.
- Per-point TCP state must be isolated. A multi-point file without a successful isolated tshark
  cache has unknown transport classification rather than contaminated analysis flags.
- Keep profiles/series lazy and generation-cached, so ordinary packet analysis need not build
  every flow chart. Bound offline profile samples and keep complete selected-flow evidence local.

- Keep fast/spurious/SACK and timer-compatible retry interpretations separate. A generic
  retransmission flag is not sufficient RTO evidence, nor does the one-second conservative
  threshold reproduce every OS TCP timer. Short/unsupported mechanisms remain unknown.
- A first reordering hop needs a matched original pair that reverses arrival order and trustworthy
  independently decoded TCP state. A downstream out-of-order counter alone cannot name a device.
- Extend the existing isolated tshark cache to all required stateful fields; remap RTO frame
  references to original evidence. Never use merged tap copies as independent TCP state.

- DNS ID alone cannot identify a transaction. Require tuple/protocol/question identity and unique
  response ownership; do not pick the nearest retry. Separate local timeout observation from its
  possible resolver/path/capture cause, and retain unknown when the resolver side is not covered.
- Reuse supported path events for DNS disappearance. Do not treat an observed downstream response
  capture miss as network loss or join resolver populations from different points into one latency.
- Stream isolated TCP state into a separate bounded-batch native cache. Dense ACK/flight fields
  must not consume the existing 10,000 HTTP/TLS application-event budget or require whole-capture
  Python mapping. Validate ordinal/tuple/sequence/length/time mapping in SQL.

- Plot byte spans and normalized ACK/window edge, not packet counts. Unknown handshake scale
  suppresses the window line. A local unaligned clock must not silently filter another point.
- Keep packet rendering bounded while rate/RTT aggregates include all observations. Mark partial
  buckets unknown and expose omitted-point counts. Link actual frame evidence on chart clicks.
- Reuse the existing HTTP boundary checks once per flow for service hypotheses instead of
  rebuilding ten complete waterfalls during every profile/export. Pipelining ambiguity suppresses
  service association for the flow, rather than shifting responses.

- A tshark `rto_frame` may point at a neighbouring packet in a first-appearance reordered trace.
  Require that frame to contain the retry's sequence range before calling it RTO-compatible.
  Reordering still needs the original matched-pair reversal; a generic tshark retry hint alone
  cannot identify a loss or ordering cause.
- Keep selected-flow and bounded export results cached by report generation. Batch retry-frame
  evidence and segment lookup rather than performing one SQL query for every observed retry.
  Skip HTTP service scans when prerequisites already force an unknown limitation result.
- Unknown diagnoses retain representative frame evidence. Exact timing, a sender's physical
  bandwidth cap, encrypted application service and short/unobservable TCP timer mechanisms
  remain outside what these captures prove.

- A sender/application hypothesis needs matched timing evidence across every drawn edge of its
  captured TCP leg. Healthy surviving edges cannot vouch for an unmeasurable hop. Supported local
  receiver pressure or a separately supported loss cause remains independent of that path claim.

## Phase 4 / Part 2

- Select IP and its own L4 subtree together from tshark's protocol stack; never zip first/last
  flattened field occurrences, which mixes IPv4/IPv6 envelopes and inner/outer ports.
- ERSPAN is a remote SPAN default: inner identity. Other tunnels require explicit selection.
  Layer selection precedes source-CIDR filtering. Preserve outer context and layer-scoped filters.
- Cache point-isolated decoded layer variants; validate selected frame counts and timestamps,
  retain original frame IDs, bound JSON batches and honor cancellation/file identity changes.

- tshark owns byte reassembly. SQL validates decoded fragment spans/membership, including overlaps,
  gaps, repeated incomplete IDs and truncated records; it does not parse or reconstruct headers.
- Count an assembly once, preserve its member frame filters, and use completion time for a complete
  datagram. Missing members are not multiple lost packets. Ambiguous assemblies cannot prove loss.
- A first observed fragmentation boundary names the drawn device/link, not an unseen internal
  device. Unsupported clocks suppress attribution. A downstream reappearance remains capture miss.

- Measure capture-byte rate over a rolling window, not only fixed bins: a burst crossing a bucket
  boundary must remain visible. Derive a transparent relative threshold; this is not a measurement
  of link capacity or queue depth. Zero-span batching cannot provide an exact duration.
- Bursts and supported next-segment loss onsets are temporally associated only. A burst with no
  loss produces no cause finding, and uncertain clocks cannot assert precedence. Never use this
  association to promote the burst point to a loss suspect.

- A selected outer view must actually become eligible. Strip tunnel markers only from the chosen
  IP/L4 field view, retain outer metadata, and mark incompatible adjacent matching layers unknown.
- Keep logical datagram IP length separate from the final fragment's physical IP length; otherwise
  ICMP reassembly silently changes the match signature. Validate TCP, UDP and ICMP in both families.
- Batch microburst frame evidence once, and use the existing two-worker test fixture pool for the
  new independent datasets. Keep every new test fast; do not hide runtime regressions with marks.

- Layer overlays replace identity fields only; preserve original frame identity/hash and ingest
  timestamp precision. Secondary tshark JSON timestamps are mapping checks, not replacement clocks.

## Phase 4 / Part 3 — bounded pilot readiness

- Keep original captures in place and write the case project beside the capture folder. Preserve
  manual topology edits on resume; do not infer order from file names or silently omit unreadable
  capture names. Ctrl-C signals ingest workers before executor shutdown; completed batches remain.
- Reuse a source capture for additional tshark indexes only when it exactly represents the selected
  point: one interface, no point/vendor/source filters, all records usable, no damaged/zero tail.
  Filtered/invalid-time/tail cases retain isolated decode and validation. tshark remains the dissector.
- Cache a genuinely absent optional pandas import once. DuckDB otherwise repeats filesystem searches
  for every scalar parameter. Installed/imported pandas is untouched; installing pandas in an already
  running process requires restart. Join evidence flow filters instead of querying twice per frame.
- Session fixtures share identical generator arguments after canonicalizing defaults/order. Tests
  that mutate healthy captures clone the shared database; exact-window and scenario-specific fixtures
  keep their original population. Plain IPv4/IPv6 reference decodes are shared across tunnel variants.
  No assertions are removed or weakened and no test is moved to the slow suite.
- Topology node aggregates are observation counts and adjacent segment events, not per-device fault
  totals. Arrow retransmissions cannot override supported loss attribution. Reset-origin cells accept
  supported findings only; an absent/ambiguous origin remains unknown. Full-exchange/selected-packet
  scope is explicitly labelled where brushing must not hide causal evidence.
- Keep the 512 MB DuckDB budget. Wide layer structs are joined in batches of 5,000 physical frames;
  the full-point UPDATE and full-point hash-join prototypes both failed the new corpus. Logical
  fragment replacement preserves the separate physical wire table and capture evidence identity.
- A missing null TLS key after JSON merge does not mean the probe was absent: `transport_index=1`
  proves the first-pass field coverage. Visible TLS, legacy coverage and declared full proxies still
  decode. Clear old protocol state when a new generation needs no application index.
- Use a separate same-input plain-path control when the older engine cannot complete the new
  tunnel/fragment path. Report that failure explicitly; never turn it into a completed baseline
  time or compare unlike functionality as a regression percentage. The successful control remains
  below 20% elapsed/RSS regression; full new-path analysis and cached opening are separate gates.

- Windows case labels use portable relative separators; native file paths remain unchanged.
  Tiny Windows test SQL uses one thread per process and can prefetch three fixtures on four-core
  hosts with 6 GiB available RAM. Production concurrency/memory budgets are unchanged.

- Prepared fixture handles skip repeated initialization only after a real worker build/analysis or
  a closed database copy. Source creation, schema migration and explicit cached reopen acceptance
  continue using the real Project constructor; this is not a production fast-open path.

## Phase 4 / Part 4

- Require the full sequence-consistent local handshake; an ACK flag alone is not establishment.
  Count SYN retries once, and do not manufacture sessions where the SYN was not captured.
- Use a configurable 10-second observation expiry for half-open occupancy. This is neither a
  measured device timer nor its internal session-table occupancy. FIN means closure has started.
- A SYN-rate excursion needs low completion ratios, at least 20 observed sources and three
  sustained buckets (defaults: 50 sessions/s, maximum ratio 0.2). A healthy flash crowd is a
  required negative guard. Source diversity is not proof of spoofing; incomplete deadlines,
  capture loss, translation or clock uncertainty suppress supported absence-based patterns.
- Fan-out alone is insufficient. Default scan pattern: at least 20 destination IP/port pairs in
  five seconds, at least 80% unestablished handshakes, and complete observation deadlines.
  Successful health checks, LB-style traffic and NAT-pool fan-out are mandatory distractors.
  Intent and authorized unsuccessful scanning cannot be distinguished from packets alone.
- Session-table pressure is corroboration, never a measured table capacity/cause. Require the
  same stateful node, an early healthy baseline, a local connection/occupancy excursion and
  aligned positive device-drop evidence at its onset. Supported packet loss without positive
  device-stage evidence yields unknown. Do not promote upstream SYN symptoms to device faults.
- Keep every stopping-hop row in DuckDB and balance representative UI evidence across direction
  and boundary. Bounded examples cannot silently masquerade as the complete failure population.
- Security fixtures use the same captures for healthy rate/fan-out distractors and supported
  faults, with two firewalls and an explicit inter-device link. Native SQL mutants execute rate-only,
  destinations-only and global-drop/spike rules; the acceptance contracts reject all three.
- Prefetch in first-consumer order across every fixture family. Appending special diagnostic
  builds after a late heavy matrix creates a test wait, not a detector regression; do not hide
  it by relaxing assertions, increasing duration gates or moving the new cases to slow.
- Bound work by the observed event population: if even every SYN-anchored session cannot reach
  any pattern/spike floor, skip heuristic joins and remove stale heuristic tables. A no-SYN
  lifecycle uses an empty typed observation source; it cannot manufacture establishment or zeros.
- Keep one full default-threshold security fixture (including the strict occupancy 260 assertion).
  The location/ID/IP-family matrix uses compact traffic with proportionally configured floors;
  healthy distractors still exceed each configured rate/fan-out threshold and every supported/
  unknown, evidence and exact-location assertion remains. Compact occupancy is independently 48.
- SYN patterns use low SYN/ACK **or** established ratio, as requested. A fully replying server
  with no client final ACK is a required wire case; requiring both ratios low would miss it.
  Completion thresholds cannot include a healthy 100% population (maximum configurable 0.5).
- Observation expiry only limits half-open occupancy. Late sequence-consistent handshakes and
  later FIN/RST closure still count; expiry is not a connection lifetime or failure oracle.
- Keep the six-target CI policy. Windows runs the same complete fast collection in two isolated
  pytest processes within each existing job, one fixture worker each. Its unchanged 240-second
  gate measures actual wall time including collection, process startup and teardown. JUnit counts
  must equal the complete fast collection; failures/errors or missing cases fail the job.

## Phase 4 / Part 5

- tshark owns NTP/SNMP/RADIUS/syslog decoding. A protocol transaction identifier correlates
  observed packets; it does not authenticate a response or prove the responder's internal cause.
- Unknown UDP pairing is conditional on declared client direction and a finite response window.
  Reject multiple candidates or reused responses; never choose the nearest candidate to hide
  ambiguity. Known one-way messages are not unanswered requests.
- Protocol fields use a cached, point-isolated secondary decode only when non-DNS UDP is present;
  pure TCP captures retain their existing first pass. Validate source identity and original-frame
  mapping. Reuse bounded native JSON batches instead of widening DuckDB's file permissions.


SSRC and UDP ports alone are not stream identities. Sequence gaps are observations: only supported cross-hop disappearance becomes RTP loss. Downstream arrival jitter does not make the receiver the suspect. One-direction observations alone do not prove audio failure.


Declared ALG rewriting is expected and remains a visible comparison. Undeclared rewriting and advertised/actual media mismatch are separate findings: a valid rewrite is not an ALG bug. Missing endpoint SDP, ambiguous message ownership, unknown clocks, sendonly/recvonly/inactive sessions or absent opposite-leg evidence cannot support a one-way-audio diagnosis. Multi-media SDP, renegotiation and encrypted SIP remain bounded limitations.


Part 5 attribution requires the same coverage/translation/clock support as packet matching. Incomplete candidate replies and positive capture-drop inventories cannot establish a UDP timeout. SNMP responses also need version/community (hashed in reported identity) or visible v3 msgID context, not request ID alone. Native evidence batching and an empty-protocol shortcut replace repeated SQL work; tests remain in the fast suite. Supported one-way audio requires visible bidirectional audio SDP, a unique media-source owner and actual opposite-leg disappearance evidence. Video/sendonly/recvonly/inactive, encrypted or ambiguous SDP is not an invented audio failure. Remaining bounds: one visible audio-media section, initial offer/answer only, 300-second association; ICE/BUNDLE, renegotiation, encrypted SIP/SRTP and auxiliary metadata across vendor-split/tunneled/fragment captures remain unknown rather than pretending packet equivalence. Generic UDP pairing does not authenticate a RADIUS peer or prove why a resolver/device did not respond.

Part 5 Windows follow-up: case counts do not represent fixture cost. The two-process runner co-locates known shared fixture families and schedules using measured per-file elapsed weights, logs actual timing, and still requires exact collected/JUnit coverage and wall time below 240 s. Proxy fixtures join the session prefetch lifecycle, so an early standalone build cannot be generated again by the pool. The checked-in local scheduling weights and hosted VoIP multiplier are estimates for allocation; only actual CI wall time satisfies the gate.
