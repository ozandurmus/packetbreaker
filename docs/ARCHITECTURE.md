# PacketBreaker — Phase 1.1 architecture

## Boundary and components
Python 3.11+, FastAPI bound only to 127.0.0.1, a bundled React/TypeScript UI,
React Flow topology editor and ECharts coverage/ladder plots. `packetbreaker`
starts one local process and opens a browser. No telemetry, remote resources,
live capture, AI service or network dissection. tshark is the protocol authority.
One project directory contains `project.duckdb`, uploaded captures and temporary
batch files. Attached captures stay at their original path. The CLI also exposes
a synthetic demo and offline analysis for reproducible checks.

Ingest is a serial background job with cancellation, progress and transactional
checkpoints. tshark exports fields with name resolution disabled. Bounded CSV
batches enter DuckDB using COPY/read_csv; no entire capture becomes Python objects.
A metadata-only pcap/pcapng block walker reads snaplen/link/interface/drop options;
it never dissects packets. Completed files are cached by path/stat, parser version
and hash-prefix settings. Resume replays tshark up to the committed frame because
TCP analysis needs preceding history, but does not duplicate committed records.
File changes invalidate partial/completed caches. SQL joins and aggregation spill
to project-local DuckDB temporary storage under a 512 MB SQL memory budget.

## Data model
- `settings`: versioned project settings, topology and latest report JSON.
- `captures`: source identity, state/checkpoint, inventory, failure message.
- `packets`: `(capture_id, frame)` plus observed timestamp, interface, IP/L4 fields,
  wire/captured lengths, bounded payload prefix and digest, raw TCP seq/ack/flags,
  Wireshark TCP analysis flags, stream id and unsupported/truncation indicators.
- Analysis tables: selected observations, canonical flow identities, packet
  appearances, flow summaries and classified missing appearances.
- Every finding: schema version, type, severity, segment, direction, time range,
  metrics, confidence, explanation and file/frame evidence with display filters.

## Topology
Nodes own capture points; paths are ordered point IDs obtained from directed
React Flow edges, with an optional separately drawn return path. A point selects
a file and optional interface plus a source CIDR filter. Reused interface IDs across multiple pcapng sections are rejected when an interface filter is requested. Several points may use
the same file with different filters. Forward direction is explicitly defined by
client CIDRs (including translated addresses). Never infer direction from address
lexical order. User order is authoritative. Full proxies stop packet-level
attribution. Part 3 learns declared sequence-randomization boundaries per session;
insufficient or contradictory translation evidence leaves that session unknown.

## Matching
Forwarding-invariant candidates combine protocol, IPv4 ID/IPv6 flow label, TCP
raw seq/ack/flags/segment length or ICMP identity/type, and canonical directional
5-tuple. TTL, checksums, MAC/VLAN, DSCP and changed NAT endpoints are excluded.
Payload prefixes are compared over the common captured length, never by a full
frame hash. A SQL minimum-prefix pass disambiguates otherwise identical structural
keys (for example UDP with zero IPv4 ID), preserving different snaplen support. Repeated signatures retain separate corrected-time occurrences. A most-observed
point supplies ordered anchors; predecessor/successor ASOF joins choose the nearest
monotone, one-to-one occurrence within the match window, after subtracting a
normal relative-transit estimate for matching only. Lost originals leave a gap,
not a shifted occurrence index. Genuine timing collisions stay explicitly unknown.
SPAN duplicates are a separate rule: equal tshark full-frame MD5 at the same
point, full snaplen and a nonnegative gap <=20 microseconds (configurable).
Fragments, super-frames and unknown/insufficient transport identities are also
excluded with visible quality limitations; Phase 2/3 owns their richer handling.

NAT suggestions use unique payload-bearing invariant signatures on the two sides
of a declared NAT device. At least three agreeing packet pairs and a consistent
time difference are required, and mappings must be one-to-one. Suggested endpoint
5-tuples remain unapplied until the engineer confirms or supplies a correction.
Confirmed mappings canonicalize both directions and combine per-hop tuples into
one logical flow. Conflicting mappings are rejected, never silently merged.

## Clock model
For observed timestamps B-A, forward minima bound offset from above; reverse
maxima bound it from below. Their midpoint is an estimate under minimum-path
symmetry, not a measurement of true offset. Half the bound width is uncertainty.
Use independent equal-duration bins, minimum-delay envelopes and median pairwise
slopes to estimate linear drift. Fit only with adequate samples and temporal span;
otherwise offset-only or unknown. One-way traffic cannot identify clock offset.
Fit against an already aligned point with shared packets in reference-clock coordinates; propagate offset uncertainty and allow explicit overrides.
Same-file interfaces share a clock. Negative corrected delays invalidate latency
for that segment rather than being clamped. Report uncertainty/confidence and
calibration frame references. Apply correction before computing overlap.

## Classification
Supported TCP data and SYN/SYN-ACK/FIN/RST, UDP and ICMP appearances are eligible.
An absent intermediate point followed by a downstream appearance is a capture
miss. A covering ACK without a preceding retransmission also supports a capture
miss (within the same local TCP stream, bounded modular sequence comparison).
A delivered retransmission of the same byte range supplies recovery evidence;
recovery >= configured stall threshold or repeated upstream attempts is impactful, otherwise
recovered loss. Coverage/clock/translation uncertainty takes priority over network
attribution. Covered unrecovered disappearance is `unrecovered_loss`, or impactful when
followed by a reset or observed stall; its cause is unknown. A stopped handshake
is high severity. Insufficient coverage, clocks or translation stay `unknown`. Confirmed device drops require positive device evidence, absent from
generic Phase 1 PCAP. Missing ACK-only packets do not become network-loss events.
A retransmission is a separate occurrence, possibly with identical bytes; its wait is not per-hop transit time.

Results use explicit denominators (eligible data transmission observations, including retries), first
observed event time (not a Phase 2 change-point onset) and bounded/paginated evidence.

ACK and retry evidence must belong to the original local TCP stream. Recovery and
ACK searches are bounded to 60 seconds; longer waits remain unknown.

## Phase 1.1 / item 1

Clock calibration uses independently unique signatures (after SPAN deduplication);
this restriction never discards retransmissions from loss classification. IPv4
ID modes increment/zero/constant/random and constant-flow-label IPv6 are synthetic
fixture dimensions. DuckDB project schema 2 adds frame hashes. Opening a schema-1
project preserves captures/topology but marks indexes stale and clears the old
report; reattach once to rebuild with tshark's frame hash.

## Phase 1.1 / item 2

Each directional segment exposes matchable fractions at both endpoints, the lower
`eligible_ratio`, and explicit excluded counts by reason. Unknown-direction rows
count against quality rather than silently disappearing. Below `min_eligible_ratio`
(default 0.9), aggregate `loss_percent` is null and the segment states the excluded
fraction/reasons. Concrete eligible-packet findings remain visible. Such a segment
cannot produce a healthy overall verdict. The threshold is editable in Settings.

## Phase 1.1 / item 3

TCP data and SYN/SYN-ACK/FIN/RST enter missing-appearance classification. SYN/FIN
ACK coverage consumes the control byte; RST has no ACK-delivery assumption.
Same-local-stream reset, retransmission or non-advancing ACK after the stall
threshold supports impactful unrecovered loss. A covered, unrecovered SYN/SYN-ACK
produces `handshake_blocked` (high severity, unknown cause). Covered disappearances
without recovery/impact evidence use `unrecovered_loss`; `unknown` is reserved for
insufficient coverage, clocks or translation. Positive device-drop attribution
still requires device evidence. Failure/ACK support frames accompany the original.

## Phase 1.1 / item 4

TCP stream identities are local to a capture. Build a small graph of distinct
local streams joined by shared packet occurrences at neighboring points, then
JOIN its components back onto observations. This preserves reused-port sessions
without running Python per packet. DNS transaction IDs/response flags and ICMP
echo IDs/sequences come from tshark. A response without an intervening retry can
prove delivery through a capture gap just as a TCP ACK can. Schema 3 adds those
fields; older indexes require a one-time reattach. Realistic fixtures include 50
concurrent clients, 51 TCP sessions, both IP versions, DNS, ICMP, an asymmetric
return point and ISB counters. One-way points cannot estimate their own offsets;
known fixture clocks are explicitly supplied as overrides, not inferred values.

## Phase 1.1 / item 5

Headline sentences query the event table and eligible upstream observations from
the first observed data-loss event through the selected window end. They expose
the exact numerator/denominator, quick recoveries, measured stalls and other
outcomes. "No loss observed upstream" is allowed only with complete matchability
and reliable prior segments in that same interval. Otherwise upstream comparison
is explicitly inconclusive. The browser supplies its IANA timezone; JSON records
local and UTC event times plus the clock uncertainty caveat. First event time is
not a Phase 2 change-point onset. Later unrelated resets do not inflate recovered
packet stall metrics.

## Phase 1.1 / item 6

Direction, reversed/canonical tuples and source-CIDR membership are computed only
for distinct tuples/addresses, then joined in SQL. No Python UDF runs per packet.
Ingest checkpoints now contain at most 50,000 rows. Whole-table metadata, clock,
occurrence and session transforms use CREATE TABLE AS SELECT rather than UPDATE;
the latter exhausted the 512 MB SQL budget at 5.4M rows. Analysis disables
insertion-order preservation and explicitly orders occurrences. Spill remains
project-local. NAT candidate scans are restricted to declared NAT boundaries;
unmapped tuples at those boundaries remain translation-unknown even with clock
overrides. Equal-size repeated sequences use their monotone ordinal pairing;
unequal sequences use nearest-time gaps within the window. dpkt remains a
benchmark-only dependency; its measured complete path did not meet the 2x gate.

## Phase 1.1 / item 7

Every supported IP/L4 evidence reference retains its exact file/frame selector and
adds a content selector using the observed local tuple, IPv4 ID or IPv6 flow label,
raw TCP seq/ack/length/flags (or DNS/ICMP identifiers). Content selectors deliberately
may match identical retransmissions or multiple capture copies after merging.
Per-file flow filters use observed post-NAT tuples in both directions and the
selected session's raw timestamp range, widened by one microsecond for stored
floating-point timestamp rounding. Metadata is built once per flow/file/tuple,
not once per packet. The UI offers all filters and all classified flow outcomes.

## Phase 1.1 / item 8 and release integrity

TestClient uses httpx2 with Starlette >=1.7. Starlette deprecation warnings are test
errors, not suppressed warnings. Project metadata carries the analysis engine
version; changing it clears old reports without reparsing current-schema indexes.
The application and bundled frontend identify themselves as 0.1.1.

## Phase 2 / Part 1: damaged final records

A known tshark cut-short tail error after usable frames is recoverable. Committed
and pending batches are retained and the capture becomes ready with a visible
warning and usable count. The pcapng metadata walk tolerates an incomplete final
block so tshark can read preceding packets. Other errors and zero usable frames
still fail. Completed warned captures use the normal cache and do not resume-loop.

## Zero tails and timestamp validity

The metadata walker scans the trailing zero suffix once, then walks only container
record/block boundaries. A padding suffix supplies an exact physical record limit
to tshark (`-c N`), including any invalid-time records before the suffix so original
frame numbers are retained. Zero-tail counts are 16-byte pcap record-header slots
or 12-byte minimum pcapng block slots; byte counts are exact. Protocol payloads are
not dissected by this walker.

Frames before 2000-01-01 or later than ingest-start + one day are recorded in
`excluded_frames` with their reason, not in the packet index. Coverage, overlap,
clock fitting and Gantt therefore only use validated timestamps. Timestamp quality
also caps segment matchability conservatively at the whole-capture level because
invalid times cannot be assigned to a selected interval. Schema-4 migration marks
old indexes stale until this one-time validation occurs; stale Gantt ranges are hidden.

## Declared versus observed capture lengths

Inventory retains every interface's declared header snaplen and independently
reports observed maximum caplen and the min/max caplen of truncated packets.
A fixed truncation limit is stated only when observed truncated records agree.
Current indexes can derive these values from stored columns without reparsing.

## Parallel ingest

Batch ingestion uses one tshark subprocess per file, with workers equal to the
minimum of unique files, CPU cores minus one, and floor(available RAM / 1.6 GiB).
A zero resource budget is an explicit error. Each file has a separate cancellation
token/checkpoint/progress record; global cancellation reaches all workers. A failed
or cancelled file does not discard completed files. DuckDB commits remain serialized
through the existing project lock. Multi-file uploads are staged, then ingested as
one batch. Cache hits do not spawn tshark. `psutil` supplies cross-platform RAM data.

## Segment-level headlines

Each segment owns one aggregate headline, clock caveat and headline denominator.
Its finding classes retain short independent lines and evidence links. Multiple
classes no longer repeat the same aggregate sentence; the executive view ranks
unique segments and shows their class lines below the shared headline.


Part 1 ships as 0.1.2, invalidating older cached analysis reports so the segment
headline shape is regenerated; current-schema packet indexes remain reusable.

## Phase 2 / Part 2: bucketed path observations

`segment_buckets` stores a grid for every directed adjacent segment. Epoch-aligned
buckets default to 1 second (`bucket_seconds`, 0.1–3600 seconds). The grid covers
the requested interval, or the union of validated capture coverage; missing-loss
classification remains bounded by the analysis overlap. Outside endpoint coverage
is `not capturing`, missing clock coverage is `unknown coverage`, boundary buckets
are `partial coverage`, and unavailable
metrics are SQL NULL. Zero is used only for an observed zero count/rate in a full
covered bucket. The grid is limited to 200,000 cells; larger windows require a
coarser bucket or a narrower interval.

Rates use upstream observations, loss classes use eligible upstream candidates,
and transit quantiles use matched eligible packet occurrences. RTT remains local
tshark ACK RTT, not isolated hop transit. Each metric carries its unit and exact
meaning in the API. Coverage bounds cannot establish capture continuity.

Onset baselines use five early covered, matchable samples. Loss needs an initially
loss-free reference; capture misses and unknown events only add quality notes.
Count signals use a fixed reference event count/exposure and per-bucket MAD, then
a rolling 15-second evidence window rounded up to whole buckets (minimum two).
The window must exceed the robust baseline threshold and contain at least three
excess events across two buckets. The reported onset is the first excess-event
bucket; the later threshold crossing and confirmation are stored separately.
Latency retains rolling median/MAD and two consecutive crossings.

Raw loss, TCP, retransmission and failed-handshake counts persist beside displayed
rates. Counter onsets do not reconstruct integer counts from rounded percentages.
Rates use summed denominators over the window; count-only metrics use event counts
per bucket. Failed handshakes count each session at its first blocked attempt; SYN
retries remain packet-loss events but do not create additional failed connections. Covered/matchable samples with quality notes remain available. Missing
metric values are reported per metric, not used to invalidate every other signal.
Summary status aggregates segment results as detected/none/partial/unknown.

Retransmission, reset and zero-window onsets are local capture signals with original
frame evidence. They are excluded from network-hop prime-suspect ordering; supported
loss, matched transit p95 and blocked handshakes retain segment attribution.

The heatmap is an ECharts grid with metric selection, missing-data states and onset
diamonds. A horizontal brush selects a half-open corrected-time interval. Flow rows
are filtered by observations in the interval (their totals still describe the full
analysis); findings are regrouped from interval events with fresh frame evidence;
ladder packet identities and event/point metrics are filtered by time. Analysis and
its baseline remain unchanged when brushing. Onset summaries remain full-window.

The per-bucket matchable fraction is checked independently at both endpoints. A
brief unmatchable interval cannot inherit a healthy whole-window ratio and turn
into a false zero-loss cell or onset. Part 2 ships as 0.1.3; old reports are
invalidated, while current packet indexes remain reusable.

Review 0.1.4 invalidates old reports while retaining packet indexes.
Default pytest excludes registered `slow` real-tshark matrices and large repeated-analysis fixtures;
explicit slow selection runs every matrix case. No tests were deleted.

## Phase 2 / Part 3: declared sequence randomization

Adjacent ingress/egress points of the same declared device learn per-connection
modulo-2³² SEQ/ACK translations. Independent payload/ID anchors link local streams;
three packet correspondences and two observations for each directional offset are
required. Any contradictory offset marks the affected connection unknown rather
than selecting a majority. Raw packet SEQ/ACK stay in the index and in content
filters; only analysis coordinates are normalized. Frame evidence exposes both
coordinate systems. Other connections remain independently matchable.

## Part 3: offload-aware TCP coverage

Physical `obs` rows stay intact for pps, throughput, frame filters and local TCP
counters. Differing segmentation creates a separate bounded `byte_obs` table of
shared sequence intervals. SYN/FIN consume sequence-space units without adding
payload bytes; wrap is split at 2³². Clock fitting can use unique first-byte/prefix
anchors, and occurrence matching keeps original and retransmitted ranges separate.
`byte_links` records one-to-many coverage; `byte_missing` retains missing ranges and
byte counts. Recovery must cover every missing interval, and ACKs after an earlier
range retry cannot prove a pure capture miss. Partial conflicting delivery support
is unknown rather than an inflated whole-frame network-loss claim.

Counts are affected upstream capture frames; at an MSS capture point a missing MSS
segment is one loss. Byte totals quantify partial/coalesced frames and flow bytes
are deduplicated across representations. Evidence uses original positive frame
numbers and raw headers, with sequence-range context; no virtual atom ID leaks into
Wireshark filters. Offload/coalescing notes are visible on the affected points.
Checksums are not classified as network errors. Legacy excluded-superframe indexes
require reattach to rebuild missing segmentation/fragment metadata.

Range expansion is limited to one million observations and 65,535 boundaries in
one frame; larger inputs must be split. Payload equality is checked only where both
captured prefixes exist. Conflicting/reused range content becomes unknown, and
offload capture timestamps are not individual wire-segment timestamps.

Retransmission onset records carry a display label, a false local suspect flag
and related downstream loss segments. `symptoms.py` joins the onset's observed
retransmitting sessions to independently classified loss events within its time
window. Segment loss-suspect badges derive from loss classes, preserving the
distinction between sender symptoms and a supported disappearance boundary.

## Phase 2 / Part 4: on-demand waterfalls

`waterfall.py` reads normalized observations for one TCP session when the flow
inspector requests a timeline. It traces matched physical frames (or shared byte
occurrences for offload) over every ordered forward/return edge, distinguishing
links from same-device ingress/egress dwell. The three-way handshake includes
server SYN/ACK turnaround and client final-ACK turnaround. HTTP shows the client
transmission/retry span, request-completion traversal, server processing from all
request bytes received to the first final response, and its return traversal.
Each bar retains original per-file frame filters and clock uncertainty. Negative
or unverified clock intervals, missing evidence and full proxies remain unknown.

HTTP reads contiguous captured header prefixes, recognizes Content-Length and
tracks sequence coverage including out-of-order body delivery. It does not invent
bytes missing from prefixes. Chunked requests, overlapping/pipelined requests and
TLS are not decoded. The on-demand budget is 20,000 observations per flow, 8 KiB
headers, 8 MiB requests and 100 selectable request starts. These limits are visible;
no waterfall work is added to the full-capture analysis pass.

## Part 4: offline export

`export.py` validates a `packetbreaker.findings` envelope (schema version 1) before
serializing JSON or HTML. The contract is published in `findings-v1.schema.json`;
its version is separate from the internal analysis report schema. Every finding
has a type, hop, time range, metrics, evidence refs and confidence. The analysis
persists the complete finding list for export, independent of the UI's 200-row
summary cap. Export takes a locked snapshot of that report, stored buckets and
per-file flow filters. It includes the complete saved analysis window, independent
of the live heatmap brush, and contains no raw packet payloads.

HTML embeds escaped metadata, inline CSS and a small canvas heatmap renderer; it
has no external assets or requests. Its CSP disables network connections. Capture
labels and evidence text are HTML-escaped; embedded JSON escapes markup delimiters.
Coverage gaps remain not-capturing cells, partial/unknown cells stay distinct from
zero, and metric tooltips/onset markers remain available offline. Summary, onset,
findings, segments and filters are plain HTML and remain readable without scripts.
The live per-flow waterfall is not precomputed for every flow during export.

Waterfall frame refs are resolved in one batch after constructing the stages,
then reused across bars. The flow inspector does not issue a separate metadata
lookup for each bar. The 0.1.6 analysis version refreshes reports while retaining
compatible packet indexes.

## Part 5 vendor metadata: Check Point

Snoop RFC 1761 container framing is read for inventory only. tshark performs all
protocol decoding with `eth.interpret_as_fw1_monitor:TRUE` and chain display on.
The UUID file variant is an explicit ingest setting (`fw1.with_uuid`); it changes
the header's interface-name width and is never guessed. The four exported fw1
fields remain in per-frame vendor metadata and original evidence refs.

Each stage maps to a distinct point of one node using one file; overlap is rejected.
The inspection audit reuses matched occurrence identities. An unmatched i event
is confirmed only with explicitly attested continuous stage coverage, mapped I/o
points, no container/timestamp/drop-counter problems and enough trailing coverage.
Later appearances, including O/additional inspection points, contradict the disappearance.
Unattested or incomplete capture evidence stays unknown. The separate audit feeds
the final confirmed-device-drop integration. Ordinary tshark TCP flags can include
repeated inspection appearances; they are not independent device-drop evidence.

F5 trailer decoding is enabled with tshark's `--enable-protocol f5ethtrailer`.
Raw flow/peer IDs, peer addresses/ports, ingress, VIP, processor and reset-cause
fields are retained (including multiple peer-field occurrences). The adapter
pairs reciprocal nonzero IDs within a capture and slot/TMM namespace, checking
local TCP streams for reuse and client CIDRs for an unambiguous role. Client and
server TCP conversations remain separate; the proxy is not packet-forwarding.

Request forwarding dwell uses tshark-decoded HTTP request-bearing frames on the
paired legs. Distinct request lines match one-to-one; repeated identical lines,
unequal counts and reversed time order remain unknown. This is not whole-body
completion or server processing. Same-capture timing cancels clock offset. The
request budget is 2,000 observations per pair; reset annotations retain TMM's
rstcausetxt verbatim as evidence, not an independently inferred policy diagnosis.

Palo Alto files receive explicit receive/firewall/transmit/drop tags for one node.
Receive/transmit map to ingress/egress; drop and other auxiliary stage points need
not be forwarding-path edges. Auxiliary observations are indexed for evidence and
positive session links, but do not shorten the common path coverage interval.
Every usable drop-stage frame is positive device-stage evidence, regardless of
whether cross-capture clocks are aligned. Unaligned evidence retains observed time.
A drop-only investigation is allowed without inventing a network path.

Fortinet verbose-6 import is an original text/container converter. It copies only
hex bytes into nanosecond pcap records and splits interfaces into separate files
and points; tshark then performs ordinary dissection. Absolute `a` timestamps are
UTC and retained exactly. Relative timestamps require an ISO start with timezone,
and low clock confidence persists through cache/reattach. Split interfaces share
the transcript's clock domain, not independently inferred file clocks.

CRLF, ANSI console coloring, ASCII gutters and indented hex continuations are
handled. Malformed/gapped hex causes that packet to be skipped, not zero-filled or
spliced. Noise/skipped lines and packets are counted. Explicit cooked-link metadata is compared against tshark Ethernet/SLL/SLL2
decodes. Only a unique matching link type is used; bytes are never rewritten.
Ambiguous or incomplete cooked metadata is reported and skipped. At a byte boundary, unseen
trailing bytes cannot be inferred from text alone. Conversion has 64-interface and
16 MiB per-frame limits and creates only new owned output directories; cancellation
checks run while streaming the text. Provenance survives interrupted ingest.

## Confirmed device-drop integration and export v2

`device_proofs` persists every vendor evidence row in DuckDB, with device, stage,
source frame, time basis and coverage status. SQL batches build and associate proof
rows; display refs are bounded and resolved together. A unique packet identity can
link a PA auxiliary stage to a path event without guessing a clock offset. Positive
evidence upgrades that event to `confirmed_device_drop`; unmatched evidence gets
a device-stage finding with no invented upstream loss-rate denominator. Capture
misses are not relabeled as disappearance proof. Inferred recovery metrics remain.

Unknown inspection-stage absences are not ordinary network-loss claims. Confirmed
counts feed the executive summary, node/edge overlay, flow filters, time series
and exports. Standalone stage evidence has no healthy path baseline for an onset.
The export contract is now `packetbreaker.findings` version 2; confirmed findings
require nonempty `device` and `evidence_stage`. Version 1 remains documented for
old consumers. F5 forwarding/reset metadata is also inspectable in offline HTML.

### Format references

- [Snoop RFC 1761](https://www.rfc-editor.org/rfc/rfc1761).
- [Wireshark fw1 fields](https://www.wireshark.org/docs/dfref/f/fw1.html) and
  [tagged fw1 dissector](https://github.com/wireshark/wireshark/blob/v4.6.9/epan/dissectors/packet-fw1.c).
- [Wireshark F5 fields](https://www.wireshark.org/docs/dfref/f/f5ethtrailer.html) and
  [tagged trailer dissector](https://github.com/wireshark/wireshark/blob/v4.6.9/epan/dissectors/packet-f5ethtrailer.c).
- [Check Point fw monitor options](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_CLI_ReferenceGuide/Topics-CLIG/FWG/fw-monitor.htm).
- [Fortinet sniffer KB](https://community.fortinet.com/fortigate-3/troubleshooting-tip-using-the-fortios-built-in-packet-sniffer-for-capturing-packets-96295)
  and [timestamp format reference](https://docs.fortinet.com/document/fortigate/7.0.11/administration-guide/680228/performing-a-sniffer-trace-cli-and-packet-capture).

Wire-layout references inform only synthetic test construction. Production vendor
fields and expected test values come from tshark; no third-party captures are
embedded in tests or tracked.

## Phase 3 / Part 1 — path integrity

Matched-packet field differences use raw headers beside the normalized occurrence identity.
The index adds tshark-decoded TCP options, IPv6 DSCP, DF/ICMP metadata and a complete-captured-payload
SHA-256 (separate from the existing matching prefix). Schema 6 / parser 9 require reattaching older
captures. `/api/packets/{packet_key}/field-diff` supplies stream drill-down comparisons and evidence.
Offline HTML and JSON include a labelled, bounded 200-comparison sample. Truncated payloads,
missing fields, unsupported boundaries and offload segmentation are unknown, not modifications.

PMTUD checks require three distinct disappearing large sequence ranges plus three passing small
payload segments of the same flow. They report a size-selective black-hole pattern, not a proven
MTU cause. IPv4 DF, IPv6, MSS clamping and ICMP feedback are separate evidence. Quoted ICMP TCP
headers are retained as quoted metadata and never mistaken for the outer packet's transport.
Feedback association requires the quoted tuple and raw sequence to match an observed flow.
Protocol references: [RFC 1191](https://www.rfc-editor.org/info/rfc1191/),
[RFC 8201](https://www.rfc-editor.org/info/rfc8201/), and
[Wireshark ICMP fields](https://www.wireshark.org/docs/dfref/i/icmp.html).

Path-integrity checks run after normal loss/onset analysis and contribute separate finding
classes, not network-loss numerators. Before loss classification, complete payload changes can
join a unique canonical tuple/SEQ/ACK/flags/length pair within a calibrated match window; the
joined occurrence is propagated downstream. This avoids calling a modified-but-observed packet
lost. Ambiguous retries, segmentation differences and unsupported proxy identity remain unknown.
Checks batch adjacent-edge queries in DuckDB and bound representative findings with visible notes.
Origin evidence includes endpoint TTL/IP-ID samples, vendor metadata and capture-quality gates.

Schema-v3 integrity types are `reset_origin`, `icmp_origin`, `payload_modified`,
`downstream_packet`, `mtu_black_hole`, `mss_clamping`, `ttl_path`, `dscp_remark`,
`option_stripping`, `asymmetric_routing`, `capture_duplicate`, and `duplication`.
Normal endpoint-origin reset observations are quality annotations; only a bracketed device-origin
hypothesis gets high severity. Findings include their rule tooltip and portable frame references.
Window filtering includes integrity findings. Generic full-proxy correlation remains unsupported.

### PR #6 review — multi-device attribution (0.1.9)

Origin checks require an explicitly declared Client/Server capture at the source end of the
selected direction. A first middlebox capture cannot substitute for it. Matched endpoint
reference packets project the observed TTL distribution to the candidate's first capture point;
raw TTL equality at different path positions is not the comparison. An endpoint-compatible
pattern leaves capture miss unresolved, including with zero/constant IDs. Device first-appearance
and coverage/clock gates still apply. IP ID observations do not authenticate a source.

Unique header-matched payload changes are indexed once in `modified_payload_pairs` and used
both to join the physical occurrence and to produce findings. This works across inter-device
links as well as inside a device. Expected ALG transformations exempt the device boundary,
not an adjoining link. Link findings retain `device=null` and an explicit link label.

Asymmetry groups a completely bypassed device into one observation, and separately recognizes
a return-path detour between two otherwise-present points. Both bounding return points and an
alternate-path observation of the same flow are required. A detoured link is never assigned to
either adjacent device. Existing report-version invalidation clears pre-fix reports on upgrade.
