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
lexical order. User order is authoritative. Full proxy/sequence translation are
recorded as unsupported boundaries in Phase 1 and stop packet-level attribution.

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
