# PacketBreaker — Phase 1 architecture

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
keys (for example UDP with zero IPv4 ID), preserving different snaplen support. A signature occurring more than once at any point is ambiguous and
is excluded from loss/latency attribution (SPAN duplicates/repeated datagrams).
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
Only unambiguous, supported TCP data / UDP / ICMP appearances are eligible.
An absent intermediate point followed by a downstream appearance is a capture
miss. A covering ACK without a preceding retransmission also supports a capture
miss (within the same local TCP stream, bounded modular sequence comparison).
A delivered retransmission of the same byte range supplies recovery evidence;
recovery >= configured stall threshold or repeated upstream attempts is impactful, otherwise
recovered loss. Coverage/clock/translation uncertainty takes priority over network
attribution. Unrecovered disappearance is unknown/suspected, not proof of device
policy drop. Confirmed device drops require positive device evidence, absent from
generic Phase 1 PCAP. Missing ACK-only packets do not become network-loss events.
A retransmission is a different wire packet; its wait is not per-hop transit time.

Results use explicit denominators (eligible data transmission observations, including retries), first
observed event time (not a Phase 2 change-point onset) and bounded/paginated evidence.

ACK and retry evidence must belong to the original local TCP stream. Recovery and
ACK searches are bounded to 60 seconds; longer waits remain unknown.
