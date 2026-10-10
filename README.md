# PacketBreaker

A local desktop web app for correlating packet captures along a traffic path.
Attach captures, draw capture points, and inspect **which segment first loses an
original packet**, how it is recovered, and the frame evidence supporting that
conclusion. Runs offline after installation. Phase 2 / Parts 1–5: robust ingest, explainable onset detection, a path × time heatmap, translation-aware TCP matching, waterfalls, vendor inputs and offline exports. Later phases remain out of scope.

## Install on macOS (Intel or Apple Silicon)

Install Python 3.11+ (3.12 was tested) and [Wireshark](https://www.wireshark.org/download.html).
Keep Wireshark in `/Applications`; PacketBreaker finds the bundled tshark without
requiring a PATH change. From this source directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/packetbreaker
```

The prebuilt frontend is included. Node is not needed to install or run the app.
To install the built wheel instead, use `python -m pip install
/path/to/packetbreaker-0.1.9-py3-none-any.whl`, then run `packetbreaker` in that
Python environment. This project has not been published to PyPI.

## Install on Windows 10/11

Install Python 3.11+ from [python.org](https://www.python.org/downloads/windows/)
and Wireshark with its **TShark** component. The normal
`C:\Program Files\Wireshark\tshark.exe` path is detected automatically. In PowerShell,
from the extracted source directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\packetbreaker.exe
```

Use `py -3.11` instead if that is the installed version. Alternatively install the
wheel using the virtual environment's Python. Activation and administrator
privileges are not required to run PacketBreaker. It does not capture live traffic.
Windows and Intel macOS are CI targets; local validation was on Apple Silicon.

## First run

`packetbreaker` opens `http://127.0.0.1:8765` and uses `~/PacketBreaker/default`.
Use `packetbreaker --project /path/to/case` for a separate project. Each directory
contains one `project.duckdb`, uploaded files under `captures/`, and temporary SQL
spill space. Keep the directory on a local disk. One process owns a project at a time.

- **Captures:** attach absolute local paths (no copying), or upload files. Ingest
  runs in the background; Cancel keeps committed batches and Resume continues.
- **Path:** add/drag capture points, assign files and optional interface filters,
  and connect arrows. Give ingress/egress points the same device name. Draw a
  return path only when it differs from the reversed forward path. Save topology.
- Set **client networks** to identify forward traffic, including translated
  client addresses. The app does not guess direction from address sort order.
- **Analyze path:** inspect capture quality, clock alignment, hop-level latency,
  ranked findings and the flow table. Each finding links to file/frame filters.
- **Settings:** set a tshark override if auto-detection fails, choose a payload
  prefix (8–4096 bytes), adjust the 200 ms stall threshold, or override clocks.
  Changing the prefix requires reattaching files to rebuild their indexes.

Files are identified by resolved path, size, modification time, parser version and
prefix settings. Reopening a completed project reads DuckDB, without reparsing.
On resume tshark replays earlier frames to reconstruct TCP analysis state, then
PacketBreaker appends only after the last committed frame. Resume is not a byte
seek into a stateful TCP dissection. Keep source files unchanged for evidence to
remain verifiable; attached files are not copied into the project.

## Five-minute synthetic tutorial

Use the virtual environment command above in place of `packetbreaker` if it is
not on PATH. On Windows substitute backslashes where appropriate.

```sh
packetbreaker demo demo --scenario demo
packetbreaker --project demo/project
```

1. **Captures:** five files describe Client → FW ingress → FW egress → LB ingress
   → Server. Their deliberately offset clocks range from −80 ms to +250 ms, with
   drift. The timestamps use a fixed synthetic epoch, not current traffic.
2. **Path:** the firewall is declared as NAT. Confirm a suggested mapping (its reverse is included) and
   click **Save mapping decisions**, then **Analyze path**. The two directions
   now describe one canonical conversation. Before confirmation, affected results
   are explicitly inconclusive.
3. **Overview:** expect **4 impactful loss**, **5 recovered loss** events between
   **FW egress and LB ingress**, and **8 capture misses** at FW ingress. Click a
   finding: the original/retransmitted frames and per-file Wireshark filters are
   shown. The maximum recovery wait is approximately **301 ms**, including the
   next segment's transit. It is not firewall processing time.
4. **Onset + heatmap:** the confirmed demo detects the first degradation at
   **FW egress → LB ingress**, bucket **14 s** relative to the synthetic epoch.
   Read the measured baseline, threshold and evidence. Select **Network loss (%)**
   or **Transit p95 (ms)** in the heatmap. Brush the loss interval to filter flows,
   findings and the ladder. Grey **NC** means not capturing, not zero loss. Clear
   the selection before inspecting the beginning of the connection.
5. **Flows:** select the conversation and open **Where did the time go?**. The
   handshake has outbound SYN, server turnaround, returning SYN/ACK, client
   turnaround and outbound ACK. Select an HTTP request to inspect transmission /
   retry time, every link/device dwell, server processing and first-response
   return time. Every bar shows clock uncertainty and opens its original frame
   evidence. Unknown bars have no invented width. The ladder below provides the
   packet-by-packet view; teal means original and amber means retransmission.
6. **Export HTML / Export JSON:** use the header buttons. HTML opens locally as a
   single file; its metric-selectable heatmap, onset markers and evidence filters
   work without the running app or Internet. JSON follows
   [findings schema v3](docs/findings-v3.schema.json). Both export the complete
   saved analysis window, independent of the current brush. Neither embeds packet
   payloads; addresses and filters are still sensitive investigation metadata.
7. **Settings:** inspect clock estimates/calibration frames, then stop with Ctrl+C.
   Reopen the project to reuse its packet index and report. For CLI exports, run:

   ```sh
   packetbreaker --project demo/project export --format html --output demo/report.html
   packetbreaker --project demo/project export --format json --output demo/report.json
   ```

   Omit `--output` to write to stdout. Existing output files are not overwritten.
   The live per-flow waterfall is not batch-generated into the offline report.

For an already-confirmed demo use `packetbreaker demo demo --scenario demo
--confirm-demo-nat`. This flag applies only to the generated synthetic project.
Other scenarios: `healthy`, `capture_miss`, `acked_unseen`, `recovered_loss`,
`impactful_loss`, `nat`, `delay`, `truncation`, and `duplicate`.

The generator's Python API also accepts point count, offsets, drift, loss hop,
loss start time, added delay, NAT hop and capture-miss point. It writes ground
truth and topology JSON next to the captures. Part 2 adds `onset_loss`, `onset_delay`,
`onset_propagation` and `onset_capture_miss`: 40-second fixtures with explicit
hop/time ground truth, also available with `--ip-id zero|constant` and `--ipv6`.

## What PacketBreaker measures, estimates and leaves unknown

| Result | Meaning |
|---|---|
| Packet appearances | Matching protocol identity, canonical tuple and common captured payload prefix; concrete file/frame refs |
| Capture miss | Absent at an intermediate point but present farther downstream, or acknowledged without preceding retransmission |
| Recovered / impactful loss | Original absent downstream, with matching bytes delivered by a later retransmission; impact uses recovery time/repeat count |
| Clock offset and drift | Estimates from bidirectional minimum-delay envelopes and a robust linear fit; asymmetry remains uncertainty |
| Per-hop latency | Clock-corrected matched-packet transit; negative/inconsistent values are suppressed, not clamped |
| Handshake halves and RTT | Same-capture SYN/SYN-ACK/ACK intervals and tshark TCP ACK RTT, with frame references |
| Unrecovered disappearance | Covered absence is `unrecovered_loss`; a reset or observed stall makes it impactful. Policy cause stays unknown. |
| First event time | First observed classified event; distinct from change-point onset |
| Degradation onset | Sustained rolling event-count or latency departure from a measured baseline, with threshold and frame evidence |

Repeated fingerprints are matched as separate time-ordered occurrences. Only
byte-identical full frames within the configured microsecond threshold are marked
as potential SPAN copies; unresolved timing collisions are explicitly excluded. Truncated captures compare only common payload bytes. Unsupported
identities and fragmentation are flagged. Differently segmented TCP captures use sequence byte coverage; affected points show an offload note. Checksums
are not classified as network errors. Missing pcapng drop counters mean **unknown**,
not zero. Observed first/last timestamps cannot prove continuous capture coverage.

TCP conversation rows join local streams through shared packet occurrences;
port-reuse sessions remain separate. UDP/ICMP use endpoint conversations. Retransmission observations are counted per capture point, not globally
unique retransmissions. Covered UDP disappearance without delivery evidence is unrecovered loss with an
unknown cause; insufficient coverage/clock/translation evidence remains unknown. Recovery/ACK searches are bounded to 60 seconds; longer waits remain unknown. Window changes affect hop findings/latency; conversation inventory
and drilldown retain the full selected captures for context. The heatmap brush additionally
filters flow membership, findings and ladder packets without refitting the baseline.

Declared full proxies stop packet-level attribution. Declared sequence randomizers
learn session-specific offsets; inconsistent or insufficient evidence stays unknown.
Fragment reassembly,
tunnel decapsulation selection, additional vendor adapters,
MTU/security attribution, packaging as native executables and the AI placeholder
remain deferred beyond Parts 1–5. Positive device-drop classification awaits device-stage evidence.

## Offline JSON / API

```sh
packetbreaker --project demo/project analyze > analysis.json
packetbreaker --project demo/project analyze --topology demo/topology.json
packetbreaker --project demo/project --port 8766 --no-browser
```

The internal analysis report schema (version 2) includes `window`, `clocks`, `quality`, `nat_suggestions`,
`segments`, `findings`, `flow_count` and interpretation limits. Findings include
`type`, `severity`, `hop`, `direction`, `time_range`, `confidence`, `metrics`, and
`evidence` with file/frame/display-filter references. Report findings are capped
at 200; event/flow/ladder APIs are paginated. The UI shows the top five findings.
The separate `packetbreaker.findings` export schema is version 3 and exports all
grouped findings, with `evidence_refs`, plus saved report metadata, buckets and
per-file flow filters. `GET /api/export?format=html|json` returns a download;
`GET /api/flows/{flow}/waterfall` returns the on-demand timeline.

The loopback API is same-origin only. Mutations require `X-PacketBreaker: local`;
foreign Host/Origin/cross-site requests are rejected. There is no authentication,
cloud integration, telemetry, remote agent or runtime CDN dependency. DuckDB
external access and automatic extension loading are disabled except the bounded
local CSV load during ingestion. Project files contain addresses, packet prefixes
and local paths; they are not encrypted. Do not serve this app through a public proxy.

## Development and validation

```sh
python -m pip install -e '.[test]'
cd frontend
npm ci
npm run build
cd ..
ruff check src tests tools
pytest -q                 # default fast suite
pytest -m slow -q         # exhaustive real-tshark matrices
# pytest -m "slow or not slow" -q  # both suites in one invocation
python -m build
```

Wireshark/tshark is required for tests: missing tools fail the acceptance gate
instead of silently skipping packet tests. CI builds the UI, installs tshark,
runs the fast suite on Windows and macOS (Intel/Apple Silicon), Python 3.11/3.12
for PR/manual checks. Push checks remain macos-14/Python 3.12, fast only. The slow
real-tshark matrices run only on PR/manual macos-14/Python 3.12. The repository is
public; this review revision was pushed with `[skip ci]` at the user's request.

`tools/benchmark.py` generates a configurable, synthetic multi-file workload and
reports measured ingest/analysis times. Example:

```sh
python tools/benchmark.py /path/to/scratch --hops 10 --rounds 10000
```

Ingest uses bounded 50,000-row batches; analysis uses DuckDB SQL with a 512 MB SQL
memory budget and disk spill. tshark has its own memory usage. A five-file,
5.4M-frame benchmark with one 1.31 GB file is measured. Large real-world incidents,
larger files and ten simultaneous multi-GB captures remain **unverified**; see
[validation notes](docs/VALIDATION.md) for the measured workload and remaining gaps.

Design: [architecture](docs/ARCHITECTURE.md), [decisions](docs/DECISIONS.md).

### Phase 1.1 synthetic coverage

`--ip-id increment|zero|constant|random` and `--ipv6` exercise identical
retransmissions without relying on changing IP IDs. Additional demo scenarios:
`syn_blocked`, `unrecovered_reset`, `unrecovered_stall`, `control_capture_miss`,
`realistic_healthy`, `realistic_capture_miss`, `realistic_loss`, and
`realistic_syn_blocked`. Realistic scenarios have 50 concurrent clients, a reused
TCP tuple, mixed IPv4/IPv6, DNS and ICMP, a separate return capture point and a
pcapng ISB. One-way points use explicit ground-truth clock overrides in fixtures.

### Phase 1.1 upgrade and evidence

Older packet indexes need one reattach for full-frame hashes and DNS/ICMP metadata.
A current-schema project keeps its index across an engine upgrade; the old analysis
report is invalidated and recomputed on Analyze. Loss rates are unknown below the
configurable 90% matchability threshold. Headline rates expose their exact
denominators and local/UTC times with clock uncertainty. Evidence dialogs offer
frame, content and per-file flow filters; content filters can select multiple
identical retransmissions after merging.

For the large benchmark, install `.[benchmark]` and run the stages of
`tools/large_benchmark.py` under `/usr/bin/time -l` on macOS. dpkt remains an
experiment: its complete measured speedup was 1.07x, below the required 2x gate.

## Phase 2 / Part 1 ingest behavior

Known damaged final records preserve preceding usable frames with a visible
warning. Zero-filled suffixes are detected at container boundaries and tshark is
limited to preceding record count. Out-of-range timestamps are quarantined and
never used for coverage or clock fitting. Older indexes need one reattach for
timestamp validation; completed validated indexes still reopen from cache.

Inventory distinguishes header snaplen, maximum stored caplen and the observed
truncation range. Serial ingestion is the default after the equal-file re-check.
Optional parallel attach/upload runs one tshark per file, bounded by
`min(files, CPU cores - 1, floor(available RAM / 1.6 GiB))`. The job panel supports
per-file cancellation/resume; completed files survive other file failures. SQL
commits stay serialized. A segment now has one headline with short finding-class
lines. Parallel can be enabled in Settings or with `demo --parallel-ingest`.

## Phase 2 / Part 2 investigation

Analyze the path, then use **Overview → Path × time**. Select a metric and drag
horizontally to filter flows, findings and ladder packets. Grey `NC` means not
capturing; `?` means partial/unknown coverage or an unavailable metric, never zero.
Clear selection returns to the full analysis. Flow totals and the executive onset
summary describe the complete analysis; the selection does not refit its baseline.

Settings exposes the bucket width (1 second by default); save and re-analyze after
changing it. Onset explanations show baseline, MAD, threshold, first crossing and
confirming bucket, with clickable evidence. The executive summary lists temporal
propagation order and explicitly unknown baselines. Earliest observed segments
are suspects, not proof of device causation. Clock uncertainty still applies.

`GET /api/timeseries` returns stored buckets and metric tooltips. Optional `start` /
`end` parameters on `/api/flows`, `/api/findings`, `/api/events` and flow `/ladder`
use a half-open interval in corrected Unix seconds.

### Reviewed onset behavior (0.1.4)

Loss and TCP event signals use a rolling window of 15 seconds, rounded up to whole
buckets (at least two). They require at least three excess events in at least two
event buckets. Onset is backdated to the first event bucket of that sustained run;
the report separately records the later confirmation/threshold-crossing bucket.
This detects intermittent losses, including the NAT-confirmed README demo, without
calling a single event or one isolated bucket an onset. The count reference is
kept fixed so intervening quiet buckets cannot train away a sparse change.

Capture misses and unknown events are quality notes, never loss counts or reasons
to reject otherwise covered/matchable baseline samples. Per-segment and per-metric
status remain visible; one unknown segment does not override other valid results.
Retransmissions, failed handshakes, RSTs and zero windows have count-floor onsets.
Local retransmission/reset/window changes do not establish the network-loss hop;
only segment-backed loss, delay and blocked handshakes enter prime-suspect ordering.

Additional fixtures: `onset_intermittent_2` through `onset_intermittent_5` and
`onset_random_loss` (seeded Bernoulli p=0.02; realized counts are ground truth).

## Phase 2 / Part 3 translation-aware matching (0.1.5)

For a sequence-randomizing device, add adjacent ingress and egress capture points
with the same device name and select **Seq randomization (learn offsets)**. Confirm
any NAT tuple mapping first. The overview shows each session's directional SEQ/ACK
offsets and anchor evidence. Filters retain the actual headers at each capture;
normalization never changes the source file. Insufficient anchors or inconsistent
offsets leave the affected session unknown, with an explicit reason.

TCP segmentation/coalescing is detected from large frames and overlapping sequence
ranges in linked sessions. One source frame may cover several downstream frames,
or the reverse. Findings expose missing byte ranges and original frame references.
Loss counts mean affected source frames; byte counts/rates provide the comparison
when captures have different segmentation. The tool does not invent a wire-packet
count inside a coalesced frame. Offload checksum artifacts are not network errors.
The bounded range index supports up to one million derived observations per analysis;
exceeding that budget requires splitting the captures. Legacy indexes that excluded
superframes are marked stale and must be reattached once.

Upstream retransmission onsets are labeled **symptom observed here (sender
retransmits)**. Only independently supported loss segments receive a loss-suspect
badge; seeing the sender retry does not locate the fault at that capture point.

Synthetic scenarios `sequence_randomization`, `sequence_inconsistent` and `offload`
include ground truth. The first uses per-session offsets plus intermittent loss
after the translating device; the offload fixture combines 64 KB sender frames,
MSS segments, receiver coalescing, sequence wrap and a separate capture miss.

## Waterfall interpretation limits

HTTP/1.x must be cleartext, with a captured request line and complete header bytes
in the stored prefixes. Content-Length request bodies are tracked by TCP sequence
coverage, including out-of-order arrival. Missing prefixes are never reconstructed
from guesses. If headers are incomplete, choose a larger payload prefix in Settings
and reattach the captures to rebuild the index. Chunked requests, pipelining, TLS
and response-body download timing are not decoded. Full-proxy boundaries explicitly
show **unknown (full proxy, Phase 3)**. The view is bounded to 20,000 observations
per flow, 8 KiB headers, 8 MiB request bodies and 100 request choices.

Clock correction estimates contain path-asymmetry uncertainty. Even a positive
bar duration is an estimate; invalid/unverified intervals remain unknown. Offload
timestamps represent coalesced capture units, not precise per-wire-frame times.
Server processing measures the interval between observed complete request receipt
and first final response byte; it is not an application CPU profile.

## Vendor inputs (0.1.7)

All packet/vendor dissection is performed by tshark. The adapters select decoder
options, retain its fields and select capture points. Reattach older indexes once
to obtain the new vendor fields. Do not run live device commands through this app.

| Input | How to use it | Evidence boundary |
|---|---|---|
| Check Point fw monitor snoop | Attach `.cap`/`.snoop`; tshark's fw monitor interpretation and chain fields are enabled. In Settings select the UUID file variant only if the capture contains it. In Path, map each inspection stage to a point with the same device name; optionally filter `fw1.interface`. | An i disappearance is confirmed only with mapped I/o stages, explicit continuous-coverage attestation, sufficient trailing coverage and no capture-quality/unsupported-proxy problem. Later appearances contradict a drop. |
| F5 BIG-IP TMM trailer | Enable **Decode F5 TMM trailer** in Settings, attach/reattach the capture, then add client/server points for one BIG-IP node, choose **F5 TMM trailer** and use precise client CIDRs. | Reciprocal flow/peer IDs and local streams pair the legs. They remain separate TCP conversations. Overview shows request-forwarding dwell and TMM-reported reset origins. |
| Palo Alto stage files | Add receive/firewall/transmit/drop points for one device. Receive/transmit become ingress/egress. Drop can remain off the forwarding path; a drop-only project is supported. | Every usable drop-stage frame is positive device-drop evidence. The stage is a user file tag, not a decoded packet property; keep original file provenance. |
| Fortinet verbose-6 text | In Captures, use **Import Fortinet verbose-6 text**, supply its absolute path and device name. Points are created per interface; draw the actual path afterward. | Absolute `a` timestamps are UTC. Relative timestamps require a timezone-bearing start and retain low clock confidence, including after reattach. |

Inspection-stage order is not necessarily the reversed physical return path. Map
the actual stages/interfaces and draw an explicit return path when required. VPN
inspection stages and other transformations are not automatically treated as a
linear forwarding chain. UUID is exported as metadata, not used alone as packet
identity. Unattested inspection gaps remain unknown, not inferred network loss.

F5 request timing is the same-capture interval between tshark-decoded HTTP request-
bearing frames. It is not a whole-body completion or application processing metric.
Per-packet peer IDs handle multiple peers on one server TCP stream. Reused IDs
across ambiguous sessions, repeated identical request lines, unequal request counts
and reversed ordering remain unknown. The overview is bounded to 100 pairs, 20
unknown mappings, 200 requests and 200 reset annotations; full vendor metadata
remains in the per-flow frame ladder. Capture-byte throughput can include vendor
trailer/header overhead. No device policy cause is inferred from reset text.

Fortinet CLI import is also available:

```sh
packetbreaker --project demo/fortinet import-fortinet /absolute/path/sniffer.txt
packetbreaker --project demo/fortinet import-fortinet /absolute/path/relative.txt --start-time 2026-10-09T12:00:00Z --device FGT
```

The converter copies formatted hex bytes; it does not dissect protocols or repair
missing bytes. CRLF, wrapped hex and console noise are tolerated. Skipped lines
and incomplete packets are reported. Explicit cooked-link metadata is checked against tshark Ethernet/SLL/SLL2
decodes; only an unambiguous matching link type is used without altering bytes.
Incomplete/ambiguous cooked metadata is reported and skipped; a text dump ending cleanly at a byte
boundary cannot reveal unseen trailing bytes. The project retains conversion
provenance; copying a bare pcap elsewhere does not carry that clock annotation.
No code from unlicensed FortiGate-PCAP or any other converter was copied.

**Confirmed device drop** is visible in the summary, device overlay, flow filter
and export schema v2. Each finding names its device and evidence stage. Positive
stage evidence replaces the matching inferred disappearance, retaining recovery
metrics without counting the same event twice. Unpaired drop-stage observations
remain visible with an unknown rate denominator. All proof rows are persisted;
the overview's vendor audit samples at most 200 references.

The optional Wireshark sample `demo/samples/fw1_mon2018.cap` remains gitignored.
`pytest tests/test_checkpoint.py::test_local_fw1_sample -q` runs only if it exists
and is skipped in CI. All required adapter fixtures are generated synthetically.


## Path integrity (0.1.8)

In **Flows**, select a stream and click **Field diff** beside a packet. The table compares raw
addresses/ports, TTL or hop limit, DSCP, MSS, window scale, SACK/timestamps, sequence offset,
payload SHA-256 and IPv4 ID across matched points. Each comparison opens its frame/content/flow
filters. IPv6 has no IPv4 ID; unavailable fields and incomplete payloads remain unknown.
HTML and JSON exports include a bounded sample distributed across segments with the same tables
and filters. The stream API can inspect another selected occurrence on demand.

The overview adds reset/ICMP origin evidence, downstream-only observations, unexpected payload
changes, size-selective MTU/PMTUD patterns, MSS clamping, TTL deviations, option stripping,
DSCP remarking, asymmetric return paths and capture/duplication observations. Hover a finding
for its rule and limitations, then open its evidence. A first appearance is conditional on
capture coverage; TTL/IP ID patterns never authenticate a sender. MTU is a hypothesis unless
additional device evidence establishes the cause. Unreported capture loss can mimic disappearance
or injection. These checks do not inflate loss percentages or nominate a device from TTL alone.

Declare **Payload transformation** (proxy, ALG or SSL inspection) in the path editor when
expected. Full proxies still have no end-to-end packet identity; their field comparisons remain
unknown. This part does not implement TLS decryption or general full-proxy request correlation.
Reattach older capture indexes once to populate schema-6 path fields. Real captures remain local.


PR #6 attribution hardening (0.1.9): identify capture endpoints as **Client** / **Server**
in the path editor. A middlebox at the beginning of a path is not an endpoint capture;
reset origin stays unknown with `no endpoint-side capture`. A server-compatible TTL pattern
at the first observation also leaves capture miss unresolved. Links are explicitly named
(e.g. `link between FW egress and LB ingress`) with no device assignment. Updating from
0.1.8 invalidates the old analysis report; run **Analyze path** again.
