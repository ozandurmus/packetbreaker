# PacketBreaker

A local desktop web app for correlating packet captures along a traffic path.
Attach captures, draw capture points, and inspect **which segment first loses an
original packet**, how it is recovered, and the frame evidence supporting that
conclusion. Runs offline after installation. Phase 1.1 correctness hardening. Phase 2 has not started.

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
/path/to/packetbreaker-0.1.1-py3-none-any.whl`, then run `packetbreaker` in that
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
4. **Flows:** select the conversation. Inspect per-point handshake halves and
   local tuples, then the packet ladder. Teal lines are original observations,
   amber lines are retransmissions, and red × marks missing appearances.
5. **Settings:** inspect estimated clock offsets/drift, uncertainty and calibration
   frames. Close the terminal with Ctrl+C and reopen the same project: indexed
   captures and the saved report are reused.

For an already-confirmed demo use `packetbreaker demo demo --scenario demo
--confirm-demo-nat`. This flag applies only to the generated synthetic project.
Other scenarios: `healthy`, `capture_miss`, `acked_unseen`, `recovered_loss`,
`impactful_loss`, `nat`, `delay`, `truncation`, and `duplicate`.

The generator's Python API also accepts point count, offsets, drift, loss hop,
loss start time, added delay, NAT hop and capture-miss point. It writes ground
truth and topology JSON next to the captures. Phase 2/3 fixture types are not yet
implemented.

## What Phase 1.1 measures, estimates and leaves unknown

| Result | Meaning |
|---|---|
| Packet appearances | Matching protocol identity, canonical tuple and common captured payload prefix; concrete file/frame refs |
| Capture miss | Absent at an intermediate point but present farther downstream, or acknowledged without preceding retransmission |
| Recovered / impactful loss | Original absent downstream, with matching bytes delivered by a later retransmission; impact uses recovery time/repeat count |
| Clock offset and drift | Estimates from bidirectional minimum-delay envelopes and a robust linear fit; asymmetry remains uncertainty |
| Per-hop latency | Clock-corrected matched-packet transit; negative/inconsistent values are suppressed, not clamped |
| Handshake halves and RTT | Same-capture SYN/SYN-ACK/ACK intervals and tshark TCP ACK RTT, with frame references |
| Unrecovered disappearance | Covered absence is `unrecovered_loss`; a reset or observed stall makes it impactful. Policy cause stays unknown. |
| First event time | First observed classified event; **not** a change-point onset estimate |

Repeated fingerprints are matched as separate time-ordered occurrences. Only
byte-identical full frames within the configured microsecond threshold are marked
as potential SPAN copies; unresolved timing collisions are explicitly excluded. Truncated captures compare only common payload bytes. Unsupported
identities, fragmentation and possible large offload frames are flagged. Checksums
are not classified as network errors. Missing pcapng drop counters mean **unknown**,
not zero. Observed first/last timestamps cannot prove continuous capture coverage.

TCP conversation rows join local streams through shared packet occurrences;
port-reuse sessions remain separate. UDP/ICMP use endpoint conversations. Retransmission observations are counted per capture point, not globally
unique retransmissions. Covered UDP disappearance without delivery evidence is unrecovered loss with an
unknown cause; insufficient coverage/clock/translation evidence remains unknown. Recovery/ACK searches are bounded to 60 seconds; longer waits remain unknown. Window changes affect hop findings/latency; conversation inventory
and drilldown retain the full selected captures for context.

Declared full proxies and sequence randomizers stop packet-level attribution.
Automatic sequence offsets, offload byte-range matching, fragment reassembly,
tunnel decapsulation selection, vendor inspection-point adapters, change-point
onset/heatmaps, waterfall, HTML export, MTU/security attribution, packaging as
native executables and the AI placeholder belong to Phase 2/3. No Phase 2 work is
included. Positive device-drop classification awaits device-stage evidence.

## Offline JSON / API

```sh
packetbreaker --project demo/project analyze > analysis.json
packetbreaker --project demo/project analyze --topology demo/topology.json
packetbreaker --project demo/project --port 8766 --no-browser
```

JSON schema version 1 includes `window`, `clocks`, `quality`, `nat_suggestions`,
`segments`, `findings`, `flow_count` and interpretation limits. Findings include
`type`, `severity`, `hop`, `direction`, `time_range`, `confidence`, `metrics`, and
`evidence` with file/frame/display-filter references. Report findings are capped
at 200; event/flow/ladder APIs are paginated. The UI shows the top five findings.

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
pytest -q
python -m build
```

Wireshark/tshark is required for tests: missing tools fail the acceptance gate
instead of silently skipping packet tests. CI builds the UI, installs tshark,
runs real five-file ingest/API tests, and builds distributions on Windows and
macOS (Intel/Apple Silicon), Python 3.11/3.12. CI runs require pushing this source
to a GitHub repository; no remote repository was created by this delivery.

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
