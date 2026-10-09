# PacketBreaker validation — through Phase 2 / Part 2 review

The Phase 1.1 measurements and regression results below supersede the historical
Phase 1 checks. The later Phase 2 / Part 1 section records the currently authorized infrastructure changes. Other Phase 2 work remains unstarted.

## Historical Phase 1 baseline (2026-10-08)

Environment: Apple Silicon macOS, Python 3.12.8, tshark 4.6.9, Node 24.21.0.
The automated suite exercises the real tshark executable, not a mocked dissector.

- All 37 tests passed in the final full suite (33.59 seconds), including the
  NAT reverse-confirmation, configurable NAT hop, reused-session ACK isolation,
  repeated short-loss classification and 64 KB super-frame ingestion checks.
- Tests cover five-file ingest → topology → analysis → JSON, plus HTTP API jobs,
  project reopen, no-tshark cache hits, cancel/resume without duplicated frames,
  file-change invalidation, actual pcapng conversion and cumulative ISB counters.
- TCP loss/recovery and capture-side misses match synthetic ground truth: correct
  segment and first observed event within one second. Pure capture misses never
  become supported network loss in the tested scenarios.
- NAT candidates require confirmation; one confirmed mapping includes its reverse.
  Conflicting tuples are rejected and canonical conversations collapse after confirmation.
- Offset/drift calibration matches synthetic ground truth (offset within 0.1 ms,
  drift within 0.6 ppm); long-window drift, one-way ambiguity and negative-delay
  suppression are tested. These tolerances describe the fixtures, not accuracy
  guarantees for real capture clocks.
- Truncated payloads, repeated fingerprints, UDP with reused zero IP ID, unsupported
  tunnel identities and large offload frames are covered.
- Ethernet, raw IP, Linux SLL/SLL2 and QinQ fixtures were dissected successfully.
- Foreign Host/Origin, missing mutation header and malformed topology/settings
  are rejected. DuckDB external reads are disabled by default.
- TypeScript check and Vite production build passed. Ruff passed.
- Manual browser checks: overview, flow table, per-point handshake metrics,
  multi-hop ladder, evidence dialog with frame filters, topology assignments and
  NAT decisions. No browser console errors were observed in those checks.
- A wheel and source distribution were built with the prebuilt UI included.
  Installing the wheel into a separate directory and serving its HTML/JS/CSS
  through the API succeeded; imports were verified to come from that installation.

## Measured scale smoke test

`python tools/benchmark.py /private/tmp/packetbreaker-scale --hops 10 --rounds 10000`

| Measurement | Result |
|---|---:|
| Input files | 10 |
| Input size | 38,903,740 bytes (38.9 MB) |
| Total frames | 300,050 |
| Ingest wall time | 25.69 s |
| Analysis wall time | 3.61 s |
| Directional segments with matches | 18 / 18 |
| Segments with unknown latency | 0 |
| Verdict | No supported network loss in selected window |

This is a synthetic warm-environment smoke test on this machine, not a throughput
promise or a memory benchmark. The earlier run measured 23.79 s ingest and 3.59 s
analysis. Multi-GB-per-file input, 10+ simultaneous multi-GB captures and peak RSS
remain unverified. The design bounds application ingest batches and uses SQL spill;
tshark has its own state and memory requirements.

## Not verified / deliberately outside Phase 1

Windows and Intel macOS execution were not available locally. GitHub Actions
contains a Windows/macOS Intel/Apple Silicon × Python 3.11/3.12 matrix, but it has
not been executed because no remote repository or workflow run was created.
No real incident captures, production devices or live capture interfaces were used.
No code was committed, pushed or deployed to a production service.

Phase 2/3 onset detection and fixtures (full proxy, sequence randomization,
MSS/MTU black holes, vendor inspection stages, injected reset, offload byte-range
matching) are not implemented. First-event timing is not change-point detection.
A generic missing egress packet is never labeled a confirmed device drop.

Historical Phase 1 warning: Starlette requested a newer TestClient transport.
Phase 1.1 resolves it by using httpx2; it is now a test failure if reintroduced. Vite reports a large local
ECharts/React Flow bundle (~1.6 MB uncompressed); it is bundled, with no CDN fetch.

## Work accounting

Work started at 15:39:58 Europe/Istanbul. Final test/usage checkpoint was at
16:42:21 (approximately 62 minutes). Account-wide weekly usage read 9% at
the start and 15% at the final checkpoint. This is a 6 percentage-point account-wide
change, not exact per-task token usage or cost; other account activity may contribute.

## Phase 1.1 baseline reproduction

Baseline commit: `9ec5879` (`Phase 1 baseline`). The real tshark ingest of the
`recovered_loss` fixture with every IPv4 ID forced to zero produced 10 ground-truth
losses but zero findings and 0.0% on all eight directional segments. Excluded
packet counts were 20/20/20/10/10 by capture point. The baseline incorrectly said
"No supported network loss in the selected window". Before/after acceptance now
uses every existing scenario across four IPv4 ID modes and IPv6.

Item 1 after: the same zero-ID input now yields **10 recovered losses**, all at
`forward:p2:p3`, and **0 exclusions** at every point. The 80-case scenario × ID mode
× IP-version matrix passed in 151.93 seconds. No Phase 2 implementation was used.

Item 2 tests cover explicit exclusion reasons, the default 90% guard, threshold
overrides, and SPAN-copy quality degradation. Frontend TypeScript/build passed.

Item 3: 32 control/failed-delivery × IP mode × IPv4/IPv6 cases passed. Fixtures
include stopped SYN, unrecovered data followed by RST or a measured stalled
sequence, and pure capture misses of SYN/SYN-ACK/FIN/RST. A directional hop check
also verifies reverse SYN/ACK capture-miss location.

Item 4: 17 real-tshark integration cases passed in 111.19 seconds: four realistic
scenarios × four ID modes, plus all-IPv6 TCP. Each contains >=50 concurrent clients,
port reuse, DNS query/response, ICMP echo, a different return point and an actual
pcapng ISB. Tests assert 51 separate TCP sessions (52 with the blocked connection),
no cross-tuple occurrence collisions, exact per-hop/direction ground truth and
zero network-loss findings for pure capture misses, including DNS/ICMP requests
missing at multiple downstream points.

Item 5: headline checks verify the demo's 9 losses (5 quick recoveries / 4 measured
stalls), exact data-packet denominators, omission of upstream no-loss claims under
incomplete matchability, event-date DST handling, and isolation of an unrelated
later reset from quick-recovery stall metrics. TypeScript/build passed.

## Phase 1.1 large benchmark (item 6)

Five real synthetic PCAP files: **5,400,750 frames / 1,414,852,620 bytes** total.
The largest file has **5,000,150 frames / 1,310,010,524 bytes**; each of the four
others has 100,150 frames. Fifty concurrent TCP streams. The smaller files cover
a prefix, so common-window metrics cover that prefix, while indexing and analysis
preparation process all 5.4M rows. Twenty-five boundary capture misses were correctly
supported by ACK evidence; there were no network-loss findings.

| Measurement | Wall time | Throughput | `/usr/bin/time -l` peak RSS |
|---|---:|---:|---:|
| Production ingest, all 5 files | 279.10 s | 19,350 frames/s | 1,605,877,760 B (1.50 GiB) |
| Analysis, all indexed rows | 85.83 s | — | 1,884,618,752 B (1.76 GiB) |
| tshark-only ingest, largest file | 257.34 s | 19,430 frames/s | Included above |
| dpkt core index, largest file | 154.93 s | 32,273 frames/s | Included in hybrid below |
| Mandatory tshark enrichment of dpkt | 84.52 s | — | Included in hybrid below |
| Complete dpkt + tshark hybrid | 239.51 s | 20,877 frames/s | 2,071,838,720 B (1.93 GiB) |
| Exact full-row equality check | 7.01 s | 5,000,150 rows / 40 fields | 862,846,976 B |

**Equality: zero mismatched rows across all 40 stored fields**, including tshark's
TCP analysis flags. Raw first-pass speedup: **1.66x**. Complete speedup: **1.07x**.
**dpkt not adopted**: neither meets the required 2x threshold. The experiment is
limited to the full-snaplen Ethernet/IPv4/TCP workload; it is not a new production
parser or a claim of equivalence for all capture formats.

Commands: `tools/large_benchmark.py generate|ingest|analyze|dpkt|verify DIRECTORY`;
timed stages were prefixed with `/usr/bin/time -l`. The first sandboxed run lacked
OS counters (`sysctl kern.clockrate` was denied), so an uncached index was rebuilt
with read access to those counters. That repeat is the table above. The original
279/285-second ingest logs and the failed UPDATE analysis log are retained in the
scratch benchmark directory. The first large analysis failed at 23.85 s with a
512 MB allocation error; after replacing whole-table UPDATEs with CTAS, the same
input completed. These are warm local SSD runs; caches were not flushed. Timed
phases ran serially. RSS is the high-water mark reported by time, not a sum of
simultaneous process footprints. Ingest parent RSS was 667,746,304 B and tshark
child RSS 1,605,877,760 B. The SQL memory budget is not a process-RSS cap.

Exact machine-readable results: [phase11-benchmark.json](phase11-benchmark.json).

Item 7: five tests passed using the real tshark/mergecap tools. IPv4 zero-ID and
IPv6 filters locate the same packet timestamps after merge to pcapng despite
renumbered frames. Per-file flow filters select all 80 frames of the NAT fixture
and use the translated tuple at egress. DNS and ICMP identifier filters are run
against their source files. Flow rows expose blocked/unrecovered/unknown outcomes,
not only the original three counters.

## Phase 1.1 final release checks (item 8)

The test extra now uses HTTPX2 >=2.13 with Starlette >=1.7. A subprocess regression
runs TestClient with Python warnings promoted to errors and asserts HTTPX2 is the
active transport. The API checks pass without the old deprecation warning. No
warning suppression was added. Engine upgrades invalidate cached reports while
preserving current-schema packet indexes; a regression covers that migration.
Application/CLI and bundled frontend version: **0.1.1**.

The final zero-ID demo contains 4 impactful losses, 5 quick recoveries and 8 capture
misses, all matching ground truth. Its headline reports the measured 9/74 (12.16%)
data-packet loss rate from the first loss onward, local and UTC timestamps, 55.6%
quick recovery / 44.4% measured stalls, maximum 0.301 s, and clock uncertainty.
These fractions intentionally use that stated time-range denominator, not the
whole-capture packet count.

Final gates: **183 tests passed in 378.41 seconds, with no warnings**. Ruff passed;
TypeScript/Vite production build passed. The 0.1.1 wheel was installed into a
separate directory; its API, HTML and bundled JS/CSS passed with warnings-as-errors.
The large performance table records the item-6 implementation; subsequent portable
filter metadata/UI and TestClient changes were verified functionally, not rerun
as another large performance experiment.

Phase 1.1 work accounting: start 2026-10-08 19:40:22 Europe/Istanbul; final usage
checkpoint 22:06:25 (about 146 minutes). Account-wide weekly use changed from 15%
to 28% (13 percentage points); this is not exact per-task token usage or cost.
The elapsed time exceeded an efficient delivery for this scope; it included
repeated validation and the bounded large-file measurement/recovery work.

No Phase 2 work, remote push, live-device access or production capture was used.
Windows/Intel macOS CI execution remains unverified locally; the matrix is in
`.github/workflows/ci.yml`. The measured workload and unverified larger/real-world
workloads must not be conflated.

## Phase 2 / Part 1 acceptance

Scope is limited to ingest/CI robustness, inventory, parallel ingest and segment
headline deduplication. Tail fixtures are generated in tests for both pcap and
pcapng: incomplete final records, zero-filled suffixes, invalid timestamps in the
middle, future timestamps, combinations and header/observed snaplen mismatch.
A separately authorized local-only manual acceptance check passed. No real input,
address, source path or decoded packet content is included in tests or this report.

Focused local gates passed for tail/timestamp/length handling, per-file parallel
cancel/resume, API behavior and headline grouping. Push CI uses only macos-14 and
Python 3.12. Pull requests and workflow dispatch use the full six-job matrix.
Application and bundled frontend version: **0.1.2**. The local wheel built with
installed build tools (`--no-isolation`) and passed isolated-package API, HTML and
bundled-asset checks. Isolated local build dependency download was unavailable in
the sandbox; CI performs the normal isolated build. The suite contains **203 tests**
(up from 183). The authorized local manual
check retained exactly **302,152 packets**, spanning **12:59:00.000103–12:59:43.540715
Europe/Istanbul**, and ignored 141,516,731 zero-tail bytes / 8,844,795 record slots.
No invalid-time records remained among those usable packets.

### Same-input serial / parallel benchmark

Both modes rebuilt fresh indexes from the same five synthetic files used for the
Phase 1.1 benchmark: **5,400,750 frames / 1,414,852,620 bytes**. The largest input is
**5,000,150 frames / 1,310,010,524 bytes**. This isolates the concurrency change using
the same current ingest implementation: one worker before, automatic budget after.
The machine has 10 logical cores; available RAM was 8.57 / 8.27 GB at the respective
starts. The automatic resource budget selected **4 workers**.

| Mode | Ingest wall time | End-to-end `time -l` wall | Frames/s | `time -l` peak RSS | Sampled process-tree peak RSS |
|---|---:|---:|---:|---:|---:|
| Serial (1 worker) | 293.49 s | 293.71 s | 18,402 | 1,277,034,496 B | 1,795,883,008 B |
| Parallel (4 workers) | 302.45 s | 302.67 s | 17,856 | 1,205,960,704 B | 1,804,189,696 B |

Parallel ingest was **3.1% slower** on this strongly skewed workload, where one
file contains most frames. No throughput improvement is claimed. Process-tree
peak RSS rose by 0.46%; individual file counts were exactly equal in both runs.
`time -l` reports a per-process high-water mark; the separately sampled 100 ms
process-tree sum measures concurrent processes and can count shared pages twice.
Neither is an enforced total RSS cap. Runs were sequential, with warm local SSD
caches and no cache flush. The 1.6 GiB worker budget is a scheduling estimate.

Reproduction: prefix `python tools/parallel_benchmark.py serial|parallel
SYNTHETIC_INPUT_ROOT FRESH_OUTPUT_ROOT` with `/usr/bin/time -l` (on macOS). The input
root contains `captures/point-0.pcap` through `point-4.pcap`; use a fresh output
root per comparison. [Machine-readable measurements](phase2-part1-benchmark.json)
contain exact counts, RAM and timings. No input capture is tracked.

### Remote acceptance

The [full pull-request run](https://github.com/ozandurmus/packetbreaker/actions/runs/37840337213)
passed all six jobs on runtime-code revision `ee56786eb7c1aeca1663b0caf8c21549121b69ce`.
The following close-out amendment changes this validation document only; current
head checks are visible on [PR #1](https://github.com/ozandurmus/packetbreaker/pull/1/checks).
Each job passed Ruff, frontend build, all **203 tests** (no skips), isolated sdist/wheel
build and artifact upload. The matrix results were:

| Runner | Python | Tests | Test time |
|---|---|---:|---:|
| macos-14 | 3.11 | 203 passed | 234.67 s |
| macos-14 | 3.12 | 203 passed | 235.88 s |
| macos-15-intel | 3.11 | 203 passed | 794.40 s |
| macos-15-intel | 3.12 | 203 passed | 683.32 s |
| windows-latest | 3.11 | 203 passed | 753.33 s |
| windows-latest | 3.12 | 203 passed | 1085.45 s |

Both Windows jobs verified `C:\Program Files\Wireshark\tshark.exe` exists, starts,
and is returned by Python auto-detection. The single-job push policy also passed.
The GitHub repository was initially private (made public during PR #2 review); `demo/`, capture files and databases are untracked.
The initial baseline was pushed to main once as requested; all Part 1 work is on
`phase2-part1`, with one commit for each numbered item. PR #1 stays open with
no auto-merge. Other Phase 2 work remains outside scope.

## Phase 2 / Part 2 — equal-file ingest re-check (item 0)

Five equal synthetic inputs, each **1,000,150 frames / 262,010,524 bytes**:
**5,000,750 frames / 1,310,052,620 bytes** total. Fresh indexes for every run,
warm local SSD caches, timed stages sequential without concurrent tests/builds.
The machine has 10 logical cores. No real capture was read for this benchmark.

| Implementation | Mode / workers | Ingest seconds | Frames/s | `time -l` peak RSS (B) | Sampled process-tree peak RSS (B) |
|---|---|---:|---:|---:|---:|
| before | serial / 1 | 267.91 | 18666 | 655,163,392 | 1,248,722,944 |
| before | parallel / 4 | 199.36 | 25084 | 861,634,560 | 2,604,679,168 |
| after | serial / 1 | 271.29 | 18433 | 744,095,744 | 1,359,822,848 |
| after | parallel / 5 | 183.54 | 27247 | 932,954,112 | 2,849,832,960 |

Initial speedup: **1.34×**. Repeated tuple serialization and packet-signature hashing
were reduced with bounded 65,536-entry caches, preserving the exact stored values.
Afterward: **1.48×**, still below 1.5×. Available RAM selected four workers before
and five afterward (8.29 / 8.66 decimal GB available); this is not a controlled
claim that caching alone produced the wall-time improvement. Even the more
favorable five-worker run did not meet the threshold. **Serial is the default**;
parallel remains an explicit API/CLI/UI option with the same resource budget.

The parallel profile measured 171.52 / 171.99 sampled tshark CPU seconds before /
after. Python row-processing CPU was 117.28 / 104.11 seconds and CSV-write CPU
38.03 / 39.18 seconds. Aggregate DuckDB connection-wait/open wall time was 34.82 /
136.19 seconds; held-connection wall time was 111.49 / 137.30 seconds. More
simultaneous files increase contention at the single writer. Python row processing
and CSV serialization retain the GIL; tshark parallelism does not make the entire
pipeline parallel. These summed per-file durations overlap and must not be added
to predict wall time. Counters are sampled per process or collected per batch;
connection-wait includes connection opening, not just lock acquisition.

Exact before/after comparison: **5,000,750 rows, zero mismatches across all 39 packet
fields**, with the random capture ID normalized by filename (the 40th column).
The parser/cache/cancel regressions passed. `time -l` RSS is a per-process high-water
mark; the separately sampled 100 ms process-tree sum can count shared pages twice.
The resource ratio remains a scheduling estimate, not an enforced RSS limit.

Reproduce with `tools/large_benchmark.py generate INPUT --frames 1000000
--small-frames 1000000`, then `/usr/bin/time -l python tools/parallel_benchmark.py
serial|parallel INPUT FRESH_OUTPUT --profile`. The script explicitly opts into
parallel mode. Use `tools/compare_indexes.py BEFORE_PROJECT AFTER_PROJECT OUTPUT.json`
for exact equality. [Raw measurements](phase2-part2-benchmark.json) retain the
profile totals, exact frame counts and both memory measurements.

## Phase 2 / Part 2 — onset and heatmap acceptance

Part 2 started only after PR #1 was explicitly authorized and merged into main
(`eccf81e19ef3a9a267a6453a760972acdaa916fb`). Work is on `phase2-part2`; no direct
main push or auto-merge. The package and bundled UI identify as **0.1.3**.

The suite now contains **228 tests** (203 in Part 1). Focused local gates passed:

- Four 40-second synthetic scenarios: loss onset, delay onset, upstream loss then
  a later downstream delay, and capture-miss only. Every scenario is tested with
  zero/constant IPv4 IDs and both corresponding IPv6 variants: 16 combinations.
- All expected onsets were detected at the correct forward segment within one
  bucket. No unexpected forward onset appeared. Capture-miss-only generated no
  onset in either direction. Propagation ordering and the prime-suspect segment
  matched ground truth. Original-frame evidence and threshold explanations exist.
- 0.5 s and 2 s buckets retained the correct onset/order on the IPv6 propagation
  fixture. Insufficient or already-lossy baselines report unknown; isolated spikes
  do not confirm onset. These are deterministic synthetic acceptance checks, not
  a general statistical false-positive/false-negative guarantee.
- Stored throughput/pps and loss-class denominators were checked against SQL
  counts. Coverage outside the captures remains NULL / not capturing. Unknown
  clock coverage remains unknown, not not-capturing. Transient bucket-level
  unmatchability suppresses loss/latency even if whole-window matchability is high.
- API checks verify half-open time filtering for flow membership, findings and
  ladder packets, and reject non-finite times. Existing API/headline regressions
  passed. Ruff and the TypeScript/Vite production build passed.

Interactive local QA used only generated IPv6/zero-ID propagation captures in a
scratch project. A healthy brush interval removed the later loss findings and
restricted ladder packet times to that selection. Transit-p95 selection displayed
the later downstream change and onset diamonds. Widening the synthetic analysis
window showed grey `NC` cells on both ends, with partial/unknown cells distinct
from zero. Metric tooltips, default-serial preference and the 0.1.3 footer were
visually checked. No production capture was used in Part 2.

CI policy is unchanged: pushes run macos-14/Python 3.12; PR/manual runs execute all
six OS/Python combinations, including Windows tshark installation/auto-detection.
[Part 2 CI runs](https://github.com/ozandurmus/packetbreaker/actions?query=branch%3Aphase2-part2)
retain the authoritative final results; the final run URL is also recorded in the
PR close-out. Documentation-only amendments are avoided after that final run.

Limits: the baseline is observational, not proof that the network was historically
healthy. Onsets use supported network loss and matched transit-p95; traffic volume,
RTT, retransmission, reset and window counters are contextual heatmap metrics.
Time order is uncertain within overlapping buckets/clock bounds and does not prove
causation. The 200,000-cell limit requires coarser buckets for very long windows.

## PR #2 review acceptance — 0.1.4

This section supersedes the earlier onset-baseline and CI scheduling rules above.
The branch remains `phase2-part2`; no Part 3 work or merge is included. The user
explicitly requested public repository visibility and no CI for these pushes.
Capture/secret file-history checks passed before publication. Every review commit
uses `[skip ci]`; the workflow remains active. GitHub run listings showed no runs
for these review commits. Cross-platform execution was intentionally not requested.

### README demo regression

Reproduced the prior failure on the NAT-confirmed README demo: **9 losses** on
**FW egress → LB ingress** (5 recovered, 4 impactful), no sustained onset and an
unknown overall onset summary. With the reviewed detector:

- First loss: **14.102000 s** relative to the synthetic reference epoch.
- Reported onset: **14.000 s**, the first loss bucket, at the correct segment.
- Confirmation/threshold crossing: bucket **19**, after three loss events.
- Reference loss rate: **0%**; rolling minimum event count: **3**.
- Eight original/recovery frame references; overall status **detected**.
- Sole forward prime-suspect segment: `forward:p2:p3`.

`recovered_loss` and `impactful_loss` also detect the first loss within one bucket.
New fixtures cover one loss every 2, 3, 4 or 5 seconds and seeded Bernoulli p=0.02
loss, including zero-ID IPv4 and IPv6. Random realized counts, not an assertion of
exactly 2% in a finite sample, remain ground truth. Quality-only samples do not
invent loss or invalidate usable baselines; mixed valid/unknown segments retain
per-segment status. Counter tests cover single events, isolated buckets, sustained
excess counts, nonzero reference counts and actual SYN/retransmission/RST/zero-window
frame evidence. SYN retries do not create additional failed connections.

### Full local suite, disjoint selections

| Invocation | Passed | Deselected | pytest duration | End-to-end wall time |
|---|---:|---:|---:|---:|
| Default `pytest -q` | 90 | 164 | **103.38 s** | 103.91 s |
| `pytest -m slow -q` | 164 | 90 | **627.54 s** | 628.07 s |

**All 254 tests passed locally, with no warnings.** Suites ran sequentially. No
cases were deleted; the extra real-tshark identity/scenario matrices, 50-client
fixtures and repeated-analysis headline/bucket checks are explicitly marked slow.
The fast selection retains the README regression, API/ingest/cancel-resume tests,
IPv4/IPv6 evidence filters, baseline/quality logic and TCP event-floor checks.
The full validation remains substantial; it is not presented as a two-minute run.

The first fast selection took 138 s; an explicit bucket-insert transaction trial
did not improve it and was reverted. Moving the large repeated-analysis fixtures
to the registered slow group provided headroom below the local two-minute target.
Ruff, TypeScript/Vite and the 0.1.4 sdist/wheel build passed.

PR/manual CI runs fast checks on all six OS/Python combinations. Slow checks run
only once, on macos-14/Python 3.12, and are not repeated for push events. Push CI
remains fast macos-14/Python 3.12 only. This policy is configured but was deliberately
not executed for this review, per the user's instruction.
