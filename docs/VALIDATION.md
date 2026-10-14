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

## Phase 2 / Part 3 — translation-aware matching (0.1.5)

PR #2 was merged before branching (`d527c19c2a11412cdb24bd11468412d40547f484`).
This phase uses synthetic inputs only; no real capture was read, copied or added.

### Correctness acceptance

- Two overlapping TCP sessions with distinct per-direction random offsets,
  including modulo-2³² wrap and IPv6 with the zero-ID fixture setting: offsets
  learned exactly, intermittent post-device losses attributed only to `forward:p2:p3`.
  Frame evidence contains both normalized coordinates and unchanged raw-header
  content filters. A forward offset step and a single reverse SEQ change each
  make only the affected session unknown in constant-ID IPv4, with an explicit
  inconsistency reason.
- 64,000-byte sender frames → MSS-sized firewall frames → coalesced receiver
  frames: one 1,460-byte impactful loss and a separate 1,460-byte capture miss at
  FW → LB, exactly matching ground truth. Sequence wrap, FIN data/FIN-only retry
  and deliberately bad offload checksums are included. The flow totals 257,460
  observed unique payload bytes including the retransmission, without counting
  GSO and MSS representations twice. Original positive frame numbers are retained.
- Mixed partial downstream coverage is unknown; complete downstream coverage is
  a capture miss. Neither is promoted to network loss. A legacy excluded-offload
  index is invalidated and successfully rebuilt.
- Retransmission onsets upstream of the translated-flow loss are labeled as
  sender symptoms and reference the independently supported downstream segment.
  Only `forward:p2:p3` receives a loss-suspect badge.

### Same-input large regression benchmark

`tools/path_benchmark.py` measures fresh serial ingest and analysis separately.
Both revisions use the same five synthetic files: **5,400,750 frames /
1,414,852,620 bytes**, including a **5,000,150-frame / 1,310,010,524-byte** file.
The frozen pre-Part-3 code and final code ran sequentially, without concurrent
local tests or builds. Timing and maximum RSS come from `/usr/bin/time -l`;
this is a serial regression check, not a new parallel-speedup claim.

| Stage | Before elapsed / process wall | After elapsed / process wall | Before max RSS | After max RSS |
|---|---:|---:|---:|---:|
| Serial ingest | 290.30 / 290.63 s | 281.90 / 282.18 s | 1,044,594,688 B (0.973 GiB) | 1,253,982,208 B (1.168 GiB) |
| Analysis | 87.59 / 87.96 s | 88.13 / 88.39 s | 1,839,153,152 B (1.713 GiB) | 1,837,187,072 B (1.711 GiB) |

Ingest throughput: **18,604 → 19,158 frames/s**
(-2.89% elapsed time). Analysis elapsed time increased
**0.62%**; ingest maximum RSS increased **20.04%**
(about 200 MiB). Analysis maximum RSS changed
-0.11%. These are single measured runs, not a statistical
claim of improved speed or proof of the RSS increase's cause. Maximum RSS is the
value reported by `time -l`, not a sum of simultaneous process footprints.
Both analyses returned **50 flows, one capture-miss finding and zero network-loss
findings**. This ordinary-segmentation workload measures baseline-path regression;
the bounded byte-range expansion is validated separately by the offload fixture.

### Test and packaging gates

Default `pytest -q`: **95 passed, 164 deselected, 101.15 s** (101.61 s
end-to-end). All five new cases are fast; the default stays below two minutes.
Ruff and TypeScript/Vite passed; the UI build took **3.40 s**. The complete suite
contains **259 tests**. The unchanged slow selection runs once in the PR matrix,
while all six OS/Python combinations run the fast suite.

No capture, DuckDB, private-key, `.env` or demo files are tracked. Part 3 restores
normal CI execution after the previous review's explicitly skipped pushes. Push
checks remain macos-14/Python 3.12; the PR runs the full six-job matrix, with the
slow suite only on macos-14/Python 3.12. Windows verifies the installed tshark path
and Python auto-detection.

The 0.1.5 wheel and sdist build passed. A local browser check on the synthetic
translation/offload projects verified exact offset rows, raw/canonical frame
evidence, upstream symptom labels, only the actual loss-segment badge, affected
GSO/GRO point notes and the single-loss/single-capture-miss result. Long evidence
text wraps instead of being clipped. Temporary verification servers/tabs were
closed afterward.

[Part 3 CI runs](https://github.com/ozandurmus/packetbreaker/actions?query=branch%3Aphase2-part3)
provide the final cross-platform results; the exact green full-matrix run is
recorded in the PR close-out. No auto-merge is enabled.

## Phase 2 / Part 4 — waterfall and export (0.1.6)

PR #3 was merged first; branch `phase2-part4` starts at `493956b`. All inputs
remain synthetic. No new capture files or project databases are tracked.

### Correctness and UI

- Handshake: every ordered link and device dwell, server SYN/ACK turnaround,
  reverse path and client final-ACK turnaround have frame evidence. The synthetic
  complete handshake measures **44 ms**, including **16 ms** server turnaround.
- HTTP: Content-Length byte coverage handles out-of-order request bodies; the
  synthetic server-processing interval is **16 ms**. Missing header prefixes,
  chunked request boundaries and overlapping requests cannot create an invented
  duration. Negative or unverified clock intervals remain unknown.
- Confirmed NAT and learned IPv6 sequence translations retain original per-file
  filters. Explicit return-path ordering is exercised. A declared proxy produces
  `unknown (full proxy, Phase 3)` instead of timing attribution across its boundary.
- Export schema v1 validates type/hop/time range/metrics/evidence refs/confidence.
  A 201-finding fixture verifies export is independent of the UI summary cap.
  HTML has no remote asset references; markup-like capture labels cannot escape
  inert JSON or become executable HTML. CSP forbids network connections.
- UI and CLI HTML/JSON export work; the CLI rejects an existing destination file.
  Exports include stored buckets, onset explanations, all grouped findings,
  segments and original per-file filters, with no raw packet payloads.
- Browser validation of the NAT-confirmed README demo showed 4 impactful losses,
  5 recovered losses, 8 capture misses and the loss onset at bucket 14. The live
  waterfall rendered its bars/uncertainties and opened the two original ingress /
  egress frame references. The HTML button completed its download.

The browser's security policy blocked direct `file://` navigation, so visual
rendering of the downloaded offline file is **unverified** in that browser. No
protocol workaround was used. The generated HTML's asset/CSP/escaping tests and
the embedded heatmap JavaScript syntax check passed. Live chart rendering was
visually verified separately.

### Gates and timing

The initial whole-fast run exposed a shared-fixture ordering issue: an earlier
clock/window test had modified the cached healthy project. The waterfall test
now explicitly reanalyzes its baseline; its timing checks assert the ground-truth
16 ms / 44 ms intervals. Frame evidence lookups are batched per waterfall.
All six added tests stay in the fast selection; none were moved to slow.

Final default `pytest -q` selection: **101 passed, 164 deselected in 108.24 s**
(108.73 s end-to-end). The complete suite contains **265 tests**. A preceding
all-passing run took 121.03 s; the fixture now overlaps startup of independent tiny
captures with the existing resource-bounded two-worker ingest option. No tests
were deleted or moved to slow, and production serial defaults are unchanged.
Ruff, TypeScript/Vite, and the embedded export-script syntax check passed.

[Part 4 CI runs](https://github.com/ozandurmus/packetbreaker/actions?query=branch%3Aphase2-part4)
retain the cross-platform results; the exact final green full-matrix run is
recorded in the PR close-out. Push checks are macos-14/Python 3.12; PR/manual
checks run all six OS/Python combinations and the slow suite once on
macos-14/Python 3.12. No auto-merge is enabled.

The 0.1.6 wheel and sdist build passed. The tracked-file check found no capture,
DuckDB, private-key, `.env` or demo files. Temporary browser/server verification
sessions were closed; the user's other local projects were not touched.

## Phase 2 / Part 5 — vendor inputs (0.1.7)

PR #4 was merged before branching; the main baseline is `3b90eb3`. The six commits
follow requested items 0–5. tshark remains the only packet/vendor dissector.
Synthetic fixture writers live in tests, and expected vendor fields/timestamps
come from separate tshark decodes. No third-party capture is a required fixture.

### Adapter and classification acceptance

- Onset priority: prime-suspect network segment first; local retransmission
  symptoms follow with subdued styling in the live UI and standalone HTML.
- Check Point: generated RFC 1761 snoop, all eight mapped stage names, interface
  selection and UUID variant. Decoded fields match tshark exactly. Complete
  inspection evidence confirms the single intended drop; later O appearances
  remain capture misses. Unattested/damaged coverage cannot confirm a device drop.
  A delayed, unpaired later-stage appearance with the same signature remains
  unknown instead of turning two unmatched appearances into two confirmed drops.
  Unconfirmed NAT and unsupported proxy boundaries do not license negative proof.
- Optional local format check: Wireshark's `fw1_mon2018.cap` was downloaded only
  to gitignored `demo/samples/`, size **3,476 bytes**. Its fw1 fields match a direct
  tshark decode. The test is skipped in CI or when the local file does not exist.
- F5: generated legacy TMM low/medium/high trailers, peer IPv4/IPv6 aliases,
  reciprocal flow/peer IDs, slot/TMM namespace, ingress/VIP and reset causes. All
  requested field values match tshark. Separate proxy conversations produce
  **240 ms / 100 ms** request-bearing-frame forwarding intervals. Multiple client
  peers on one server stream remain separate and correctly paired. Ambiguous
  client CIDRs remain unknown. Reset origin is the decoded TMM text.
- Palo Alto: synthetic receive/firewall/transmit/drop files, raw fields compared
  with tshark. The one positive drop upgrades the inferred event without counting
  it twice; it also works as standalone stage evidence without a path denominator.
  Every finding includes device/stage, and the flow filter finds the affected flow.
- Fortinet: original converter, CRLF/wrapped hex/noise, exact byte and nanosecond
  timestamp round trip (`pcap → text → pcap`) and equal tshark fields. Interface
  split, missing-anchor rejection and persistent low confidence after relative
  import/reattach pass. Ethernet/SLL/SLL2 cooked variants are also selected from tshark decode and
  round-trip byte-for-byte. Malformed hex or ambiguous cooked metadata is reported
  as skipped, never repaired into invented bytes.
- Export v2 requires device/stage for `confirmed_device_drop`; v1 remains documented.
  All vendor proof rows are persisted; only display evidence is capped. Raw packet
  payloads are not exported, while addresses, request URIs and reset text remain
  investigation metadata and are not automatically redacted.

### Local UI and packaging

Browser checks on synthetic projects verified confirmed-drop summary/flow filter/
node overlay, F5 pair IDs and both frame references for the 240 ms interval,
TMM reset explanation, and prime-suspect ordering with visibly muted symptoms.
The Fortinet form imported **4 packets across 2 interfaces**, reported **3 skipped
console lines** and marked both interface clocks **low**. Temporary servers and
the verification tab were closed afterward. No user's real capture was opened.

The existing browser policy still prevents direct `file://` preview; offline HTML
visual rendering is not claimed. Structural asset/CSP/escaping and onset-order
export tests cover the standalone file. Live UI rendering was visually checked.

### Runtime and gates

An initial all-passing fast run took 121.78 s. Three-worker fixture preparation did
not help (126.47 s) and was reverted. F5/HTTP fields are now requested only for the
explicit F5 ingest option; ordinary PCAPs use the original lightweight projection,
and snoop selects its fw1 fields automatically. The existing IPv4/IPv6 merge-and-resave real-tshark matrix runs in the slow
selection; all new vendor cases remain fast. Tests that inspect ladder totals
request one evidence row rather than generating unused full pages. No tests were
deleted, and production serial ingest defaults remain unchanged.

Final default selection: **110 passed, 166 deselected in 118.36 s** (118.93 s
end-to-end), including the optional local Wireshark sample. There are **276 tests**
in total. CI fast selection has 109 mandatory cases plus the one intentional
sample skip; the 166 slow cases run once on macos-14/Python 3.12. All added vendor
cases remain fast. The reused-server-flow F5 and three cooked-link decode cases
are synthetic and remain byte/field checked against tshark.

Ruff, TypeScript/Vite and wheel/sdist packaging passed. The tracked-file checks
found no capture, DuckDB, secret-key, `.env` or demo files. The public sample is
explicitly gitignored. No live capture or real-device commands were executed.

[Part 5 CI runs](https://github.com/ozandurmus/packetbreaker/actions?query=branch%3Aphase2-part5)
retain the authoritative cross-platform results; the exact final full-matrix run
is recorded in the PR close-out. The push/PR/manual matrix policy is unchanged,
and auto-merge remains disabled.

## Phase 3 / Part 1 — path integrity (0.1.8)

Item 1: field-diff and export focused tests: 4 passed (6.63 s). UI TypeScript/Vite build passes.
The hash test changes bytes beyond the retained matching prefix and checks truncation uncertainty.


Local default run before the adjacent-repeat stress addition: **120 passed, 166 deselected in 98.19 s** (98.71 s wall),
below the two-minute gate. Final collection: **287 tests**, 11 more than Part 5;
all new tests are fast. CI omits the optional local Check Point sample: 120 fast
passes plus one skip are expected per job. The existing 166-test real-tshark slow
matrix remains exclusive to macos-14 / Python 3.12 on PR/manual events.

Ground-truth fixtures identify the Firewall for injected RST, MTU black hole,
MSS clamping, option stripping, DSCP remark, payload change and TTL deviation;
asymmetric return and pure capture-miss fixtures pass. Zero IPv4 ID and
constant-flow-label IPv6 mutations pass. Declared ALG and uncertain-clock tests
prevent unsupported modification/injection claims. A changed-but-observed payload
is explicitly checked not to become network loss. Existing matrix assertions
continue to compare loss ground truth separately from new quality annotations.

Ruff, TypeScript/Vite and wheel/sdist builds pass. A local browser check opened a
modified packet in the flow ladder: only the Firewall comparison changed its full
payload hash, with evidence controls. Offline exports retain the no-external-assets
and escaping tests. No real capture was copied or tracked.

Performance: an initial 118-test run took 126.15 s. Profiling isolated repeated
optional-pandas import probes during bucket cell insertion; typed JSON bulk writes
reduced the same healthy analysis from 2.925 s to 0.731 s. A subsequent 118-test run
took 88.87 s; the 120-test result above includes zero-ID/IPv6 coverage and the
normal endpoint-origin annotation tests. No tests were moved to slow to meet the gate.

[Part 1 CI runs](https://github.com/ozandurmus/packetbreaker/actions?query=branch%3Aphase3-part1)
are authoritative for the full matrix; the exact final run is recorded in the PR
close-out. Push remains macos-14 / Python 3.12 only. PR/manual remain all three OSes
by both Python versions. Auto-merge remains disabled.


Final scale review replaced all-pairs duplicate scans with adjacent-observation windows and
reduced asymmetry evidence to one representative per flow before joining. The 20,000-observation
stress test verifies adjacent duplicate evidence, falling-TTL evidence and the SPAN threshold.
Focused integrity plus legacy SPAN checks: 9 passed in 9.91 s. This adds one fast test; the final
full-head default duration and exact CI run are recorded in the PR close-out.

## PR #6 review fixes — 0.1.9

The pre-fix detector module from `f30f710` was loaded in an isolated test process against the
new generated fixtures and assertions (without editing the checkout's production module):
**48 failed, 60 passed**. The same 108 parametrized attribution/guard cases pass after the fix.

| New case that failed before the fix | Failures (four address/ID variants) | Correction |
|---|---:|---|
| RST, MTU, MSS, option stripping and DSCP at the FW–LB link | 20 | Explicit link location; never substitute the upstream device name |
| Payload change at the FW–LB link | 4 | Correlate and report unique payload changes across links |
| Asymmetric return at FW, LB or the link | 12 | Consolidate device bypasses and identify edge-only detours |
| Legitimate server RST missing at server and LB server-side point | 4 | Compare endpoint TTL at the first-observation point; capture miss remains possible |
| No server-side endpoint capture | 4 | First middlebox is not an endpoint; `no endpoint-side capture` |
| Equal-TTL middlebox RST without endpoint-side capture | 4 | Withhold injection attribution despite TTL/first-observation appearance |

The single server-point RST capture miss, equal-raw-TTL injection with sufficient first-appearance
evidence, and MTU-sized packets reappearing downstream already passed; these remain mandatory
regression guards. The positive FW/LB cases also already passed, while the old single-device
fixtures could not establish that fact.

Local default: **225 passed, 166 deselected in 106.03 s** (106.56 s wall). Total collection:
**391 tests**. The matrix adds 108 fast cases and replaces four weaker standalone cases.
An initial full run took 139.73 s; indexing payload pairs once and isolating altered-topology
views with synthetic database snapshots removed duplicate computation and unnecessary restores.
All new cases remain in the default suite. CI expects 224 fast passes plus one optional local
sample skip on each job, and all 166 slow cases on macos-14 / Python 3.12 only.

No real captures were added. Full final-head CI results and the exact run URL are recorded in
PR #6's review-fix close-out; the existing push/PR/manual matrix policy is unchanged.

## Phase 3 / Part 2 — 0.2.0

Branch `phase3-part2` starts from main `82c6d3b`, after PRs #6 and #7 were merged.
No real or third-party capture is tracked. The new wire fixtures are generated in test temporary
folders: two full proxies, one plain router, eight capture points, concurrent equal-URI requests,
pooled backend sockets, ambiguity at either proxy, per-leg losses/capture misses, legitimate and
proxy-emitted resets, visible TLS chains, client-auth-only chains and encrypted TLS 1.3. IPv4 zero
and constant IDs and IPv6 zero/constant-per-flow labels are covered; no fixture depends on unique IP IDs.

The negative cases precede positive cases. Exact-device assertions distinguish Proxy A, Proxy B,
Router and the intervening link; a link change cannot justify a supported device attribution.
Nearest-time-only pairing fails the same one-to-one/XFF contract at both proxy locations. An
always-first-proxy mutant fails the Proxy B TLS contract. The pooled case also rejects connection-level
pairing: two distinct requests must map to one backend flow. Declaring the router as a proxy cannot
turn copies of one TCP socket into independent request legs.

Measured request/response forwarding intervals (shared capture clock, ms):

| Device | Client | Request dwell | Response dwell |
|---|---|---:|---:|
| Proxy A | synthetic client A | 92 | 27 |
| Proxy A | synthetic client B | 20 | 27 |
| Proxy B | synthetic client A | 53 | 39 |
| Proxy B | synthetic client B | 84 | 29 |

Every value is asserted within 0.001 ms against the fixture schedule. Both proxies' request and
response bars, ordinary links, server processing and three separate TCP handshakes retain original
frame/content filters. A missing pooled response never shifts another request's response association.
Out-of-order header/body delivery uses the logical first byte and physical completion frame.
Traveling copies produce zero retransmissions on healthy pooled legs; each intentionally retransmitted
leg records exactly one at its sender. Each leg's single loss is assigned to its actual link, and a pure
capture miss produces no network-loss event.

TLS chain expectations come from tshark's decoded subject/issuer/DER values. Only server-direction
chains participate. TLS 1.3, absent/client-auth-only chains, incomplete quality evidence, missing points,
clock uncertainty and equal request candidates remain unknown. Declared inspection yields a quality
observation. JSON schema 4 validates all new finding classes; exported HTML includes proxy/TLS evidence
and has no external HTTP(S) asset reference. Package and bundled UI builds pass.

The initial complete default run passed 354 fast tests but exceeded the limit (155.14 s;
153.88 s on profiling). Selected synthetic prefetch and existing bounded file workers
reduced the later 357-case run to 132.19 s; separate preparation processes reduced it to 126.98 s.
These were failed performance acceptance attempts, not accepted final timings. Evidence lookup was
then batched per application graph/TLS comparison instead of repeatedly querying the same frames.
No tests were removed, marked slow, or excluded to meet the time target. The slow matrix remains
166 cases, on macos-14/Python 3.12 only.

Final local default: **357 passed, 166 deselected in 113.58 s** (114.11 s wall,
111.31 s user, 43.95 s system). Total collection: **523 tests**. Ruff, bundled UI and
Python wheel/sdist builds pass. CI expects 356 passes plus the optional sample skip per fast job.

Full PR matrix evidence: [PR #8 checks](https://github.com/ozandurmus/packetbreaker/pull/8/checks).
This stable link tracks the final head's six-job matrix; the exact completed run URL is added to
the PR validation section. Pushes retain the single macos-14/Python 3.12 job. No auto-merge is enabled.

Initial PR run [38053124527](https://github.com/ozandurmus/packetbreaker/actions/runs/38053124527)
passed all six fast suites and five complete jobs; its macos-14/Python 3.12 slow stage failed 13 of
166 cases (153 passed, 391.68 s). All failures were the existing asymmetric realistic corpus:
clock overrides for one-way points had no domain label, so otherwise matchable loss/SYN events were
incorrectly classified unknown. User corrections now explicitly belong to the reference domain,
while their uncertainty remains unverified and propagates as unverified. No assertion was weakened.
A fast clock regression verifies both domain membership and that child fits do not invent verified
uncertainty. The unchanged affected matrix passes locally: **17 passed in 70.51 s**. Final-head PR
checks above contain the subsequent full six-job matrix.

After the clock-override regression fix, the final local default run is **357 passed, 166 deselected
in 109.03 s** (109.53 s wall, 107.40 s user, 41.55 s system), with no warnings. The final package
build also succeeds. Test selection and all ground-truth assertions are unchanged.

## Phase 3 / Part 3 — packaging checkpoint

Baseline: PR #8 merged at `82d3d94`; branch `phase3-part3`. Native build uses PyInstaller
6.22.3, Python 3.12 and bundled frontend. The local arm64 executable is approximately 33 MiB;
Windows/x86_64 validation belongs to the native CI jobs. `tests/test_api.py`: 3 passed in 2.88 s,
including the health endpoint's loopback guard. Exact final binary smoke, complete fast suite
and full nine-job PR run are recorded below after the remaining items.

The first local packaging attempt could not write PyInstaller's user cache; the build helper
now uses ignored `build/pyinstaller-cache`. The first smoke workload used only 30 rounds and
therefore ended before the generator's loss onset; the workload now uses its standard 100 rounds.
No detector assertion or synthetic ground truth was weakened.

### Assistant checkpoint

`tests/test_assistant.py` rejects preview access when disabled and rejects absent analyses.
It checks canonical IPv6/case-insensitive hostname identity, IPv4/mapped IPv6, CIDR and URL/filter
strings, dictionary keys, certificate CNs, single-label hostnames, immutable source input and
unchanged metrics/schema. A TestClient guard prohibits socket connect/connect_ex, connection
creation, DNS lookup and urllib requests while enabling, previewing and disabling the setting;
foreign origins remain rejected. The ordinary API ingest test enables the setting before attach
and proves UI-only preferences do not reach ingest. Assistant/API/export focused run: **8 passed
in 9.46 s**. TypeScript and Vite build pass. No new test is marked slow.

### Final local acceptance

Default `pytest -q`: **360 passed, 166 deselected in 108.53 s** (109.00 s wall,
109.69 s user, 40.66 s system), with no warnings. **526 total tests**, three new fast cases;
none moved to slow. Ruff and TypeScript/Vite pass. The final arm64 one-file build succeeds.
Its smoke verifies 10 recovered losses at `forward:p2:p3`, five captures, health/version,
auto-detected external tshark, both bundled UI assets and local findings-only assistant preview.
The separate wheel/sdist build and native Windows/x86_64 smokes are required gates below.

The audit in `BRIEF_COVERAGE.md` is source/test evidence, not a claim that every original brief
item is implemented. No RTP/DNS/window/microburst/flood/session-pressure feature was added.

Wheel/sdist build succeeds with the installed build requirements (`--no-isolation` locally;
CI uses an isolated build). Native UI manual check confirms disabled-by-default state, saved
setting activation and rendered tokenized JSON. That check found a stale hardcoded version
badge; the badge now reads the app state's version. The following stable link follows the
final head's complete gate: [PR #9 acceptance and packaging checks](https://github.com/ozandurmus/packetbreaker/pull/9/checks).
The exact completed Actions run is also linked in the PR close-out after all nine jobs succeed.

The initial PR run [38076159014](https://github.com/ozandurmus/packetbreaker/actions/runs/38076159014)
passed the Intel native smoke. Windows also completed the exact-loss/health/UI/assistant checks,
but failed smoke cleanup: terminating only PyInstaller's bootloader parent left its server child
holding `server.log` (WinError 32). Windows smoke now terminates that process tree, waits and
asserts the loopback port is closed; it does not ignore cleanup failures. Failed server readiness
also prints its log before temporary files are removed. The subsequent final-head checks above
include this fix and the dynamic UI version badge.

## Phase 4 / Part 1 — working checkpoints

Baseline: green PR #9 merged at `a74b34f`; work on `phase4-part1`. Negative limitation tests were
written first (initial collection failed because the new module did not exist). Single-counter,
missing-handshake/index/sender, untrusted TCP state, receiver ACK delay and competing-cause cases
reject a naive diagnosis. Initial limitation guards plus real five-file healthy profile: 3 passed
in 2.13 s. Final wire fixture assertions, complete fast suite and CI are recorded at close-out.

Recovery negative tests reject no-RTT/short timers, untrusted decode, spurious flags without ACK
coverage and retries with competing ACK triggers. Positive subtype contracts cover fast,
SACK-backed fast, ACK-corroborated spurious and RTO-compatible recovery. Recovery/diagnosis/proxy
integration checkpoint: 45 passed in 15.64 s; no tests marked slow. Full wire-location assertions
are supplied by the shared adversarial corpus in item 5.

DNS negative contracts reject incomplete questions, ambiguous ownership, insufficient deadline or
resolver coverage and unsupported far-response attribution. The tiny real-tshark same-ID/same-name
fixture uses distinct clients: only the owning client's response yields 50 ms; the distractor stays
unanswered. DNS/native/export checkpoint: 8 passed in 7.54 s. Export preserves DNS evidence and the
HTML section. A cached profile regression exposed a temporary edge table; generation-cached edges
are now persistent. Dense isolated TCP state is streamed separately from bounded HTTP/TLS events.

Chart tests verify packet limits, complete-population throughput, negotiated window lines,
point/flow-scoped evidence and brush bounds. The first brush test caught a partial selected
bucket divided by a full second; selected-range/capture boundaries now both gate known rates.
Chart/diagnosis/export/waterfall checkpoint: 10 passed in 12.47 s; TypeScript/Vite pass.


### Adversarial diagnostic corpus and regression fixes

`diagnostic_synthetic.py` generates six independent client/FW/LB/server captures with 17 TCP
and 9 DNS conversations on every point. `test_diagnostics_wire.py` checks exact directional
receiver/service/pacing/loss evidence, FW/LB/link loss and reordering origins, RTO/fast/spurious/
SACK recovery, and same-ID/name concurrent DNS owners. Each runs with IPv4 zero/constant IDs
and IPv6 zero/constant labels. Negative controls include fully acknowledged idle zero windows,
receiver-delayed high RTT, missing handshake, healthy traffic, one pure capture miss, unknown
clocks, missing endpoint roles and insufficient DNS deadline coverage. No new test is slow.

The first wire retry test exposed a neighbouring `rto_frame` that tshark attached to an original
reordered packet. Original-range validation now prevents calling that RTO; matched original
arrival-order pairs still locate the correct FW/LB/link boundary. No assertion was weakened.
An API boundary check also exercises point/flow frame scoping and oversized/invalid requests.

Two actual in-process mutants were run without editing source: zero-window-only classification
fails `test_single_counter_and_quality_guards_first`; removing original-range corroboration fails
`test_unknown_timer_and_untrusted_state_first`. Exact location assertions independently reject
"always FW", downstream-counter-only attribution and DNS-ID-only pairing across clients.
The diagnostic/proxy/TLS/retry focused regression gate passed 104 tests in 48.45 s.

Manual synthetic UI check observed forward receiver-limited with 7 zero-window observations,
active flight and a 1 ms matched path, while the reverse direction remained unknown. DNS showed
9 client-side questions, 3 answers (50 ms), and 6 deadline timeouts, separating FW/LB/link response
disappearances from resolver-side no-response observations. Three sequence/RTT/throughput charts
loaded with frame-linked packet points. No real capture was used or tracked; `demo/` is ignored.
Ruff, TypeScript/Vite and local sdist/wheel build (`--no-isolation`) passed.

Fast-suite optimization retains all assertions: report-generation profile/export caching,
batched recovery evidence/segment lookup, a single decoded TCP-tree visit, and the existing
bounded two-worker fixture pool prefetching selected independent scenarios/proxy datasets.
The earlier sequential-preparation run took 161.38 s; intermediate runs remained above the
120 s target (130.02 s / 133.97 s). Final timing and PR CI acceptance are recorded below.

Final local default gate (including partial-path correction): **386 passed, 166 deselected in 95.14 s** (Apple Silicon, Python 3.12),
versus the 161.38 s earlier run with serial waits. Total acceptance collection is 552 tests,
including 26 newly added fast tests; CI skips the existing optional local-only sample if absent.
The fast test gate remains below two minutes without moving diagnostic tests to `slow`.
Brief coverage audit now records 70 done, 15 partial and 9 missing rows, with explicit scope limits.
Full six-target portability plus three native packaging jobs remain the PR close-out gate.

Post-PR negative check: a healthy partial path plus sender gaps previously returned an application
hypothesis. The single-counter/quality guard failed before the fix; profiles now require at least
three timing pairs per drawn TCP-leg edge to attest a healthy monitored path. A wire clone with
only firewall clocks unavailable must remain unknown, even with healthy timing elsewhere.


PR close-out: [PR #10 checks](https://github.com/ozandurmus/packetbreaker/pull/10/checks).
The final run URL and completed matrix results are recorded in the PR validation section.
The initial run on `a5b3be2` was deliberately cancelled for the partial-path correction after all
three native packaging jobs passed; it is not claimed as final full-matrix acceptance.

## Phase 4 / Part 2 — working checkpoints

Baseline: PR #10 merged at `7482180`; branch `phase4-part2`. Layer negative test first failed
collection because the new module did not exist. Seven fast layer tests pass in 6.69 s: ERSPAN
II/III, GRE, VXLAN and GENEVE fields match a separate plain-file tshark ingest, including mixed
IPv4/IPv6 envelopes. Content filters are executed by tshark. A six-point FW/LB topology contains
a deliberate outer-address/inner-port collision distractor; ERSPAN defaults inner, VXLAN stays
unknown until selected, and outer selection retains UDP ports. ERSPAN truncation is visible.
TypeScript/Vite build passes. No real capture is used.

Fragment checkpoint: **13 passed in 22.95 s**. Four IPv4/IPv6 zero/constant-ID variants share
seven concurrent flows on six points. Exact FW, LB and link origins each have one supported
fragmentation finding and one datagram per point. A middle fragment disappearing at LB yields
exactly one unrecovered datagram; a middle-fragment capture miss yields capture_miss only.
Overlaps are unknown. Missing-clock attribution is rejected. Every emitted fragment evidence
filter in the checked finding is executed by tshark against its original file. Combined prior
fragment/layer/export gate: 19 passed in 35.71 s. Schema assertions deliberately advance to v5.

Microburst checkpoint: **7 passed in 7.82 s**. IPv4 zero-ID and IPv6 constant-label captures carry
concurrent FW/LB/link loss flows and independent burst traffic. Each of six points sees two bursts:
one without a nearby loss and one near supported loss onset. Only the three correct next segments
receive corroborating associations; every cause remains unknown. Peak rate is independently
recomputed from tshark's frame lengths/timestamps. Configurable 10 ms windows and SPAN-copy guards
pass. The initial association check correctly rejected unverified manual clock uncertainty; the
positive fixture now exercises fitted bidirectional clocks rather than pretending an override is
a measured bound. Unknown-clock negative assertions remain intact.

### Adversarial close-out

Three in-process naive implementation mutants were executed without changing source files, and
all were rejected: selecting outer headers as inner identity; counting each fragment as a complete
packet; and promoting a nearby burst to a proven loss cause. The exact failing tests are
`test_inner_outer_fields_and_content_filter_against_tshark`,
`test_wire_complete_datagrams_exact_first_hop_and_single_loss`, and
`test_burst_is_never_a_proven_loss_cause_and_clock_order_is_unknown`.

The new matching-layer boundary test failed before the guard was added. That test also exposed
outer UDP retaining a tunnel exclusion marker; the selected layer now clears only that envelope
marker. Undecided/undecodable layers and outer-to-inner/plain boundaries have null loss rates.
UDP and ICMP reassembly identities in both IP families match separate plain-file tshark ingest
(4 passed in 1.92 s); logical IP length is independent of the last fragment's physical length.
Layer/quality regression gate: 11 passed in 10.60 s. Ruff and bundled UI/sdist/wheel builds pass.

The initial complete fast run passed 417 tests but took 128.25 s. Batched microburst evidence and
prefetching the new small fixtures reduced it to 112.06 s without moving any tests to slow.
The audit now records 73 done, 15 partial and 6 missing rows. Captures are generated in temporary
directories; no real or third-party capture is tracked. Final gate/CI results follow at close-out.

Final local default gate: **417 passed, 166 deselected in 114.87 s**; 31 new fast tests, 583 total.
After strengthening IPv6 fragment-ID collisions to use zero/constant IDs across clients as well,
the focused fragment gate passed **17 tests in 24.20 s**. No assertion was weakened and no new
case was marked slow. Layer/quality guard recheck: 11 passed in 10.60 s. Three naive mutants fail.
The local browser showed 12 burst episodes, 161.66 Mbps peak, 0.46 ms maximum duration and 0.07 Hz
frequency on the synthetic six-point capture. Point buttons opened frame-number and content
filters. Path exposed Auto/Inner/Outer matching choices. The temporary server/tab were closed.
Full six-target portability plus three native packaging jobs are the PR close-out gate; final run
URL and completed matrix results are recorded in the PR validation section to avoid another CI
cycle solely for a post-run documentation edit.

Final precision guard: a nanosecond pcap with ERSPAN timestamps ending in 789 ns failed equality
against the original ingest timestamps. tshark JSON emits ISO timestamps; Python datetime loses
sub-microsecond digits. Layer overlays now retain the original validated `ts` and physical frame
hash rather than overwriting them with the secondary decoder representation. The initial PR CI
run was cancelled for this correction after its three packaging jobs passed; it is not the final
full-matrix acceptance run.

## Phase 4 / Part 3 — pilot readiness (0.3.2)

PR #11 was merged at `53418db` before branching `phase4-part3`. Captures remain untracked and
`demo/` remains ignored. Every new fixture is synthetic; no real incident capture was accessed.

### Scale and regression

Same-input Part 1 reference: `668e364`. On this Apple Silicon arm64 host (10 logical cores,
32 GiB RAM, macOS 27.0.1), the new `tools/pilot_benchmark.py` produced **six files / 9,000,900
physical frames / 8,800,900 logical observations / 2,320,670,644 bytes**. The largest file is
**8,300,150 frames / 2,174,610,524 bytes (>2 GiB)**. One point is ERSPAN II; another contains
300,150 physical frames including fragmented datagrams. Fifty concurrent client conversations
use bounded timestamp jitter. Files and databases are outside the checkout in temporary storage.

| Stage | Part 1 elapsed / process wall | Current elapsed / process wall | Part 1 peak RSS | Current peak RSS |
|---|---:|---:|---:|---:|
| Fresh six-file serial ingest | 596.02 / 596.32 s | 599.28 / 599.58 s | 4,342,972,416 B | 4,342,628,352 B |
| Full six-point analysis | Failed at 228.42 s | 583.22 / 583.50 s | 1,919,369,216 B at failure | 2,611,970,048 B |
| Comparable plain-path analysis control | 220.62 / 220.92 s | 239.08 / 239.39 s | 2,284,240,896 B | 2,308,603,904 B |
| Cached current project open | — | 0.085 / 0.30 s | — | 91,865,088 B |

Ingest: **15,102 → 15,020 frames/s**, +0.55% elapsed and essentially unchanged peak RSS.
The plain control uses the same indexed corpus and reference window, but only the four plain
points (`p0,p1,p3,p5`, 8,600,600 physical frames). Both versions complete it: **+8.37%** analysis
elapsed and **+1.07%** RSS, below the 20% gate. This control is separate from the full new-path
acceptance. Part 1 cannot complete the six-point path under its unchanged 512 MB DuckDB budget,
so a full-analysis before/after percentage is **undefined**, not a measured regression percentage.

The fixed **0.98 s reference window** is common to both versions because the largest capture
extends beyond the smaller files. All input frames are indexed/prepared; classification is bounded
by that selected interval. Full current analysis returns 50 flows, matchable ratio **1.0** on all
ten directional segments, and only fragmentation/TTL-path findings, with **no network-loss
finding**. The generator uses `64-hop` TTL in both directions; reverse TTL increases are workload
header artifacts, not a loss ground truth. This workload does not certify large TLS/proxy decoding
performance or change-point accuracy; those behaviors retain their separate adversarial tests.

The first candidate exhausted memory in a wide layer `UPDATE`; a full-point CTAS hash join also
failed. The final implementation parses/joins at most **5,000 selected physical frames per batch**,
retains original timestamps/frame hashes, and normalizes fragment points through native temporary
tables. A later trial exposed a redundant full TCP JSON decode: fragment JSON merge removes null
TLS fields, although the first-pass probe is complete. The completeness marker now prevents that
reparse while visible TLS, legacy indexes and declared proxies still require decoding. A new
non-TLS generation discards stale application/certificate state. Unique-flow observation counts
reuse the existing packet grouping instead of a second high-cardinality distinct aggregation.

The successful analysis clears secondary decode indexes before measurement. Stages ran serially;
`/usr/bin/time -l` supplies wall/RSS values, not an aggregate simultaneous process-tree RSS cap.
The initial sandbox-only ingest had no usable RSS counter and is not used in the table.
`cached` prevents any subprocess launch across construction, inventory and saved-report reading;
it returns the complete report and six captures without parsing.

Reproduce: `python tools/pilot_benchmark.py generate INPUT`, then prefix `ingest`, `analyze`,
`control` or `cached INPUT OUTPUT` stages with `/usr/bin/time -l`. Use fresh projects for ingest
and independent database snapshots for the paired control. Exact inputs/results/caveats:
[phase4-part3-benchmark.json](phase4-part3-benchmark.json).

### Fast-suite profile and contracts

Before: **417 passed / 166 deselected in 112.40 s**. Final default:
**438 passed / 166 deselected in 86.49 s** — 604 collected, **21 new fast cases**, no assertions
removed/weakened and no test moved to slow. The twenty slowest tests before/after are retained in
[phase4-part3-test-profile.json](phase4-part3-test-profile.json). Missing optional pandas searches,
redundant source selection/decode, repeated per-frame evidence queries and duplicate fixture
arguments were reduced. Healthy mutation tests clone the session database; IPv4/IPv6 plain
reference decodes are shared. A third tiny-fixture worker requires at least six CPUs (four on Windows) and 6 GiB
available RAM; smaller hosted runners keep two. Windows tiny-fixture SQL uses one thread per
process to avoid competing two-thread pools; production/large benchmarks retain two threads. Cancellation closes the reader pipe before waiting
for tshark and signals batch workers before executor shutdown.

The TLS probe absence guard failed before the completeness fix (1 failed / 5 passed, 0.08 s).
The stale-generation negative guard failed before cache cleanup (0.05 s). Both pass in the final
suite. Sparse-frame batch tests preserve foreign points, incomplete identities, original frame
ordinals, timestamps, interface IDs and hashes against a shared tshark reference. Tunnel/fragment
repair checks: 24 passed in 23.70 s; preflight/overlay/API scope checks: 11 passed in 7.26 s.
Ruff and TypeScript/Vite pass. Hosted Windows enforces **<240 s** from JUnit timing; full CI runs
six OS/Python targets, slow tests on macos-14/Python 3.12 only, and three native packaging smokes.
The final CI run URL, Windows timing and completed matrix are recorded in the PR validation
section, avoiding another matrix solely to append a post-run documentation URL.

### Pilot use and boundaries

Case tests cover recursive discovery, sibling project placement, original input byte equality,
ready/cache reuse, preservation of manual topology, tunnel/truncation/drop/tail warnings, raw
non-overlap caveats and interruption. Overlay tests reject out-of-coverage/out-of-analysis zeros,
verify selected denominators/p95/retransmissions, exact arrow inspection and sortable supported
reset-origin/same-clock handshake timing. A no-server capture still permits supported client-side
injections: the negative column fixture therefore removes **both** endpoints rather than assuming
all reset origins become unknown after removing only the server.

The topology overlay, its colors and device-drop badges follow the brush. Complete-exchange
waterfalls and selected-packet field differences explicitly disclose their wider scope. Inventory
and exports retain full context. Node counts are observations/adjacent events, not device fault
counts. Fragment loss matching uses logical datagrams; physical sub-bucket rates remain separate.
Application visibility across fragmented/tunneled captures is bounded and may remain unknown;
TLS 1.3 certificates, missing endpoints and uncertain clocks are not inferred. No real incident
analysis or production certification is claimed by these synthetic checks.

Initial full matrix run [38267794980](https://github.com/ozandurmus/packetbreaker/actions/runs/38267794980):
all four macOS acceptance jobs (including slow coverage) and all three packaging jobs passed.
Both Windows jobs exposed platform-dependent relative labels (`\\` versus `/`); product labels
now use `Path.as_posix()`, preserving the assertions. Their fast durations were 266.74 s (3.12)
and 326.61 s (3.11), above the pilot target. The retained Windows profile drove the fixture SQL
thread budget/prefetch adjustment; the final replacement run remains the acceptance gate.
Manual local UI verification exposed long arrow labels overlapping nodes on the narrow panel.
Compact labels above same-row nodes plus a legend retain all three values; arrow clicks still
open the inspector. Scope notes, case warnings and handshake/reset sort options were visible.

Second CI run: Windows 3.12 passed the duration gate, and Windows 3.11 passed all assertions
(437 passed / 1 skipped) but took 258.27 s. Prepared fixture handles now reuse already validated,
closed current-schema databases instead of repeating migrations in the parent/clone path. Real
constructor/reopen tests remain unchanged. Local regression after this test-only optimization:
438 passed / 166 deselected in 86.51 s. Production ingest/analysis and benchmark budgets are unchanged.

## Phase 4 / Part 4 — lifecycle and security heuristics

PR #12 was merged at `478c85b` before creating `phase4-part4`. Lifecycle negative tests were
written first (initial collection failed because the implementation did not exist). They reject
invented sessions after capture misses, duplicate occupancy for SYN retries, zero occupancy with
unknown clocks/coverage, and establishment inferred from an ACK flag with inconsistent sequence.
SYN-pattern and export focused gate: 4 passed in 7.01 s. The healthy flash crowd exceeds the
rate floor but does not trigger; missing coverage cannot support a flood pattern. Lifecycle plus
bucket regression: 8 passed in 8.10 s. TypeScript/Vite build passes after fixing the JSX wrapper.
Scan negative/positive tests were added before implementation: the required scan assertion failed
(1 failed / 3 passed). Final combined SYN/scan gate: 4 passed in 5.11 s. Healthy health-check,
NAT-pool, endpoint FIN closure and downstream-completed capture-miss traffic do not become scans.
Pressure guards were written before implementation (2 failed / 4 passed). Final focused gate:
6 passed in 5.33 s. A source-spread SYN wave traverses FW1 but is positively dropped at FW2;
only FW2 receives supported pressure corroboration. Removing device proofs while preserving
supported handshake disappearance yields unknown, with the missing-device-evidence reason.

Final local default gate: **464 passed / 166 deselected in 112.89 s** (630 collected,
**26 new fast tests**, none moved to slow). Before the last fixture strengthening: 464 passed
in 111.42 s. The first complete run was 458 passed / 5 failed in 102.37 s: all failures were
legacy exact-v5 assertions after the explicit schema-v6 change; their full field-diff, TLS and
positive-drop assertions remain intact. Focused affected-regression gate: 53 passed in 18.66 s.
Final new-security/lifecycle gate: 26 passed in 21.15 s. Ruff and TypeScript/Vite pass.

Nine real-tshark synthetic fixtures cover FW1, FW2 and their link × IPv4 zero/constant ID and
IPv6. Each shares healthy flash-crowd, health-check and NAT-pool distractors with the irregular
SYN wave and port scan; every NAT pool address independently exceeds the target-count floor
with successful handshakes. Exact pressure support names only the evidenced device; a link
has no invented device. Occupancy ground truth is 260 at bucket 16 at the client. Reverse
SYN/ACK stopping evidence and late FIN closure are independently asserted. The latter failed
before removing the half-open observation timeout from established-session closure lookup.

Three SQL mutants executed on the same captured populations are rejected by the acceptance
contracts: `syn_rate >= 50` alone flags the flash crowd; `targets >= 20` alone flags the healthy
checker/NAT pool; any-drop × all-device-spikes blames both FW1 and FW2. Quality mutations cover
missing point coverage, unknown clocks, capture drops, unconfirmed translation and local missing
handshake completion with healthy downstream evidence. Generic disappearance without device
proof yields unknown pressure. Bucket API validates finite ordered times and point ownership;
HTML/JSON exports retain frame/content filters and full-window scope.

All captures are generated into test temporary directories or ignored demo storage. None is
tracked. Coverage audit now has **79 done / 12 partial / 3 missing** rows. Observed lifecycle is
not an internal device table, and heuristic traffic shape is not intent or resource-exhaustion
proof. The PR full-matrix acceptance (six OS/Python plus three native packaging jobs, slow suite
only macos-14/Python 3.12) is the remaining close-out gate. Its final run URL and measured hosted
Windows duration are recorded in the PR validation section to avoid a matrix just for a URL edit.

Initial PR CI run `38301335270` passed all test assertions, but Windows missed its duration gate
(3.11: 509.94 s; 3.12: 563.43 s). Its first diagnostic fixture spent 221.60/239.09 s waiting:
late-used security scenarios were queued ahead of special diagnostic/fragment/proxy builders.
The existing session prefetch pool now orders **all** work by its first test consumer, retaining
identical assertions, fixture sharing and process/thread budgets. Final local default after the
queue repair and irregular SYN cohort counts: **464 passed / 166 deselected in 102.23 s**.
No new test was marked slow. New-security focused gate: 26 passed in 22.53 s.

Manual localhost UI caught ranked findings assuming every finding belonged to a segment.
Capture-point heuristics now use point labels/direction when no segment exists, without adding
fake heatmap segments. The browser verified lifecycle totals, bucket-16 occupancy 260, the
200-of-261 failure-example notice and clicking occupancy frames/content filters. Temporary
server/tab were closed. The SYN wave has irregular per-bucket counts 61/79/57/63 and random
arrival times, preserving exactly 260 half-open sessions. Initial macOS arm packaging failed
before build due to runner DNS resolution of files.pythonhosted.org; Intel/Windows packaging
passed. The replacement full matrix on the final source head remains the close-out gate.

The first-consumer repair removed diagnostic starvation, but Windows still took 438.14/446.93 s;
late security-matrix fixture wait was 64.74/69.30 s. One full default-threshold dataset and its
strict **260** occupancy assertion remain. Nine compact location/ID/family fixtures configure
proportional floors: SYN rate 8, sources 5, fan-out 8, half-open floor 5; occupancy is strictly
**48**. Each healthy NAT-pool address independently reaches the fan-out floor. Thus all signal,
false-positive, device/link, evidence and coverage assertions remain, without duplicated large
populations. No case moved to slow and the Windows 240 s gate remains unchanged.

Native maximum-SYN bounds skip joins only when even all observed sessions cannot reach any
heuristic floor. Tests lower a floor to force the complete detector path and reject an unsafe
shortcut; a no-SYN guard proves unknown state/occupancy. tshark directly checks the generator's
increment/random IP-ID choices; zero/constant/IPv6 retain the matrix. Final local default:
**468 passed / 166 deselected in 93.69 s** (**634 total / 30 new fast tests**). Ruff and bundled
TypeScript/Vite pass. Final hosted acceptance remains the close-out gate.

After compact fixtures/native event bounds, Windows passed every assertion but still exceeded
240 seconds (3.12: 295.58 s). `tools/windows_fast_suite.py` now executes the identical complete
fast collection in two isolated processes **inside** each existing Windows job. It verifies that
JUnit total equals collected cases and that failures/errors are zero. The 240 s gate measures
wall time from before collection through process teardown, not summed parallel process duration.
No case is omitted or marked slow; one fixture worker per process avoids nested oversubscription.
Partition/coverage negative guards are fast unit tests; full hosted execution is the close-out gate.

A new real-tshark `security_reply` scenario has SYN/ACK replies but no final ACK; its positive
pattern test failed before changing the erroneous AND of ratios to the requested OR. A late
sequence-consistent handshake still counts after half-open observation expiry; the timer limits
occupancy only. Healthy-completion thresholds cannot be configured to include ratio 1.
Final local default: **473 passed / 166 deselected in 96.14 s** (**639 total / 35 new fast cases**).
Ruff and TypeScript/Vite pass. The remaining hosted wall-time/full-matrix result is recorded in
PR #13 before close-out. Large-capture ingest/analysis/RSS was not re-benchmarked in this part.

## Phase 4 / Part 5 — UDP, RTP and SIP

PR #13 was merged at `e6c0a06` before branching `phase4-part5`. All new captures are wholly
synthetic. Initial UDP contracts failed before pipeline integration (unknown fixture); subsequent
execution caught the disabled external-file-access constraint. Bounded field batches preserve
that security boundary. Nine real-tshark point-isolated fixtures passed in 15.36 s: exact FW1,
FW2 or inter-device-link response stops × zero/constant IPv4 IDs and IPv6; known NTP/SNMP/RADIUS
turnaround; syslog no-response expectation; ambiguous unknown ownership and a pure capture miss.
TypeScript/Vite and Ruff pass. Further media/SIP acceptance and full CI follow at close-out.


Part 5 RTP: zero/constant IP ID and IPv6 fixtures use two firewalls, LB and links, concurrent NAT calls sharing ports/SSRC, sequence/timestamp wrap, duplicate/reordered packets and a pure capture miss. 18 UDP/RTP tests passed in 18.12 s before SDP-directed decode hardening; final gate below supersedes this checkpoint.


Part 5 SIP: the pre-integration fixtures failed because SIP comparison was absent. The first integration correctly compared the rewriting hop but failed all nine mismatch assertions: a two-port SDP rate JOIN duplicated RTP rows and made call ownership ambiguous. A scalar unique-rate lateral JOIN fixed cardinality; all 28 UDP/RTP/SIP cases then passed in 21.25 s. Additional clock, missing-endpoint, legitimate sendonly and RFC 3550 header-oracle guards passed (22 SIP/RTP cases, 21.53 s). No acceptance assertions were removed.


Part 5 final fixtures share one original eight-interface pcapng per mode: client, FW1 ingress/egress, FW2 ingress/egress, LB ingress/egress and server, with reverse path. Faults vary across FW1, FW2 and their link; zero/constant IP ID and IPv6 repeat the acceptance. Two simultaneous calls deliberately collide on SIP/RTP ports and SSRC across confirmed NAT; loss is intermittent, jitter starts only at LB, with real duplicate/reordered/wrapped RTP headers. Separate healthy and capture-miss-only populations, missing endpoint/clock, sendonly, video, dynamic clock, partial reply and inventory-drop controls are fast tests. Executed naive alternatives (nearest UDP candidate, SSRC-only streams, receiver-only jitter blame, every SDP change as bug and always-first-FW attribution) violate the same ground truth in `test_media_mutants.py`. Portable evidence filters are executed by tshark; RFC 3550 values are independently recomputed from tshark-decoded headers. The initial incomplete-response guard failed (`unanswered`, expected `unknown`) and was fixed. The first full fast gate passed 512 tests but exceeded the budget at 127.11 s; batching evidence and avoiding empty-point work reduced it to 117.13 s, with no deleted assertions or new slow marks. The latest full gate and CI status are recorded below. No capture files are tracked; demo stays ignored. Source, branch and docs changed; no live device or real capture was used.


Final Part 5 local gate: **513 passed, 166 deselected in 118.08 s** (679 collected; 40 new fast tests vs the Part 4 baseline). `ruff check src tests tools`, `git diff --check`, and `npm --prefix frontend run build` passed. No new slow marks. Full hosted gate: six OS/Python acceptance jobs (slow matrix only macos-14/3.12) and three native packaging/smoke jobs on the Part 5 PR; see its checks for the exact final-head run and logs. The media views and offline exports include decoded protocol identities and tooltip/evidence references.


Initial full CI run: https://github.com/ozandurmus/packetbreaker/actions/runs/38383805639 . Windows/3.12 exposed a pre-existing cancel/resume cleanup race (`stderr.log` held open during temporary-directory removal); all other completed jobs passed, including the slow macos-14/3.12 matrix and all three native packages. stderr now uses an independent auto-closing TemporaryFile and the child is always reaped, even after poll reports exit. A deterministic already-exited-child cancellation guard failed before the fix (wait count 0) and passes afterward; five focused cancel/resume/shard tests passed in 0.68 s. Initial Windows/3.12 wall time was 231.40 s, with one failed test and one intentional optional-sample skip. Shared VoIP test files now stay in one Windows shard so their session-scoped tshark fixtures are built once; every collected test remains accounted for. Final-head results are available at [PR #14 checks](https://github.com/ozandurmus/packetbreaker/pull/14/checks).

Latest local full gate after CI hardening: **515 passed, 166 deselected in 116.57 s** (681 collected; 42 new fast tests versus Part 4). No assertions weakened or moved to slow. Ruff and whitespace gates remain clean.


Second full CI run https://github.com/ozandurmus/packetbreaker/actions/runs/38385366033 passed every functional test and all macOS/packaging jobs, but Windows elapsed budgets failed at 328.68 s (3.12) / 331.86 s (3.11). Shard case counts were balanced while real elapsed costs were not (141.21 vs 325.34 s). A local two-shard profile passed all 517 tests and recorded per-file JUnit elapsed costs (132.16/162.53 s; 163.77 s wall). `windows_test_costs.json` stores that measured scheduling profile; the runner co-locates VoIP/proxy families and balances elapsed costs, with an explicit 1.5× VoIP scheduling allowance for hosted tshark startup (an estimate, not a benchmark claim). It logs all per-file timings for future validation. `proxy_capture` now depends on the same session prefetcher as fragment/burst fixtures, preventing an early standalone proxy build followed by unused duplicate prefetch builds. Six focused coverage/cost/shard tests passed in 0.03 s. The 240 s hosted gate and every test assertion remain unchanged.

Local default gate after cost balancing and prefetch sharing: **518 passed, 166 deselected in 114.12 s** (684 collected; 45 new fast tests). The separate two-shard profile is not the default-suite duration. Ruff/whitespace and six focused runner tests pass; no new slow marks or relaxed time gates.


## Pilot fixes — stage semantics

Stage capture mode is declared per device through capture points. rx/ingress precedes tx/egress in both directional paths; physical wire interfaces keep the ordinary reversed return order. Clock calibration derives orientation from those actual directional paths. TTL wire-hop checks and reverse-edge detour checks are suppressed at stage endpoints because capture hooks are not physical interfaces. Two negative/ordering contracts failed before the change and pass after it; full multi-device wire replica follows.


Pilot shared clocks: points may name one source clock domain across files. Its fitted/reference parameters are inherited without relative fitting. Automatic inference requires both directional populations, temporal span and stable near-zero positive transit; it is labelled inferred, with the observed bound as uncertainty, because small offset and physical transit cannot be distinguished. Host captures are excluded from automatic grouping. Clock-domain and existing clock regression checks: 7 passed.


Pilot timestamp jitter: robust adjacent calibration-delta variation estimates a per-capture timestamp-noise bound, capped at 2 ms so selective 100 ms+ host events cannot be trained away. Small crossing clock envelopes may use robust centers; gross inconsistent envelopes remain unknown. Transit is invalidated only by a systematic negative median beyond jitter plus offset uncertainty. Isolated negative outliers remain explicit quality notes; latency shows its combined uncertainty. Nine stage/clock/jitter/invalid-override checks pass.


Pilot host scope/memory: non-host points are selected and decapsulated first. Host observations are restricted to conversations present on those points (including confirmed NAT tuples) before wide matching/calibration tables are built. `analysis_scope` reports input/retained/excluded frame counts; captures themselves are untouched. DuckDB retains its 512 MB budget and spill directory with insertion-order preservation disabled. OOM becomes an actionable message and preserves ingest checkpoints. Scoped host application decoding uses the same selected tuples and a bounded filter, not the unfiltered host stream. The six-file replica now has reliable clocks on every segment and no supported loss/asymmetry/TTL findings; host timing report is the next integration step.


Pilot host-path diagnosis: matched TCP byte ranges produce separate RX and TX per-flow/per-second series, peaks, matched bytes and byte-weighted excess-delay shares. A host capture is explicitly tagged; no application cause is inferred from the boundary alone. Same-host HTTP request-completion/first-response boundaries come from tshark. Opaque protocols expose only ACK-consistent data-burst turnaround, while application timing remains unknown. Host headlines, frame filters, uncertainty, scope exclusions and HTML/JSON export schema 8 are integrated. The current synthetic six-file replica passes clock, no-false-loss/integrity and <1 ms local HTTP timing checks.


Pilot event windows: latency uses three excursions within a bounded 15 s interval against the early median/MAD baseline, followed by three healthy observations to confirm recovery. Idle sampling gaps do not require consecutive one-second crossings. A host incident combines RX/TX into one observed window while retaining directional first-delay data and separate before/event/recovery raw latency distributions. Propagation ties still use the onset bucket, not the entire incident duration. Byte-range matches supply onset evidence for GRO/TSO. Host boundary onsets are labelled separately from network segments and enter the executive summary. Pilot plus existing fast onset regressions: 26 passed.


## Pilot fixes — final local validation

- PR #14 was merged at `2cf6e6f` before branching `pilot-fixes`. Real captures were not opened, copied or committed.
- Default fast suite: **529 passed, 179 deselected in 111.66 s**; Ruff and bundled TypeScript/Vite passed. Added 11 fast cases and 13 slow cases. The slow additions are a 12-cell, six-file real-tshark location/ID/IP-family matrix and the one-million-frame ingest/analysis test; they do not replace or weaken fast assertions.
- Replica: reliable clocks on all 10 directed segments; no supported loss/asymmetry/TTL finding; correct mirror/host RX/TX localisation, event endpoints within one second, RX/TX delay shares within 0.2 percentage points of ground truth, max delays within 1 ms, local HTTP p95 below 1 ms. IPv6 also passes automatic shared-clock inference and the healthy-flow negative guard.
- Initial wire replica reproduced bad segment quality before host cohort filtering; after the clock/stage/scope fixes it reached the missing host-report assertion, then passed the complete timing/window contract. Stage ordering, any-negative-invalidates and before/after-average naive contracts are explicitly rejected by `test_pilot.py`.
- Device/link matrix: A/B device controls and healthy controls passed; the mirror-link fixture initially injected its reverse delay before the mirror (the host boundary), so it correctly produced a host TX finding. The generator was corrected to inject on mirror→B.rx, the same physical link as B.tx→mirror. All three repaired link variants passed; assertions stayed intact.
- Million-frame synthetic host: **1,000,222 input frames → 222 selected**, with exactly one million unrelated host-only frames excluded. Ingest **93.424 s**, analysis **35.021 s**, test completed without OOM or false loss/integrity attribution.
- Independent cold analysis of that same generated project (application decode cache cleared): **33.714 s**; `/usr/bin/time -l` wall **33.94 s**, command maximum RSS **666,501,120 B (635.6 MiB)**. This is whole-command RSS, not a claim that the 512 MB DuckDB setting caps total runtime memory. The first sandbox time command could not read `kern.clockrate`; the successful RSS measurement used the approved statistics read.
- Spill smoke: with external file access still disabled, a generated 500k-row sort under a 96 MB SQL setting completed and JSON profiling on stderr recorded **97,550,336 B peak temporary storage**. A 32 MB probe exhausted a non-spillable/pinned allocation and exercised the actionable error path. No file-access permission was widened. DuckDB documents larger-than-memory support and remaining blocking/aggregate limitations: https://duckdb.org/docs/current/guides/performance/how_to_tune_workloads.html .
- Full hosted acceptance remains the PR close-out gate: six OS/Python targets, slow tests only on macos-14/3.12, and three native packaging/smoke jobs.

Cached reopen of the same 1M-frame project took **0.046 s** with subprocess creation patched to fail; its saved host report remained available and no parser launched. Measurement runtime: DuckDB 1.5.6. Final focused clock-domain-conflict and waterfall checks: 5 passed in 3.22 s.


Initial full pilot CI: https://github.com/ozandurmus/packetbreaker/actions/runs/38410851390 . All platform fast suites and native packaging passed; the slow job passed 169 tests (including the new scale case) but failed 10 existing continuous-delay/propagation onset cases. The event-quality check incorrectly included the first uncaptured bucket at the event's exclusive end. A new fast trailing-bucket guard failed before the fix; changing the comparison to a half-open interval preserves a confirmed ongoing onset with recovery unknown. All 28 slow onset regressions then passed locally in 25.42 s. No expectation or timing gate was weakened.

Final local default after the trailing-window regression fix: **530 passed, 179 deselected in 112.52 s** (709 total; 12 new fast and 13 new slow cases). Ruff/whitespace gates remain clean.


Second pilot CI (https://github.com/ozandurmus/packetbreaker/actions/runs/38414264095) passed all 179 slow cases and every functional assertion. The balanced Windows shards exceeded the unchanged 240 s wall gate at 247.87/262.27 s. The runner now selects at most three isolated processes, bounded by CPU cores minus one and 1.5 GiB available RAM per parent/fixture-producer pair; each still has one fixture worker. The six OS/Python jobs and exact JUnit/collection check are unchanged. Local end-to-end runner: **531 tests, zero failures/errors/skips, 101.44 s wall** across 87.97/93.58/100.29 s shards. Seven focused runner tests passed in 0.03 s. This runner timing is distinct from the last bare-pytest default timing (530 tests / 112.52 s); the only added case checks the CPU/RAM budget. Pilot additions now total 13 fast and 13 slow tests.


Three-process hosted experiment (https://github.com/ozandurmus/packetbreaker/actions/runs/38416926815) did not improve the four-core Windows budget: all functional cases passed, wall times were 280.44/251.95 s. Actual execution is capped at two again, still bounded by CPU/RAM. Work was removed instead: clock direction ordering is computed once per point pair, impossible near-zero clock candidates avoid extra inference work, and timestamp-noise sorting runs only when an envelope crosses. For explicit UDP decode-as and no TCP SIP, one source-level header pass is shared across points; original-frame/tuple/time validation remains. TCP SIP, SDP-driven state, vendor and layer paths retain point isolation.

A new equivalence/negative guard verifies **1 batched tshark call versus 16 isolated calls**, equal decoded fields (excluding decoder-local frame numbering), original frame identity, and forced isolation when a TCP SIP probe exists. Related media/pilot tests: **41 passed in 13.91 s**. Final local default: **532 passed, 179 deselected in 111.13 s** (711 total; 14 new fast and 13 new slow cases). Ruff/whitespace pass; no assertion or CI duration threshold was relaxed.


## Pilot polish / anonymizer — item 0

A supported host boundary event window with the largest added delay leads the ranked findings and executive summary at high severity. An isolated earlier packet loss cannot displace it by timestamp alone. Positive retransmission delivery at a host/wire boundary gets a host receive/transmit-path loss label; recovery class remains in metrics and internal event counters, preserving loss-rate accounting. Capture misses, absent recovery, uncertain coverage and ordinary device/link losses retain their classifications. Findings export schema 9 adds both boundary classes. The boundary does not prove a particular driver/NIC cause.

Focused pilot checks: 21 passed, 13 slow cases deselected in 4.57 s. Tests include two devices and a link as negative attribution candidates and an executed naive severity/time ranking that incorrectly prioritizes an isolated loss. Full suite/CI are the final close-out gate.

Anonymizer implementation checkpoint: generated planted-secret fixtures exposed an
ERSPAN leak when tshark's enclosing protocol size was mistaken for its header size.
Bounding it at the next decoded protocol fixed the failure. CLI, UI ZIP, IPv4/IPv6,
little/big-endian pcapng, both payload modes, all five tunnel formats and ICMP quotes
pass; exact TCP transport report/onset comparison passes in zero-ID and constant-ID
IPv6 modes. Initial 10-test run: 14.18 s. Final proof and complete gates follow below.

Proof extension: the six-point stage-clock/jitter/GRO pilot initially differed after
headers-only export because byte calibration required a payload prefix; removing that
gate also required coalescing NULL prefixes. Then exact uncertainty equality exposed
address-dependent hash sampling and unstable same-time jitter ordering. Stable frame
sampling/order fixed both; all three exact transport-equivalence cases pass (zero-ID,
constant-ID IPv6, and headers-only GRO/TSO pilot), while the removed HTTP service data
is explicitly unknown. A negative cardinality test keeps repeated sequence starts out
of clock calibration. Positive RX/TX retry delivery localizes to the host boundary;
FW, LB and inter-device link distractors do not receive those labels.

Initial full fast gate: 554 passed / 179 deselected in 134.00 s, over budget. Shared
preparation and batched oracle reads reduced a subsequent measurement to 117.41 s;
that run caught a test adapter treating the ingest column list as a dict, fixed without
changing its assertion. The next all-green run was 556 passed in 122.25 s, still over
budget. Native SQL fixture pools were then limited to one thread on every OS; the final
measured gate below supersedes these checkpoints. No tests or assertions were removed
or moved to slow. No real capture or key is tracked.

Final local full gate: **558 passed, 179 deselected in 119.07 s** (737 total;
26 new fast tests versus PR #15). Ruff, whitespace checks and the TypeScript/Vite
production bundle pass. No new slow marks. Added fixtures cover metadata/TLS-secret
leaks, MAC/IP masking, quoted and tunnel headers, checksum preservation, default-IP
retention, prefix consistency, damage/no-overwrite cleanup, CLI/UI ZIP, exact TCP
transport/onset and GRO/TSO host-window equivalence. The XML JUnit profile supplies
new anonymizer/pilot scheduling costs to the existing Windows runner; its complete
collection and 240-second wall gate remain unchanged. The existing full CI matrix
and native packaging remain the PR close-out gate.

Initial hosted run: https://github.com/ozandurmus/packetbreaker/actions/runs/38455217663 .
All three native packages and macOS arm64 acceptance (including the slow suite) passed.
Windows passed every functional assertion (558 collected, zero failures/errors, one
intentional optional-sample skip) but failed the unchanged wall gate: **294.77 s on
3.12, 276.90 s on 3.11**. The 3.12 shards were 216.74 / 291.07 s; anonymizer cost was
48.49 s versus its 9.44 s local estimate. The runner now uses actual hosted per-file
costs, without the former local-to-Windows VoIP multiplier, and keeps anonymizer,
pilot and evidence consumers together. Equivalence builders expose their original
project as the shared scenario baseline, eliminating duplicate ingest/analysis.
An identity assertion proves that reuse; no acceptance assertion is removed.
Related fixtures/scheduling checks: 46 passed / 17 deselected in 19.44 s.

A final source-stability guard refuses publication if file identity, size or modification
metadata changes while tshark/container streams are read. The generated concurrent-copy
guard passed in 0.20 s; output and temporary files are absent on failure. Final count:
559 fast tests plus 179 existing slow cases. Final-head CI is linked in PR #16's checks;
this initial run URL is retained as the performance evidence, not a green certification.

Second full run: https://github.com/ozandurmus/packetbreaker/actions/runs/38457338884 .
Final local gate at that head: **559 passed, 179 deselected in 119.26 s**. Windows
3.12 improved to **195.72 s**; 3.11 still took **266.00 s**, with zero functional
failures and shards 262/223 s. The next correction exports only tshark's header
protocol trees (`-J`) instead of serializing application payload into PDML. On the
2,222-frame synthetic host capture this reduced anonymization from **2.84 to 2.02 s**,
with byte-identical output. A new full-tree/projection byte-equivalence guard and all
17 anonymizer cases pass (18.13 s). Current Windows weights use the slower 3.11 profile.
No time gate or assertion was relaxed. Final collection is 560 fast + 179 slow cases.

## Real-case round 2 — local validation

PR #17 and #16 were merged before branching `real-case-2` from `ccc8c0b`.
No real capture was read or committed for this work; fixtures are generated locally.

- The old global byte budget failed its reduced-limit regression before the change;
  per-flow work units now complete it. The nearest-point/no-mirror and short shared-clock
  host tests pass; disconnected declared domains retain relative clocks.
- The 50-flow six-file replica passed in **39.47 s**: all 50 flows survive, host-local p95
  remains below 1 ms, only mirror→host has hold/release signatures, and no high MTU/TTL/
  asymmetry false positive appears. Native saved-table inspection confirms four TX drops
  and zero TX-delay classifications at host→mirror; the host event endpoints are within
  one second of the 25-second ground-truth interval. This is not a 2.4M-frame benchmark.
- Six additional FW1/FW2/link, zero-ID/IPv6-constant real-tshark cells passed in **22.82 s**.
  These seven new large wire cases are slow; ordinary guards remain fast.
- Tiny missing ranges (16/84 B), healthy/capture-miss traffic, unexplained IP-ID changes,
  CSV/XLSX structure, complete top-cycle evidence and local service time are fast guards.
  The ID-change guard first exposed that the other ranges of an ambiguous GRO frame still
  entered latency; ambiguity now propagates to those counterparts. An ID change alone is
  never proof of retry delivery. Constant identity stays unknown where necessary.
- One full default run: **564 passed, 3 failed, 186 deselected, 153.24 s**. Failures were
  integration regressions: failed clock attempts prevented an independent proxy-leg
  reference, a minimal clock fixture entered a host-only fallback, and a standalone PA
  drop segment was treated as a timing edge. All three were corrected without weakening
  assertions; the three affected tests plus seven new fast guards then passed:
  **10 passed, 7 deselected in 12.24 s**. The full suite was not repeated, per AGENTS.md.
- Ruff, whitespace and TypeScript/Vite production build pass. Final collection: **567 fast
  + 186 slow = 753 tests**, 14 new tests versus the prior 739. Local timing is advisory;
  no test-speed or CI-runtime optimization was attempted in this task.
- Export schema 10, generated UI assets, README, architecture, decisions and coverage notes
  are updated. CI is checked once after the single push/PR; pending or infrastructure/timing
  status is reported without polling. Actual full-scale performance and real-case agreement
  remain for the user's local incident re-run.

## Real-case round 2: two remaining blockers

Synthetic inputs only; PR #18 merged before branching `real-case-2-fix`.
The correlated ±150 µs timestamp test failed before the fix (`offset=None`). After the
percentile-envelope fix, the focused clock/ACK checks passed (11 tests, 4.85 s), and all
five new regressions passed (6.40 s). The wire replicas remove the adjacent mirror and
exercise IPv4/IP ID zero and IPv6/constant IDs: clock error <0.1 ms, RX/TX present, event
bounds within one second, host-local response p95 <1 ms, and a host-path verdict without
overrides. A truly infeasible clock and one-way timing remain unknown.

One full fast-suite run: **572 passed, 186 deselected in 157.62 s** (concurrent with the
requested large ingest measurement). No full-suite rerun. Ruff and whitespace checks pass.
The ACK guard fixture preserves ACK-before-retry and no-retry originals, removes a proven
retry-delivered original, and deliberately collides base keys between different flows.
The scale script is `tools/real_case_2_scale.py`; it retains the default 512 MB DuckDB limit
and generates 2,016,088 frames across six captures (50 flows, 750 rounds, unrelated host
traffic). Generation took 23.88 s and ingest took 148.52 s in this run.

Scale acceptance **passed**: 2,016,088 input frames, 50 byte-range work units and 1,942,424
atoms; analysis **359.27 s**, complete generation+ingest+analysis command **532.09 s**.
`/usr/bin/time -l` maximum resident set size **2,641,215,488 bytes (2.460 GiB)**; this includes
generation and ingest, not just the DuckDB working set. Peak memory footprint was
1,923,303,416 bytes; no swaps. DuckDB retained its 512 MB budget and spilled to disk.
The host model used **20,000 samples**, offset **39.998317 ms** versus 40 ms truth (error
**0.001683 ms**), uncertainty **0.878656 ms**. RX event bounds were BASE+19 through BASE+46,
within one second of BASE+20..45 truth. The host-path verdict appeared. In this replica TX
is original loss plus retry delivery, rather than a falsely reported TX delay; the compact
jitter replicas separately verify both genuine RX and TX holds. The large case completes
without the ACK-guard allocation failure. No claim is made about the user's untested capture.

## Real-case 2b: aggregate incident summary and visualisations

PR #19 merged before branching `real-case-viz`. All inputs are original synthetic fixtures.
The new replica has 50 concurrent flows, 25 with host RX/TX holds, two stage devices/shared
clock, no adjacent mirror in the selected topology, ±150 µs host jitter, 1% stage capture
misses, GRO and unfiltered host noise. One healthy-network application flow has 188 ms local
turnaround; it must not own the aggregate headline. The tests assert exactly one finding per
direction, exactly 25 affected flows, all 50 flows in drill-down, a global event window within
one second, and the exact raw-cycle aggregate p95 (not an average of per-flow percentiles).
A separate mixed-loss guard preserves the 284 generic + 14 host-TX subtype counts beneath
one boundary heading without inventing a device cause.

Focused pilot/engine/clock integration: **33 passed, 20 deselected in 16.30 s** before the
final presentation additions. Reference/runner guards: **25 passed in 0.29 s**. The first
new presentation check exposed a test-only `str.decode()` misuse; the export returns text
and the test now uses it directly. No assertion weakened, no test moved to slow.

The synthetic UI renders the global 25-flow headline, timeline periods and cycle components.
A timeline drag was verified to set the shared selected interval and filter the displayed
chart data. TypeScript/Vite production build and Ruff pass. The offline export embeds its
ECharts asset and local renderer; no CDN or external asset is needed. The final fast suite
runs once through the existing isolated-process runner with four shards on this 10-core
machine; every collected fast test must appear in the JUnit totals.

Final full fast run, once, using **four isolated shards on 10 cores**: **593 collected and
593 executed**, **591 passed / 2 failed**, **126.77 s wall**. The failures were this change's
fixed-code script-count layout and a synthetic stage point lacking its ingress side. The
HTML now combines its trusted executable assets into the existing single code script
(the inert JSON script remains separate); the injection/external-asset assertions are
unchanged. The fixture declares ingress. Both failed checks then passed: **2 passed in
3.10 s**; the full suite was not repeated, per efficiency rules. Twenty-one new fast tests;
186 slow tests retain their existing policy.

A focused refresh of presentation projections against the already ingested 50-flow fixture
verified missing RX/TX components remain null, without repeating tshark or analysis. The
offline renderer was visually checked: timeline/stack rendered, no console errors, a point
click exposed concrete frame/content/flow filters. It uses embedded assets only. Live timeline
brushing was checked against the shared selected interval. Plain serial pytest remains
available; the new parallel runner defaults to four locally and applies CPU/RAM caps.
The prior 157.62 s serial run contained 572 tests and ran alongside a scale benchmark, so
these figures are not claimed as a controlled same-workload speedup. No real-case capture
was read or committed; the user's local re-run remains the incident verification.

The final frame-evidence audit found that a wire-side packet key could resolve to the first
four wire observations and omit the host. Peak and aggregate-finding evidence now selects
the actual matched keys at both boundary endpoints. The new guard and existing pilot check
passed (**2 passed, 3.90 s**); the same assertions passed against the cached 50-flow projection
without repeating ingest. Final collection is **594 fast + 186 slow** (22 new fast tests).
Runner partition guards passed (**7 passed, 0.03 s**); subsequent runs reuse per-file timings
from the same platform to balance shards instead of using only hosted Windows estimates.

## Aggregate reference metrics (0.3.9)

PR #20 merged before branching `aggregate-metrics`. The Windows asset decode failure is
reproduced by decoding the installed ECharts asset as cp1252. The HTML guard asserts explicit
UTF-8 at every asset text read; the source AST guard requires explicit encoding for all text
read/write/open calls, excluding binary captures and ZipFile streams. Both guards passed
(2 tests, 0.17 s). Compare/report/template CLI text files and synthetic JSON writes also
use UTF-8. No real capture is used.

`pytest -n auto` uses four resource-bounded workers on this 10-core machine, loadfile scheduling
and locked shared source fixtures/private DB copies. Focused UTF-8/reference checks passed
(20 tests, 1.11 s); pilot/host-jitter checks passed (4 tests, 5.51 s). The initial aggregate
fixture check correctly matched 1,350 unique cycles and 352 stalled cycles, but its test
expected a client port where the existing engine stores service port 8080. The assertion now
checks service port plus the selected flow's client-port range, preserving the app-only
slow-flow distractor guard. The full fast suite runs once at close-out.

Final complete fast suite, once: **599 passed in 146.53 s**, `pytest -n auto` (four workers,
loadfile), with shared source fixtures and private writable DBs. All 599 fast tests executed;
186 slow tests retain their existing policy. Ruff and whitespace checks pass.

The 50-flow replica verifies **1,350 unique cycles**, **352 stalled** (325 incident cycles
plus 27 app-only 188 ms distractor cycles), a ~1,300 ms maximum RX+TX boundary addition at
the affected flow/service port, and frames at both sides. Server-local application time is
excluded from that maximum. Event counts tolerate only the documented onset edge/jitter;
RX share is checked against generated truth, and silence against the actual bracketing host
frame timestamps. Both directions have exactly 25 flows with >= stall_ms boundary samples.
Multi-hop packet appearances produce zero repeat groups. The separate RTO replica produces
positive repeat groups in both directions and verifies peak count against the selected host
point, without multiplying by capture hops. Missing host/event metrics are not-computed.
No real captures or new large benchmark were used. Windows jobs are read once after PR
creation, with pending/failure status reported without a monitoring loop.

## Real-case 3: resource budget, scope and no-baseline host delay (0.3.10)

Synthetic fixtures only, starting from merged PR #21 on `real-case-3-fix`.
New guards verify the 25%-RAM/1–8 GiB defaults, persistent 512 MiB setting, explicit override
precedence, selected-point TCP field reset/merge with untouched peer points, shared/CIDR
flow selection, and capture-start incidents in IPv4/zero-ID and IPv6/constant-ID modes.
The capture-start replica has both stage devices, a healthy flow, jitter, capture misses,
GRO and 2,000 unrelated host frames / 1,000 unrelated tuples. Both RX/TX delays are reported,
the dominant finding is high severity, and onset is explicitly unknown for no pre-event
coverage. The unrelated traffic is absent from the per-point TCP index and counted in quality.

Targeted integration: 66 passed in 16.68 s; new guards: 5 passed in 7.67 s; API/integrity/new
checks: 12 passed in 9.56 s. One complete `pytest -n auto` run: **604 passed in 153.43 s**.
Ruff, whitespace and the TypeScript/Vite build pass. No full-suite repeat or slow-test moves.

`tools/real_case_3_replica.py` generates **604,303 frames / 56 shared flows / six points**.
The initial constrained run exposed two further wide integrity-query allocations after TCP
indexing: unique payload-header pairing and changed-packet aggregation. Both now use narrow
rows/one adjacent pair and fetch full evidence only after choosing frame IDs. Existing
integrity assertions remain unchanged. An HTTP version of the corpus reached the existing
10,000-event application cap, so final acceptance uses opaque TCP and explicitly asserts
successful decoding plus a nonempty TCP state index; it does not count a skipped index as a
pass. The final opaque corpus generated and ingested in **40.37 s ingest time**, then:

| Budget | Native threads | TCP frames re-indexed | Analysis completion |
|---|---:|---:|---:|
| Explicit 512 MiB | 8 | 44,924 | 110.48 s, success |
| Adaptive 8,192 MiB (this host) | 8 | 44,924 | 51.29 s, success |

Both retain 56 flows and the supported host degradation. The default run reuses the point
index cache but still reapplies point TCP metadata; these times are not a controlled budget
speed comparison. Spill stays enabled in both. The corpus is generated from scratch, not
copied from the user's incident. The real incident remains for the user's local re-run.

## UI clarity and frontend refactor

Branch `ui-clarity` starts from merged PR #22. No Python engine or report schema changes.
The original synthetic pilot is reused at 50 flows with 25 affected flows, 100 hold/release
findings, and one application-only 16.188 s cycle. `tools/ui_clarity_replica.py` reproduces it;
captures/project stay in ignored `demo/ui-clarity`. Screenshots show the same saved report
before/after, including hash labels/outlier flattening before, and the aggregate card, readable
labels, display cap and one selector afterward. Only synthetic content appears in images.

Frontend guards: six build-time tests cover unknown/clean classification, uncertainty,
client-port evidence versus service ports/hashes, p99/outlier handling, lossless signature
grouping, human metric units and the <=400-line source limit. Four additional local rendering
checks use the 50-flow report: six evidence-linked summary lines, correct outlier client port,
100 findings rendered as one chart, and the existing Captures/Path/Flows/Settings controls.
**10/10 passed in 0.51 s** against the replica. TypeScript/Vite and Ruff/whitespace pass.
One mandatory `pytest -n auto` run: **604 passed in 127.02 s**; no assertions weakened or tests
moved to slow. Engine fixture data and exports are not rebuilt by these UI views.

The screenshot files in `docs/screenshots/ui-clarity/` are attached by image links in the PR.
The display p99 uses available per-bucket maximum samples, not the full engine population;
partial components remain unknown. Summary/path metrics remain full-window while brushed
charts and the existing flow/finding/ladder requests use the selected interval. The real
incident is not opened. CI is checked once after the single push, without polling.

## UI correctness fixes after real-case review

`ui-fixes` branches from main after PR #23 merge. Synthetic-only frontend checks reuse the
saved 50-flow report; no engine source or real capture changes. Against the preceding model,
a 0.01% recovered-loss segment with 0.1 ms maximum was `degraded`; it is now `clean`. Tests
also retain unknown clock/coverage and distinguish impactful event loss, outside-event minor
loss, and material delay/loss at the thresholds.

Before correction, maximum event-window stack was 16,188.054 ms versus the aggregate added
maximum 1,300.176 ms (server-local time was stacked). RX/TX-only complete stacks now agree
with that aggregate within 1 ms; the test also inserts the aggregate maximum with its own
frames when absent from the elapsed-time top-N list. A separate 1,223 ms addition / 4,000 ms
local / 2,000 ms wait distractor asserts that the stack remains exactly 1,223 ms. Unknown
components remain unknown. No values are rescaled to force the comparison.

**Frontend: 14/14 passed in 0.643 s**, including the replica checks; TypeScript/Vite production
build and whitespace pass. One `pytest -n auto`: **604 passed in 141.76 s**. No tests weakened,
moved to slow or repeated for wall-clock timing. At an actual 800 px browser viewport, all
point labels used nowrap/ellipsis with full-title tooltips; the ten RX/TX legend entries were
one row without pagination, and the browser console had no errors. CI is inspected once
following the single branch push. Existing bundle-size advisory remains unchanged.

## Seamless case setup and finding hygiene (`auto-assemble`)

Synthetic fixtures only on branch `auto-assemble` from `main`. Negative guards precede positive
acceptance for every item:

- **Auto-assemble suggested topology & mismatch warning:** Rejects equal-TTL unaligned captures
  and mid-stream ephemeral-port captures as `ambiguous` instead of guessing from filenames.
  Assembles the 6-file stage-pair + shared-clock + host replica and the 50-flow replica with
  zero manual input, displaying `Suggested topology — review & confirm` with frame-level
  evidence and confirming via one click (`POST /api/topology/confirm`). Reversed stage labels
  (`ark_fw_in.pcap` vs `ark_fw_out.pcap`) emit the informational mismatch warning while keeping
  packet-derived ordering.
- **Downstream-only grouping:** Rejects grouping when `downstream_packet` is upstream of or
  earlier than a `capture_miss`; groups downstream observations following an upstream
  `capture_miss` into one summary line and combined evidence under that `capture_miss`.
- **Chronic low-rate loss:** Rejects event-concentrated burst loss (`sw_rx -> sw_tx`, 24 of 26
  drops during event) while labelling uniform low-rate loss (`fw_rx -> fw_tx`, 26 drops across
  before/during/after, `~205 ms RTO each`) as `chronic low-rate loss (not event-correlated)` and
  rendering `transit clean; chronic loss 0.013%` in `ResultCard`.
- **Ingest pre-filter & `<10%` retention guard:** Does not filter captures `<=5x` peer size,
  computes the reference set from the union of IP pairs of all other captures so same-size peers
  (`GenisSegment1/2`) and both client paths on a shared host capture remain intact, skips the
  filter with a warning when `<10%` of frames would remain, and exposes per-file excluded counts
  in the case summary and inventory.
- **Truthful exclusion ambiguity & multi-path Folder B replica (`multipath-fix`):** Reports empty
  or mostly-excluded captures with exact excluded/usable counts instead of `"share no directional
  TCP traffic"`. Isolates groups so an inconsistent-TTL `LB` group (`status="ambiguous"`) does not
  block the unambiguous `GenisSegment` group (`status="ready"`, assembled and analyzed). When `LB`
  is 7–8 TTL hops upstream of `Segin`/`Segout` in both directions with a `-120 µs` clock offset
  (timestamps ~84–168 µs earlier in both directions), takes order from TTL (`LB -> Segin -> Segout -> host`),
  isolates `LB` into its own clock domain (`clock_domain=None`), fits the ~120 µs clock offset,
  and emits `"LB.pcap timestamps are inconsistent with its TTL position; treated as a separate clock (offset fitted)"`.

Full fast suite (`pytest -n auto -q`): **611 passed**, frontend build and unit tests pass.

