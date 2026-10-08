# Phase 1 validation — 2026-10-08

## Locally verified

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

Known non-blocking tool output: Starlette warns about a future TestClient HTTP
transport change; tests currently pass with httpx. Vite reports a large local
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
