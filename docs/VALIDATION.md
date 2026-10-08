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
