# Decisions

1. Deliver Phase 1 only. Onset detector, vendor adapters, sequence translation,
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
See [VALIDATION.md](VALIDATION.md) for passing local gates, measured scale and unverified platforms. Phase 2 remains unstarted.

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
