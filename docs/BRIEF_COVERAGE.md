# Original brief coverage — Phase 4 / Part 2

This is a report, not an implementation plan or a certification of arbitrary real captures.
Scope: the original **Codex Brief: PacketBreaker — Multi-Hop PCAP Correlation and Path Analysis
Tool**, assessed against this branch (engine 0.3.1). The original requirements are identified
below by section and phrase; the private pasted attachment is not copied into the repository.

**done** means the specified behavior exists, with the named source/test evidence, within its
stated bounds. **partial** means a useful subset exists but the missing part is explicit.
**missing** means no supported implementation was found. A stored field or synthetic packet is
not proof of a metric, detector or UI. Code-reviewed UI coverage is distinguished from tested
backend behavior. CI proves synthetic portability, not production correctness on every format.
All paths below are repository-relative. Tests marked slow remain part of acceptance on the one
macOS/Python 3.12 job; they are not omitted from this assessment. This part implements only the
transport/DNS/stream gaps requested for Phase 4 / Part 2; remaining gaps stay explicit.

## 1. Platform and stack (context)

| Item | Status | Evidence and limits |
|---|---|---|
| Python 3.11+, Windows/macOS, local FastAPI/React/TypeScript/DuckDB | done | `pyproject.toml`, `app.py`, `.github/workflows/ci.yml`; six OS/Python acceptance targets. Windows 10 specifically is not a hosted runner. |
| tshark sole dissector, discovery/override/missing-tool message | done | `ingest.py::find_tshark`, `application_index.py`; `test_api.py::test_upload_path_and_bad_settings`; CI verifies the Windows install path. |
| Streaming ingest/progress/cancel/resume/cache | done | `ingest.py`, `batch_ingest.py`, `test_ingest.py::test_cancel_resume_is_exact`, `test_cache_does_not_launch_tshark`, `test_parallel_ingest.py`. |
| Several-GB captures and 10+ simultaneous large files | partial | Bounded CSV/SQL batches and spill are implemented; `tools/large_benchmark.py`, `parallel_benchmark.py` and `VALIDATION.md` measure five files/5.4M frames. Ten simultaneous multi-GB inputs are unverified. Serial stays the measured default. |
| Prebuilt UI, pip command and native executables | done | `cli.py`, `tools/build_binary.py`, `frozen_entry.py`, `smoke_binary.py`; native CI builds arm64/x86_64 macOS and Windows x64. No installer, publisher signing or notarization. |
| No cloud/login/telemetry/outbound product calls | done | `app.py` loopback/Origin/header/CSP checks; `test_api.py`, `test_assistant.py::test_enabling_and_preview_make_no_outbound_connection`; no provider SDK/runtime CDN. |

## 2. Core workflow (context)

| Item | Status | Evidence and limits |
|---|---|---|
| Create/open project; attach and upload captures | done | `store.py`, `app.py`, `frontend/src/main.tsx`; `test_api.py` project/upload/analysis roundtrips. |
| Inventory: time/duration/count/ISB drops/snaplen/link type/interfaces | done | `metadata.py`, `ingest.py`, Captures UI; `test_ingest.py::test_pcapng_inventory_and_real_tshark`, `test_isb_cumulative_drop_counters`, `test_ingest_tails.py`. Header snaplen and observed caplen are separate; absent counters are unknown. |
| Coverage Gantt, common overlap, outside-coverage warning | done | `Charts.tsx::Coverage`, `analysis.py` window/quality, `timeseries.py`; `test_timeseries.py::test_coverage_and_exact_bucket_rates`, `test_empty_selected_window_is_unknown_not_zero_loss` in `test_analysis.py`. Observed first/last packets cannot attest continuous capture. |
| Drag/drop kinds, arrows, ingress/egress, file/interface/stage selection | done | `topology.py::Point`, `TopologyEditor.tsx`, `main.tsx`; model validation/API tests and vendor selection tests. Rendering is source-reviewed; there is no comprehensive browser automation suite. |
| Optional different return path; JSON topology save/load | done | `topology.py`, API persistence; `test_realistic.py::test_concurrent_protocols_and_asymmetric_path`, `test_waterfall.py::test_confirmed_nat_and_explicit_return_path`. |
| Auto-order suggestion, user drawing authoritative | done | `analysis.py` TTL/time suggestion, `TopologyEditor.tsx` explicit accept action; never silently rewrites the saved path. Source-reviewed UI. |
| Per-node NAT/proxy/seq settings and MSS declaration | partial | NAT/proxy/seq and payload-transform declarations exist in `topology.py`/editor; MSS changes are observed by integrity checks. No separate user-declared expected MSS-clamping policy/threshold control. |

## 2.1 Input formats

| Item | Status | Evidence and limits |
|---|---|---|
| pcap / pcapng | done | `metadata.py`, `ingest.py`; `test_ingest.py`, `test_ingest_tails.py` test both containers, partial tails, padding and invalid timestamps. |
| Ethernet, raw IP, Linux SLL/SLL2, VLAN/QinQ | done | tshark field ingest; `test_ingest.py::test_common_link_types_and_vlan` constructs all five cases, including stacked VLAN. |
| Optional VXLAN/GRE/GENEVE inner decapsulation | done | `capture_layers.py`, `Point.matching_layer`, `TopologyEditor.tsx`; `test_capture_layers.py` compares ERSPAN II/III, GRE, VXLAN and GENEVE with separately decoded plain packets, mixed IP versions and collision distractors. ERSPAN defaults inner; other tunnels require a choice. Outer metadata and layer-scoped filters persist. Nested/incomplete IP envelopes and tunnel+vendor adapters remain unknown. |
| Check Point snoop i/I/o/O and e/E/oe/OE mappings | done | `vendors.py`, `metadata.py`, `device_drops.py`, editor; `test_checkpoint.py::test_snoop_adapter_matches_tshark_and_stage_drop`. Conditional local sample test is skipped when absent; synthetic expectations come from tshark. |
| F5 trailer: split legs and peer-flow pairing | done | `vendors.py`, `vendors.py`; `test_f5.py::test_f5_decode_pair_request_dwell_and_reset`, including peer reuse. tshark decodes trailers; trailer forwarding markers are bounded HTTP evidence. |
| Palo Alto receive/firewall/transmit/drop stages | done | `topology.py` stage mapping, `device_drops.py`; `test_paloalto.py::test_paloalto_drop_is_positive_without_path_coverage`. Positive drop-stage evidence names the node. |
| Fortinet verbose-6 text conversion/interface split | done | `fortinet.py`; `test_fortinet.py` exact-byte roundtrip, CRLF/noise/truncated lines, Ethernet/SLL/SLL2, absolute/anchored relative times. Relative clocks retain low confidence. |
| Cisco ASA/FTD pcap exports | done | Ordinary `ingest.py` pcap path and sequence-randomization handling; `test_translation.py`. No ASA-specific metadata adapter or real ASA corpus is claimed. |
| Bidirectional SPAN/TAP captures | done | Direction/CIDR and matching in `analysis.py`, `matching.py`; five-file and realistic/asymmetric fixtures. Microsecond same-point full-byte duplicates are separate from retransmissions. |

## 3. Cross-hop correlation

### 3.1 Fingerprint

| Item | Status | Evidence and limits |
|---|---|---|
| IP ID/IPv6 label, protocol, L4 length; repeated identities | done | `ingest.py`, `matching.py`; `test_occurrences.py::test_every_scenario_every_ip_id_mode` (slow), `test_balanced_occurrences_preserve_order_when_delay_changes`. Zero/constant IDs are not discarded. |
| Configurable payload prefix and truncated-snaplen matching | done | `ingest.py`, `matching.py` common captured prefix; `test_analysis.py::test_truncated_payload_prefixes_still_match`, `test_field_diff.py::test_field_diff_full_hash_not_prefix_and_truncation`. An unavailable full payload hash cannot prove modification. |
| TCP flags and canonical sequence/ACK | done | `translation.py`, `byte_ranges.py`; `test_translation.py`, `test_byte_ranges.py` wrap/offset/range cases. |
| ICMP identity/sequence, UDP hash and DNS transaction identity | done | `ingest.py`, `matching.py`, delivery checks in `analysis.py`; `test_realistic.py`, `test_analysis.py::test_udp_payload_disambiguates_reused_zero_ip_id`. This is not a DNS timing metric. |
| RTP sequence identity | missing | No RTP fields/sequence index. Generic UDP identity does not implement RTP loss or jitter. |
| Ignore forwarding changes (TTL/checksum/MAC/VLAN/DSCP); normalize NAT tuple | done | `matching.py`, `analysis.py` tuple lookup; `test_ingest.py` VLAN/QinQ, `test_integrity_attribution.py` DSCP/TTL-related evidence and `test_analysis.py::test_nat_must_be_confirmed_then_collapses_logical_flow`. |

### 3.2 Translation and framing

| Item | Status | Evidence and limits |
|---|---|---|
| NAT/PAT inferred tuples, confirmation/correction table | done | `analysis.py` NAT suggestion SQL, topology mappings and `main.tsx`; `test_analysis.py` NAT confirmation/configurable boundary tests, `test_quality.py::test_unlearned_nat_remains_unknown_even_with_known_clocks`. |
| Per-flow constant seq/ACK randomization offsets | done | `translation.py`; `test_translation.py` wrap and inconsistent-session cases; exact observed/canonical offset evidence. |
| Full proxy: separate TCP legs, HTTP/XFF/SNI/F5 request associations | done | `proxy_matching.py`, `proxy_analysis.py`, `vendors.py`; `test_proxy_pairing.py::test_request_pooling_and_xff_beat_nearest_time`, `test_proxy_integration.py`. One-to-one request graph; pooled connections stay separate. SNI means TLS setup only, not encrypted HTTP request correlation. |
| Proxy per-request request/response dwell | done | `proxy_waterfall.py`, `proxy_resets.py`; `test_proxy_integration.py::test_exact_request_dwell_and_waterfall`, missing/streaming/clock guards. Bounded visible HTTP/1.x; opaque HTTP/2/3/chunked/coalesced boundaries remain unknown. |
| TSO/GSO/GRO/LRO sequence byte ranges and visible offload note | done | `byte_ranges.py`, `analysis.py`, Overview offload notes; `test_byte_ranges.py::test_gso_gro_wrap_loss_and_capture_miss_are_not_multiplied` (64,000-byte frames). Counts are affected source frames/bytes, not invented wire segments; derived-range budget applies. |
| Fragment reassembly and first fragmentation hop | done | Point-isolated tshark reassembly in `capture_layers.py`; SQL span/membership validation and datagram normalization in `fragments.py`. `test_fragments.py`: IPv4/IPv6, zero/constant IDs, FW/LB/link origins, one lost middle fragment = one datagram, overlap unknown, capture miss guards, UDP/ICMP identity and executable frame filters. Incomplete ID reuse and ambiguous associations stay unknown. |

### 3.3 Clocks

| Item | Status | Evidence and limits |
|---|---|---|
| Bidirectional min-delay envelope, robust linear drift fit | done | `clock.py`; `test_analysis.py::test_healthy_five_file_e2e_and_reopen`, `test_clock_drift_over_hour_long_window`. Asymmetry remains uncertainty; one-way timing needs explicit evidence/override. |
| Offset/drift/confidence, calibration frames and overrides | done | `analysis.py`, Settings UI; `test_timeseries.py::test_unaligned_clock_coverage_is_unknown_not_not_capturing`, `test_proxy_clocks.py`. User corrections do not manufacture verified uncertainty. |
| Reject unreliable negative transit / cross-domain timing | done | `clock.py`, `analysis.py`, waterfall guards; `test_waterfall.py::test_handshake_http_and_uncertainty`, `test_proxy_clocks.py::test_independent_leg_clocks_never_imply_cross_proxy_timing`. |

## 4. Classification and location

| Item | Status | Evidence and limits |
|---|---|---|
| 4.1 Capture miss: later appearance or ACK without retry | done | `analysis.py`, byte-range delivery checks; `test_analysis.py::test_capture_miss_never_network_loss`, `test_byte_ranges.py`, `test_control.py`, realistic matrix. DNS/echo response can also prove delivery; no network loss is invented. |
| 4.1 Recovered loss, minor severity and measured recovery | done | `analysis.py`, `headlines.py`; `test_analysis.py::test_loss_has_correct_hop_time_and_recovery`, `test_headlines.py` quick recovery vs later unrelated reset (slow). Recovery classification does not identify every SACK mechanism. |
| 4.1 Impactful loss: stalls/retries/connection failure/reset | partial | `analysis.py`, `test_control.py::test_control_and_unrecovered_outcomes`, `test_analysis.py::test_short_repeated_loss_is_impactful`. Configurable 200 ms/repeat/reset/failed-handshake rules exist; no receive-window-collapse causal rule or complete computed TCP RTO model. |
| 4.1 Confirmed device drop and named stage/device | done | `device_drops.py`; Check Point/Palo Alto tests and `test_export.py`. Positive stage evidence required. Ordinary ingress/egress absence alone cannot prove policy/IPS/resource cause. |
| 4.1 Unknown for coverage/clock/translation insufficiency | done | `analysis.py` eligible ratios/reasons; `test_quality.py::test_low_eligible_ratio_never_claims_zero_loss`, proxy/clock negative cases. Supported unrecovered disappearance is a separate class; cause stays unknown. |
| 4.2 Correct device vs inter-device link; exact evidence | done | `integrity.py`, `analysis.py`, `evidence.py`; `test_integrity_attribution.py::test_exact_integrity_location` FW/LB/link with IPv6 and zero/constant IDs. Links have no fabricated device. |
| 4.2 Data-only segment headline, first event/onset, denominators and uncertainty | done | `headlines.py`, `onset.py`; `test_headlines.py` (slow), `test_onset.py::test_readme_and_existing_loss_onsets`. Local/UTC times; conditional upstream-loss statement. Do not equate every recovered event with fast retransmit or every stall with verified RTO. |
| 4.3 Per-segment/direction adjustable buckets, all listed metrics | done | `timeseries.py::METRICS`, stored `segment_buckets`; `test_timeseries.py`. Throughput includes observed wire bytes/retransmissions; RTT is upstream ACK RTT, not isolated link RTT. |
| 4.3 Healthy baseline, sustained rolling/MAD onset, evidence and propagation | done | `onset.py`; `test_onset.py` intermittent/random loss, delay/propagation, no capture-miss onset, insufficient baseline, event-count floors. Uncertain cross-clock propagation order stays unknown; prime suspect is temporal evidence, not device causation. |
| 4.3 Heatmap with onset markers | done | `Heatmap.tsx`, offline export heatmap; bucket/metric/coverage tests and `test_export.py`. Not-capturing and unavailable cells are not zero. |

## 5. Results UI

| Item | Status | Evidence and limits |
|---|---|---|
| Executive verdict/top-five ranked findings, hop/onset/confidence/evidence | done | `main.tsx` Overview, `headlines.py`, `ordered_onsets`; `test_headlines.py`, `test_onset.py::test_prime_suspect_precedes_sender_symptoms`. UI source reviewed. |
| Health topology, per-arrow loss/p95/retransmission/node drilldown | partial | `TopologyEditor.tsx` colors and loss/p95 labels; segment cards/evidence in `main.tsx`. No complete per-arrow retransmission label, node aggregate or click-to-open-stream overlay. |
| Heatmap brush filters every other view | partial | `Heatmap.tsx`, range query in `main.tsx`; `test_timeseries.py::test_loss_rates_and_brush_filters` covers flows/findings/events/ladder. Executive baseline, inventory, topology, waterfall/field diffs and exports retain full-window/context semantics. |
| Canonical/NAT flow table, bytes/duration/loss/retrans/stall/sorting/quick filters | partial | `analysis.py::flow_page`, `main.tsx` Flows; five-file/API/range tests. Per-hop tuples/handshake halves appear in drilldown. Reset origin and handshake RTT are not complete table columns/sort keys. Proxy legs deliberately stay separate rows. |
| Multi-hop ladder, missing X, retrans color and clickable evidence | done | `Charts.tsx::LadderChart`, `analysis.py::ladder`; `test_api.py`, `test_analysis.py`, `test_timeseries.py`. Paginated evidence, not millions of browser objects. |
| Handshake + HTTP/1.x waterfall, links/dwell/server processing/return | done | `waterfall.py`, `proxy_waterfall.py`, `Waterfall.tsx`; `test_waterfall.py`, `test_proxy_integration.py`. Clock-uncertain bars are unknown. Other application protocols/opaque boundaries are unavailable. |
| tcptrace-style per-hop sequence/time graphs | done | `stream_charts.py`, `TransportCharts.tsx`, `test_stream_charts.py`: per-point/direction data spans, cumulative ACK, negotiated window edge and retry markers. Bounded packet rendering, frame clicks and brush; absent scale suppresses window line. |
| Per-flow per-hop RTT/throughput graphs | done | `stream_charts.py`, `TransportCharts.tsx`: full-population ACK RTT/payload-rate buckets for each flow/point/data direction, brush/evidence links, partial/not-capturing rates null. RTT includes ACK delay; unaligned clocks have a local-only brush. |
| Packet field diff: tuple/TTL/DSCP/MSS/window/options/offset/hash | done | `field_diff.py`, `FieldDiff.tsx`; `test_field_diff.py`, integrity tests, `test_export.py`; full vs prefix hash distinction and unknowns preserved. |
| File/frame + content + per-file post-NAT display filters | done | `evidence.py`; `test_evidence.py`, export/API tests. Content filters survive renumbering but can select multiple identical occurrences; tokenized AI preview filters are intentionally not usable filters. |
| Standalone HTML and versioned JSON; optional PDF | done | `export.py`, CLI/UI exports; `test_export.py::test_offline_export_schema_escape_and_all_findings` rejects external asset references. Schema 4 includes integrity/proxy/TLS evidence. PDF is optional and absent; live per-flow waterfalls are not batch-exported. |

## 6. Metrics and checks

### Transport / performance (do not infer implementation from counters)

| Item | Status | Evidence and exact missing behavior |
|---|---|---|
| Handshake halves at each point | done | `analysis.py::ladder` local handshake metrics, `waterfall.py`; `test_waterfall.py`, `test_timeseries.py::test_handshake_retries_do_not_count_as_new_failed_connections`. Incomplete captures remain unknown. |
| Ongoing data/ACK RTT and TCP timestamp RTT | partial | tshark `tcp.analysis.ack_rtt` in `ingest.py`, segment RTT/local maximum in `timeseries.py`/ladder. Timestamp options are exported for diffs; no independent TSval/TSecr RTT estimator. |
| Fast/RTO/spurious/SACK-driven retransmission breakdown | partial | `ingest.py` stores retrans/fast/spurious flags; loss recovery and stall rules exist. Per-flow/point/segment exclusive fast, spurious, SACK-backed and RTO-compatible counters plus duplicate ACKs now exist in `retransmissions.py`, `Diagnosis.tsx`; wire tests assert all subtypes. Actual kernel timers and unsupported recovery algorithms are not observable; short/ambiguous timers stay unknown. |
| Duplicate ACKs, reordering and first reordering hop | partial | tshark out-of-order flag is stored. `retransmissions.py` counts ACKs by acknowledged data direction and compares matched original sequence-neighbour arrival order; `test_diagnostics_wire.py` asserts FW/LB/link, excluding retry-only hints and capture misses. State/coverage/translation ambiguity remains unknown. |
| Zero windows, full windows, shrinking receive windows | done | `ingest.py`, `transport.py`, `stream_charts.py`, `test_diagnostics_wire.py`: captured handshake scale, unscaled SYN window, window shrink/full/zero traces and demand/flight comparison. Missing negotiation is unknown; idle zero windows are not receiver limitation. |
| Receiver/app slow vs network slow | done | `transport.py`, `Diagnosis.tsx`, `test_diagnosis.py`, `test_diagnostics_wire.py`: per-leg/data-direction corroboration of negotiated window, flight/demand, receiver ACK delay, matched path/loss and bounded visible service time. One counter, absent handshake/endpoints, insufficient clock/coverage or competing causes stay unknown. Pacing does not prove a physical bandwidth cap. |
| Server/app response vs network time | partial | HTTP/1.x last-request-byte → first-response-byte processing and separate links/return/proxy dwell in `waterfall.py`; `test_waterfall.py`, `test_proxy_integration.py::test_exact_request_dwell_and_waterfall`. No generic L7, opaque TLS request timing or fleet/application aggregates. |
| RTP jitter and sequence loss | missing | No RTP tshark export, sequence-gap accounting, interarrival jitter metric or tests. Generic UDP disappearance is not RTP quality. |
| DNS query/response timing | done | `dns.py`, `DNS.tsx`, `test_dns.py`, `test_diagnostics_wire.py`: scoped question/tuple/protocol/ID ownership, per-resolver/point p50/p95/max, configurable deadlines, timeout vs query/response disappearance, and HTML/JSON evidence. One complete unicast question/message per indexed frame; ambiguous retries or incomplete deadline/endpoint coverage are unknown. |
| Generic UDP request/response pairing/jitter | missing | UDP payload/tuple matching and covered disappearance exist; no application transaction pairing or jitter measurement. |
| Throughput and pps per hop/direction | done | `timeseries.py`; `test_timeseries.py::test_coverage_and_exact_bucket_rates`. Wire-byte observations include retransmissions; no unseen traffic estimates. |
| Bursts/microbursts | done | `microbursts.py`, `Microbursts.tsx`, Settings and exports; `test_microbursts.py` checks 1–10 ms rolling windows, independent tshark peak-rate calculation, SPAN-copy rejection, bursts without loss and correct next-segment onset associations. Rates describe captured bytes, not physical line capacity. Timing uncertainty, offload and timestamp batching limit interpretation; no causal loss claim. |

### Path integrity / middleboxes

| Item | Status | Evidence and limits |
|---|---|---|
| MTU/PMTUD size-selective disappearance, ICMP/DF/MSS evidence | partial | `integrity.py::Checks.mtu`, field diffs; `test_integrity_attribution.py` MTU/MSS exact FW/LB/link and capture-miss guard. Large-missing/small-passing TCP pattern and quoted ICMP feedback exist; size-selective policy/capture loss can mimic MTU. No proof of blocked ICMP, exact path-MTU search or general UDP/fragment PMTUD model. |
| TTL/hop-limit path anomalies / unexpected hops / loops | partial | `integrity.py` TTL anomaly finding; `test_integrity.py`. Flags unexpected increases/decrements; cannot distinguish extra routers, tunnels, rewrites and loops or locate an unobserved loop. |
| DSCP remarking, SACK/window-scale/timestamp option stripping, MSS clamp | done | `integrity.py`, `field_diff.py`; `test_integrity_attribution.py` exact device/link matrix and `test_integrity.py`. Supported matched complete headers; SYN-only options are not compared to unrelated later packets. |
| Asymmetric routing | done | Explicit return topology plus `integrity.py`; `test_realistic.py`, `test_integrity_attribution.py` asymmetric-return variants. Unsupported capture coverage cannot prove absence. |
| SPAN double-capture vs real duplication | done | Microsecond full-frame duplicate rule in `analysis.py`/integrity; `test_quality.py::test_span_exclusions_are_reported_separately`, `test_integrity.py::test_long_repeat_stream_uses_adjacent_evidence`. Ambiguous repeats remain unknown. |

### Security-relevant

| Item | Status | Evidence and limits |
|---|---|---|
| RST / ICMP origin using first appearance, endpoint TTL/IP-ID and vendors | done | `integrity.py`, `proxy_resets.py`, `device_drops.py`; `test_integrity_attribution.py::test_false_positive_guards`, F5/Check Point and proxy reset tests. Missing endpoint capture/compatible endpoint TTL cannot become injection. TTL/IP ID are corroboration, not authentication or proof of IPS/policy intent. |
| Downstream-only injection / undeclared payload modification | done | `integrity.py`, `field_diff.py`; multi-device `test_integrity_attribution.py`, `test_integrity.py::test_declared_alg_and_unknown_clock_do_not_claim_modification`. Coverage, mapping and complete payload evidence gate claims; middlebox vs link attribution stays explicit. |
| TLS certificate/server-hello differences | partial | `tls_analysis.py`, `application_index.py`; `test_tls_interception.py` exact proxy/link, declared inspection, ambiguity, client-auth and TLS 1.3 guards. Visible server-chain subject/issuer/fingerprint comparison exists. No complete cipher/extension/ServerHello change detector or certificate trust validation; encrypted/absent chains remain unknown. |
| SYN stops at hop / failed handshakes / half-open accounting | partial | `analysis.py`, blocked-handshake class and distinct-session buckets; `test_control.py`, `test_timeseries.py`. Hop failure supported; no full session-state lifecycle/half-open occupancy model. |
| SYN-flood-like patterns | missing | New-connection/failed-handshake onsets are available, but no SYN/established ratio or flood heuristic, detector or fixtures. A rate spike alone is not an attack. |
| Scan-like fan-out | missing | No per-client destination/port fan-out heuristic or supported scan finding. |
| Session-table-pressure hints | missing | No correlation rule joining connection-rate spikes to confirmed stateful-device drops. Existing charts are inputs, not evidence of session-table capacity/resource cause. |

### Capture quality

| Item | Status | Evidence and limits |
|---|---|---|
| Capture drops / snaplen / coverage / clock confidence first | done | `metadata.py`, `analysis.py` quality/eligible ratios, UI quality panel; `test_quality.py`, `test_ingest_tails.py`, `test_ingest.py` ISB. Missing counters remain unknown; invalid timestamps never enter fitting/coverage. |
| Offload artifacts and checksum handling | done | `byte_ranges.py`, offload notes; `test_byte_ranges.py`. Bad/offloaded checksums are not classified as network faults. No separate validated genuine-wire checksum-error detector is claimed. |

## 7. AI hook (context)

| Item | Status | Evidence and limits |
|---|---|---|
| Clean findings schema with type/hop/time/metrics/refs/confidence | done | `export.py::FindingsExport`, `docs/findings-v4.schema.json`, `test_export.py`. |
| Disabled setting/panel, tokenized findings-only preview, no outbound calls | done | `assistant.py`, `app.py`, `Assistant.tsx`; `test_assistant.py`. Consistent ephemeral tokens, no packet data/provider/key/send action. Other free text/local paths/organization names are not guaranteed anonymized. |

## 8. Testing

| Item | Status | Evidence and limits |
|---|---|---|
| Ground-truth multi-hop generator: clock offset/drift/NAT/loss/delay/capture gaps | done | `synthetic.py`, `test_analysis.py`, `test_onset.py`, `test_realistic.py`; configurable ordinary N-hop path, clocks and fault hop/time; intermittent/random loss and concurrent port reuse. |
| Seq randomization, full proxies/pooling, MSS/MTU/injected RST/offload fixtures | done | `translation_synthetic.py`, `integrity_synthetic.py`, `tests/proxy_fixtures.py`; `test_translation.py`, `test_proxy_integration.py`, `test_integrity_attribution.py`, `test_byte_ranges.py`. Generated in temporary folders; tshark defines vendor/TLS expected decode. |
| Negative guards and exact device/link attribution with distractors | done | `test_integrity_attribution.py` FW/LB/link, `test_proxy_pairing.py` nearest-time mutant, `test_tls_interception.py` always-first-proxy mutant; endpoint/capture/clock/ambiguity controls. No real/third-party captures tracked. |
| Matching/clocks/classification/onset ground-truth unit + integration tests | done | Named tests above plus `test_occurrences.py`; IPv4 zero/constant/random/increment and IPv6 matrices. |
| Correct hop and onset within one bucket for **every** original generator scenario | partial | `test_onset.py` asserts hop/time for loss/delay/propagation, intermittent/random loss and ID/IPv6 variants. Integrity, vendor, proxy and MTU scenarios assert attribution, but not all define/verify a change-point onset. No onset acceptance for missing RTP/burst/flood features. |
| Pure capture miss never network loss | done | `test_analysis.py::test_capture_miss_never_network_loss`, slow occurrences/realistic matrices, byte-range/control/proxy/integrity MTU negative cases. Correct unsupported cases may be unknown. |
| Five-file topology/ingest/JSON end-to-end | done | `test_analysis.py::test_healthy_five_file_e2e_and_reopen`, `test_api.py::test_api_ingest_analysis_report`; native `tools/smoke_binary.py` independently runs five-file zero-ID loss. |
| Windows/macOS CI with tshark; fast default <2 min | done | `.github/workflows/ci.yml`: six PR/manual OS×Python checks, slow only macos-14/3.12, three packaging smoke jobs. Final measured fast duration and exact CI run are in `VALIDATION.md`; threshold is a local acceptance requirement, not enforced as a cross-runner timeout. |

## Decision inputs for the next part

The largest unimplemented transport/security areas are RTP quality, generic UDP transaction
semantics, SYN-flood/fan-out heuristics and session-pressure correlation. Remaining partial rows
include application/protocol breadth, encrypted visibility and topology/path ambiguity. Tunnel,
fragment and microburst support is bounded as described above; it does not turn capture timing
into proof of queue overflow or identify unseen devices. The owner chooses the next part.
