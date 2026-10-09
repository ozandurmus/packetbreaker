import { Heatmap } from "./Heatmap";
import type { TimeSeries, Finding } from "./types";
import React, { useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, num, time, reverseTuple } from "./api";
import { FieldDiff, type FieldDiffData } from "./FieldDiff";
import { Waterfall } from "./Waterfall";
import { Coverage, LadderChart } from "./Charts";
import { TopologyEditor } from "./TopologyEditor";
import type { State, Topology, Ref, Flow, Ladder, Segment, Job } from "./types";
import "./style.css";

function Tip({ children, text }: { children: React.ReactNode; text: string }) {
  return (
    <span title={text} tabIndex={0} className="tip">
      {children}
      <sup>ⓘ</sup>
    </span>
  );
}
function Badge({
  children,
  kind = "neutral",
}: {
  children: React.ReactNode;
  kind?: string;
}) {
  return <span className={"badge " + kind}>{children}</span>;
}
function Evidence({ refs, onClose }: { refs: Ref[]; onClose: () => void }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section
        className="evidence-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Frame evidence"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="section-head">
          <div>
            <span className="eyebrow">Verify in Wireshark</span>
            <h2>Frame evidence</h2>
          </div>
          <button className="secondary" onClick={onClose}>
            Close
          </button>
        </div>
        <p className="hint">
          Open the named file in Wireshark and paste its display filter. Times
          are UTC.
        </p>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Capture point / file</th>
                <th>Frame</th>
                <th>Observed</th>
                <th>Corrected</th>
                <th>Display filter</th>
              </tr>
            </thead>
            <tbody>
              {refs.map((e, i) => (
                <tr key={i}>
                  <td>
                    <strong>{e.point}</strong>
                    <small>{e.file}</small>
                  </td>
                  <td>
                    {e.frame}
                    {e.vendor && (
                      <details>
                        <summary>Vendor evidence</summary>
                        <pre>{JSON.stringify(e.vendor, null, 2)}</pre>
                      </details>
                    )}
                    {e.sequence_translation && (
                      <small>
                        {e.sequence_translation.reason
                          ? `Unknown translation: ${e.sequence_translation.reason}`
                          : `SEQ ${e.sequence_translation.observed_seq} → ${e.sequence_translation.canonical_seq}; ACK ${e.sequence_translation.observed_ack} → ${e.sequence_translation.canonical_ack}; offsets ${e.sequence_translation.seq_offset} / ${e.sequence_translation.ack_offset} (mod 2³²)`}
                      </small>
                    )}
                  </td>
                  <td>
                    {time(e.observed_time)}
                    {e.byte_ranges?.length ? (
                      <small>
                        {e.byte_ranges
                          .slice(0, 4)
                          .map(
                            (r) => `${r.start_seq}–${r.end_seq} (${r.bytes} B)`,
                          )
                          .join(", ")}
                        {e.byte_ranges.length > 4 ? " …" : ""}
                      </small>
                    ) : null}
                    {e.range_note && <small>{e.range_note}</small>}
                  </td>
                  <td>{time(e.corrected_time)}</td>
                  <td>
                    <code>{e.display_filter}</code>
                    <button
                      className="icon"
                      title="Copy Wireshark filter"
                      onClick={() =>
                        navigator.clipboard.writeText(e.display_filter)
                      }
                    >
                      Copy
                    </button>
                    {e.content_filter && (
                      <details>
                        <summary>Packet content filter</summary>
                        <code>{e.content_filter}</code>
                        <button
                          className="icon"
                          title="Copy content filter"
                          onClick={() =>
                            navigator.clipboard.writeText(e.content_filter!)
                          }
                        >
                          Copy
                        </button>
                        <p className="hint">{e.filter_note}</p>
                      </details>
                    )}
                    {e.flow_filter && (
                      <details>
                        <summary>Flow filter for this file</summary>
                        <code>{e.flow_filter}</code>
                        <button
                          className="icon"
                          title="Copy flow filter"
                          onClick={() =>
                            navigator.clipboard.writeText(e.flow_filter!)
                          }
                        >
                          Copy
                        </button>
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!refs.length && (
          <div className="empty">No frame evidence available.</div>
        )}
      </section>
    </div>
  );
}
function App() {
  const [series, setSeries] = useState<TimeSeries | null>(null);
  const [range, setRange] = useState<[number, number] | null>(null);
  const [rangeFindings, setRangeFindings] = useState<Finding[] | null>(null);
  const rangeQuery = range ? `&start=${range[0]}&end=${range[1]}` : "";
  const selectRange = useCallback((r: [number, number] | null) => {
    setRange(r);
    setFlowOffset(0);
    setLadderOffset(0);
    setEvents(null);
  }, []);

  const [state, setState] = useState<State | null>(null),
    [tab, setTab] = useState("Overview"),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [job, setJob] = useState<Job>({ state: "idle", busy: false }),
    [topology, setTopology] = useState<Topology | null>(null),
    [evidence, setEvidence] = useState<Ref[] | null>(null),
    [path, setPath] = useState(""),
    [projectPath, setProjectPath] = useState(""),
    [uploadPercent, setUploadPercent] = useState<number | null>(null);
  const [flows, setFlows] = useState<{ total: number; items: Flow[] }>({
      total: 0,
      items: [],
    }),
    [flowOffset, setFlowOffset] = useState(0),
    [search, setSearch] = useState(""),
    [filter, setFilter] = useState(""),
    [sort, setSort] = useState("bytes"),
    [selectedFlow, setSelectedFlow] = useState<Flow | null>(null),
    [ladder, setLadder] = useState<Ladder | null>(null),
    [ladderOffset, setLadderOffset] = useState(0);
  const [fieldDiff, setFieldDiff] = useState<FieldDiffData | null>(null);
  const [events, setEvents] = useState<{
    label: string;
    items: {
      id: string;
      kind: string;
      reason: string;
      ts: number;
      recovery_ms: number | null;
      evidence: Ref[];
    }[];
    total: number;
    segment: Segment;
    offset: number;
  } | null>(null);
  const [parallelIngest, setParallelIngest] = useState(false);
  const [checkpointUuid, setCheckpointUuid] = useState(false);
  const [f5Trailer, setF5Trailer] = useState(false);
  const [fortiPath, setFortiPath] = useState("");
  const [fortiStart, setFortiStart] = useState("");
  const [fortiDevice, setFortiDevice] = useState("FortiGate");
  const [tsharkPath, setTsharkPath] = useState(""),
    [prefix, setPrefix] = useState(64);
  useEffect(() => {
    setRange(null);
    setSeries(null);
    if (!state?.report) return;
    let active = true;
    api<TimeSeries>("/timeseries")
      .then((s) => {
        if (active && s.bucket_count) setSeries(s);
      })
      .catch(fail);
    return () => {
      active = false;
    };
  }, [state?.report]);
  useEffect(() => {
    setRangeFindings(null);
    if (!range || !state?.report) return;
    let active = true;
    api<{ items: Finding[] }>(`/findings?start=${range[0]}&end=${range[1]}`)
      .then((r) => {
        if (active) setRangeFindings(r.items);
      })
      .catch(fail);
    return () => {
      active = false;
    };
  }, [range, state?.report]);
  async function refresh() {
    const s = await api<State>("/state");
    setState(s);
    setTopology(s.topology);
    setJob(s.job);
    setProjectPath(s.project);
    setTsharkPath(s.settings.tshark || "");
    setPrefix(s.settings.prefix_bytes || 64);
    setParallelIngest(s.settings.parallel ?? false);
    setCheckpointUuid(s.settings.checkpoint_uuid ?? false);
    setF5Trailer(s.settings.f5_trailer ?? false);
  }
  const fail = (e: unknown) =>
    setError(e instanceof Error ? e.message : String(e));
  useEffect(() => {
    refresh().catch(fail);
  }, []);
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [tab]);
  useEffect(() => {
    if (!job.busy) return;
    const id = setInterval(() => {
      api<Job>("/jobs")
        .then((j) => {
          setJob(j);
          if (!j.busy) {
            if (j.error) setError(j.error);
            refresh().catch(fail);
          }
        })
        .catch(fail);
    }, 700);
    return () => clearInterval(id);
  }, [job.busy]);
  useEffect(() => {
    if (!state?.report) {
      setFlows({ total: 0, items: [] });
      setSelectedFlow(null);
      setLadder(null);
      setEvents(null);
      return;
    }
    if (job.busy) return;
    let active = true;
    const timer = setTimeout(
      () =>
        api<{ total: number; items: Flow[] }>(
          `/flows?offset=${flowOffset}&search=${encodeURIComponent(search)}&filter_by=${filter}&sort=${sort}${rangeQuery}`,
        )
          .then((r) => {
            if (active) setFlows(r);
          })
          .catch(fail),
      150,
    );
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [state?.report, flowOffset, search, filter, sort, job.busy, rangeQuery]);
  useEffect(() => {
    if (!selectedFlow) return;
    let active = true;
    api<Ladder>(
      `/flows/${selectedFlow.flow}/ladder?offset=${ladderOffset}${rangeQuery}`,
    )
      .then((r) => {
        if (active) setLadder(r);
      })
      .catch(fail);
    return () => {
      active = false;
    };
  }, [selectedFlow, ladderOffset, rangeQuery]);
  useEffect(() => setFieldDiff(null), [selectedFlow, rangeQuery]);
  async function action(fn: () => Promise<unknown>) {
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (e) {
      fail(e);
    }
  }
  async function downloadReport(format: "html" | "json") {
    const response = await fetch(`/api/export?format=${format}`);
    if (!response.ok)
      throw new Error((await response.json()).detail || "Export failed");
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = `packetbreaker-report.${format}`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice(
      "Exported the complete saved analysis window (independent of the heatmap brush).",
    );
  }
  async function saveTopology(t: Topology) {
    const saved = await api<Topology>("/topology", "PUT", t);
    setTopology(saved);
    setState((s) => (s ? { ...s, topology: saved, report: null } : s));
    setNotice("Topology saved. Run analysis to refresh results.");
  }
  async function analyze() {
    if (!topology) return;
    setSelectedFlow(null);
    setLadder(null);
    setEvents(null);
    setJob(
      await api<Job>("/analyze", "POST", {
        ...topology,
        report_timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      }),
    );
  }
  async function upload(files: FileList | null) {
    if (!files?.length) return;
    setUploadPercent(0);
    const paths: string[] = [];
    try {
      for (const f of Array.from(files)) {
        await new Promise<void>((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.open(
            "POST",
            "/api/captures/upload?defer=true&name=" +
              encodeURIComponent(f.name),
          );
          xhr.setRequestHeader("X-PacketBreaker", "local");
          xhr.upload.onprogress = (e) =>
            setUploadPercent(
              e.lengthComputable ? Math.round((e.loaded / e.total) * 100) : 0,
            );
          xhr.onload = () => {
            if (xhr.status < 300) {
              paths.push(JSON.parse(xhr.responseText).path);
              resolve();
            } else reject(new Error(xhr.responseText));
          };
          xhr.onerror = () => {
            setUploadPercent(null);
            reject(new Error("Upload failed"));
          };
          xhr.send(f);
        });
      }
      setJob(await api<Job>("/captures/attach", "POST", { paths }));
    } finally {
      setUploadPercent(null);
    }
  }
  async function showEvents(s: Segment, offset = 0) {
    const page = await api<{
      items: NonNullable<typeof events>["items"];
      total: number;
    }>(
      `/events?a=${s.point_a}&b=${s.point_b}&direction=${s.direction}&offset=${offset}${rangeQuery}`,
    );
    setEvents({ label: s.label, ...page, segment: s, offset });
  }
  if (!state || !topology)
    return (
      <div className="loading">
        <div className="brand-mark">P↯</div>
        <h1>PacketBreaker</h1>
        <p>{error || "Opening local workspace…"}</p>
      </div>
    );
  const report = state.report;
  const visibleFindings = range ? rangeFindings || [] : report?.findings || [];
  const ready = state.captures.filter((c) => c.state === "ready").length;
  const kinds =
    report?.findings.reduce(
      (acc, f) => {
        acc[f.type] = (acc[f.type] || 0) + f.metrics.count;
        return acc;
      },
      {} as Record<string, number>,
    ) || {};
  const busy = job.busy || uploadPercent !== null;
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">P↯</div>
          <div>
            PacketBreaker<small>FOLLOW THE PACKET</small>
          </div>
        </div>
        <div className="workspace-label">LOCAL WORKSPACE</div>
        <nav>
          {["Overview", "Captures", "Path", "Flows", "Settings"].map((x, i) => (
            <button
              key={x}
              className={tab === x ? "active" : ""}
              onClick={() => setTab(x)}
            >
              <span>{["◈", "▤", "⌘", "≋", "⚙"][i]}</span>
              {x}
              {x === "Captures" && <b>{state.captures.length}</b>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="local-dot" /> Local processing only
          <p>
            No cloud. No telemetry.
            <br />
            Your captures stay on this computer.
          </p>
          <small>PHASE 3 / PART 1 · v0.1.9</small>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <div className="breadcrumbs">
              Workspace <span>/</span> {state.project.split(/[\\/]/).pop()}
            </div>
            <h1>
              {tab === "Overview"
                ? "Path investigation"
                : tab === "Captures"
                  ? "Capture inventory"
                  : tab === "Path"
                    ? "Map the traffic path"
                    : tab === "Flows"
                      ? "Follow a conversation"
                      : "Workspace settings"}
            </h1>
            <p>
              {tab === "Overview"
                ? "Find where the evidence changes, one capture point at a time."
                : tab === "Captures"
                  ? "Understand capture quality before interpreting the network."
                  : tab === "Path"
                    ? "Your diagram is the authority. Connect capture points in traffic order."
                    : tab === "Flows"
                      ? "Trace packets across every point and verify the original frames."
                      : "Local tools, analysis thresholds and clock overrides."}
            </p>
          </div>
          <div className="header-actions">
            <Badge kind="neutral">● OFFLINE</Badge>
            <button
              className="secondary"
              disabled={busy || !report}
              onClick={() => action(() => downloadReport("html"))}
            >
              Export HTML
            </button>
            <button
              className="secondary"
              disabled={busy || !report}
              onClick={() => action(() => downloadReport("json"))}
            >
              Export JSON
            </button>
            <button
              disabled={
                busy ||
                ready < 1 ||
                (topology.forward.length < 2 &&
                  !topology.points.some(
                    (p) => p.vendor === "paloalto" && p.vendor_stage === "drop",
                  ))
              }
              onClick={() => action(analyze)}
            >
              ▶ Analyze path
            </button>
          </div>
        </header>
        {error && (
          <div className="alert" role="alert">
            {error}
            <button onClick={() => setError("")}>Dismiss</button>
          </div>
        )}
        {notice && <div className="notice">{notice}</div>}
        {state.tshark.error && (
          <div className="alert">{state.tshark.error}</div>
        )}
        {busy && (
          <div className="job-bar" role="status">
            <div className="spinner" />
            <strong>
              {uploadPercent !== null
                ? `Uploading · ${uploadPercent}%`
                : job.state}
            </strong>
            <span>
              {job.file}{" "}
              {job.frames != null ? `· ${num(job.frames, " frames", 0)}` : ""}{" "}
              {job.file_count
                ? `· ${job.file_count} files · ${job.workers ?? 1} workers`
                : ""}
            </span>
            {job.kind === "ingest" && job.busy && (
              <button
                className="secondary"
                onClick={() => action(() => api("/jobs/cancel", "POST"))}
              >
                Cancel ingest
              </button>
            )}
          </div>
        )}
        {job.kind === "ingest" && !!job.files?.length && (
          <section style={{ margin: "18px 38px" }}>
            <h2>File ingest progress</h2>
            {job.files.map((f) => (
              <div className="mapping" key={f.file_id}>
                <div>
                  <strong>{f.file}</strong>
                  <small>
                    {" "}
                    · {f.state} · {num(f.usable_packets ?? f.frames, "", 0)}{" "}
                    {f.usable_packets == null
                      ? "frames read"
                      : "usable packets"}
                  </small>
                  {f.error && <p className="red">{f.error}</p>}
                  {f.warnings?.map((w) => (
                    <p className="hint" key={w}>
                      {w}
                    </p>
                  ))}
                </div>
                {job.busy &&
                  !["ready", "cached", "cancelled", "error"].includes(
                    f.state,
                  ) && (
                    <button
                      className="secondary"
                      onClick={() =>
                        action(() =>
                          api("/jobs/cancel", "POST", { file_id: f.file_id }),
                        )
                      }
                    >
                      Cancel file
                    </button>
                  )}
                {!job.busy && ["cancelled", "error"].includes(f.state) && (
                  <button
                    onClick={() =>
                      action(async () =>
                        setJob(
                          await api<Job>("/captures/attach", "POST", {
                            paths: [f.path],
                          }),
                        ),
                      )
                    }
                  >
                    Resume file
                  </button>
                )}
              </div>
            ))}
          </section>
        )}
        <div className="content">
          {range && (
            <section>
              <strong>
                Selected interval: {new Date(range[0] * 1000).toISOString()} –{" "}
                {new Date(range[1] * 1000).toISOString()}
              </strong>
              <p className="hint">
                Flows, findings and ladder are filtered to this half-open
                interval. Flow totals describe the complete analysis; onset
                estimates use the full baseline.
              </p>
              <button onClick={() => selectRange(null)}>Clear selection</button>
            </section>
          )}
          {tab === "Overview" && (
            <>
              {!!report?.sequence_translations?.length && (
                <section>
                  <h2>Sequence translations</h2>
                  {report.sequence_translations.map((m, i) => (
                    <button
                      key={i}
                      className="finding"

                      onClick={() => setEvidence(m.evidence)}
                    >
                      {m.ingress} → {m.egress} · flow{" "}
                      {m.flow?.slice(0, 8) || "unknown"}:{" "}
                      {m.status === "learned"
                        ? `forward SEQ offset ${m.boundary_forward_offset}, ACK offset ${m.boundary_reverse_offset} (mod 2³²); ${m.samples} anchors`
                        : `unknown — ${m.reason}`}
                    </button>
                  ))}
                </section>
              )}
              {!!report?.vendor_device_events?.some(
                (e) => e.status === "unknown",
              ) && (
                <section>
                  <h2>Inspection evidence limitations</h2>
                  {report.vendor_device_events
                    .filter((e) => e.status === "unknown")
                    .slice(0, 10)
                    .map((e, i) => (
                      <button
                        className="finding onset-symptom"
                        key={i}
                        onClick={() => setEvidence(e.evidence)}
                      >
                        {e.device} · {e.stage}: {e.reason}
                      </button>
                    ))}
                </section>
              )}
              {!!report?.f5?.pairs.length && (
                <section>
                  <h2>F5 connection pairs and request forwarding</h2>
                  <p className="hint">{report.f5.note}</p>
                  <p className="hint">
                    Capture context. Client/server TCP legs remain separate;
                    forwarding intervals use tshark-decoded request-bearing
                    frames.
                  </p>
                  {report.f5.pairs.map((p, i) => (
                    <p key={i}>
                      {p.role} · flowid {p.flowid} ↔ peerid {p.peerid} ·
                      processor {p.tmm}
                      {p.reason && ` · unknown: ${p.reason}`}
                      {p.client_flow && (
                        <small>
                          Client conversation {p.client_flow} / server
                          conversation {p.server_flow}
                        </small>
                      )}
                    </p>
                  ))}
                  {report.f5.requests.map((r, i) => (
                    <button
                      className="finding"

                      key={i}
                      onClick={() => setEvidence(r.evidence)}
                    >
                      {r.device} · {r.request}: {num(r.request_dwell_ms, " ms")}{" "}
                      ±{num(r.clock_uncertainty_ms, " ms")}
                      <small>{r.reason || r.note}</small>
                    </button>
                  ))}
                  {report.f5.resets.map((r, i) => (
                    <button
                      className="finding"

                      key={i}
                      onClick={() => setEvidence(r.evidence)}
                    >
                      {r.device} · {time(r.time)} · RST origin (TMM reported):{" "}
                      {r.reason}
                    </button>
                  ))}
                </section>
              )}
              {!!report?.offload_points?.length && (
                <section>
                  <h2>Offload / segmentation notes</h2>
                  {report.offload_points
                    .filter((p) => p.large_frames > 0)
                    .map((p) => (
                      <p key={p.point}>
                        <strong>
                          {topology.points.find((x) => x.id === p.point)
                            ?.label || p.point}
                          : {p.large_frames} large TCP frames.
                        </strong>{" "}
                        {p.note}
                      </p>
                    ))}
                  <p className="hint">
                    Matching uses TCP sequence coverage, not equality of capture
                    packet counts. Loss counts describe affected upstream
                    frames; missing-byte totals retain partial-frame detail.
                  </p>
                </section>
              )}
              {report?.onsets && (
                <section>
                  <h2>Degradation onset</h2>
                  <p>{report.onsets.summary}</p>
                  {Object.entries(report.onsets.directions).map(
                    ([direction, d]) =>
                      d.propagation_order.length > 0 && (
                        <p key={direction} className="hint" title={d.caveat}>
                          Propagation · {direction}:{" "}
                          {d.propagation_order
                            .map(
                              (g) =>
                                `${g.segments.map((id) => report.segments.find((s) => s.id === id)?.label || id).join(" / ")}${g.segments.length > 1 ? " (order unresolved)" : ""} at ${time(g.time)}`,
                            )
                            .join(" → ")}
                        </p>
                      ),
                  )}
                  <details>
                    <summary>Onset status and quality notes by segment</summary>
                    {report.segments.map((s) => (
                      <div key={s.id}>
                        <p>
                          <strong>
                            {s.label} · {s.direction}: {s.onset_status}
                          </strong>
                        </p>
                        <p className="hint">
                          Quality notes:{" "}
                          {s.onset_quality_notes?.capture_misses || 0} capture
                          misses; {s.onset_quality_notes?.unknown_events || 0}{" "}
                          unknown events. These are not counted as network loss.
                        </p>
                        {s.onset_reasons?.map((r) => (
                          <p className="hint" key={r.metric}>
                            {r.metric}: {r.reason}
                          </p>
                        ))}
                        {s.onset_quality_notes?.reasons.map((reason) => (
                          <p className="hint" key={reason}>
                            {reason}
                          </p>
                        ))}
                      </div>
                    ))}
                  </details>
                  {report.onsets.items.map((o, i) => (
                    <button
                      key={i}
                      className={`finding ${o.scope === "capture_signal" ? "onset-symptom" : ""}`}
                      onClick={() => setEvidence(o.evidence)}
                    >
                      {o.segment} · {o.explanation}
                    </button>
                  ))}
                </section>
              )}
              {report && series && (
                <Heatmap
                  data={series}
                  report={report}
                  onSelect={selectRange}
                  selectedRange={range}
                />
              )}
              <div className="stats">
                <div>
                  <Tip text="Completed captures available for correlation. Incomplete files are excluded.">
                    Ready captures
                  </Tip>
                  <strong>
                    {ready}
                    <small> / {state.captures.length}</small>
                  </strong>
                </div>
                <div>
                  <Tip text="TCP sessions joined across capture points and confirmed NAT mappings. UDP and ICMP use endpoint conversations.">
                    Conversations
                  </Tip>
                  <strong>
                    {report ? num(report.flow_count, "", 0) : "—"}
                  </strong>
                </div>
                <div>
                  <Tip text="Missing original TCP segments with delivered retransmission and recovery at or above the configured stall threshold.">
                    Impactful loss
                  </Tip>
                  <strong className={kinds.impactful_loss ? "red" : ""}>
                    {report ? num(kinds.impactful_loss || 0, "", 0) : "—"}
                  </strong>
                </div>
                <div>
                  <Tip text="Positive vendor-stage evidence, not an inferred device cause. Each finding names its device and inspection/drop stage.">
                    Confirmed device drops
                  </Tip>
                  <strong
                    className={report?.confirmed_device_drop_count ? "red" : ""}
                  >
                    {report
                      ? num(report.confirmed_device_drop_count || 0, "", 0)
                      : "—"}
                  </strong>
                </div>
                <div>
                  <Tip text="Intermediate capture absence contradicted by later packet or ACK evidence. These are not network loss.">
                    Capture misses
                  </Tip>
                  <strong>
                    {report ? num(kinds.capture_miss || 0, "", 0) : "—"}
                  </strong>
                </div>
              </div>
              {!report ? (
                <section className="empty-start">
                  <div className="path-illustration">
                    ◉ <span>·····</span> ◇ <span>·····</span> ◇{" "}
                    <span>·····</span> ◉
                  </div>
                  <span className="eyebrow">FROM CAPTURES TO EVIDENCE</span>
                  <h2>One path. Multiple perspectives.</h2>
                  <p>
                    Attach the captures, connect their capture points, then
                    analyze the same traffic across the path.
                  </p>
                  <div className="steps">
                    <button onClick={() => setTab("Captures")}>
                      <b>01</b> Attach captures →
                    </button>
                    <button onClick={() => setTab("Path")}>
                      <b>02</b> Map the path →
                    </button>
                    <button
                      disabled={
                        busy ||
                        (topology.forward.length < 2 &&
                          !topology.points.some(
                            (p) =>
                              p.vendor === "paloalto" &&
                              p.vendor_stage === "drop",
                          ))
                      }
                      onClick={() => action(analyze)}
                    >
                      <b>03</b> Analyze →
                    </button>
                  </div>
                </section>
              ) : (
                <>
                  <section className="verdict">
                    <div>
                      <span className="eyebrow">EVIDENCE SUMMARY</span>
                      <h2>{report.verdict}</h2>
                      <p>
                        {time(report.window.start)} — {time(report.window.end)}
                      </p>
                    </div>
                    <Badge kind={kinds.impactful_loss ? "high" : "neutral"}>
                      {kinds.impactful_loss ? "INVESTIGATE" : "REVIEW COVERAGE"}
                    </Badge>
                  </section>
                  <section>
                    <div className="section-head">
                      <h2>Capture quality comes first</h2>
                      <button
                        className="text-button"
                        onClick={() => setTab("Captures")}
                      >
                        Inspect all captures →
                      </button>
                    </div>
                    <div className="quality-grid">
                      {report.quality.map((q) => (
                        <button
                          key={q.point}
                          className="quality-card"
                          onClick={() => setEvidence(q.evidence)}
                        >
                          <strong>
                            {topology.points.find((p) => p.id === q.point)
                              ?.label || q.point}
                          </strong>
                          <span title="Capture-reported interface and OS drops. Unknown is not zero.">
                            Drops: {num(q.ifdrop, "", 0)} /{" "}
                            {num(q.osdrop, "", 0)}
                          </span>
                          <span title="Frames excluded because their fingerprint repeats, conflicts, or is unsupported.">
                            {num(q.excluded, " excluded", 0)}
                          </span>
                          <span title="Captured length is smaller than wire length; only common payload prefixes are compared.">
                            {num(q.truncated, " truncated", 0)}
                          </span>
                          <span title="Payloads above 1500 bytes may be jumbo frames or offload artifacts, not proof of an error.">
                            {num(q.possible_offload, " large frames", 0)}
                          </span>
                        </button>
                      ))}
                    </div>
                  </section>
                  <section>
                    <div className="section-head">
                      <h2>Ranked findings</h2>
                      <small>
                        First observed event · click for frame evidence
                      </small>
                    </div>
                    {visibleFindings.length ? (
                      [...new Set(visibleFindings.map((f) => f.hop))]
                        .slice(0, 5)
                        .map((hop) => {
                          const segment = report.segments.find(
                            (s) => s.id === hop,
                          )!;
                          return (
                            <article key={hop} style={{ marginBottom: 20 }}>
                              <h3>
                                {segment.label} · {segment.direction}
                              </h3>
                              {!range && <p>{segment.headline}</p>}
                              {visibleFindings
                                .filter((f) => f.hop === hop)
                                .map((f) => (
                                  <button
                                    key={f.id}
                                    title={f.tooltip || f.evidence_note}
                                    className="finding"

                                    onClick={() => setEvidence(f.evidence)}
                                  >
                                    <Badge kind={f.severity}>
                                      {f.type.replaceAll("_", " ")}
                                    </Badge>
                                    <div>
                                      <strong>{f.headline || f.summary}</strong>
                                      <small>
                                        {time(f.time_range[0])} · {f.confidence}
                                      </small>
                                    </div>
                                    <span>↗</span>
                                  </button>
                                ))}
                            </article>
                          );
                        })
                    ) : (
                      <div className="empty">
                        {range && rangeFindings === null
                          ? "Loading selected findings…"
                          : range
                            ? "No supported missing-packet events in the selected interval."
                            : "No supported missing-packet events in this analysis."}
                      </div>
                    )}
                  </section>
                  <section>
                    <div className="section-head">
                      <h2>Hop-by-hop evidence</h2>
                      <small>
                        Click a segment to inspect every missing appearance
                      </small>
                    </div>
                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>Path segment</th>
                            <th>Direction</th>
                            <th>
                              <Tip text="Supported loss events divided by eligible data observations at the upstream point.">
                                Loss
                              </Tip>
                            </th>
                            <th>
                              <Tip text="95th percentile of corrected matched-packet transit times. This is an estimate with clock uncertainty.">
                                Transit p95
                              </Tip>
                            </th>
                            <th>
                              <Tip text="Matched packet appearances or TCP byte-range units at both ends; offload units may span several frames.">
                                Matched
                              </Tip>
                            </th>
                            <th>
                              <Tip text="Lower matchable fraction of the two endpoints; exclusions include SPAN copies, unsupported protocols, and unresolved occurrence timing. Rates are unknown below the configured threshold.">
                                Matchable
                              </Tip>
                            </th>
                            <th>Confidence / limitation</th>
                          </tr>
                        </thead>
                        <tbody>
                          {report.segments.map((s) => (
                            <tr
                              key={s.id}
                              className="clickable"
                              onClick={() => action(() => showEvents(s))}
                            >
                              <td>
                                <strong>{s.label}</strong>
                                {s.loss_suspect && (
                                  <small className="red">
                                    {s.classes.confirmed_device_drop
                                      ? "Confirmed device drop — stage evidence"
                                      : "Loss suspect — supported disappearance here"}
                                  </small>
                                )}
                                {s.symptom_note && (
                                  <small>{s.symptom_note}</small>
                                )}
                                <small>{s.location}</small>
                              </td>
                              <td>{s.direction}</td>
                              <td>{num(s.loss_percent, "%")}</td>
                              <td>{num(s.p95_ms, " ms", 3)}</td>
                              <td>
                                {s.location === "device_stage"
                                  ? "not applicable"
                                  : num(s.matched, "", 0)}
                              </td>
                              <td
                                title={Object.entries(s.excluded_counts || {})
                                  .map(([k, v]) => `${k}: ${v}`)
                                  .join(", ")}
                              >
                                {s.location === "device_stage"
                                  ? "not applicable"
                                  : num(
                                      s.eligible_ratio == null
                                        ? null
                                        : s.eligible_ratio * 100,
                                      "%",
                                    )}
                              </td>
                              <td>
                                {s.reason ||
                                  `Estimated · offset uncertainty ±${num(s.offset_uncertainty_ms, " ms", 3)}`}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </section>
                  {events && (
                    <section>
                      <div className="section-head">
                        <h2>{events.label}</h2>
                        <button
                          className="secondary"
                          onClick={() => setEvents(null)}
                        >
                          Close
                        </button>
                      </div>
                      {events.items.map((e) => (
                        <button
                          className="finding"

                          key={e.id}
                          onClick={() => setEvidence(e.evidence)}
                        >
                          <Badge>{e.kind.replaceAll("_", " ")}</Badge>
                          <div>
                            <strong>{e.reason}</strong>
                            <small>
                              {time(e.ts)} · recovery{" "}
                              {num(e.recovery_ms, " ms")}
                            </small>
                          </div>
                        </button>
                      ))}
                      <div className="pagination">
                        <span>{events.total} events</span>
                        <button
                          disabled={!events.offset}
                          onClick={() =>
                            action(() =>
                              showEvents(events.segment, events.offset - 50),
                            )
                          }
                        >
                          Previous
                        </button>
                        <button
                          disabled={events.offset + 50 >= events.total}
                          onClick={() =>
                            action(() =>
                              showEvents(events.segment, events.offset + 50),
                            )
                          }
                        >
                          Next
                        </button>
                      </div>
                    </section>
                  )}
                </>
              )}
              <section>
                <div className="section-head">
                  <h2>Capture coverage</h2>
                  <Badge>{report ? "CLOCK CORRECTED" : "OBSERVED TIME"}</Badge>
                </div>
                <Coverage captures={state.captures} report={report} />
              </section>
              {report && (
                <details>
                  <summary>Interpretation limits</summary>
                  {report.limitations.map((l) => (
                    <p key={l}>{l}</p>
                  ))}
                  <p>{report.scope}</p>
                </details>
              )}
            </>
          )}
          {tab === "Captures" && (
            <>
              <section>
                <h2>Import Fortinet verbose-6 text</h2>
                <p className="hint">
                  One capture point per interface. Absolute “a” timestamps are
                  UTC. Relative timestamps require an explicit start and retain
                  low clock confidence. Draw the path after importing.
                </p>
                <label>
                  Text file (absolute local path)
                  <input
                    value={fortiPath}
                    onChange={(e) => setFortiPath(e.target.value)}
                  />
                </label>
                <label>
                  Device name
                  <input
                    value={fortiDevice}
                    onChange={(e) => setFortiDevice(e.target.value)}
                  />
                </label>
                <label>
                  Start time for relative timestamps
                  <input
                    placeholder="2026-10-09T12:00:00Z"
                    value={fortiStart}
                    onChange={(e) => setFortiStart(e.target.value)}
                  />
                </label>
                <button
                  disabled={busy || !fortiPath || !fortiDevice}
                  onClick={() =>
                    action(async () =>
                      setJob(
                        await api<Job>("/fortinet/import", "POST", {
                          path: fortiPath,
                          start_time: fortiStart || null,
                          device: fortiDevice,
                        }),
                      ),
                    )
                  }
                >
                  Convert and attach interfaces
                </button>
                {state.fortinet_conversion && (
                  <p>
                    Last conversion: {state.fortinet_conversion.packets}{" "}
                    packets; {state.fortinet_conversion.skipped_lines} skipped
                    lines; {state.fortinet_conversion.skipped_packets}{" "}
                    incomplete/unsupported packets skipped.{" "}
                    {state.fortinet_conversion.files
                      .map(
                        (f) =>
                          `${f.interface}: ${f.packets} packets, clock ${f.clock_confidence}`,
                      )
                      .join(" · ")}
                  </p>
                )}
              </section>
              <section>
                <div className="section-head">
                  <h2>Add packet captures</h2>
                  <Badge>PCAP / PCAPNG / SNOOP</Badge>
                </div>
                <div className="upload-area">
                  <span>⇧</span>
                  <h3>Bring the path into view</h3>
                  <p>
                    Attach local files without copying, or upload them into the
                    project.
                  </p>
                  <label className={"button " + (busy ? "disabled" : "")}>
                    Choose capture files
                    <input
                      type="file"
                      multiple
                      accept=".pcap,.pcapng,.cap,.snoop"
                      hidden
                      disabled={busy}
                      onChange={(e) => action(() => upload(e.target.files))}
                    />
                  </label>
                </div>
                <label>
                  Absolute local file paths (one per line)
                  <textarea
                    value={path}
                    onChange={(e) => setPath(e.target.value)}
                    placeholder="/path/to/firewall-ingress.pcap"
                    rows={3}
                  />
                </label>
                <button
                  disabled={busy || !path.trim()}
                  onClick={() =>
                    action(async () => {
                      setJob(
                        await api<Job>("/captures/attach", "POST", {
                          paths: path
                            .split("\n")
                            .map((s) => s.trim())
                            .filter(Boolean),
                        }),
                      );
                    })
                  }
                >
                  Attach files
                </button>
              </section>
              <section>
                <Coverage captures={state.captures} report={report} />
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Capture</th>
                        <th>Status</th>
                        <th>
                          <Tip text="Number of frames successfully indexed by tshark.">
                            Packets
                          </Tip>
                        </th>
                        <th>Start / end (observed UTC)</th>
                        <th>
                          <Tip text="Elapsed time between first and last observed frame; this does not prove continuous capture.">
                            Duration
                          </Tip>
                        </th>
                        <th>
                          <Tip text="pcapng interface/OS drop counters. Unknown means the file did not report the counter.">
                            Drops (if / OS)
                          </Tip>
                        </th>
                        <th>Interfaces / snaplen / link type</th>
                      </tr>
                    </thead>
                    <tbody>
                      {state.captures.map((c) => (
                        <tr key={c.id}>
                          <td>
                            <strong>{c.name}</strong>
                            <small title={c.path}>{c.path}</small>
                            {c.inventory.warnings?.map((w) => (
                              <small className="red" key={w}>
                                {w}
                              </small>
                            ))}
                            {c.error && (
                              <small className="red">{c.error}</small>
                            )}
                          </td>
                          <td>
                            <Badge
                              kind={c.state === "ready" ? "good" : "unknown"}
                            >
                              {c.state}
                            </Badge>
                            {!["ready", "ingesting"].includes(c.state) && (
                              <button
                                disabled={busy}
                                onClick={() =>
                                  action(async () =>
                                    setJob(
                                      await api<Job>(
                                        "/captures/attach",
                                        "POST",
                                        { paths: [c.path] },
                                      ),
                                    ),
                                  )
                                }
                              >
                                Resume
                              </button>
                            )}
                          </td>
                          <td>
                            {num(
                              c.inventory.packet_count ?? c.checkpoint,
                              "",
                              0,
                            )}
                          </td>
                          <td>
                            {time(
                              c.inventory.timestamps_validated
                                ? c.inventory.start
                                : null,
                            )}
                            <small>
                              {time(
                                c.inventory.timestamps_validated
                                  ? c.inventory.end
                                  : null,
                              )}
                            </small>
                          </td>
                          <td>{num(c.inventory.duration, " s")}</td>
                          <td>
                            {num(c.inventory.ifdrop, "", 0)} /{" "}
                            {num(c.inventory.osdrop, "", 0)}
                          </td>
                          <td>
                            {c.inventory.interfaces.map((x, i) => (
                              <small key={i}>
                                #{x.id} {x.name} · {x.snaplen} B · DLT{" "}
                                {x.link_type}
                              </small>
                            ))}
                            <small title="Largest number of bytes actually stored for a usable packet, independent of the declared interface snaplen.">
                              Observed max{" "}
                              {num(c.inventory.observed_max_caplen, " B", 0)}
                            </small>
                            {!!c.inventory.truncated && (
                              <small className="red">
                                {c.inventory.truncated_caplen_min ===
                                c.inventory.truncated_caplen_max
                                  ? `Packets truncated at ${num(c.inventory.truncated_caplen_max, " B", 0)}`
                                  : `Truncated packet caplen ${num(c.inventory.truncated_caplen_min, " B", 0)}–${num(c.inventory.truncated_caplen_max, " B", 0)}`}
                              </small>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}
          {tab === "Path" && (
            <>
              <section>
                <TopologyEditor
                  topology={topology}
                  captures={state.captures}
                  report={report}
                  onChange={setTopology}
                  onSave={(t) => action(() => saveTopology(t))}
                  onError={setError}
                />
              </section>
              <section>
                <div className="section-head">
                  <h2>Translation mappings</h2>
                  <small>
                    Confirmed mappings combine the two 5-tuples and their
                    reverse direction.
                  </small>
                </div>
                {report?.nat_suggestions.length ? (
                  <>
                    {report.nat_suggestions.map((s, i) => (
                      <div className="mapping" key={i}>
                        <div>
                          <Badge>
                            {num(s.samples, " matching packets", 0)}
                          </Badge>
                          <code>{s.tuple_a}</code>
                          <span>↓</span>
                          <code>{s.tuple_b}</code>
                        </div>
                        <button
                          disabled={topology.nat_mappings.some(
                            (m) =>
                              m.point_a === s.point_a &&
                              m.point_b === s.point_b &&
                              ((m.tuple_a === s.tuple_a &&
                                m.tuple_b === s.tuple_b) ||
                                (reverseTuple(m.tuple_a) === s.tuple_a &&
                                  reverseTuple(m.tuple_b) === s.tuple_b)),
                          )}
                          onClick={() =>
                            setTopology({
                              ...topology,
                              nat_mappings: [...topology.nat_mappings, s],
                            })
                          }
                        >
                          Confirm mapping
                        </button>
                        <button
                          className="secondary"
                          onClick={() => setEvidence(s.evidence || [])}
                        >
                          Evidence
                        </button>
                      </div>
                    ))}
                  </>
                ) : (
                  <p className="hint">
                    Declare both sides of a device as NAT and run analysis to
                    learn candidates. Candidates remain unapplied until
                    confirmed.
                  </p>
                )}
                {topology.nat_mappings.map((m, i) => (
                  <div className="mapping" key={i}>
                    <Badge kind="good">Confirmed</Badge>
                    <div>
                      <input
                        aria-label="Original tuple"
                        value={m.tuple_a}
                        onChange={(e) =>
                          setTopology({
                            ...topology,
                            nat_mappings: topology.nat_mappings.map((x, j) =>
                              i === j ? { ...x, tuple_a: e.target.value } : x,
                            ),
                          })
                        }
                      />
                      <input
                        aria-label="Translated tuple"
                        value={m.tuple_b}
                        onChange={(e) =>
                          setTopology({
                            ...topology,
                            nat_mappings: topology.nat_mappings.map((x, j) =>
                              i === j ? { ...x, tuple_b: e.target.value } : x,
                            ),
                          })
                        }
                      />
                    </div>
                    <button
                      className="secondary"
                      onClick={() =>
                        setTopology({
                          ...topology,
                          nat_mappings: topology.nat_mappings.filter(
                            (_, j) => i !== j,
                          ),
                        })
                      }
                    >
                      Remove
                    </button>
                  </div>
                ))}
                <button
                  disabled={busy}
                  onClick={() => action(() => saveTopology(topology))}
                >
                  Save mapping decisions
                </button>
              </section>
            </>
          )}
          {tab === "Flows" && (
            <>
              <section>
                <div className="section-head">
                  <h2>Conversations</h2>
                  <Badge>{num(flows.total, " TOTAL", 0)}</Badge>
                </div>
                <div className="toolbar">
                  <input
                    aria-label="Search conversations"
                    placeholder="Search an address or port…"
                    value={search}
                    onChange={(e) => {
                      setSearch(e.target.value);
                      setFlowOffset(0);
                    }}
                  />
                  <select
                    aria-label="Quick filter"
                    value={filter}
                    onChange={(e) => {
                      setFilter(e.target.value);
                      setFlowOffset(0);
                    }}
                  >
                    <option value="">All conversations</option>
                    <option value="device_drops">Confirmed device drops</option>
                    <option value="impactful">Impactful loss</option>
                    <option value="handshakes">Incomplete handshakes</option>
                    <option value="resets">Resets observed</option>
                  </select>
                  <select
                    aria-label="Sort conversations"
                    value={sort}
                    onChange={(e) => setSort(e.target.value)}
                  >
                    <option value="bytes">Sort by bytes</option>
                    <option value="max_stall_ms">Sort by recovery wait</option>
                    <option value="impactful_loss">
                      Sort by impactful loss
                    </option>
                    <option value="retrans_observations">
                      Sort by retransmissions
                    </option>
                    <option value="start">Sort by start</option>
                  </select>
                </div>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Canonical conversation</th>
                        <th>
                          <Tip text="Sum of lengths of distinct packet signatures across the selected points, including retransmitted wire packets.">
                            Bytes
                          </Tip>
                        </th>
                        <th>
                          <Tip text="Elapsed corrected time between first and last packet in this 5-tuple conversation.">
                            Duration
                          </Tip>
                        </th>
                        <th>
                          <Tip text="Wireshark retransmission observations summed across capture points; the same retransmission may be observed at several points.">
                            Retrans observations
                          </Tip>
                        </th>
                        <th>Confirmed device drops</th>
                        <th>
                          <Tip text="Impactful / recovered / unrecovered / capture miss / blocked handshake / unknown events. A capture miss is not network loss.">
                            Loss classes
                          </Tip>
                        </th>
                        <th>
                          <Tip text="Largest observed interval from missing original to delivered retransmission; not device processing time.">
                            Max recovery
                          </Tip>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {flows.items.map((f) => (
                        <tr
                          className="clickable"
                          key={f.flow}
                          onClick={() => {
                            setSelectedFlow(f);
                            setLadderOffset(0);
                          }}
                        >
                          <td>
                            <code>{f.tuple}</code>
                            {f.matching_unknown_reason && (
                              <small className="red">
                                Unknown matching: {f.matching_unknown_reason}
                              </small>
                            )}
                            <small>
                              {f.has_reset ? "RST observed · " : ""}
                              {f.handshake_incomplete
                                ? "Handshake incomplete in captures"
                                : ""}
                            </small>
                          </td>
                          <td>{num(f.bytes, " B", 0)}</td>
                          <td>
                            {num(
                              f.start != null && f.end != null
                                ? f.end - f.start
                                : null,
                              " s",
                            )}
                          </td>
                          <td>{f.retrans_observations}</td>
                          <td className={f.confirmed_device_drop ? "red" : ""}>
                            {f.confirmed_device_drop || 0}
                          </td>
                          <td>
                            {f.impactful_loss} / {f.recovered_loss} /{" "}
                            {f.unrecovered_loss} / {f.capture_miss} /{" "}
                            {f.handshake_blocked} / {f.unknown_events}
                          </td>
                          <td>{num(f.max_stall_ms, " ms")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!report && (
                  <div className="empty">
                    Run analysis to populate conversations.
                  </div>
                )}
                <div className="pagination">
                  <span>
                    {flows.total
                      ? `${flowOffset + 1}–${Math.min(flowOffset + 50, flows.total)} of ${flows.total}`
                      : "No conversations"}
                  </span>
                  <button
                    disabled={flowOffset === 0}
                    onClick={() => setFlowOffset(flowOffset - 50)}
                  >
                    Previous
                  </button>
                  <button
                    disabled={flowOffset + 50 >= flows.total}
                    onClick={() => setFlowOffset(flowOffset + 50)}
                  >
                    Next
                  </button>
                </div>
              </section>
              {selectedFlow && (
                <Waterfall
                  key={selectedFlow.flow}
                  flow={selectedFlow.flow}
                  rangeQuery={rangeQuery}
                  onEvidence={setEvidence}
                />
              )}
              {selectedFlow && ladder && (
                <section>
                  <div className="section-head">
                    <div>
                      <span className="eyebrow">STREAM DRILL-DOWN</span>
                      <h2>Multi-hop packet ladder</h2>
                    </div>
                    <button
                      className="secondary"
                      onClick={() => setSelectedFlow(null)}
                    >
                      Close
                    </button>
                  </div>
                  <p className="hint">
                    Teal: original · amber: retransmission · red ×: missing
                    appearance. Click a line or row for Wireshark frame filters.
                  </p>
                  {ladder.local_metrics && (
                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>Capture point / local tuple</th>
                            <th>
                              <Tip text="Observed SYN to matching SYN/ACK at this capture point. Same-clock interval; frame numbers identify the pair.">
                                SYN → SYN/ACK
                              </Tip>
                            </th>
                            <th>
                              <Tip text="Observed SYN/ACK to matching ACK at this capture point.">
                                SYN/ACK → ACK
                              </Tip>
                            </th>
                            <th>
                              <Tip text="Largest Wireshark data/ACK RTT observed at this capture point.">
                                Max RTT
                              </Tip>
                            </th>
                            <th>
                              <Tip text="Observed zero receive windows. These may indicate a receiver/application stall.">
                                Zero windows
                              </Tip>
                            </th>
                          </tr>
                        </thead>
                        <tbody>
                          {ladder.local_metrics.map((m) => (
                            <tr key={m.point}>
                              <td>
                                <strong>{m.point}</strong>
                                <small>{m.tuple}</small>
                              </td>
                              <td>
                                {num(m.handshake?.syn_to_synack_ms, " ms")}
                                <small>
                                  {m.handshake
                                    ? `Frames #${m.handshake.syn_frame} → #${m.handshake.synack_frame}`
                                    : ""}
                                </small>
                              </td>
                              <td>
                                {num(m.handshake?.synack_to_ack_ms, " ms")}
                              </td>
                              <td>{num(m.max_rtt_ms, " ms")}</td>
                              <td>{m.zero_windows}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                  {ladder.flow_filters && (
                    <details>
                      <summary>Wireshark flow filters — one per file</summary>
                      {ladder.flow_filters.map((f) => (
                        <div className="mapping" key={f.capture_id}>
                          <strong>{f.file}</strong>
                          <code>{f.display_filter}</code>
                          <button
                            className="icon"
                            onClick={() =>
                              navigator.clipboard.writeText(f.display_filter)
                            }
                          >
                            Copy flow filter
                          </button>
                        </div>
                      ))}
                      <p className="hint">
                        These use the tuple observed at each file, including
                        NAT, and the selected session's observed time range.
                        Merging or re-saving may change frame numbers.
                      </p>
                    </details>
                  )}
                  {fieldDiff && (
                    <FieldDiff data={fieldDiff} onEvidence={setEvidence} />
                  )}
                  <LadderChart
                    data={ladder}
                    points={topology.forward.map((id) =>
                      topology.points.find((p) => p.id === id)!,
                    )}
                    onEvidence={setEvidence}
                  />
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Direction</th>
                          <th>Sequence / ACK</th>
                          <th>Length</th>
                          <th>Appearances / field differences</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ladder.items.map((p) => (
                          <tr
                            className="clickable"
                            key={p.packet_key}
                            onClick={() => setEvidence(p.evidence)}
                          >
                            <td>
                              {time(p.ts)}{" "}
                              {p.retrans && <Badge kind="low">retrans</Badge>}
                            </td>
                            <td>{p.direction}</td>
                            <td>
                              {p.seq} / {p.ack}
                            </td>
                            <td>{p.length} B</td>
                            <td>
                              {p.evidence
                                .map((e) => `${e.point} #${e.frame}`)
                                .join(" · ")}
                              <button
                                title="Compare raw fields across matched capture points, with evidence and unknowns"
                                onClick={async (event) => {
                                  event.stopPropagation();
                                  try {
                                    setFieldDiff(
                                      await api(
                                        `/packets/${p.packet_key}/field-diff`,
                                      ),
                                    );
                                  } catch (error) {
                                    setFieldDiff({
                                      items: [],
                                      note: String(error),
                                    });
                                  }
                                }}
                              >
                                Field diff
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="pagination">
                    <span>
                      {ladderOffset + 1}–
                      {Math.min(ladderOffset + 100, ladder.total)} of{" "}
                      {ladder.total} packet identities
                    </span>
                    <button
                      disabled={!ladderOffset}
                      onClick={() => setLadderOffset(ladderOffset - 100)}
                    >
                      Previous
                    </button>
                    <button
                      disabled={ladderOffset + 100 >= ladder.total}
                      onClick={() => setLadderOffset(ladderOffset + 100)}
                    >
                      Next
                    </button>
                  </div>
                </section>
              )}
            </>
          )}
          {tab === "Settings" && (
            <>
              <section>
                <h2>Project directory</h2>
                <p className="hint">
                  Create a project in an empty directory or reopen an existing
                  project. Completed captures are cached in its DuckDB file.
                </p>
                <div className="toolbar">
                  <input
                    aria-label="Project directory"
                    value={projectPath}
                    onChange={(e) => setProjectPath(e.target.value)}
                  />
                  <button
                    disabled={busy}
                    onClick={() =>
                      action(async () => {
                        await api("/project", "POST", { path: projectPath });
                        await refresh();
                        setSelectedFlow(null);
                      })
                    }
                  >
                    Open / create project
                  </button>
                </div>
              </section>
              <section>
                <h2>Packet dissection</h2>
                <label>
                  <input
                    type="checkbox"
                    checked={parallelIngest}
                    onChange={(e) => setParallelIngest(e.target.checked)}
                  />{" "}
                  Parallel ingest (optional)
                </label>
                <p className="hint">
                  Serial is the measured default. Parallel uses spare CPU/RAM,
                  but did not reach 1.5× speedup in the equal-file benchmark.
                </p>
                <p className="hint">
                  Detected: {state.tshark.path || "unknown"}
                </p>
                <label>
                  <input
                    type="checkbox"
                    checked={checkpointUuid}
                    onChange={(e) => setCheckpointUuid(e.target.checked)}
                  />
                  fw monitor file includes UUID (-u); reattach after changing
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={f5Trailer}
                    onChange={(e) => setF5Trailer(e.target.checked)}
                  />
                  Decode F5 TMM trailer and request metadata; reattach after
                  changing
                </label>
                <label>
                  tshark override (blank = auto-detect)
                  <input
                    value={tsharkPath}
                    onChange={(e) => setTsharkPath(e.target.value)}
                  />
                </label>
                <label>
                  <Tip text="Maximum captured L4 payload prefix stored for matching. Reattach existing files after changing this value to rebuild their cache.">
                    Payload prefix bytes
                  </Tip>
                  <input
                    type="number"
                    min="8"
                    max="4096"
                    value={prefix}
                    onChange={(e) => setPrefix(Number(e.target.value))}
                  />
                </label>
                <button
                  disabled={busy}
                  onClick={() =>
                    action(async () => {
                      await api("/settings", "POST", {
                        ...state.settings,
                        tshark: tsharkPath || null,
                        prefix_bytes: prefix,
                        parallel: parallelIngest,
                        checkpoint_uuid: checkpointUuid,
                        f5_trailer: f5Trailer,
                      });
                      setNotice(
                        "Settings saved. Reattach files to apply a changed payload prefix.",
                      );
                      await refresh();
                    })
                  }
                >
                  Save settings
                </button>
              </section>
              <section>
                <h2>Analysis window and thresholds</h2>
                <label title="Bucket width for stored time series and onset resolution. Re-run analysis after changing it.">
                  Time bucket (seconds)
                  <input
                    type="number"
                    min="0.1"
                    max="3600"
                    step="0.1"
                    value={topology.bucket_seconds ?? 1}
                    onChange={(e) =>
                      setTopology({
                        ...topology,
                        bucket_seconds: Number(e.target.value),
                      })
                    }
                  />
                </label>
                <div className="two-col">
                  <label>
                    <Tip text="Suppress loss rates when either endpoint's matchable fraction falls below this value. Default 90%.">
                      Minimum matchable fraction (%)
                    </Tip>
                    <input
                      type="number"
                      min="0"
                      max="100"
                      value={(topology.min_eligible_ratio ?? 0.9) * 100}
                      onChange={(e) =>
                        setTopology({
                          ...topology,
                          min_eligible_ratio: Number(e.target.value) / 100,
                        })
                      }
                    />
                  </label>
                  <label>
                    <Tip text="Recovery waits at or above this threshold are impactful loss. Default 200 ms.">
                      Impactful stall threshold (ms)
                    </Tip>
                    <input
                      type="number"
                      value={topology.stall_ms}
                      onChange={(e) =>
                        setTopology({
                          ...topology,
                          stall_ms: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                  <div className="notice">
                    Blank window bounds use the common clock-corrected overlap.
                    Results outside coverage remain unknown.
                  </div>
                  <label>
                    Start (Unix seconds, optional)
                    <input
                      type="number"
                      value={topology.start ?? ""}
                      onChange={(e) =>
                        setTopology({
                          ...topology,
                          start: e.target.value ? Number(e.target.value) : null,
                        })
                      }
                    />
                  </label>
                  <label>
                    End (Unix seconds, optional)
                    <input
                      type="number"
                      value={topology.end ?? ""}
                      onChange={(e) =>
                        setTopology({
                          ...topology,
                          end: e.target.value ? Number(e.target.value) : null,
                        })
                      }
                    />
                  </label>
                </div>
              </section>
              <section>
                <h2>Clock alignment</h2>
                <p className="hint">
                  Offset is capture clock minus reference clock. Drift is parts
                  per million relative to the reference epoch. Estimates assume
                  symmetric minimum path delay; they are not calibrated
                  measurements.
                </p>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Capture</th>
                        <th>Estimated offset / drift</th>
                        <th>Confidence</th>
                        <th>Override offset (ms)</th>
                        <th>Override drift (ppm)</th>
                      </tr>
                    </thead>
                    <tbody>
                      {state.captures.map((c) => {
                        const m = report?.clocks[c.id],
                          o = topology.clock_overrides[c.id];
                        return (
                          <tr key={c.id}>
                            <td>{c.name}</td>
                            <td title={m?.reason}>
                              {num(
                                m?.offset != null ? m.offset * 1000 : null,
                                " ms",
                                3,
                              )}
                              <small>
                                {num(m?.drift_ppm, " ppm", 3)} ·{" "}
                                {m?.samples ?? 0} pairs
                              </small>
                            </td>
                            <td title={m?.reason}>
                              <Badge>{m?.confidence || "unknown"}</Badge>
                              {!!m?.evidence?.length && (
                                <button
                                  className="icon"
                                  onClick={() => setEvidence(m.evidence)}
                                >
                                  Frames
                                </button>
                              )}
                              <small>
                                ±
                                {num(
                                  m?.uncertainty != null
                                    ? m.uncertainty * 1000
                                    : null,
                                  " ms",
                                  3,
                                )}
                              </small>
                            </td>
                            <td>
                              <input
                                aria-label={`Offset ${c.name}`}
                                type="number"
                                step="any"
                                value={o?.offset_ms ?? ""}
                                placeholder="Automatic"
                                onChange={(e) => {
                                  const overrides = {
                                    ...topology.clock_overrides,
                                  };
                                  if (e.target.value === "")
                                    delete overrides[c.id];
                                  else
                                    overrides[c.id] = {
                                      offset_ms: Number(e.target.value),
                                      drift_ppm: o?.drift_ppm || 0,
                                    };
                                  setTopology({
                                    ...topology,
                                    clock_overrides: overrides,
                                  });
                                }}
                              />
                            </td>
                            <td>
                              <input
                                aria-label={`Drift ${c.name}`}
                                disabled={!o}
                                type="number"
                                step="any"
                                value={o?.drift_ppm ?? ""}
                                onChange={(e) =>
                                  setTopology({
                                    ...topology,
                                    clock_overrides: {
                                      ...topology.clock_overrides,
                                      [c.id]: {
                                        offset_ms: o.offset_ms,
                                        drift_ppm: Number(e.target.value),
                                      },
                                    },
                                  })
                                }
                              />
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <button
                  disabled={busy}
                  onClick={() => action(() => saveTopology(topology))}
                >
                  Save analysis settings
                </button>
              </section>
            </>
          )}
        </div>
        <footer>
          PacketBreaker <span>Evidence first. Uncertainty visible.</span>
          <span>All analysis stays on this computer.</span>
        </footer>
      </main>
      {evidence && (
        <Evidence refs={evidence} onClose={() => setEvidence(null)} />
      )}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
