










import {Heatmap} from "./Heatmap";



import {num,time} from "./api";

import {ProxyEvidence} from "./ProxyEvidence";
import {Assistant} from "./Assistant";








import {useWorkspace} from "./WorkspaceContext";
import {Tip} from "./UI";

export function ProtocolDiagnostics() {
  const {
    series,
    range,
    selectRange,
    inspection,
    state,
    topology,
    evidence,
    setEvidence,
    filter,
    events,
    report,
    ready,
    kinds,
  } = useWorkspace();
  return (
    <>
      <Assistant
        enabled={state.settings.assistant_enabled ?? false}
        ready={!!report}
        project={state.project}
      />
      {!!report?.sequence_translations?.length && (
        <section>
          <h2>Sequence translations</h2>
          {report.sequence_translations.map((m, i) => (
            <button
              key={i}
              className="finding"

              onClick={() => setEvidence(m.evidence)}
            >
              {m.ingress} → {m.egress} · flow {m.flow?.slice(0, 8) || "unknown"}
              :{" "}
              {m.status === "learned"
                ? `forward SEQ offset ${m.boundary_forward_offset}, ACK offset ${m.boundary_reverse_offset} (mod 2³²); ${m.samples} anchors`
                : `unknown — ${m.reason}`}
            </button>
          ))}
        </section>
      )}
      {!!report?.vendor_device_events?.some((e) => e.status === "unknown") && (
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
      {report && <ProxyEvidence report={report} onEvidence={setEvidence} />}
      {!!report?.f5?.pairs.length && (
        <section>
          <h2>F5 connection pairs and request forwarding</h2>
          <p className="hint">{report.f5.note}</p>
          <p className="hint">
            Capture context. Client/server TCP legs remain separate; forwarding
            intervals use tshark-decoded request-bearing frames.
          </p>
          {report.f5.pairs.map((p, i) => (
            <p key={i}>
              {p.role} · flowid {p.flowid} ↔ peerid {p.peerid} · processor{" "}
              {p.tmm}
              {p.reason && ` · unknown: ${p.reason}`}
              {p.client_flow && (
                <small>
                  Client conversation {p.client_flow} / server conversation{" "}
                  {p.server_flow}
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
              {r.device} · {r.request}: {num(r.request_dwell_ms, " ms")} ±
              {num(r.clock_uncertainty_ms, " ms")}
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
                  {topology.points.find((x) => x.id === p.point)?.label ||
                    p.point}
                  : {p.large_frames} large TCP frames.
                </strong>{" "}
                {p.note}
              </p>
            ))}
          <p className="hint">
            Matching uses TCP sequence coverage, not equality of capture packet
            counts. Loss counts describe affected upstream frames; missing-byte
            totals retain partial-frame detail.
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
                  Quality notes: {s.onset_quality_notes?.capture_misses || 0}{" "}
                  capture misses; {s.onset_quality_notes?.unknown_events || 0}{" "}
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
          <strong>{report ? num(report.flow_count, "", 0) : "—"}</strong>
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
          <strong className={report?.confirmed_device_drop_count ? "red" : ""}>
            {report ? num(report.confirmed_device_drop_count || 0, "", 0) : "—"}
          </strong>
        </div>
        <div>
          <Tip text="Intermediate capture absence contradicted by later packet or ACK evidence. These are not network loss.">
            Capture misses
          </Tip>
          <strong>{report ? num(kinds.capture_miss || 0, "", 0) : "—"}</strong>
        </div>
      </div>
    </>
  );
}
