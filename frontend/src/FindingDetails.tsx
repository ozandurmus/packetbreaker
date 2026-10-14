import { num, time } from "./api";

import { useWorkspace } from "./WorkspaceContext";
import { Badge, Tip } from "./UI";

export function FindingDetails() {
  const {
    range,
    rangeFindings,
    setTab,
    error,
    topology,
    evidence,
    setEvidence,
    path,
    flows,
    filter,
    events,
    setEvents,
    action,
    analyze,
    showEvents,
    report,
    visibleFindings,
    kinds,
    busy,
  } = useWorkspace();
  return (
    <>
      {!report ? (
        <section className="empty-start">
          <div className="path-illustration">
            ◉ <span>·····</span> ◇ <span>·····</span> ◇ <span>·····</span> ◉
          </div>
          <span className="eyebrow">FROM CAPTURES TO EVIDENCE</span>
          <h2>One path. Multiple perspectives.</h2>
          <p>
            Attach the captures, connect their capture points, then analyze the
            same traffic across the path.
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
                    (p) => p.vendor === "paloalto" && p.vendor_stage === "drop",
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
          <section>
            <div className="section-head">
              <h2>Ranked findings</h2>
              <small>First observed event · click for frame evidence</small>
            </div>
            {visibleFindings.length ? (
              [...new Set(visibleFindings.map((f) => f.hop))]
                .slice(0, 5)
                .map((hop) => {
                  const segment = report.segments.find((s) => s.id === hop);
                  return (
                    <article key={hop} style={{ marginBottom: 20 }}>
                      <h3>
                        {segment?.label ||
                          topology.points.find(
                            (p) => p.id === hop.split(":")[1],
                          )?.label ||
                          hop}{" "}
                        · {segment?.direction || hop.split(":")[0]}
                      </h3>
                      {!range &&
                        report.incident?.loss_groups
                          .filter((g) => g.hop === hop)
                          .map((g) => (
                            <details key={g.hop} open>
                              <summary>{g.headline}</summary>
                              <p>
                                {Object.entries(g.counts)
                                  .map(([k, v]) => `${k}: ${v}`)
                                  .join(" · ")}
                              </p>
                            </details>
                          ))}
                      {!range && segment?.headline && <p>{segment.headline}</p>}
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
                              {f.downstream_summary && (
                                <small>{f.downstream_summary}</small>
                              )}
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
              <small>Click a segment to inspect every missing appearance</small>
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
                        {s.symptom_note && <small>{s.symptom_note}</small>}
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
                        {s.quality_notes?.length ? (
                          <small>{s.quality_notes.join("; ")}</small>
                        ) : null}
                        {s.reason ||
                          `Estimated · offset uncertainty ±${num(s.latency_uncertainty_ms ?? s.offset_uncertainty_ms, " ms", 3)}`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          {events && (
            <section id="selected-segment">
              <div className="section-head">
                <h2>{events.label}</h2>
                <button className="secondary" onClick={() => setEvents(null)}>
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
                      {time(e.ts)} · recovery {num(e.recovery_ms, " ms")}
                    </small>
                  </div>
                </button>
              ))}
              <div className="pagination">
                <span>{events.total} events</span>
                <button
                  disabled={!events.offset}
                  onClick={() =>
                    action(() => showEvents(events.segment, events.offset - 50))
                  }
                >
                  Previous
                </button>
                <button
                  disabled={events.offset + 50 >= events.total}
                  onClick={() =>
                    action(() => showEvents(events.segment, events.offset + 50))
                  }
                >
                  Next
                </button>
              </div>
            </section>
          )}
        </>
      )}
    </>
  );
}
