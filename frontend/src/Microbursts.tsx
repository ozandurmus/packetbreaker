import {num,time} from "./api";
import type {Ref} from "./types";
export type MicroburstReport = {
  note: string;
  total: number;
  window_ms: number;
  points: {
    evidence: Ref[];
    point: string;
    label: string;
    peak_observed_mbps: number | null;
    baseline_mbps: number;
    threshold_mbps: number;
    burst_count: number | null;
    max_duration_ms: number | null;
    frequency_hz: number | null;
    tooltip: string;
  }[];
  items: {
    point: string;
    start: number;
    end: number;
    corrected_start: number | null;
    peak_mbps: number;
    duration_ms: number | null;
    min_interarrival_us: number | null;
    tooltip: string;
    evidence: Ref[];
    loss_associations: {
      segment: string;
      ordering: string;
      reason: string;
      evidence: Ref[];
    }[];
  }[];
};
export function Microbursts({
  data,
  onEvidence,
}: {
  data: MicroburstReport;
  onEvidence: (refs: Ref[]) => void;
}) {
  return (
    <section>
      <h2>Capture microbursts</h2>
      <p className="hint">{data.note}</p>
      <p>
        Rolling window: {num(data.window_ms, " ms")}. {data.total} episodes;{" "}
        {data.items.length} shown.
      </p>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Point</th>
              <th>Peak observed Mbps</th>
              <th>Baseline / threshold Mbps</th>
              <th>Bursts</th>
              <th>Max duration ms</th>
              <th>Frequency Hz</th>
            </tr>
          </thead>
          <tbody>
            {data.points.map((p) => (
              <tr key={p.point} title={p.tooltip}>
                <td>
                  <button onClick={() => onEvidence(p.evidence)}>
                    {p.label}
                  </button>
                </td>
                <td>{num(p.peak_observed_mbps)}</td>
                <td>
                  {num(p.baseline_mbps)} / {num(p.threshold_mbps)}
                </td>
                <td>{num(p.burst_count)}</td>
                <td>{num(p.max_duration_ms)}</td>
                <td>{num(p.frequency_hz)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <details>
        <summary>Burst episodes and frame evidence</summary>
        {data.items.map((b, i) => (
          <article key={i} title={b.tooltip}>
            <h3>
              {b.point} · {num(b.peak_mbps, " Mbps")}
            </h3>
            <p>
              {time(b.corrected_start ?? b.start)}
              {b.corrected_start === null
                ? " (local unaligned capture time)"
                : ""}{" "}
              · {num(b.duration_ms, " ms")} · minimum inter-arrival{" "}
              {num(b.min_interarrival_us, " μs")}
            </p>
            <button onClick={() => onEvidence(b.evidence)}>
              Open burst frames
            </button>
            {b.loss_associations.length === 0 ? (
              <p>No supported nearby loss onset association; cause unknown.</p>
            ) : (
              b.loss_associations.map((a, j) => (
                <p key={j}>
                  {a.segment}: {a.reason}. Timing order: {a.ordering}.{" "}
                  <button onClick={() => onEvidence(a.evidence)}>
                    Loss onset frames
                  </button>
                </p>
              ))
            )}
          </article>
        ))}
      </details>
    </section>
  );
}
