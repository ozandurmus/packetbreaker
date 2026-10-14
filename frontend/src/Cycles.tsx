export type CycleAggregate = {
  max_added_ms: number | null;
  max_added?: {
    cycle_id: string;
    flow: string;
    time: number;
    host: string;
    rx_ms: number;
    tx_ms: number;
    added_ms: number;
    uncertainty_ms: number;
    frames: {
      point_a: string;
      point_b: string;
      frame_a: number;
      frame_b: number;
    }[];
    evidence: Ref[];
  };
};
import { Chart } from "./Charts";
import { num } from "./api";
import type { Ref, Report } from "./types";
export type CycleReport = {
  event?: CycleAggregate;
  analysis?: CycleAggregate;
  total?: number;
  stalled_total?: number;
  max_added_ms?: number | null;
  note: string;
  scope: string;
  stall_ms: number;
  series: {
    point: string;
    start: number;
    evidence?: Ref[];
    p95_ms: number | null;
    max_ms: number | null;
    stalled: number;
  }[];
  flow_ports: {
    point: string;
    flow: string;
    port: number;
    cycles: number;
    stalled: number;
    p95_ms: number;
    max_ms: number;
    before_p95_ms?: number;
    event_p95_ms?: number;
    recovery_p95_ms?: number;
    per_hop_added?: string;
  }[];
  periods: {
    point: string;
    flow: string;
    period: string;
    cycles: number;
    p95_ms: number;
    reason?: string;
  }[];
  top: {
    cycle_id: string;
    point: string;
    flow: string;
    port: number;
    request_first: number;
    period?: string;
    cycle_ms: number | null;
    turnaround_ms: number | null;
    reason?: string;
    evidence?: Ref[];
  }[];
  pairs: {
    hop: string;
    component: string;
    added_ms: number | null;
    uncertainty_ms: number;
    reason?: string;
  }[];
};
export function Cycles({
  data,
  delivery,
  range,
  onSelect,
  onEvidence,
}: {
  data?: CycleReport;
  delivery?: Report["delivery"];
  range: [number, number] | null;
  onSelect: (r: [number, number] | null) => void;
  onEvidence: (refs: Ref[]) => void;
}) {
  if (!data) return null;
  const visible = (t: number) => !range || (t >= range[0] && t < range[1]);
  const points = [...new Set(data.series.map((s) => s.point))];
  return (
    <section>
      <h2>Opaque TCP cycles</h2>
      <p>{data.note}</p>
      <p className="hint">
        {data.scope}. Stalled ≥ {data.stall_ms} ms. Charts and top cycles use
        the selected time range; flow/port and three-period aggregates describe
        the full saved window. UI series are limited to 20,000 rows; table
        exports include all rows.
      </p>
      <p>
        <a href="/api/engine/export?format=csv">Download CSV tables (ZIP)</a> ·{" "}
        <a href="/api/engine/export?format=xlsx">Download XLSX workbook</a>
      </p>
      <Chart
        option={{
          toolbox: { feature: { brush: { type: ["lineX", "clear"] } } },
          brush: { xAxisIndex: 0 },
          tooltip: {
            trigger: "item",
            formatter: (p: unknown) => {
              const q = p as { seriesName: string; data: { value: number[] } };
              return `${q.seriesName}: ${num(q.data.value[1])} ms; observed opaque TCP-cycle p95, not application response.`;
            },
          },
          xAxis: { type: "time" },
          yAxis: { type: "value", name: "Cycle p95 ms" },
          series: points.map((p) => ({
            name: p,
            type: "scatter",
            data: data.series
              .filter((r) => r.point === p && visible(r.start))
              .map((r) => ({
                value: [r.start * 1000, r.p95_ms],
                evidence: r.evidence,
              })),
          })),
        }}
        onClick={(e) =>
          onEvidence((e as { data: { evidence?: Ref[] } }).data.evidence || [])
        }
        onBrush={(e) => {
          const a = (e as { areas?: { coordRange: number[] }[] }).areas?.[0]
            ?.coordRange;
          onSelect(a ? [Math.min(...a) / 1000, Math.max(...a) / 1000] : null);
        }}
      />
      <details>
        <summary>Per flow / port</summary>
        <table>
          <thead>
            <tr>
              <th>Point</th>
              <th>Flow / port</th>
              <th>Cycles</th>
              <th>Stalled</th>
              <th>p95 ms</th>
              <th>Max ms</th>
              <th>Before p95</th>
              <th>Event p95</th>
              <th>Recovery p95</th>
              <th>Per-hop added p95 ms</th>
            </tr>
          </thead>
          <tbody>
            {data.flow_ports.map((r) => (
              <tr key={r.point + r.flow + r.port}>
                <td>{r.point}</td>
                <td>
                  {r.flow.slice(0, 8)} / {r.port}
                </td>
                <td>{r.cycles}</td>
                <td>{r.stalled}</td>
                <td>{num(r.p95_ms)}</td>
                <td>{num(r.max_ms)}</td>
                <td>{num(r.before_p95_ms)}</td>
                <td>{num(r.event_p95_ms)}</td>
                <td>{num(r.recovery_p95_ms)}</td>
                <td title="Full-window adjacent RX/TX added time; missing clocks remain unknown">
                  {r.per_hop_added}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
      <details>
        <summary>Before / event / recovery</summary>
        <table>
          <thead>
            <tr>
              <th>Point / flow</th>
              <th>Period</th>
              <th>Cycles</th>
              <th>p95 ms</th>
            </tr>
          </thead>
          <tbody>
            {data.periods.map((r, i) => (
              <tr key={i} title={r.reason}>
                <td>
                  {r.point} / {r.flow.slice(0, 8)}
                </td>
                <td>{r.period}</td>
                <td>{r.cycles}</td>
                <td>{num(r.p95_ms)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
      <details>
        <summary>RX / TX added time between adjacent points</summary>
        <table>
          <thead>
            <tr>
              <th>Boundary</th>
              <th>Component</th>
              <th>Added ms ± uncertainty</th>
            </tr>
          </thead>
          <tbody>
            {data.pairs.slice(0, 200).map((r, i) => (
              <tr key={i} title={r.reason}>
                <td>{r.hop}</td>
                <td>{r.component}</td>
                <td>
                  {num(r.added_ms)} ± {num(r.uncertainty_ms)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
      {delivery && (
        <details>
          <summary>Per-second delay versus drop, by direction</summary>
          <p>{delivery.note}</p>
          <table>
            <thead>
              <tr>
                <th>Time / boundary</th>
                <th>Direction</th>
                <th>Delayed</th>
                <th>Dropped</th>
                <th>Capture miss / unknown</th>
                <th>Delay / recovery ms</th>
              </tr>
            </thead>
            <tbody>
              {delivery.series.slice(0, 1000).map((r, i) => (
                <tr key={i}>
                  <td>
                    {new Date(r.start * 1000).toLocaleTimeString()} /{" "}
                    {r.point_a} → {r.point_b}
                  </td>
                  <td>{r.direction}</td>
                  <td>{r.delayed}</td>
                  <td>{r.dropped}</td>
                  <td>
                    {r.capture_misses} / {r.unknown}
                  </td>
                  <td>
                    {num(r.max_delay_ms)} / {num(r.max_recovery_ms)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
      <h3>Top slow cycles — evidence at every observed point</h3>
      <table>
        <thead>
          <tr>
            <th>Cycle / point</th>
            <th>Port</th>
            <th>Period</th>
            <th>Cycle ms</th>
            <th>Local turnaround ms</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {data.top
            .filter((r) => visible(r.request_first))
            .map((r, i) => (
              <tr key={i} title={r.reason}>
                <td>
                  {r.cycle_id?.slice(0, 8)} / {r.point}
                </td>
                <td>{r.port}</td>
                <td>{r.period || "unknown"}</td>
                <td>{num(r.cycle_ms)}</td>
                <td>{num(r.turnaround_ms)}</td>
                <td>
                  <button onClick={() => onEvidence(r.evidence || [])}>
                    Frames
                  </button>
                  {r.reason && <small>{r.reason}</small>}
                </td>
              </tr>
            ))}
        </tbody>
      </table>
    </section>
  );
}
