import { Chart } from "./Charts";
import { num } from "./api";
import type { Ref } from "./types";
export type HostPathReport = {
  note: string;
  scope: string;
  window_reason?: string;
  local_service: {
    samples?: number;
    p95_ms?: number | null;
    cycle_aggregate?: { p95_ms: number | null; samples: number };
  };
  items: {
    hop: string;
    flow: string | null;
    affected_flow_count: number;
    flow_details: {
      flow: string;
      p95_ms: number;
      max_ms: number;
      reason?: string;
      evidence: Ref[];
    }[];
    direction: string;
    headline: string;
    max_ms: number;
    uncertainty_ms: number;
    delay_share_percent: number;
    window: {
      start: number;
      end: number;
      recovery_confirmed: boolean;
      status?: string;
      reason?: string;
    };
    periods: {
      period: string;
      p95_ms: number;
      max_ms: number;
      bytes: number;
    }[];
    series: {
      start: number;
      p95_ms: number;
      max_ms: number;
      evidence?: Ref[];
    }[];
    evidence: Ref[];
  }[];
};
export function HostPath({
  data,
  onEvidence,
}: {
  data?: HostPathReport;
  onEvidence: (refs: Ref[]) => void;
}) {
  if (!data?.items.length) return null;
  return (
    <section>
      <h2>Host receive / transmit path</h2>
      <p>{data.note}</p>
      <p className="hint">
        {data.scope}. This view uses the saved analysis window, not the heatmap
        brush.
      </p>
      {data.items.map((item) => {
        const values = new Map(item.series.map((r) => [r.start, r]));
        const times = [];
        for (
          let t = item.series[0].start;
          t <= item.series[item.series.length - 1].start;
          t++
        )
          times.push(t);
        return (
          <article key={item.hop + item.flow}>
            <h3>
              {item.direction.toUpperCase()} · {item.hop}
            </h3>
            <p>{item.headline}</p>
            <p>
              Maximum {num(item.max_ms)} ms ± {num(item.uncertainty_ms)} ms;
              share of byte-weighted excess boundary delay{" "}
              {num(item.delay_share_percent)}%.
            </p>
            <p>
              {item.window.status === "unknown"
                ? "Observed interval (onset unknown)"
                : "Event"}{" "}
              {new Date(item.window.start * 1000).toLocaleString()} —{" "}
              {new Date(item.window.end * 1000).toLocaleString()} (
              {new Date(item.window.start * 1000).toISOString()} —{" "}
              {new Date(item.window.end * 1000).toISOString()}); recovery{" "}
              {item.window.recovery_confirmed ? "confirmed" : "unknown"}.
            </p>
            <Chart
              option={{
                tooltip: { trigger: "axis" },
                xAxis: { type: "time" },
                yAxis: { type: "value", name: "ms" },
                series: [
                  {
                    type: "line",
                    name: "Host boundary p95",
                    showSymbol: true,
                    data: times.map((t) => [
                      t * 1000,
                      values.get(t)?.p95_ms ?? null,
                    ]),
                    markArea: {
                      data: [
                        [
                          { xAxis: item.window.start * 1000 },
                          { xAxis: item.window.end * 1000 },
                        ],
                      ],
                    },
                  },
                ],
              }}
              onClick={(e) => {
                const t = (e as { value?: number[] }).value?.[0];
                onEvidence(
                  t
                    ? values.get(t / 1000)?.evidence || item.evidence
                    : item.evidence,
                );
              }}
            />
            <table>
              <thead>
                <tr>
                  <th>Period</th>
                  <th>p95 ms</th>
                  <th>Max ms</th>
                  <th>Matched bytes</th>
                </tr>
              </thead>
              <tbody>
                {item.periods.map((p) => (
                  <tr key={p.period}>
                    <td>{p.period}</td>
                    <td>{num(p.p95_ms)}</td>
                    <td>{num(p.max_ms)}</td>
                    <td>{p.bytes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <button onClick={() => onEvidence(item.evidence)}>
              Open boundary evidence
            </button>
            <details>
              <summary>
                {item.affected_flow_count} affected flows — drill-down
              </summary>
              <table>
                <thead>
                  <tr>
                    <th>Flow</th>
                    <th>Boundary p95 ms</th>
                    <th>Max ms</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {item.flow_details.map((r) => (
                    <tr key={r.flow} title={r.reason}>
                      <td>{r.flow}</td>
                      <td>{num(r.p95_ms)}</td>
                      <td>{num(r.max_ms)}</td>
                      <td>
                        <button onClick={() => onEvidence(r.evidence)}>
                          Frames
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          </article>
        );
      })}
    </section>
  );
}
