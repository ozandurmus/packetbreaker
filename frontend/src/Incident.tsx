import { useState } from "react";
import { Chart } from "./Charts";
import type { EChartsOption } from "echarts";
import type { Ref } from "./types";
import { num } from "./api";
type Row = { start: number; evidence: Ref[]; [key: string]: unknown };
type Part = {
  name: string;
  component: string;
  ms: number | null;
  uncertainty_ms: number;
  reason?: string;
  evidence: Ref[];
};
export type IncidentReport = {
  headline: string;
  scope: string;
  quality_note: string;
  window?: { start: number; end: number };
  timeline: Row[];
  delivery: Row[];
  quality: Row[];
  cycle_bars: {
    cycle_id: string;
    flow: string;
    time: number;
    total_ms: number | null;
    rx_ms: number | null;
    tx_ms: number | null;
    parts: Part[];
  }[];
  hold_release: {
    id: string;
    hop: string;
    time_range: number[];
    metrics: { wire_spacing_ms: number[]; receive_spacing_ms: number[] };
    evidence: Ref[];
    tooltip: string;
    summary: string;
  }[];
  loss_groups: {
    hop: string;
    headline: string;
    counts: Record<string, number>;
    evidence: Ref[];
  }[];
};
const descriptions: Record<string, string> = {
  rx_max_ms:
    "Maximum measured same-copy RX boundary transit per second, ms; clock uncertainty applies.",
  tx_max_ms:
    "Maximum measured same-copy TX boundary transit per second, ms. Retry substitutions are excluded.",
  tx_dropped:
    "TX original copies absent across the host boundary, or supported loss; later retry is delivery, not delay.",
  tx_delayed:
    "TX copies with original identity observed later; delay above max(1 ms, twice clock uncertainty).",
  retransmissions:
    "tshark retransmissions observed at the host; sender symptom, not fault attribution.",
  delayed:
    "Original copy observed downstream later; same-copy evidence required.",
  dropped: "Original disappears; retry delivery is not original transit.",
  capture_miss_percent:
    "Capture miss supported by ACK or a later downstream appearance / observed pair units.",
  loss_percent:
    "Supported dropped pair units / observed pair units; no device cause implied.",
  offload_mismatch_percent:
    "Unknown pairs with different segmentation and a super-frame, not network loss.",
  unknown_percent:
    "Other unknown pair units; identity or timing evidence insufficient.",
};
export function Incident({
  data,
  range,
  onSelect,
  onEvidence,
}: {
  data?: IncidentReport;
  range: [number, number] | null;
  onSelect: (r: [number, number] | null) => void;
  onEvidence: (e: Ref[]) => void;
}) {
  const [sort, setSort] = useState<"total_ms" | "rx_ms" | "tx_ms">("total_ms");
  if (!data) return null;
  const visible = (t: number) => !range || (t >= range[0] && t < range[1]);
  function brush(event: unknown) {
    const a = (event as { areas?: { coordRange: number[] }[] }).areas?.[0]
      ?.coordRange;
    if (!a) {
      onSelect(null);
      return;
    }
    onSelect([Math.min(...a) / 1000, Math.max(...a) / 1000]);
  }
  const base: EChartsOption = {
    animation: false,
    tooltip: {
      trigger: "item",
      renderMode: "richText",
      formatter: (p: unknown) => {
        const q = p as {
          seriesName: string;
          data: { value: unknown[]; note?: string; evidence?: Ref[] };
        };
        return `${q.seriesName}\n${String(q.data.value[0])}: ${num(q.data.value[1] as number)}\n${q.data.note || ""}\nClick for frame evidence; drag to select time.`;
      },
    },
    toolbox: { feature: { brush: { type: ["lineX", "clear"] } } },
    brush: { xAxisIndex: 0, brushMode: "single" },
    legend: { type: "scroll" },
    grid: { top: 55, bottom: 65, left: 70, right: 75 },
    xAxis: { type: "time" },
    yAxis: { type: "value" },
    dataZoom: [{ type: "slider", height: 18 }],
  };
  function click(event: unknown) {
    onEvidence((event as { data?: { evidence?: Ref[] } }).data?.evidence || []);
  }
  function series(rows: Row[], keys: string[], stack?: string) {
    return keys.map((name) => ({
      name,
      type: stack ? "bar" : "line",
      stack,
      showSymbol: true,
      data: rows
        .filter((r) => visible(r.start))
        .map((r) => ({
          value: [r.start * 1000, r[name] as number | null],
          evidence: r.evidence,
          note: descriptions[name],
        })),
    })) as EChartsOption["series"];
  }
  const shaded = data.window
    ? {
        data: [
          [
            {
              name: "before",
              xAxis: Math.min(...data.timeline.map((r) => r.start)) * 1000,
            },
            { xAxis: data.window.start * 1000 },
          ],
          [
            {
              name: "event",
              xAxis: data.window.start * 1000,
              itemStyle: { color: "rgba(220,140,40,.2)" },
            },
            { xAxis: data.window.end * 1000 },
          ],
          [
            { name: "recovery", xAxis: data.window.end * 1000 },
            {
              xAxis:
                Math.max(...data.timeline.map((r) => r.start)) * 1000 + 1000,
            },
          ],
        ],
      }
    : undefined;
  const timeline = series(data.timeline, [
    "rx_max_ms",
    "tx_max_ms",
    "tx_dropped",
    "tx_delayed",
    "retransmissions",
  ]) as Record<string, unknown>[];
  timeline.forEach((s, i) => {
    s.yAxisIndex = i < 2 ? 0 : 1;
    if (!i) s.markArea = shaded;
  });
  const bars = data.cycle_bars
    .filter((r) => visible(r.time))
    .sort((a, b) => (b[sort] ?? -Infinity) - (a[sort] ?? -Infinity));
  const names = [...new Set(bars.flatMap((b) => b.parts.map((p) => p.name)))];
  const boundaries = [
    ...new Set(
      data.delivery.map((r) => `${r.direction}: ${r.point_a} → ${r.point_b}`),
    ),
  ];
  return (
    <section>
      <h2>Incident timeline</h2>
      <p className="hint">{data.scope}</p>
      <Chart
        option={{
          ...base,
          yAxis: [
            { type: "value", name: "Boundary max ms", min: 0 },
            { type: "value", name: "Count", min: 0 },
          ],
          series: timeline as EChartsOption["series"],
        }}
        onBrush={brush}
        onClick={click}
      />
      <p>{data.headline}</p>
      {data.loss_groups.map((g) => (
        <article key={g.hop}>
          <h3>{g.headline}</h3>
          <p>
            {Object.entries(g.counts)
              .map(([k, v]) => `${k}: ${v}`)
              .join(" · ")}
          </p>
          <button onClick={() => onEvidence(g.evidence)}>Evidence</button>
        </article>
      ))}
      <h3>Where was the time added?</h3>
      <label>
        Sort top cycles{" "}
        <select
          value={sort}
          onChange={(e) => setSort(e.target.value as typeof sort)}
        >
          <option value="total_ms">Total</option>
          <option value="rx_ms">RX</option>
          <option value="tx_ms">TX</option>
        </select>
      </label>
      <p className="hint">
        Stacked last-request-byte RX + server-local turnaround +
        first-response-byte TX. Missing components stay unknown; components may
        not sum to the cycle duration (request serialization and incomplete
        coverage).
      </p>
      <Chart
        option={{
          ...base,
          xAxis: {
            type: "category",
            data: bars.map((b) => b.cycle_id.slice(0, 8)),
            axisLabel: { rotate: 35 },
          },
          yAxis: { type: "value", name: "Added ms" },
          series: names.map((name) => ({
            name,
            type: "bar",
            stack: "time",
            data: bars.map((b) => {
              const p = b.parts.find((p) => p.name === name);
              return {
                value: p?.ms ?? null,
                evidence: p?.evidence,
                note: `${p?.reason || "Observed component"}; uncertainty ±${num(p?.uncertainty_ms)} ms; cycle total ${num(b.total_ms)} ms`,
              };
            }),
          })),
          tooltip: {
            trigger: "item",
            renderMode: "richText",
            formatter: (e: unknown) => {
              const p = e as {
                seriesName: string;
                data: { value: number; note: string };
              };
              return `${p.seriesName}: ${num(p.data.value)} ms\n${p.data.note}`;
            },
          },
        }}
        onClick={click}
        onBrush={(e) => {
          const a = (e as { areas?: { coordRange: number[] }[] }).areas?.[0]
            ?.coordRange;
          if (!a) {
            onSelect(null);
            return;
          }
          const b = bars.slice(
            Math.max(0, Math.ceil(Math.min(...a))),
            Math.floor(Math.max(...a)) + 1,
          );
          if (b.length)
            onSelect([
              Math.min(...b.map((x) => x.time)),
              Math.max(...b.map((x) => x.time)) + 1,
            ]);
        }}
      />
      <h3>Hold and release</h3>
      {!data.hold_release.length && (
        <p>No supported hold-and-release copy train in this saved window.</p>
      )}
      {data.hold_release
        .filter((f) => visible(f.time_range[0]))
        .map((f) => {
          const points = [...new Set(f.evidence.map((e) => e.point))];
          const copies = points.map((point) => {
            const refs = f.evidence
              .filter((e) => e.point === point)
              .sort((a, b) => (a.observed_time ?? 0) - (b.observed_time ?? 0));
            const t = refs[0]?.observed_time ?? 0;
            return {
              name: point,
              type: "line",
              data: refs.map((r, i) => ({
                value: [((r.observed_time ?? t) - t) * 1000, i + 1],
                evidence: [r],
                note: `${r.file} frame ${r.frame}; observed ${r.observed_time}; local spacing, clock independent.`,
              })),
            };
          });
          return (
            <article key={f.id}>
              <p>{f.summary}</p>
              <p className="hint">
                {f.tooltip} Each point starts at its own first copy; this is
                local spacing, not cross-clock transit.
              </p>
              <Chart
                option={{
                  ...base,
                  xAxis: { type: "value", name: "Local elapsed ms" },
                  yAxis: { type: "value", name: "Copy number", minInterval: 1 },
                  series: copies as EChartsOption["series"],
                }}
                onClick={click}
                onBrush={(e) => {
                  const a = (e as { areas?: { coordRange: number[] }[] })
                    .areas?.[0]?.coordRange;
                  if (a)
                    onEvidence(
                      copies.flatMap((p) =>
                        p.data
                          .filter(
                            (d) =>
                              d.value[0] >= Math.min(...a) &&
                              d.value[0] <= Math.max(...a),
                          )
                          .flatMap((d) => d.evidence),
                      ),
                    );
                }}
              />
            </article>
          );
        })}
      <h3>Delay versus drop</h3>
      <p>
        Same original identity seen later → delayed. Original missing, retry
        delivered → dropped.
      </p>
      <p>
        Seq-only matching can pair the retry with the original and falsely
        display RTO recovery as transit delay.
      </p>
      {boundaries.map((key) => {
        const rows = data.delivery.filter(
          (r) => `${r.direction}: ${r.point_a} → ${r.point_b}` === key,
        );
        return (
          <article key={key}>
            <h4>{key}</h4>
            <Chart
              option={{
                ...base,
                yAxis: { type: "value", name: "Observed units" },
                series: series(rows, ["delayed", "dropped"], "delivery"),
              }}
              onClick={click}
              onBrush={brush}
            />
          </article>
        );
      })}
    </section>
  );
}
