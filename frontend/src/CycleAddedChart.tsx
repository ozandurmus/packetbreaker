import { useState } from "react";
import { Chart } from "./Charts";
import { useWorkspace } from "./WorkspaceContext";
import { boundaryTitle, cycleLabel, quantile } from "./overviewModel";
import { timeChart, clickEvidence } from "./IncidentCharts";
import { addedParts, addedTotal, displayCycles } from "./cycleDisplay";
import { num } from "./api";
import type { EChartsOption } from "echarts";
export function CycleAddedChart() {
  const { report, topology, range, selectRange, setEvidence } = useWorkspace();
  const [order, setOrder] = useState<"total" | "components">("components"),
    [eventOnly, setEventOnly] = useState(true);
  const data = report?.incident;
  if (!data) return null;
  const event = data.window;
  const inside = (t: number) =>
    (!range || (t >= range[0] && t < range[1])) &&
    (!eventOnly || !event || (t >= event.start && t < event.end));
  const bars = displayCycles(report!, eventOnly)
    .filter((b) => inside(b.time))
    .sort((a, b) =>
      order === "total"
        ? (b.total_ms ?? -Infinity) - (a.total_ms ?? -Infinity)
        : (b.rx_ms ?? -Infinity) +
          (b.tx_ms ?? 0) -
          ((a.rx_ms ?? -Infinity) + (a.tx_ms ?? 0)),
    );
  const sample = bars.map(addedTotal).filter((n): n is number => n != null);
  const cap = Math.max(1, quantile(sample, 0.99) ?? 1);
  const names = [
    ...new Set(bars.flatMap((b) => addedParts(b).map((p) => p.name))),
  ];
  const display = (name: string) => {
    const component =
      bars.flatMap(addedParts).find((p) => p.name === name)?.component ||
      "Added";
    return `${component} ${names.filter((n) => n.endsWith(" " + component)).indexOf(name) + 1}`;
  };
  const series = names.map((name) => ({
    name: display(name),
    type: "bar",
    stack: "cycle",
    clip: true,
    data: bars.map((b) => {
      const p = b.parts.find((p) => p.name === name);
      return {
        value: p?.ms == null ? null : Math.max(0, p.ms),
        evidence: p?.evidence,
        note:
          p?.reason ||
          `${boundaryTitle(name.split(" ")[0], topology)}: measured ${num(p?.ms)} ms ±${num(p?.uncertainty_ms)} ms. Added stack ${num(addedTotal(b))} ms. Server-local ${num(b.parts.find((p) => p.component === "local")?.ms)} ms (not stacked). Cycle elapsed ${num(b.total_ms)} ms. Client wait / serialization residual ${num(b.total_ms != null && addedTotal(b) != null && b.parts.some((p) => p.component === "local" && p.ms != null) ? Math.max(0, b.total_ms - addedTotal(b)! - b.parts.find((p) => p.component === "local")!.ms!) : null)} ms (not stacked). Null parts remain unknown.`,
      };
    }),
  }));
  const clipped = bars.flatMap((b, i) => {
    const measured = addedParts(b).reduce(
      (sum, p) => sum + Math.max(0, p.ms ?? 0),
      0,
    );
    return measured > cap
      ? [
          {
            value: [i, cap],
            name: `${num(measured)} ms ↑`,
            label: { show: measured > cap * 1.05 },
            evidence: b.parts.flatMap((p) => p.evidence),
            note: `Real stack ${num(measured)} ms; display clipped at ${num(cap)} ms. Total cycle ${num(b.total_ms)} ms.`,
          },
        ]
      : [];
  });
  const option: EChartsOption = {
    ...timeChart(),
    legend: {
      type: "plain",
      orient: "horizontal",
      top: 0,
      itemWidth: 10,
      itemGap: 8,
      textStyle: { fontSize: 10 },
      data: names.map(display),
    },
    grid: { top: 55, bottom: 105, left: 85, right: 35 },
    xAxis: {
      type: "category",
      data: bars.map((b) => cycleLabel(b, topology.forward)),
      axisLabel: { fontSize: 10, interval: "auto", rotate: 0 },
      name: "Time / client port",
      nameLocation: "middle",
      nameGap: 45,
    },
    yAxis: {
      type: "value",
      name: "Added time (ms)",
      nameLocation: "middle",
      nameGap: 55,
      min: 0,
      max: cap,
      axisLabel: { formatter: (v: number) => num(v, "", 0) },
    },
    tooltip: {
      trigger: "item",
      renderMode: "richText",
      formatter: (e: unknown) => {
        const p = e as {
          seriesName: string;
          data: { value: number | number[]; name?: string; note: string };
        };
        return `${p.seriesName}\n${p.data.name || num(typeof p.data.value === "number" ? p.data.value : p.data.value[1]) + " ms"}\n${p.data.note}\nClick for evidence.`;
      },
    },
    series: [
      ...series,
      {
        name: "Clipped — real value (ms)",
        type: "scatter",
        symbol: "triangle",
        symbolSize: 13,
        itemStyle: { color: "#c4563e" },
        label: {
          show: true,
          position: "top",
          formatter: (e: unknown) =>
            (e as { data: { name: string } }).data.name,
        },
        data: clipped,
      },
    ] as EChartsOption["series"],
  };
  return (
    <>
      <div className="chart-controls">
        <div className="segmented">
          <button
            className={order === "total" ? "active" : ""}
            onClick={() => setOrder("total")}
          >
            By total
          </button>
          <button
            className={order === "components" ? "active" : ""}
            onClick={() => setOrder("components")}
          >
            By RX/TX
          </button>
        </div>
        <label>
          <input
            type="checkbox"
            checked={eventOnly}
            onChange={(e) => setEventOnly(e.target.checked)}
          />{" "}
          Event-window cycles only
        </label>
      </div>
      <p className="hint">
        Y-axis capped at p99 of displayed added-time samples ({num(cap)} ms);
        triangles retain the real stack value. Null/partial components are
        unknown. Only RX/TX added time is stacked; server-local and client wait
        remain in tooltips. Legend numbers identify path boundaries (hover for
        names).{" "}
        {!event && "No supported event window: showing available cycles."}
      </p>
      {bars.length ? (
        <Chart
          option={option}
          height={340}
          onClick={(e) => clickEvidence(e, setEvidence)}
          onBrush={(e) => {
            const a = (e as { areas?: { coordRange: number[] }[] }).areas?.[0]
              ?.coordRange;
            if (!a) {
              selectRange(null);
              return;
            }
            const b = bars.slice(
              Math.max(0, Math.ceil(Math.min(...a))),
              Math.floor(Math.max(...a)) + 1,
            );
            if (b.length)
              selectRange([
                Math.min(...b.map((x) => x.time)),
                Math.max(...b.map((x) => x.time)) + 1,
              ]);
          }}
        />
      ) : (
        <p>
          No top cycles in this interval. Clear the brush or include the full
          window.
        </p>
      )}
    </>
  );
}
