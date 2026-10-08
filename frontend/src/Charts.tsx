import { useEffect, useRef } from "react";
import * as echarts from "echarts";
import type { EChartsOption } from "echarts";
import type { Capture, Ladder, Point, Report, Ref } from "./types";

function Chart({
  option,
  height = 260,
  onClick,
}: {
  option: EChartsOption;
  height?: number;
  onClick?: (params: unknown) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current);
    chart.setOption(option);
    if (onClick) chart.on("click", onClick);
    const resize = new ResizeObserver(() => chart.resize());
    resize.observe(ref.current);
    return () => {
      resize.disconnect();
      chart.dispose();
    };
  }, [option, onClick]);
  return (
    <div
      role="img"
      aria-label="Interactive packet capture chart"
      ref={ref}
      style={{ height, width: "100%" }}
    />
  );
}
export function Coverage({
  captures,
  report,
}: {
  captures: Capture[];
  report: Report | null;
}) {
  const values = captures.filter(
    (c) =>
      c.state === "ready" &&
      c.inventory.timestamps_validated &&
      c.inventory.start != null,
  );
  const hasClocks = !!report;
  const data = values.map((c, i) => {
    const m = report?.clocks[c.id];
    const correct = (t: number) =>
      m?.offset != null
        ? m.epoch + (t - m.epoch - m.offset) / (1 + m.drift_ppm / 1e6)
        : t;
    return [
      i,
      correct(c.inventory.start!) * 1000,
      correct(c.inventory.end!) * 1000,
    ];
  });
  const overlap = report?.window;
  const option: EChartsOption = {
    useUTC: true,
    animation: false,
    grid: { left: 150, right: 25, top: 20, bottom: 55 },
    tooltip: { renderMode: "richText" },
    xAxis: { type: "time", axisLabel: { color: "#657780" } },
    yAxis: {
      type: "category",
      data: values.map((c) => c.name),
      axisLabel: { width: 130, overflow: "truncate" },
      inverse: true,
    },
    dataZoom: [{ type: "slider", height: 18, bottom: 8 }],
    series: [
      {
        type: "custom",
        data,
        renderItem: (params, api) => {
          const a = api.coord([api.value(1), api.value(0)]),
            b = api.coord([api.value(2), api.value(0)]);
          return {
            type: "rect",
            shape: {
              x: a[0],
              y: a[1] - 9,
              width: Math.max(b[0] - a[0], 2),
              height: 18,
            },
            style: { fill: "#168a84", opacity: 0.8 },
          };
        },
        encode: { x: [1, 2], y: 0 },
        markArea:
          overlap?.common_start != null && overlap.common_end != null
            ? {
                silent: true,
                itemStyle: { color: "rgba(234,183,64,.18)" },
                data: [
                  [
                    { xAxis: overlap.common_start * 1000 },
                    { xAxis: overlap.common_end * 1000 },
                  ],
                ],
              }
            : undefined,
      },
    ],
  };
  return (
    <>
      <p className="hint">
        {hasClocks
          ? "Corrected timestamps where alignment is available. Amber marks common overlap."
          : "Observed timestamps. Run analysis to align clocks and calculate common overlap."}{" "}
        First and last packets bound observed coverage.
      </p>
      <Chart option={option} height={Math.max(220, values.length * 35 + 75)} />
    </>
  );
}
export function LadderChart({
  data,
  points,
  onEvidence,
}: {
  data: Ladder;
  points: Point[];
  onEvidence: (refs: Ref[]) => void;
}) {
  const pointIndex = new Map(points.map((p, i) => [p.id, i]));
  const timed = data.items.flatMap((p) =>
    p.evidence
      .map((e) => e.corrected_time)
      .filter((t): t is number => t != null),
  );
  const start = Math.min(...timed);
  const series: echarts.SeriesOption[] = data.items.map((p) => ({
    name: p.packet_key,
    type: "line",
    connectNulls: false,
    showSymbol: true,
    symbolSize: 5,
    lineStyle: {
      width: 1.2,
      color: p.retrans ? "#d78325" : "#268b86",
      opacity: 0.65,
    },
    itemStyle: { color: p.retrans ? "#d78325" : "#268b86" },
    data: points.map((point, i) => {
      const e = p.evidence.find((e) => e.point === point.id);
      return [
        i,
        e?.corrected_time != null ? (e.corrected_time - start) * 1000 : null,
      ];
    }),
    emphasis: { lineStyle: { width: 3 } },
  }));
  series.push({
    type: "scatter",
    name: "Missing appearance",
    symbol: "path://M-5,-5 L5,5 M5,-5 L-5,5",
    symbolSize: 12,
    itemStyle: { color: "#c44842" },
    data: data.events
      .filter(
        (e) =>
          pointIndex.has(e.point_b) &&
          data.items.some((p) => p.packet_key === e.packet_key),
      )
      .map((e) => [pointIndex.get(e.point_b)!, (e.ts - start) * 1000]),
  });
  const option: EChartsOption = {
    useUTC: true,
    animation: false,
    grid: { left: 80, right: 30, top: 45, bottom: 70 },
    tooltip: { renderMode: "richText", trigger: "item" },
    xAxis: {
      type: "category",
      position: "top",
      data: points.map((p) => p.label),
      axisLabel: { interval: 0, rotate: 10 },
    },
    yAxis: {
      type: "value",
      inverse: true,
      name: "Elapsed ms",
      axisLabel: { formatter: "{value} ms" },
    },
    dataZoom: [
      { type: "slider", yAxisIndex: 0, orient: "vertical", right: 0 },
      { type: "inside", yAxisIndex: 0 },
    ],
    series,
  };
  if (!timed.length)
    return (
      <div className="empty">
        Clock alignment is unknown. Frame evidence is available below.
      </div>
    );
  return (
    <Chart
      option={option}
      height={520}
      onClick={(params) => {
        const key = (params as { seriesName: string }).seriesName;
        const p = data.items.find((p) => p.packet_key === key);
        if (p) onEvidence(p.evidence);
      }}
    />
  );
}
