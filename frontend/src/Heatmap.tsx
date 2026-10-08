import { useCallback, useEffect, useMemo, useState } from "react";
import type { EChartsOption } from "echarts";
import { Chart } from "./Charts";
import type { Report, TimeSeries } from "./types";

export function Heatmap({
  data,
  report,
  onSelect,
  selectedRange,
}: {
  data: TimeSeries;
  selectedRange: [number, number] | null;
  report: Report;
  onSelect: (range: [number, number] | null) => void;
}) {
  const [metric, setMetric] = useState("loss_percent");
  const [clear, setClear] = useState(0);
  useEffect(() => {
    if (selectedRange === null) setClear((n) => n + 1);
  }, [selectedRange]);
  const descriptor = data.metrics[metric];
  const onBrush = useCallback(
    (event: unknown) => {
      const areas = (
        event as { areas?: { coordRange?: number[] | number[][] }[] }
      ).areas;
      if (!areas?.length) {
        onSelect(null);
        return;
      }
      const raw = areas[0].coordRange;
      if (!raw) return;
      const range = Array.isArray(raw[0]) ? raw[0] : (raw as number[]);
      const left = Math.max(0, Math.floor(Math.min(...range)));
      const right = Math.min(
        data.bucket_count - 1,
        Math.ceil(Math.max(...range)),
      );
      if (Number.isFinite(left) && Number.isFinite(right))
        onSelect([
          data.start + left * data.bucket_seconds,
          data.start + (right + 1) * data.bucket_seconds,
        ]);
    },
    [data.start, data.bucket_seconds, data.bucket_count, onSelect],
  );
  const option = useMemo<EChartsOption>(() => {
    const segments = report.segments;
    const index = new Map(segments.map((s, i) => [s.id, i]));
    const full: { value: number[]; row: TimeSeries["items"][number] }[] = [];
    const empty: typeof full = [];
    for (const row of data.items) {
      const v = row[metric];
      const target = typeof v === "number" ? full : empty;
      target.push({
        value: [
          row.bucket,
          index.get(row.segment)!,
          typeof v === "number" ? v : -1,
        ],
        row,
      });
    }
    const max = full.reduce((m, x) => Math.max(m, x.value[2]), 1);
    const markers =
      report.onsets?.items
        .filter((o) => o.metric === metric)
        .map((o) => ({
          value: [o.bucket, index.get(o.segment)!, 0],
          name: o.explanation,
        })) || [];
    return {
      animation: false,
      grid: { left: 220, right: 35, top: 55, bottom: 130 },
      tooltip: {
        renderMode: "richText",
        formatter: (p: unknown) => {
          const item = (
            p as { data?: { row?: TimeSeries["items"][number]; name?: string } }
          ).data;
          if (!item?.row) return item?.name || "Onset";
          const r = item.row,
            v = r[metric],
            s = segments.find((s) => s.id === r.segment)!;
          return `${s.label} · ${s.direction}\n${new Date(r.start * 1000).toISOString()}\n${descriptor.label}: ${typeof v === "number" ? v.toFixed(3) + " " + descriptor.unit : r.coverage !== "capturing" ? r.coverage : "unknown / no samples"}\n${descriptor.tooltip}\n${r.reason || "Observed coverage; gaps between packets do not prove capture continuity."}`;
        },
      },
      toolbox: { feature: { brush: { type: ["lineX", "clear"] } } },
      brush: {
        xAxisIndex: 0,
        brushMode: "single",
        throttleType: "debounce",
        throttleDelay: 150,
      },
      xAxis: {
        type: "category",
        name: "UTC",
        data: Array.from({ length: data.bucket_count }, (_, i) =>
          new Date((data.start + i * data.bucket_seconds) * 1000)
            .toISOString()
            .slice(11, data.bucket_seconds < 1 ? 23 : 19),
        ),
        axisLabel: {
          interval: Math.max(0, Math.ceil(data.bucket_count / 8) - 1),
          rotate: 0,
        },
      },
      yAxis: {
        type: "category",
        inverse: true,
        data: segments.map((s) => `${s.label} · ${s.direction}`),
        axisLabel: { width: 200, overflow: "truncate" },
      },
      visualMap: {
        min: 0,
        max,
        calculable: true,
        orient: "horizontal",
        left: "center",
        bottom: 0,
        seriesIndex: 0,
        inRange: { color: ["#d9efea", "#69bcb4", "#e9b44c", "#c44842"] },
        text: [descriptor.unit, "0"],
      },
      dataZoom: [{ type: "slider", xAxisIndex: 0, bottom: 55, height: 15 }],
      series: [
        {
          type: "heatmap",
          name: descriptor.label,
          data: full,
          emphasis: { itemStyle: { borderColor: "#243b46", borderWidth: 1 } },
        },
        {
          type: "heatmap",
          name: "Unavailable",
          data: empty,
          itemStyle: { color: "#d9dfe3", borderColor: "#fff", borderWidth: 1 },
          label: {
            show: true,
            fontSize: 8,
            formatter: (p: unknown) =>
              (p as { data: { row: TimeSeries["items"][number] } }).data.row
                .coverage === "not capturing"
                ? "NC"
                : "?",
          },
        },
        {
          type: "scatter",
          name: "Onset",
          symbol: "diamond",
          symbolSize: 14,
          itemStyle: { color: "#101f32", borderColor: "#fff", borderWidth: 2 },
          data: markers,
          z: 10,
        },
      ],
    };
  }, [data, report, metric, descriptor]);
  return (
    <section>
      <div className="section-head">
        <h2>Path × time</h2>
        <label>
          Metric{" "}
          <select
            aria-label="Heatmap metric"
            value={metric}
            onChange={(e) => setMetric(e.target.value)}
          >
            {Object.entries(data.metrics).map(([key, m]) => (
              <option key={key} value={key} title={m.tooltip}>
                {m.label} ({m.unit})
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="hint" title={descriptor.tooltip}>
        {descriptor.tooltip} Diamonds mark detected onsets. NC = not capturing;
        ? = partial coverage or unavailable metric. Use the horizontal brush
        tool to filter flows, findings and the ladder.
      </p>
      <button
        onClick={() => {
          setClear((n) => n + 1);
          onSelect(null);
        }}
      >
        Clear time selection
      </button>
      <Chart
        key={clear}
        option={option}
        height={Math.max(360, report.segments.length * 36 + 200)}
        onBrush={onBrush}
      />
    </section>
  );
}
