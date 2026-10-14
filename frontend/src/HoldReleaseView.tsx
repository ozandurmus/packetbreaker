import { useState } from "react";
import { Chart } from "./Charts";
import { useWorkspace } from "./WorkspaceContext";
import {
  boundaryTitle,
  groupHolds,
  quantile,
  portFromEvidence,
} from "./overviewModel";
import { timeChart, clickEvidence } from "./IncidentCharts";
import { num, time } from "./api";
import type { EChartsOption } from "echarts";
export function HoldReleaseView() {
  const { report, topology, range, setEvidence } = useWorkspace();
  const [groupIndex, setGroupIndex] = useState(0),
    [memberIndex, setMemberIndex] = useState(0);
  const all = report?.incident?.hold_release || [];
  const visible = all.filter(
    (f) =>
      !range || (f.time_range[0] >= range[0] && f.time_range[0] < range[1]),
  );
  const groups = groupHolds(visible);
  const group = groups[Math.min(groupIndex, groups.length - 1)];
  if (!group)
    return <p>No supported hold-and-release signature in this interval.</p>;
  const selected = group[Math.min(memberIndex, group.length - 1)];
  const points = [...new Set(selected.evidence.map((e) => e.point))];
  const series = points.map((point) => {
    const refs = selected.evidence
      .filter((e) => e.point === point)
      .sort((a, b) => a.observed_time - b.observed_time);
    const start = refs[0].observed_time;
    return {
      name: `${topology.points.find((p) => p.id === point)?.label || point} — copy spacing`,
      type: "line",
      symbolSize: 8,
      data: refs.map((r, i) => ({
        value: [(r.observed_time - start) * 1000, i + 1],
        evidence: [r],
        note: `${r.file} · frame ${r.frame}; local elapsed ${num((r.observed_time - start) * 1000)} ms; observed ${time(r.observed_time)}.`,
      })),
    };
  });
  return (
    <>
      <label>
        Hold/release signatures{" "}
        <select
          aria-label="Hold/release signature"
          value={Math.min(groupIndex, groups.length - 1)}
          onChange={(e) => {
            setGroupIndex(Number(e.target.value));
            setMemberIndex(0);
          }}
        >
          {groups.map((g, i) => (
            <option key={i} value={i}>
              {boundaryTitle(g[0].hop, topology)} · {g.length} trains · wire{" "}
              {g[0].metrics.wire_spacing_ms
                .map((_, k) =>
                  num(
                    quantile(
                      g.map((f) => f.metrics.wire_spacing_ms[k]),
                      0.5,
                    ),
                  ),
                )
                .join("/")}{" "}
              ms → compressed{" "}
              {g[0].metrics.receive_spacing_ms
                .map((_, k) =>
                  num(
                    quantile(
                      g.map((f) => f.metrics.receive_spacing_ms[k]),
                      0.5,
                    ),
                  ),
                )
                .join("/")}{" "}
              ms
            </option>
          ))}
        </select>
      </label>
      <label>
        Occurrence{" "}
        <select
          value={Math.min(memberIndex, group.length - 1)}
          aria-label="Hold/release occurrence"
          onChange={(e) => setMemberIndex(Number(e.target.value))}
        >
          {group.map((f, i) => (
            <option key={f.id} value={i}>
              {time(f.time_range[0])} · client port{" "}
              {portFromEvidence(f.evidence, topology.forward) ?? "unknown"}
            </option>
          ))}
        </select>
      </label>
      <p className="hint">
        One representative train is shown; all {group.length} occurrences retain
        their evidence. Each capture starts at its own first copy, so spacing is
        clock-independent. {selected.tooltip}
      </p>
      <Chart
        height={260}
        option={{
          ...timeChart(),
          xAxis: { type: "value", name: "Local elapsed (ms)" },
          yAxis: { type: "value", name: "Copy number", minInterval: 1 },
          tooltip: {
            trigger: "item",
            renderMode: "richText",
            formatter: (e: unknown) => {
              const p = e as {
                seriesName: string;
                data: { value: number[]; note: string };
              };
              return `${p.seriesName}\nCopy ${p.data.value[1]} at ${num(p.data.value[0])} ms\n${p.data.note}`;
            },
          },
          series: series as EChartsOption["series"],
        }}
        onClick={(e) => clickEvidence(e, setEvidence)}
        onBrush={(e) => {
          const a = (e as { areas?: { coordRange: number[] }[] }).areas?.[0]
            ?.coordRange;
          if (a)
            setEvidence(
              series.flatMap((s) =>
                s.data
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
    </>
  );
}
