import type { IncidentReport } from "./Incident";
import { useState } from "react";
import { Chart } from "./Charts";
import { useWorkspace } from "./WorkspaceContext";
import { metricLabels } from "./overviewModel";
import {
  timeChart,
  metricNotes,
  clickEvidence,
  brushTime,
} from "./IncidentCharts";
import type { EChartsOption } from "echarts";
export function EvidenceQualityCharts() {
  const { report, topology, range, setEvidence, selectRange } = useWorkspace();
  const [selected, setSelected] = useState("");
  const data = report?.incident;
  if (!data) return null;
  const edges = [
    ...new Set(
      data.quality.map((r) => `${r.direction}:${r.point_a}:${r.point_b}`),
    ),
  ];
  const edge = edges.includes(selected)
    ? selected
    : edges.find((e) => {
        const [, a, b] = e.split(":");
        return topology.points.some(
          (p) => p.host_capture && (p.id === a || p.id === b),
        );
      }) || edges[0];
  const label = (e: string) => {
    const [d, a, b] = e.split(":");
    return `${d === "forward" ? "RX / forward" : "TX / return"} · ${topology.points.find((p) => p.id === a)?.label || a} → ${topology.points.find((p) => p.id === b)?.label || b}`;
  };
  function plotted(
    rows: IncidentReport["quality"],
    keys: string[],
    stack: string,
  ) {
    return keys.map((key) => ({
      name: metricLabels[key],
      type: "bar",
      stack,
      data: rows
        .filter(
          (r) =>
            `${r.direction}:${r.point_a}:${r.point_b}` === edge &&
            (!range || (r.start >= range[0] && r.start < range[1])),
        )
        .map((r) => ({
          value: [r.start * 1000, r[key]],
          evidence: r.evidence,
          note: metricNotes[key],
        })),
    })) as EChartsOption["series"];
  }
  return (
    <>
      <label>
        Adjacent pair and direction{" "}
        <select value={edge} onChange={(e) => setSelected(e.target.value)}>
          {edges.map((e) => (
            <option value={e} key={e}>
              {label(e)}
            </option>
          ))}
        </select>
      </label>
      <h3>Delay versus drop</h3>
      <p className="hint">
        Same original identity seen later → delayed. Original missing, retry
        delivered → dropped.
        <br />
        Seq-only matching can pair the retry with the original and misread RTO
        recovery as transit delay.
      </p>
      <Chart
        option={{
          ...timeChart(),
          yAxis: { type: "value", name: "Observed units (count)", min: 0 },
          series: plotted(data.delivery, ["delayed", "dropped"], "delivery"),
        }}
        onClick={(e) => clickEvidence(e, setEvidence)}
        onBrush={(e) => brushTime(e, selectRange)}
      />
      <h3>Capture mismatch</h3>
      <p className="hint">{data.quality_note}</p>
      <Chart
        option={{
          ...timeChart(),
          yAxis: { type: "value", name: "Mismatch (%)", min: 0, max: 100 },
          series: plotted(
            data.quality,
            [
              "capture_miss_percent",
              "loss_percent",
              "offload_mismatch_percent",
              "unknown_percent",
            ],
            "quality",
          ),
        }}
        onClick={(e) => clickEvidence(e, setEvidence)}
        onBrush={(e) => brushTime(e, selectRange)}
      />
    </>
  );
}
