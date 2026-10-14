import { Chart } from "./Charts";
import { useWorkspace } from "./WorkspaceContext";
import { metricLabels } from "./overviewModel";
import {
  timeChart,
  metricNotes,
  brushTime,
  clickEvidence,
} from "./IncidentCharts";
import type { EChartsOption } from "echarts";
export function IncidentTimeline() {
  const { report, range, selectRange, setEvidence } = useWorkspace();
  const data = report?.incident;
  if (!data) return <p>No incident series computed.</p>;
  const keys = [
    "rx_max_ms",
    "tx_max_ms",
    "tx_dropped",
    "tx_delayed",
    "retransmissions",
  ];
  const rows = data.timeline.filter(
    (r) => !range || (r.start >= range[0] && r.start < range[1]),
  );
  const series = keys.map((key, i) => ({
    name: metricLabels[key],
    type: "line",
    yAxisIndex: i < 2 ? 0 : 1,
    showSymbol: true,
    data: rows.map((r) => ({
      value: [r.start * 1000, r[key]],
      evidence: r.evidence,
      note: metricNotes[key],
    })),
    markArea:
      i === 0 && data.window && data.timeline.length
        ? {
            data: [
              [
                { name: "Before", xAxis: data.timeline[0].start * 1000 },
                { xAxis: data.window.start * 1000 },
              ],
              [
                {
                  name: "Event",
                  xAxis: data.window.start * 1000,
                  itemStyle: { color: "rgba(232,155,52,.16)" },
                },
                { xAxis: data.window.end * 1000 },
              ],
              [
                { name: "Recovery", xAxis: data.window.end * 1000 },
                { xAxis: data.timeline.at(-1)!.start * 1000 + 1000 },
              ],
            ],
          }
        : undefined,
  }));
  return (
    <>
      <p className="hint">
        Same-copy RX/TX transit is separate from original-copy drops and sender
        retransmissions. Select a time interval or click a point for evidence.
      </p>
      <Chart
        height={310}
        option={{
          ...timeChart(),
          yAxis: [
            { type: "value", name: "Transit (ms)", min: 0 },
            { type: "value", name: "Count", min: 0 },
          ],
          series: series as EChartsOption["series"],
        }}
        onBrush={(e) => brushTime(e, selectRange)}
        onClick={(e) => clickEvidence(e, setEvidence)}
      />
    </>
  );
}
