import type { IncidentReport, Part } from "./Incident";
import type { Report } from "./types";
export type CycleBar = IncidentReport["cycle_bars"][number];
export function addedParts(bar: CycleBar) {
  return bar.parts.filter((p) => p.component === "RX" || p.component === "TX");
}
export function addedTotal(bar: CycleBar) {
  const parts = addedParts(bar);
  return parts.length && parts.every((p) => p.ms != null)
    ? parts.reduce((sum, p) => sum + Math.max(0, p.ms!), 0)
    : null;
}
export function displayCycles(report: Report, eventOnly: boolean) {
  const bars = [...(report.incident?.cycle_bars || [])];
  const best = (eventOnly ? report.cycles?.event : report.cycles?.analysis)
    ?.max_added;
  if (best && !bars.some((b) => b.cycle_id === best.cycle_id)) {
    const parts: Part[] = ["RX", "TX"].map((component) => {
      const refs = best.evidence.filter((r) => r.point === best.host);
      const frame = best.frames.find((f) =>
        component === "RX" ? f.point_b === best.host : f.point_a === best.host,
      );
      const name = frame
        ? `${component === "RX" ? "forward" : "reverse"}:${frame.point_a}:${frame.point_b} ${component}`
        : component;
      return {
        name,
        component,
        ms: component === "RX" ? best.rx_ms : best.tx_ms,
        uncertainty_ms: best.uncertainty_ms,
        evidence: best.evidence.length ? best.evidence : refs,
      };
    });
    bars.push({
      cycle_id: best.cycle_id,
      flow: best.flow,
      time: best.time,
      total_ms: null,
      rx_ms: best.rx_ms,
      tx_ms: best.tx_ms,
      parts,
    });
  }
  return bars;
}
