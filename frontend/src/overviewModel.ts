import type { Ref, Report, Segment, Topology } from "./types";
import type { IncidentReport } from "./Incident";
export const metricLabels: Record<string, string> = {
  rx_max_ms: "RX max (ms)",
  tx_max_ms: "TX max (ms)",
  tx_dropped: "TX dropped (count)",
  tx_delayed: "TX delayed (count)",
  retransmissions: "Retransmissions (count)",
  delayed: "Delayed originals (count)",
  dropped: "Dropped originals (count)",
  capture_miss_percent: "Capture miss (%)",
  loss_percent: "Supported loss (%)",
  offload_mismatch_percent: "Offload mismatch (%)",
  unknown_percent: "Other unknown (%)",
};
export function quantile(values: number[], p: number) {
  const sorted = values
    .filter((v) => Number.isFinite(v) && v >= 0)
    .sort((a, b) => a - b);
  if (!sorted.length) return null;
  const at = (sorted.length - 1) * p,
    lo = Math.floor(at);
  return sorted[lo] + (sorted[Math.ceil(at)] - sorted[lo]) * (at - lo);
}
export function portFromEvidence(refs: Ref[], path: string[] = []) {
  const ordered = [...refs].sort((a, b) => {
    const ai = path.indexOf(a.point),
      bi = path.indexOf(b.point);
    return (ai < 0 ? 999 : ai) - (bi < 0 ? 999 : bi);
  });
  for (const r of ordered) {
    const m = r.content_filter?.match(/tcp\.srcport\s*==\s*(\d+)/);
    if (m) return Number(m[1]);
  }
  return null;
}
export function cycleLabel(
  bar: IncidentReport["cycle_bars"][number],
  path: string[],
) {
  const refs = bar.parts
    .filter((p) => p.component === "RX")
    .flatMap((p) => p.evidence);
  const port = portFromEvidence(refs, path);
  return `${new Date(bar.time * 1000).toLocaleTimeString([], { hour12: false })}\n:${port ?? "unknown"}`;
}
export function segmentHealth(segment: Segment, topology: Topology) {
  if (
    segment.reason ||
    segment.max_ms == null ||
    segment.loss_percent == null ||
    segment.eligible_ratio == null ||
    segment.eligible_ratio < topology.min_eligible_ratio
  )
    return "unknown";
  const loss = [
    "impactful_loss",
    "recovered_loss",
    "unrecovered_loss",
    "confirmed_device_drop",
    "handshake_blocked",
    "host_transmit_path_loss",
    "host_receive_path_loss",
  ].some((k) => (segment.classes[k] || 0) > 0);
  if (loss || segment.loss_percent > 0) return "degraded";
  const uncertainty =
    segment.latency_uncertainty_ms ?? segment.offset_uncertainty_ms ?? 0;
  if (segment.max_ms - uncertainty >= topology.stall_ms) return "degraded";
  return segment.max_ms + uncertainty < topology.stall_ms ? "clean" : "unknown";
}
export function segmentRefs(report: Report, segment: Segment) {
  const finding = report.findings
    .filter((f) => f.hop === segment.id)
    .flatMap((f) => f.evidence);
  const quality = report.quality
    .filter((q) => q.point === segment.point_a || q.point === segment.point_b)
    .flatMap((q) => q.evidence);
  const samples = (report.incident?.quality || [])
    .filter(
      (r) =>
        r.point_a === segment.point_a &&
        r.point_b === segment.point_b &&
        r.direction === segment.direction,
    )
    .flatMap((r) => r.evidence);
  const clocks = Object.values(report.clocks).flatMap((c) => c.evidence);
  return finding.length ? finding : quality.length ? quality : clocks;
}
export function boundaryTitle(hop: string, topology: Topology) {
  const [, a, b] = hop.split(":");
  const label = (id: string) =>
    topology.points.find((p) => p.id === id)?.label || id;
  return `${label(a)} → ${label(b)}`;
}
export function groupHolds(findings: IncidentReport["hold_release"]) {
  const groups = new Map<string, typeof findings>();
  for (const f of findings) {
    const key =
      f.hop +
      ":" +
      f.metrics.wire_spacing_ms.map((v) => Math.round(v)).join(",") +
      ":" +
      f.metrics.receive_spacing_ms.map((v) => Math.round(v)).join(",");
    groups.set(key, [...(groups.get(key) || []), f]);
  }
  return [...groups.values()];
}
