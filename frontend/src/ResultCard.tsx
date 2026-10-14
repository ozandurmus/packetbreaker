import { useWorkspace } from "./WorkspaceContext";
import {
  boundaryTitle,
  isChronicLoss,
  segmentHealth,
  segmentRefs,
} from "./overviewModel";
import { num, time } from "./api";
import type { Ref } from "./types";
export function ResultCard() {
  const { report, topology, setEvidence } = useWorkspace();
  if (!report) return null;
  const host = report.host_path,
    items = host?.items || [],
    primary = [...items].sort(
      (a, b) => b.max_ms - b.uncertainty_ms - (a.max_ms - a.uncertainty_ms),
    )[0];
  const window = report.incident?.window;
  const rx = items.find((i) => i.direction === "rx"),
    tx = items.find((i) => i.direction === "tx");
  const evidence = primary?.evidence || report.findings[0]?.evidence || [];
  const local = host?.local_service.cycle_aggregate;
  const hostPoints = new Set(
    topology.points.filter((p) => p.host_capture).map((p) => p.id),
  );
  const localRefs = (report.cycles?.top || [])
    .filter((r) => hostPoints.has(r.point))
    .flatMap((r) => r.evidence || []);
  const clockRefs = Object.values(report.clocks).flatMap((c) => c.evidence);
  const clockUnknown = Object.values(report.clocks).some(
    (c) => c.offset == null || c.uncertainty == null,
  );
  const uncertainty = Math.max(...items.map((i) => i.uncertainty_ms), 0);
  const peak = (key: string, fallback?: number) => {
    const values = (report.incident?.timeline || [])
      .map((r) => r[key])
      .filter((n): n is number => typeof n === "number" && Number.isFinite(n));
    return values.length ? Math.max(...values) : fallback;
  };
  const losses = (direction: "forward" | "reverse") => {
    const segments = report.segments.filter(
      (s) =>
        s.direction === direction &&
        topology.points.some(
          (p) => p.host_capture && (p.id === s.point_a || p.id === s.point_b),
        ),
    );
    if (
      !segments.length ||
      segments.some((s) => s.reason || s.loss_percent == null)
    )
      return null;
    return (report.incident?.loss_groups || [])
      .filter((g) => g.hop.startsWith(direction + ":"))
      .reduce(
        (n, g) => n + Object.values(g.counts).reduce((a, b) => a + b, 0),
        0,
      );
  };
  const clean = report.segments.filter(
    (s) => segmentHealth(s, topology, report) === "clean",
  );
  const unknown = report.segments.filter(
    (s) => segmentHealth(s, topology, report) === "unknown",
  );
  const groups = new Map<string, typeof clean>();
  for (const segment of clean) {
    const a =
        topology.points.find((p) => p.id === segment.point_a)?.device ||
        segment.point_a,
      b =
        topology.points.find((p) => p.id === segment.point_b)?.device ||
        segment.point_b;
    const key = a === b ? a : [a, b].sort().join(" ↔ ");
    groups.set(key, [...(groups.get(key) || []), segment]);
  }
  function line(label: string, value: string, refs: Ref[], hint: string) {
    return (
      <div className="result-line">
        <strong>{label}</strong>
        <span title={hint}>{value}</span>
        <button className="text-button" onClick={() => setEvidence(refs)}>
          Evidence ↗
        </button>
      </div>
    );
  }
  return (
    <section id="overview-summary" className="result-card">
      <div className="section-head">
        <h2>Investigation result</h2>
        <small>Full saved analysis · evidence-led localisation</small>
      </div>
      {line(
        "Where",
        primary
          ? `Delay is added between ${boundaryTitle(primary.hop, topology).replace(" → ", " and ")}`
          : report.findings[0]
            ? `Observed finding at ${boundaryTitle(report.findings[0].hop, topology)}`
            : "No supported degradation localisation",
        evidence,
        "Localisation identifies capture boundaries; it does not prove a driver, device or application cause.",
      )}
      {line(
        "When",
        window
          ? `${new Date(window.start * 1000).toLocaleString()} — ${new Date(window.end * 1000).toLocaleTimeString()} local`
          : `Onset unknown: ${host?.window_reason || primary?.window.reason || "no supported event window"}`,
        evidence,
        window
          ? `${time(window.start)} — ${time(window.end)} UTC; clock and bucket uncertainty applies.`
          : "Observed delay can remain supported while onset is unknown.",
      )}
      {line(
        "How much",
        `RX max ${num(peak("rx_max_ms", rx?.max_ms))} ms · TX max ${num(peak("tx_max_ms", tx?.max_ms))} ms · ${num(report.cycles?.stalled_total, "", 0)} stalled cycles · TX/RX loss ${num(losses("reverse"), "", 0)}/${num(losses("forward"), "", 0)}`,
        evidence,
        "Same-copy transit maxima. Stalled cycles use the configured cycle threshold; host TX/RX loss can include network and recovery wait. Full-window counts.",
      )}
      <div className="result-line">
        <strong>Not the cause</strong>
        <span title="Clean means p95 <1 ms, max <10 ms and supported loss <0.1%, without impactful loss in the event window; usable clocks/coverage required. It does not rule out an unobserved fault.">
          {groups.size
            ? [...groups.entries()].map(([label, segments]) => {
                const chronic = segments.some((s) => isChronicLoss(s, report));
                const maxMs = num(Math.max(...segments.map((s) => s.max_ms!)));
                const maxLoss = Math.max(
                  ...segments.map((s) => s.loss_percent!),
                );
                return (
                  <button
                    className="clean-chip"
                    key={label}
                    onClick={() =>
                      setEvidence(
                        segments.flatMap((s) => segmentRefs(report, s)),
                      )
                    }
                  >
                    {chronic
                      ? `${label}: ${maxMs} ms · transit clean; chronic loss ${maxLoss.toFixed(3)}%`
                      : `${label}: ${maxMs} ms · ${num(maxLoss)}% loss · clean observed`}
                  </button>
                );
              })
            : "No segment can be marked clean from the available evidence."}
          {unknown.length > 0 && (
            <small>{unknown.length} segment(s) remain unknown; see Path.</small>
          )}
        </span>
        <button
          className="text-button"
          onClick={() =>
            setEvidence(report.segments.flatMap((s) => segmentRefs(report, s)))
          }
        >
          Evidence ↗
        </button>
      </div>
      {line(
        "Server-local p95",
        `${num(local?.p95_ms ?? host?.local_service.p95_ms)} ms`,
        localRefs,
        "All measured host cycles. Opaque data turnaround is not a decoded application service boundary; clock offset cancels locally.",
      )}
      {line(
        "Clock confidence",
        clockUnknown
          ? "Unknown for part of the path"
          : `Shared/reference clocks · host ${
              topology.points
                .filter((p) => p.host_capture)
                .map(
                  (p) =>
                    report.clocks[p.capture_id]?.confidence.replaceAll(
                      "_",
                      " ",
                    ) || "unknown",
                )
                .join(" / ") || "not declared"
            } ±${num(uncertainty)} ms`,
        clockRefs,
        "User-declared shared clock domains and fitted host offsets are distinct. Inspect the recorded models and matched frame evidence.",
      )}
    </section>
  );
}
