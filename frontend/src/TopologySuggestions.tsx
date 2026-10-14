import { useState } from "react";
import { api } from "./api";
import { Badge } from "./UI";
import type { Topology, Capture, Ref, SuggestedTopology } from "./types";
type Suggestion = {
  kind: string;
  capture_ids: string[];
  reason: string;
  metrics: unknown;
  evidence: Ref[];
  warning?: string;
};
export function SuggestedTopologyBanner({
  suggested,
  captures,
  onConfirm,
  onEvidence,
}: {
  suggested?: SuggestedTopology | null;
  captures: Capture[];
  onConfirm: () => void;
  onEvidence: (e: Ref[]) => void;
}) {
  if (!suggested) return null;
  if (suggested.ambiguous) {
    return (
      <section role="alert">
        <Badge kind="bad">Suggested topology ambiguous — manual input required</Badge>
        <p>{suggested.reason}</p>
        {suggested.warnings?.map((w, idx) => (
          <p key={idx} className="hint">
            {w}
          </p>
        ))}
      </section>
    );
  }
  return (
    <section>
      <div className="section-head">
        <Badge kind={suggested.confirmed ? "good" : "warn"}>
          {suggested.confirmed
            ? "Suggested topology — confirmed"
            : suggested.badge || "Suggested topology — review & confirm"}
        </Badge>
        {!suggested.confirmed && (
          <button onClick={onConfirm}>Confirm suggested topology</button>
        )}
      </div>
      {captures.length > 0 && (
        <p className="hint">
          Case summary (pre-filter excluded per file):{" "}
          {captures
            .map(
              (c) =>
                `${c.name}: ${c.inventory?.prefilter_excluded ?? 0} excluded`,
            )
            .join(" · ")}
        </p>
      )}
      {suggested.warnings?.map((w, idx) => (
        <p key={idx} role="status">
          {w}
        </p>
      ))}
      <details open={!suggested.confirmed}>
        <summary>
          Inferred topology roles, client direction and path order (
          {suggested.inferences.length})
        </summary>
        {suggested.inferences.map((inf, idx) => (
          <article key={idx}>
            <strong>
              {inf.kind.replaceAll("_", " ")}:{" "}
              {inf.capture_ids
                .map((id) => captures.find((c) => c.id === id)?.name || id)
                .join(" → ")}
            </strong>
            <p>{inf.reason}</p>
            {inf.warning && <p>{inf.warning}</p>}
            {inf.evidence?.length ? (
              <button
                className="secondary"
                onClick={() => onEvidence(inf.evidence)}
              >
                Evidence frames
              </button>
            ) : null}
          </article>
        ))}
      </details>
    </section>
  );
}
export function TopologySuggestions({
  topology,
  captures,
  suggested,
  onAssemble,
  onConfirmSuggested,
  onChange,
  onEvidence,
}: {
  topology: Topology;
  captures: Capture[];
  suggested?: SuggestedTopology | null;
  onAssemble?: () => void;
  onConfirmSuggested?: () => void;
  onChange: (t: Topology) => void;
  onEvidence: (e: Ref[]) => void;
}) {
  const [items, setItems] = useState<Suggestion[]>([]),
    [warnings, setWarnings] = useState<string[]>([]),
    [message, setMessage] = useState("");
  async function detect() {
    try {
      const r = await api<{ items: Suggestion[]; warnings?: string[] }>(
        "/topology/suggest",
      );
      setItems(r.items);
      setWarnings(r.warnings || []);
      setMessage(
        r.items.length
          ? "Review each suggestion. Confirm changes only the editor; Save topology to apply."
          : "Insufficient unique bidirectional packet evidence.",
      );
    } catch (e) {
      setMessage(String(e));
    }
  }
  function confirm(s: Suggestion) {
    const points = topology.points.map((p) => ({ ...p }));
    const selected = points.filter((p) => s.capture_ids.includes(p.capture_id));
    if (!selected.length) {
      setMessage("Assign these files to capture points first.");
      return;
    }
    const domains = new Set(
      selected.map((p) => p.clock_domain).filter(Boolean),
    );
    const domain =
        [...domains].sort()[0] || "suggested-" + s.capture_ids[0].slice(0, 8),
      device =
        selected.find((p) => p.capture_id === s.capture_ids[0])?.device ||
        selected[0].device;
    for (const p of points.filter(
      (p) =>
        selected.includes(p) ||
        (s.kind === "shared_clock" && domains.has(p.clock_domain)),
    )) {
      if (s.kind === "host_capture") {
        p.host_capture = true;
        p.kind = "Server";
      } else if (s.kind === "shared_clock") {
        p.clock_domain = domain;
      } else {
        p.stage_capture = true;
        p.device = device;
        p.side = p.capture_id === s.capture_ids[0] ? "ingress" : "egress";
      }
    }
    onChange({ ...topology, points });
    setItems(items.filter((i) => i !== s));
    setMessage("Confirmed in editor. Review and Save topology.");
  }
  return (
    <section>
      <h2>Suggested capture roles and clocks</h2>
      <div className="actions">
        <button onClick={detect}>Suggest from packet evidence</button>
        {onAssemble && (
          <button onClick={onAssemble}>Analyze with suggested topology</button>
        )}
      </div>
      {onConfirmSuggested && (
        <SuggestedTopologyBanner
          suggested={suggested}
          captures={captures}
          onConfirm={onConfirmSuggested}
          onEvidence={onEvidence}
        />
      )}
      {warnings.map((w, i) => (
        <p key={i} role="status">
          {w}
        </p>
      ))}
      <p>{message}</p>
      {items.map((s, i) => (
        <article key={i}>
          <strong>
            {s.kind.replaceAll("_", " ")}:{" "}
            {s.capture_ids
              .map((id) => captures.find((c) => c.id === id)?.name || id)
              .join(" → ")}
          </strong>
          <p>{s.reason}</p>
          {s.warning && <p>{s.warning}</p>}
          <details>
            <summary>Measured evidence</summary>
            <pre>{JSON.stringify(s.metrics, null, 2)}</pre>
          </details>
          <button onClick={() => confirm(s)}>Apply in topology editor</button>
          <button onClick={() => setItems(items.filter((x) => x !== s))}>
            Dismiss
          </button>
          <button onClick={() => onEvidence(s.evidence)}>
            Evidence frames
          </button>
        </article>
      ))}
    </section>
  );
}
