import { useState } from "react";
import { api } from "./api";
import type { Topology, Capture, Ref } from "./types";
type Suggestion = {
  kind: string;
  capture_ids: string[];
  reason: string;
  metrics: unknown;
  evidence: Ref[];
};
export function TopologySuggestions({
  topology,
  captures,
  onChange,
  onEvidence,
}: {
  topology: Topology;
  captures: Capture[];
  onChange: (t: Topology) => void;
  onEvidence: (e: Ref[]) => void;
}) {
  const [items, setItems] = useState<Suggestion[]>([]),
    [message, setMessage] = useState("");
  async function detect() {
    try {
      const r = await api<{ items: Suggestion[] }>("/topology/suggest");
      setItems(r.items);
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
      <button onClick={detect}>Suggest from packet evidence</button>
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
