import { useWorkspace } from "./WorkspaceContext";
import { num } from "./api";
export function CaptureQualityCards() {
  const { report, topology, setTab, setEvidence } = useWorkspace();
  if (!report) return null;
  return (
    <section>
      <div className="section-head">
        <h2>Capture quality comes first</h2>
        <button className="text-button" onClick={() => setTab("Captures")}>
          Inspect all captures →
        </button>
      </div>
      <div className="quality-grid">
        {report.quality.map((q) => (
          <button
            key={q.point}
            className="quality-card"
            onClick={() => setEvidence(q.evidence)}
          >
            <strong>
              {topology.points.find((p) => p.id === q.point)?.label || q.point}
            </strong>
            <span title="Capture-reported interface and OS drops. Unknown is not zero.">
              Drops: {num(q.ifdrop, "", 0)} / {num(q.osdrop, "", 0)}
            </span>
            {q.index_scope && (
              <span title="Before per-point application/TCP indexing: shared flows or explicit client CIDRs; declared proxy/vendor evidence retained.">
                {q.index_scope.excluded_flows} flows /{" "}
                {q.index_scope.excluded_frames} frames outside indexing scope
              </span>
            )}
            <span title="Frames excluded because their fingerprint repeats, conflicts, or is unsupported.">
              {num(q.excluded, " excluded", 0)}
            </span>
            {q.prefilter_excluded !== undefined && (
              <span title="Frames excluded at ingest by the >5x shared IP-pair pre-filter.">
                {num(q.prefilter_excluded, " pre-filter excluded", 0)}
              </span>
            )}
            <span title="Captured length is smaller than wire length; only common payload prefixes are compared.">
              {num(q.truncated, " truncated", 0)}
            </span>
            <span title="Payloads above 1500 bytes may be jumbo frames or offload artifacts, not proof of an error.">
              {num(q.possible_offload, " large frames", 0)}
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}
