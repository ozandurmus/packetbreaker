import { useState } from "react";
import { api } from "./api";

export function Assistant({
  enabled,
  ready,
  project,
}: {
  enabled: boolean;
  ready: boolean;
  project: string;
}) {
  const [preview, setPreview] = useState<{
    project: string;
    value: string;
  } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <section>
      <h2>Ask an assistant</h2>
      <p className="hint">
        Local placeholder only. No assistant provider, network calls or API
        keys. Enable the placeholder in Settings to preview tokenized findings
        JSON.
      </p>
      <button
        disabled={!enabled || !ready || busy}
        onClick={async () => {
          setBusy(true);
          setError("");
          setPreview(null);
          try {
            const value = await api<unknown>("/assistant/preview");
            setPreview({ project, value: JSON.stringify(value, null, 2) });
          } catch (e) {
            setError(String(e));
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? "Preparing local preview…" : "Preview redacted findings"}
      </button>
      {!enabled && <p className="hint">Disabled (off by default).</p>}
      {enabled && !ready && (
        <p className="hint">Analyze a path before previewing findings.</p>
      )}
      {error && <p role="alert">{error}</p>}
      {enabled && preview?.project === project && (
        <>
          <p className="hint">
            Snapshot only; refresh after analysis changes. IPs and hostnames use
            consistent tokens within this preview. Other investigation metadata
            may remain sensitive. Original evidence filters are available in the
            ordinary report.
          </p>
          <pre
            className="assistant-preview"
            tabIndex={0}
            aria-label="Redacted findings JSON"
          >
            {preview.value}
          </pre>
        </>
      )}
    </section>
  );
}
