import {useState} from "react";
import {api} from "./api";
import type {Report} from "./types";
type Result = {
  items?: {
    id: string;
    description: string;
    metric: string;
    expected: unknown;
    value: unknown;
    status: string;
    reason?: string;
  }[];
  counts?: unknown;
  diff?: {
    metrics: unknown[];
    findings: unknown[];
    metric_difference_count: number;
    truncated: boolean;
    note: string;
  };
};
export function ReferenceCompare({ report }: { report: Report | null }) {
  const [reference, setReference] = useState<unknown>(null),
    [run, setRun] = useState<unknown>(null),
    [result, setResult] = useState<Result | null>(null),
    [error, setError] = useState("");
  async function load(file: File | undefined, save: (x: unknown) => void) {
    if (!file) return;
    try {
      if (file.size > 64 * 1024 * 1024) throw Error("JSON file exceeds 64 MiB");
      save(JSON.parse(await file.text()));
      setResult(null);
      setError("");
    } catch (e) {
      setError(String(e));
    }
  }
  async function compare() {
    try {
      setResult(
        await api<Result>("/compare", "POST", { reference, against: run }),
      );
      setError("");
    } catch (e) {
      setError(String(e));
    }
  }
  if (!report) return null;
  return (
    <section>
      <h2>Reference and run comparison</h2>
      <p>
        Local comparison of the saved report. Missing or null metrics are
        not-computed. Generated timestamps and frame IDs are ignored in run
        diffs; changed analysis values are retained.
      </p>
      <p>
        <a href="/api/reference/template">Export reference template</a>
      </p>
      <label>
        Reference JSON{" "}
        <input
          type="file"
          accept=".json"
          onChange={(e) => load(e.target.files?.[0], setReference)}
        />
      </label>
      <label>
        Previous analysis JSON export{" "}
        <input
          type="file"
          accept=".json"
          onChange={(e) => load(e.target.files?.[0], setRun)}
        />
      </label>
      <button disabled={!reference && !run} onClick={compare}>
        Compare with current saved report
      </button>
      {error && <p role="alert">{error}</p>}
      {result?.items && (
        <>
          <pre>{JSON.stringify(result.counts)}</pre>
          <table>
            <thead>
              <tr>
                <th>Item / metric</th>
                <th>Product value</th>
                <th>Expected</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {result.items.map((r) => (
                <tr key={r.id} title={r.reason}>
                  <td>
                    {r.description}
                    <small>{r.metric}</small>
                  </td>
                  <td>{JSON.stringify(r.value)}</td>
                  <td>{JSON.stringify(r.expected)}</td>
                  <td>
                    <strong>{r.status}</strong>
                    {r.reason && <small>{r.reason}</small>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {result?.diff && (
        <>
          <p>
            {result.diff.metric_difference_count} metric differences
            {result.diff.truncated ? " (first 1,000 displayed)" : ""}.{" "}
            {result.diff.note}
          </p>
          <details open>
            <summary>Differing findings</summary>
            <pre>{JSON.stringify(result.diff.findings, null, 2)}</pre>
          </details>
          <details>
            <summary>Differing metrics</summary>
            <pre>{JSON.stringify(result.diff.metrics, null, 2)}</pre>
          </details>
        </>
      )}
    </section>
  );
}
