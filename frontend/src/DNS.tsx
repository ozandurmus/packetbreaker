import {useEffect,useState} from "react";
import {api,num,time} from "./api";
import type {Ref} from "./types";
type Result = {
  items: {
    point: string;
    frame: number;
    question: string | null;
    resolver: string;
    status: string;
    reason: string;
    tooltip: string;
    latency_ms: number | null;
    location?: string;
    evidence: Ref[];
    corrected: number | null;
  }[];
  total: number;
  summary: {
    point: string;
    resolver: string;
    queries: number;
    matchable_queries: number;
    answered: number;
    timed_out_queries: number;
    unknown_queries: number;
    p50_ms: number | null;
    p95_ms: number | null;
    max_ms: number | null;
  }[];
  points: { point: string; label: string; kind: string }[];
  timeout_ms?: number;
  tooltip: string;
  note?: string;
  reason: string | null;
};
export function DNS({
  rangeQuery,
  onEvidence,
}: {
  rangeQuery: string;
  onEvidence: (refs: Ref[]) => void;
}) {
  const [initialized, setInitialized] = useState(false);
  const [result, setResult] = useState<Result | null>(null),
    [point, setPoint] = useState(""),
    [resolver, setResolver] = useState(""),
    [offset, setOffset] = useState(0),
    [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    setError("");
    api<Result>(
      `/dns?offset=${offset}&point=${encodeURIComponent(point)}&resolver=${encodeURIComponent(resolver)}${rangeQuery}`.replace(
        /&(?:point|resolver)=(?=&|$)/g,
        "",
      ),
    )
      .then((r) => {
        if (active) {
          setResult(r);
          if (
            !initialized &&
            !point &&
            r.points.some((p) => p.kind === "Client")
          )
            setPoint(r.points.find((p) => p.kind === "Client")!.point);
          setInitialized(true);
        }
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, [point, resolver, offset, rangeQuery]);
  useEffect(() => setOffset(0), [point, resolver, rangeQuery]);
  return (
    <section>
      <h2>DNS: resolver or return path?</h2>
      <p className="hint" title={result?.tooltip}>
        Same-point query → response turnaround; timeout{" "}
        {num(result?.timeout_ms, " ms")}. A timeout is not proof of a resolver
        fault.
      </p>
      {error && <p role="alert">{error}</p>}
      {result?.reason && <p>{result.reason}</p>}
      <label>
        Observation point
        <select
          aria-label="DNS observation point"
          value={point}
          onChange={(e) => setPoint(e.target.value)}
        >
          <option value="">All points (separate populations)</option>
          {result?.points.map((p) => (
            <option value={p.point} key={p.point}>
              {p.label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Resolver IP
        <input
          aria-label="DNS resolver filter"
          value={resolver}
          onChange={(e) => setResolver(e.target.value)}
          placeholder="All resolvers"
        />
      </label>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Point / resolver</th>
              <th>Queries / matchable</th>
              <th>Answered / timed out / unknown</th>
              <th>p50 / p95 / max (ms)</th>
            </tr>
          </thead>
          <tbody>
            {result?.summary.map((s, i) => (
              <tr key={i} title={result.tooltip}>
                <td>
                  {s.point} / {s.resolver}
                </td>
                <td>
                  {s.queries}/{s.matchable_queries}
                </td>
                <td>
                  {s.answered}/{s.timed_out_queries}/{s.unknown_queries}
                </td>
                <td>
                  {num(s.p50_ms)}/{num(s.p95_ms)}/{num(s.max_ms)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {result?.items.map((q, i) => (
        <button
          className="finding"
          key={i}
          title={q.tooltip}
          onClick={() => onEvidence(q.evidence)}
        >
          <strong>
            {q.question || "unknown question"} · {q.resolver} ·{" "}
            {q.status.replaceAll("_", " ")}
          </strong>
          <span>{q.reason}</span>
          <span>
            {q.location || q.point} · {time(q.corrected)} ·{" "}
            {num(q.latency_ms, " ms")}
          </span>
        </button>
      ))}
      <div className="pagination">
        <span>
          {result?.total || 0} indexed queries; same transaction can appear at
          several capture points.
        </span>
        <button
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - 100))}
        >
          Previous
        </button>
        <button
          disabled={!result || offset + 100 >= result.total}
          onClick={() => setOffset(offset + 100)}
        >
          Next
        </button>
      </div>
      <p className="hint">{result?.note}</p>
    </section>
  );
}
