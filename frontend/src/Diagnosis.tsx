import {useEffect,useState} from "react";
import {api,num} from "./api";
import type {Ref} from "./types";

type Diagnosis = {
  flow: string;
  direction: string;
  classification: string;
  reason: string;
  tooltip: string;
  evidence: Ref[];
  metrics: {
    max_receive_window: number | null;
    max_bytes_in_flight: number | null;
    zero_windows: number;
    window_full: number;
    window_shrinks: number;
    ack_delay_p95_ms: number | null;
    path_p95_ms: number | null;
    service_ms: number | null;
    loss_count: number;
  };
};
type RetryPoint = {
  flow: string;
  point: string;
  direction: string;
  tooltip: string;
  reason: string | null;
  rto: number | null;
  fast: number | null;
  spurious: number | null;
  sack: number | null;
  unknown: number | null;
  duplicate_acks: number | null;
};
export function Diagnosis({
  flow,
  onEvidence,
}: {
  flow: string;
  onEvidence: (refs: Ref[]) => void;
}) {
  const [result, setResult] = useState<{
    items: Diagnosis[];
    reason: string | null;
    note?: string;
    retransmissions?: {
      points: RetryPoint[];
      segments: (RetryPoint & { hop: string })[];
      events: {
        reason: string;
        retry_kind: string;
        point: string;
        evidence: Ref[];
      }[];
      reordering: {
        location: string;
        hop: string;
        tooltip: string;
        reason: string;
        evidence: Ref[];
      }[];
      note: string;
    };
  } | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    setResult(null);
    setError("");
    api<typeof result>(`/flows/${flow}/diagnosis`)
      .then((r) => {
        if (active) setResult(r);
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, [flow]);
  return (
    <section>
      <h2>Network or application?</h2>
      <p className="hint">
        Per TCP leg and data direction. A hypothesis needs independent evidence;
        one counter is not a cause.
      </p>
      {error && <p role="alert">{error}</p>}
      {!result && !error && <p>Preparing local evidence…</p>}
      {result?.reason && <p>{result.reason}</p>}
      {result?.items.map((d, i) => (
        <article key={i} title={d.tooltip}>
          <h3>
            {d.direction} · {d.classification}
          </h3>
          <p>{d.reason}</p>
          <p>
            Scaled window (max): {num(d.metrics.max_receive_window, " B")} ·
            flight (max): {num(d.metrics.max_bytes_in_flight, " B")} ·
            zero/full/shrink: {d.metrics.zero_windows}/{d.metrics.window_full}/
            {d.metrics.window_shrinks}
          </p>
          <p title="ACK delay is measured locally at the receiving endpoint. Path p95 uses corrected matched-packet times and retains clock uncertainty. Service time is last request byte to first response byte at the server.">
            Receiver ACK p95: {num(d.metrics.ack_delay_p95_ms, " ms")} · path
            p95: {num(d.metrics.path_p95_ms, " ms")} · visible server service:{" "}
            {num(d.metrics.service_ms, " ms")} · supported loss events:{" "}
            {d.metrics.loss_count}
          </p>
          <button
            disabled={!d.evidence.length}
            onClick={() => onEvidence(d.evidence)}
          >
            Open diagnosis evidence
          </button>
        </article>
      ))}
      <p className="hint">{result?.note}</p>
      {result?.retransmissions && (
        <>
          <h3>Retransmission breakdown (data direction)</h3>
          <p className="hint">{result.retransmissions.note}</p>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Point</th>
                  <th>Direction</th>
                  <th>RTO-compatible</th>
                  <th>Fast</th>
                  <th>Spurious</th>
                  <th>SACK-driven</th>
                  <th>Unknown</th>
                  <th>Duplicate ACKs</th>
                </tr>
              </thead>
              <tbody>
                {result.retransmissions.points.map((p, i) => (
                  <tr key={i} title={p.reason || p.tooltip}>
                    <td>{p.point}</td>
                    <td>{p.direction}</td>
                    <td>{num(p.rto)}</td>
                    <td>{num(p.fast)}</td>
                    <td>{num(p.spurious)}</td>
                    <td>{num(p.sack)}</td>
                    <td>{num(p.unknown)}</td>
                    <td>{num(p.duplicate_acks)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <details>
            <summary>Counts by hop segment</summary>
            <pre>
              {JSON.stringify(result.retransmissions.segments, null, 2)}
            </pre>
          </details>
          {result.retransmissions.events.map((e, i) => (
            <button
              key={i}
              className="finding"
              title={e.reason}
              onClick={() => onEvidence(e.evidence)}
            >
              {e.point} · {e.retry_kind}: {e.reason}
            </button>
          ))}
          <h3>First observed reordering hop</h3>
          {!result.retransmissions.reordering.length && (
            <p className="hint">
              No supported cross-hop arrival-order reversal. Missing/unreliable
              point evidence cannot prove absence of reordering.
            </p>
          )}
          {result.retransmissions.reordering.map((r, i) => (
            <button
              key={i}
              className="finding"
              title={r.tooltip}
              onClick={() => onEvidence(r.evidence)}
            >
              {r.location} · {r.hop}: {r.reason}
            </button>
          ))}
        </>
      )}
    </section>
  );
}
