import { useState } from "react";
import { api, num, time } from "./api";
import type { Ref } from "./types";
export type SessionReport = {
  note: string;
  scope: string;
  timeout_seconds: number;
  points: {
    point: string;
    label: string;
    status: string;
    syn_sent: number | null;
    synack_seen: number | null;
    established: number | null;
    closed: number | null;
    tooltip: string;
    evidence: Ref[];
  }[];
  buckets: {
    point: string;
    start: number;
    end: number;
    coverage: string;
    syns: number | null;
    synacks: number | null;
    established: number | null;
    closed: number | null;
    half_open: number | null;
  }[];
  failed_handshake_count: number;
  failed_handshakes: {
    point_a: string;
    point_b: string;
    time: number;
    reason: string;
    evidence: Ref[];
  }[];
};
export function Sessions({
  data,
  onEvidence,
}: {
  data?: SessionReport;
  onEvidence: (refs: Ref[]) => void;
}) {
  const [point, setPoint] = useState("");
  const [error, setError] = useState("");
  if (!data) return null;
  const selected = point || data.points[0]?.point;
  return (
    <section>
      <h2>TCP lifecycle and security heuristics</h2>
      <p className="hint">{data.note}</p>
      <p>
        {data.scope}. Half-open observation timeout: {data.timeout_seconds} s.
      </p>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Point</th>
              <th>SYN sessions</th>
              <th>SYN/ACK</th>
              <th>Established</th>
              <th>FIN/RST closure</th>
            </tr>
          </thead>
          <tbody>
            {data.points.map((p) => (
              <tr key={p.point} title={p.tooltip}>
                <td>
                  <button onClick={() => onEvidence(p.evidence)}>
                    {p.label}
                  </button>{" "}
                  ({p.status})
                </td>
                <td>{num(p.syn_sent)}</td>
                <td>{num(p.synack_seen)}</td>
                <td>{num(p.established)}</td>
                <td>{num(p.closed)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {error && <p role="alert">{error}</p>}
      <details>
        <summary>Half-open occupancy over time</summary>
        <label>
          Capture point{" "}
          <select value={selected} onChange={(e) => setPoint(e.target.value)}>
            {data.points.map((p) => (
              <option key={p.point} value={p.point}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Bucket</th>
                <th>Coverage</th>
                <th>New SYN</th>
                <th>SYN/ACK</th>
                <th>Established</th>
                <th>Closed</th>
                <th>Half-open at end</th>
              </tr>
            </thead>
            <tbody>
              {data.buckets
                .filter((b) => b.point === selected)
                .map((b) => (
                  <tr key={b.start}>
                    <td>
                      <button
                        onClick={async () => {
                          try {
                            const d = await api<{ evidence: Ref[] }>(
                              `/sessions/evidence?point=${encodeURIComponent(b.point)}&start=${b.start}&end=${b.end}`,
                            );
                            setError("");
                            onEvidence(d.evidence);
                          } catch (e) {
                            setError(String(e));
                          }
                        }}
                      >
                        {time(b.start)}
                      </button>
                    </td>
                    <td>{b.coverage}</td>
                    <td>{num(b.syns)}</td>
                    <td>{num(b.synacks)}</td>
                    <td>{num(b.established)}</td>
                    <td>{num(b.closed)}</td>
                    <td>{num(b.half_open)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </details>
      <details>
        <summary>
          Supported failed handshake stopping hops (
          {data.failed_handshakes.length} of {data.failed_handshake_count}{" "}
          shown)
        </summary>
        {data.failed_handshakes.map((f, i) => (
          <p key={i}>
            <button onClick={() => onEvidence(f.evidence)}>
              {f.point_a} → {f.point_b}, {time(f.time)}
            </button>
            : {f.reason}
          </p>
        ))}
      </details>
    </section>
  );
}
