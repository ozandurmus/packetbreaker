import type { Report, Ref } from "./types";
import { num } from "./api";

export function ProxyEvidence({
  report,
  onEvidence,
}: {
  report: Report;
  onEvidence: (refs: Ref[]) => void;
}) {
  const proxies = report.proxies;
  return (
    <>
      {!!proxies?.transactions.length && (
        <section>
          <h2>Full-proxy requests and independent TCP legs</h2>
          <p className="hint">{proxies.note}</p>
          <p>
            {proxies.transaction_count} pairing records.{" "}
            {proxies.transaction_count > proxies.transactions.length &&
              "Overview shows the first 200; all pairings are stored locally."}
          </p>
          {proxies.transactions.map((p, i) => (
            <button
              className={`finding ${p.status === "unknown" ? "onset-symptom" : ""}`}
              key={i}
              onClick={() => onEvidence(p.evidence)}
              title={
                p.reason ||
                "One-to-one request evidence; timing only breaks bounded ties"
              }
            >
              <strong>
                {p.device} · {p.request || p.kind}
              </strong>
              <span>
                {p.status === "matched"
                  ? `Request paired (${p.kind === "tls_setup" ? "TLS setup only" : "HTTP/1.x"})`
                  : `unknown: ${p.reason}`}
              </span>
              {p.kind === "http" && p.status === "matched" && (
                <span>
                  Request dwell{" "}
                  {num(p.request_dwell?.duration_ms ?? null, " ms")} ±
                  {num(p.request_dwell?.uncertainty_ms ?? null, " ms")}
                  {p.request_dwell?.reason && ` · ${p.request_dwell.reason}`}
                  <br />
                  Response dwell{" "}
                  {num(p.response_dwell?.duration_ms ?? null, " ms")} ±
                  {num(p.response_dwell?.uncertainty_ms ?? null, " ms")}
                  {p.response_dwell?.reason && ` · ${p.response_dwell.reason}`}
                </span>
              )}
              <small>
                Client leg {p.client_flow || "unknown"} / backend leg{" "}
                {p.server_flow || "unknown"}. Click for evidence frames and
                filters.
              </small>
            </button>
          ))}
          <details>
            <summary>Per-point leg classification</summary>
            <table>
              <thead>
                <tr>
                  <th>Point / TCP leg</th>
                  <th>Loss classes</th>
                  <th>Retransmissions</th>
                  <th>Resets</th>
                </tr>
              </thead>
              <tbody>
                {proxies.legs?.map((l, i) => (
                  <tr key={i}>
                    <td>
                      {l.point}
                      <br />
                      <small>{l.flow}</small>
                    </td>
                    <td>
                      {Object.entries(l.loss_by_class)
                        .map(([k, v]) => `${k}: ${v}`)
                        .join(", ") || "None classified; see segment coverage"}
                    </td>
                    <td>{l.retransmissions}</td>
                    <td>{l.resets}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
          {proxies.reset_notes?.map((n, i) => (
            <button
              className="finding onset-symptom"
              key={`reset-${i}`}
              onClick={() => onEvidence(n.evidence)}
            >
              {n.device} · reset origin unknown: {n.reason}
            </button>
          ))}
        </section>
      )}
      {!!report.tls?.length && (
        <section>
          <h2>TLS interception evidence</h2>
          <p className="hint">
            Compared per visible handshake. An absent or encrypted chain remains
            unknown.
          </p>
          {report.tls.map((n, i) => (
            <button
              className="finding onset-symptom"
              key={i}
              onClick={() => onEvidence(n.evidence)}
              title={n.reason}
            >
              {n.device || n.point} · {n.sni} · {n.status}: {n.reason}
            </button>
          ))}
        </section>
      )}
    </>
  );
}
