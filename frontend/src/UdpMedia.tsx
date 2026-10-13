import { num } from "./api";
import type { Ref } from "./types";
export type UdpReport = {
  note: string;
  scope: string;
  total: number;
  summary: {
    point: string;
    protocol: string;
    endpoint: string;
    requests: number;
    answered: number;
    unanswered: number;
    unknown: number;
    no_response_expected: number;
    p50_ms: number | null;
    p95_ms: number | null;
    max_ms: number | null;
  }[];
  items: {
    point: string;
    frame: number;
    protocol: string;
    status: string;
    latency_ms: number | null;
    hop: string | null;
    reason: string;
    tooltip: string;
    evidence: Ref[];
  }[];
};
export type RtpReport = { note: string; scope: string; streams: { point: string; flow: string; direction: string; ssrc: number; packets: number; gaps: number; duplicates: number; reordered: number; jitter_p95_ms: number | null; jitter_max_ms: number | null; evidence: Ref[] }[]; one_way: { point: string; seen_direction: string; reason: string; stopping_hop: string | null; evidence: Ref[] }[] };
export type SipReport = { note: string; scope: string; total: number; comparisons: { call_id: string; hop: string; status: string; reason: string; media_status?: string; changes: Record<string, {before: unknown; after: unknown}>; evidence: Ref[]; tooltip: string }[]; one_way: {call_id: string; hop: string; reason: string; evidence: Ref[]; tooltip: string}[] };
export function UdpMedia({
  udp,
  rtp,
  sip,
  onEvidence,
}: {
  udp?: UdpReport;
  rtp?: RtpReport;
  sip?: SipReport;
  onEvidence: (refs: Ref[]) => void;
}) {
  return (
    <section>
      <h2>SIP / SDP through devices</h2>
      {sip && <><p>{sip.note}</p><p className="hint">{sip.scope}; {sip.comparisons.length} of {sip.total} shown.</p>{sip.comparisons.map((c,i)=><button className="finding" key={'sip'+i} title={c.tooltip} onClick={()=>onEvidence(c.evidence)}><strong>{c.call_id} · {c.hop}: {c.status}</strong><span>{c.reason} · media: {c.media_status||'not evaluated'}</span>{Object.entries(c.changes).map(([field,v])=><small key={field}>{field}: {String(v.before)} → {String(v.after)}</small>)}</button>)}{sip.one_way.map((c,i)=><button className="finding" key={'audio'+i} title={c.tooltip} onClick={()=>onEvidence(c.evidence)}>{c.call_id}: one-way audio · {c.hop} · {c.reason}</button>)}</>}
      <h2>RTP streams</h2>
      {rtp && <><p>{rtp.note}</p><p className="hint">{rtp.scope}</p>{rtp.streams.map((r,i)=><button className="finding" key={i} title={rtp.note} onClick={()=>onEvidence(r.evidence)}><strong>{r.point} · {r.direction} · SSRC {r.ssrc} · flow {r.flow}</strong><span>{r.packets} packets; gaps {r.gaps}; duplicates {r.duplicates}; reordered {r.reordered}; jitter p95/max {num(r.jitter_p95_ms)}/{num(r.jitter_max_ms)} ms</span></button>)}{rtp.one_way.map((r,i)=><button className="finding" key={'one'+i} onClick={()=>onEvidence(r.evidence)}>{r.point}: only {r.seen_direction} observed; {r.reason}; {r.stopping_hop||'stopping hop unknown'}</button>)}</>}
      <h2>UDP transactions</h2>
      {!udp ? (
        <p>Run analysis first.</p>
      ) : (
        <>
          <p>{udp.note}</p>
          <p className="hint">
            {udp.scope}. {udp.items.length} of {udp.total} examples shown. DNS
            has its own view.
          </p>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Point / protocol / peer</th>
                  <th>Answered / unanswered</th>
                  <th>No response expected / unknown</th>
                  <th>p50 / p95 / max ms</th>
                </tr>
              </thead>
              <tbody>
                {udp.summary.map((s, i) => (
                  <tr key={i}>
                    <td>
                      {s.point} · {s.protocol} · {s.endpoint}
                    </td>
                    <td>
                      {s.answered} / {s.unanswered}
                    </td>
                    <td>
                      {s.no_response_expected} / {s.unknown}
                    </td>
                    <td>
                      {num(s.p50_ms)} / {num(s.p95_ms)} / {num(s.max_ms)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {udp.items.map((r, i) => (
            <button
              className="finding"
              key={i}
              title={r.tooltip}
              onClick={() => onEvidence(r.evidence)}
            >
              <strong>
                {r.point}: {r.protocol} · {r.status} ·{" "}
                {num(r.latency_ms, " ms")}
              </strong>
              <span>
                {r.hop || "No supported disappearance hop"} — {r.reason}
              </span>
            </button>
          ))}
        </>
      )}
    </section>
  );
}
