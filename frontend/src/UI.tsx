import React from "react";
import {time} from "./api";
import type {Ref} from "./types";
export function Tip({
  children,
  text,
}: {
  children: React.ReactNode;
  text: string;
}) {
  return (
    <span title={text} tabIndex={0} className="tip">
      {children}
      <sup>ⓘ</sup>
    </span>
  );
}
export function Badge({
  children,
  kind = "neutral",
}: {
  children: React.ReactNode;
  kind?: string;
}) {
  return <span className={"badge " + kind}>{children}</span>;
}
export function Evidence({
  refs,
  onClose,
}: {
  refs: Ref[];
  onClose: () => void;
}) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section
        className="evidence-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Frame evidence"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="section-head">
          <div>
            <span className="eyebrow">Verify in Wireshark</span>
            <h2>Frame evidence</h2>
          </div>
          <button className="secondary" onClick={onClose}>
            Close
          </button>
        </div>
        <p className="hint">
          Open the named file in Wireshark and paste its display filter. Times
          are UTC.
        </p>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Capture point / file</th>
                <th>Frame</th>
                <th>Observed</th>
                <th>Corrected</th>
                <th>Display filter</th>
              </tr>
            </thead>
            <tbody>
              {refs.map((e, i) => (
                <tr key={i}>
                  <td>
                    <strong>{e.point}</strong>
                    <small>{e.file}</small>
                  </td>
                  <td>
                    {e.frame}
                    {e.vendor && (
                      <details>
                        <summary>Vendor evidence</summary>
                        <pre>{JSON.stringify(e.vendor, null, 2)}</pre>
                      </details>
                    )}
                    {e.sequence_translation && (
                      <small>
                        {e.sequence_translation.reason
                          ? `Unknown translation: ${e.sequence_translation.reason}`
                          : `SEQ ${e.sequence_translation.observed_seq} → ${e.sequence_translation.canonical_seq}; ACK ${e.sequence_translation.observed_ack} → ${e.sequence_translation.canonical_ack}; offsets ${e.sequence_translation.seq_offset} / ${e.sequence_translation.ack_offset} (mod 2³²)`}
                      </small>
                    )}
                  </td>
                  <td>
                    {time(e.observed_time)}
                    {e.byte_ranges?.length ? (
                      <small>
                        {e.byte_ranges
                          .slice(0, 4)
                          .map(
                            (r) => `${r.start_seq}–${r.end_seq} (${r.bytes} B)`,
                          )
                          .join(", ")}
                        {e.byte_ranges.length > 4 ? " …" : ""}
                      </small>
                    ) : null}
                    {e.range_note && <small>{e.range_note}</small>}
                  </td>
                  <td>{time(e.corrected_time)}</td>
                  <td>
                    <code>{e.display_filter}</code>
                    <button
                      className="icon"
                      title="Copy Wireshark filter"
                      onClick={() =>
                        navigator.clipboard.writeText(e.display_filter)
                      }
                    >
                      Copy
                    </button>
                    {e.content_filter && (
                      <details>
                        <summary>Packet content filter</summary>
                        <code>{e.content_filter}</code>
                        <button
                          className="icon"
                          title="Copy content filter"
                          onClick={() =>
                            navigator.clipboard.writeText(e.content_filter!)
                          }
                        >
                          Copy
                        </button>
                        <p className="hint">{e.filter_note}</p>
                      </details>
                    )}
                    {e.flow_filter && (
                      <details>
                        <summary>Flow filter for this file</summary>
                        <code>{e.flow_filter}</code>
                        <button
                          className="icon"
                          title="Copy flow filter"
                          onClick={() =>
                            navigator.clipboard.writeText(e.flow_filter!)
                          }
                        >
                          Copy
                        </button>
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!refs.length && (
          <div className="empty">No frame evidence available.</div>
        )}
      </section>
    </div>
  );
}
