














import {api,num,time} from "./api";
import {FieldDiff} from "./FieldDiff";






import {LadderChart} from "./Charts";



import {useWorkspace} from "./WorkspaceContext";
import {Badge,Tip} from "./UI";

export function FlowDrilldown() {
  const {
    range,
    error,
    topology,
    evidence,
    setEvidence,
    filter,
    selectedFlow,
    setSelectedFlow,
    ladder,
    ladderOffset,
    setLadderOffset,
    fieldDiff,
    setFieldDiff,
  } = useWorkspace();
  return (
    <>
      {selectedFlow && ladder && (
        <section>
          <div className="section-head">
            <div>
              <span className="eyebrow">STREAM DRILL-DOWN</span>
              <h2>Multi-hop packet ladder</h2>
            </div>
            <button className="secondary" onClick={() => setSelectedFlow(null)}>
              Close
            </button>
          </div>
          <p className="hint">
            Teal: original · amber: retransmission · red ×: missing appearance.
            Click a line or row for Wireshark frame filters.
          </p>
          {ladder.local_metrics && (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Capture point / local tuple</th>
                    <th>
                      <Tip text="Observed SYN to matching SYN/ACK at this capture point. Same-clock interval; frame numbers identify the pair.">
                        SYN → SYN/ACK
                      </Tip>
                    </th>
                    <th>
                      <Tip text="Observed SYN/ACK to matching ACK at this capture point.">
                        SYN/ACK → ACK
                      </Tip>
                    </th>
                    <th>
                      <Tip text="Largest Wireshark data/ACK RTT observed at this capture point.">
                        Max RTT
                      </Tip>
                    </th>
                    <th>
                      <Tip text="Observed zero receive windows. These may indicate a receiver/application stall.">
                        Zero windows
                      </Tip>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {ladder.local_metrics.map((m) => (
                    <tr key={m.point}>
                      <td>
                        <strong>{m.point}</strong>
                        <small>{m.tuple}</small>
                      </td>
                      <td>
                        {num(m.handshake?.syn_to_synack_ms, " ms")}
                        <small>
                          {m.handshake
                            ? `Frames #${m.handshake.syn_frame} → #${m.handshake.synack_frame}`
                            : ""}
                        </small>
                      </td>
                      <td>{num(m.handshake?.synack_to_ack_ms, " ms")}</td>
                      <td>{num(m.max_rtt_ms, " ms")}</td>
                      <td>{m.zero_windows}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {ladder.flow_filters && (
            <details>
              <summary>Wireshark flow filters — one per file</summary>
              {ladder.flow_filters.map((f) => (
                <div className="mapping" key={f.capture_id}>
                  <strong>{f.file}</strong>
                  <code>{f.display_filter}</code>
                  <button
                    className="icon"
                    onClick={() =>
                      navigator.clipboard.writeText(f.display_filter)
                    }
                  >
                    Copy flow filter
                  </button>
                </div>
              ))}
              <p className="hint">
                These use the tuple observed at each file, including NAT, and
                the selected session's observed time range. Merging or re-saving
                may change frame numbers.
              </p>
            </details>
          )}
          {fieldDiff && <FieldDiff data={fieldDiff} onEvidence={setEvidence} />}
          <LadderChart
            data={ladder}
            points={topology.forward.map((id) =>
              topology.points.find((p) => p.id === id)!,
            )}
            onEvidence={setEvidence}
          />
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Direction</th>
                  <th>Sequence / ACK</th>
                  <th>Length</th>
                  <th>Appearances / field differences</th>
                </tr>
              </thead>
              <tbody>
                {ladder.items.map((p) => (
                  <tr
                    className="clickable"
                    key={p.packet_key}
                    onClick={() => setEvidence(p.evidence)}
                  >
                    <td>
                      {time(p.ts)}{" "}
                      {p.retrans && <Badge kind="low">retrans</Badge>}
                    </td>
                    <td>{p.direction}</td>
                    <td>
                      {p.seq} / {p.ack}
                    </td>
                    <td>{p.length} B</td>
                    <td>
                      {p.evidence
                        .map((e) => `${e.point} #${e.frame}`)
                        .join(" · ")}
                      <button
                        title="Compare raw fields across matched capture points, with evidence and unknowns"
                        onClick={async (event) => {
                          event.stopPropagation();
                          try {
                            setFieldDiff(
                              await api(`/packets/${p.packet_key}/field-diff`),
                            );
                          } catch (error) {
                            setFieldDiff({
                              items: [],
                              note: String(error),
                            });
                          }
                        }}
                      >
                        Field diff
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            <span>
              {ladderOffset + 1}–{Math.min(ladderOffset + 100, ladder.total)} of{" "}
              {ladder.total} packet identities
            </span>
            <button
              disabled={!ladderOffset}
              onClick={() => setLadderOffset(ladderOffset - 100)}
            >
              Previous
            </button>
            <button
              disabled={ladderOffset + 100 >= ladder.total}
              onClick={() => setLadderOffset(ladderOffset + 100)}
            >
              Next
            </button>
          </div>
        </section>
      )}
    </>
  );
}
