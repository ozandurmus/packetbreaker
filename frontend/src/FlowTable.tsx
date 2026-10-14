














import {num} from "./api";



import {Diagnosis} from "./Diagnosis";

import {TransportCharts} from "./TransportCharts";
import {Waterfall} from "./Waterfall";




import {useWorkspace} from "./WorkspaceContext";
import {Badge,Tip} from "./UI";

export function FlowTable() {
  const {
    setRange,
    rangeQuery,
    setEvidence,
    flows,
    flowOffset,
    setFlowOffset,
    search,
    setSearch,
    filter,
    setFilter,
    sort,
    setSort,
    selectedFlow,
    setSelectedFlow,
    setLadderOffset,
    events,
    report,
  } = useWorkspace();
  return (
    <>
      <section>
        <div className="section-head">
          <h2>Conversations</h2>
          <Badge>{num(flows.total, " TOTAL", 0)}</Badge>
        </div>
        <div className="toolbar">
          <input
            aria-label="Search conversations"
            placeholder="Search an address or port…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setFlowOffset(0);
            }}
          />
          <select
            aria-label="Quick filter"
            value={filter}
            onChange={(e) => {
              setFilter(e.target.value);
              setFlowOffset(0);
            }}
          >
            <option value="">All conversations</option>
            <option value="device_drops">Confirmed device drops</option>
            <option value="impactful">Impactful loss</option>
            <option value="handshakes">Incomplete handshakes</option>
            <option value="resets">Resets observed</option>
          </select>
          <select
            aria-label="Sort conversations"
            value={sort}
            onChange={(e) => setSort(e.target.value)}
          >
            <option value="bytes">Sort by bytes</option>
            <option value="max_stall_ms">Sort by recovery wait</option>
            <option value="impactful_loss">Sort by impactful loss</option>
            <option value="retrans_observations">
              Sort by retransmissions
            </option>
            <option value="start">Sort by start</option>
            <option value="reset_origin">Sort by reset origin</option>
            <option value="handshake_rtt_ms">Sort by handshake RTT</option>
          </select>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Canonical conversation</th>
                <th>
                  <Tip text="Sum of lengths of distinct packet signatures across the selected points, including retransmitted wire packets.">
                    Bytes
                  </Tip>
                </th>
                <th>
                  <Tip text="Elapsed corrected time between first and last packet in this 5-tuple conversation.">
                    Duration
                  </Tip>
                </th>
                <th>
                  <Tip text="Wireshark retransmission observations summed across capture points; the same retransmission may be observed at several points.">
                    Retrans observations
                  </Tip>
                </th>
                <th>Reset origin (supported only)</th>
                <th title="Client-most capture SYN to SYN/ACK in one clock domain; includes endpoint turnaround. Missing handshake is unknown.">
                  Handshake RTT
                </th>
                <th>Confirmed device drops</th>
                <th>
                  <Tip text="Impactful / recovered / unrecovered / capture miss / blocked handshake / unknown events. A capture miss is not network loss.">
                    Loss classes
                  </Tip>
                </th>
                <th>
                  <Tip text="Largest observed interval from missing original to delivered retransmission; not device processing time.">
                    Max recovery
                  </Tip>
                </th>
              </tr>
            </thead>
            <tbody>
              {flows.items.map((f) => (
                <tr
                  className="clickable"
                  key={f.flow}
                  onClick={() => {
                    setSelectedFlow(f);
                    setLadderOffset(0);
                  }}
                >
                  <td>
                    <code>{f.tuple}</code>
                    {f.matching_unknown_reason && (
                      <small className="red">
                        Unknown matching: {f.matching_unknown_reason}
                      </small>
                    )}
                    <small>
                      {f.has_reset ? "RST observed · " : ""}
                      {f.handshake_incomplete
                        ? "Handshake incomplete in captures"
                        : ""}
                    </small>
                  </td>
                  <td>{num(f.bytes, " B", 0)}</td>
                  <td>
                    {num(
                      f.start != null && f.end != null ? f.end - f.start : null,
                      " s",
                    )}
                  </td>
                  <td>{f.retrans_observations}</td>
                  <td>{f.reset_origin || "unknown / no supported reset"}</td>
                  <td>{num(f.handshake_rtt_ms, " ms")}</td>
                  <td className={f.confirmed_device_drop ? "red" : ""}>
                    {f.confirmed_device_drop || 0}
                  </td>
                  <td>
                    {f.impactful_loss} / {f.recovered_loss} /{" "}
                    {f.unrecovered_loss} / {f.capture_miss} /{" "}
                    {f.handshake_blocked} / {f.unknown_events}
                  </td>
                  <td>{num(f.max_stall_ms, " ms")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!report && (
          <div className="empty">Run analysis to populate conversations.</div>
        )}
        <div className="pagination">
          <span>
            {flows.total
              ? `${flowOffset + 1}–${Math.min(flowOffset + 50, flows.total)} of ${flows.total}`
              : "No conversations"}
          </span>
          <button
            disabled={flowOffset === 0}
            onClick={() => setFlowOffset(flowOffset - 50)}
          >
            Previous
          </button>
          <button
            disabled={flowOffset + 50 >= flows.total}
            onClick={() => setFlowOffset(flowOffset + 50)}
          >
            Next
          </button>
        </div>
      </section>
      {selectedFlow && (
        <Diagnosis
          key={selectedFlow.flow + "-diagnosis"}
          flow={selectedFlow.flow}
          onEvidence={setEvidence}
        />
      )}
      {selectedFlow && (
        <Waterfall
          key={selectedFlow.flow}
          flow={selectedFlow.flow}
          rangeQuery={rangeQuery}
          onEvidence={setEvidence}
        />
      )}
      {selectedFlow && (
        <TransportCharts
          key={selectedFlow.flow + "-charts"}
          flow={selectedFlow.flow}
          rangeQuery={rangeQuery}
          onRange={setRange}
          onEvidence={setEvidence}
        />
      )}
    </>
  );
}
