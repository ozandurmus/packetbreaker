






import {CasePreflight} from "./CasePreflight";







import {api,num,time} from "./api";







import {Coverage} from "./Charts";

import type {Job} from "./types";

import {useWorkspace} from "./WorkspaceContext";
import {Badge,Tip} from "./UI";

export function CapturesView() {
  const {
    state,
    error,
    setJob,
    path,
    setPath,
    filter,
    fortiPath,
    setFortiPath,
    fortiStart,
    setFortiStart,
    fortiDevice,
    setFortiDevice,
    action,
    upload,
    report,
    ready,
    busy,
  } = useWorkspace();
  return (
    <>
      <CasePreflight state={state} />
      <section>
        <h2>Import Fortinet verbose-6 text</h2>
        <p className="hint">
          One capture point per interface. Absolute “a” timestamps are UTC.
          Relative timestamps require an explicit start and retain low clock
          confidence. Draw the path after importing.
        </p>
        <label>
          Text file (absolute local path)
          <input
            value={fortiPath}
            onChange={(e) => setFortiPath(e.target.value)}
          />
        </label>
        <label>
          Device name
          <input
            value={fortiDevice}
            onChange={(e) => setFortiDevice(e.target.value)}
          />
        </label>
        <label>
          Start time for relative timestamps
          <input
            placeholder="2026-10-09T12:00:00Z"
            value={fortiStart}
            onChange={(e) => setFortiStart(e.target.value)}
          />
        </label>
        <button
          disabled={busy || !fortiPath || !fortiDevice}
          onClick={() =>
            action(async () =>
              setJob(
                await api<Job>("/fortinet/import", "POST", {
                  path: fortiPath,
                  start_time: fortiStart || null,
                  device: fortiDevice,
                }),
              ),
            )
          }
        >
          Convert and attach interfaces
        </button>
        {state.fortinet_conversion && (
          <p>
            Last conversion: {state.fortinet_conversion.packets} packets;{" "}
            {state.fortinet_conversion.skipped_lines} skipped lines;{" "}
            {state.fortinet_conversion.skipped_packets} incomplete/unsupported
            packets skipped.{" "}
            {state.fortinet_conversion.files
              .map(
                (f) =>
                  `${f.interface}: ${f.packets} packets, clock ${f.clock_confidence}`,
              )
              .join(" · ")}
          </p>
        )}
      </section>
      <section>
        <div className="section-head">
          <h2>Add packet captures</h2>
          <Badge>PCAP / PCAPNG / SNOOP</Badge>
        </div>
        <div className="upload-area">
          <span>⇧</span>
          <h3>Bring the path into view</h3>
          <p>
            Attach local files without copying, or upload them into the project.
          </p>
          <label className={"button " + (busy ? "disabled" : "")}>
            Choose capture files
            <input
              type="file"
              multiple
              accept=".pcap,.pcapng,.cap,.snoop"
              hidden
              disabled={busy}
              onChange={(e) => action(() => upload(e.target.files))}
            />
          </label>
        </div>
        <label>
          Absolute local file paths (one per line)
          <textarea
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/path/to/firewall-ingress.pcap"
            rows={3}
          />
        </label>
        <button
          disabled={busy || !path.trim()}
          onClick={() =>
            action(async () => {
              setJob(
                await api<Job>("/captures/attach", "POST", {
                  paths: path
                    .split("\n")
                    .map((s) => s.trim())
                    .filter(Boolean),
                }),
              );
            })
          }
        >
          Attach files
        </button>
      </section>
      <section>
        <Coverage captures={state.captures} report={report} />
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Capture</th>
                <th>Status</th>
                <th>
                  <Tip text="Number of frames successfully indexed by tshark.">
                    Packets
                  </Tip>
                </th>
                <th>Start / end (observed UTC)</th>
                <th>
                  <Tip text="Elapsed time between first and last observed frame; this does not prove continuous capture.">
                    Duration
                  </Tip>
                </th>
                <th>
                  <Tip text="pcapng interface/OS drop counters. Unknown means the file did not report the counter.">
                    Drops (if / OS)
                  </Tip>
                </th>
                <th>Interfaces / snaplen / link type</th>
              </tr>
            </thead>
            <tbody>
              {state.captures.map((c) => (
                <tr key={c.id}>
                  <td>
                    <strong>{c.name}</strong>
                    <small title={c.path}>{c.path}</small>
                    {c.inventory.warnings?.map((w) => (
                      <small className="red" key={w}>
                        {w}
                      </small>
                    ))}
                    {c.error && <small className="red">{c.error}</small>}
                  </td>
                  <td>
                    <Badge kind={c.state === "ready" ? "good" : "unknown"}>
                      {c.state}
                    </Badge>
                    {!["ready", "ingesting"].includes(c.state) && (
                      <button
                        disabled={busy}
                        onClick={() =>
                          action(async () =>
                            setJob(
                              await api<Job>("/captures/attach", "POST", {
                                paths: [c.path],
                              }),
                            ),
                          )
                        }
                      >
                        Resume
                      </button>
                    )}
                  </td>
                  <td>
                    {num(c.inventory.packet_count ?? c.checkpoint, "", 0)}
                  </td>
                  <td>
                    {time(
                      c.inventory.timestamps_validated
                        ? c.inventory.start
                        : null,
                    )}
                    <small>
                      {time(
                        c.inventory.timestamps_validated
                          ? c.inventory.end
                          : null,
                      )}
                    </small>
                  </td>
                  <td>{num(c.inventory.duration, " s")}</td>
                  <td>
                    {num(c.inventory.ifdrop, "", 0)} /{" "}
                    {num(c.inventory.osdrop, "", 0)}
                  </td>
                  <td>
                    {c.inventory.interfaces.map((x, i) => (
                      <small key={i}>
                        #{x.id} {x.name} · {x.snaplen} B · DLT {x.link_type}
                      </small>
                    ))}
                    <small title="Largest number of bytes actually stored for a usable packet, independent of the declared interface snaplen.">
                      Observed max{" "}
                      {num(c.inventory.observed_max_caplen, " B", 0)}
                    </small>
                    {!!c.inventory.truncated && (
                      <small className="red">
                        {c.inventory.truncated_caplen_min ===
                        c.inventory.truncated_caplen_max
                          ? `Packets truncated at ${num(c.inventory.truncated_caplen_max, " B", 0)}`
                          : `Truncated packet caplen ${num(c.inventory.truncated_caplen_min, " B", 0)}–${num(c.inventory.truncated_caplen_max, " B", 0)}`}
                      </small>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
