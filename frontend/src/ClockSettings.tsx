














import {num} from "./api";











import {useWorkspace} from "./WorkspaceContext";
import {Badge} from "./UI";

export function ClockSettings() {
  const {
    state,
    topology,
    setTopology,
    evidence,
    setEvidence,
    path,
    action,
    saveTopology,
    report,
    busy,
  } = useWorkspace();
  return (
    <>
      <section>
        <h2>Clock alignment</h2>
        <p className="hint">
          Offset is capture clock minus reference clock. Drift is parts per
          million relative to the reference epoch. Estimates assume symmetric
          minimum path delay; they are not calibrated measurements.
        </p>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Capture</th>
                <th>Estimated offset / drift</th>
                <th>Confidence</th>
                <th>Override offset (ms)</th>
                <th>Override drift (ppm)</th>
              </tr>
            </thead>
            <tbody>
              {state.captures.map((c) => {
                const m = report?.clocks[c.id],
                  o = topology.clock_overrides[c.id];
                return (
                  <tr key={c.id}>
                    <td>{c.name}</td>
                    <td title={m?.reason}>
                      {num(
                        m?.offset != null ? m.offset * 1000 : null,
                        " ms",
                        3,
                      )}
                      <small>
                        {num(m?.drift_ppm, " ppm", 3)} · {m?.samples ?? 0} pairs
                      </small>
                    </td>
                    <td title={m?.reason}>
                      <Badge>{m?.confidence || "unknown"}</Badge>
                      {!!m?.evidence?.length && (
                        <button
                          className="icon"
                          onClick={() => setEvidence(m.evidence)}
                        >
                          Frames
                        </button>
                      )}
                      <small>
                        ±
                        {num(
                          m?.uncertainty != null ? m.uncertainty * 1000 : null,
                          " ms",
                          3,
                        )}
                      </small>
                    </td>
                    <td>
                      <input
                        aria-label={`Offset ${c.name}`}
                        type="number"
                        step="any"
                        value={o?.offset_ms ?? ""}
                        placeholder="Automatic"
                        onChange={(e) => {
                          const overrides = {
                            ...topology.clock_overrides,
                          };
                          if (e.target.value === "") delete overrides[c.id];
                          else
                            overrides[c.id] = {
                              offset_ms: Number(e.target.value),
                              drift_ppm: o?.drift_ppm || 0,
                            };
                          setTopology({
                            ...topology,
                            clock_overrides: overrides,
                          });
                        }}
                      />
                    </td>
                    <td>
                      <input
                        aria-label={`Drift ${c.name}`}
                        disabled={!o}
                        type="number"
                        step="any"
                        value={o?.drift_ppm ?? ""}
                        onChange={(e) =>
                          setTopology({
                            ...topology,
                            clock_overrides: {
                              ...topology.clock_overrides,
                              [c.id]: {
                                offset_ms: o.offset_ms,
                                drift_ppm: Number(e.target.value),
                              },
                            },
                          })
                        }
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <button
          disabled={busy}
          onClick={() => action(() => saveTopology(topology))}
        >
          Save analysis settings
        </button>
      </section>
    </>
  );
}
