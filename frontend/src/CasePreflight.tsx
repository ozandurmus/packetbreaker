import type { State } from "./types";
import { time } from "./api";
export function CasePreflight({ state }: { state: State }) {
  if (!state.preflight) return null;
  return (
    <section>
      <h2>Capture inventory — review before analysis</h2>
      {state.case_context && <p>{state.case_context.note}</p>}
      {state.case_context?.warning && (
        <p role="alert">{state.case_context.warning}</p>
      )}
      {state.case_context?.issues?.map((i, n) => (
        <p className="red" key={n}>
          {i.file}: {i.error}
        </p>
      ))}
      <p
        className={state.preflight.overlap.status === "none" ? "red" : "hint"}
        role={state.preflight.overlap.status === "none" ? "alert" : undefined}
      >
        {state.preflight.overlap.reason}
      </p>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>File / state</th>
              <th>Observed time range</th>
              <th>Inventory warnings</th>
            </tr>
          </thead>
          <tbody>
            {state.preflight.files.map((f) => (
              <tr key={f.id || f.name}>
                <td>
                  {f.name}
                  <small>
                    {f.state} · {f.packet_count ?? "?"} usable packets
                  </small>
                  <small>
                    Header{" "}
                    {f.header_snaplen ??
                      (f.header_snaplens?.join(" / ") || "?")}{" "}
                    B · maximum captured {f.observed_max_caplen ?? "?"} B
                  </small>
                </td>
                <td>
                  {time(f.start)} – {time(f.end)}
                </td>
                <td>
                  {f.warnings.length
                    ? f.warnings.map((w, n) => <div key={n}>{w}</div>)
                    : "No recorded warnings"}
                  <small>
                    Capture drops: interface {f.ifdrop ?? "unknown"}, OS{" "}
                    {f.osdrop ?? "unknown"}
                  </small>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
