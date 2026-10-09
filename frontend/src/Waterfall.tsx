import { useEffect, useState } from "react";
import { api, num } from "./api";
import { Chart } from "./Charts";
import type { Ref } from "./types";

type Bar = {
  label: string;
  kind: string;
  duration_ms: number | null;
  start_ms: number | null;
  uncertainty_ms: number | null;
  reason: string | null;
  note: string;
  evidence: Ref[];
};
type Result = {
  items: { kind: string; title: string; bars: Bar[]; note?: string }[];
  requests: { index: number; label: string; time: number | null }[];
  reason: string | null;
};
export function Waterfall({
  flow,
  rangeQuery,
  onEvidence,
}: {
  flow: string;
  rangeQuery: string;
  onEvidence: (refs: Ref[]) => void;
}) {
  const [data, setData] = useState<Result | null>(null);
  const [request, setRequest] = useState(0);
  const [error, setError] = useState("");
  useEffect(() => {
    setRequest(0);
  }, [flow, rangeQuery]);
  useEffect(() => {
    let active = true;
    setData(null);
    setError("");
    api<Result>(
      `/flows/${flow}/waterfall?request_index=${request}${rangeQuery}`,
    )
      .then((r) => {
        if (active) setData(r);
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, [flow, request, rangeQuery]);
  return (
    <section>
      <h2>Where did the time go?</h2>
      <p className="hint">
        Handshake and cleartext HTTP/1.x. Every link and device dwell uses frame
        evidence. Unknown bars have no invented duration.
      </p>
      {error && <p role="alert">{error}</p>}
      {!data && !error && <p>Loading waterfall…</p>}
      {data?.reason && <p>{data.reason}</p>}
      {!!data?.requests.length && (
        <label>
          HTTP request{" "}
          <select
            aria-label="Waterfall HTTP request"
            value={request}
            onChange={(e) => setRequest(Number(e.target.value))}
          >
            {data.requests.map((r) => (
              <option key={r.index} value={r.index}>
                {r.index + 1}. {r.label}
              </option>
            ))}
          </select>
        </label>
      )}
      {data?.items.map((item) => (
        <div key={item.kind}>
          <h3>{item.title}</h3>
          {item.note && <p className="hint">{item.note}</p>}
          <Chart
            height={Math.max(240, item.bars.length * 30 + 70)}
            option={{
              animation: false,
              grid: { left: 290, right: 30, top: 20, bottom: 45 },
              xAxis: { type: "value", name: "Elapsed ms", min: 0 },
              yAxis: {
                type: "category",
                inverse: true,
                data: item.bars.map(
                  (b) => b.label + (b.reason ? " · unknown" : ""),
                ),
                axisLabel: { width: 270, overflow: "truncate" },
              },
              tooltip: {
                renderMode: "richText",
                trigger: "item",
                formatter: (params: unknown) => {
                  const b =
                    item.bars[(params as { dataIndex: number }).dataIndex];
                  return `${b.label}\n${b.reason || `${num(b.duration_ms, " ms")} ±${num(b.uncertainty_ms, " ms")}`}\n${b.note}\nClick for evidence`;
                },
              },
              series: [
                {
                  type: "bar",
                  stack: "time",
                  silent: true,
                  itemStyle: { color: "transparent" },
                  data: item.bars.map((b) => b.start_ms),
                  tooltip: { show: false },
                },
                {
                  type: "bar",
                  stack: "time",
                  barMinHeight: 2,
                  data: item.bars.map((b) => ({
                    value: b.duration_ms,
                    itemStyle: {
                      color:
                        b.kind === "server_processing" ? "#c98a35" : "#168a84",
                    },
                  })),
                },
              ],
            }}
            onClick={(p) =>
              onEvidence(
                item.bars[(p as { dataIndex: number }).dataIndex].evidence,
              )
            }
          />
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Stage / evidence</th>
                  <th>Duration</th>
                  <th>Clock uncertainty</th>
                </tr>
              </thead>
              <tbody>
                {item.bars.map((b, i) => (
                  <tr key={i}>
                    <td>
                      <button
                        className="secondary"
                        disabled={!b.evidence.length}
                        onClick={() => onEvidence(b.evidence)}
                      >
                        {b.label}
                      </button>
                      {b.reason && <p>{b.reason}</p>}
                    </td>
                    <td>{num(b.duration_ms, " ms")}</td>
                    <td title={b.note}>±{num(b.uncertainty_ms, " ms")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </section>
  );
}
