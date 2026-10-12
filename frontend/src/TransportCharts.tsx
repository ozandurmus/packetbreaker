import { useCallback, useEffect, useMemo, useState } from "react";
import type { EChartsOption } from "echarts";
import { Chart } from "./Charts";
import { api } from "./api";
import type { Ref } from "./types";
type Packet = {
  frame: number;
  time: number;
  kind: string;
  sequence: number | null;
  length: number;
  window_edge: number | null;
  retransmission: boolean | null;
};
type Bucket = {
  time: number;
  throughput_bps: number | null;
  rtt_ms: number | null;
  data_frame: number | null;
  rtt_frame: number | null;
  coverage: string;
};
type Result = {
  point?: string;
  direction?: string;
  aligned?: boolean;
  points: { point: string; label: string }[];
  packets: Packet[];
  buckets: Bucket[];
  note?: string;
  reason: string | null;
  sampling_note?: string;
  clock_uncertainty_ms?: number | null;
};
type Datum = { value: (number | null)[]; frames: number[] };
export function TransportCharts({
  flow,
  rangeQuery,
  onRange,
  onEvidence,
}: {
  flow: string;
  rangeQuery: string;
  onRange: (range: [number, number] | null) => void;
  onEvidence: (refs: Ref[]) => void;
}) {
  const [point, setPoint] = useState(""),
    [direction, setDirection] = useState("forward"),
    [localRange, setLocalRange] = useState<[number, number] | null>(null),
    [result, setResult] = useState<Result | null>(null),
    [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    setError("");
    const query = localRange
      ? `&local=true&start=${localRange[0]}&end=${localRange[1]}`
      : rangeQuery;
    api<Result>(
      `/flows/${flow}/charts?direction=${direction}${point ? `&point=${encodeURIComponent(point)}` : ""}${query}`,
    )
      .then((r) => {
        if (active) setResult(r);
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, [flow, point, direction, rangeQuery, localRange]);
  const click = useCallback(
    (p: unknown) => {
      const frames = (
        p as { data?: { frames?: number[] } }
      ).data?.frames?.filter(Boolean);
      if (!frames?.length || !result?.point) return;
      api<Ref[]>(
        `/flows/${flow}/frames?point=${encodeURIComponent(result.point)}${frames
          .slice(0, 8)
          .map((f) => `&frames=${f}`)
          .join("")}`,
      )
        .then(onEvidence)
        .catch((e) => setError(String(e)));
    },
    [flow, result?.point, onEvidence],
  );
  const brush = useCallback(
    (p: unknown) => {
      const areas = (p as { areas?: { coordRange?: number[] }[] }).areas;
      const r = areas?.[0]?.coordRange;
      const selected =
        r && r.length === 2
          ? ([Math.min(...r) / 1000, Math.max(...r) / 1000] as [number, number])
          : null;
      if (result?.aligned) {
        onRange(selected);
      } else setLocalRange(selected);
    },
    [result?.aligned, onRange],
  );
  const options = useMemo(() => {
    const base: EChartsOption = {
      useUTC: true,
      animation: false,
      grid: { left: 90, right: 35, top: 55, bottom: 75 },
      xAxis: { type: "time", name: "UTC" },
      yAxis: { type: "value" },
      tooltip: { trigger: "item", renderMode: "richText" },
      legend: { top: 0 },
      dataZoom: [{ type: "inside" }, { type: "slider" }],
      toolbox: { feature: { brush: { type: ["lineX", "clear"] } } },
      brush: { xAxisIndex: 0, brushMode: "single" },
    };
    const packets = result?.packets || [];
    const spans = packets
      .filter((p) => p.kind === "data" && p.sequence !== null)
      .flatMap((p) => [
        { value: [p.time * 1000, p.sequence], frames: [p.frame] },
        { value: [p.time * 1000, p.sequence! + p.length], frames: [p.frame] },
        { value: [p.time * 1000, null], frames: [] },
      ]);
    const ack = packets
      .filter((p) => p.kind === "ack" && p.sequence !== null)
      .map((p) => ({ value: [p.time * 1000, p.sequence], frames: [p.frame] }));
    const window = packets
      .filter((p) => p.kind === "ack" && p.window_edge !== null)
      .map((p) => ({
        value: [p.time * 1000, p.window_edge],
        frames: [p.frame],
      }));
    const retrans = packets
      .filter(
        (p) => p.kind === "data" && p.retransmission && p.sequence !== null,
      )
      .map((p) => ({ value: [p.time * 1000, p.sequence], frames: [p.frame] }));
    const seq: EChartsOption = {
      ...base,
      yAxis: { type: "value", name: "Sequence bytes" },
      series: [
        {
          type: "line",
          name: "Data byte spans",
          data: spans as Datum[],
          connectNulls: false,
          showSymbol: true,
          symbolSize: 3,
        },
        {
          type: "line",
          name: "ACK",
          step: "end",
          data: ack as Datum[],
          showSymbol: true,
          symbolSize: 3,
        },
        {
          type: "line",
          name: "Receive-window edge",
          step: "end",
          data: window as Datum[],
          showSymbol: true,
          symbolSize: 3,
        },
        {
          type: "scatter",
          name: "Retransmission",
          symbol: "diamond",
          symbolSize: 9,
          itemStyle: { color: "#d78325" },
          data: retrans as Datum[],
        },
      ],
    };
    const bucketSeries = (
      metric: "rtt_ms" | "throughput_bps",
      frame: "rtt_frame" | "data_frame",
    ) =>
      (result?.buckets || []).map((b) => ({
        value: [b.time * 1000, b[metric]],
        frames: b[frame] ? [b[frame]!] : [],
      }));
    return [
      seq,
      {
        ...base,
        yAxis: { type: "value", name: "RTT (ms)" },
        series: [
          {
            name: "ACK RTT (includes receiver ACK delay)",
            type: "line",
            showSymbol: true,
            data: bucketSeries("rtt_ms", "rtt_frame"),
          },
        ],
      },
      {
        ...base,
        yAxis: { type: "value", name: "Payload bit/s" },
        series: [
          {
            name: "Observed payload throughput (includes retries)",
            type: "line",
            showSymbol: true,
            data: bucketSeries("throughput_bps", "data_frame"),
          },
        ],
      },
    ] as EChartsOption[];
  }, [result]);
  return (
    <section>
      <h2>TCP sequence, RTT and throughput</h2>
      <p className="hint">
        Brush any chart to filter the aligned investigation range; click a
        packet/bucket for original frame filters. Window edge = cumulative ACK +
        negotiated receive window. RTT includes ACK delay and is not isolated
        hop latency.
      </p>
      <label>
        Capture point
        <select
          aria-label="Stream chart capture point"
          value={point || result?.point || ""}
          onChange={(e) => {
            setPoint(e.target.value);
            setLocalRange(null);
          }}
        >
          {result?.points.map((p) => (
            <option key={p.point} value={p.point}>
              {p.label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Data direction
        <select
          aria-label="Stream chart direction"
          value={direction}
          onChange={(e) => setDirection(e.target.value)}
        >
          <option value="forward">Forward</option>
          <option value="reverse">Reverse</option>
        </select>
      </label>
      <button
        onClick={() => {
          setLocalRange(null);
          onRange(null);
        }}
      >
        Clear chart selection
      </button>
      {error && <p role="alert">{error}</p>}
      {result?.reason && <p>{result.reason}</p>}
      <p className="hint">
        {result?.note} Clock uncertainty:{" "}
        {result?.clock_uncertainty_ms == null
          ? "unknown"
          : `±${result.clock_uncertainty_ms.toFixed(3)} ms`}
        . {result?.sampling_note}
      </p>
      {result &&
        !result.reason &&
        options.map((o, i) => (
          <Chart
            key={i}
            option={o}
            height={310}
            onClick={click}
            onBrush={brush}
          />
        ))}
    </section>
  );
}
