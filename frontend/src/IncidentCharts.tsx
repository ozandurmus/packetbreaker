import type { EChartsOption } from "echarts";
import type { Ref } from "./types";
import { num } from "./api";
export const metricNotes: Record<string, string> = {
  rx_max_ms:
    "Maximum measured same-copy RX boundary transit; clock uncertainty applies.",
  tx_max_ms:
    "Maximum measured same-copy TX boundary transit; retry substitutions are excluded.",
  tx_dropped:
    "Original TX units missing; retry delivery is a drop/recovery, not original transit delay.",
  tx_delayed:
    "Original TX units seen downstream later than the uncertainty threshold.",
  retransmissions:
    "tshark retransmission observations at the host; a symptom, not fault attribution.",
  delayed: "Same original unit observed downstream later.",
  dropped: "Original absent; retry recovery is not original transit.",
  capture_miss_percent:
    "Capture miss supported by later or ACK evidence / observed pair units.",
  loss_percent: "Supported loss / observed pair units.",
  offload_mismatch_percent:
    "Unknown pair with different segmentation and a super-frame.",
  unknown_percent: "Other incomplete identity/clock/coverage evidence.",
};
export function timeChart(): EChartsOption {
  return {
    animation: false,
    tooltip: {
      trigger: "item",
      renderMode: "richText",
      formatter: (event: unknown) => {
        const p = event as {
          seriesName: string;
          data: { value: number[]; note?: string };
        };
        return `${p.seriesName}\n${new Date(p.data.value[0]).toLocaleString()}\n${num(p.data.value[1])}\n${p.data.note || ""}\nClick for frame evidence.`;
      },
    },
    toolbox: { feature: { brush: { type: ["lineX", "clear"] } } },
    brush: { xAxisIndex: 0, brushMode: "single" },
    legend: { type: "scroll", top: 0 },
    grid: { top: 60, bottom: 80, left: 85, right: 85 },
    xAxis: { type: "time" },
    yAxis: { type: "value", min: 0 },
    dataZoom: [{ type: "slider", height: 18, bottom: 12 }],
  };
}
export function clickEvidence(
  event: unknown,
  onEvidence: (refs: Ref[]) => void,
) {
  onEvidence((event as { data?: { evidence?: Ref[] } }).data?.evidence || []);
}
export function brushTime(
  event: unknown,
  onSelect: (range: [number, number] | null) => void,
) {
  const a = (event as { areas?: { coordRange: number[] }[] }).areas?.[0]
    ?.coordRange;
  onSelect(a ? [Math.min(...a) / 1000, Math.max(...a) / 1000] : null);
}
