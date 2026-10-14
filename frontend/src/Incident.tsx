import type { Ref } from "./types";
export type Row = { start: number; evidence: Ref[]; [key: string]: unknown };
export type Part = {
  name: string;
  component: string;
  ms: number | null;
  uncertainty_ms: number;
  reason?: string;
  evidence: Ref[];
};
export type IncidentReport = {
  headline: string;
  scope: string;
  quality_note: string;
  window?: { start: number; end: number };
  timeline: Row[];
  delivery: Row[];
  quality: Row[];
  cycle_bars: {
    cycle_id: string;
    flow: string;
    time: number;
    total_ms: number | null;
    rx_ms: number | null;
    tx_ms: number | null;
    parts: Part[];
  }[];
  hold_release: {
    id: string;
    hop: string;
    time_range: number[];
    metrics: { wire_spacing_ms: number[]; receive_spacing_ms: number[] };
    evidence: Ref[];
    tooltip: string;
    summary: string;
  }[];
  loss_groups: {
    hop: string;
    headline: string;
    counts: Record<string, number>;
    evidence: Ref[];
  }[];
};
