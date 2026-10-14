import type { Ref } from "../types";
export type Flow = {
  reset_origin?: string | null;
  handshake_rtt_ms?: number | null;
  matching_unknown_reason?: string | null;
  flow: string;
  tuple: string;
  start: number | null;
  end: number | null;
  bytes: number;
  points: number;
  confirmed_device_drop: number;
  impactful_loss: number;
  recovered_loss: number;
  unrecovered_loss: number;
  handshake_blocked: number;
  unknown_events: number;
  capture_miss: number;
  retrans_observations: number;
  max_stall_ms: number | null;
  max_rtt_ms: number | null;
  has_reset: boolean;
  handshake_incomplete: boolean;
};
export type Ladder = {
  flow_filters?: { capture_id: string; file: string; display_filter: string }[];
  local_metrics?: {
    point: string;
    tuple: string;
    retransmissions: number;
    zero_windows: number;
    resets: number;
    max_rtt_ms: number | null;
    handshake: {
      syn_frame: number;
      synack_frame: number;
      syn_to_synack_ms: number;
      synack_to_ack_ms: number | null;
    } | null;
  }[];
  total: number;
  items: {
    packet_key: string;
    ts: number | null;
    retrans: boolean;
    seq: number;
    ack: number;
    flags: number;
    length: number;
    direction: string;
    evidence: Ref[];
  }[];
  events: { point_b: string; kind: string; ts: number; packet_key: string }[];
};
