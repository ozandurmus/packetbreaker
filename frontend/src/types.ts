export type Ref = {
  point: string;
  file: string;
  capture_id: string;
  frame: number;
  display_filter: string;
  content_filter?: string | null;
  flow_filter?: string | null;
  filter_note?: string;
  observed_time: number;
  corrected_time: number | null;
};
export type Point = {
  id: string;
  label: string;
  device: string;
  kind: string;
  side: string;
  capture_id: string;
  interface: number | null;
  source_cidr: string | null;
  translation: string;
  x: number;
  y: number;
};
export type Mapping = {
  point_a: string;
  point_b: string;
  tuple_a: string;
  tuple_b: string;
  samples?: number;
  evidence?: Ref[];
};
export type Topology = {
  report_timezone?: string | null;
  points: Point[];
  forward: string[];
  reverse: string[];
  client_cidrs: string[];
  nat_mappings: Mapping[];
  clock_overrides: Record<string, { offset_ms: number; drift_ppm: number }>;
  min_eligible_ratio: number;
  duplicate_us: number;
  stall_ms: number;
  match_window_ms: number;
  start: number | null;
  end: number | null;
};
export type Capture = {
  id: string;
  path: string;
  name: string;
  state: string;
  checkpoint: number;
  error: string | null;
  inventory: {
    warnings?: string[];
    timestamps_validated?: boolean;
    timestamp_excluded_counts?: Record<string, number>;
    start?: number;
    end?: number;
    duration?: number;
    packet_count?: number;
    truncated?: number;
    possible_offload?: number;
    ifdrop?: number | null;
    osdrop?: number | null;
    format: string;
    interfaces: {
      id: number;
      section: number;
      name: string | null;
      snaplen: number;
      link_type: number;
    }[];
  };
};
export type Finding = {
  headline?: string;
  clock_caveat?: string;
  time_labels?: { local: string; utc: string };
  id: string;
  type: string;
  severity: string;
  hop: string;
  direction: string;
  time_range: number[];
  confidence: string;
  summary: string;
  evidence: Ref[];
  evidence_note: string;
  metrics: Record<string, number>;
};
export type Segment = {
  id: string;
  point_a: string;
  point_b: string;
  label: string;
  location: string;
  direction: string;
  reason: string | null;
  matched: number;
  p50_ms: number | null;
  p95_ms: number | null;
  max_ms: number | null;
  loss_percent: number | null;
  eligible_packets: number;
  eligible_ratio: number;
  excluded_counts: Record<string, number>;
  classes: Record<string, number>;
  offset_uncertainty_ms: number | null;
};
export type Report = {
  auto_order_suggestion?: { points: string[]; reason: string };
  verdict: string;
  scope: string;
  flow_count: number;
  window: {
    start: number | null;
    end: number | null;
    common_start: number | null;
    common_end: number | null;
  };
  clocks: Record<
    string,
    {
      offset: number | null;
      drift_ppm: number;
      epoch: number;
      uncertainty: number | null;
      confidence: string;
      reason: string;
      samples: number;
      evidence: Ref[];
    }
  >;
  coverage: { point: string; start: number | null; end: number | null }[];
  quality: {
    ifdrop: number | null;
    osdrop: number | null;
    point: string;
    packets: number;
    excluded: number;
    truncated: number;
    possible_offload: number;
    unknown_direction: number;
    evidence: Ref[];
  }[];
  nat_suggestions: Mapping[];
  segments: Segment[];
  findings: Finding[];
  limitations: string[];
};
export type Job = {
  state: string;
  busy: boolean;
  kind?: string;
  file?: string;
  file_index?: number;
  file_count?: number;
  frames?: number;
  error?: string;
};
export type State = {
  project: string;
  captures: Capture[];
  topology: Topology;
  report: Report | null;
  settings: { tshark?: string; prefix_bytes?: number };
  tshark: { path: string | null; error: string | null };
  job: Job;
};
export type Flow = {
  flow: string;
  tuple: string;
  start: number | null;
  end: number | null;
  bytes: number;
  points: number;
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
