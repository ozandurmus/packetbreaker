export type Ref = {
  vendor?: Record<string, string>;
  byte_ranges?: { start_seq: number; end_seq: number; bytes: number }[];
  range_note?: string;
  sequence_translation?: {
    observed_seq: number;
    observed_ack: number;
    canonical_seq: number;
    canonical_ack: number;
    seq_offset: number;
    ack_offset: number;
    reason: string | null;
  };
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
  vendor?: string;
  vendor_stage?: string | null;
  inspection_complete?: boolean;
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
  bucket_seconds?: number;
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
    observed_max_caplen?: number | null;
    truncated_caplen_min?: number | null;
    truncated_caplen_max?: number | null;
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
  loss_suspect?: boolean;
  symptom_note?: string;
  matching_mode?: string;
  byte_loss_percent?: number | null;
  lost_bytes?: number;
  onset_status?: string;
  onset_quality_notes?: {
    capture_misses: number;
    unknown_events: number;
    reasons: string[];
  };
  onset_reasons?: { metric: string; reason: string }[];
  headline?: string;
  finding_ids?: string[];
  severity?: string;
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
  f5?: {
    pairs: {
      flowid: string;
      peerid: string;
      tmm: string;
      role: string;
      reason: string | null;
      client_flow?: string;
      server_flow?: string;
    }[];
    requests: {
      device: string;
      request: string;
      request_dwell_ms: number | null;
      clock_uncertainty_ms: number;
      reason: string | null;
      note: string;
      evidence: Ref[];
    }[];
    resets: {
      device: string;
      reason: string;
      time: number | null;
      evidence: Ref[];
    }[];
  };
  offload_points?: { point: string; large_frames: number; note: string }[];
  sequence_translations?: {
    ingress: string;
    egress: string;
    flow: string | null;
    status: string;
    reason: string | null;
    boundary_forward_offset: number | null;
    boundary_reverse_offset: number | null;
    samples: number;
    evidence: Ref[];
  }[];
  onsets?: {
    directions: Record<
      string,
      {
        prime_suspects: string[];
        propagation_order: { time: number; segments: string[] }[];
        caveat: string;
      }
    >;
    status: string;
    summary: string;
    items: {
      segment: string;
      metric: string;
      bucket: number;
      time: number;
      explanation: string;
      scope?: string;
      display_label?: string;
      related_loss_segments?: string[];
      evidence: Ref[];
    }[];
  };
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
export type FileJob = {
  file_id: string;
  file: string;
  path: string;
  state: string;
  frames: number;
  usable_packets?: number;
  error?: string;
  warnings?: string[];
};
export type Job = {
  files?: FileJob[];
  workers?: number;
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
  fortinet_conversion?: {
    packets: number;
    skipped_lines: number;
    skipped_packets: number;
    files: { interface: string; packets: number; clock_confidence: string }[];
  };
  settings: {
    checkpoint_uuid?: boolean;
    tshark?: string;
    prefix_bytes?: number;
    parallel?: boolean;
  };
  tshark: { path: string | null; error: string | null };
  job: Job;
};
export type Flow = {
  matching_unknown_reason?: string | null;
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

export type TimeSeries = {
  start: number;
  end: number;
  bucket_seconds: number;
  bucket_count: number;
  metrics: Record<string, { label: string; unit: string; tooltip: string }>;
  items: ({
    segment: string;
    direction: string;
    bucket: number;
    start: number;
    end: number;
    coverage: string;
    reason: string | null;
  } & Record<string, number | string | null>)[];
};
