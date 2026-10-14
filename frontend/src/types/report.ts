import type { Ref, Mapping } from "../types";
export type SuggestedInference = {
  kind: string;
  capture_ids: string[];
  reason: string;
  metrics?: unknown;
  evidence: Ref[];
  warning?: string;
};
export type SuggestedTopology = {
  status: string;
  ambiguous: boolean;
  confirmed: boolean;
  badge?: string;
  reason?: string | null;
  topology?: import("../types").Topology;
  inferences: SuggestedInference[];
  warnings: string[];
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
  downstream_summary?: string;
  downstream_count?: number;
  chronic_loss?: boolean;
  evidence: Ref[];
  evidence_note: string;
  tooltip?: string;
  metrics: Record<string, number>;
};
export type Segment = {
  loss_suspect?: boolean;
  chronic_loss?: boolean;
  chronic_loss_summary?: string;
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
  eligible_ratio: number | null;
  excluded_counts: Record<string, number>;
  classes: Record<string, number>;
  offset_uncertainty_ms: number | null;
  latency_uncertainty_ms?: number;
  quality_notes?: string[];
};
export type Report = {
  suggested_topology?: SuggestedTopology;
  delivery?: {
    series: {
      point_a: string;
      point_b: string;
      direction: string;
      start: number;
      delayed: number;
      dropped: number;
      capture_misses: number;
      unknown: number;
      max_delay_ms: number | null;
      max_recovery_ms: number | null;
    }[];
    note: string;
  };
  cycles?: import("../Cycles").CycleReport;
  incident?: import("../Incident").IncidentReport;
  host_path?: import("../HostPath").HostPathReport;
  analysis_scope?: {
    point: string;
    input_frames: number;
    retained_frames: number;
    excluded_single_point_frames: number;
  }[];
  udp?: import("../UdpMedia").UdpReport;
  rtp?: import("../UdpMedia").RtpReport;
  sip?: import("../UdpMedia").SipReport;
  application_status?: {
    point: string;
    reason: string | null;
    cached: boolean;
  }[];
  proxies?: {
    note: string;
    transaction_count: number;
    transactions: {
      device: string;
      kind: string;
      request?: string;
      status: string;
      reason: string | null;
      client_flow?: string | null;
      server_flow?: string | null;
      request_dwell?: {
        duration_ms: number | null;
        uncertainty_ms: number | null;
        reason: string | null;
      };
      response_dwell?: {
        duration_ms: number | null;
        uncertainty_ms: number | null;
        reason: string | null;
      };
      evidence: Ref[];
    }[];
    legs?: {
      point: string;
      flow: string;
      packets: number;
      retransmissions: number;
      resets: number;
      loss_by_class: Record<string, number>;
    }[];
    reset_notes?: {
      device: string;
      status: string;
      reason: string;
      evidence: Ref[];
    }[];
  };
  tls?: {
    status: string;
    device?: string | null;
    point?: string;
    sni: string;
    reason: string;
    evidence: Ref[];
  }[];
  confirmed_device_drop_count?: number;
  confirmed_device_drops?: { device: string; stage: string; count: number }[];
  vendor_device_event_count?: number;
  vendor_device_events?: {
    device: string;
    stage: string;
    status: string;
    reason: string;
    evidence: Ref[];
  }[];
  f5?: {
    note?: string;
    connection_count?: number;
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
  security?: {
    note: string;
    thresholds: Record<string, number>;
    quality: { point: string; status: string; reason: string }[];
  };
  sessions?: import("../Sessions").SessionReport;
  microbursts?: import("../Microbursts").MicroburstReport;
  fragment_points?: {
    point: string;
    status: string;
    datagrams: number;
    physical_fragments: number;
  }[];
  tunnel_points?: {
    point: string;
    selected: number;
    unselected: number;
    layer: string | null;
    truncated_inner: number;
  }[];
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
    index_scope?: {
      input_frames: number;
      retained_frames: number;
      input_flows: number;
      retained_flows: number;
      excluded_frames: number;
      excluded_flows: number;
    };
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
