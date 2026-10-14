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
export type TopologyOverlay = {
  segments: {
    id: string;
    loss_percent: number | null;
    p95_ms: number | null;
    retrans_observations: number;
    reason: string | null;
    classes: Record<string, number>;
  }[];
  nodes: {
    device: string;
    observations: number;
    retrans_observations: number;
    supported_loss_events: number;
    confirmed_device_drops: number;
    findings: number;
  }[];
  note: string;
};
