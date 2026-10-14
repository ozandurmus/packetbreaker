import type { Topology, Capture, Report } from "../types";
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
  preflight?: {
    files: {
      id?: string;
      name: string;
      state: string;
      start: number | null;
      end: number | null;
      packet_count: number | null;
      header_snaplen: number | null;
      header_snaplens: number[];
      observed_max_caplen: number | null;
      ifdrop: number | null;
      osdrop: number | null;
      warnings: string[];
    }[];
    overlap: { status: string; reason: string };
  };
  case_context?: {
    note: string;
    warning: string | null;
    issues: { file: string; error: string }[];
  } | null;
  version: string;
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
    memory_limit_mb?: number | null;
    assistant_enabled?: boolean;
    checkpoint_uuid?: boolean;
    f5_trailer?: boolean;
    tshark?: string;
    prefix_bytes?: number;
    parallel?: boolean;
  };
  tshark: { path: string | null; error: string | null };
  job: Job;
};
