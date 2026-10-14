import type { TopologyOverlay } from "./types";

import type { TimeSeries, Finding } from "./types";
import { useCallback, useEffect, useState } from "react";

import { api } from "./api";
import { type FieldDiffData } from "./FieldDiff";

import type { State, Topology, Ref, Flow, Ladder, Segment, Job } from "./types";

export function useWorkspaceController() {
  const [series, setSeries] = useState<TimeSeries | null>(null);
  const [range, setRange] = useState<[number, number] | null>(null);
  const [rangeFindings, setRangeFindings] = useState<Finding[] | null>(null);
  const rangeQuery = range ? `&start=${range[0]}&end=${range[1]}` : "";
  const selectRange = useCallback((r: [number, number] | null) => {
    setRange(r);
    setFlowOffset(0);
    setLadderOffset(0);
    setEvents(null);
  }, []);

  const [overlay, setOverlay] = useState<TopologyOverlay | null>(null);
  const [inspection, setInspection] = useState<{
    findings: Finding[];
    flows: { total: number; items: Flow[] };
  } | null>(null);
  const [inspectQuery, setInspectQuery] = useState<string | null>(null);
  const [state, setState] = useState<State | null>(null),
    [tab, setTab] = useState(
      new URLSearchParams(location.search).get("view") === "Path"
        ? "Path"
        : "Overview",
    ),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [job, setJob] = useState<Job>({ state: "idle", busy: false }),
    [topology, setTopology] = useState<Topology | null>(null),
    [evidence, setEvidence] = useState<Ref[] | null>(null),
    [path, setPath] = useState(""),
    [projectPath, setProjectPath] = useState(""),
    [uploadPercent, setUploadPercent] = useState<number | null>(null);
  const [flows, setFlows] = useState<{ total: number; items: Flow[] }>({
      total: 0,
      items: [],
    }),
    [flowOffset, setFlowOffset] = useState(0),
    [search, setSearch] = useState(""),
    [filter, setFilter] = useState(""),
    [sort, setSort] = useState("bytes"),
    [selectedFlow, setSelectedFlow] = useState<Flow | null>(null),
    [ladder, setLadder] = useState<Ladder | null>(null),
    [ladderOffset, setLadderOffset] = useState(0);
  const [fieldDiff, setFieldDiff] = useState<FieldDiffData | null>(null);
  const [events, setEvents] = useState<{
    label: string;
    items: {
      id: string;
      kind: string;
      reason: string;
      ts: number;
      recovery_ms: number | null;
      evidence: Ref[];
    }[];
    total: number;
    segment: Segment;
    offset: number;
  } | null>(null);
  const [parallelIngest, setParallelIngest] = useState(false);
  const [memoryLimit, setMemoryLimit] = useState("");
  const [checkpointUuid, setCheckpointUuid] = useState(false);
  const [f5Trailer, setF5Trailer] = useState(false);
  const [assistantEnabled, setAssistantEnabled] = useState(false);
  const [fortiPath, setFortiPath] = useState("");
  const [fortiStart, setFortiStart] = useState("");
  const [fortiDevice, setFortiDevice] = useState("FortiGate");
  const [tsharkPath, setTsharkPath] = useState(""),
    [prefix, setPrefix] = useState(64);
  useEffect(() => {
    setRange(null);
    setSeries(null);
    if (!state?.report) return;
    let active = true;
    api<TimeSeries>("/timeseries")
      .then((s) => {
        if (active && s.bucket_count) setSeries(s);
      })
      .catch(fail);
    return () => {
      active = false;
    };
  }, [state?.report]);
  useEffect(() => {
    setRangeFindings(null);
    if (!range || !state?.report) return;
    let active = true;
    api<{ items: Finding[] }>(`/findings?start=${range[0]}&end=${range[1]}`)
      .then((r) => {
        if (active) setRangeFindings(r.items);
      })
      .catch(fail);
    return () => {
      active = false;
    };
  }, [range, state?.report]);
  async function refresh() {
    const s = await api<State>("/state");
    setState(s);
    setTopology(s.topology);
    setJob(s.job);
    setProjectPath(s.project);
    setTsharkPath(s.settings.tshark || "");
    setPrefix(s.settings.prefix_bytes || 64);
    setParallelIngest(s.settings.parallel ?? false);
    setMemoryLimit(
      s.settings.memory_limit_mb == null
        ? ""
        : String(s.settings.memory_limit_mb),
    );
    setCheckpointUuid(s.settings.checkpoint_uuid ?? false);
    setF5Trailer(s.settings.f5_trailer ?? false);
    setAssistantEnabled(s.settings.assistant_enabled ?? false);
  }
  const fail = (e: unknown) =>
    setError(e instanceof Error ? e.message : String(e));
  useEffect(() => {
    refresh().catch(fail);
  }, []);
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [tab]);
  useEffect(() => {
    if (!job.busy) return;
    const id = setInterval(() => {
      api<Job>("/jobs")
        .then((j) => {
          setJob(j);
          if (!j.busy) {
            if (j.error) setError(j.error);
            refresh().catch(fail);
          }
        })
        .catch(fail);
    }, 700);
    return () => clearInterval(id);
  }, [job.busy]);
  useEffect(() => {
    if (!state?.report) {
      setFlows({ total: 0, items: [] });
      setSelectedFlow(null);
      setLadder(null);
      setEvents(null);
      return;
    }
    if (job.busy) return;
    let active = true;
    const timer = setTimeout(
      () =>
        api<{ total: number; items: Flow[] }>(
          `/flows?offset=${flowOffset}&search=${encodeURIComponent(search)}&filter_by=${filter}&sort=${sort}${rangeQuery}`,
        )
          .then((r) => {
            if (active) setFlows(r);
          })
          .catch(fail),
      150,
    );
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [state?.report, flowOffset, search, filter, sort, job.busy, rangeQuery]);
  useEffect(() => {
    if (!selectedFlow) return;
    let active = true;
    api<Ladder>(
      `/flows/${selectedFlow.flow}/ladder?offset=${ladderOffset}${rangeQuery}`,
    )
      .then((r) => {
        if (active) setLadder(r);
      })
      .catch(fail);
    return () => {
      active = false;
    };
  }, [selectedFlow, ladderOffset, rangeQuery]);
  useEffect(() => {
    let active = true;
    setOverlay(null);
    setInspection(null);
    if (!state?.report || job.busy || tab !== "Path") return;
    api<TopologyOverlay>(`/topology/overlay?${rangeQuery}`)
      .then((r) => {
        if (active) setOverlay(r);
      })
      .catch(fail);
    if (inspectQuery)
      api<{ findings: Finding[]; flows: { total: number; items: Flow[] } }>(
        `/topology/inspect?${inspectQuery}${rangeQuery}`,
      )
        .then((r) => {
          if (active) setInspection(r);
        })
        .catch(fail);
    return () => {
      active = false;
    };
  }, [state?.report, rangeQuery, inspectQuery, job.busy, tab]);
  useEffect(() => setFieldDiff(null), [selectedFlow, rangeQuery]);
  async function action(fn: () => Promise<unknown>) {
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (e) {
      fail(e);
    }
  }
  async function downloadReport(format: "html" | "json") {
    const response = await fetch(`/api/export?format=${format}`);
    if (!response.ok)
      throw new Error((await response.json()).detail || "Export failed");
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = `packetbreaker-report.${format}`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice(
      "Exported the complete saved analysis window (independent of the heatmap brush).",
    );
  }
  async function saveTopology(t: Topology) {
    const saved = await api<Topology>("/topology", "PUT", t);
    setTopology(saved);
    setState((s) =>
      s ? { ...s, topology: saved, suggested_topology: null, report: null } : s,
    );
    setNotice("Topology saved. Run analysis to refresh results.");
  }
  async function analyzeTopology(t: Topology) {
    setSelectedFlow(null);
    setLadder(null);
    setEvents(null);
    setJob(
      await api<Job>("/analyze", "POST", {
        ...t,
        report_timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      }),
    );
  }
  async function analyze() {
    if (!topology) return;
    await analyzeTopology(topology);
  }
  async function editTopology(t: Topology) {
    setTopology(t);
    const pending =
      (state?.suggested_topology || state?.report?.suggested_topology) &&
      !(state?.suggested_topology || state?.report?.suggested_topology)
        ?.confirmed;
    if (pending && t.forward.length >= 2 && !job.busy) {
      await analyzeTopology(t);
    }
  }
  async function assembleSuggestedTopology() {
    const res = await api<{
      suggested_topology: NonNullable<State["suggested_topology"]>;
      topology: Topology;
      report: State["report"];
    }>("/topology/assemble", "POST", {});
    setTopology(res.topology);
    setState((s) =>
      s ? { ...s, suggested_topology: res.suggested_topology, topology: res.topology, report: res.report } : s,
    );
    if (res.suggested_topology.ambiguous) {
      setError(res.suggested_topology.reason || "Suggested path order is ambiguous; assign the path manually.");
    } else {
      setNotice(res.suggested_topology.badge || "Suggested topology — review & confirm");
    }
  }
  async function confirmSuggestedTopology(group?: string) {
    const res = await api<{
      confirmed: boolean;
      suggested_topology: NonNullable<State["suggested_topology"]>;
      topology: Topology;
      report?: State["report"];
    }>("/topology/confirm", "POST", group ? { group } : {});
    if (res.topology) setTopology(res.topology);
    setState((s) =>
      s
        ? {
            ...s,
            topology: res.topology || s.topology,
            suggested_topology: res.suggested_topology,
            report: res.report ?? (s.report ? { ...s.report, suggested_topology: res.suggested_topology } : null),
          }
        : s,
    );
    setNotice(group ? `Suggested topology confirmed for ${group}.` : "Suggested topology confirmed.");
  }
  function selectSuggestedGroup(g: import("./types").SuggestedTopologyGroup) {
    setTopology(g.topology);
    if (g.report) {
      setState((s) =>
        s
          ? {
              ...s,
              topology: g.topology,
              report: { ...g.report!, suggested_topology: s.suggested_topology || g.report!.suggested_topology },
            }
          : s,
      );
    }
    setNotice(`Showing analysis for client path ${g.name}.`);
  }
  async function upload(files: FileList | null) {
    if (!files?.length) return;
    setUploadPercent(0);
    const paths: string[] = [];
    try {
      for (const f of Array.from(files)) {
        await new Promise<void>((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.open("POST", "/api/captures/upload?defer=true&name=" + encodeURIComponent(f.name));
          xhr.setRequestHeader("X-PacketBreaker", "local");
          xhr.upload.onprogress = (e) =>
            setUploadPercent(e.lengthComputable ? Math.round((e.loaded / e.total) * 100) : 0);
          xhr.onload = () => {
            if (xhr.status < 300) {
              paths.push(JSON.parse(xhr.responseText).path);
              resolve();
            } else reject(new Error(xhr.responseText));
          };
          xhr.onerror = () => {
            setUploadPercent(null);
            reject(new Error("Upload failed"));
          };
          xhr.send(f);
        });
      }
      setJob(await api<Job>("/captures/attach", "POST", { paths }));
    } finally {
      setUploadPercent(null);
    }
  }
  async function showEvents(s: Segment, offset = 0) {
    const page = await api<{ items: NonNullable<typeof events>["items"]; total: number }>(
      `/events?a=${s.point_a}&b=${s.point_b}&direction=${s.direction}&offset=${offset}${rangeQuery}`,
    );
    setEvents({ label: s.label, ...page, segment: s, offset });
  }
  const report = state?.report ?? null;
  const visibleFindings = range ? rangeFindings || [] : report?.findings || [];
  const ready = state?.captures.filter((c) => c.state === "ready").length ?? 0;
  const kinds =
    report?.findings.reduce((acc, f) => {
      acc[f.type] = (acc[f.type] || 0) + f.metrics.count;
      return acc;
    }, {} as Record<string, number>) || {};
  const busy = job.busy || uploadPercent !== null;
  return {
    series, setSeries, range, setRange, rangeFindings, setRangeFindings, rangeQuery, selectRange,
    overlay, setOverlay, inspection, setInspection, inspectQuery, setInspectQuery, state, setState,
    tab, setTab, error, setError, notice, setNotice, job, setJob, topology, setTopology,
    evidence, setEvidence, path, setPath, projectPath, setProjectPath, uploadPercent, setUploadPercent,
    flows, setFlows, flowOffset, setFlowOffset, search, setSearch, filter, setFilter, sort, setSort,
    selectedFlow, setSelectedFlow, ladder, setLadder, ladderOffset, setLadderOffset, fieldDiff, setFieldDiff,
    events, setEvents, parallelIngest, setParallelIngest, memoryLimit, setMemoryLimit,
    checkpointUuid, setCheckpointUuid, f5Trailer, setF5Trailer, assistantEnabled, setAssistantEnabled,
    fortiPath, setFortiPath, fortiStart, setFortiStart, fortiDevice, setFortiDevice,
    tsharkPath, setTsharkPath, prefix, setPrefix, refresh, fail, action, downloadReport,
    saveTopology, editTopology, assembleSuggestedTopology, confirmSuggestedTopology, selectSuggestedGroup,
    analyze, upload, showEvents, report, visibleFindings, ready, kinds, busy,
  };
}
export type Workspace = ReturnType<typeof useWorkspaceController>;
