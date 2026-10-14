import { useState } from "react";
import { useWorkspace } from "./WorkspaceContext";
import { ResultCard } from "./ResultCard";
import { PathHealth } from "./PathHealth";
import { IncidentTimeline } from "./IncidentTimeline";
import { CycleAddedChart } from "./CycleAddedChart";
import { HoldReleaseView } from "./HoldReleaseView";
import { EvidenceQualityCharts } from "./EvidenceQualityCharts";
import { FindingDetails } from "./FindingDetails";
import { CoverageDetails } from "./CoverageDetails";
import { ProtocolDiagnostics } from "./ProtocolDiagnostics";
import { CaptureQualityCards } from "./CaptureQualityCards";
import { CaptureNotes } from "./CaptureNotes";
import { Cycles } from "./Cycles";
import { HostPath } from "./HostPath";
import { ReferenceCompare } from "./ReferenceCompare";
import { Sessions } from "./Sessions";
import { Microbursts } from "./Microbursts";
import { SuggestedTopologyBanner } from "./TopologySuggestions";
import type { ReactNode } from "react";
export function OverviewView() {
  const {
    state,
    report,
    range,
    selectRange,
    setEvidence,
    action,
    confirmSuggestedTopology,
    selectSuggestedGroup,
  } = useWorkspace();
  const [open, setOpen] = useState<Record<string, boolean>>({
    timeline: true,
    path: true,
    cycles: false,
    quality: false,
  });
  if (!report)
    return (
      <>
        <FindingDetails />
        <CoverageDetails />
      </>
    );
  function jump(id: string) {
    setOpen((s) => ({ ...s, [id]: true }));
    requestAnimationFrame(() =>
      document
        .getElementById("overview-" + id)
        ?.scrollIntoView({ behavior: "instant", block: "start" }),
    );
  }
  function section(id: string, label: string, children: ReactNode) {
    return (
      <details
        id={"overview-" + id}
        className="overview-section"
        open={open[id]}
        onToggle={(e) => {
          const value = e.currentTarget.open;
          setOpen((s) => (s[id] === value ? s : { ...s, [id]: value }));
        }}
      >
        <summary>
          <h2>{label}</h2>
        </summary>
        {open[id] && <div className="overview-section-body">{children}</div>}
      </details>
    );
  }
  const suggested = state?.suggested_topology || report.suggested_topology;
  return (
    <div className="overview">
      <nav className="overview-nav" aria-label="Overview sections">
        {["summary", "timeline", "path", "cycles", "quality"].map((id) => (
          <button key={id} onClick={() => jump(id)}>
            {id === "quality"
              ? "Evidence quality"
              : id[0].toUpperCase() + id.slice(1)}
          </button>
        ))}
      </nav>
      <SuggestedTopologyBanner
        suggested={suggested}
        captures={state?.captures || []}
        onConfirm={(g) => action(() => confirmSuggestedTopology(g))}
        onSelectGroup={selectSuggestedGroup}
        onEvidence={setEvidence}
      />
      <ResultCard />
      {section("timeline", "Timeline", <IncidentTimeline />)}
      {section(
        "path",
        "Path",
        <>
          <PathHealth />
          <details id="path-findings">
            <summary>Findings and per-segment evidence</summary>
            <FindingDetails />
          </details>
        </>,
      )}
      {section(
        "cycles",
        "Cycles",
        <>
          <h3>Where was the time added?</h3>
          <CycleAddedChart />
          <h3>Hold and release</h3>
          <HoldReleaseView />
          <details>
            <summary>Opaque TCP cycles — table, periods and exports</summary>
            <Cycles
              data={report.cycles}
              delivery={report.delivery}
              range={range}
              onSelect={selectRange}
              onEvidence={setEvidence}
            />
          </details>
          <details>
            <summary>Host receive / transmit flow detail</summary>
            <HostPath data={report.host_path} onEvidence={setEvidence} />
          </details>
        </>,
      )}
      {section(
        "quality",
        "Evidence quality",
        <>
          <CaptureQualityCards />
          <CaptureNotes />
          <details open>
            <summary>Delay/drop and mismatch evidence</summary>
            <EvidenceQualityCharts />
          </details>
          <details>
            <summary>Capture coverage and interpretation limits</summary>
            <CoverageDetails />
          </details>
          <details>
            <summary>Protocol, translation and onset details</summary>
            <ProtocolDiagnostics />
          </details>
          <details>
            <summary>Session and microburst details</summary>
            <Sessions data={report.sessions} onEvidence={setEvidence} />
            {report.microbursts && (
              <Microbursts data={report.microbursts} onEvidence={setEvidence} />
            )}
          </details>
          <details>
            <summary>Reference / run comparison</summary>
            <ReferenceCompare report={report} />
          </details>
        </>,
      )}
    </div>
  );
}
