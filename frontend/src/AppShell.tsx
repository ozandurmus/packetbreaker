import { CaptureNotes } from "./CaptureNotes";

import { AnonymizeExport } from "./AnonymizeExport";

import { UdpMedia } from "./UdpMedia";

import { DNS } from "./DNS";

import { useWorkspace } from "./WorkspaceContext";
import { Badge } from "./UI";

import { Evidence } from "./UI";
import { JobStatus } from "./JobStatus";
import { SelectionBanner } from "./SelectionBanner";
import { OverviewView } from "./OverviewView";
import { CapturesView } from "./CapturesView";
import { PathView } from "./PathView";
import { FlowsView } from "./FlowsView";
import { SettingsView } from "./SettingsView";
export function AppShell() {
  const {
    rangeQuery,
    state,
    tab,
    setTab,
    topology,
    evidence,
    setEvidence,
    path,
    action,
    downloadReport,
    analyze,
    report,
    ready,
    busy,
  } = useWorkspace();
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">P↯</div>
          <div>
            PacketBreaker<small>FOLLOW THE PACKET</small>
          </div>
        </div>
        <div className="workspace-label">LOCAL WORKSPACE</div>
        <nav>
          {[
            "Overview",
            "Captures",
            "Path",
            "Flows",
            "DNS",
            "UDP / Media",
            "Settings",
          ].map((x, i) => (
            <button
              key={x}
              className={tab === x ? "active" : ""}
              onClick={() => setTab(x)}
            >
              <span>{["◈", "▤", "⌘", "≋", "⇄", "⚙"][i]}</span>
              {x}
              {x === "Captures" && <b>{state.captures.length}</b>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="local-dot" /> Local processing only
          <p>
            No cloud. No telemetry.
            <br />
            Your captures stay on this computer.
          </p>
          <small>PHASE 4 / PART 2 · v{state.version}</small>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <div className="breadcrumbs">
              Workspace <span>/</span> {state.project.split(/[\\/]/).pop()}
            </div>
            <h1>
              {tab === "Overview"
                ? "Path investigation"
                : tab === "Captures"
                  ? "Capture inventory"
                  : tab === "Path"
                    ? "Map the traffic path"
                    : tab === "Flows"
                      ? "Follow a conversation"
                      : tab === "DNS"
                        ? "DNS investigation"
                        : "Workspace settings"}
            </h1>
            <p>
              {tab === "Overview"
                ? "Find where the evidence changes, one capture point at a time."
                : tab === "Captures"
                  ? "Understand capture quality before interpreting the network."
                  : tab === "Path"
                    ? "Your diagram is the authority. Connect capture points in traffic order."
                    : tab === "Flows"
                      ? "Trace packets across every point and verify the original frames."
                      : tab === "DNS"
                        ? "Separate resolver turnaround from query or response disappearance."
                        : "Local tools, analysis thresholds and clock overrides."}
            </p>
          </div>
          <div className="header-actions">
            <AnonymizeExport disabled={busy || ready < 1} />
            <Badge kind="neutral">● OFFLINE</Badge>
            <button
              className="secondary"
              disabled={busy || !report}
              onClick={() => action(() => downloadReport("html"))}
            >
              Export HTML
            </button>
            <button
              className="secondary"
              disabled={busy || !report}
              onClick={() => action(() => downloadReport("json"))}
            >
              Export JSON
            </button>
            <button
              disabled={
                busy ||
                ready < 1 ||
                (topology.forward.length < 2 &&
                  !topology.points.some(
                    (p) => p.vendor === "paloalto" && p.vendor_stage === "drop",
                  ))
              }
              onClick={() => action(analyze)}
            >
              ▶ Analyze path
            </button>
          </div>
        </header>
        <JobStatus />
        <div className="content">
          <SelectionBanner />
          {tab !== "Overview" && <CaptureNotes />}
          {tab === "Overview" && <OverviewView />}
          {tab === "Captures" && <CapturesView />}
          {tab === "Path" && <PathView />}
          {tab === "Flows" && <FlowsView />}
          {tab === "Settings" && <SettingsView />}
          {tab === "DNS" && (
            <DNS rangeQuery={rangeQuery} onEvidence={setEvidence} />
          )}
          {tab === "UDP / Media" && (
            <UdpMedia
              udp={report?.udp}
              rtp={report?.rtp}
              sip={report?.sip}
              onEvidence={setEvidence}
            />
          )}
        </div>
        <footer>
          PacketBreaker <span>Evidence first. Uncertainty visible.</span>
          <span>All analysis stays on this computer.</span>
        </footer>
      </main>
      {evidence && (
        <Evidence refs={evidence} onClose={() => setEvidence(null)} />
      )}
    </div>
  );
}
