import { useWorkspace } from "./WorkspaceContext";
import { num } from "./api";
import { segmentHealth, boundaryTitle } from "./overviewModel";
export function PathHealth() {
  const {
    report,
    topology,
    setInspectQuery,
    setTab,
    setEvents,
    action,
    showEvents,
  } = useWorkspace();
  if (!report) return null;
  return (
    <div className="path-health">
      <div className="path-health-points">
        {topology.forward.map((id, i) => {
          const point = topology.points.find((p) => p.id === id);
          const segment = report.segments.find(
            (s) => s.point_a === id && s.direction === "forward",
          );
          const health = segment
            ? segmentHealth(segment, topology)
            : "endpoint";
          return (
            <div key={id} className="path-health-step">
              <button
                className={"path-point " + health}
                onClick={() => {
                  setInspectQuery(`point=${encodeURIComponent(id)}`);
                  setTab("Path");
                }}
                title="Open this capture point's findings and flows"
              >
                <strong>{point?.label || id}</strong>
                <small>{point?.device}</small>
              </button>
              {segment && (
                <button
                  className={"path-arrow " + health}
                  onClick={() =>
                    action(async () => {
                      await showEvents(segment);
                      const panel = document.getElementById(
                        "path-findings",
                      ) as HTMLDetailsElement | null;
                      if (panel) panel.open = true;
                      requestAnimationFrame(() =>
                        document
                          .getElementById("selected-segment")
                          ?.scrollIntoView({
                            behavior: "smooth",
                            block: "start",
                          }),
                      );
                    })
                  }
                  title={`${boundaryTitle(segment.id, topology)}; ${health}. Click to inspect findings/frames. Max ${num(segment.max_ms)} ms; p95 ${num(segment.p95_ms)} ms; loss ${num(segment.loss_percent)}%${segment.reason ? " — " + segment.reason : ""}`}
                >
                  →<small>max {num(segment.max_ms)} ms</small>
                  <small>
                    p95 {num(segment.p95_ms)} ms · {num(segment.loss_percent)}%
                    loss
                  </small>
                </button>
              )}
            </div>
          );
        })}
      </div>
      <p className="hint">
        Green: clean observed · red: supported loss or high transit · grey:
        unknown. Capture order is the saved topology; return-path details remain
        in the segment table. Full-window strip.
      </p>
    </div>
  );
}
