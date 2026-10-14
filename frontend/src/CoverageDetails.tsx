






















import {Coverage} from "./Charts";



import {useWorkspace} from "./WorkspaceContext";
import {Badge} from "./UI";

export function CoverageDetails() {
  const { state, report } = useWorkspace();
  return (
    <>
      <section>
        <div className="section-head">
          <h2>Capture coverage</h2>
          <Badge>{report ? "CLOCK CORRECTED" : "OBSERVED TIME"}</Badge>
        </div>
        <Coverage captures={state.captures} report={report} />
      </section>
      {report && (
        <details>
          <summary>Interpretation limits</summary>
          {report.limitations.map((l) => (
            <p key={l}>{l}</p>
          ))}
          <p>{report.scope}</p>
        </details>
      )}
    </>
  );
}
