


























import {useWorkspace} from "./WorkspaceContext";


export function SelectionBanner() {
  const { range, selectRange, ladder } = useWorkspace();
  return (
    <>
      {range && (
        <section>
          <strong>
            Selected interval: {new Date(range[0] * 1000).toISOString()} –{" "}
            {new Date(range[1] * 1000).toISOString()}
          </strong>
          <p className="hint">
            Flows, findings and ladder are filtered to this half-open interval.
            Flow totals describe the complete analysis; onset estimates use the
            full baseline.
          </p>
          <button onClick={() => selectRange(null)}>Clear selection</button>
        </section>
      )}
    </>
  );
}
