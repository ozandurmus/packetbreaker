



import {TopologySuggestions} from "./TopologySuggestions";


import {CasePreflight} from "./CasePreflight";







import {num,reverseTuple} from "./api";








import {TopologyEditor} from "./TopologyEditor";


import {useWorkspace} from "./WorkspaceContext";
import {Badge} from "./UI";

export function PathView() {
  const {
    range,
    overlay,
    inspection,
    setInspectQuery,
    state,
    setTab,
    setError,
    topology,
    setTopology,
    evidence,
    setEvidence,
    flows,
    filter,
    setSelectedFlow,
    setLadderOffset,
    action,
    saveTopology,
    editTopology,
    assembleSuggestedTopology,
    confirmSuggestedTopology,
    selectSuggestedGroup,
    report,
    busy,
  } = useWorkspace();
  if (!state || !topology) return null;
  const suggested = state.suggested_topology || report?.suggested_topology;
  return (
    <>
      <CasePreflight state={state} />
      <p className="hint">
        Topology overlay:{" "}
        {range ? "selected heatmap interval" : "full analysis window"}.{" "}
        {overlay?.note}
      </p>
      {inspection && (
        <section>
          <h2>Selected device / arrow</h2>
          <p>
            {inspection.flows.total} associated conversations (first 50 listed)
          </p>
          {inspection.findings.map((f) => (
            <div key={f.id}>
              <span>{f.summary}</span>{" "}
              <button onClick={() => setEvidence(f.evidence)}>Evidence</button>
            </div>
          ))}
          {inspection.flows.items.map((f) => (
            <button
              className="secondary"
              key={f.flow}
              onClick={() => {
                setSelectedFlow(f);
                setTab("Flows");
                setLadderOffset(0);
              }}
            >
              {f.tuple}
            </button>
          ))}
          {!inspection.findings.length && (
            <p>No findings in this selected range.</p>
          )}
        </section>
      )}

      <TopologySuggestions
        topology={topology}
        captures={state.captures}
        suggested={suggested}
        onAssemble={() => action(assembleSuggestedTopology)}
        onConfirmSuggested={(g) => action(() => confirmSuggestedTopology(g))}
        onSelectGroup={selectSuggestedGroup}
        onChange={(t) => void editTopology(t)}
        onEvidence={setEvidence}
      />
      <section>
        <TopologyEditor
          topology={topology}
          captures={state.captures}
          report={report}
          overlay={overlay}
          onInspect={setInspectQuery}
          onChange={(t) => void editTopology(t)}
          onSave={(t) => action(() => saveTopology(t))}
          onError={setError}
        />
      </section>
      <section>
        <div className="section-head">
          <h2>Translation mappings</h2>
          <small>
            Confirmed mappings combine the two 5-tuples and their reverse
            direction.
          </small>
        </div>
        {report?.nat_suggestions.length ? (
          <>
            {report.nat_suggestions.map((s, i) => (
              <div className="mapping" key={i}>
                <div>
                  <Badge>{num(s.samples, " matching packets", 0)}</Badge>
                  <code>{s.tuple_a}</code>
                  <span>↓</span>
                  <code>{s.tuple_b}</code>
                </div>
                <button
                  disabled={topology.nat_mappings.some(
                    (m) =>
                      m.point_a === s.point_a &&
                      m.point_b === s.point_b &&
                      ((m.tuple_a === s.tuple_a && m.tuple_b === s.tuple_b) ||
                        (reverseTuple(m.tuple_a) === s.tuple_a &&
                          reverseTuple(m.tuple_b) === s.tuple_b)),
                  )}
                  onClick={() =>
                    setTopology({
                      ...topology,
                      nat_mappings: [...topology.nat_mappings, s],
                    })
                  }
                >
                  Confirm mapping
                </button>
                <button
                  className="secondary"
                  onClick={() => setEvidence(s.evidence || [])}
                >
                  Evidence
                </button>
              </div>
            ))}
          </>
        ) : (
          <p className="hint">
            Declare both sides of a device as NAT and run analysis to learn
            candidates. Candidates remain unapplied until confirmed.
          </p>
        )}
        {topology.nat_mappings.map((m, i) => (
          <div className="mapping" key={i}>
            <Badge kind="good">Confirmed</Badge>
            <div>
              <input
                aria-label="Original tuple"
                value={m.tuple_a}
                onChange={(e) =>
                  setTopology({
                    ...topology,
                    nat_mappings: topology.nat_mappings.map((x, j) =>
                      i === j ? { ...x, tuple_a: e.target.value } : x,
                    ),
                  })
                }
              />
              <input
                aria-label="Translated tuple"
                value={m.tuple_b}
                onChange={(e) =>
                  setTopology({
                    ...topology,
                    nat_mappings: topology.nat_mappings.map((x, j) =>
                      i === j ? { ...x, tuple_b: e.target.value } : x,
                    ),
                  })
                }
              />
            </div>
            <button
              className="secondary"
              onClick={() =>
                setTopology({
                  ...topology,
                  nat_mappings: topology.nat_mappings.filter((_, j) => i !== j),
                })
              }
            >
              Remove
            </button>
          </div>
        ))}
        <button
          disabled={busy}
          onClick={() => action(() => saveTopology(topology))}
        >
          Save mapping decisions
        </button>
      </section>
    </>
  );
}
