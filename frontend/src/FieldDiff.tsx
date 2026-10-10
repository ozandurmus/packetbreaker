import type { Ref } from "./types";

export type FieldDiffData = {
  note: string;
  items: {
    location: string;
    tooltip: string;
    packet_key: string;
    fields: Record<string, { before: unknown; after: unknown; status: string }>;
    evidence: Ref[];
  }[];
};

export function FieldDiff({
  data,
  onEvidence,
}: {
  data: FieldDiffData;
  onEvidence: (refs: Ref[]) => void;
}) {
  const value = (v: unknown) =>
    v == null ? "unknown / not applicable" : String(v);
  return (
    <section className="card">
      <h3>Matched packet field differences</h3>
      <p>{data.note}</p>
      {data.items.map((item, i) => (
        <details key={i} open>
          <summary title={item.tooltip}>{item.location}</summary>
          <p>{item.tooltip}</p>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Field</th>
                  <th>Before</th>
                  <th>After</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(item.fields).map(([name, field]) => (
                  <tr key={name}>
                    <th>{name.replaceAll("_", " ")}</th>
                    <td style={{ overflowWrap: "anywhere" }}>
                      {value(field.before)}
                    </td>
                    <td style={{ overflowWrap: "anywhere" }}>
                      {value(field.after)}
                    </td>
                    <td>
                      <strong>{field.status}</strong>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <button onClick={() => onEvidence(item.evidence)}>
            Evidence frames and filters
          </button>
        </details>
      ))}
    </section>
  );
}
