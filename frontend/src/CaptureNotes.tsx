import { useWorkspace } from "./WorkspaceContext";
export function CaptureNotes() {
  const { report } = useWorkspace();
  return (
    <>
      {" "}
      {report?.fragment_points?.map((p) => (
        <p className="hint" key={p.point + p.status}>
          {p.point}: {p.datagrams} IP datagrams from {p.physical_fragments}{" "}
          fragments — {p.status}.
          {p.status !== "complete" &&
            " Reassembly evidence incomplete or ambiguous; no guessed packet identity."}
        </p>
      ))}
      {report?.tunnel_points?.map((p) => (
        <p className="hint" key={p.point}>
          {p.point}: tunnel layer{" "}
          {p.layer || "unknown — choose inner or outer in Path"}; {p.selected}{" "}
          selected, {p.unselected} unselected.
          {p.truncated_inner > 0 && (
            <strong>
              {" "}
              ERSPAN/inner payload truncation: {p.truncated_inner} observations;
              full payload unavailable.
            </strong>
          )}
        </p>
      ))}
    </>
  );
}
