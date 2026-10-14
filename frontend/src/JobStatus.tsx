














import {api,num} from "./api";









import type {Job} from "./types";

import {useWorkspace} from "./WorkspaceContext";


export function JobStatus() {
  const {
    state,
    error,
    setError,
    notice,
    job,
    setJob,
    path,
    uploadPercent,
    action,
    ready,
    busy,
  } = useWorkspace();
  return (
    <>
      {error && (
        <div className="alert" role="alert">
          {error}
          <button onClick={() => setError("")}>Dismiss</button>
        </div>
      )}
      {notice && <div className="notice">{notice}</div>}
      {state.tshark.error && <div className="alert">{state.tshark.error}</div>}
      {busy && (
        <div className="job-bar" role="status">
          <div className="spinner" />
          <strong>
            {uploadPercent !== null
              ? `Uploading · ${uploadPercent}%`
              : job.state}
          </strong>
          <span>
            {job.file}{" "}
            {job.frames != null ? `· ${num(job.frames, " frames", 0)}` : ""}{" "}
            {job.file_count
              ? `· ${job.file_count} files · ${job.workers ?? 1} workers`
              : ""}
          </span>
          {job.kind === "ingest" && job.busy && (
            <button
              className="secondary"
              onClick={() => action(() => api("/jobs/cancel", "POST"))}
            >
              Cancel ingest
            </button>
          )}
        </div>
      )}
      {job.kind === "ingest" && !!job.files?.length && (
        <section style={{ margin: "18px 38px" }}>
          <h2>File ingest progress</h2>
          {job.files.map((f) => (
            <div className="mapping" key={f.file_id}>
              <div>
                <strong>{f.file}</strong>
                <small>
                  {" "}
                  · {f.state} · {num(f.usable_packets ?? f.frames, "", 0)}{" "}
                  {f.usable_packets == null ? "frames read" : "usable packets"}
                </small>
                {f.error && <p className="red">{f.error}</p>}
                {f.warnings?.map((w) => (
                  <p className="hint" key={w}>
                    {w}
                  </p>
                ))}
              </div>
              {job.busy &&
                !["ready", "cached", "cancelled", "error"].includes(
                  f.state,
                ) && (
                  <button
                    className="secondary"
                    onClick={() =>
                      action(() =>
                        api("/jobs/cancel", "POST", { file_id: f.file_id }),
                      )
                    }
                  >
                    Cancel file
                  </button>
                )}
              {!job.busy && ["cancelled", "error"].includes(f.state) && (
                <button
                  onClick={() =>
                    action(async () =>
                      setJob(
                        await api<Job>("/captures/attach", "POST", {
                          paths: [f.path],
                        }),
                      ),
                    )
                  }
                >
                  Resume file
                </button>
              )}
            </div>
          ))}
        </section>
      )}
    </>
  );
}
