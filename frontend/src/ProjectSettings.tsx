














import {api} from "./api";











import {useWorkspace} from "./WorkspaceContext";
import {Tip} from "./UI";

export function ProjectSettings() {
  const {
    state,
    setNotice,
    path,
    projectPath,
    setProjectPath,
    setSelectedFlow,
    parallelIngest,
    setParallelIngest,
    memoryLimit,
    setMemoryLimit,
    checkpointUuid,
    setCheckpointUuid,
    f5Trailer,
    setF5Trailer,
    assistantEnabled,
    setAssistantEnabled,
    tsharkPath,
    setTsharkPath,
    prefix,
    setPrefix,
    refresh,
    action,
    busy,
  } = useWorkspace();
  return (
    <>
      <section>
        <h2>Project directory</h2>
        <p className="hint">
          Create a project in an empty directory or reopen an existing project.
          Completed captures are cached in its DuckDB file.
        </p>
        <div className="toolbar">
          <input
            aria-label="Project directory"
            value={projectPath}
            onChange={(e) => setProjectPath(e.target.value)}
          />
          <button
            disabled={busy}
            onClick={() =>
              action(async () => {
                await api("/project", "POST", { path: projectPath });
                await refresh();
                setSelectedFlow(null);
              })
            }
          >
            Open / create project
          </button>
        </div>
      </section>
      <section>
        <h2>Packet dissection</h2>
        <label>
          <input
            type="checkbox"
            checked={parallelIngest}
            onChange={(e) => setParallelIngest(e.target.checked)}
          />{" "}
          Parallel ingest (optional)
        </label>
        <p className="hint">
          Serial is the measured default. Parallel uses spare CPU/RAM, but did
          not reach 1.5× speedup in the equal-file benchmark.
        </p>
        <p className="hint">Detected: {state.tshark.path || "unknown"}</p>
        <label>
          <input
            type="checkbox"
            checked={checkpointUuid}
            onChange={(e) => setCheckpointUuid(e.target.checked)}
          />
          fw monitor file includes UUID (-u); reattach after changing
        </label>
        <label>
          <input
            type="checkbox"
            checked={f5Trailer}
            onChange={(e) => setF5Trailer(e.target.checked)}
          />
          Decode F5 TMM trailer and request metadata; reattach after changing
        </label>
        <label>
          tshark override (blank = auto-detect)
          <input
            value={tsharkPath}
            onChange={(e) => setTsharkPath(e.target.value)}
          />
        </label>
        <label>
          <Tip text="Maximum captured L4 payload prefix stored for matching. Reattach existing files after changing this value to rebuild their cache.">
            Payload prefix bytes
          </Tip>
          <input
            type="number"
            min="8"
            max="4096"
            value={prefix}
            onChange={(e) => setPrefix(Number(e.target.value))}
          />
        </label>
        <label>
          DuckDB memory limit (MiB; blank = automatic 25% RAM, 1–8 GiB)
          <input
            type="number"
            min="64"
            value={memoryLimit}
            onChange={(e) => setMemoryLimit(e.target.value)}
          />
        </label>
        <button
          disabled={busy}
          onClick={() =>
            action(async () => {
              await api("/settings", "POST", {
                ...state.settings,
                tshark: tsharkPath || null,
                prefix_bytes: prefix,
                parallel: parallelIngest,
                memory_limit_mb:
                  memoryLimit === "" ? null : Number(memoryLimit),
                checkpoint_uuid: checkpointUuid,
                f5_trailer: f5Trailer,
                assistant_enabled: assistantEnabled,
              });
              setNotice(
                "Settings saved. Reattach files to apply a changed payload prefix.",
              );
              await refresh();
            })
          }
        >
          Save settings
        </button>
        <label title="Enable a local redaction preview only; no assistant connection is implemented.">
          <input
            type="checkbox"
            checked={assistantEnabled}
            onChange={(e) => setAssistantEnabled(e.target.checked)}
          />
          Enable Ask an assistant placeholder (off by default)
        </label>
      </section>
    </>
  );
}
