import React from "react";
import { createRoot } from "react-dom/client";
import { useWorkspaceController } from "./workspace";
import { WorkspaceContext } from "./WorkspaceContext";
import { AppShell } from "./AppShell";
import "./style.css";
function App() {
  const value = useWorkspaceController();
  if (!value.state || !value.topology)
    return (
      <div className="loading">
        <div className="brand-mark">P↯</div>
        <h1>PacketBreaker</h1>
        <p>{value.error || "Opening local workspace…"}</p>
      </div>
    );
  return (
    <WorkspaceContext.Provider
      value={{ ...value, state: value.state, topology: value.topology }}
    >
      <AppShell />
    </WorkspaceContext.Provider>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
