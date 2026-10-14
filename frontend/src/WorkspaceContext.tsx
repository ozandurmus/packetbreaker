import {createContext,useContext} from "react";
import type {Workspace} from "./workspace";
import type {State,Topology} from "./types";
export type LoadedWorkspace = Workspace & { state: State; topology: Topology };
export const WorkspaceContext = createContext<LoadedWorkspace | null>(null);
export function useWorkspace() {
  const value = useContext(WorkspaceContext);
  if (!value) throw Error("Workspace provider missing");
  return value;
}
