import type {Edge} from "@xyflow/react";
export const kinds = [
  "Client",
  "Firewall",
  "IPS",
  "Router/Switch",
  "Load Balancer",
  "Proxy",
  "WAF",
  "Server",
  "Generic",
];
export function pathFromEdges(edges: Edge[], direction: string): string[] {
  const selected = edges.filter((e) => e.data?.direction === direction);
  if (!selected.length) return [];
  const next = new Map<string, string>(),
    incoming = new Set<string>();
  for (const e of selected) {
    if (next.has(e.source) || incoming.has(e.target))
      throw new Error(
        "A path cannot branch. Each point needs at most one incoming and outgoing arrow per direction.",
      );
    next.set(e.source, e.target);
    incoming.add(e.target);
  }
  const heads = [...next.keys()].filter((x) => !incoming.has(x));
  if (heads.length !== 1)
    throw new Error("Connect one continuous path without cycles.");
  const path = [heads[0]];
  while (next.has(path.at(-1)!)) {
    const n = next.get(path.at(-1)!)!;
    if (path.includes(n)) throw new Error("Path contains a cycle");
    path.push(n);
  }
  if (path.length !== selected.length + 1)
    throw new Error("Path contains disconnected arrows");
  return path;
}
