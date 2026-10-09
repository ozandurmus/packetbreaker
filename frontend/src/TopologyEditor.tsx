import { useEffect, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
  Position,
  addEdge,
  applyNodeChanges,
  applyEdgeChanges,
  type Node,
  type Edge,
  type Connection,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { Capture, Point, Topology, Report } from "./types";

const kinds = [
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
function pathFromEdges(edges: Edge[], direction: string): string[] {
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
export function TopologyEditor({
  topology,
  captures,
  report,
  onSave,
  onChange,
  onError,
}: {
  topology: Topology;
  captures: Capture[];
  report: Report | null;
  onSave: (t: Topology) => void;
  onChange: (t: Topology) => void;
  onError: (e: string) => void;
}) {
  const [nodes, setNodes] = useState<Node[]>([]),
    [edges, setEdges] = useState<Edge[]>([]),
    [selection, setSelection] = useState<string | null>(null),
    [direction, setDirection] = useState("forward");
  useEffect(() => {
    const deviceDrops = (device: string) =>
      report?.confirmed_device_drops
        ?.filter((d) => d.device === device)
        .reduce((n, d) => n + d.count, 0) || 0;
    setNodes(
      topology.points.map((p) => ({
        id: p.id,
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        position: { x: p.x, y: p.y },
        data: {
          label: (
            <div>
              <small>
                {p.kind} · {p.side}
              </small>
              <strong>{p.label}</strong>
              {!!deviceDrops(p.device) && (
                <small className="red">
                  {p.device}: {deviceDrops(p.device)} confirmed device drops
                  (device total)
                </small>
              )}
              <span>
                {captures.find((c) => c.id === p.capture_id)?.name ||
                  "Assign a capture"}
              </span>
            </div>
          ),
        },
        className: `capture-node ${deviceDrops(p.device) ? "confirmed-device" : ""}`,
      })),
    );
    setEdges(
      ["forward", "reverse"].flatMap((dir) => {
        const path = topology[dir as "forward" | "reverse"];
        return path.slice(1).map((target, i) => {
          const source = path[i];
          const seg = report?.segments.find(
            (s) =>
              s.point_a === source &&
              s.point_b === target &&
              s.direction === dir,
          );
          const color =
            seg?.classes.confirmed_device_drop ||
            seg?.classes.impactful_loss ||
            seg?.classes.handshake_blocked
              ? "#c44842"
              : seg?.reason
                ? "#b48526"
                : dir === "reverse"
                  ? "#8384b6"
                  : "#168a84";
          return {
            id: `${dir}:${source}:${target}`,
            source,
            target,
            data: { direction: dir },
            label: seg
              ? `${seg.loss_percent == null ? "?" : seg.loss_percent.toFixed(1)}% · ${seg.p95_ms == null ? "?" : seg.p95_ms.toFixed(2)} ms`
              : dir,
            animated: false,
            style: { stroke: color, strokeWidth: 2 },
            markerEnd: { type: MarkerType.ArrowClosed, color },
          };
        });
      }),
    );
  }, [topology, captures, report]);
  const selected = topology.points.find((p) => p.id === selection);
  function current() {
    return {
      ...topology,
      points: topology.points.map((p) => {
        const n = nodes.find((n) => n.id === p.id);
        return { ...p, x: n?.position.x ?? p.x, y: n?.position.y ?? p.y };
      }),
      forward: pathFromEdges(edges, "forward"),
      reverse: pathFromEdges(edges, "reverse"),
    };
  }
  function update(patch: Partial<Point>) {
    if (!selected) return;
    onChange({
      ...current(),
      points: current().points.map((p) =>
        p.id === selected.id ? { ...p, ...patch } : p,
      ),
    });
  }
  function connect(c: Connection) {
    setEdges((es) =>
      addEdge(
        {
          ...c,
          id: `${direction}:${c.source}:${c.target}`,
          data: { direction },
          label: direction,
          markerEnd: { type: MarkerType.ArrowClosed },
          style: {
            stroke: direction === "forward" ? "#168a84" : "#8384b6",
            strokeWidth: 2,
          },
        },
        es,
      ),
    );
  }
  function add(kind: string, x = 100, y = 80) {
    const id = "p" + crypto.randomUUID().slice(0, 8);
    const p: Point = {
      id,
      label: kind,
      device: kind + " " + (topology.points.length + 1),
      kind,
      side: "both",
      capture_id: captures[0]?.id || "",
      interface: null,
      source_cidr: null,
      translation: "none",
      x,
      y,
    };
    onChange({ ...current(), points: [...current().points, p] });
    setSelection(id);
  }
  return (
    <>
      <div className="toolbar">
        {report?.auto_order_suggestion?.points.length ===
          topology.points.length && (
          <button
            className="secondary"
            title={report.auto_order_suggestion.reason}
            onClick={() =>
              onChange({
                ...current(),
                forward: report.auto_order_suggestion!.points,
              })
            }
          >
            Apply suggested order
          </button>
        )}
        <select
          aria-label="Arrow direction"
          value={direction}
          onChange={(e) => setDirection(e.target.value)}
        >
          <option value="forward">Draw forward path</option>
          <option value="reverse">Draw return path</option>
        </select>
        <button
          onClick={() => {
            try {
              onSave(current());
            } catch (e) {
              onError(String(e));
            }
          }}
        >
          Save topology
        </button>
        <button
          className="secondary"
          onClick={() => {
            try {
              const blob = new Blob([JSON.stringify(current(), null, 2)], {
                type: "application/json",
              });
              const a = document.createElement("a");
              a.href = URL.createObjectURL(blob);
              a.download = "topology.json";
              a.click();
              URL.revokeObjectURL(a.href);
            } catch (e) {
              onError(String(e));
            }
          }}
        >
          Save JSON
        </button>
        <label className="button secondary">
          Load JSON
          <input
            type="file"
            hidden
            accept=".json"
            onChange={async (e) => {
              try {
                const f = e.target.files?.[0];
                if (f) {
                  const t = JSON.parse(await f.text());
                  await onSave(t);
                }
              } catch (e) {
                onError(String(e));
              }
            }}
          />
        </label>
      </div>
      <div className="topology-layout">
        <aside className="palette">
          <span className="eyebrow">Capture points</span>
          <p className="hint">
            Drag a device onto the canvas, or click to add. Use the same device
            name for ingress and egress.
          </p>
          {kinds.map((k) => (
            <button
              draggable
              key={k}
              className="palette-item"
              onDragStart={(e) =>
                e.dataTransfer.setData("application/packetbreaker", k)
              }
              onClick={() => {
                try {
                  add(k);
                } catch (e) {
                  onError(String(e));
                }
              }}
            >
              ＋ {k}
            </button>
          ))}
        </aside>
        <div
          className="canvas"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            const kind = e.dataTransfer.getData("application/packetbreaker");
            if (kinds.includes(kind)) {
              try {
                add(kind, e.nativeEvent.offsetX, e.nativeEvent.offsetY);
              } catch (e) {
                onError(String(e));
              }
            }
          }}
        >
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={(c) =>
              setNodes((n) =>
                applyNodeChanges(
                  c.filter((x) => x.type !== "remove"),
                  n,
                ),
              )
            }
            onEdgesChange={(c) => setEdges((e) => applyEdgeChanges(c, e))}
            onConnect={connect}
            onNodeClick={(_, n) => setSelection(n.id)}
            fitView
            minZoom={0.15}
          >
            <Background color="#d6dfdf" gap={22} />
            <Controls />
          </ReactFlow>
        </div>
        <aside className="inspector">
          {selected ? (
            <>
              <span className="eyebrow">Selected point</span>
              <h3>{selected.label}</h3>
              <label>
                Point label
                <input
                  value={selected.label}
                  onChange={(e) => update({ label: e.target.value })}
                />
              </label>
              <label>
                Device name
                <input
                  value={selected.device}
                  onChange={(e) => update({ device: e.target.value })}
                />
              </label>
              <label>
                Capture file
                <select
                  value={selected.capture_id}
                  onChange={(e) => update({ capture_id: e.target.value })}
                >
                  <option value="">Select capture</option>
                  {captures.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Side
                <select
                  value={selected.side}
                  onChange={(e) => update({ side: e.target.value })}
                >
                  {["ingress", "egress", "both"].map((x) => (
                    <option key={x}>{x}</option>
                  ))}
                </select>
              </label>
              <label>
                Vendor input
                <select
                  value={selected.vendor || "none"}
                  onChange={(e) =>
                    update({
                      vendor: e.target.value,
                      vendor_stage:
                        e.target.value === "checkpoint"
                          ? "i"
                          : e.target.value === "f5"
                            ? "client"
                            : e.target.value === "paloalto"
                              ? "receive"
                              : null,
                    })
                  }
                >
                  <option value="none">Generic capture</option>
                  <option value="checkpoint">Check Point fw monitor</option>
                  <option value="f5">F5 TMM trailer</option>
                  <option value="paloalto">Palo Alto stage file</option>
                  <option value="fortinet">Converted Fortinet interface</option>
                </select>
              </label>
              {selected.vendor === "paloalto" && (
                <label>
                  Capture stage
                  <select
                    value={selected.vendor_stage || "receive"}
                    onChange={(e) =>
                      update({
                        vendor_stage: e.target.value,
                        side:
                          e.target.value === "receive"
                            ? "ingress"
                            : e.target.value === "transmit"
                              ? "egress"
                              : "both",
                      })
                    }
                  >
                    {["receive", "firewall", "transmit", "drop"].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                  <small>
                    Use the same device name for all stage files. A drop point
                    can remain off the forwarding path.
                  </small>
                </label>
              )}
              {selected.vendor === "f5" && (
                <label>
                  Proxy leg
                  <select
                    value={selected.vendor_stage || "client"}
                    onChange={(e) => update({ vendor_stage: e.target.value })}
                  >
                    <option value="client">Client side</option>
                    <option value="server">Server side</option>
                  </select>
                  <small>
                    Enable F5 trailer decoding in Settings and reattach first.
                    Use specific client CIDRs. Reciprocal TMM IDs pair
                    connections; TCP legs stay separate.
                  </small>
                </label>
              )}
              {selected.vendor === "checkpoint" && (
                <>
                  <label>
                    fw1.interface filter (optional)
                    <input
                      value={selected.vendor_interface || ""}
                      onChange={(e) =>
                        update({ vendor_interface: e.target.value || null })
                      }
                      placeholder="Decoded interface name"
                    />
                  </label>
                  <label>
                    Inspection stage
                    <select
                      value={selected.vendor_stage || "i"}
                      onChange={(e) => update({ vendor_stage: e.target.value })}
                    >
                      {["i", "I", "o", "O", "e", "E", "oe", "OE"].map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={selected.inspection_complete || false}
                      onChange={(e) =>
                        update({ inspection_complete: e.target.checked })
                      }
                    />
                    Required inspection stages captured continuously (map I and
                    o too)
                  </label>
                </>
              )}
              <label>
                Interface ID (blank = all)
                <input
                  type="number"
                  min="0"
                  value={selected.interface ?? ""}
                  onChange={(e) =>
                    update({
                      interface:
                        e.target.value === "" ? null : Number(e.target.value),
                    })
                  }
                />
              </label>
              <label>
                Source CIDR filter
                <input
                  placeholder="Optional"
                  value={selected.source_cidr || ""}
                  onChange={(e) =>
                    update({ source_cidr: e.target.value || null })
                  }
                />
              </label>
              <label>
                Declared payload transformation
                <select
                  value={selected.payload_transform || "none"}
                  onChange={(e) =>
                    update({ payload_transform: e.target.value as Point["payload_transform"] })
                  }
                >
                  <option value="none">None</option>
                  <option value="proxy">Proxy</option>
                  <option value="alg">ALG</option>
                  <option value="ssl_inspection">SSL inspection</option>
                </select>
              </label>
              <label>
                Translation
                <select
                  value={selected.translation}
                  onChange={(e) => update({ translation: e.target.value })}
                >
                  <option value="none">None</option>
                  <option value="nat">NAT / PAT</option>
                  <option value="full_proxy">Full proxy (unsupported)</option>
                  <option value="seq_randomization">
                    Seq randomization (learn offsets)
                  </option>
                </select>
              </label>
              <button
                className="danger"
                onClick={() => {
                  const t = current();
                  onChange({
                    ...t,
                    points: t.points.filter((p) => p.id !== selected.id),
                    forward: t.forward.filter((id) => id !== selected.id),
                    reverse: t.reverse.filter((id) => id !== selected.id),
                  });
                  setSelection(null);
                }}
              >
                Remove point
              </button>
            </>
          ) : (
            <div className="empty">
              Select a point to assign its capture and inspection side.
            </div>
          )}
        </aside>
      </div>
      <div className="two-col">
        <label>
          Client networks (comma separated)
          <input
            value={topology.client_cidrs.join(", ")}
            onChange={(e) =>
              onChange({
                ...topology,
                client_cidrs: e.target.value
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean),
              })
            }
          />
          <span className="hint">
            Defines forward direction. Include translated client addresses. Your
            arrows define path order.
          </span>
        </label>
        <div className="notice">
          Leave the return path empty to use the reversed forward path. Draw
          purple arrows for asymmetric routing. Save the topology before
          analysis.
        </div>
      </div>
    </>
  );
}
