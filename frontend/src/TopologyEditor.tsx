import {kinds,pathFromEdges} from "./TopologyHelpers";
import {PointInspector} from "./PointInspector";
import {useEffect,useState} from "react";
import {ReactFlow,Background,Controls,MarkerType,Position,addEdge,applyNodeChanges,applyEdgeChanges,type Node,type Edge,type Connection} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type {Capture,Point,Topology,Report,TopologyOverlay} from "./types";

export function TopologyEditor({
  topology,
  captures,
  report,
  overlay,
  onInspect,
  onSave,
  onChange,
  onError,
}: {
  topology: Topology;
  captures: Capture[];
  report: Report | null;
  overlay?: TopologyOverlay | null;
  onInspect?: (query: string) => void;
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
      overlay?.nodes.find((n) => n.device === device)?.confirmed_device_drops ||
      0;
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
              {overlay?.nodes
                .filter((n) => n.device === p.device)
                .map((n) => (
                  <small
                    key={n.device}
                    title="Device aggregate across its capture points; observations can include the same packet at ingress and egress."
                  >
                    {n.observations} observations · {n.retrans_observations}{" "}
                    retrans · {n.supported_loss_events} adjacent supported loss
                    events · {n.findings} findings
                  </small>
                ))}
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
          const metric = overlay?.segments.find(
            (s) => s.id === `${dir}:${source}:${target}`,
          );
          const color =
            metric?.classes.confirmed_device_drop ||
            metric?.classes.impactful_loss ||
            metric?.classes.handshake_blocked
              ? "#c44842"
              : metric?.reason
                ? "#b48526"
                : dir === "reverse"
                  ? "#8384b6"
                  : "#168a84";
          return {
            id: `${dir}:${source}:${target}`,
            source,
            target,
            data: { direction: dir },
            label: metric
              ? `${metric.loss_percent == null ? "?" : metric.loss_percent.toFixed(1)}% · ${metric.p95_ms == null ? "?" : metric.p95_ms.toFixed(2)}ms · R${metric.retrans_observations}`
              : seg
                ? "Full-window metrics available; loading selected interval…"
                : dir,
            labelStyle: {
              transform:
                topology.points.find((p) => p.id === source)?.y ===
                topology.points.find((p) => p.id === target)?.y
                  ? "translateY(-90px)"
                  : undefined,
            },
            labelBgStyle: {
              transform:
                topology.points.find((p) => p.id === source)?.y ===
                topology.points.find((p) => p.id === target)?.y
                  ? "translateY(-90px)"
                  : undefined,
            },
            ariaLabel: metric
              ? `${dir}: ${metric.loss_percent ?? "unknown"}% loss, ${metric.p95_ms ?? "unknown"} ms p95, ${metric.retrans_observations} retransmission observations. Clock uncertainty ${seg?.offset_uncertainty_ms ?? "unknown"} ms.`
              : dir,
            animated: false,
            style: { stroke: color, strokeWidth: 2 },
            markerEnd: { type: MarkerType.ArrowClosed, color },
          };
        });
      }),
    );
  }, [topology, captures, report, overlay]);
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
        p.id === selected.id
          ? { ...p, ...patch }
          : patch.stage_capture !== undefined && p.device === selected.device
            ? { ...p, stage_capture: patch.stage_capture }
            : p,
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
          <small className="hint">
            Arrows: loss % · p95 added transit (ms) · R retransmission
            observations.
          </small>
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
            onNodeClick={(_, n) => {
              setSelection(n.id);
              if (report) onInspect?.(`point=${encodeURIComponent(n.id)}`);
            }}
            onEdgeClick={(_, e) => {
              if (report) onInspect?.(`segment=${encodeURIComponent(e.id)}`);
            }}
            fitView
            minZoom={0.15}
          >
            <Background color="#d6dfdf" gap={22} />
            <Controls />
          </ReactFlow>
        </div>
        <PointInspector
          selected={selected}
          captures={captures}
          update={update}
          current={current}
          onChange={onChange}
          setSelection={setSelection}
        />
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
