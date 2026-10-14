import type {Capture,Point,Topology} from "./types";
export function PointInspector({
  selected,
  captures,
  update,
  current,
  onChange,
  setSelection,
}: {
  selected: Point | undefined;
  captures: Capture[];
  update: (p: Partial<Point>) => void;
  current: () => Topology;
  onChange: (t: Topology) => void;
  setSelection: (s: string | null) => void;
}) {
  return (
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
            Shared clock domain (same name for files from one appliance)
            <input
              value={selected.clock_domain || ""}
              onChange={(e) => update({ clock_domain: e.target.value || null })}
            />
          </label>
          <label>
            <input
              type="checkbox"
              checked={selected.host_capture || false}
              onChange={(e) => update({ host_capture: e.target.checked })}
            />
            Host capture (OS receive/transmit path)
          </label>
          <label>
            <input
              type="checkbox"
              checked={selected.stage_capture || false}
              onChange={(e) => update({ stage_capture: e.target.checked })}
            />
            Device stage captures: rx/ingress then tx/egress in both directions
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
                Use the same device name for all stage files. A drop point can
                remain off the forwarding path.
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
                Enable F5 trailer decoding in Settings and reattach first. Use
                specific client CIDRs. Reciprocal TMM IDs pair connections; TCP
                legs stay separate.
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
                Required inspection stages captured continuously (map I and o
                too)
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
              onChange={(e) => update({ source_cidr: e.target.value || null })}
            />
          </label>
          <label>
            Tunnel matching layer
            <select
              aria-label="Tunnel matching layer"
              value={selected.matching_layer || ""}
              onChange={(e) =>
                update({
                  matching_layer: (e.target.value ||
                    null) as Point["matching_layer"],
                })
              }
            >
              <option value="">Auto: inner for ERSPAN; otherwise choose</option>
              <option value="inner">Inner IP / transport</option>
              <option value="outer">Outer IP / transport</option>
            </select>
          </label>
          <label>
            Declared payload transformation
            <select
              value={selected.payload_transform || "none"}
              onChange={(e) =>
                update({
                  payload_transform: e.target
                    .value as Point["payload_transform"],
                })
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
  );
}
