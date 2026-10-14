


























import {useWorkspace} from "./WorkspaceContext";
import {Tip} from "./UI";

export function AnalysisSettings() {
  const { series, range, setError, notice, topology, setTopology, analyze } =
    useWorkspace();
  return (
    <>
      <section>
        <h2>Analysis window and thresholds</h2>
        <label>
          RTP UDP decode-as ports (comma-separated port or range, e.g.
          40000-40100,50000; empty uses SDP)
          <input
            defaultValue={(topology.rtp_port_ranges || [])
              .map(([a, b]) => (a === b ? String(a) : `${a}-${b}`))
              .join(",")}
            onBlur={(e) => {
              const parts = e.target.value.trim()
                ? e.target.value.split(",").map((x) => x.trim())
                : [];
              if (
                parts.length > 16 ||
                parts.some((x) => !/^\d+(?:-\d+)?$/.test(x))
              ) {
                setError("Use up to 16 UDP ports or ranges");
                return;
              }
              const ranges = parts.map((x) => {
                const [a, b] = x.split("-").map(Number);
                return [a, b ?? a] as [number, number];
              });
              if (ranges.some(([a, b]) => a < 1 || b > 65535 || a > b)) {
                setError("UDP ports must be 1–65535 in ascending ranges");
                return;
              }
              setTopology({ ...topology, rtp_port_ranges: ranges });
            }}
          />
        </label>
        <label>
          RTP clock override (Hz, blank uses SDP/static payload rate)
          <input
            type="number"
            min={1000}
            max={192000}
            value={topology.rtp_clock_rate ?? ""}
            onChange={(e) =>
              setTopology({
                ...topology,
                rtp_clock_rate: e.target.value ? Number(e.target.value) : null,
              })
            }
          />
        </label>
        <label>
          Added RTP transit variation threshold (ms)
          <input
            type="number"
            min={0.1}
            max={1000}
            step={0.1}
            value={topology.rtp_jitter_ms ?? 2}
            onChange={(e) =>
              setTopology({
                ...topology,
                rtp_jitter_ms: Number(e.target.value),
              })
            }
          />
        </label>
        <label>
          UDP response window (ms)
          <input
            type="number"
            min={100}
            max={60000}
            value={topology.udp_timeout_ms ?? 2000}
            onChange={(e) =>
              setTopology({
                ...topology,
                udp_timeout_ms: Number(e.target.value),
              })
            }
          />
        </label>
        <div className="two-col">
          <label>
            Pressure minimum observed half-open sessions
            <input
              type="number"
              min={2}
              value={topology.security_half_open_floor ?? 20}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  security_half_open_floor: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            Scan rolling window (s)
            <input
              type="number"
              min={1}
              max={300}
              value={topology.security_scan_window_seconds ?? 5}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  security_scan_window_seconds: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            Scan minimum destinations/ports
            <input
              type="number"
              min={2}
              value={topology.security_scan_targets ?? 20}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  security_scan_targets: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            Scan failed handshake ratio
            <input
              type="number"
              min={0.5}
              max={1}
              step={0.05}
              value={topology.security_scan_failed_ratio ?? 0.8}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  security_scan_failed_ratio: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            SYN heuristic rate floor (sessions/s)
            <input
              type="number"
              min={1}
              value={topology.security_syn_rate ?? 50}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  security_syn_rate: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            Maximum completion ratio for SYN pattern
            <input
              type="number"
              min={0}
              max={0.5}
              step={0.05}
              value={topology.security_completion_ratio ?? 0.2}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  security_completion_ratio: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            Minimum observed sources
            <input
              type="number"
              min={2}
              value={topology.security_min_sources ?? 20}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  security_min_sources: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            Sustained SYN buckets
            <input
              type="number"
              min={2}
              value={topology.security_sustained_buckets ?? 3}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  security_sustained_buckets: Number(e.target.value),
                })
              }
            />
          </label>
        </div>
        <label title="Bucket width for stored time series and onset resolution. Re-run analysis after changing it.">
          Time bucket (seconds)
          <input
            type="number"
            min="0.1"
            max="3600"
            step="0.1"
            value={topology.bucket_seconds ?? 1}
            onChange={(e) =>
              setTopology({
                ...topology,
                bucket_seconds: Number(e.target.value),
              })
            }
          />
        </label>
        <div className="two-col">
          <label>
            <Tip text="Suppress loss rates when either endpoint's matchable fraction falls below this value. Default 90%.">
              Minimum matchable fraction (%)
            </Tip>
            <input
              type="number"
              min="0"
              max="100"
              value={(topology.min_eligible_ratio ?? 0.9) * 100}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  min_eligible_ratio: Number(e.target.value) / 100,
                })
              }
            />
          </label>
          <label title="Observed half-open expiry, not a measurement of the device session-table timer.">
            Half-open observation timeout (seconds)
            <input
              type="number"
              min={1}
              max={300}
              value={topology.session_timeout_seconds ?? 10}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  session_timeout_seconds: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            Microburst window (ms)
            <input
              type="number"
              min={1}
              max={10}
              step={0.1}
              value={topology.microburst_window_ms ?? 1}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  microburst_window_ms: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            <Tip text="Recovery waits at or above this threshold are impactful loss. Default 200 ms.">
              Impactful stall threshold (ms)
            </Tip>
            <input
              type="number"
              value={topology.stall_ms}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  stall_ms: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            Opaque cycle stall threshold (ms)
            <input
              type="number"
              min="1"
              max="60000"
              value={topology.cycle_stall_ms ?? 100}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  cycle_stall_ms: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            Top slow cycles
            <input
              type="number"
              min="1"
              max="100"
              value={topology.cycle_top_n ?? 20}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  cycle_top_n: Number(e.target.value),
                })
              }
            />
          </label>
          <label title="DNS response deadline at each observation point; incomplete coverage stays unknown. Re-analyze after changing it.">
            DNS timeout (ms)
            <input
              type="number"
              min="100"
              max="60000"
              value={topology.dns_timeout_ms ?? 2000}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  dns_timeout_ms: Number(e.target.value),
                })
              }
            />
          </label>
          <div className="notice">
            Blank window bounds use the common clock-corrected overlap. Results
            outside coverage remain unknown.
          </div>
          <label>
            Start (Unix seconds, optional)
            <input
              type="number"
              value={topology.start ?? ""}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  start: e.target.value ? Number(e.target.value) : null,
                })
              }
            />
          </label>
          <label>
            End (Unix seconds, optional)
            <input
              type="number"
              value={topology.end ?? ""}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  end: e.target.value ? Number(e.target.value) : null,
                })
              }
            />
          </label>
        </div>
      </section>
    </>
  );
}
