/* Offline projections of the same incident data used by the live UI. No requests. */
(() => {
  "use strict";
  const report = JSON.parse(
    document.getElementById("report-data").textContent,
  ).report;
  const data = report.incident;
  if (!data) return;
  const root = document.getElementById("incident"),
    views = [];
  let range = null,
    sort = "total_ms";
  const title = (text) => {
    const h = document.createElement("h3");
    h.textContent = text;
    root.append(h);
  };
  const text = (s) => {
    const p = document.createElement("p");
    p.textContent = s;
    root.append(p);
    return p;
  };
  const controls = document.createElement("p"),
    clear = document.createElement("button");
  clear.textContent = "Clear chart selection";
  controls.append(clear);
  root.append(controls);
  const status = text(
    "Drag any time chart to brush the shared interval. Click a point for evidence.",
  );
  const refs = document.createElement("pre");
  refs.setAttribute("aria-live", "polite");
  root.append(refs);
  function evidence(items) {
    refs.textContent = items?.length
      ? items
          .map(
            (e) =>
              `${e.file} frame ${e.frame}\n${e.display_filter}\n${e.content_filter || ""}\n${e.flow_filter || ""}`,
          )
          .join("\n\n")
      : "No frame evidence computed for this point.";
  }
  const visible = (t) => !range || (t >= range[0] && t < range[1]);
  const number = (v) => (v == null ? "unknown" : Number(v).toFixed(3));
  const notes = {
    rx_max_ms:
      "Maximum measured same-copy RX transit, ms; clock uncertainty applies.",
    tx_max_ms:
      "Maximum same-copy TX transit, ms; retry substitutions excluded.",
    tx_dropped:
      "TX originals missing, with supported drop/retry evidence; not transit delay.",
    tx_delayed:
      "TX originals seen later, above max(1 ms, twice clock uncertainty).",
    retransmissions:
      "tshark retransmission count; sender symptom, not fault attribution.",
    delayed: "Same original copy seen downstream later.",
    dropped: "Original missing; retry delivery is not original transit.",
    capture_miss_percent:
      "Supported capture miss / observed physical pair units.",
    loss_percent: "Supported loss / observed physical pair units.",
    offload_mismatch_percent:
      "Unknown pairs with different segmentation and a super-frame.",
    unknown_percent: "Other unknowns; insufficient identity/timing evidence.",
  };
  const base = () => ({
    animation: false,
    toolbox: { feature: { brush: { type: ["lineX", "clear"] } } },
    brush: { xAxisIndex: 0 },
    legend: { type: "scroll" },
    grid: { left: 80, right: 80, top: 55, bottom: 65 },
    xAxis: { type: "time" },
    yAxis: { type: "value" },
    dataZoom: [{ type: "slider", height: 20 }],
    tooltip: {
      trigger: "item",
      renderMode: "richText",
      formatter: (p) =>
        `${p.seriesName}: ${number(Array.isArray(p.data.value) ? p.data.value[1] : p.data.value)}\n${p.data.note || ""}\nClick for evidence; drag to brush.`,
    },
  });
  function renderAll() {
    for (const v of views) v.draw();
    status.textContent = range
      ? `Selected ${new Date(range[0] * 1000).toISOString()} — ${new Date(range[1] * 1000).toISOString()}; aggregate headline/baseline remain full-window.`
      : "Full saved window. Drag to brush, click for evidence.";
  }
  clear.onclick = () => {
    range = null;
    renderAll();
  };
  function chart(name, option, brush) {
    title(name);
    const div = document.createElement("div");
    div.style.height = "330px";
    div.setAttribute("role", "img");
    div.setAttribute("aria-label", name);
    root.append(div);
    const c = echarts.init(div);
    const draw = () => c.setOption(option(), true);
    views.push({ draw });
    c.on("click", (p) => evidence(p.data.evidence));
    c.on("brushEnd", (p) => {
      const a = p.areas?.[0]?.coordRange;
      if (!a) {
        range = null;
        renderAll();
        return;
      }
      if (brush) {
        brush(a);
        return;
      }
      range = [Math.min(...a) / 1000, Math.max(...a) / 1000];
      renderAll();
    });
    window.addEventListener("resize", () => c.resize());
  }
  const series = (rows, keys, stack) =>
    keys.map((name) => ({
      name,
      type: stack ? "bar" : "line",
      stack,
      showSymbol: true,
      data: rows
        .filter((r) => visible(r.start))
        .map((r) => ({
          value: [r.start * 1000, r[name]],
          evidence: r.evidence,
          note: notes[name],
        })),
    }));
  chart("Incident timeline", () => {
    const s = series(data.timeline, [
      "rx_max_ms",
      "tx_max_ms",
      "tx_dropped",
      "tx_delayed",
      "retransmissions",
    ]);
    s.forEach((v, i) => (v.yAxisIndex = i < 2 ? 0 : 1));
    if (data.window && data.timeline.length)
      s[0].markArea = {
        data: [
          [
            { name: "before", xAxis: data.timeline[0].start * 1000 },
            { xAxis: data.window.start * 1000 },
          ],
          [
            {
              name: "event",
              xAxis: data.window.start * 1000,
              itemStyle: { color: "rgba(220,140,40,.2)" },
            },
            { xAxis: data.window.end * 1000 },
          ],
          [
            { name: "recovery", xAxis: data.window.end * 1000 },
            { xAxis: data.timeline.at(-1).start * 1000 + 1000 },
          ],
        ],
      };
    return {
      ...base(),
      yAxis: [
        { type: "value", name: "Boundary max ms", min: 0 },
        { type: "value", name: "Count", min: 0 },
      ],
      series: s,
    };
  });
  text(data.headline);
  for (const g of data.loss_groups || []) {
    title(g.headline);
    text(
      Object.entries(g.counts)
        .map(([k, v]) => `${k}: ${v}`)
        .join(" · "),
    );
  }
  const label = document.createElement("label");
  label.textContent = "Sort top cycles ";
  const select = document.createElement("select");
  for (const key of ["total_ms", "rx_ms", "tx_ms"]) {
    const option = document.createElement("option");
    option.value = key;
    option.textContent = key;
    select.append(option);
  }
  label.append(select);
  root.append(label);
  select.onchange = () => {
    sort = select.value;
    renderAll();
  };
  const bars = () =>
    data.cycle_bars
      .filter((r) => visible(r.time))
      .sort((a, b) => (b[sort] ?? -Infinity) - (a[sort] ?? -Infinity));
  chart(
    "Where was the time added",
    () => {
      const b = bars(),
        names = [...new Set(b.flatMap((r) => r.parts.map((p) => p.name)))];
      return {
        ...base(),
        xAxis: {
          type: "category",
          data: b.map((r) => r.cycle_id.slice(0, 8)),
          axisLabel: { rotate: 35 },
        },
        yAxis: { type: "value", name: "Added ms" },
        series: names.map((name) => ({
          name,
          type: "bar",
          stack: "cycle",
          data: b.map((r) => {
            const p = r.parts.find((p) => p.name === name);
            return {
              value: p?.ms ?? null,
              evidence: p?.evidence,
              note: `${p?.reason || "Observed component"}; uncertainty ±${number(p?.uncertainty_ms)} ms. Total cycle ${number(r.total_ms)} ms; request serialization and incomplete coverage can prevent equality.`,
            };
          }),
        })),
      };
    },
    (a) => {
      const selected = bars().slice(
        Math.max(0, Math.ceil(Math.min(...a))),
        Math.floor(Math.max(...a)) + 1,
      );
      if (selected.length) {
        range = [
          Math.min(...selected.map((r) => r.time)),
          Math.max(...selected.map((r) => r.time)) + 1,
        ];
        renderAll();
      }
    },
  );
  text(
    "Stacked RX + server-local turnaround + TX. Unknown components remain null; the stack is not guaranteed to equal total cycle duration.",
  );
  title("Cycle table");
  text(
    "Three-period and per-hop added time are available in the expanded existing Opaque TCP cycles section below. CSV/XLSX engine tables retain all rows.",
  );
  title("Hold and release");
  if (!data.hold_release.length)
    text("No supported hold-and-release copy train in this saved window.");
  for (const f of data.hold_release) {
    const points = [...new Set(f.evidence.map((e) => e.point))];
    chart(
      "Hold and release · " + f.hop,
      () => ({
        ...base(),
        xAxis: { type: "value", name: "Local elapsed ms" },
        yAxis: { type: "value", name: "Copy number", minInterval: 1 },
        series: points.map((point) => {
          const e = f.evidence
              .filter((r) => r.point === point)
              .sort((a, b) => a.observed_time - b.observed_time),
            t = e[0]?.observed_time || 0;
          return {
            name: point,
            type: "line",
            data: e.map((r, i) => ({
              value: [(r.observed_time - t) * 1000, i + 1],
              evidence: [r],
              note: `${f.tooltip} Observed time ${r.observed_time}; each capture starts at its own first copy.`,
            })),
          };
        }),
      }),
      (a) =>
        evidence(
          f.evidence.filter((r) => {
            const t = Math.min(
              ...f.evidence
                .filter((x) => x.point === r.point)
                .map((x) => x.observed_time),
            );
            return (
              (r.observed_time - t) * 1000 >= Math.min(...a) &&
              (r.observed_time - t) * 1000 <= Math.max(...a)
            );
          }),
        ),
    );
    text(f.summary);
  }
  title("Delay versus drop");
  text(
    "Same original identity seen later → delayed. Original missing, retry delivered → dropped.",
  );
  text(
    "Seq-only matching can pair an original with a retry and mistake RTO recovery for transit delay.",
  );
  const keys = [
    ...new Set(
      data.delivery.map((r) => `${r.direction}: ${r.point_a} → ${r.point_b}`),
    ),
  ];
  for (const key of keys)
    chart(key + " · delay/drop", () => ({
      ...base(),
      yAxis: { type: "value", name: "Observed units" },
      series: series(
        data.delivery.filter(
          (r) => `${r.direction}: ${r.point_a} → ${r.point_b}` === key,
        ),
        ["delayed", "dropped"],
        "delivery",
      ),
    }));
  title("Capture quality");
  text(data.quality_note);
  for (const key of keys)
    chart(key + " · mismatch %", () => ({
      ...base(),
      yAxis: { type: "value", max: 100, name: "Mismatch %" },
      series: series(
        data.quality.filter(
          (r) => `${r.direction}: ${r.point_a} → ${r.point_b}` === key,
        ),
        [
          "capture_miss_percent",
          "loss_percent",
          "offload_mismatch_percent",
          "unknown_percent",
        ],
        "quality",
      ),
    }));
  renderAll();
})();
