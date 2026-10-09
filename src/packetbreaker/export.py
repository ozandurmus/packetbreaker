"""Versioned metadata export and a standalone, network-free HTML report."""

from datetime import datetime, timezone
from html import escape
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from .store import rows
from .field_diff import field_diffs
from .topology import Topology
from .onset import ordered_onsets


class Finding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"type": {"const": "confirmed_device_drop"}}, "required": ["type"]},
                    "then": {
                        "required": ["device", "evidence_stage"],
                        "properties": {
                            "device": {"type": "string", "minLength": 1},
                            "evidence_stage": {"type": "string", "minLength": 1},
                        },
                    },
                }
            ]
        },
    )
    id: str
    type: Literal[
        "recovered_loss",
        "impactful_loss",
        "unrecovered_loss",
        "handshake_blocked",
        "capture_miss",
        "unknown",
        "confirmed_device_drop",
        "reset_origin",
        "icmp_origin",
        "payload_modified",
        "downstream_packet",
    ]
    tooltip: str | None = None
    device: str | None = None
    evidence_stage: str | None = None
    hop: str
    direction: str
    time_range: tuple[float | None, float | None]
    metrics: dict[str, Any]
    evidence_refs: list[dict[str, Any]]
    confidence: Literal["supported", "unknown"]
    severity: str
    summary: str
    cause: str

    @model_validator(mode="after")
    def stage_provenance(self):
        if self.type == "confirmed_device_drop" and (not self.device or not self.evidence_stage):
            raise ValueError("Confirmed device drops require device and evidence_stage")
        return self


class FindingsExport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_name: Literal["packetbreaker.findings"] = "packetbreaker.findings"
    schema_version: Literal[3] = 3
    engine_version: str
    exported_at: str
    findings: list[Finding]
    report: dict[str, Any]
    timeseries: dict[str, Any]
    flow_filters: list[dict[str, Any]]


def export_data(project):
    with project.connect() as db:
        report = project.get(db, "report")
        if not report:
            raise ValueError("Run analysis before exporting")
        findings = project.get(db, "export_findings")
        if findings is None:
            if report["finding_count"] > len(report["findings"]):
                raise ValueError("Re-run analysis to export all findings from this older report")
            findings = report["findings"]
        snapshot = dict(report)
        snapshot.pop("findings", None)
        snapshot["field_diffs"] = field_diffs(db, Topology.model_validate(project.get(db, "topology")))
        return FindingsExport(
            engine_version=report["engine_version"],
            exported_at=datetime.now(timezone.utc).isoformat(),
            findings=[
                Finding(
                    **{
                        k: f[k]
                        for k in (
                            "id",
                            "type",
                            "hop",
                            "direction",
                            "time_range",
                            "metrics",
                            "confidence",
                            "severity",
                            "summary",
                            "cause",
                        )
                    },
                    evidence_refs=f["evidence"],
                    tooltip=f.get("tooltip"),
                    device=f.get("device"),
                    evidence_stage=f.get("evidence_stage"),
                )
                for f in findings
            ],
            report=snapshot,
            timeseries={
                **report["timeseries"],
                "items": rows(db, "SELECT * FROM segment_buckets ORDER BY direction,segment,bucket"),
            },
            flow_filters=rows(
                db,
                """SELECT f.flow,f.capture_id,c.name AS file,f.display_filter
                FROM flow_filters f JOIN captures c ON c.id=f.capture_id ORDER BY f.flow,c.name""",
            ),
        ).model_dump(mode="json")


def html_report(data):
    report = data["report"]

    def h(value):
        return escape(str(value) if value is not None else "unknown", quote=True)

    def details(value, title="Details"):
        return f"<details><summary>{h(title)}</summary><pre>{h(json.dumps(value, indent=2, ensure_ascii=False))}</pre></details>"

    def refs(items):
        return "".join(
            "<li><strong>"
            + h(e["file"])
            + " · frame "
            + h(e["frame"])
            + "</strong>"
            + details(e, "Frame, content and flow filters")
            + "</li>"
            for e in items
        )

    findings = "".join(
        f'<article id="finding-{i}"><h3>{h(f["type"])} · {h(f["hop"])}</h3><p title="{h(f.get("tooltip"))}">{h(f["summary"])}</p><p>{h(f.get("device") or "")} {h(f.get("evidence_stage") or "")}</p><p>Confidence: {h(f["confidence"])}; severity: {h(f["severity"])}</p>{details(f["metrics"], "Metrics")}<ul>{refs(f["evidence_refs"])}</ul></article>'
        for i, f in enumerate(data["findings"])
    )
    segments = "".join(
        f"<article><h3>{h(s['label'])} · {h(s['direction'])}</h3><p>{h(s.get('headline') or s.get('reason'))}</p>{details(s, 'Segment metrics and uncertainty')}</article>"
        for s in report["segments"]
    )
    onset = report.get("onsets", {})
    onsets = "".join(
        f"<article class='{'symptom' if o.get('scope') == 'capture_signal' else 'primary'}'><h3>{h(o['segment'])} · {h(o['metric'])}</h3><p>{h(o['explanation'])}</p>{details(o.get('time_labels'), 'Onset time')}<ul>{refs(o.get('evidence', []))}</ul></article>"
        for o in ordered_onsets(onset.get("items", []), onset.get("directions", {}))
    )
    # JSON is data, not executable markup. Escape '<' even inside arbitrary capture labels.
    encoded = (
        json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        .replace("<", r"\u003c")
        .replace(">", r"\u003e")
        .replace("&", r"\u0026")
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>PacketBreaker offline report</title><style>
body{{font:15px system-ui,sans-serif;color:#173d40;background:#f3f7f6;max-width:1200px;margin:auto;padding:24px}}h1,h2,h3{{line-height:1.3}}article,section{{background:white;padding:18px;margin:16px 0;border:1px solid #d7e3df;border-radius:8px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f7f6;padding:12px}}article.symptom{{background:#f4f6f5;color:#667772;font-size:0.9em}}summary,select{{cursor:pointer}}canvas{{display:block}}.scroll{{overflow:auto}}nav a{{margin-right:18px;color:#176b68}}small{{color:#526b6a}}li{{margin:10px 0}}#tip{{white-space:pre-wrap;min-height:4em}}
</style></head><body><h1>PacketBreaker · offline report</h1>
<p>Engine {h(data["engine_version"])} · findings schema {data["schema_version"]} · exported {h(data["exported_at"])}</p>
<p>This file contains capture metadata, addresses and evidence filters. It embeds no packet payloads. Treat it with the same care as an investigation summary.</p>
<nav><a href="#summary">Summary</a><a href="#onset">Onset</a><a href="#heatmap">Heatmap</a><a href="#findings">Findings</a><a href="#segments">Segments</a><a href="#filters">Flow filters</a></nav>
<section id="summary"><h2>{h(report["verdict"])}</h2><p>{h(onset.get("summary"))}</p>{details(report["window"], "Analysis window (Unix seconds)")}{details(report["clocks"], "Clock uncertainty")}{details(report.get("limitations", []), "Interpretation limits")}</section>
<section id="onset"><h2>Onset</h2>{onsets or "<p>No supported onset detected. See per-segment status.</p>"}{details(onset.get("segments", onset), "Per-segment onset status")}</section>
<section id="heatmap"><h2>Path × time</h2><label>Metric <select id="metric"></select></label><p id="metric-note"></p><p>Grey = not capturing; amber = unknown/partial. Black markers = detected onsets. Hover for time, value and coverage.</p><div class="scroll"><canvas id="map" aria-label="Path by time heatmap"></canvas></div><p id="tip" role="status"></p><noscript>Enable JavaScript for the offline heatmap; summary, findings and evidence remain readable.</noscript></section>
<section id="findings"><h2>Findings ({len(data["findings"])})</h2>{findings or "<p>No findings.</p>"}</section>
<section id="segments"><h2>Segments</h2>{segments}</section>
<section id="field-diffs"><h2>Matched packet field differences</h2>{details(report.get("field_diffs", {}), "Observed values, unknowns and frame filters")}</section>
<section id="filters"><h2>Per-file flow filters</h2>{details(data["flow_filters"], "Copy filters for original or re-saved files")}</section>
<script id="report-data" type="application/json">{encoded}</script><script>{HEATMAP_SCRIPT}</script></body></html>"""


HEATMAP_SCRIPT = r"""
'use strict';
const data=JSON.parse(document.getElementById('report-data').textContent);
const series=data.timeseries, segments=data.report.segments, canvas=document.getElementById('map'), ctx=canvas.getContext('2d');
const metric=document.getElementById('metric'), tip=document.getElementById('tip'), note=document.getElementById('metric-note');
const lookup=new Map(series.items.map(r=>[r.segment+':'+r.bucket,r]));
const count=series.bucket_count||0, left=270, cell=Math.max(0.02,Math.min(18,3000/Math.max(1,count))), height=28;
canvas.width=Math.ceil(left+cell*count+10); canvas.height=segments.length*height+40;
for(const [key,value] of Object.entries(series.metrics||{})){const option=document.createElement('option');option.value=key;option.textContent=value.label+' ('+value.unit+')';metric.append(option);}
metric.value='loss_percent';
function draw(){
 ctx.clearRect(0,0,canvas.width,canvas.height);ctx.font='12px system-ui';
 const key=metric.value, descriptor=series.metrics[key];note.textContent=descriptor?descriptor.tooltip:'';
 let max=0;for(const r of series.items)if(typeof r[key]==='number')max=Math.max(max,r[key]);
 segments.forEach((s,i)=>{ctx.fillStyle='#173d40';ctx.fillText(s.label+' · '+s.direction,0,i*height+19,260);
 for(let j=0;j<count;j++){const r=lookup.get(s.id+':'+j), value=r&&r[key];
 ctx.fillStyle=!r||r.coverage==='not capturing'?'#b9c4c3':r.coverage!=='capturing'||value==null?'#e7cc96':`hsl(${170-160*Math.min(1,value/(max||1))} 55% 62%)`;
 ctx.fillRect(left+j*cell,i*height+3,Math.max(cell-0.4,0.02),height-5);}}
 );
 ctx.fillStyle='#172a2d';for(const onset of (data.report.onsets?.items||[])){if(onset.metric!==key)continue;const i=segments.findIndex(s=>s.id===onset.segment);if(i<0)continue;const j=Math.floor((onset.time-series.start)/series.bucket_seconds);if(j<0||j>=count)continue;const x=left+j*cell,y=i*height;ctx.beginPath();ctx.moveTo(x,y+1);ctx.lineTo(x+6,y+9);ctx.lineTo(x-6,y+9);ctx.closePath();ctx.fill();}
 if(count){ctx.fillText(new Date(series.start*1000).toISOString(),left,canvas.height-8);ctx.fillText(new Date((series.start+count*series.bucket_seconds)*1000).toISOString(),Math.max(left,canvas.width-195),canvas.height-8);}
}
metric.addEventListener('change',draw);
canvas.addEventListener('mousemove',event=>{const box=canvas.getBoundingClientRect(), x=(event.clientX-box.left)*canvas.width/box.width, y=(event.clientY-box.top)*canvas.height/box.height;
const i=Math.floor(y/height), j=Math.floor((x-left)/cell);if(i<0||i>=segments.length||j<0||j>=count)return;
const r=lookup.get(segments[i].id+':'+j), descriptor=series.metrics[metric.value];tip.textContent=segments[i].label+' · '+segments[i].direction+'\n'+new Date((series.start+j*series.bucket_seconds)*1000).toISOString()+'\n'+(!r||r.coverage==='not capturing'?'not capturing':r[metric.value]==null?'unknown':r[metric.value].toFixed(3)+' '+descriptor.unit)+'\n'+(r?.coverage||'not capturing')+' · '+(r?.reason||'')+'\n'+(descriptor?.tooltip||'');});
draw();
"""


def export_report(project, format):
    data = export_data(project)
    if format == "json":
        return json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    if format == "html":
        return html_report(data)
    raise ValueError("Export format must be html or json")
