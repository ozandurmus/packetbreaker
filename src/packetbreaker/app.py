from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
import threading
from urllib.parse import urlsplit
import uuid

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .field_diff import packet_diff
from .waterfall import waterfall
from .export import export_report
from .analysis import analyze, event_page, flow_page, ladder, findings_page
from .ingest import find_tshark
from .batch_ingest import ingest_many, normalize_paths
from .store import Project
from .topology import Topology
from .timeseries import timeseries_page


class Attach(BaseModel):
    f5_trailer: bool | None = None
    paths: list[str] = Field(min_length=1, max_length=100)


class Settings(BaseModel):
    memory_limit_mb: int | None = Field(default=None, ge=64)
    assistant_enabled: bool = False
    f5_trailer: bool = False
    checkpoint_uuid: bool = False
    parallel: bool = False
    tshark: str | None = None
    prefix_bytes: int = Field(default=64, ge=8, le=4096)


class FortinetImport(BaseModel):
    path: str
    start_time: str | None = None
    device: str = Field(default="FortiGate", min_length=1, max_length=100)


class CancelFile(BaseModel):
    file_id: str | None = None


class OpenProject(BaseModel):
    path: str = Field(min_length=1, max_length=4096)


class Jobs:
    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="packetbreaker")
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.file_cancels = {}
        self.status = dict(state="idle", busy=False)

    def update(self, **values):
        with self.lock:
            self.status.update(values)

    def start(self, kind, fn):
        with self.lock:
            if self.status.get("busy"):
                raise HTTPException(409, "Wait for the current job or cancel ingestion first")
            self.cancel.clear()
            self.file_cancels = {}
            self.status = dict(state="queued", kind=kind, busy=True)

        def run():
            try:
                fn()
                self.update(state="done", busy=False)
            except InterruptedError as exc:
                self.update(state="cancelled", busy=False, error=str(exc))
            except Exception as exc:
                self.update(state="error", busy=False, error=str(exc))

        self.pool.submit(run)
        return self.status.copy()


def create_app(project_path, *, memory_limit_mb=None):
    project = Project(project_path, memory_limit_mb=memory_limit_mb)
    jobs = Jobs()

    @asynccontextmanager
    async def lifespan(app):
        yield
        jobs.cancel.set()
        jobs.pool.shutdown(wait=True, cancel_futures=True)

    app = FastAPI(title="PacketBreaker", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.jobs = jobs

    @app.middleware("http")
    async def local_only(request, call_next):
        host = request.headers.get("host", "")
        parsed = urlsplit("http://" + host)
        if parsed.hostname not in ("127.0.0.1", "localhost"):
            return JSONResponse({"detail": "Loopback Host required"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin not in ("http://" + host, "https://" + host):
            return JSONResponse({"detail": "Foreign Origin rejected"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site request rejected"}, status_code=403)
        if request.method not in ("GET", "HEAD") and request.headers.get("x-packetbreaker") != "local":
            return JSONResponse({"detail": "Same-origin application header required"}, status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ValueError)
    async def value_error(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    def idle():
        if jobs.status.get("busy"):
            raise HTTPException(409, "A job is running; wait or cancel ingestion first")

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/flows/{flow}/diagnosis")
    def flow_diagnosis(flow: str):
        from .transport import profiles

        return profiles(project, flow)

    @app.get("/api/flows/{flow}/charts")
    def stream_charts(
        flow: str,
        point: str | None = None,
        direction: str = Query("forward", pattern="^(forward|reverse)$"),
        start: float | None = Query(None, allow_inf_nan=False),
        end: float | None = Query(None, allow_inf_nan=False),
        limit: int = Query(2000, ge=1, le=5000),
        local: bool = False,
    ):
        idle()
        from .stream_charts import charts

        return charts(project, flow, point, direction, start, end, limit, local)

    @app.get("/api/flows/{flow}/frames")
    def chart_evidence(flow: str, point: str, frames: list[int] = Query(min_length=1, max_length=8)):
        if any(frame < 1 for frame in frames):
            raise HTTPException(status_code=422, detail="Frame numbers must be positive")
        from .stream_charts import frame_evidence

        return frame_evidence(project, flow, point, frames)

    @app.get("/api/dns")
    def dns(
        point: str | None = None,
        resolver: str | None = None,
        start: float | None = Query(None, allow_inf_nan=False),
        end: float | None = Query(None, allow_inf_nan=False),
        offset: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=200),
    ):
        from .dns import dns_page

        return dns_page(project, point, resolver, start, end, offset, limit)

    @app.get("/api/state")
    def state():
        with project.connect() as db:
            settings = project.get(db, "preferences", {})
            topology = project.get(db, "topology", Topology().model_dump())
            report = project.get(db, "report")
            conversion = project.get(db, "fortinet_conversion")
            case_context = project.get(db, "case_context")
        try:
            tshark = dict(path=find_tshark(settings.get("tshark")), error=None)
        except ValueError as exc:
            tshark = dict(path=None, error=str(exc))
        from .case_setup import inventory_overview

        captures = project.inventory()
        return dict(
            version=__version__,
            project=str(project.path),
            captures=captures,
            preflight=inventory_overview(captures),
            case_context=case_context,
            topology=topology,
            report=report,
            settings=settings,
            fortinet_conversion=conversion,
            tshark=tshark,
            job=jobs.status,
        )

    @app.post("/api/project")
    def open_project(body: OpenProject):
        nonlocal project
        idle()
        project = Project(Path(body.path).expanduser(), memory_limit_mb=memory_limit_mb)
        return {"path": str(project.path)}

    @app.post("/api/settings")
    def settings(body: Settings):
        idle()
        if body.tshark:
            find_tshark(body.tshark)
        with project.connect() as db:
            project.set(db, "preferences", body.model_dump())
        return body

    @app.get("/api/assistant/preview")
    def assistant_preview():
        with project.connect() as db:
            enabled = project.get(db, "preferences", {}).get("assistant_enabled", False)
        if not enabled:
            raise HTTPException(403, "Assistant placeholder is disabled in Settings")
        from .assistant import preview

        return preview(project)

    def ingest_files(paths, f5_trailer=None):
        paths = normalize_paths(paths)
        with project.connect() as db:
            preferences = project.get(db, "preferences", {})
        preferences.pop("assistant_enabled", None)
        preferences.pop("memory_limit_mb", None)
        if f5_trailer is not None:
            preferences["f5_trailer"] = f5_trailer
        with jobs.lock:
            jobs.file_cancels = {str(i): threading.Event() for i in range(len(paths))}
        ingest_many(
            project,
            paths,
            **preferences,
            cancel=jobs.cancel,
            file_cancels=jobs.file_cancels,
            progress=jobs.update,
        )

    @app.post("/api/fortinet/import")
    def fortinet_import(body: FortinetImport):
        from .fortinet import import_text

        if not Path(body.path).expanduser().is_file():
            raise ValueError("Fortinet text file does not exist")
        return jobs.start(
            "ingest",
            lambda: import_text(
                project, Path(body.path).expanduser(), body.start_time, body.device, jobs.cancel, jobs.update
            ),
        )

    @app.post("/api/captures/attach")
    def attach(body: Attach):
        for path in body.paths:
            if not Path(path).expanduser().is_file():
                raise ValueError("File does not exist: " + path)
        return jobs.start("ingest", lambda: ingest_files(body.paths, body.f5_trailer))

    @app.post("/api/captures/upload")
    async def upload(request: Request, name: str = Query(min_length=1, max_length=255), defer: bool = False):
        idle()
        name = name.replace("\\", "/").split("/")[-1]
        if Path(name).suffix.lower() not in (".pcap", ".pcapng", ".cap", ".snoop"):
            raise ValueError("Choose a pcap, pcapng or snoop capture")
        uploads = project.path / "captures"
        uploads.mkdir(exist_ok=True)
        destination = uploads / (uuid.uuid4().hex[:8] + "-" + name)
        try:
            with destination.open("xb") as f:
                async for chunk in request.stream():
                    f.write(chunk)
            if defer:
                return {"path": str(destination)}
            return jobs.start("ingest", lambda: ingest_files([destination]))
        except BaseException:
            destination.unlink(missing_ok=True)
            raise

    @app.get("/api/jobs")
    def job_status():
        with jobs.lock:
            return jobs.status.copy()

    @app.post("/api/jobs/cancel")
    def cancel(body: CancelFile | None = None):
        if jobs.status.get("kind") != "ingest" or not jobs.status.get("busy"):
            raise HTTPException(409, "No cancellable ingest is running")
        if body and body.file_id is not None:
            with jobs.lock:
                states = {s["file_id"]: s for s in jobs.status.get("files", [])}
                if body.file_id not in states:
                    raise HTTPException(404, "Unknown file job")
                if states[body.file_id]["state"] in ("ready", "cached", "cancelled", "error"):
                    raise HTTPException(409, "File is not running")
                jobs.file_cancels[body.file_id].set()
            return {"state": "cancelling", "file_id": body.file_id}
        jobs.cancel.set()
        return {"state": "cancelling"}

    @app.put("/api/topology")
    def save_topology(body: Topology):
        idle()
        with project.connect() as db:
            project.set(db, "topology", body.model_dump())
            project.set(db, "report", None)
        return body

    @app.post("/api/analyze")
    def run_analysis(body: Topology):
        return jobs.start(
            "analysis", lambda: analyze(project, body, progress=jobs.update, cancel=jobs.cancel)
        )

    @app.get("/api/report")
    def report():
        with project.connect() as db:
            return project.get(db, "report")

    @app.get("/api/export")
    def export(format: str = Query("html", pattern="^(html|json)$")):
        idle()
        content = export_report(project, format)
        return Response(
            content,
            media_type="text/html" if format == "html" else "application/json",
            headers={"Content-Disposition": f'attachment; filename="packetbreaker-report.{format}"'},
        )

    @app.post("/api/anonymize")
    def anonymized_export(mode: str = Query("zero", pattern="^(zero|headers-only)$"), map_ips: bool = False):
        import tempfile
        import shutil
        from starlette.background import BackgroundTask
        from .anonymize import anonymize_files, local_key

        idle()
        with project.connect() as db:
            paths = [
                r[0]
                for r in db.execute("SELECT path FROM captures WHERE state='ready' ORDER BY id").fetchall()
            ]
            tshark = project.get(db, "preferences", {}).get("tshark")
        if not paths:
            raise HTTPException(400, "No ready captures to export")
        directory = Path(tempfile.mkdtemp(prefix="packetbreaker-anonymize-"))
        try:
            key = local_key(project.path / ".anonymize.key") if map_ips else None
            anonymize_files(paths, directory / "captures", mode=mode, key=key, map_ips=map_ips, tshark=tshark)
            archive = shutil.make_archive(
                str(directory / "anonymized-captures"), "zip", directory / "captures"
            )
            return FileResponse(
                archive,
                filename="anonymized-captures.zip",
                media_type="application/zip",
                background=BackgroundTask(shutil.rmtree, directory),
            )
        except BaseException:
            shutil.rmtree(directory)
            raise

    @app.get("/api/engine/export")
    def engine_export(format: str = Query("xlsx", pattern="^(csv|xlsx)$")):
        from .engine_export import export_tables

        idle()
        return Response(
            export_tables(project, format),
            media_type="application/zip"
            if format == "csv"
            else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": f'attachment; filename="packetbreaker-engine.{"zip" if format == "csv" else "xlsx"}"'
            },
        )

    @app.get("/api/reference/template")
    def reference_export():
        from .reference import reference_template
        import json

        with project.connect() as db:
            saved = project.get(db, "report")
        if not saved:
            raise HTTPException(400, "Run analysis first")
        return Response(
            json.dumps(reference_template(saved), indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="packetbreaker-reference.json"'},
        )

    @app.post("/api/compare")
    async def compare(request: Request):
        from .reference import compare_reference, compare_runs
        import json

        idle()
        content = bytearray()
        async for chunk in request.stream():
            content.extend(chunk)
            if len(content) > 64 * 1024 * 1024:
                raise HTTPException(413, "Comparison input exceeds 64 MiB")
        try:
            payload = json.loads(content)
            if not isinstance(payload, dict) or set(payload) - {"reference", "against"}:
                raise ValueError("Choose reference and/or against")
            with project.connect() as db:
                saved = project.get(db, "report")
            if not saved:
                raise ValueError("Run analysis first")
            result = {}
            if payload.get("reference") is not None:
                result.update(compare_reference(saved, payload["reference"]))
            if payload.get("against") is not None:
                if not isinstance(payload["against"], dict):
                    raise ValueError("Analysis export must be an object")
                result["diff"] = compare_runs(payload["against"], saved)
            if not result:
                raise ValueError("Choose reference and/or against")
            return result
        except (ValueError, TypeError, RecursionError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/topology/suggest")
    def topology_suggestions():
        from .topology_suggest import suggest_topology

        idle()
        return suggest_topology(project)

    @app.get("/api/findings")
    def findings(
        start: float | None = Query(None, allow_inf_nan=False),
        end: float | None = Query(None, allow_inf_nan=False),
    ):
        return findings_page(project, start, end)

    @app.get("/api/sessions/evidence")
    def lifecycle_evidence(
        point: str, start: float = Query(allow_inf_nan=False), end: float = Query(allow_inf_nan=False)
    ):
        from .security import session_evidence

        try:
            return session_evidence(project, point, start, end)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/timeseries")
    def timeseries():
        return timeseries_page(project)

    @app.get("/api/topology/overlay")
    def overlay(
        start: float | None = Query(None, allow_inf_nan=False),
        end: float | None = Query(None, allow_inf_nan=False),
    ):
        from .pilot import topology_overlay

        return topology_overlay(project, start, end)

    @app.get("/api/topology/inspect")
    def inspect(
        point: str | None = None,
        segment: str | None = None,
        start: float | None = Query(None, allow_inf_nan=False),
        end: float | None = Query(None, allow_inf_nan=False),
    ):
        from .pilot import topology_inspect

        if bool(point) == bool(segment):
            raise HTTPException(422, "Choose exactly one point or segment")
        try:
            return topology_inspect(project, point, segment, start, end)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/flows")
    def flows(
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=200),
        search: str = "",
        filter_by: str = "",
        sort: str = "bytes",
        start: float | None = Query(None, allow_inf_nan=False),
        end: float | None = Query(None, allow_inf_nan=False),
    ):
        return flow_page(project, offset, limit, search, filter_by, sort, start, end)

    @app.get("/api/packets/{packet_key}/field-diff")
    def matched_field_diff(packet_key: str):
        return packet_diff(project, packet_key)

    @app.get("/api/flows/{flow}/ladder")
    def flow_ladder(
        flow: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=200),
        start: float | None = Query(None, allow_inf_nan=False),
        end: float | None = Query(None, allow_inf_nan=False),
    ):
        return ladder(project, flow, offset, limit, start, end)

    @app.get("/api/flows/{flow}/waterfall")
    def flow_waterfall(
        flow: str,
        request_index: int = Query(0, ge=0, le=99),
        start: float | None = Query(None, allow_inf_nan=False),
        end: float | None = Query(None, allow_inf_nan=False),
    ):
        return waterfall(project, flow, start, end, request_index)

    @app.get("/api/events")
    def events(
        a: str,
        b: str,
        direction: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=200),
        start: float | None = Query(None, allow_inf_nan=False),
        end: float | None = Query(None, allow_inf_nan=False),
    ):
        return event_page(project, a, b, direction, offset, limit, start, end)

    static = Path(__file__).parent / "static"
    if static.exists():
        app.mount("/assets", StaticFiles(directory=static / "assets"), name="assets")

    @app.get("/")
    def index():
        if not (static / "index.html").exists():
            raise HTTPException(503, "Frontend is not built. Run npm ci && npm run build in frontend.")
        return FileResponse(static / "index.html")

    return app
