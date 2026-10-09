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

from .waterfall import waterfall
from .export import export_report
from .analysis import analyze, event_page, flow_page, ladder, findings_page
from .ingest import find_tshark
from .batch_ingest import ingest_many, normalize_paths
from .store import Project
from .topology import Topology
from .timeseries import timeseries_page


class Attach(BaseModel):
    paths: list[str] = Field(min_length=1, max_length=100)


class Settings(BaseModel):
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


def create_app(project_path):
    project = Project(project_path)
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

    @app.get("/api/state")
    def state():
        with project.connect() as db:
            settings = project.get(db, "preferences", {})
            topology = project.get(db, "topology", Topology().model_dump())
            report = project.get(db, "report")
            conversion = project.get(db, "fortinet_conversion")
        try:
            tshark = dict(path=find_tshark(settings.get("tshark")), error=None)
        except ValueError as exc:
            tshark = dict(path=None, error=str(exc))
        return dict(
            project=str(project.path),
            captures=project.inventory(),
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
        project = Project(Path(body.path).expanduser())
        return {"path": str(project.path)}

    @app.post("/api/settings")
    def settings(body: Settings):
        idle()
        if body.tshark:
            find_tshark(body.tshark)
        with project.connect() as db:
            project.set(db, "preferences", body.model_dump())
        return body

    def ingest_files(paths):
        paths = normalize_paths(paths)
        with project.connect() as db:
            preferences = project.get(db, "preferences", {})
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
        return jobs.start("ingest", lambda: ingest_files(body.paths))

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
        return jobs.start("analysis", lambda: analyze(project, body, progress=jobs.update))

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

    @app.get("/api/findings")
    def findings(
        start: float | None = Query(None, allow_inf_nan=False),
        end: float | None = Query(None, allow_inf_nan=False),
    ):
        return findings_page(project, start, end)

    @app.get("/api/timeseries")
    def timeseries():
        return timeseries_page(project)

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
