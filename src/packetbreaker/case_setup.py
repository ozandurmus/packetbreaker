"""Local case scaffold and inventory-only preflight; no topology or clock inference."""

from pathlib import Path
from .store import Project
from .batch_ingest import ingest_many
from .topology import Topology, Point

MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
    b"snoo",
}


def capture_paths(folder):
    root = Path(folder).expanduser().resolve()
    if not root.is_dir() or root == root.parent:
        raise ValueError("Choose an existing capture folder, not the filesystem root")
    result = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        with path.open("rb") as source:
            magic = source.read(4)
        if magic in MAGICS or path.suffix.lower() in (".pcap", ".pcapng", ".cap", ".snoop"):
            result.append(path)
    if not result:
        raise ValueError("No supported capture files found in this folder")
    return result


def inventory_overview(captures):
    files = []
    intervals = []
    for capture in captures:
        info = capture["inventory"]
        warnings = list(info.get("warnings", []))
        if capture.get("error"):
            warnings.append(capture["error"])
        if info.get("truncated"):
            warnings.append(
                f"{info['truncated']} capture-truncated packets; only retained bytes can be compared"
            )
        if (info.get("ifdrop") or 0) > 0 or (info.get("osdrop") or 0) > 0:
            warnings.append(
                f"Capture-reported drops: interface {info.get('ifdrop')}, OS {info.get('osdrop')}"
            )
        tunnels = info.get("tunnel_counts", {})
        snaplens = sorted({i["snaplen"] for i in info.get("interfaces", []) if i.get("snaplen") is not None})
        if tunnels:
            warnings.append(
                f"Tunnel observations: {tunnels}; choose a matching layer in Path (ERSPAN defaults inner)"
            )
        if info.get("unsupported") and not tunnels:
            warnings.append(
                f"{info['unsupported']} observations need protocol/layer/reassembly validation during analysis"
            )
        files.append(
            dict(
                id=capture.get("id"),
                name=capture["name"],
                state=capture["state"],
                warnings=warnings,
                start=info.get("start"),
                end=info.get("end"),
                packet_count=info.get("packet_count"),
                prefilter_total=info.get("prefilter_total"),
                prefilter_retained=info.get("prefilter_retained"),
                prefilter_excluded=info.get("prefilter_excluded", 0),
                header_snaplen=snaplens[0] if len(snaplens) == 1 else info.get("snaplen"),
                header_snaplens=snaplens,
                observed_max_caplen=info.get("observed_max_caplen"),
                ifdrop=info.get("ifdrop"),
                osdrop=info.get("osdrop"),
                tunnel_counts=tunnels,
            )
        )
        if capture["state"] == "ready" and info.get("start") is not None and info.get("end") is not None:
            intervals.append((info["start"], info["end"]))
    if len(intervals) < 2:
        overlap = dict(
            status="unknown", reason="At least two ready captures with valid time ranges are required"
        )
    else:
        start = max(a for a, b in intervals)
        end = min(b for a, b in intervals)
        overlap = dict(
            status="overlap" if start < end else "none",
            start=start,
            end=end,
            reason="Observed timestamp ranges overlap; clock alignment is still required"
            if start < end
            else "Capture time ranges have no positive-duration overlap. Clock offsets may explain this; verify capture windows and clock settings before analysis.",
        )
    return dict(
        files=files,
        overlap=overlap,
        prefilter_excluded={f["name"]: f["prefilter_excluded"] for f in files if f.get("prefilter_excluded")},
    )


def create_case(folder, *, tshark=None, progress=None, memory_limit_mb=None, prefilter=True):
    paths = capture_paths(folder)
    root = Path(folder).expanduser().resolve()
    project = Project(root.with_name(root.name + ".packetbreaker"), memory_limit_mb=memory_limit_mb)
    latest = {}
    warning = None

    def update(**state):
        latest.update(state)
        if progress:
            progress(**state)

    try:
        ingest_many(project, paths, tshark=tshark, progress=update, prefilter=prefilter)
    except ValueError as exc:
        warning = str(exc)
    inventory = project.inventory()
    labels = {str(p.resolve()): p.relative_to(root).as_posix() for p in paths}
    prefilter_excluded = {
        c["name"]: c["inventory"].get("prefilter_excluded", 0)
        for c in inventory
        if c["inventory"].get("prefilter_excluded")
    }
    with project.connect() as db:
        saved = project.get(db, "topology")
        topology = Topology.model_validate(saved) if saved else Topology()
        assigned = {p.capture_id for p in topology.points}
        for capture in inventory:
            if capture["path"] in labels and capture["id"] not in assigned and len(topology.points) < 64:
                n = len(topology.points)
                label = labels[capture["path"]][:100]
                topology.points.append(
                    Point(
                        id="p_" + capture["id"],
                        label=label,
                        device=label,
                        capture_id=capture["id"],
                        x=(n % 4) * 240,
                        y=(n // 4) * 180,
                    )
                )
        project.set(db, "topology", topology.model_dump())
        project.set(
            db,
            "case_context",
            dict(
                folder=str(root),
                files=len(paths),
                warning=warning,
                prefilter=prefilter,
                prefilter_excluded=prefilter_excluded,
                issues=[
                    dict(file=f["file"], error=f.get("error"))
                    for f in latest.get("files", [])
                    if f.get("error")
                ],
                note="File names do not establish path order, device identity or client direction. Draw the path and assign ingress/egress explicitly.",
            ),
        )
    return project
