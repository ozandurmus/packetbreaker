import argparse
import json
from pathlib import Path
import socket
import sys
import threading
import webbrowser

from . import __version__
from .analysis import analyze
from .export import export_report
from .batch_ingest import ingest_many
from .store import Project
from .synthetic import generate, bind_capture_ids


def main():
    parser = argparse.ArgumentParser(description="PacketBreaker — local multi-hop capture analysis")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--project", default=str(Path.home() / "PacketBreaker" / "default"))
    parser.add_argument(
        "--memory-limit-mb", type=int, help="DuckDB MiB override (>=64); default 25% RAM, 1–8 GiB"
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    commands = parser.add_subparsers(dest="command")
    anon = commands.add_parser(
        "anonymize", help="Remove payload and metadata from a capture or capture folder"
    )
    anon.add_argument("input", type=Path)
    anon.add_argument("output", type=Path)
    anon.add_argument("--payload", choices=["zero", "headers-only"], default="zero")
    anon.add_argument(
        "--map-ips", action="store_true", help="Keyed prefix-preserving address mapping; default keeps IPs"
    )
    anon.add_argument(
        "--key", type=Path, help="Local 32-byte key, created if absent; reuse across the project; never share"
    )
    case = commands.add_parser("case", help="Ingest a capture folder into a sibling project and open Path")
    case.add_argument("folder", type=Path)
    case.add_argument(
        "--prefilter",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Pre-filter captures with >5x the frames of the others to shared IP pairs (default: on)",
    )
    case.add_argument("--no-browser", action="store_true", default=argparse.SUPPRESS)
    case.add_argument("--port", type=int, default=argparse.SUPPRESS)
    demo = commands.add_parser("demo", help="Generate and ingest five synthetic captures")
    demo.add_argument("directory", type=Path)
    demo.add_argument(
        "--scenario",
        default="demo",
        choices=[
            "udp_transactions",
            "pilot",
            "real_case_2",
            "pilot_healthy",
            "security",
            "security_reply",
            "diagnostics",
            "onset_intermittent_2",
            "onset_intermittent_3",
            "onset_intermittent_4",
            "onset_intermittent_5",
            "onset_random_loss",
            "onset_loss",
            "onset_delay",
            "onset_propagation",
            "onset_capture_miss",
            "offload",
            "sequence_randomization",
            "sequence_inconsistent",
            "healthy",
            "demo",
            "capture_miss",
            "recovered_loss",
            "impactful_loss",
            "nat",
            "delay",
            "truncation",
            "duplicate",
            "acked_unseen",
            "syn_blocked",
            "unrecovered_reset",
            "unrecovered_stall",
            "control_capture_miss",
            "realistic_healthy",
            "realistic_capture_miss",
            "realistic_loss",
            "realistic_syn_blocked",
        ],
    )
    demo.add_argument(
        "--parallel-ingest", action="store_true", help="Opt in to resource-bounded parallel ingestion"
    )
    demo.add_argument("--rounds", type=int, default=100)
    demo.add_argument("--ip-id", choices=["increment", "zero", "constant", "random"], default="increment")
    demo.add_argument("--ipv6", action="store_true")
    demo.add_argument(
        "--confirm-demo-nat",
        action="store_true",
        help="Confirm only mappings inferred from generated demo data",
    )
    run = commands.add_parser("analyze", help="Analyze saved or supplied topology; print JSON")
    run.add_argument("--topology", type=Path)
    run.add_argument("--memory-limit-mb", type=int, default=argparse.SUPPRESS)
    export = commands.add_parser("export", help="Export the last analysis as offline HTML or versioned JSON")
    export.add_argument("--format", required=True, choices=["html", "json", "csv", "xlsx"])
    export.add_argument("--output", "-o", type=Path, help="New output file; defaults to stdout")
    compare = commands.add_parser("compare", help="Compare a saved analysis against local reference/run JSON")
    compare.add_argument("--reference", type=Path)
    compare.add_argument("--against", type=Path, help="Previous analysis JSON export")
    compare.add_argument("--report", type=Path, help="Current analysis/export JSON; otherwise saved project")
    compare.add_argument("--template", type=Path, help="Write a reference template to a new file")
    forti = commands.add_parser(
        "import-fortinet", help="Convert verbose-6 text and add one capture point per interface"
    )
    forti.add_argument("path", type=Path)
    forti.add_argument("--start-time", help="Required for relative timestamps, ISO 8601 with Z or offset")
    forti.add_argument("--device", default="FortiGate")
    args = parser.parse_args()
    try:
        if args.command == "compare":
            from .reference import compare_reference, compare_runs, reference_template, unwrap

            if not (args.reference or args.against or args.template):
                parser.error("Choose --reference, --against or --template")
            if args.report:
                saved = json.loads(args.report.read_text(encoding="utf-8"))
            else:
                project = Project(args.project, memory_limit_mb=args.memory_limit_mb)
                with project.connect() as db:
                    saved = project.get(db, "report")
            if not saved:
                raise ValueError("Run analysis first")
            saved = unwrap(saved)
            if args.template:
                with args.template.open("x", encoding="utf-8") as target:
                    json.dump(reference_template(saved), target, indent=2)
            result = {}
            if args.reference:
                result.update(
                    compare_reference(saved, json.loads(args.reference.read_text(encoding="utf-8")))
                )
            if args.against:
                result["diff"] = compare_runs(json.loads(args.against.read_text(encoding="utf-8")), saved)
            print(json.dumps(result, indent=2))
            return
        if args.command == "anonymize":
            from .anonymize import anonymize, anonymize_files, local_key

            if args.map_ips and not args.key:
                parser.error("--map-ips requires --key pointing to a local key file")
            key = local_key(args.key) if args.key else None
            kwargs = dict(mode=args.payload, key=key, map_ips=args.map_ips)
            if args.input.is_dir():
                files = sorted(
                    p
                    for p in args.input.iterdir()
                    if p.suffix.lower() in (".pcap", ".pcapng", ".cap") and p.is_file()
                )
                if not files:
                    raise ValueError("No capture files found in input folder")
                result = anonymize_files(files, args.output, **kwargs)
            else:
                result = anonymize(args.input, args.output, **kwargs)
            print(json.dumps(result, indent=2))
            return
        if args.command == "case":
            if not 1024 <= args.port <= 65535:
                parser.error("Port must be between 1024 and 65535")
            from .case_setup import create_case, inventory_overview

            project = create_case(
                args.folder,
                memory_limit_mb=args.memory_limit_mb,
                prefilter=args.prefilter,
                progress=lambda **s: print(f"\rIngest: {s.get('frames', 0):,} frames", end="", flush=True),
            )
            overview = inventory_overview(project.inventory())
            print("\n" + json.dumps(overview, indent=2))
            if overview.get("files"):
                by_file = ", ".join(
                    f"{f['name']}: {f.get('prefilter_excluded', 0)} excluded" for f in overview["files"]
                )
                print(f"Case summary (pre-filter excluded per file): {by_file}")
            print(f"Project: {project.path}")
            args.project = str(project.path)

        if args.command == "demo":
            truth, topology = generate(
                args.directory, scenario=args.scenario, rounds=args.rounds, ip_id=args.ip_id, ipv6=args.ipv6
            )
            project = Project(args.directory / "project", memory_limit_mb=args.memory_limit_mb)
            ids = ingest_many(project, truth["files"], parallel=args.parallel_ingest)
            bind_capture_ids(topology, {Path(path).name: cid for path, cid in zip(truth["files"], ids)})
            report = analyze(project, topology)
            if args.confirm_demo_nat:
                topology["nat_mappings"] = [
                    {k: s[k] for k in ("point_a", "point_b", "tuple_a", "tuple_b")}
                    for s in report["nat_suggestions"]
                ]
                report = analyze(project, topology)
            (args.directory / "topology.json").write_text(json.dumps(topology, indent=2), encoding="utf-8")
            (args.directory / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f'{report["verdict"]}\nOpen: packetbreaker --project "{project.path}"')
        elif args.command == "analyze":
            project = Project(args.project, memory_limit_mb=args.memory_limit_mb)
            with project.connect() as db:
                topology = (
                    json.loads(args.topology.read_text(encoding="utf-8"))
                    if args.topology
                    else project.get(db, "topology")
                )
            if not topology:
                parser.error("Save a topology in the UI or supply --topology")
            print(json.dumps(analyze(project, topology), indent=2))
        elif args.command == "import-fortinet":
            from .fortinet import import_text

            print(
                json.dumps(
                    import_text(
                        Project(args.project, memory_limit_mb=args.memory_limit_mb),
                        args.path,
                        args.start_time,
                        args.device,
                    ),
                    indent=2,
                )
            )
        elif args.command == "export":
            if args.format in ("csv", "xlsx"):
                from .engine_export import export_tables

                if not args.output:
                    parser.error("CSV/XLSX engine exports require --output (CSV is a ZIP of tables)")
                content = export_tables(
                    Project(args.project, memory_limit_mb=args.memory_limit_mb), args.format
                )
                with args.output.open("xb") as output:
                    output.write(content)
                print(f"Exported {args.output}")
                return
            content = export_report(Project(args.project, memory_limit_mb=args.memory_limit_mb), args.format)
            if args.output:
                with args.output.open("x", encoding="utf-8") as output:
                    output.write(content)
                print(f"Exported {args.output}")
            else:
                print(content, end="")
        else:
            if not 1024 <= args.port <= 65535:
                parser.error("Port must be between 1024 and 65535")
            # Check before opening the browser, so another process cannot receive it accidentally.
            sock = socket.socket()
            try:
                sock.bind(("127.0.0.1", args.port))
            finally:
                sock.close()
            import uvicorn
            from .app import create_app

            app = create_app(args.project, memory_limit_mb=args.memory_limit_mb)
            if not args.no_browser:

                def open_when_ready():
                    for _ in range(50):
                        try:
                            with socket.create_connection(("127.0.0.1", args.port), timeout=0.1):
                                webbrowser.open(
                                    f"http://127.0.0.1:{args.port}"
                                    + ("/?view=Path" if args.command == "case" else "")
                                )
                                return
                        except OSError:
                            threading.Event().wait(0.1)

                threading.Thread(target=open_when_ready, daemon=True).start()
            uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False)
    except KeyboardInterrupt:
        print("Cancelled; completed ingest batches are retained. Re-run to resume.", file=sys.stderr)
        raise SystemExit(130) from None
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
