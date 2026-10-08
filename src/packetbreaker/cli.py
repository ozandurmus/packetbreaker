import argparse
import json
from pathlib import Path
import socket
import sys
import threading
import webbrowser

from .analysis import analyze
from .ingest import ingest
from .store import Project
from .synthetic import generate


def main():
    parser = argparse.ArgumentParser(description="PacketBreaker — local multi-hop capture analysis")
    parser.add_argument("--project", default=str(Path.home() / "PacketBreaker" / "default"))
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    commands = parser.add_subparsers(dest="command")
    demo = commands.add_parser("demo", help="Generate and ingest five synthetic captures")
    demo.add_argument("directory", type=Path)
    demo.add_argument(
        "--scenario",
        default="demo",
        choices=[
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
        ],
    )
    demo.add_argument("--rounds", type=int, default=100)
    demo.add_argument(
        "--confirm-demo-nat",
        action="store_true",
        help="Confirm only mappings inferred from generated demo data",
    )
    run = commands.add_parser("analyze", help="Analyze saved or supplied topology; print JSON")
    run.add_argument("--topology", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "demo":
            truth, topology = generate(args.directory, scenario=args.scenario, rounds=args.rounds)
            project = Project(args.directory / "project")
            for point, path in zip(topology["points"], truth["files"]):
                point["capture_id"] = ingest(project, path)
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
            project = Project(args.project)
            with project.connect() as db:
                topology = (
                    json.loads(args.topology.read_text(encoding="utf-8"))
                    if args.topology
                    else project.get(db, "topology")
                )
            if not topology:
                parser.error("Save a topology in the UI or supply --topology")
            print(json.dumps(analyze(project, topology), indent=2))
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

            app = create_app(args.project)
            if not args.no_browser:

                def open_when_ready():
                    for _ in range(50):
                        try:
                            with socket.create_connection(("127.0.0.1", args.port), timeout=0.1):
                                webbrowser.open(f"http://127.0.0.1:{args.port}")
                                return
                        except OSError:
                            threading.Event().wait(0.1)

                threading.Thread(target=open_when_ready, daemon=True).start()
            uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False)
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
