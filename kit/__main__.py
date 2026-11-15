"""Command line for the kit.

    python -m kit copy <project>                       start a local copy, or reset it to its migrations
    python -m kit probe <job.toml> --project <project> run the attacks and normal-use checks on the copy
    python -m kit report <job.toml> --findings-before ... --findings-after ... --before ... --after ...

Exit code: 0 = done, 1 = `probe --expect-clean` found an attack that worked or a normal use that broke,
2 = a usage or setup error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import local, probe, report
from .job import JobError, load


def _read_json(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def cmd_copy(args: argparse.Namespace) -> int:
    if args.schema:
        if not args.into:
            raise local.LocalError("--schema needs --into <folder> for the project built around the export")
        project = local.from_schema(args.schema, args.into)
    elif args.project:
        project = args.project
    else:
        raise local.LocalError("give the app's folder, or --schema <export.sql> --into <folder>")
    if args.stop:
        local.stop(project)
        return 0
    found = local.start(project, stop_others=args.stop_others)
    print(f"Local copy of {project} is running at {found['API_URL']}")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    job = load(args.job)
    found = local.env(args.project)
    results = probe.run(job, probe.Api(found["API_URL"], found["ANON_KEY"], found["SERVICE_ROLE_KEY"]))
    as_json = json.dumps(results, indent=2) + "\n"
    if args.out:
        args.out.write_text(as_json, encoding="utf-8", newline="\n")
    print(as_json if args.json else probe.render(results), end="" if args.json else "\n")
    bad = any(r["result"] in ("EXPOSED", "BROKEN") for r in results)
    return 1 if args.expect_clean and bad else 0


def cmd_report(args: argparse.Namespace) -> int:
    print(report.build(load(args.job), _read_json(args.findings_before), _read_json(args.findings_after),
                       _read_json(args.before), _read_json(args.after)), end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kit", description="Railo's kit for Supabase audits.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("copy", help="start a local copy of an app, or reset it to its migrations")
    p.add_argument("project", nargs="?", type=Path, help="the app's folder (it holds supabase/migrations)")
    p.add_argument("--schema", type=Path, help="a schema export to build a project folder around")
    p.add_argument("--into", type=Path, help="with --schema: the folder to build")
    p.add_argument("--stop", action="store_true", help="stop this copy")
    p.add_argument("--stop-others", action="store_true", help="first stop every other local Supabase on this machine")
    p.set_defaults(run=cmd_copy)

    p = sub.add_parser("probe", help="run the job file's attacks and normal-use checks on the local copy")
    p.add_argument("job", type=Path)
    p.add_argument("--project", type=Path, required=True, help="the app's folder, already started with `copy`")
    p.add_argument("--json", action="store_true", help="print the results as JSON")
    p.add_argument("--out", type=Path, help="also write the results to this file as JSON")
    p.add_argument("--expect-clean", action="store_true", help="exit 1 if an attack worked or a normal use broke")
    p.set_defaults(run=cmd_probe)

    p = sub.add_parser("report", help="build the report's tables from recorded results")
    p.add_argument("job", type=Path)
    for name in ("findings-before", "findings-after", "before", "after"):
        p.add_argument(f"--{name}", type=Path, required=True)
    p.set_defaults(run=cmd_report)

    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    try:
        return args.run(args)
    except (JobError, local.LocalError, probe.SetupError, report.ReportError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
