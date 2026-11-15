"""Run a Supabase project as a local copy, and refuse anything that is not local.

    python -m kit copy <project>                        # start it, or reset it to its migrations
    python -m kit copy --schema export.sql --into work/acme
    python -m kit copy <project> --stop

A copy is rebuilt from `supabase/migrations` every time, so each run starts from the same state.
Requires Docker and Node. Set SUPABASE_CLI to use an installed CLI instead of npx.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

CLI = os.environ.get("SUPABASE_CLI", "npx --yes supabase@latest")
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
FIRST_MIGRATION = "00000000000000_schema.sql"


class LocalError(RuntimeError):
    """The local copy could not be started or read."""


def is_local(url: str) -> bool:
    try:
        return urlsplit(url).hostname in LOCAL_HOSTS
    except ValueError:
        return False


def cli(args: list[str], project: Path, quiet: bool = True) -> subprocess.CompletedProcess:
    """Run the Supabase CLI in the project folder. With quiet off, its progress goes to the terminal."""
    parts = shlex.split(CLI, posix=os.name != "nt") + args
    exe = shutil.which(parts[0])  # on Windows npx is npx.cmd, which only a full path starts without a shell
    if exe is None:
        raise LocalError(f"`{parts[0]}` not found: install Node, or set SUPABASE_CLI to an installed Supabase CLI")
    if quiet:
        return subprocess.run([exe, *parts[1:]], cwd=project, text=True, capture_output=True)
    return subprocess.run([exe, *parts[1:]], cwd=project, text=True, stdout=sys.stderr)


def env(project: Path) -> dict[str, str]:
    """The running copy's address and keys. Refuses a copy that is not on this machine."""
    done = cli(["status", "-o", "env"], project)
    if done.returncode != 0:
        raise LocalError(f"no local Supabase is running for {project}: start it with `python -m kit copy {project}`")
    found: dict[str, str] = {}
    for line in done.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            found[k.strip()] = v.strip().strip('"')
    missing = [k for k in ("API_URL", "ANON_KEY", "SERVICE_ROLE_KEY") if not found.get(k)]
    if missing:
        raise LocalError(f"`supabase status` did not report {missing}; it reported {sorted(found)}")
    if not is_local(found["API_URL"]):
        raise LocalError(f"refusing to run: {found['API_URL']!r} is not a local Supabase")
    return found


def running(project: Path) -> bool:
    return cli(["status", "-o", "env"], project).returncode == 0


def start(project: Path, stop_others: bool = False) -> dict[str, str]:
    """Start the copy, or reset a running one, so the database holds exactly what the migrations say."""
    supabase = project / "supabase"
    if not (supabase / "migrations").is_dir():
        raise LocalError(f"{supabase / 'migrations'} not found: point at the app's folder, or use --schema")
    config = supabase / "config.toml"
    if not config.is_file():
        config.write_text(f'project_id = "{project.resolve().name}"\n', encoding="utf-8")
    if not running(project):
        if stop_others:
            cli(["stop", "--all"], project, quiet=False)
        if cli(["start"], project, quiet=False).returncode != 0:
            hint = "" if stop_others else " If another local Supabase holds the ports, run again with --stop-others."
            raise LocalError("`supabase start` failed; its output is above." + hint)
    # A stopped copy comes back with the rows of its last run, so reset even after a fresh start.
    if cli(["db", "reset"], project, quiet=False).returncode != 0:
        raise LocalError("`supabase db reset` failed; its output is above")
    return env(project)


def stop(project: Path) -> None:
    cli(["stop"], project, quiet=False)


def from_schema(schema: Path, into: Path) -> Path:
    """Build a project folder around a schema export, so it can be started like any other app.

    A schema export holds the public schema. Storage buckets and their policies live elsewhere and are
    not in it: add them to the folder as a second migration before testing them.
    """
    if not schema.is_file():
        raise LocalError(f"{schema} not found")
    migrations = into / "supabase" / "migrations"
    if migrations.is_dir() and any(migrations.iterdir()):
        raise LocalError(f"{migrations} already has migrations; choose an empty folder for --into")
    migrations.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(schema, migrations / FIRST_MIGRATION)
    (into / "supabase" / "config.toml").write_text(f'project_id = "{into.resolve().name}"\n', encoding="utf-8")
    return into
