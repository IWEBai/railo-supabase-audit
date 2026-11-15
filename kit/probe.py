"""Run a job file's attacks and normal-use checks against a LOCAL copy and record what happened.

    python -m kit probe jobs/tripnest.toml --project sample            # print a table
    python -m kit probe jobs/tripnest.toml --project sample --json     # machine-readable

Every attempt uses only what a browser has: the public anon key, or a normal sign-up. The service role
is used for three things only: to create the test people, to seed rows, and to look at the database
afterwards to see whether a write really happened.

An attack that returns nothing proves something only if there was something to take. So before an
attempt reads, changes, deletes or downloads, the service role confirms the row or file is there. If
it is not, the run stops with a setup error and gives no verdict at all.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote

from .job import VISITOR, Attempt, Job, fill
from .local import is_local

PASSWORD = "sample-password-1"  # test accounts on the local copy only


class SetupError(RuntimeError):
    """The copy is not in the state the job file expects, so a verdict would mean nothing."""


class Api:
    def __init__(self, url: str, anon: str, service: str):
        if not is_local(url):
            raise SetupError(f"refusing to run: {url!r} is not a local Supabase")
        self.url, self.anon, self.service = url.rstrip("/"), anon, service

    def call(self, method: str, path: str, body=None, token: str | None = None, key: str | None = None,
             extra: dict | None = None) -> tuple[int, Any]:
        headers = {"apikey": key or self.anon, "Authorization": f"Bearer {token or key or self.anon}",
                   "Content-Type": "application/json"}
        headers.update(extra or {})
        data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, _decode(r.read())
        except urllib.error.HTTPError as e:
            return e.code, _decode(e.read())

    def admin(self, method: str, path: str, body=None, extra: dict | None = None) -> tuple[int, Any]:
        return self.call(method, path, body, key=self.service, extra=extra)

    def sign_in(self, email: str) -> str:
        code, res = self.call("POST", "/auth/v1/token?grant_type=password", {"email": email, "password": PASSWORD})
        if code != 200:
            raise SetupError(f"could not sign in {email}: HTTP {code} {res!r}"[:200])
        return res["access_token"]


def _decode(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")


def _rows(res: Any) -> list[dict]:
    return [r for r in res if isinstance(r, dict)] if isinstance(res, list) else []


def _query(match: dict | None = None, select: list[str] | None = None) -> str:
    parts = [f"{quote(str(k))}=eq.{quote(str(v), safe='')}" for k, v in (match or {}).items()]
    if select:
        parts.append("select=" + ",".join(quote(c) for c in select))
    return "?" + "&".join(parts) if parts else ""


# --------------------------------------------------------------------------- people and seed


def create_people(job: Job, api: Api, run_id: str) -> dict[str, dict]:
    names: dict[str, dict] = {}
    for who, person in job.people.items():
        email = f"{who}.{run_id}@example.test"
        code, res = api.admin("POST", "/auth/v1/admin/users", {
            "email": email, "password": PASSWORD, "email_confirm": True,
            "user_metadata": person.get("metadata", {})})
        if code not in (200, 201):
            raise SetupError(f"could not create test person {who}: HTTP {code} {res!r}"[:200])
        names[who] = {"id": res["id"], "email": email}
    return names


def seed(job: Job, api: Api, names: dict[str, dict]) -> None:
    for i, raw in enumerate(job.seed, 1):
        step = fill(raw, names)
        if "insert" in step:
            code, res = api.admin("POST", f"/rest/v1/{step['insert']}", step["values"],
                                  extra={"Prefer": "return=representation"})
            if code not in (200, 201) or not _rows(res):
                raise SetupError(f"seed step {i} could not insert into `{step['insert']}`: HTTP {code} {res!r}"[:300])
            if "name" in step:
                names[step["name"]] = _rows(res)[0]
        elif "update" in step:
            code, res = api.admin("PATCH", f"/rest/v1/{step['update']}{_query(step['match'])}", step["set"],
                                  extra={"Prefer": "return=representation"})
            if code != 200 or not _rows(res):
                raise SetupError(f"seed step {i} changed no row in `{step['update']}`: HTTP {code} {res!r}"[:300])
        else:
            path = f"/storage/v1/object/{step['upload']}/{quote(step['path'])}"
            code, res = api.admin("POST", path, step["text"].encode(),
                                  extra={"Content-Type": "text/plain", "x-upsert": "true"})
            if code != 200:
                raise SetupError(f"seed step {i} could not upload to `{step['upload']}`: HTTP {code} {res!r}"[:300])


# --------------------------------------------------------------------------- the six actions
# Each returns (did it succeed, evidence). Whether success is good news depends on who tried.


def _matching(rows: list[dict], opts: dict) -> list[dict]:
    exposes = opts.get("exposes")
    return [r for r in rows if r.get(exposes)] if exposes else rows


def do_read(api: Api, table: str, opts: dict, token: str | None) -> tuple[bool, str]:
    select = opts.get("select") or ([opts["exposes"]] if opts.get("exposes") else ["*"])
    path = f"/rest/v1/{table}{_query(opts.get('match'), select)}"
    if not _matching(_rows(api.admin("GET", path)[1]), opts):
        raise SetupError(f"nothing to read in `{table}`: seed a row first, or a blocked read would prove nothing")
    got = _matching(_rows(api.call("GET", path, token=token)[1]), opts)
    done = len(got) == opts["rows"] if "rows" in opts else bool(got)
    return done, f"{len(got)} row(s) returned"


def do_insert(api: Api, table: str, opts: dict, token: str | None) -> tuple[bool, str]:
    code, _ = api.call("POST", f"/rest/v1/{table}", opts["values"], token=token)
    return code in (200, 201), f"HTTP {code}"


def do_update(api: Api, table: str, opts: dict, token: str | None) -> tuple[bool, str]:
    wanted: dict = opts["set"]
    look = f"/rest/v1/{table}{_query(opts['match'], list(wanted))}"
    before = _rows(api.admin("GET", look)[1])
    if not before:
        raise SetupError(f"no row in `{table}` matches {opts['match']}: seed it first")
    if all(before[0].get(k) == v for k, v in wanted.items()):
        raise SetupError(f"the row in `{table}` already holds {wanted}: choose a value that differs")
    api.call("PATCH", f"/rest/v1/{table}{_query(opts['match'])}", wanted, token=token)
    after = _rows(api.admin("GET", look)[1])
    row = after[0] if after else {}
    done = bool(after) and all(row.get(k) == v for k, v in wanted.items())
    return done, ", ".join(f"{k} is now {row.get(k)}" for k in wanted)


def do_delete(api: Api, table: str, opts: dict, token: str | None) -> tuple[bool, str]:
    look = f"/rest/v1/{table}{_query(opts['match'])}"
    if not _rows(api.admin("GET", look)[1]):
        raise SetupError(f"no row in `{table}` matches {opts['match']}: seed it first")
    api.call("DELETE", look, token=token)
    left = _rows(api.admin("GET", look)[1])
    return not left, "row still there" if left else "row deleted"


def do_call(api: Api, function: str, opts: dict, token: str | None) -> tuple[bool, str]:
    code, res = api.call("POST", f"/rest/v1/rpc/{function}", opts.get("args", {}), token=token)
    return code == 200 and res not in (None, 0, "", [], {}, False), f"HTTP {code}, returned {res!r}"[:80]


def do_download(api: Api, bucket: str, opts: dict, token: str | None) -> tuple[bool, str]:
    path = f"{bucket}/{quote(opts['path'])}"
    if api.admin("GET", f"/storage/v1/object/authenticated/{path}")[0] != 200:
        raise SetupError(f"no file at `{path}`: upload it in a seed step first")
    # A visitor tries the public address first; someone signed in tries their own access first.
    routes = ["public", "authenticated"] if token is None else ["authenticated", "public"]
    first = None
    for route in routes:
        code, body = api.call("GET", f"/storage/v1/object/{route}/{path}", token=token)
        first = first if first is not None else code
        if code == 200 and opts.get("contains", "") in str(body):
            return True, f"HTTP {code}"
    return False, f"HTTP {first}"


ACTIONS = {"read": do_read, "insert": do_insert, "update": do_update, "delete": do_delete,
           "call": do_call, "download": do_download}


# --------------------------------------------------------------------------- the run


def attempt(a: Attempt, api: Api, names: dict[str, dict], tokens: dict[str, str]) -> dict:
    opts = fill(a.options, names)
    token = None
    if a.who != VISITOR:
        if a.who not in tokens:
            tokens[a.who] = api.sign_in(names[a.who]["email"])
        if "self_metadata" in opts:  # set it on their own account, then sign in again so the token carries it
            api.call("PUT", "/auth/v1/user", {"data": opts.pop("self_metadata")}, token=tokens[a.who])
            tokens[a.who] = api.sign_in(names[a.who]["email"])
        token = tokens[a.who]
    done, evidence = ACTIONS[a.action](api, a.target, opts, token)
    if a.kind == "attack":
        result = "EXPOSED" if done else "BLOCKED"
    else:
        result = "WORKS" if done else "BROKEN"
    return {"kind": a.kind, "check": a.check, "result": result, "evidence": evidence}


def run(job: Job, api: Api, run_id: str | None = None) -> list[dict]:
    """Create the people, seed the rows, then make every attempt in the order the job file lists them."""
    names = create_people(job, api, run_id or str(int(time.time())))
    seed(job, api, names)
    tokens: dict[str, str] = {}
    return [attempt(a, api, names, tokens) for a in job.attacks + job.normal]


def render(results: list[dict]) -> str:
    lines = [f"{r['result']:8} {r['check']}  ({r['evidence']})" for r in results]
    exposed = sum(r["result"] == "EXPOSED" for r in results)
    broken = sum(r["result"] == "BROKEN" for r in results)
    return "\n".join(lines) + f"\n\n{exposed} attack(s) succeeded, {broken} normal use(s) broken"
