"""A tiny in-memory stand-in for a local Supabase, for tests that must not need Docker.

It has two moods. Open: every request is allowed, like an app with no access rules. Closed: only the
service role gets through, like an app locked so hard its own users are shut out. Real access rules
are tested against a real local Supabase, not here.
"""
from __future__ import annotations

import itertools
from urllib.parse import parse_qsl, unquote, urlsplit

SERVICE = "service-key"
ANON = "anon-key"


class FakeSupabase:
    url = "http://127.0.0.1:54321"

    def __init__(self, open_to_all: bool = True, rpc: dict | None = None):
        self.open = open_to_all
        self.rpc = rpc or {}
        self.tables: dict[str, list[dict]] = {}
        self.files: dict[str, bytes] = {}
        self.users: dict[str, dict] = {}
        self._ids = itertools.count(1)
        self.calls: list[tuple[str, str, str]] = []  # (who, method, path)

    # Same surface as kit.probe.Api
    def call(self, method, path, body=None, token=None, key=None, extra=None):
        who = "service" if key == SERVICE else (token or "visitor")
        self.calls.append((who, method, path))
        return self._route(method, path, body, who == "service", extra or {})

    def admin(self, method, path, body=None, extra=None):
        return self.call(method, path, body, key=SERVICE, extra=extra)

    def sign_in(self, email):
        return f"token-of-{email}-{next(self._ids)}"

    def _route(self, method, path, body, trusted, extra):
        parts = urlsplit(path)
        if parts.path == "/auth/v1/admin/users":
            user = {"id": f"user-{next(self._ids)}", "email": body["email"]}
            self.users[user["id"]] = user
            # The sample's sign-up trigger makes a profile row for every new user.
            self.tables.setdefault("profiles", []).append(
                {"id": user["id"], "email": user["email"], "phone": None, "role": "client"})
            return 200, user
        if parts.path == "/auth/v1/user":
            return 200, {}
        allowed = trusted or self.open
        if parts.path.startswith("/rest/v1/rpc/"):
            return (200, self.rpc.get(parts.path.rsplit("/", 1)[1])) if allowed else (401, {"message": "denied"})
        if parts.path.startswith("/rest/v1/"):
            return self._table(method, parts.path.rsplit("/", 1)[1], parts.query, body, allowed, extra)
        if parts.path.startswith("/storage/v1/object/"):
            name = unquote(parts.path[len("/storage/v1/object/"):])
            for route in ("public/", "authenticated/"):
                name = name.removeprefix(route)
            if method == "POST":
                self.files[name] = body
                return 200, {"Key": name}
            if allowed and name in self.files:
                return 200, self.files[name].decode()
            return 400, {"message": "not found"}
        raise AssertionError(f"the fake has no route for {method} {path}")

    def _table(self, method, table, query, body, allowed, extra):
        rows = self.tables.setdefault(table, [])
        params = parse_qsl(query)
        wanted = {k: v.removeprefix("eq.") for k, v in params if k != "select"}
        columns = next((v.split(",") for k, v in params if k == "select"), None)
        hits = [r for r in rows if all(str(r.get(k)) == v for k, v in wanted.items())]
        if method == "GET":
            if not allowed:
                return 200, []
            return 200, [r if columns in (None, ["*"]) else {c: r.get(c) for c in columns} for r in hits]
        if method == "POST":
            if not allowed:
                return 403, {"message": "denied"}
            row = {"id": next(self._ids), **body}
            rows.append(row)
            return 201, [row] if "return=representation" in extra.get("Prefer", "") else None
        if method == "PATCH":
            if allowed:
                for r in hits:
                    r.update(body)
            return 200, hits if allowed else []
        if method == "DELETE":
            if allowed:
                self.tables[table] = [r for r in rows if r not in hits]
            return 204, None
        raise AssertionError(f"the fake does not handle {method}")
