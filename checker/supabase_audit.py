"""Railo Supabase audit: static checks for apps built on Supabase (Lovable, Bolt, Cursor, hand-written).

Reads a project's SQL migrations, supabase/config.toml, edge functions and frontend code, and reports
the access-control mistakes that let a visitor with the public anon key read or change data they
should not. Standard library only.

    python supabase_audit.py <project_dir>            # human-readable report
    python supabase_audit.py <project_dir> --json     # machine-readable
    exit code: 0 = no critical/high findings, 1 = at least one, 2 = usage error

It is a static check: it reads files, it never connects to a database. Findings are leads for a
person to confirm, not proof of exploitability; probe.py confirms the read-access ones live, on a
project you own or have written permission to test.
"""
from __future__ import annotations

import base64
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SENSITIVE_COLUMNS = re.compile(
    r"\b(email|phone|passport\w*|ssn|social_security\w*|dob|date_of_birth|address\w*|iban|"
    r"card\w*|tax_id|national_id|salary|medical\w*|diagnos\w*|password\w*|token\w*|secret\w*)\b",
    re.IGNORECASE,
)
PRIVILEGED_COLUMNS = re.compile(
    r"^(role|roles|is_admin|admin|is_staff|is_superuser|plan|tier|credits|balance|is_verified|"
    r"verified|subscription\w*|permissions?)$",
    re.IGNORECASE,
)
CLIENT_PREFIXES = ("VITE_", "NEXT_PUBLIC_", "REACT_APP_", "EXPO_PUBLIC_", "PUBLIC_", "NUXT_PUBLIC_")
CLIENT_DIRS = ("src", "app", "pages", "components", "lib", "public")
CODE_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".vue", ".svelte"}


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    location: str
    detail: str
    fix: str


# --------------------------------------------------------------------------- SQL splitting


@dataclass
class Statement:
    text: str
    file: str
    line: int


def split_sql(sql: str, file: str) -> list[Statement]:
    """Split SQL into statements, respecting quotes, dollar-quoted bodies and comments."""
    out: list[Statement] = []
    buf: list[str] = []
    i, n, line, start_line = 0, len(sql), 1, None
    dollar_tag: str | None = None
    in_single = in_double = in_line_comment = in_block_comment = False
    while i < n:
        ch = sql[i]
        if ch == "\n":
            line += 1
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                buf.append(ch)
            i += 1
            continue
        if in_block_comment:
            if sql.startswith("*/", i):
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if dollar_tag is not None:
            if sql.startswith(dollar_tag, i):
                buf.append(dollar_tag)
                i += len(dollar_tag)
                dollar_tag = None
                continue
            buf.append(ch)
            i += 1
            continue
        if in_single:
            buf.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            buf.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        if sql.startswith("--", i):
            in_line_comment = True
            i += 2
            continue
        if sql.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue
        if start_line is None and not ch.isspace():
            start_line = line
        if ch == "'":
            in_single = True
        elif ch == '"':
            in_double = True
        elif ch == "$":
            m = re.match(r"\$[A-Za-z_]*\$", sql[i:])
            if m:
                dollar_tag = m.group(0)
                buf.append(dollar_tag)
                i += len(dollar_tag)
                continue
        elif ch == ";":
            text = "".join(buf).strip()
            if text:
                out.append(Statement(text, file, start_line or line))
            buf, start_line = [], None
            i += 1
            continue
        buf.append(ch)
        i += 1
    text = "".join(buf).strip()
    if text:
        out.append(Statement(text, file, start_line or line))
    return out


def norm_ident(name: str) -> str:
    """public.profiles / "public"."profiles" / profiles -> profiles (schema dropped if public)."""
    name = name.replace('"', "").strip()
    if "." in name:
        schema, rel = name.split(".", 1)
        return rel.lower() if schema.lower() == "public" else f"{schema.lower()}.{rel.lower()}"
    return name.lower()


def balanced_after(text: str, keyword_pattern: str) -> str | None:
    """Return the parenthesised expression that follows a keyword, e.g. using ( ... )."""
    m = re.search(keyword_pattern + r"\s*\(", text, re.IGNORECASE)
    if not m:
        return None
    depth, start = 0, m.end() - 1
    for j in range(start, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : j].strip()
    return None


# --------------------------------------------------------------------------- model of the schema


@dataclass
class Table:
    name: str
    loc: str
    columns: list[str] = field(default_factory=list)
    rls: bool = False
    update_restricted: bool = False  # revoke update / column-level grant seen


@dataclass
class Policy:
    name: str
    table: str
    command: str  # select / insert / update / delete / all
    roles: list[str]
    using: str | None
    check: str | None
    loc: str


@dataclass
class Function:
    name: str
    loc: str
    header: str
    body: str
    security_definer: bool
    has_search_path: bool
    returns_trigger: bool
    execute_revoked: bool = False


@dataclass
class Schema:
    tables: dict[str, Table] = field(default_factory=dict)
    policies: dict[tuple[str, str], Policy] = field(default_factory=dict)
    functions: dict[str, Function] = field(default_factory=dict)
    public_buckets: dict[str, str] = field(default_factory=dict)  # bucket id -> location


TABLE_RE = re.compile(
    r"^create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?([\w\".]+)\s*\((.*)\)\s*$",
    re.IGNORECASE | re.DOTALL,
)
RLS_RE = re.compile(
    r"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([\w\".]+)\s+(enable|disable)\s+row\s+level\s+security",
    re.IGNORECASE,
)
POLICY_RE = re.compile(
    r"^create\s+policy\s+(\"[^\"]+\"|\w+)\s+on\s+([\w\".]+)(.*)$", re.IGNORECASE | re.DOTALL
)
DROP_POLICY_RE = re.compile(
    r"^drop\s+policy\s+(?:if\s+exists\s+)?(\"[^\"]+\"|\w+)\s+on\s+([\w\".]+)", re.IGNORECASE
)
DROP_TABLE_RE = re.compile(r"^drop\s+table\s+(?:if\s+exists\s+)?([\w\".]+)", re.IGNORECASE)
FUNC_RE = re.compile(
    r"^create\s+(?:or\s+replace\s+)?function\s+([\w\".]+)\s*\((.*?)\)(.*)$", re.IGNORECASE | re.DOTALL
)
REVOKE_UPDATE_RE = re.compile(r"^revoke\s+(?:all|update)\b.*\bon\s+(?:table\s+)?([\w\".]+)", re.IGNORECASE | re.DOTALL)
GRANT_COL_UPDATE_RE = re.compile(r"^grant\s+update\s*\(.*?\)\s+on\s+(?:table\s+)?([\w\".]+)", re.IGNORECASE | re.DOTALL)
REVOKE_EXEC_RE = re.compile(r"^revoke\s+(?:all|execute)\b.*\bon\s+function\s+([\w\".]+)", re.IGNORECASE | re.DOTALL)
BUCKET_INSERT_RE = re.compile(
    r"^insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*(.*)$", re.IGNORECASE | re.DOTALL
)
BUCKET_UPDATE_RE = re.compile(
    r"^update\s+storage\.buckets\s+set\s+public\s*=\s*(true|false)\s+where\s+(?:id|name)\s*=\s*'([^']+)'",
    re.IGNORECASE,
)


def parse_columns(body: str) -> list[str]:
    cols, depth, cur = [], 0, []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            cols.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    cols.append("".join(cur))
    names = []
    for c in cols:
        c = c.strip()
        if not c or re.match(r"^(constraint|primary\s+key|foreign\s+key|unique|check)\b", c, re.IGNORECASE):
            continue
        names.append(c.split()[0].replace('"', "").lower())
    return names


def build_schema(project: Path) -> Schema:
    schema = Schema()
    mig_dir = project / "supabase" / "migrations"
    files = sorted(mig_dir.glob("*.sql")) if mig_dir.is_dir() else []
    seed = project / "supabase" / "seed.sql"
    for f in files:
        rel = f.relative_to(project).as_posix()
        for st in split_sql(f.read_text(encoding="utf-8", errors="replace"), rel):
            apply_statement(schema, st)
    del seed  # seed data is not schema; ignored on purpose
    return schema


def apply_statement(schema: Schema, st: Statement) -> None:
    t = st.text
    loc = f"{st.file}:{st.line}"
    if m := TABLE_RE.match(t):
        name = norm_ident(m.group(1))
        if "." not in name:  # public schema only
            schema.tables[name] = Table(name, loc, parse_columns(m.group(2)))
        return
    if m := RLS_RE.match(t):
        name = norm_ident(m.group(1))
        if name in schema.tables:
            schema.tables[name].rls = m.group(2).lower() == "enable"
        return
    if m := DROP_TABLE_RE.match(t):
        schema.tables.pop(norm_ident(m.group(1)), None)
        return
    if m := POLICY_RE.match(t):
        pname = m.group(1).strip('"')
        table = norm_ident(m.group(2))
        rest = m.group(3)
        cmd = re.search(r"\bfor\s+(select|insert|update|delete|all)\b", rest, re.IGNORECASE)
        roles = re.search(r"\bto\s+([\w\s,\"]+?)(?=\s+(?:using|with\s+check)\b|$)", rest, re.IGNORECASE)
        schema.policies[(table, pname)] = Policy(
            pname,
            table,
            cmd.group(1).lower() if cmd else "all",
            [r.strip().strip('"').lower() for r in roles.group(1).split(",")] if roles else ["public"],
            balanced_after(rest, r"\busing"),
            balanced_after(rest, r"\bwith\s+check"),
            loc,
        )
        return
    if m := DROP_POLICY_RE.match(t):
        schema.policies.pop((norm_ident(m.group(2)), m.group(1).strip('"')), None)
        return
    if m := FUNC_RE.match(t):
        name = norm_ident(m.group(1))
        rest = m.group(3)
        body_m = re.search(r"\bas\s+(\$[A-Za-z_]*\$)(.*?)\1", rest, re.IGNORECASE | re.DOTALL)
        header = rest[: body_m.start()] if body_m else rest
        trailer = rest[body_m.end():] if body_m else ""
        options = header + " " + trailer
        schema.functions[name] = Function(
            name,
            loc,
            header,
            body_m.group(2) if body_m else "",
            bool(re.search(r"\bsecurity\s+definer\b", options, re.IGNORECASE)),
            bool(re.search(r"\bset\s+search_path\b", options, re.IGNORECASE)),
            bool(re.search(r"\breturns\s+trigger\b", header, re.IGNORECASE)),
        )
        return
    if m := REVOKE_EXEC_RE.match(t):
        fn = norm_ident(m.group(1))
        if fn in schema.functions and re.search(r"\bfrom\b.*\b(public|anon|authenticated)\b", t, re.IGNORECASE):
            schema.functions[fn].execute_revoked = True
        return
    if m := REVOKE_UPDATE_RE.match(t):
        name = norm_ident(m.group(1))
        if name in schema.tables:
            schema.tables[name].update_restricted = True
        return
    if m := GRANT_COL_UPDATE_RE.match(t):
        name = norm_ident(m.group(1))
        if name in schema.tables:
            schema.tables[name].update_restricted = True
        return
    if m := BUCKET_INSERT_RE.match(t):
        cols = [c.strip().strip('"').lower() for c in m.group(1).split(",")]
        if "public" in cols:
            idx_pub, idx_id = cols.index("public"), cols.index("id") if "id" in cols else 0
            for tup in re.findall(r"\(([^()]*)\)", m.group(2)):
                vals = [v.strip() for v in tup.split(",")]
                if len(vals) == len(cols) and vals[idx_pub].lower() == "true":
                    schema.public_buckets[vals[idx_id].strip("'")] = loc
        return
    if m := BUCKET_UPDATE_RE.match(t):
        bucket = m.group(2)
        if m.group(1).lower() == "true":
            schema.public_buckets[bucket] = loc
        else:
            schema.public_buckets.pop(bucket, None)


# --------------------------------------------------------------------------- checks


def is_always_true(expr: str | None) -> bool:
    return expr is not None and re.fullmatch(r"\(*\s*true\s*\)*", expr.strip(), re.IGNORECASE) is not None


def reaches_anyone(roles: list[str]) -> bool:
    return any(r in ("public", "anon") for r in roles)


def check_schema(schema: Schema) -> list[Finding]:
    out: list[Finding] = []

    for t in schema.tables.values():
        sensitive = [c for c in t.columns if SENSITIVE_COLUMNS.search(c)]
        if not t.rls:
            out.append(Finding(
                "SB001", "critical", f"Row-level security is off on table `{t.name}`",
                t.loc,
                "With RLS off, anyone holding the public anon key can read, insert, update and delete every row"
                + (f", including {', '.join(sensitive)}." if sensitive else "."),
                f"`alter table public.{t.name} enable row level security;` then add one policy per action "
                "that limits rows to their owner (for example `using (auth.uid() = owner_id)`).",
            ))

    for p in schema.policies.values():
        table = schema.tables.get(p.table)
        sensitive = [c for c in (table.columns if table else []) if SENSITIVE_COLUMNS.search(c)]
        who = "anyone with the anon key" if reaches_anyone(p.roles) else "every signed-in user"
        if p.command in ("select", "all") and is_always_true(p.using):
            out.append(Finding(
                "SB002", "high" if (sensitive or not reaches_anyone(p.roles)) else "medium",
                f"Policy \"{p.name}\" lets {who} read every row of `{p.table}`",
                p.loc,
                f"`using (true)` returns all rows to {who}"
                + (f", including {', '.join(sensitive)}." if sensitive else ".")
                + (" Most apps let anyone sign up, so 'signed-in' is not a real boundary." if not reaches_anyone(p.roles) else ""),
                "Replace `true` with an ownership check, e.g. `using (auth.uid() = id)`, or expose only "
                "non-sensitive columns through a view.",
            ))
        if p.command in ("insert", "update", "all") and is_always_true(p.check):
            out.append(Finding(
                "SB003", "high", f"Policy \"{p.name}\" lets {who} write any row into `{p.table}`",
                p.loc,
                "`with check (true)` accepts any values, so a user can create or change rows on behalf of "
                "someone else (for example setting another user's id as the sender).",
                "Check ownership in `with check`, e.g. `with check (auth.uid() = sender_id)`.",
            ))
        for expr in (p.using, p.check):
            if expr and re.search(r"user_metadata|raw_user_meta_data", expr, re.IGNORECASE):
                out.append(Finding(
                    "SB005", "critical", f"Policy \"{p.name}\" trusts user-editable metadata",
                    p.loc,
                    "`user_metadata` is set by the user (supabase.auth.updateUser), so anyone can grant themselves this access.",
                    "Use `app_metadata` (only the server can set it) or a role column the user cannot update.",
                ))
                break
        if expr_calls_metadata_function(p, schema):
            fn = expr_calls_metadata_function(p, schema)
            out.append(Finding(
                "SB005", "critical",
                f"Policy \"{p.name}\" depends on `{fn}()`, which trusts user-editable metadata",
                p.loc,
                f"`{fn}()` reads `user_metadata`, which any user can set for themselves with "
                "supabase.auth.updateUser, so anyone can pass this check.",
                f"Make `{fn}()` read `app_metadata` or a server-controlled role column instead.",
            ))

    for t in schema.tables.values():
        privileged = [c for c in t.columns if PRIVILEGED_COLUMNS.match(c)]
        updaters = [p for p in schema.policies.values()
                    if p.table == t.name and p.command in ("update", "all")]
        if privileged and updaters and not t.update_restricted:
            p = updaters[0]
            out.append(Finding(
                "SB004", "critical", f"Users can change privileged column(s) {', '.join(privileged)} on `{t.name}`",
                p.loc,
                f"Policy \"{p.name}\" allows updates and no column-level restriction exists, so a user can "
                f"update their own `{privileged[0]}` (for example make themselves an admin).",
                f"`revoke update on public.{t.name} from authenticated, anon;` then "
                f"`grant update (<safe columns>) on public.{t.name} to authenticated;`.",
            ))

    for f in schema.functions.values():
        if f.returns_trigger:
            continue
        if f.security_definer and not f.has_search_path:
            out.append(Finding(
                "SB006", "medium", f"Security-definer function `{f.name}` has no fixed search_path",
                f.loc,
                "A security-definer function runs with its owner's rights; without `set search_path` it can be "
                "tricked into using objects from another schema.",
                "Add `set search_path = ''` and schema-qualify every table in the body.",
            ))
        if f.security_definer and not f.execute_revoked and not re.search(r"auth\.uid\(\)", f.body, re.IGNORECASE):
            out.append(Finding(
                "SB007", "high", f"Security-definer function `{f.name}` can be called by anyone and skips row-level security",
                f.loc,
                "Functions in the public schema are callable through the API (`/rest/v1/rpc/...`) by anon and "
                "signed-in users. This one runs as its owner, bypasses RLS and does not check who is calling.",
                f"Check the caller inside the function (e.g. compare the argument with `auth.uid()`), or "
                f"`revoke execute on function public.{f.name} from public, anon, authenticated;`.",
            ))

    for bucket, loc in schema.public_buckets.items():
        out.append(Finding(
            "SB008", "high", f"Storage bucket `{bucket}` is public",
            loc,
            "Every file in a public bucket can be downloaded by anyone who has or guesses its URL; no policy applies.",
            f"`update storage.buckets set public = false where id = '{bucket}';` and add storage policies that "
            "limit each user to their own folder.",
        ))
    return out


def expr_calls_metadata_function(p: Policy, schema: Schema) -> str | None:
    for expr in (p.using, p.check):
        if not expr:
            continue
        for fname, f in schema.functions.items():
            if re.search(r"\b(?:public\.)?" + re.escape(fname) + r"\s*\(", expr, re.IGNORECASE) and \
                    re.search(r"user_metadata|raw_user_meta_data", f.body, re.IGNORECASE):
                return fname
    return None


def jwt_role(token: str) -> str | None:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except Exception:  # noqa: BLE001 - not a JWT
        return None


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


def check_code(project: Path) -> list[Finding]:
    out: list[Finding] = []
    skip = {"node_modules", ".git", "dist", "build", ".next", ".temp", ".branches"}
    for path in project.rglob("*"):
        if not path.is_file() or any(part in skip for part in path.parts):
            continue
        rel = path.relative_to(project).as_posix()
        is_env = path.name.startswith(".env")
        in_functions = rel.startswith("supabase/functions/")
        is_client_code = path.suffix in CODE_SUFFIXES and not in_functions and (
            rel.split("/")[0] in CLIENT_DIRS or "/" not in rel)
        if not (is_env or is_client_code or path.suffix in {".json", ".toml", ".md"}):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for tok in JWT_RE.findall(line):
                if jwt_role(tok) == "service_role":
                    out.append(Finding(
                        "SB009", "critical", "A service-role key is committed to the project",
                        f"{rel}:{lineno}",
                        "The service-role key bypasses every row-level-security policy. Anyone with it controls the database.",
                        "Rotate the key in the Supabase dashboard now, delete it from the file and from git history, "
                        "and use it only in server code.",
                    ))
            if (is_client_code or is_env) and re.search(r"service[_-]?role", line, re.IGNORECASE):
                exposed = is_client_code or any(line.lstrip().startswith(p) for p in CLIENT_PREFIXES)
                if exposed:
                    out.append(Finding(
                        "SB010", "critical", "The service-role key is used in code that ships to the browser",
                        f"{rel}:{lineno}",
                        "Anything in frontend code or in a VITE_/NEXT_PUBLIC_-style variable is bundled into the "
                        "public JavaScript, so every visitor gets a key that bypasses all row-level security.",
                        "Remove the service-role client from the frontend. Do admin work in an edge function that "
                        "checks the caller's JWT and role, and rotate the key if it was ever deployed.",
                    ))
            if is_client_code and re.search(r"user_metadata\??\.\s*(is_admin|role|admin)", line):
                out.append(Finding(
                    "SB011", "medium", "Admin access is decided in the browser from user-editable metadata",
                    f"{rel}:{lineno}",
                    "Hiding a page in the frontend does not protect its data, and `user_metadata` can be set by the user.",
                    "Enforce admin access in the database (policies) or in an edge function, from `app_metadata`.",
                ))
    return out


def check_functions(project: Path) -> list[Finding]:
    out: list[Finding] = []
    cfg = project / "supabase" / "config.toml"
    if not cfg.is_file():
        return out
    text = cfg.read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r"^\[functions\.([\w-]+)\]\s*\n((?:(?!^\[).*\n?)*)", text, re.MULTILINE):
        name, block = m.group(1), m.group(2)
        if not re.search(r"^\s*verify_jwt\s*=\s*false", block, re.MULTILINE):
            continue
        line = text[: m.start()].count("\n") + 1
        src = project / "supabase" / "functions" / name / "index.ts"
        body = src.read_text(encoding="utf-8", errors="replace") if src.is_file() else ""
        uses_service = "SERVICE_ROLE" in body
        checks_auth = re.search(r"headers\.get\(\s*['\"]authorization['\"]", body, re.IGNORECASE) or \
            re.search(r"auth\.getUser\(", body)
        sev = "critical" if uses_service and not checks_auth else "medium"
        out.append(Finding(
            "SB012", sev, f"Edge function `{name}` accepts calls without a login",
            f"supabase/config.toml:{line}",
            "`verify_jwt = false` lets anyone on the internet call it"
            + (", and it uses the service-role key without checking who is calling, so it exposes data that "
               "row-level security would block." if sev == "critical" else "."),
            "Remove `verify_jwt = false`, or check the caller inside the function with `supabase.auth.getUser()` "
            "before using the service-role client.",
        ))
    return out


def audit(project: Path) -> list[Finding]:
    findings = check_schema(build_schema(project)) + check_code(project) + check_functions(project)
    uniq: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        uniq.setdefault((f.id, f.location, f.title), f)
    return sorted(uniq.values(), key=lambda f: (SEVERITY_ORDER[f.severity], f.id, f.location))


def render(findings: list[Finding], project: Path) -> str:
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    lines = [f"Railo Supabase audit: {project}",
             "Findings: " + ", ".join(f"{n} {s}" for s, n in counts.items()), ""]
    for f in findings:
        lines += [f"[{f.severity.upper()}] {f.id} {f.title}", f"  at   {f.location}",
                  f"  why  {f.detail}", f"  fix  {f.fix}", ""]
    if not findings:
        lines.append("No findings.")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    project = Path(argv[1]).resolve()
    if not project.is_dir():
        print(f"not a directory: {project}")
        return 2
    findings = audit(project)
    if "--json" in argv:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render(findings, project))
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
