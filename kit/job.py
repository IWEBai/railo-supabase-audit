"""The job file: one TOML file per audit.

It names the test people, the rows to seed, the attacks, the normal-use checks and the wording of the
report. The same file runs before and after the fixes, so the two results can be compared line by line.

    [people.ava]
    metadata = { full_name = "Ava Advisor" }

    [[seed]]
    insert = "bookings"
    name = "booking"                       # later steps can write {booking.id}
    values = { advisor_id = "{ava.id}", destination = "Lisbon" }

    [[attack]]
    check = "Visitor reads passport numbers"
    as = "visitor"                         # or a name from [people]
    read = "bookings"
    exposes = "passport_number"

    [[normal_use]]
    check = "Ava sees her own booking"
    as = "ava"
    read = "bookings"
    rows = 1

Every attempt has exactly one action: read, insert, update, delete (a table), call (a function) or
download (a storage bucket). An unknown key is an error, because a misspelt key would quietly weaken a check.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VISITOR = "visitor"

# action -> (required keys, optional keys)
ACTIONS: dict[str, tuple[set[str], set[str]]] = {
    "read": (set(), {"select", "match", "exposes", "rows"}),
    "insert": ({"values"}, set()),
    "update": ({"match", "set"}, set()),
    "delete": ({"match"}, set()),
    "call": (set(), {"args"}),
    "download": ({"path"}, {"contains"}),
}
SEED_ACTIONS: dict[str, tuple[set[str], set[str]]] = {
    "insert": ({"values"}, {"name"}),
    "update": ({"match", "set"}, set()),
    "upload": ({"path", "text"}, set()),
}
FINDING_KEYS = {"rule", "at", "says", "where", "attack", "did", "not_attacked", "after"}
NAME = re.compile(r"^[a-z][a-z0-9_]*$")
PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\}")


class JobError(ValueError):
    """The job file is wrong; the message says where."""


@dataclass
class Attempt:
    kind: str  # "attack" or "legit"
    check: str
    who: str  # VISITOR or a name from [people]
    action: str
    target: str  # table, function or bucket
    options: dict = field(default_factory=dict)


@dataclass
class Job:
    people: dict[str, dict]
    seed: list[dict]
    attacks: list[Attempt]
    normal: list[Attempt]
    findings: list[dict]
    report: dict


def _one_action(entry: dict, actions: dict, where: str) -> str:
    found = [a for a in actions if a in entry]
    if len(found) != 1:
        raise JobError(f"{where}: needs exactly one of {', '.join(actions)}; found {found or 'none'}")
    return found[0]


def _check_keys(entry: dict, action: str, actions: dict, extra: set[str], where: str) -> None:
    required, optional = actions[action]
    allowed = required | optional | extra | {action}
    unknown = set(entry) - allowed
    if unknown:
        raise JobError(f"{where}: unknown key(s) {sorted(unknown)}; `{action}` takes {sorted(allowed - {action})}")
    missing = required - set(entry)
    if missing:
        raise JobError(f"{where}: `{action}` needs {sorted(missing)}")


def _attempt(entry: dict, kind: str, table: str, i: int, people: dict) -> Attempt:
    where = f"[[{table}]] #{i}"
    check = entry.get("check")
    if not isinstance(check, str) or not check.strip():
        raise JobError(f"{where}: needs `check`, the sentence that names it in the report")
    where = f'{where} "{check}"'
    who = entry.get("as")
    if not isinstance(who, str) or (who != VISITOR and who not in people):
        raise JobError(f"{where}: `as` must be \"{VISITOR}\" or one of {sorted(people)}; got {who!r}")
    action = _one_action(entry, ACTIONS, where)
    _check_keys(entry, action, ACTIONS, {"check", "as", "self_metadata"}, where)
    if "self_metadata" in entry and who == VISITOR:
        raise JobError(f"{where}: a visitor has no account, so `self_metadata` needs a person in `as`")
    options = {k: v for k, v in entry.items() if k not in ("check", "as", action)}
    return Attempt(kind, check, who, action, entry[action], options)


def parse(data: dict) -> Job:
    unknown = set(data) - {"people", "seed", "attack", "normal_use", "finding", "report"}
    if unknown:
        raise JobError(f"unknown table(s) {sorted(unknown)}")
    people = data.get("people", {})
    for name, person in people.items():
        if not NAME.match(name) or name == VISITOR:
            raise JobError(f"[people.{name}]: use a lower-case name other than \"{VISITOR}\"")
        if set(person) - {"metadata"}:
            raise JobError(f"[people.{name}]: only `metadata` is allowed; got {sorted(person)}")

    seed = data.get("seed", [])
    taken = set(people)
    for i, step in enumerate(seed, 1):
        where = f"[[seed]] #{i}"
        action = _one_action(step, SEED_ACTIONS, where)
        _check_keys(step, action, SEED_ACTIONS, set(), where)
        name = step.get("name")
        if name is not None:
            if not NAME.match(name) or name == VISITOR or name in taken:
                raise JobError(f"{where}: name {name!r} is taken or not a lower-case name")
            taken.add(name)

    attacks = [_attempt(e, "attack", "attack", i, people) for i, e in enumerate(data.get("attack", []), 1)]
    normal = [_attempt(e, "legit", "normal_use", i, people) for i, e in enumerate(data.get("normal_use", []), 1)]
    checks = [a.check for a in attacks + normal]
    repeated = {c for c in checks if checks.count(c) > 1}
    if repeated:
        raise JobError(f"two attempts share the check name {sorted(repeated)[0]!r}; names must differ")

    findings = data.get("finding", [])
    attack_names = {a.check for a in attacks}
    for i, row in enumerate(findings, 1):
        where = f"[[finding]] #{i}"
        if set(row) - FINDING_KEYS:
            raise JobError(f"{where}: unknown key(s) {sorted(set(row) - FINDING_KEYS)}")
        if "rule" not in row or "at" not in row:
            raise JobError(f"{where}: needs `rule` and `at`, as the checker printed them")
        if "attack" in row and row["attack"] not in attack_names:
            raise JobError(f"{where}: no [[attack]] is named {row['attack']!r}")
        if "attack" in row and "not_attacked" in row:
            raise JobError(f"{where}: give `attack` or `not_attacked`, not both")
    return Job(people, seed, attacks, normal, findings, data.get("report", {}))


def load(path: Path) -> Job:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise JobError(f"{path}: {e}") from e
    return parse(data)


def fill(value: Any, names: dict[str, dict]) -> Any:
    """Replace {name.field} with the value recorded for that person or seeded row, at any depth."""
    if isinstance(value, dict):
        return {k: fill(v, names) for k, v in value.items()}
    if isinstance(value, list):
        return [fill(v, names) for v in value]
    if not isinstance(value, str):
        return value

    def lookup(m: re.Match):
        name, key = m.group(1), m.group(2)
        if name not in names or key not in names[name]:
            raise JobError(f"{m.group(0)}: nothing recorded under that name")
        return names[name][key]

    whole = PLACEHOLDER.fullmatch(value)
    if whole:  # keep the value's own type: a numeric id stays a number
        return lookup(whole)
    return PLACEHOLDER.sub(lambda m: str(lookup(m)), value)
