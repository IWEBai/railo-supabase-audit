"""Build the report's tables from recorded results, so its numbers cannot drift from what was measured.

    python -m kit report jobs/tripnest.toml --findings-before findings-before.json \\
        --findings-after findings-after.json --before before.json --after after.json

Prints three pieces of Markdown: the summary table, the findings table and the two result lists.
The counts and the "After fix" column are computed. The plain-language wording of a row comes from the
job file's [[finding]] entries; a finding with no entry still gets a row, in the checker's own words,
so nothing the checker found can be left out of the report.
"""
from __future__ import annotations

from .job import Job

SEVERITIES = ("critical", "high", "medium", "low")


class ReportError(ValueError):
    """The recorded results and the job file do not fit together."""


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|")


def _count(findings: list[dict]) -> str:
    if not findings:
        return "0"
    parts = [f"{n} {sev}" for sev in SEVERITIES if (n := sum(f["severity"] == sev for f in findings))]
    return f"{len(findings)} ({', '.join(parts)})"


def _by_check(job: Job, results: list[dict], label: str) -> dict[str, str]:
    expected = [a.check for a in job.attacks + job.normal]
    got = [r["check"] for r in results]
    if got != expected:
        raise ReportError(f"the {label} results do not list the job file's checks in order, so the two runs "
                          f"cannot be compared; run `kit probe` again with this job file")
    return {r["check"]: r["result"] for r in results}


def summary_table(job: Job, findings_before: list[dict], findings_after: list[dict],
                  before: list[dict], after: list[dict]) -> str:
    def worked(results: list[dict], kind: str, good: str) -> str:
        mine = [r for r in results if r["kind"] == kind]
        return f"{sum(r['result'] == good for r in mine)} of {len(mine)}"

    _by_check(job, before, "before")
    _by_check(job, after, "after")
    normal = job.report.get("normal_use", "Normal use")
    return "\n".join([
        "| | Before | After |",
        "|---|---|---|",
        f"| Findings from the static check | {_count(findings_before)} | {_count(findings_after)} |",
        f"| Attacks that worked on a live copy | {worked(before, 'attack', 'EXPOSED')} "
        f"| {worked(after, 'attack', 'EXPOSED')} |",
        f"| {_cell(normal)} | {worked(before, 'legit', 'WORKS')} working | {worked(after, 'legit', 'WORKS')} working |",
    ])


def _same_finding(a: dict, b: dict) -> bool:
    # Line numbers move when a file is edited, so a finding is the same one if rule, title and file agree.
    return (a["id"], a["title"], a["location"].rsplit(":", 1)[0]) == (b["id"], b["title"], b["location"].rsplit(":", 1)[0])


def _ordered(job: Job, findings_before: list[dict]) -> list[tuple[dict, dict]]:
    """Checker findings paired with their wording: the job file's order first, then any it did not mention."""
    left = list(findings_before)
    rows: list[tuple[dict, dict]] = []
    for i, wording in enumerate(job.findings, 1):
        hits = [f for f in left if f["id"] == wording["rule"] and f["location"].endswith(wording["at"])]
        if len(hits) != 1:
            raise ReportError(f"[[finding]] #{i} ({wording['rule']} at {wording['at']}) matches {len(hits)} "
                              f"checker finding(s); it must match exactly one")
        left.remove(hits[0])
        rows.append((hits[0], wording))
    return rows + [(f, {}) for f in left]


def findings_table(job: Job, findings_before: list[dict], findings_after: list[dict],
                   before: list[dict], after: list[dict]) -> str:
    was, now = _by_check(job, before, "before"), _by_check(job, after, "after")
    lines = ["| # | Severity | Finding | Where | Attack on the live copy | After fix |", "|---|---|---|---|---|---|"]
    for n, (found, wording) in enumerate(_ordered(job, findings_before), 1):
        still_open = any(_same_finding(found, f) for f in findings_after)
        check = wording.get("attack")
        if check:
            attack = wording.get("did", check) if was[check] == "EXPOSED" else "Tried, and it did not work"
            if now[check] == "EXPOSED":
                outcome = "Still exposed"
            elif still_open:
                outcome = "Still open"
            else:
                outcome = "Blocked" if was[check] == "EXPOSED" else "Fixed"
        else:
            attack = wording.get("not_attacked", "Not attacked")
            outcome = "Still open" if still_open else wording.get("after", "Fixed")
        cells = [n, found["severity"].capitalize(), wording.get("says", found["title"]),
                 wording.get("where", f"`{found['location']}`"), attack, outcome]
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    return "\n".join(lines)


def results_list(results: list[dict]) -> str:
    return "\n".join(f"{r['result']:8} {r['check']}  ({r['evidence']})" for r in results)


def build(job: Job, findings_before: list[dict], findings_after: list[dict],
          before: list[dict], after: list[dict]) -> str:
    args = (job, findings_before, findings_after, before, after)
    return "\n\n".join([
        "## Summary", summary_table(*args),
        "## Findings", findings_table(*args),
        "## Results", "Before:", "```\n" + results_list(before) + "\n```",
        "After:", "```\n" + results_list(after) + "\n```",
    ]) + "\n"
