import json
from pathlib import Path

import pytest

from kit import local, probe, report
from kit.job import JobError, fill, load, parse
from kit.tests.fake import ANON, SERVICE, FakeSupabase

ROOT = Path(__file__).resolve().parents[2]
JOB = ROOT / "jobs" / "tripnest.toml"


def recorded(name: str) -> list[dict]:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def tables_of(markdown: str) -> list[list[str]]:
    out, current = [], []
    for line in markdown.splitlines() + [""]:
        if line.startswith("|"):
            current.append(line)
        elif current:
            out.append(current)
            current = []
    return out


# --------------------------------------------------------------------------- the job file


def test_sample_job_lists_the_recorded_checks_in_order():
    job = load(JOB)
    listed = [(a.kind, a.check) for a in job.attacks + job.normal]
    assert listed == [(r["kind"], r["check"]) for r in recorded("before.json")]
    assert listed == [(r["kind"], r["check"]) for r in recorded("after.json")]


def test_a_misspelt_key_is_an_error_not_a_weaker_check():
    with pytest.raises(JobError, match="unknown key"):
        parse({"attack": [{"check": "x", "as": "visitor", "read": "profiles", "expose": "email"}]})


def test_an_attempt_needs_exactly_one_action():
    with pytest.raises(JobError, match="exactly one"):
        parse({"attack": [{"check": "x", "as": "visitor"}]})
    with pytest.raises(JobError, match="exactly one"):
        parse({"attack": [{"check": "x", "as": "visitor", "read": "a", "call": "b"}]})


def test_as_must_be_the_visitor_or_a_listed_person():
    with pytest.raises(JobError, match="`as` must be"):
        parse({"attack": [{"check": "x", "as": "mallory", "read": "profiles"}]})


def test_a_finding_cannot_name_an_attack_that_does_not_exist():
    with pytest.raises(JobError, match="no \\[\\[attack\\]\\] is named"):
        parse({"finding": [{"rule": "SB001", "at": "x.sql:1", "attack": "nope"}]})


def test_fill_keeps_a_lone_placeholder_typed_and_rejects_unknown_names():
    names = {"booking": {"id": 7}, "ben": {"id": "u-1"}}
    assert fill({"booking_id": "{booking.id}", "path": "{ben.id}/passport.txt"}, names) == {
        "booking_id": 7, "path": "u-1/passport.txt"}
    with pytest.raises(JobError, match="nothing recorded"):
        fill("{ava.id}", names)


# --------------------------------------------------------------------------- attacks and normal use


def run_sample(fake: FakeSupabase) -> list[dict]:
    return probe.run(load(JOB), fake, run_id="test")


def test_an_app_with_no_access_rules_is_exposed_to_every_attack_and_still_works():
    results = run_sample(FakeSupabase(open_to_all=True, rpc={"advisor_revenue": 245000}))
    assert [r["result"] for r in results] == ["EXPOSED"] * 8 + ["WORKS"] * 5


def test_an_app_locked_against_everyone_blocks_the_attacks_and_breaks_normal_use():
    results = run_sample(FakeSupabase(open_to_all=False))
    assert [r["result"] for r in results] == ["BLOCKED"] * 8 + ["BROKEN"] * 5


def test_visitor_attempts_carry_no_account():
    fake = FakeSupabase(rpc={"advisor_revenue": 245000})
    run_sample(fake)
    reads = [who for who, method, path in fake.calls if path.startswith("/rest/v1/bookings?") and method == "GET"]
    assert "visitor" in reads


def test_a_read_with_nothing_seeded_stops_instead_of_reporting_blocked():
    job = parse({"attack": [{"check": "x", "as": "visitor", "read": "bookings", "exposes": "passport_number"}]})
    with pytest.raises(probe.SetupError, match="nothing to read"):
        probe.run(job, FakeSupabase(open_to_all=False), run_id="test")


def test_a_delete_of_a_missing_row_stops_instead_of_reporting_exposed():
    job = parse({"people": {"mallory": {}},
                 "attack": [{"check": "x", "as": "mallory", "delete": "messages", "match": {"id": 99}}]})
    with pytest.raises(probe.SetupError, match="no row"):
        probe.run(job, FakeSupabase(), run_id="test")


def test_an_update_to_the_value_already_there_stops():
    job = parse({"people": {"mallory": {}},
                 "attack": [{"check": "x", "as": "mallory", "update": "profiles",
                             "match": {"id": "{mallory.id}"}, "set": {"role": "client"}}]})
    with pytest.raises(probe.SetupError, match="already holds"):
        probe.run(job, FakeSupabase(), run_id="test")


def test_a_download_of_a_missing_file_stops():
    job = parse({"attack": [{"check": "x", "as": "visitor", "download": "passports", "path": "a.txt"}]})
    with pytest.raises(probe.SetupError, match="no file"):
        probe.run(job, FakeSupabase(), run_id="test")


def test_a_write_is_judged_by_the_database_not_by_the_reply():
    # The closed fake answers PATCH with 200 and changes nothing, as Postgres does when a rule hides the row.
    job = parse({"people": {"mallory": {}},
                 "attack": [{"check": "x", "as": "mallory", "update": "profiles",
                             "match": {"id": "{mallory.id}"}, "set": {"role": "admin"}}]})
    [result] = probe.run(job, FakeSupabase(open_to_all=False), run_id="test")
    assert (result["result"], result["evidence"]) == ("BLOCKED", "role is now client")


def test_the_api_refuses_an_address_that_is_not_local():
    with pytest.raises(probe.SetupError, match="not a local Supabase"):
        probe.Api("https://abcd.supabase.co", ANON, SERVICE)
    probe.Api("http://127.0.0.1:54321", ANON, SERVICE)


# --------------------------------------------------------------------------- the local copy


@pytest.mark.parametrize("url,ok", [
    ("http://127.0.0.1:54321", True), ("http://localhost:54321", True),
    ("https://abcd.supabase.co", False), ("http://127.0.0.1.evil.example", False), ("", False),
])
def test_is_local(url, ok):
    assert local.is_local(url) is ok


def test_from_schema_builds_a_project_folder_and_will_not_overwrite_one(tmp_path):
    export = tmp_path / "export.sql"
    export.write_text("create table public.t (id int);\n", encoding="utf-8")
    project = local.from_schema(export, tmp_path / "work" / "acme")
    assert (project / "supabase" / "migrations" / local.FIRST_MIGRATION).read_text(encoding="utf-8") == export.read_text(encoding="utf-8")
    assert 'project_id = "acme"' in (project / "supabase" / "config.toml").read_text(encoding="utf-8")
    with pytest.raises(local.LocalError, match="already has migrations"):
        local.from_schema(export, project)


def test_start_refuses_a_folder_without_migrations(tmp_path):
    with pytest.raises(local.LocalError, match="migrations"):
        local.start(tmp_path)


# --------------------------------------------------------------------------- the report


def sample_report() -> str:
    return report.build(load(JOB), recorded("findings-before.json"), recorded("findings-after.json"),
                        recorded("before.json"), recorded("after.json"))


def test_the_sample_reports_tables_come_out_of_the_recorded_results_unchanged():
    written = tables_of((ROOT / "REPORT.md").read_text(encoding="utf-8"))
    assert tables_of(sample_report()) == written
    assert len(written) == 2


def test_a_finding_the_job_file_does_not_mention_still_gets_a_row():
    job = load(JOB)
    job.findings = job.findings[:3]
    table = report.findings_table(job, recorded("findings-before.json"), recorded("findings-after.json"),
                                  recorded("before.json"), recorded("after.json"))
    assert len(table.splitlines()) == 2 + 13
    assert "| 13 | Medium | Admin access is decided in the browser from user-editable metadata |" in table


def test_a_finding_still_reported_after_the_fix_is_shown_as_open():
    before = recorded("findings-before.json")
    table = report.findings_table(load(JOB), before, [before[0]], recorded("before.json"), recorded("after.json"))
    assert table.splitlines()[2].endswith("| Still open |")


def test_an_attack_that_still_works_after_the_fix_is_shown_as_exposed():
    after = recorded("after.json")
    after[1] = {**after[1], "result": "EXPOSED"}  # passport numbers still readable
    table = report.findings_table(load(JOB), recorded("findings-before.json"), [], recorded("before.json"), after)
    assert table.splitlines()[2].endswith("| Still exposed |")


def test_results_from_a_different_job_file_are_refused():
    with pytest.raises(report.ReportError, match="cannot be compared"):
        report.summary_table(load(JOB), [], [], recorded("before.json")[:-1], recorded("after.json"))
