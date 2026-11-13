from collections import Counter
from pathlib import Path

import pytest

import supabase_audit as sa

ROOT = Path(__file__).resolve().parents[2]


def ids(project: Path) -> Counter:
    return Counter(f.id for f in sa.audit(project))


def test_vulnerable_sample_finds_every_planted_mistake():
    assert ids(ROOT / "sample") == Counter({
        "SB001": 1,  # bookings without RLS
        "SB002": 2,  # profiles readable by anyone, messages readable by any signed-in user
        "SB003": 1,  # messages insertable as anyone
        "SB004": 1,  # role column updatable by its owner
        "SB005": 1,  # admin policy trusts user_metadata through is_admin()
        "SB006": 1,  # advisor_revenue without search_path
        "SB007": 1,  # advisor_revenue callable by anyone
        "SB008": 1,  # public passports bucket
        "SB010": 2,  # service-role key in .env.example and in frontend code
        "SB011": 1,  # admin page gated on user_metadata in the browser
        "SB012": 1,  # export-bookings without JWT check using the service role
    })


def test_fixed_sample_is_clean():
    assert sa.audit(ROOT / "sample-fixed") == []


def test_signup_trigger_reading_metadata_is_not_flagged():
    # handle_new_user copies full_name from raw_user_meta_data; that is not an authorization decision.
    assert not any("handle_new_user" in f.title for f in sa.audit(ROOT / "sample"))


def test_split_sql_keeps_dollar_quoted_bodies_whole():
    sql = "create function f() returns int language sql as $$ select 1; select 2 $$;\nselect 3;"
    parts = sa.split_sql(sql, "x.sql")
    assert len(parts) == 2 and "select 2" in parts[0].text and parts[1].line == 2


def test_split_sql_ignores_semicolons_in_comments_and_strings():
    sql = "-- a; b\ninsert into t values ('x;y');\n/* c; d */ select 1;"
    assert [p.text for p in sa.split_sql(sql, "x.sql")] == ["insert into t values ('x;y')", "select 1"]


def _schema(sql: str) -> sa.Schema:
    s = sa.Schema()
    for st in sa.split_sql(sql, "m.sql"):
        sa.apply_statement(s, st)
    return s


def test_dropped_policy_is_forgotten():
    s = _schema('create table public.t (id int, email text); alter table public.t enable row level security;'
                'create policy "open" on public.t for select using (true); drop policy "open" on public.t;')
    assert sa.check_schema(s) == []


def test_bucket_made_private_later_is_not_flagged():
    s = _schema("insert into storage.buckets (id, name, public) values ('b', 'b', true);"
                "update storage.buckets set public = false where id = 'b';")
    assert s.public_buckets == {}


@pytest.mark.parametrize("roles,expected", [("to anon", "anyone with the anon key"),
                                            ("to authenticated", "every signed-in user")])
def test_open_select_names_who_can_read(roles, expected):
    s = _schema(f'create table public.t (id int, phone text); alter table public.t enable row level security;'
                f'create policy "p" on public.t for select {roles} using (true);')
    [f] = sa.check_schema(s)
    assert f.id == "SB002" and expected in f.title and f.severity == "high"


def test_service_role_jwt_is_detected_anywhere(tmp_path):
    import base64
    import json
    payload = base64.urlsafe_b64encode(json.dumps({"role": "service_role"}).encode()).decode().rstrip("=")
    token = f"eyJhbGciOiJIUzI1NiJ9.{payload}.c2lnbmF0dXJlLXZhbHVl"
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.ts").write_text(f'export const key = "{token}";')
    assert "SB009" in {f.id for f in sa.audit(tmp_path)}


def test_anon_jwt_is_not_flagged(tmp_path):
    import base64
    import json
    payload = base64.urlsafe_b64encode(json.dumps({"role": "anon"}).encode()).decode().rstrip("=")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "client.ts").write_text(f'const k = "eyJhbGciOiJIUzI1NiJ9.{payload}.c2lnbmF0dXJlLXZhbHVl";')
    assert sa.audit(tmp_path) == []
