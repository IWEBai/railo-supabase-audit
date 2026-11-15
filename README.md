# Railo Supabase audit

Railo's audit-and-fix service for apps built on Supabase with AI app builders (Lovable, Bolt, Cursor)
or by hand: the checker, a deliberately insecure sample app, its fixed version, and the sample report.

- `REPORT.md` — the sample audit, written for clients: 13 findings, 8 of 8 attacks working before the
  fixes, 0 of 8 after, and normal use unchanged.
- `checker/supabase_audit.py` — static checker, standard library only. `python checker/supabase_audit.py <project>`.
  Rules SB001–SB012: RLS off, open policies, writes as anyone, privileged columns users can edit,
  metadata-based admin checks, security-definer functions, public buckets, service-role keys in
  frontend code or committed, and edge functions without a login.
- `checker/selfcheck.sql` — five read-only queries an app owner can paste into the Supabase SQL editor.
- `kit/` — the tools that turn an audit into proof (below). Standard library only, Python 3.11 or newer.
- `jobs/tripnest.toml` — the sample's job file: the test people, the rows to seed, the attacks, the
  normal-use checks and the report wording.
- `sample/` — TripNest, the insecure app. `sample/scripts/attack.py` is the original attack script,
  written for this app only and kept so the published results can be re-run as they were recorded.
- `sample-fixed/` — the same app after the fixes; the only database change is
  `supabase/migrations/20261113000002_railo_fixes.sql`.
- `before.json`, `after.json`, `findings-before.json`, `findings-after.json` — recorded results.
- `python -m pytest` runs the tests for the checker and the kit. None of them needs Docker.

## The kit

One job file per audit. The same file runs before the fixes and after them, so the two results can be
compared line by line. Requires Docker and Node for the local copy.

```
python checker/supabase_audit.py sample --json > findings-before.json
python -m kit copy sample
python -m kit probe jobs/tripnest.toml --project sample --out before.json
python -m kit copy sample --stop

python checker/supabase_audit.py sample-fixed --json > findings-after.json
python -m kit copy sample-fixed
python -m kit probe jobs/tripnest.toml --project sample-fixed --out after.json --expect-clean
python -m kit copy sample-fixed --stop

python -m kit report jobs/tripnest.toml --findings-before findings-before.json \
    --findings-after findings-after.json --before before.json --after after.json
```

- `copy` starts a local Supabase from the app's `supabase/migrations`, or resets a running one to
  them, so every run starts from the same state. `--schema export.sql --into work/<name>` builds a
  project folder around a schema export first; that path has not been used on a client export yet.
- `probe` creates the test people, seeds the rows, and makes each attempt with only what a browser
  has: the public key, or a normal sign-up. An attack is EXPOSED or BLOCKED; a normal use WORKS or is
  BROKEN. Before an attempt reads, changes, deletes or downloads something, the service role confirms
  it is there. If it is not, the run stops with a setup error and gives no verdict, because a blocked
  attack on nothing proves nothing.
- `report` builds the summary table and the findings table from the recorded results. The counts and
  the "After fix" column are computed; the plain wording of each row comes from the job file. A
  finding the job file does not mention still gets a row.

A job file is plain TOML; `kit/job.py` describes every key, and a misspelt key is an error.

## Rules for client work

Test only projects the client owns, with written permission. Never run attacks against a hosted
project: `copy` and `probe` refuse any address that is not on this machine. Client job files and
copies of client apps stay out of this repository (`jobs/` and `work/` are ignored by git).
