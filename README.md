# Railo Supabase audit

Railo's audit-and-fix service for apps built on Supabase with AI app builders (Lovable, Bolt, Cursor)
or by hand: the checker, a deliberately insecure sample app, its fixed version, and the sample report.

- `REPORT.md` — the sample audit, written for clients: 13 findings, 8 of 8 attacks working before the
  fixes, 0 of 8 after, and normal use unchanged.
- `checker/supabase_audit.py` — static checker, standard library only. `python checker/supabase_audit.py <project>`.
  Rules SB001–SB012: RLS off, open policies, writes as anyone, privileged columns users can edit,
  metadata-based admin checks, security-definer functions, public buckets, service-role keys in
  frontend code or committed, and edge functions without a login.
- `checker/tests/` — `python -m pytest` (11 tests).
- `checker/selfcheck.sql` — five read-only queries an app owner can paste into the Supabase SQL editor.
- `sample/` — TripNest, the insecure app. `sample/scripts/attack.py` seeds a LOCAL Supabase and runs
  the attacks. It refuses to run against anything but localhost.
- `sample-fixed/` — the same app after the fixes; the only database change is
  `supabase/migrations/20261113000002_railo_fixes.sql`.
- `before.json`, `after.json`, `findings-before.json`, `findings-after.json` — recorded results.

Rules for client work: test only projects the client owns, with written permission, and never run the
attack script against a hosted project.
