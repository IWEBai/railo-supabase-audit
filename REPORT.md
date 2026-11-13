# Sample audit: TripNest, a Supabase app built the way AI app builders build them

Railo, 13 November 2026. This is a sample report: the app was written by Railo for this audit, in the
structure Lovable generates (React frontend, Supabase database, storage and an edge function). Every
mistake in it is one that appears in real audit requests from Lovable and Supabase users. No real
person's data was used; every name, email and passport number is fake.

## Summary

TripNest lets travel advisors keep bookings for their clients, message them and store passport scans.

Before the fixes, a visitor with nothing but the app's public key could read every user's email and
phone number, every client's passport number and passport scan, and an advisor's revenue. Anyone who
signed up could read other people's messages, post messages as the advisor, and make themselves an admin.

| | Before | After |
|---|---|---|
| Findings from the static check | 13 (6 critical, 5 high, 2 medium) | 0 |
| Attacks that worked on a live copy | 8 of 8 | 0 of 8 |
| Normal use (clients and advisors) | 5 of 5 working | 5 of 5 working |

The fixes are one new database migration and changes to three code files. Nothing about how the app
looks or works for its real users changed.

## How it was tested

1. **Static check.** Railo's Supabase checker read the migrations, `supabase/config.toml`, the edge
   function and the frontend code, and reported each mistake with its file and line.
2. **Live check.** The app ran on a local Supabase. A script created three test users (an advisor, her
   client and an outsider) and tried each attack using only what any browser has: the public anon key
   and a normal sign-up. It also checked that the advisor and the client can still do their jobs.
3. **Fix and re-check.** Same checker, same script, after the fixes.

## Findings

| # | Severity | Finding | Where | Attack on the live copy | After fix |
|---|---|---|---|---|---|
| 1 | Critical | Row-level security off on `bookings`, which holds passport numbers | init migration, line 45 | Visitor read every passport number | Blocked |
| 2 | Critical | Users can change their own `role` column | init migration, line 22 | Outsider made themselves an admin | Blocked |
| 3 | Critical | Admin rule trusts `user_metadata`, which users set themselves | init migration, line 85 | Outsider set `is_admin` and deleted the advisor's message | Blocked |
| 4 | Critical | Service-role key used in frontend code | `src/integrations/supabase/admin.ts:6` | Not run (needs a production build); would give every visitor full database access | Removed |
| 5 | Critical | Service-role key placed in a `VITE_` variable | `.env.example:5` | Same as 4 | Removed |
| 6 | Critical | Export function callable without a login, using the service-role key | `supabase/config.toml` | Not run (edge runtime off); would hand anyone a CSV of all passports | Fixed in code |
| 7 | High | Every profile, with email and phone, readable by anyone | init migration, line 18 | Visitor read all emails and phone numbers | Blocked |
| 8 | High | Every message readable by any signed-in user | init migration, line 66 | Outsider read other people's messages | Blocked |
| 9 | High | Messages can be posted as anyone | init migration, line 71 | Outsider posted as the advisor: "please pay the balance to this new account" | Blocked |
| 10 | High | Revenue function callable by anyone, bypassing row-level security | init migration, line 91 | Visitor read the advisor's revenue | Blocked |
| 11 | High | Passport bucket is public | init migration, line 100 | Visitor downloaded a passport scan by URL | Blocked |
| 12 | Medium | Revenue function has no fixed `search_path` | init migration, line 91 | Not attacked | Fixed |
| 13 | Medium | Admin page decided in the browser from `user_metadata` | `src/pages/AdminDashboard.tsx:12` | Covered by 3 | Fixed |

## What was fixed

All database changes are in `sample-fixed/supabase/migrations/20261113000002_railo_fixes.sql`, one
block per finding:

- **Bookings:** row-level security on; only the advisor and the client on a booking can see it, and only
  the advisor can create or change it.
- **Profiles:** you see your own profile and the people you share a booking with. Users can edit only their
  name and phone; `role` can only be changed server-side.
- **Messages:** only the two people on a booking can read its messages, and you can only post as yourself.
- **Admin check:** reads `app_metadata`, which only the server can set.
- **Revenue function:** answers only for the advisor who calls it; anonymous calls are refused.
- **Passport bucket:** private; each client can read and upload only their own folder.

Code changes:

- The service-role client is deleted from the frontend and the key is removed from `.env.example`.
- The admin page asks the export function for data instead of querying the database with the service key.
- The export function requires a login, checks the caller's admin flag from `app_metadata`, and only then
  uses the service-role key, server-side.

## Results

Before (`before.json`):

```
EXPOSED  Visitor with only the public key reads users' emails and phone numbers  (3 profiles)
EXPOSED  Visitor with only the public key reads passport numbers from bookings  (1 passport number)
EXPOSED  Visitor reads an advisor's revenue through an RPC function  (returned 245000)
EXPOSED  Visitor downloads a client's passport scan by URL  (HTTP 200)
EXPOSED  A stranger who signs up reads other people's messages  (1 message)
EXPOSED  A stranger posts a message that appears to come from the advisor  (HTTP 201)
EXPOSED  A stranger makes themselves an admin by editing their own profile  (role is now admin)
EXPOSED  A stranger sets is_admin on their own account and deletes the advisor's message  (deleted)
```

After (`after.json`):

```
BLOCKED  Visitor with only the public key reads users' emails and phone numbers  (0 profiles)
BLOCKED  Visitor with only the public key reads passport numbers from bookings  (0 passport numbers)
BLOCKED  Visitor reads an advisor's revenue through an RPC function  (HTTP 401)
BLOCKED  Visitor downloads a client's passport scan by URL  (HTTP 400)
BLOCKED  A stranger who signs up reads other people's messages  (0 messages)
BLOCKED  A stranger posts a message that appears to come from the advisor  (HTTP 403)
BLOCKED  A stranger makes themselves an admin by editing their own profile  (role is still client)
BLOCKED  A stranger sets is_admin on their own account and deletes the advisor's message  (still there)
WORKS    Ben (client) sees his own booking
WORKS    Ava (advisor) sees her client's booking
WORKS    Ava sends a message on her own booking
WORKS    Ben updates his own phone number
WORKS    Ben downloads his own passport scan
```

## Limits of this sample

- The app was written by Railo in the style of an AI app builder, not generated by Lovable itself.
- Findings 4, 5 and 6 were confirmed by reading the code, not by attack: the frontend was not built and the
  edge-function runtime was not started for this test.
- The static checker reads files. It can miss access rules created outside migrations (for example in the
  Supabase dashboard), which is why a real audit also checks the live project's policies, with the owner's
  permission.

## Reproduce it

Requires Docker and Node. From this folder:

```
python checker/supabase_audit.py sample
cd sample && npx supabase start && python scripts/attack.py
npx supabase stop
cd ../sample-fixed && npx supabase start && python scripts/attack.py
python ../checker/supabase_audit.py .
```
