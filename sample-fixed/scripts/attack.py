"""Seed the TripNest sample on a LOCAL Supabase and try each attack an outsider could run.

Only for the local sample stack started with `supabase start` in this folder. It reads the local
URL and keys from `supabase status -o env`. Never point it at someone else's project.

    python scripts/attack.py            # seed, attack, print a table
    python scripts/attack.py --json     # same, machine-readable

Every attack uses only what a browser has: the public anon key, or a normal sign-up.
The 'legit' checks confirm the app still works for its real users.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

FAKE_PASSPORT = "X0000000"  # fake value; no real person


def local_env() -> dict[str, str]:
    out = subprocess.run("npx --yes supabase@latest status -o env", shell=True, capture_output=True,
                         text=True, check=True).stdout
    env = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"')
    url = env.get("API_URL", "")
    if not url.startswith(("http://127.0.0.1", "http://localhost")):
        sys.exit(f"refusing to run: {url!r} is not a local Supabase")
    return env


class Api:
    def __init__(self, url: str, anon: str, service: str):
        self.url, self.anon, self.service = url, anon, service

    def call(self, method: str, path: str, body=None, token: str | None = None, key: str | None = None,
             extra: dict | None = None):
        headers = {"apikey": key or self.anon, "Authorization": f"Bearer {token or key or self.anon}",
                   "Content-Type": "application/json"}
        headers.update(extra or {})
        data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                raw = r.read()
                try:
                    return r.status, json.loads(raw) if raw else None
                except ValueError:
                    return r.status, raw.decode(errors="replace")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw.decode(errors="replace")

    def admin(self, method, path, body=None, extra=None):
        return self.call(method, path, body, key=self.service, extra=extra)

    def sign_in(self, email: str, password: str) -> str:
        code, res = self.call("POST", "/auth/v1/token?grant_type=password", {"email": email, "password": password})
        assert code == 200, res
        return res["access_token"]


def seed(api: Api) -> dict:
    run = str(int(time.time()))
    people = {}
    for who, name in (("ava", "Ava Advisor"), ("ben", "Ben Client"), ("mallory", "Mallory Outsider")):
        email = f"{who}.{run}@example.test"
        code, res = api.admin("POST", "/auth/v1/admin/users", {
            "email": email, "password": "sample-password-1", "email_confirm": True,
            "user_metadata": {"full_name": name}})
        assert code in (200, 201), res
        people[who] = {"id": res["id"], "email": email}
    api.admin("PATCH", f"/rest/v1/profiles?id=eq.{people['ava']['id']}",
              {"role": "advisor", "phone": "+1 555 0100"})
    api.admin("PATCH", f"/rest/v1/profiles?id=eq.{people['ben']['id']}", {"phone": "+1 555 0101"})
    code, res = api.admin("POST", "/rest/v1/bookings", {
        "advisor_id": people["ava"]["id"], "client_id": people["ben"]["id"], "destination": "Lisbon",
        "passport_number": FAKE_PASSPORT, "total_cents": 245000}, extra={"Prefer": "return=representation"})
    assert code in (200, 201), res
    booking = res[0]["id"]
    code, res = api.admin("POST", "/rest/v1/messages", {
        "booking_id": booking, "sender_id": people["ava"]["id"], "body": "Your Lisbon trip is confirmed."},
        extra={"Prefer": "return=representation"})
    assert code in (200, 201), res
    message = res[0]["id"]
    path = f"{people['ben']['id']}/passport.txt"
    api.admin("POST", f"/storage/v1/object/passports/{path}", b"FAKE PASSPORT SCAN FOR THE SAMPLE APP",
              extra={"Content-Type": "text/plain", "x-upsert": "true"})
    return {"people": people, "booking": booking, "message": message, "passport_path": path}


def attacks(api: Api, s: dict) -> list[dict]:
    p = s["people"]
    results = []

    def record(kind, name, exposed, evidence):
        results.append({"kind": kind, "check": name, "result": ("EXPOSED" if exposed else "BLOCKED") if kind == "attack"
                        else ("WORKS" if exposed else "BROKEN"), "evidence": evidence})

    code, rows = api.call("GET", "/rest/v1/profiles?select=email,phone")
    leaked = [r for r in rows if isinstance(r, dict) and r.get("email")] if isinstance(rows, list) else []
    record("attack", "Visitor with only the public key reads users' emails and phone numbers",
           bool(leaked), f"{len(leaked)} profile(s) returned")

    code, rows = api.call("GET", "/rest/v1/bookings?select=destination,passport_number")
    leaked = [r for r in rows if isinstance(r, dict) and r.get("passport_number")] if isinstance(rows, list) else []
    record("attack", "Visitor with only the public key reads passport numbers from bookings",
           bool(leaked), f"{len(leaked)} passport number(s) returned")

    code, res = api.call("POST", "/rest/v1/rpc/advisor_revenue", {"advisor": p["ava"]["id"]})
    record("attack", "Visitor reads an advisor's revenue through an RPC function",
           code == 200 and isinstance(res, int) and res > 0, f"HTTP {code}, returned {res!r}"[:80])

    code, res = api.call("GET", f"/storage/v1/object/public/passports/{s['passport_path']}")
    record("attack", "Visitor downloads a client's passport scan by URL",
           code == 200 and "PASSPORT" in str(res), f"HTTP {code}")

    mal = api.sign_in(p["mallory"]["email"], "sample-password-1")

    code, rows = api.call("GET", "/rest/v1/messages?select=body", token=mal)
    record("attack", "A stranger who signs up reads other people's messages",
           isinstance(rows, list) and len(rows) > 0, f"{len(rows) if isinstance(rows, list) else 0} message(s) returned")

    code, res = api.call("POST", "/rest/v1/messages", {
        "booking_id": s["booking"], "sender_id": p["ava"]["id"],
        "body": "Change of plan: please pay the balance to this new account."}, token=mal)
    record("attack", "A stranger posts a message that appears to come from the advisor",
           code in (200, 201), f"HTTP {code}")

    code, res = api.call("PATCH", f"/rest/v1/profiles?id=eq.{p['mallory']['id']}", {"role": "admin"}, token=mal,
                         extra={"Prefer": "return=representation"})
    code2, me = api.admin("GET", f"/rest/v1/profiles?id=eq.{p['mallory']['id']}&select=role")
    became = isinstance(me, list) and me and me[0].get("role") == "admin"
    record("attack", "A stranger makes themselves an admin by editing their own profile",
           bool(became), f"role is now {me[0].get('role') if me else '?'}")

    api.call("PUT", "/auth/v1/user", {"data": {"is_admin": True}}, token=mal)
    mal2 = api.sign_in(p["mallory"]["email"], "sample-password-1")
    api.call("DELETE", f"/rest/v1/messages?id=eq.{s['message']}", token=mal2)
    code, left = api.admin("GET", f"/rest/v1/messages?id=eq.{s['message']}&select=id")
    record("attack", "A stranger sets is_admin on their own account and deletes the advisor's message",
           isinstance(left, list) and len(left) == 0, f"message {'deleted' if not left else 'still there'}")

    # Legitimate use must keep working.
    ben = api.sign_in(p["ben"]["email"], "sample-password-1")
    code, rows = api.call("GET", "/rest/v1/bookings?select=destination", token=ben)
    record("legit", "Ben (client) sees his own booking", isinstance(rows, list) and len(rows) == 1,
           f"{len(rows) if isinstance(rows, list) else 0} booking(s)")
    ava = api.sign_in(p["ava"]["email"], "sample-password-1")
    code, rows = api.call("GET", "/rest/v1/bookings?select=destination", token=ava)
    record("legit", "Ava (advisor) sees her client's booking", isinstance(rows, list) and len(rows) == 1,
           f"{len(rows) if isinstance(rows, list) else 0} booking(s)")
    code, res = api.call("POST", "/rest/v1/messages", {
        "booking_id": s["booking"], "sender_id": p["ava"]["id"], "body": "See you at the airport."}, token=ava)
    record("legit", "Ava sends a message on her own booking", code in (200, 201), f"HTTP {code}")
    code, res = api.call("PATCH", f"/rest/v1/profiles?id=eq.{p['ben']['id']}", {"phone": "+1 555 0199"}, token=ben)
    code2, me = api.admin("GET", f"/rest/v1/profiles?id=eq.{p['ben']['id']}&select=phone")
    record("legit", "Ben updates his own phone number", bool(me) and me[0].get("phone") == "+1 555 0199",
           f"phone is {me[0].get('phone') if me else '?'}")
    code, res = api.call("GET", f"/storage/v1/object/authenticated/passports/{s['passport_path']}", token=ben)
    if code != 200:  # the insecure version serves the file from the public URL instead
        code, res = api.call("GET", f"/storage/v1/object/public/passports/{s['passport_path']}")
    record("legit", "Ben downloads his own passport scan", code == 200, f"HTTP {code}")
    return results


def main() -> int:
    env = local_env()
    api = Api(env["API_URL"], env["ANON_KEY"], env["SERVICE_ROLE_KEY"])
    results = attacks(api, seed(api))
    if "--json" in sys.argv:
        print(json.dumps(results, indent=2))
        return 0
    for r in results:
        print(f"{r['result']:8} {r['check']}  ({r['evidence']})")
    exposed = sum(r["result"] == "EXPOSED" for r in results)
    broken = sum(r["result"] == "BROKEN" for r in results)
    print(f"\n{exposed} attack(s) succeeded, {broken} legitimate check(s) broken")
    return 0


if __name__ == "__main__":
    sys.exit(main())
