#!/usr/bin/env python3
"""Non-destructive security tests for the CNS lab. Runs from Kali against the Ubuntu VM ONLY.
Stdlib only. Every result is an observed HTTP response; nothing is simulated.
Side effects on the target: creates 5 throwaway test accounts and a few test messages (kept as evidence)."""
import argparse
import base64
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

ALLOWED_HOST = "192.168.56.102"
DEFAULT_TARGET = f"http://{ALLOWED_HOST}:5000"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    def json(self):
        try:
            return json.loads(self.body)
        except Exception:
            return None


class Client:
    def __init__(self, base):
        self.base = base
        self.jar = CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect)
        self.csrf = None

    def req(self, method, path, form=None, js=None, raw=None, headers=None, csrf=False):
        h = dict(headers or {})
        data = None
        if js is not None:
            data = json.dumps(js).encode(); h["Content-Type"] = "application/json"
        elif form is not None:
            data = urllib.parse.urlencode(form).encode(); h["Content-Type"] = "application/x-www-form-urlencoded"
        elif raw is not None:
            data = raw; h.setdefault("Content-Type", "application/json")
        if csrf:
            h["X-CSRFToken"] = self.token()
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with self.op.open(r, timeout=10) as resp:
                return Resp(resp.status, resp.headers, resp.read())
        except urllib.error.HTTPError as e:
            return Resp(e.code, e.headers, e.read())

    def token(self):
        self.csrf = self.req("GET", "/api/csrf").json()["csrf_token"]
        return self.csrf

    def cookie(self, name="session"):
        return next((c.value for c in self.jar if c.name == name), None)

    def register(self, u, p):
        return self.req("POST", "/register", form={"username": u, "password": p, "confirm": p, "csrf_token": self.token()})

    def login(self, u, p):
        return self.req("POST", "/login", form={"username": u, "password": p, "csrf_token": self.token()})


RESULTS = []


def record(tid, name, expected, observed, passed, note=""):
    RESULTS.append({"id": tid, "test": name, "expected": expected, "observed": observed,
                    "result": "PASS" if passed else "FAIL", "note": note})
    print(f"[{'PASS' if passed else 'FAIL'}] {tid} {name}\n       expected: {expected}\n       observed: {observed}" + (f"\n       note: {note}" if note else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=DEFAULT_TARGET)
    ap.add_argument("--selftest-localhost", action="store_true",
                    help="developer option: allow 127.0.0.1 so the script itself can be tested off-lab")
    args = ap.parse_args()
    host = urllib.parse.urlparse(args.target).hostname
    if host != ALLOWED_HOST and not (args.selftest_localhost and host == "127.0.0.1"):
        sys.exit(f"REFUSED: this tool only targets {ALLOWED_HOST} (your private lab). Got {host!r}.")
    base = args.target.rstrip("/")
    sfx = secrets.token_hex(3)
    pw = "Lab-" + secrets.token_urlsafe(12) + "9"
    ua, ub, uc, ud = f"kali_a_{sfx}", f"kali_b_{sfx}", f"kali_c_{sfx}", f"kali_d_{sfx}"
    A, B, C, D = Client(base), Client(base), Client(base), Client(base)
    print(f"Target {base}  run-id {sfx}  started {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # T01 connectivity / health
    try:
        r = A.req("GET", "/api/health"); j = r.json() or {}
    except urllib.error.URLError as exc:
        record("T01", "Connectivity and health", "200 and status=ok", f"UNREACHABLE: {exc.reason}", False)
        finish(base)
    
    record("T01", "Connectivity and health", "200 and status=ok", f"HTTP {r.status}, {j}", r.status == 200 and j.get("status") == "ok")
    if r.status != 200:
        finish(base); return

    # T02 registration + login
    rr = [c.register(u, pw).status for c, u in ((A, ua), (B, ub), (C, uc), (D, ud))]
    ll = [c.login(u, pw).status for c, u in ((A, ua), (B, ub), (C, uc), (D, ud))]
    record("T02", "Register and log in 4 test users", "302 x4 (register) then 302 x4 (login)", f"register={rr} login={ll}",
           rr == [302] * 4 and ll == [302] * 4)

    # T03 invalid credentials
    x = Client(base); r1 = x.login(ud, "Wrong-" + pw); r2 = x.login("nosuch_" + sfx, "Wrong-" + pw)
    same = "Invalid username or password." in r1.text and "Invalid username or password." in r2.text
    record("T03", "Invalid credentials rejected, no user enumeration", "401 for both, identical message",
           f"known user={r1.status}, unknown user={r2.status}, identical message={same}", r1.status == r2.status == 401 and same)

    # T04 unauthenticated access
    x = Client(base)
    obs = {p: x.req("GET", p).status for p in ("/dashboard", "/inbox", "/compose", "/events", "/status", "/api/me", "/api/messages", "/api/messages/1", "/api/messages/1/envelope")}
    ok = all((s in (302, 401)) for s in obs.values())
    record("T04", "Unauthenticated access denied", "302 (pages) / 401 (API) for every protected path", str(obs), ok)

    # T05 messaging + IDOR
    s = A.req("POST", "/api/messages", js={"recipient": ub, "body": f"kali-test-{sfx} confidential"}, csrf=True)
    mid = (s.json() or {}).get("id")
    record("T05a", "Authenticated send A->B", "201 with message id", f"HTTP {s.status} id={mid}", s.status == 201 and mid is not None)
    if mid:
        got = {"B(recipient)": B.req("GET", f"/api/messages/{mid}"), "A(sender)": A.req("GET", f"/api/messages/{mid}")}
        okb = all(g.status == 200 and (g.json() or {}).get("verification") == "verified" for g in got.values())
        record("T05b", "Authorized parties can read + verify", "200, verification=verified for sender and recipient",
               {k: (v.status, (v.json() or {}).get("verification")) for k, v in got.items()}.__str__(), okb)
        idor = {p: C.req("GET", p).status for p in (f"/api/messages/{mid}", f"/api/messages/{mid}/envelope", f"/messages/{mid}")}
        leak = "kali-test" in "".join(C.req("GET", p).text for p in (f"/api/messages/{mid}", f"/messages/{mid}"))
        record("T05c", "IDOR: third user cannot read A->B message", "404 on API, envelope and HTML; no plaintext",
               f"{idor}, plaintext leaked={leak}", all(v == 404 for v in idor.values()) and not leak)
        sweep = {i: C.req("GET", f"/api/messages/{i}").status for i in range(max(1, mid - 5), mid + 6)}
        record("T05d", "ID enumeration sweep by third user", "only 404 for every id (no 200/403 oracle)",
               f"statuses seen={sorted(set(sweep.values()))}", set(sweep.values()) == {404})

    # T06 SQL injection
    payloads = ["' OR '1'='1' --", "admin'--", "x'; DROP TABLE users;--", "1 UNION SELECT username,password_hash FROM users--"]
    x = Client(base); obs = []
    for p in payloads:
        obs.append(("login-user", x.login(p, "x").status)); obs.append(("login-pass", x.login(ud, p).status))
    obs.append(("register", Client(base).register("a'b" + sfx, pw).status))
    obs.append(("recipient", A.req("POST", "/api/messages", js={"recipient": payloads[0], "body": "x"}, csrf=True).status))
    obs.append(("box-param", A.req("GET", "/api/messages?box=" + urllib.parse.quote(payloads[3])).status))
    obs.append(("path-id", A.req("GET", "/api/messages/1%20OR%201=1").status))
    bad = [o for o in obs if o[1] >= 500 or o[1] in (200, 201, 302) and o[0] in ("login-user", "login-pass", "recipient")]
    still = Client(base).login(ua, pw).status
    record("T06", "SQL injection resistance (inputs: login, register, recipient, query, path)",
           "no 5xx, no auth bypass, users table intact (legit login still 302)",
           f"statuses={[o[1] for o in obs]}, anomalies={bad}, legit login after={still}", not bad and still == 302,
           "password-field payloads target throwaway user D, which the throttle may lock; legit check uses user A")

    # T07 CSRF
    y = Client(base); y.login(ua, pw)
    a = y.req("POST", "/api/messages", js={"recipient": ub, "body": "csrf"}).status
    b = y.req("POST", "/api/messages", js={"recipient": ub, "body": "csrf"}, headers={"X-CSRFToken": "forged"}).status
    c = y.req("POST", "/logout").status
    d = y.req("GET", "/api/me").status
    record("T07", "CSRF protection", "400 without token, 400 with forged token, 400 on logout w/o token; session still valid",
           f"no-token={a}, forged={b}, logout-no-token={c}, still-logged-in={d}", a == b == c == 400 and d == 200)

    # T08 session controls (dedicated user: logout invalidates ALL sessions of that account)
    ue = f"kali_e_{sfx}"; z = Client(base); z.register(ue, pw); r = z.login(ue, pw); sc = " | ".join(r.headers.get_all("Set-Cookie") or [])
    flags = {"HttpOnly": "httponly" in sc.lower(), "SameSite": "samesite" in sc.lower()}
    old = z.cookie()
    z.req("POST", "/logout", form={"csrf_token": z.token()})
    replay = Client(base); replay.jar.set_cookie(__import__("http.cookiejar").cookiejar.Cookie(
        0, "session", old, None, False, host, True, False, "/", True, False, None, False, None, None, {}))
    st = replay.req("GET", "/api/me").status
    record("T08", "Session cookie flags and server-side logout invalidation",
           "HttpOnly+SameSite present; replaying pre-logout cookie -> 401",
           f"flags={flags}, replay status={st}", all(flags.values()) and st == 401,
           "Secure flag intentionally absent: lab uses plain HTTP (see docs/limitations.md)")

    # T09 tamper tests via /api/verify
    if mid:
        env = A.req("GET", f"/api/messages/{mid}/envelope").json()
        def verify(e): return (A.req("POST", "/api/verify", js=e, csrf=True).json() or {}).get("valid")
        def flip(b64v):
            raw = bytearray(base64.b64decode(b64v)); raw[0] ^= 1; return base64.b64encode(bytes(raw)).decode()
        cases = {"unmodified": (env, True),
                 "ciphertext bit flip": (dict(env, ciphertext=flip(env["ciphertext"])), False),
                 "signature bit flip": (dict(env, signature=flip(env["signature"])), False),
                 "nonce bit flip": (dict(env, nonce=flip(env["nonce"])), False),
                 "recipient_id changed": (dict(env, recipient_id=env["sender_id"]), False),
                 "created_at changed": (dict(env, created_at="2001-01-01T00:00:00.000000Z"), False)}
        obs = {k: verify(e) for k, (e, _) in cases.items()}
        okc = all(obs[k] is exp for k, (_, exp) in cases.items())
        record("T09", "Modified ciphertext / signature / metadata rejected (server-side verification)",
               "valid=true only for the unmodified envelope", json.dumps(obs), okc)

    # T10 error handling
    x = Client(base)
    e1 = x.req("GET", "/does-not-exist-" + sfx); e2 = A.req("POST", "/api/verify", raw=b"{not json", csrf=True)
    e3 = A.req("POST", "/api/messages", raw=b"x" * 100000, csrf=True)
    trace = any("Traceback" in r.text or "File \"" in r.text for r in (e1, e2, e3))
    record("T10", "Error handling without information leakage", "404 / 400 / 413, no stack trace in body",
           f"404-page={e1.status}, bad-json={e2.status}, oversize={e3.status}, traceback_in_body={trace}",
           e1.status == 404 and e2.status == 400 and e3.status == 413 and not trace,
           f"informational: Server header = {x.req('GET', '/api/health').headers.get('Server')!r}")

    # T11 rate limiting (last: it locks only this throwaway username from this IP)
    x = Client(base); ghost = f"ratelimit_{sfx}"; codes = []
    for _ in range(8):
        codes.append(x.login(ghost, "Wrong-" + pw).status)
    first = codes.index(429) + 1 if 429 in codes else None
    ra = x.login(ghost, "Wrong-" + pw)
    record("T11", "Login throttling", "401 for the first 5 failures, then 429 with Retry-After",
           f"codes={codes}, first 429 at attempt {first}, Retry-After={ra.headers.get('Retry-After')}",
           codes[:5] == [401] * 5 and first == 6 and ra.headers.get("Retry-After") is not None)
    finish(base)


def finish(base):
    passed = sum(r["result"] == "PASS" for r in RESULTS)
    print(f"\nSUMMARY: {passed}/{len(RESULTS)} passed")
    out = Path(__file__).parent / "results"; out.mkdir(exist_ok=True)
    f = out / f"kali-run-{time.strftime('%Y%m%d-%H%M%S')}.json"
    f.write_text(json.dumps({"target": base, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "results": RESULTS}, indent=2))
    print("Results saved to", f)
    sys.exit(0 if passed == len(RESULTS) else 1)


if __name__ == "__main__":
    main()
