#!/usr/bin/env python3
"""Phase-1 acceptance test: partial/secret-only credentials, the cred->fact
bridge (feeds R3/R8), engagement scoping/purge, and report rendering.

Runs against a SCRATCH db + a scratch API server (spawned here, torn down on
exit). Your real data/redops.db is never touched.

Usage: cd ~/redops && uv run python scripts/test_creds.py
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = "/tmp/redops-cred-test"
PORT = 19110
BASE = f"http://127.0.0.1:{PORT}"

os.environ["REDOPS_DATA"] = SCRATCH
sys.path.insert(0, str(ROOT))

FAILURES = []


def check(name: str, cond: bool, detail: str = "") -> None:
    tag = "ok" if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f" - {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def req(method: str, path: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=15) as resp:
        ct = resp.headers.get("Content-Type", "")
        raw = resp.read()
        return json.loads(raw) if "json" in ct else raw.decode(errors="replace")


def new_engagement(name: str) -> int:
    return req("POST", "/api/engagements", {"name": name})["id"]


def add_target(eng, ip, status="identified"):
    return req("POST", "/api/targets", {"ip": ip, "engagement_id": eng, "status": status})


def add_fact(eng, subject, predicate, obj=None, stype=None, otype=None, object_text=None):
    body = {"engagement_id": eng, "subject_name": subject, "predicate": predicate,
            "confidence": "confirmed", "source": "agent"}
    if stype:
        body["subject_type"] = stype
    if object_text is not None:
        body["object_text"] = object_text
    elif obj is not None:
        body["object_name"] = obj
        if otype:
            body["object_type"] = otype
    return req("POST", "/api/facts", body)


# ---------------------------------------------------------------------------

def t1_secret_only():
    print("T1 - secret-only credential (bare token, no username)")
    eng = new_engagement("T1")
    c = req("POST", "/api/credentials",
            {"secret": "gldt-Rk7Xp3Nm9Qw2Vb8Yc5", "kind": "token",
             "source": "session MC-20260320-0006", "engagement_id": eng})
    check("secret-only insert accepted", c.get("id") is not None, str(c))
    check("username stored empty", c.get("username") == "", repr(c.get("username")))
    check("status defaulted to partial", c.get("status") == "partial", c.get("status"))
    check("scoped to engagement", c.get("engagement_id") == eng, c.get("engagement_id"))
    listed = req("GET", f"/api/credentials?engagement_id={eng}")
    check("listable by engagement (no target)", any(x["id"] == c["id"] for x in listed))


def t2_username_only():
    print("T2 - username-only credential (secret not yet known)")
    eng = new_engagement("T2")
    c = req("POST", "/api/credentials",
            {"username": "jira_svc_automation", "kind": "principal", "engagement_id": eng})
    check("username-only insert accepted", c.get("id") is not None, str(c))
    check("secret stored empty", c.get("secret") == "", repr(c.get("secret")))
    check("status partial", c.get("status") == "partial", c.get("status"))
    # later: solve the secret via PATCH
    c2 = req("PATCH", f"/api/credentials/{c['id']}",
             {"secret": "Xk9#mP2$vL5nQ8wR", "status": "valid"})
    check("patched to valid with secret", c2.get("status") == "valid" and c2.get("secret"),
          str(c2))


def t3_both_required():
    print("T3 - empty/empty rejected")
    eng = new_engagement("T3")
    try:
        req("POST", "/api/credentials", {"kind": "password", "engagement_id": eng})
        check("empty cred rejected", False, "insert unexpectedly succeeded")
    except urllib.error.HTTPError as e:
        check("empty cred rejected", e.code == 400, f"code {e.code}")


def t4_bridge_and_correlation():
    print("T4 - cred->fact bridge feeds reuse/spray engine")
    eng = new_engagement("T4")
    a = add_target(eng, "10.0.0.1")
    b = add_target(eng, "10.0.0.2")
    # an auth-accepting service on host B (ssh/22 is in AUTH_PORTS)
    add_fact(eng, "10.0.0.2:22", "on-host", "10.0.0.2", stype="service", otype="host")
    add_fact(eng, "10.0.0.2:22", "listens-on", object_text="22 ssh")
    # a VALID credential on host A -> bridge asserts credential valid-on hostA
    req("POST", "/api/credentials",
        {"username": "app_user", "secret": "Megacorp_DB_2026!", "kind": "password",
         "status": "valid", "valid": True, "target_id": a["id"], "engagement_id": eng})
    facts = req("GET", f"/api/facts?engagement_id={eng}")
    valid_on = [f for f in facts if f["predicate"] == "valid-on"
                and f["subject_type"] == "credential"]
    check("bridge created a credential valid-on fact", len(valid_on) >= 1,
          f"{len(valid_on)} valid-on facts")
    wl = req("GET", f"/api/worklist?engagement_id={eng}")
    spray = [it for it in wl if "spray" in (it.get("title", "") + it.get("rationale", "")).lower()
             or "reuse" in (it.get("title", "") + it.get("rationale", "")).lower()]
    check("reuse/spray surfaced on worklist", len(spray) >= 1,
          f"worklist items: {[it.get('title') for it in wl]}")


def t5_purge_orphan():
    print("T5 - engagement reset purges target-less creds (orphan-leak fix)")
    eng = new_engagement("T5")
    c = req("POST", "/api/credentials",
            {"secret": "sk_live_orphan_2026", "kind": "api-key", "engagement_id": eng})
    before = req("GET", f"/api/credentials?engagement_id={eng}")
    check("orphan cred present before reset", any(x["id"] == c["id"] for x in before))
    req("POST", f"/api/engagements/{eng}/reset")
    after = req("GET", f"/api/credentials?engagement_id={eng}")
    check("orphan cred purged on reset", not any(x["id"] == c["id"] for x in after),
          f"{len(after)} remain")


def t6_export_renders():
    print("T6 - report renders target-less creds + Status column")
    eng = new_engagement("T6")
    req("POST", "/api/credentials",
        {"secret": "xoxb-report-token-2026", "kind": "token", "engagement_id": eng})
    md = req("GET", f"/api/export/{eng}?fmt=md")
    md = md if isinstance(md, str) else json.dumps(md)
    check("Status column in report", "Status" in md, "no Status header")
    check("no-host credentials section present", "Credentials (no host)" in md, "section missing")
    check("token rendered in report", "xoxb-report-token-2026" in md, "token absent")


# ---------------------------------------------------------------------------

def main() -> int:
    shutil.rmtree(SCRATCH, ignore_errors=True)
    os.makedirs(SCRATCH, exist_ok=True)
    env = dict(os.environ, REDOPS_DATA=SCRATCH, REDOPS_PORT=str(PORT),
               REDOPS_NO_WIRETAIL="1", REDOPS_HOST="127.0.0.1")
    server = subprocess.Popen([sys.executable, "-m", "redops.api"],
                              cwd=ROOT, env=env,
                              stdout=open(f"{SCRATCH}/server.log", "w"),
                              stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                req("GET", "/api/engagements")
                break
            except Exception:
                time.sleep(0.3)
        else:
            print("scratch server did not come up; see", f"{SCRATCH}/server.log")
            return 1
        t1_secret_only()
        t2_username_only()
        t3_both_required()
        t4_bridge_and_correlation()
        t5_purge_orphan()
        t6_export_renders()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
    print("PASS" if not FAILURES else f"FAIL ({len(FAILURES)}): {FAILURES}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
