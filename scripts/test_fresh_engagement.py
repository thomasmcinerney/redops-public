#!/usr/bin/env python3
"""Regression for the 'new engagement should start clean' report: the briefing
hooks now (a) track the operator's ACTIVE engagement (not just the newest) and
(b) tell the agent when an engagement is an empty fresh slate, so it doesn't
re-register hosts from a previous engagement's memory. Also checks the status
tool scopes its counts to the active engagement.

Usage: cd ~/redops && uv run python scripts/test_fresh_engagement.py
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = "/tmp/redops-fresh-test"
PORT = 19170
BASE = f"http://127.0.0.1:{PORT}"

os.environ["REDOPS_DATA"] = SCRATCH
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "hooks"))

FAILURES = []


def check(name, cond, detail=""):
    tag = "ok" if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f" - {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=15) as resp:
        return json.loads(resp.read())


# ---- in-process: _common + the two hooks (no server) -----------------------

def t_hooks():
    print("T1 - active-engagement tracking + fresh-slate briefing")
    shutil.rmtree(SCRATCH, ignore_errors=True)
    os.makedirs(SCRATCH, exist_ok=True)
    from redops import db
    db.init_db()
    conn = db.connect()
    a = db.insert(conn, "engagements", {"name": "OLD", "created_at": db.now()})
    db.insert(conn, "targets", {"engagement_id": a, "ip": "10.0.0.1", "status": "identified"})
    b = db.insert(conn, "engagements", {"name": "FRESH", "created_at": db.now()})
    conn.commit()

    import _common
    # active = B (also newest); empty
    db.set_state(conn, "active_engagement", str(b))
    ro = _common.connect_ro()
    check("current_engagement follows active (newest)", _common.current_engagement(ro) == b)
    check("engagement_is_empty true for fresh", _common.engagement_is_empty(ro, b) is True)
    check("engagement_is_empty false for populated", _common.engagement_is_empty(ro, a) is False)
    ro.close()

    # active = A (OLDER than newest B) — the split-brain case
    db.set_state(conn, "active_engagement", str(a))
    ro = _common.connect_ro()
    check("active older-than-newest is honoured", _common.current_engagement(ro) == a,
          f"got {_common.current_engagement(ro)} want {a}")
    ro.close()

    import user_prompt
    user_prompt.read_stdin_json = lambda: {}

    # briefings are OPT-IN: silent by default even on an empty engagement
    db.set_state(conn, "active_engagement", str(b))
    conn.commit()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        user_prompt.main()
    check("briefing silent by default (opt-in)", buf.getvalue().strip() == "",
          repr(buf.getvalue()[:120]))

    # enable briefings for the rest of the checks
    db.set_state(conn, "set:brief_on_prompt", "1")
    conn.commit()

    # user_prompt hook on the empty engagement -> stand-down notice
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        user_prompt.main()
    out_empty = buf.getvalue()
    check("user_prompt warns on empty engagement (when enabled)",
          "EMPTY" in out_empty and "fresh slate" in out_empty, repr(out_empty[:160]))

    # populated, mid-mission engagement: briefing prints but is FRAMED as
    # reference (Kimi's case — a "hello" to an agent already on a mission).
    db.insert(conn, "tasks", {"engagement_id": a, "text": "probe the portal on .14:8080",
                              "status": "pending", "created_at": db.now()})
    db.set_state(conn, "active_engagement", str(a))
    conn.commit()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        user_prompt.main()
    out_pop = buf.getvalue()
    check("populated briefing is framed as reference",
          "background state for reference" in out_pop and "do NOT" in out_pop, repr(out_pop[:200]))
    check("populated briefing still carries the queue", "probe the portal" in out_pop)
    check("no false empty-slate on populated engagement", "EMPTY" not in out_pop)

    # session_start hook on empty -> stand-down + protocol
    db.set_state(conn, "active_engagement", str(b))
    conn.commit()
    import session_start
    session_start.read_stdin_json = lambda: {}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        session_start.main()
    check("session_start warns on empty engagement", "EMPTY" in buf.getvalue())

    # A populated allowlist is still assignment context when the guard is off.
    db.set_state(conn, f"scope_in:{b}", json.dumps(["10.0.0.0/24"]))
    db.set_state(conn, "set:scope_guard", "0")
    conn.commit()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        session_start.main()
    check("session_start shows guard OFF with an assigned allowlist",
          "scope guard: OFF" in buf.getvalue() and "scope guard: ACTIVE" not in buf.getvalue())
    db.set_state(conn, "set:scope_guard", "1")
    conn.commit()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        session_start.main()
    check("session_start shows guard ACTIVE only when enabled",
          "scope guard: ACTIVE" in buf.getvalue())
    conn.close()


# ---- status tool scoping (over HTTP) ---------------------------------------

def t_status_scoping():
    print("T2 - status counts scope to the active engagement")
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
            print("scratch server did not come up")
            FAILURES.append("server up")
            return
        # populated engagement + a fresh one
        e1 = req("POST", "/api/engagements", {"name": "HAS-HOSTS"})["id"]
        req("POST", "/api/targets", {"ip": "10.1.1.1", "engagement_id": e1, "status": "identified"})
        req("POST", "/api/targets", {"ip": "10.1.1.2", "engagement_id": e1, "status": "identified"})
        e2 = req("POST", "/api/engagements", {"name": "FRESH"})["id"]  # becomes active
        # the status tool scopes to the active engagement via this exact endpoint
        scoped = req("GET", f"/api/targets?engagement_id={e2}")
        previous = req("GET", f"/api/targets?engagement_id={e1}")
        check("active (fresh) engagement sees 0 targets", len(scoped) == 0, f"{len(scoped)}")
        check("previous engagement still has its hosts", len(previous) >= 2,
              f"{len(previous)}")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


def main():
    t_hooks()
    t_status_scoping()
    print("PASS" if not FAILURES else f"FAIL ({len(FAILURES)}): {FAILURES}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
