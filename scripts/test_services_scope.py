#!/usr/bin/env python3
"""Regression test: GET /api/services must honour ?engagement_id=.

services carry no engagement_id column of their own — they hang off a target.
The endpoint used to accept only target_id, so FastAPI silently DROPPED an
engagement_id query param and fell through to the unfiltered branch: the caller
asked for one engagement's ports and got EVERY service in the database back.
That is a correctness bug with teeth, because another box's open ports read as
if they belonged to the box being asked about.

Runs against a SCRATCH db + a scratch API server (spawned here, torn down on
exit) on its own port. Your real data/redops.db is never touched.

Usage: cd ~/redops && uv run python scripts/test_services_scope.py
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = "/tmp/redops-svcscope-test"
PORT = 19117
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


def add_target(eng, ip):
    return req("POST", "/api/targets", {"ip": ip, "engagement_id": eng,
                                        "status": "identified"})


def add_service(target_id, port, name):
    return req("POST", "/api/services", {"target_id": target_id, "port": port,
                                         "name": name, "state": "open"})


# ---------------------------------------------------------------------------

def t1_engagement_filter():
    """Two engagements, disjoint services. Each must see only its own."""
    print("T1 - ?engagement_id= scopes services through their target")

    # A: a Linux-shaped box. B: a Windows-shaped box, deliberately overlapping
    # on 22 so a leak cannot hide behind 'well, both have ssh'.
    eng_a = new_engagement("SVC-A")
    tgt_a = add_target(eng_a, "10.10.10.10")
    for port, name in ((22, "ssh"), (80, "http")):
        add_service(tgt_a["id"], port, name)

    eng_b = new_engagement("SVC-B")
    tgt_b = add_target(eng_b, "10.10.10.20")
    for port, name in ((22, "ssh"), (445, "microsoft-ds"), (3389, "ms-wbt-server")):
        add_service(tgt_b["id"], port, name)

    a = req("GET", f"/api/services?engagement_id={eng_a}")
    b = req("GET", f"/api/services?engagement_id={eng_b}")

    check("A returns only its own count", len(a) == 2, f"got {len(a)}: {[s['port'] for s in a]}")
    check("B returns only its own count", len(b) == 3, f"got {len(b)}: {[s['port'] for s in b]}")
    check("A's ports are A's", sorted(s["port"] for s in a) == [22, 80],
          str(sorted(s["port"] for s in a)))
    check("B's ports are B's", sorted(s["port"] for s in b) == [22, 445, 3389],
          str(sorted(s["port"] for s in b)))
    # the actual regression: B's Windows ports must not surface under A
    check("no cross-engagement leak into A", not {445, 3389} & {s["port"] for s in a},
          "A saw B's ports")
    check("every row belongs to A's target", all(s["target_id"] == tgt_a["id"] for s in a),
          str({s["target_id"] for s in a}))
    return eng_a, tgt_a, eng_b


def t2_target_filter_still_works(eng_a, tgt_a):
    """The pre-existing target_id path must be untouched by the fix."""
    print("T2 - ?target_id= still filters (no regression)")
    rows = req("GET", f"/api/services?target_id={tgt_a['id']}")
    check("target filter returns that target's rows", len(rows) == 2, f"got {len(rows)}")
    check("target filter rows all match", all(s["target_id"] == tgt_a["id"] for s in rows))


def t3_unfiltered_returns_all(eng_a, eng_b):
    """No params defaults to the active engagement."""
    print("T3 - no filter returns the active engagement")
    every = req("GET", "/api/services")
    check("unfiltered sees active engagement", len(every) == 3, f"got {len(every)}")


def t4_empty_engagement():
    """An engagement with no targets yields [], not the whole table.

    This is the shape the bug wore in practice: a freshly launched box whose
    agent has not called target_add yet. Pre-fix this returned everything.
    """
    print("T4 - engagement with no targets returns empty, not everything")
    eng = new_engagement("SVC-EMPTY")
    rows = req("GET", f"/api/services?engagement_id={eng}")
    check("empty engagement returns []", rows == [], f"got {len(rows)} rows")


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
        eng_a, tgt_a, eng_b = t1_engagement_filter()
        t2_target_filter_still_works(eng_a, tgt_a)
        t3_unfiltered_returns_all(eng_a, eng_b)
        t4_empty_engagement()
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
