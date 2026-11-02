#!/usr/bin/env python3
"""Regression for engagement desync: lab IPs recur across engagements, and
resolvers that searched globally / used the newest engagement filed scans, facts
and target lookups under the WRONG engagement. Everything now resolves via the
active engagement.

Usage: cd ~/redops && uv run python scripts/test_engagement_scoping.py
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
SCRATCH = "/tmp/redops-scope-test"
PORT = 19190
BASE = f"http://127.0.0.1:{PORT}"

os.environ["REDOPS_DATA"] = SCRATCH
os.environ["REDOPS_URL"] = BASE          # so client.find_target hits this server
sys.path.insert(0, str(ROOT))

FAILURES = []
REUSED_IP = "192.168.99.5"               # the same lab host in two engagements


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


def set_active(eid):
    req("PUT", "/api/active_engagement", {"id": eid})


def main():
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
            print("scratch server did not come up")
            return 1

        # OLD engagement with the reused IP, then a NEW active engagement with the
        # same IP as a different target row.
        old = req("POST", "/api/engagements", {"name": "OLD"})["id"]
        told = req("POST", "/api/targets",
                   {"ip": REUSED_IP, "engagement_id": old, "status": "identified"})["id"]
        new = req("POST", "/api/engagements", {"name": "NEW"})["id"]   # becomes active
        tnew = req("POST", "/api/targets",
                   {"ip": REUSED_IP, "engagement_id": new, "status": "identified"})["id"]
        check("distinct target rows per engagement", told != tnew, f"{told} vs {tnew}")

        from redops import client
        print("T1 - find_target resolves within the active engagement")
        t = client.find_target(REUSED_IP)
        check("find_target returns the ACTIVE engagement's target", t["id"] == tnew,
              f"got {t['id']} want {tnew}")
        check("find_target target is scoped to active engagement",
              t["engagement_id"] == new, t.get("engagement_id"))

        print("T2 - tool run files under the active engagement even with a stale target_id")
        # simulate the agent passing the OLD target_id (as the unscoped bug did)
        req("POST", "/api/tools/run",
            {"tool": "quick-scan", "ip": REUSED_IP, "target_id": told, "actor": "agent"})
        run = None
        for _ in range(20):
            runs = req("GET", f"/api/tools/runs?engagement_id={new}")
            if runs:
                run = runs[0]
                break
            time.sleep(0.2)
        check("run recorded under the active engagement", run is not None, "no run appeared")
        if run:
            check("run re-targeted to the active engagement's host", run["target_id"] == tnew,
                  f"got {run['target_id']} want {tnew}")
        old_runs = req("GET", f"/api/tools/runs?engagement_id={old}")
        check("no run leaked onto the old engagement", len(old_runs) == 0, f"{len(old_runs)}")

        print("T3 - fact with no engagement_id lands in the active engagement")
        req("POST", "/api/facts", {"subject_name": "qdrant", "subject_type": "service",
            "predicate": "runs-as", "object_text": "system", "confidence": "confirmed",
            "source": "agent"})   # no engagement_id -> must use active (new)
        new_facts = req("GET", f"/api/facts?engagement_id={new}")
        old_facts = req("GET", f"/api/facts?engagement_id={old}")
        check("fact landed in active engagement", len(new_facts) >= 1, f"{len(new_facts)}")
        check("fact did not land in the old engagement", len(old_facts) == 0, f"{len(old_facts)}")

        print("T4 - switching active to the OLDER engagement redirects resolution")
        set_active(old)
        t2 = client.find_target(REUSED_IP)
        check("find_target follows active back to the older engagement", t2["id"] == told,
              f"got {t2['id']} want {told}")
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
