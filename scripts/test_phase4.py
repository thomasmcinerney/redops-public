#!/usr/bin/env python3
"""Phase-4 acceptance test: objective->proof links, and hostname/URL scope-guard
matching (the guard no longer fails open when scope contains a hostname).

Usage: cd ~/redops && uv run python scripts/test_phase4.py
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
SCRATCH = "/tmp/redops-phase4-test"
PORT = 19160
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
        ct = resp.headers.get("Content-Type", "")
        raw = resp.read()
        return json.loads(raw) if "json" in ct else raw.decode(errors="replace")


# ---- scope guard: pure, monkeypatched (no server, no DNS) ------------------

def t_scope_guard():
    print("T1 - scope guard handles hostnames/URLs (no fail-open)")
    import scope_guard as sg
    # the hook no longer owns these — it delegates to the shared scope module, so
    # the helpers are asserted where they actually live (a local copy here is what
    # let the hook rot into an IPv4-only weaker policy than the broker).
    check("hook delegates to redops.scope", hasattr(sg, "scope"))
    check("host suffix match", sg.scope._host_match("app.examplecorp.ai", ["examplecorp.ai"]))
    check("host non-match", not sg.scope._host_match("evil.com", ["examplecorp.ai"]))
    nets, hosts = sg.scope.partition(["10.0.0.0/24", "examplecorp.ai"])
    check("partition splits nets/hosts", len(nets) == 1 and hosts == ["examplecorp.ai"], f"{nets} {hosts}")

    class _Conn:
        def close(self):
            pass

    def run(cmd, scope_in, scope_out):
        sg.read_stdin_json = lambda: {"tool_input": {"command": cmd}}
        sg.connect_ro = lambda: _Conn()
        sg.current_engagement = lambda conn: 1
        sg.guard_enabled = lambda conn: True
        sg.scope_lists = lambda conn, eng: (scope_in, scope_out)
        sg.scope.resolve_all = lambda names: {}   # no real DNS in the test
        return sg.main()

    # hostname scope no longer aborts enforcement:
    check("blocklist hostname blocks subdomain",
          run("curl http://app.examplecorp.ai/x", [], ["examplecorp.ai"]) == 2)
    check("allowlist hostname blocks outsider",
          run("curl https://evil.com/", ["examplecorp.ai"], []) == 2)
    check("allowlist hostname allows in-scope subdomain",
          run("curl https://app.examplecorp.ai/", ["examplecorp.ai"], []) == 0)
    # classic IP behaviour still holds:
    check("blocklist IP still blocks", run("nmap 10.0.0.5", [], ["10.0.0.0/24"]) == 2)
    check("allowlist IP blocks outsider", run("curl 10.9.9.9", ["10.10.0.0/24"], []) == 2)
    check("never-block loopback passes", run("curl 127.0.0.1", ["10.10.0.0/24"], []) == 0)
    check("mixed scope: hostname entry doesn't disable IP rule",
          run("nmap 10.0.0.5", [], ["10.0.0.0/24", "examplecorp.ai"]) == 2)


# ---- objectives: proof links (server) --------------------------------------

def t_objectives():
    print("T2 - objectives link to proof (target + evidence) and render")
    eng = req("POST", "/api/engagements", {"name": "OBJ"})["id"]
    t = req("POST", "/api/targets", {"ip": "10.10.10.5", "engagement_id": eng, "status": "rooted"})
    o = req("POST", "/api/objectives",
            {"text": "Recover the GitLab deploy token", "value": "gldt-abc123",
             "target_id": t["id"], "evidence_id": 7, "engagement_id": eng})
    check("objective stores target link", o.get("target_id") == t["id"], str(o))
    check("objective stores evidence link", o.get("evidence_id") == 7, str(o))
    o2 = req("PATCH", f"/api/objectives/{o['id']}", {"status": "done"})
    check("objective marked done", o2.get("status") == "done", str(o2))
    md = req("GET", f"/api/export/{eng}?fmt=md")
    md = md if isinstance(md, str) else json.dumps(md)
    check("report shows proof link", "proof:" in md and "10.10.10.5" in md, "no proof rendered")
    check("report shows captured value", "gldt-abc123" in md)


def main():
    shutil.rmtree(SCRATCH, ignore_errors=True)
    os.makedirs(SCRATCH, exist_ok=True)
    # scope-guard tests need no server:
    t_scope_guard()
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
        t_objectives()
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
