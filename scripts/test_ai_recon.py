#!/usr/bin/env python3
"""Phase-2 acceptance test: AI-native entity vocabulary + deterministic
agent-card recon. Stands up a fake A2A agent (stdlib http.server), runs the
`agent-card` / `agent-probe` tools against it, and asserts agent/model/skill/
endpoint entities+facts land — no LLM in the loop.

Usage: cd ~/redops && uv run python scripts/test_ai_recon.py
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = "/tmp/redops-airecon-test"
PORT = 19130
AGENT_PORT = 18771
BASE = f"http://127.0.0.1:{PORT}"

os.environ["REDOPS_DATA"] = SCRATCH
sys.path.insert(0, str(ROOT))

FAILURES = []

AGENT_CARD = {
    "name": "Sales Orchestrator",
    "protocolVersion": "0.2.0",
    "capabilities": {"streaming": True},
    "skills": [{"name": "sales_analysis"}, {"name": "report_builder"}],
    "metadata": {"model": "qwen2.5-7b-instruct"},
}
OPENAPI = {"paths": {"/a2a": {}, "/a2a/workflow": {}, "/agents/register": {}, "/health": {}}}
HEALTH = {"status": "healthy", "agent": "Sales Orchestrator"}


class AgentHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = None
        if self.path == "/.well-known/agent.json":
            body = AGENT_CARD
        elif self.path == "/openapi.json":
            body = OPENAPI
        elif self.path == "/health":
            body = HEALTH
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


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


def t_recon():
    print("T - agent-card recon populates the graph")
    eng = req("POST", "/api/engagements", {"name": "AIRECON"})["id"]
    req("POST", "/api/targets", {"ip": "127.0.0.1", "engagement_id": eng, "status": "identified"})
    tid = [t for t in req("GET", f"/api/targets?engagement_id={eng}")][0]["id"]
    req("POST", "/api/tools/run",
        {"tool": "agent-probe", "target_id": tid, "ip": "127.0.0.1", "port": AGENT_PORT,
         "actor": "operator", "engagement_id": eng})
    # async: poll for the runs-model fact
    facts = []
    for _ in range(40):
        facts = req("GET", f"/api/facts?engagement_id={eng}")
        if any(f["predicate"] == "runs-model" for f in facts):
            break
        time.sleep(0.25)
    graph = req("GET", f"/api/graph?engagement_id={eng}")
    types = {n["type"] for n in graph.get("nodes", [])}
    preds = {f["predicate"] for f in facts}
    check("agent entity created", "agent" in types, str(types))
    check("model entity created", "model" in types, str(types))
    check("runs-model fact recorded", "runs-model" in preds, str(preds))
    skills = [f for f in facts if f["predicate"] == "has-skill"]
    check("skills recorded as facts", len(skills) >= 2, f"{len(skills)} skills")
    endpoints = [f for f in facts if f["predicate"] == "exposes"]
    check("openapi endpoints recorded", len(endpoints) >= 3, f"{len(endpoints)} endpoints")
    model_node = [n for n in graph["nodes"] if n["type"] == "model"]
    check("model fingerprint captured", any("qwen" in n["name"].lower() for n in model_node),
          str([n["name"] for n in model_node]))


def main():
    shutil.rmtree(SCRATCH, ignore_errors=True)
    os.makedirs(SCRATCH, exist_ok=True)
    agent_srv = ThreadingHTTPServer(("127.0.0.1", AGENT_PORT), AgentHandler)
    threading.Thread(target=agent_srv.serve_forever, daemon=True).start()
    env = dict(os.environ, REDOPS_DATA=SCRATCH, REDOPS_PORT=str(PORT),
               REDOPS_NO_WIRETAIL="1", REDOPS_HOST="127.0.0.1", REDOPS_ALLOW_LOOPBACK="1")
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
        t_recon()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
        agent_srv.shutdown()
    print("PASS" if not FAILURES else f"FAIL ({len(FAILURES)}): {FAILURES}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
