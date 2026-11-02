#!/usr/bin/env python3
"""Acceptance fixtures F1-F4 (deterministic layers) + F5 analyst plumbing
for the RedOps v6 leads/interest-capture engine.

Runs against a SCRATCH db (REDOPS_DATA=/tmp/redops-f-test) and a scratch API
server on port 19100 (spawned here, torn down on exit). Your real
data/redops.db is never touched.

F5 caveat (spec §3d/§5): this is a CANNED-RESPONSE plumbing test ONLY -
it verifies cursor/parse/post mechanics against a fake chat-completions
endpoint. Analyst RECALL IS UNPROVEN without a live model; the real recall
check must run a representative local transcript through a live local model.

Usage: cd ~/redops && ./venv/bin/python scripts/test_leads.py
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = "/tmp/redops-f-test"
PORT = 19100
BASE = f"http://127.0.0.1:{PORT}"

os.environ["REDOPS_DATA"] = SCRATCH
os.environ["REDOPS_ATTACKER_NETS"] = "203.0.113."
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
        return json.loads(resp.read())


def new_engagement(name: str) -> int:
    return req("POST", "/api/engagements", {"name": name})["id"]


def add_fact(eng, subject, predicate, obj=None, stype=None, otype=None, object_text=None):
    body = {"engagement_id": eng, "subject_name": subject, "predicate": predicate,
            "confidence": "confirmed", "source": "agent"}
    if stype:
        body["subject_type"] = stype
    if object_text is not None:
        body["object_text"] = object_text
    else:
        body["object_name"] = obj
        if otype:
            body["object_type"] = otype
    return req("POST", "/api/facts", body)


def worklist(eng):
    return req("GET", f"/api/worklist?engagement_id={eng}")


def opportunities(eng):
    return req("GET", f"/api/opportunities?engagement_id={eng}")


def wl_item_covering(items, fact_id):
    return [it for it in items if fact_id in it["fact_ids"]]


# ---------------------------------------------------------------------------

def f1_r2_restart_boost():
    print("F1 - 6.4.4 R2 (facts-only, restart primitive boost)")
    eng = new_engagement("F1")
    # step 1: lone write primitive
    f1 = add_fact(eng, "qdrant config", "writable-by", obj="us", stype="config")
    wl = worklist(eng)
    lone = wl_item_covering(wl, f1["id"])
    check("step1: fact created and in worklist", len(lone) == 1 and lone[0]["kind"] == "fact")
    low_score = lone[0]["score"] if lone else 99
    check("step1: low score (<4)", low_score < 4, f"score={low_score}")
    check("step1: NO opportunity", opportunities(eng) == [])

    # step 2: R2 fires from a structured runs-as fact. (Prose extraction was
    # deliberately removed in 6f86251 — extract_facts is structured-sources-only;
    # the sole deterministic text parser left is /etc/hosts, sanity-checked here.)
    from redops import wiretail
    hosts_facts = wiretail.extract_facts("cat /etc/hosts\n10.10.10.9 db-internal.local\n")
    check("step2: deterministic /etc/hosts extractor still works",
          any(f["predicate"] == "resolves-to" and f["subject_name"] == "db-internal.local"
              for f in hosts_facts),
          f"extracted={hosts_facts}")
    f2 = add_fact(eng, "qdrant", "runs-as", object_text="system", stype="service")
    opps = opportunities(eng)
    r2 = [o for o in opps if o["rule"] == "R2"]
    check("step2: R2 opportunity created", len(r2) == 1, f"opps={[(o['rule'], o['id']) for o in opps]}")
    wl2 = worklist(eng)
    covering = wl_item_covering(wl2, f1["id"])
    check("step2: writable fact's worklist score jumps",
          len(covering) == 1 and covering[0]["score"] > low_score,
          f"before={low_score} after={covering[0]['score'] if covering else None}")
    step2_score = covering[0]["score"] if covering else 0

    # step 3: restart primitive lands -> strengthened R2 naming it
    f3 = add_fact(eng, "qdrant", "crashes", object_text="unauth PUT /collections", stype="service")
    opps = opportunities(eng)
    boosted = [o for o in opps if o["rule"] == "R2" and len(o["facts"]) == 3]
    check("step3: R2 with all three facts attached", len(boosted) == 1,
          f"r2 fact counts={[len(o['facts']) for o in opps if o['rule']=='R2']}")
    # regression guard: a late restart fact must UPGRADE the existing R2 in
    # place, not mint a second one (dedup on the core pair, not all facts).
    check("step3: exactly one R2 (no stale duplicate)",
          len([o for o in opps if o["rule"] == "R2"]) == 1,
          f"r2 count={len([o for o in opps if o['rule']=='R2'])}")
    if boosted:
        rat = boosted[0]["rationale"]
        check("step3: rationale names the restart primitive",
              "restart primitive" in rat and "reload" in rat and "qdrant crashes" in rat, rat[:160])
        wl3 = worklist(eng)
        cov3 = wl_item_covering(wl3, f1["id"])
        best = max((it["score"] for it in cov3), default=0)
        check("step3: score strengthens again", best > step2_score,
              f"step2={step2_score} step3={best}")


def f2_r8_spray():
    print("F2 - R8 spray matrix (leads, ranked by proven reuse)")
    eng = new_engagement("F2")
    add_fact(eng, "svc_backup", "valid-on", obj="10.0.0.1", stype="credential", otype="host")
    add_fact(eng, "svc_backup", "valid-on", obj="10.0.0.2", stype="credential", otype="host")
    add_fact(eng, "root", "valid-on", obj="10.0.0.1", stype="credential", otype="host")
    add_fact(eng, "10.0.0.9:22", "listens-on", object_text="22", stype="service")
    leads_list = req("GET", f"/api/leads?engagement_id={eng}&status=open")
    spray = [l for l in leads_list if l["observation"].startswith("spray ")]
    check("R8 emits reuse LEADS (not opportunities)", len(spray) == 2,
          f"leads={[l['observation'] for l in leads_list]}")
    check("R8 leads carry rule provenance", all(l["source"] == "rule" for l in spray))
    two = [l for l in spray if "svc_backup" in l["observation"]]
    zero = [l for l in spray if l["observation"].startswith("spray root")]
    check("cred valid on 2 hosts outranks one valid on fewer",
          two and zero and two[0]["score"] > zero[0]["score"],
          f"two={two[0]['score'] if two else None} other={zero[0]['score'] if zero else None}")
    r8_opps = [o for o in opportunities(eng) if o["rule"] == "R8"]
    check("no R8 opportunity (expansion stays leads)", r8_opps == [])


def f3_r10_sink_tool():
    print("F3 - R10 sink x tool (both arms)")
    eng = new_engagement("F3")
    add_fact(eng, "user uploads", "no-auth", object_text="anyone can upload", stype="endpoint")
    add_fact(eng, "user uploads", "is-read-by", obj="support agent", stype="endpoint", otype="service")
    add_fact(eng, "support agent", "has-tool", object_text="file_read", stype="service")
    add_fact(eng, "support agent", "has-tool", object_text="user-facing response channel", stype="service")
    opps = opportunities(eng)
    r10 = [o for o in opps if o["rule"] == "R10"]
    check("(a) injection-to-action opportunity", any("Indirect injection" in o["title"] for o in r10),
          f"titles={[o['title'] for o in opps]}")
    check("(b) poison-to-user opportunity (synthetic arm does not escape)",
          any("Poison-to-user" in o["title"] for o in r10),
          f"titles={[o['title'] for o in opps]}")


def f4_r11_cover_tracks():
    print("F4 - R11 cover-tracks + detected flag")
    eng = new_engagement("F4")
    add_fact(eng, "payment-agent.internal", "resolves-to", obj="203.0.113.166", otype="host")
    add_fact(eng, "audit agent", "logs-to", obj="198.51.100.155 ELK")
    add_fact(eng, "elk-creds", "valid-on", obj="198.51.100.155 ELK", stype="credential")
    add_fact(eng, "payment-agent.internal", "flagged", object_text="SPOOFED by audit agent")
    opps = opportunities(eng)
    r5 = [o for o in opps if o["rule"] == "R5"]
    check("R5 spoof opportunity exists", len(r5) == 1)
    check("detected flips to 1 on the related opportunity",
          r5 and r5[0]["detected"] == 1, f"detected={r5[0]['detected'] if r5 else None}")
    r11 = [o for o in opps if o["rule"] == "R11"]
    check("R11 cover-tracks opportunity emitted", len(r11) >= 1,
          f"rules={[o['rule'] for o in opps]}")
    check("R11 references the sink", r11 and "198.51.100.155" in r11[0]["rationale"],
          r11[0]["rationale"][:160] if r11 else "")


# ---------------------------------------------------------------------------

CANNED = {
    "facts": [{"subject": "qdrant", "predicate": "runs-as", "object": "system",
               "confidence": "confirmed"},
              {"subject": "qdrant config", "predicate": "writable-by", "object": "us",
               "confidence": "confirmed"}],
    "leads": [{"observation": "denied path query implies privileged guard process",
               "category": "anomaly", "candidate_vector": "reverse the guard"}],
}


class FakeLLM(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps({"choices": [{"message": {"content": json.dumps(CANNED)}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def f5_analyst_plumbing():
    print("F5 - analyst plumbing (CANNED response; recall UNPROVEN without live model)")
    from redops import analyst, db
    srv = HTTPServer(("127.0.0.1", 0), FakeLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    analyst.ANALYST_URL = f"http://127.0.0.1:{srv.server_address[1]}"
    analyst.ANALYST_MODEL = "fake"
    analyst.WRITE_FACTS = True   # this check is about the fact path specifically;
                                 # the shipped default demotes facts to leads
    conn = db.connect()
    db.add_event(conn, "transcript", "output", "the qdrant service runs as system; config writable")
    conn.close()
    report = analyst.tick(BASE)
    check("tick posts canned payload", report.get("posted") == {"facts": 2, "leads": 1},
          f"report={report}")
    eng = req("GET", "/api/engagements")[0]["id"]
    facts = req("GET", f"/api/facts?engagement_id={eng}")
    ana = [f for f in facts if f["source"] == "analyst"]
    check("facts land with source=analyst", len(ana) == 2, f"analyst facts={len(ana)}")
    leads_list = req("GET", f"/api/leads?engagement_id={eng}")
    check("lead lands with source=analyst",
          any(l["source"] == "analyst" for l in leads_list),
          f"sources={set(l['source'] for l in leads_list)}")
    check("cursor advanced", report.get("cursor", 0) > 0, f"cursor={report.get('cursor')}")
    srv.shutdown()


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
        f1_r2_restart_boost()
        f2_r8_spray()
        f3_r10_sink_tool()
        f4_r11_cover_tracks()
        f5_analyst_plumbing()
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
