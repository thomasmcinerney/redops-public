#!/usr/bin/env python3
"""Phase-3 acceptance test: the AI-artifact stores — payload library, detection-
rule catalog, planted-poison provenance. Covers REST CRUD, engagement scoping +
purge cascade, the detection-rule -> opportunity 'detected' wiring, and export.

Usage: cd ~/redops && uv run python scripts/test_artifacts.py
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
SCRATCH = "/tmp/redops-artifacts-test"
PORT = 19140
BASE = f"http://127.0.0.1:{PORT}"

os.environ["REDOPS_DATA"] = SCRATCH
sys.path.insert(0, str(ROOT))

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


def add_fact(eng, subject, predicate, stype=None, object_text=None, obj=None, otype=None):
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


def t_crud():
    print("T1 - CRUD for payloads / rules / poison")
    eng = req("POST", "/api/engagements", {"name": "ARS"})["id"]
    p = req("POST", "/api/payloads", {"technique": "char-spacing", "target_model": "qwen2.5-7b",
            "guardrail_defeated": "output string filter", "outcome": "worked",
            "body": "put a space between every character", "engagement_id": eng})
    check("payload created", p.get("id") is not None, str(p))
    check("payload outcome stored", p.get("outcome") == "worked", p.get("outcome"))
    r = req("POST", "/api/detection_rules", {"name": "AIM3: Prompt Injection Keywords",
            "source_system": "elk", "match_mechanism": "exact substring",
            "blind_spot": "reformatting breaks the literal", "evasion": "char-spacing",
            "engagement_id": eng})
    check("rule created", r.get("id") is not None, str(r))
    po = req("POST", "/api/poison", {"location": "examplecorp_wiki.kb_articles id=5",
             "store_type": "kb-db", "verify_method": "query the agent, not the DB",
             "payload_id": p["id"], "engagement_id": eng})
    check("poison created", po.get("id") is not None, str(po))
    check("payloads listable", len(req("GET", f"/api/payloads?engagement_id={eng}")) == 1)
    check("rules listable", len(req("GET", f"/api/detection_rules?engagement_id={eng}")) == 1)
    check("poison listable", len(req("GET", f"/api/poison?engagement_id={eng}")) == 1)
    # patch: mark cleanup done
    po2 = req("PATCH", f"/api/poison/{po['id']}", {"cleanup_done": True, "live": False})
    check("poison cleanup patch", po2.get("cleanup_done") == 1 and po2.get("live") == 0, str(po2))
    # validation
    try:
        req("POST", "/api/payloads", {"outcome": "bogus", "technique": "x", "engagement_id": eng})
        check("bad outcome rejected", False)
    except urllib.error.HTTPError as e:
        check("bad outcome rejected", e.code == 400, f"code {e.code}")


def t_detected_wiring():
    print("T2 - fired detection rule flips opportunity 'detected'")
    eng = req("POST", "/api/engagements", {"name": "DETECT"})["id"]
    # build an R6 poisoning-surface opportunity; its rationale names the endpoint
    add_fact(eng, "upload-api", "no-auth", stype="endpoint", object_text="unauthenticated ingest")
    opps = req("GET", f"/api/opportunities?engagement_id={eng}")
    r6 = [o for o in opps if o["rule"] == "R6"]
    check("R6 opportunity created", len(r6) >= 1, f"opps: {[o['rule'] for o in opps]}")
    if not r6:
        return
    check("not yet detected", r6[0]["detected"] == 0, str(r6[0]["detected"]))
    # record a fired rule whose name matches the opportunity rationale (the endpoint)
    req("POST", "/api/detection_rules",
        {"name": "upload-api", "source_system": "elk", "fired": True, "engagement_id": eng})
    opps2 = req("GET", f"/api/opportunities?engagement_id={eng}")
    r6b = [o for o in opps2 if o["rule"] == "R6"]
    check("opportunity flipped to detected", r6b and r6b[0]["detected"] == 1,
          str(r6b[0]["detected"]) if r6b else "gone")


def t_purge():
    print("T3 - engagement reset purges all three stores")
    eng = req("POST", "/api/engagements", {"name": "PURGE"})["id"]
    req("POST", "/api/payloads", {"technique": "crescendo", "engagement_id": eng})
    req("POST", "/api/detection_rules", {"name": "keyword-density", "engagement_id": eng})
    req("POST", "/api/poison", {"location": "doc.txt", "engagement_id": eng})
    req("POST", f"/api/engagements/{eng}/reset")
    check("payloads purged", len(req("GET", f"/api/payloads?engagement_id={eng}")) == 0)
    check("rules purged", len(req("GET", f"/api/detection_rules?engagement_id={eng}")) == 0)
    check("poison purged", len(req("GET", f"/api/poison?engagement_id={eng}")) == 0)


def t_export():
    print("T4 - report renders all three appendices")
    eng = req("POST", "/api/engagements", {"name": "REPORT"})["id"]
    req("POST", "/api/payloads", {"technique": "css-concealment", "guardrail_defeated": "content log",
        "body": "<div style=font-size:0>...</div>", "outcome": "worked", "engagement_id": eng})
    req("POST", "/api/detection_rules", {"name": "AIM3: Instruction Strings",
        "match_mechanism": "per-file scan", "evasion": "fragmentation", "engagement_id": eng})
    req("POST", "/api/poison", {"location": "kb_articles id=9", "store_type": "kb-db",
        "verify_method": "ask the agent", "engagement_id": eng})
    md = req("GET", f"/api/export/{eng}?fmt=md")
    md = md if isinstance(md, str) else json.dumps(md)
    check("payload library section", "Payload library" in md)
    check("payload body rendered", "css-concealment" in md and "font-size:0" in md)
    check("detection rules section", "Detection rules encountered" in md)
    check("poison cleanup checklist", "Planted artifacts (cleanup checklist)" in md)
    check("poison location rendered", "kb_articles id=9" in md)


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
            print("scratch server did not come up; see", f"{SCRATCH}/server.log")
            return 1
        t_crud()
        t_detected_wiring()
        t_purge()
        t_export()
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
