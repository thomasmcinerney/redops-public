"""Smoke-test the v20 loop: absence -> mechanism -> precedent.

    uv run python scripts/test_precedent.py        # needs the API running

Checks the three properties the design rests on:

  1. An absent fact is recorded, and correlate.Ctx CANNOT see it. This is the
     safety property. An absent `writable-by` joining R1/R2 would manufacture an
     attack path out of its own negation.
  2. Mechanism is a controlled vocabulary — a typo is rejected, not stored,
     because a mechanism that matches nothing else is worse than no label.
  3. Precedent ranks a past engagement above an unrelated one, matches on the
     terms it says it matched on, and stays silent when there is no corpus.

Property 3 is the one worth re-running after any scoring change: the failure
mode is not "ranks badly", it is "ranks confidently on a shared port 80".
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

BASE = os.environ.get("REDOPS_URL", "http://127.0.0.1:9100")
FAILED = []


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=15) as fh:
            return json.loads(fh.read() or "null")
    except urllib.error.HTTPError as e:
        return {"_status": e.code, "_body": e.read().decode()[:200]}


def check(name, cond, detail=""):
    print(f"  {'ok  ' if cond else 'FAIL'}  {name}{'  ' + detail if detail else ''}")
    if not cond:
        FAILED.append(name)


def seed(name, ip, port, product, mech=None, finding=None, outcome=None, note="", t=""):
    eng = req("POST", "/api/engagements", {"name": name})["id"]
    req("PUT", "/api/active_engagement", {"id": eng})
    tgt = req("POST", "/api/targets", {"ip": ip, "engagement_id": eng})
    if product:
        req("POST", "/api/services", {"target_id": tgt["id"], "port": port, "proto": "tcp",
                                      "name": "http", "product": product})
    if finding:
        f = req("POST", "/api/findings", {"title": finding, "severity": "critical",
                                          "engagement_id": eng})
        if mech:
            req("PATCH", f"/api/findings/{f['id']}", {"mechanism": mech})
    if outcome:
        req("PATCH", f"/api/engagements/{eng}",
            {"outcome": outcome, "outcome_note": note, "lab_time": t})
    return eng


def main():
    if "_status" in (req("GET", "/api/health") or {}):
        print("API not reachable — start it: uv run python -m redops.api")
        return 1
    print(f"precedent smoke test against {BASE}\n")

    # --- 1. absence is recorded and is invisible to the engine ---------------
    solved = seed("t-precedent-solved", "10.77.0.5", 8080, "FuguHub",
                  mech="setup-wizard-exposed",
                  finding="Unauthenticated Config-Wizard allows admin creation",
                  outcome="solved", note="wizard -> admin -> RCE", t="6m58")
    req("POST", "/api/facts", {"engagement_id": solved, "subject_name": "10.77.0.5",
                               "predicate": "no-auth", "object_text": "/admin returns 401",
                               "polarity": "absent"})
    unrelated = seed("t-precedent-unrelated", "10.77.0.20", 5432, "PostgreSQL",
                     mech="db-exec-primitive", finding="COPY FROM PROGRAM RCE",
                     outcome="solved", note="superuser -> COPY FROM PROGRAM", t="5m47")
    live = seed("t-precedent-live", "10.77.0.9", 8080, "BarracudaDrive")
    req("POST", "/api/facts", {"engagement_id": live, "subject_name": "10.77.0.9",
                               "predicate": "no-auth", "object_text": "/admin returns 401",
                               "polarity": "absent"})

    from redops import correlate, db  # noqa: E402  (after the API has migrated)
    conn = db.connect()
    try:
        stored = db.rows(conn, "SELECT * FROM facts WHERE engagement_id=? AND polarity='absent'",
                         (live,))
        seen = correlate.Ctx(conn, live).facts
        check("absent fact is stored", len(stored) == 1, f"{len(stored)} row(s)")
        check("correlate.Ctx cannot see it", len(seen) == 0, f"{len(seen)} visible")
    finally:
        conn.close()

    # --- 2. mechanism vocabulary is controlled -------------------------------
    vocab = req("GET", "/api/mechanisms")
    check("mechanism vocabulary served", isinstance(vocab, list) and len(vocab) > 20,
          f"{len(vocab) if isinstance(vocab, list) else '?'} terms")
    f = req("POST", "/api/findings", {"title": "typo probe", "engagement_id": live})
    bad = req("PATCH", f"/api/findings/{f['id']}", {"mechanism": "wizard-exposed-typo"})
    check("invalid mechanism rejected", bad.get("_status") == 400,
          f"got {bad.get('_status', 'accepted')}")

    # --- 3. precedent ranks, explains, and discriminates ---------------------
    r = req("GET", f"/api/precedent?engagement_id={live}&limit=5")
    ps = r.get("precedents", [])
    names = [p["name"] for p in ps]
    check("precedent returns a ranking", bool(ps), f"{len(ps)} row(s)")
    check("solved lookalike ranks first",
          bool(names) and names[0] == "t-precedent-solved", f"got {names[:2]}")
    check("unrelated box does not rank above it",
          "t-precedent-unrelated" not in names[:1], f"order {names}")
    if ps:
        top = ps[0]
        check("match is explained", bool(top.get("matched")), str(list(top.get("matched", {}))))
        # the shared-port/product channel must contribute, not just the absence —
        # otherwise a scoring regression there would pass this test unnoticed
        check("service channel contributes",
              bool(set(top.get("matched", {})) & {"ports", "products"}),
              str(list(top.get("matched", {}))))
        check("common ports are not treated as signal",
              80 not in top.get("matched", {}).get("ports", []))
        check("outcome carried through", top["outcome"] == "solved" and top["lab_time"] == "6m58",
              f"{top['outcome']}/{top['lab_time']}")
        check("mechanism reaches the caller",
              any(x["mechanism"] == "setup-wizard-exposed" for x in top["findings"]))

    empty = seed("t-precedent-bare", "10.77.0.44", 9999, "")
    r2 = req("GET", f"/api/precedent?engagement_id={empty}&limit=5")
    check("silent with nothing to match on", not r2.get("precedents"),
          f"{len(r2.get('precedents', []))} row(s)")

    for name in ("t-precedent-solved", "t-precedent-unrelated", "t-precedent-live",
                 "t-precedent-bare"):
        for e in req("GET", "/api/engagements") or []:
            if e["name"] == name:
                req("DELETE", f"/api/engagements/{e['id']}")

    print()
    if FAILED:
        print(f"{len(FAILED)} FAILED: {', '.join(FAILED)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
