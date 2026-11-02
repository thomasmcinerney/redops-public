"""Retention regression (redops.retention).

The dangerous failure mode for a retention policy in a red-team tool is not
"kept too much" — it is deleting evidence. These cases assert the negative:
facts, findings, evidence, credentials and the narrative events survive, and a
dry run changes nothing at all.

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_retention
"""
import os
import sys
import tempfile


def _setup():
    tmp = tempfile.mkdtemp(prefix="redops-retention-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db
    db.use_data_dir(tmp)
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements",
                    {"name": "r", "scope": "", "notes": "", "created_at": db.now()})
    tid = db.insert(conn, "targets", {"engagement_id": eng, "ip": "10.0.0.1"})

    old = "2020-01-01T00:00:00"
    # disposable: old wire noise
    for i in range(20):
        conn.execute("INSERT INTO events (ts,source,kind,text,engagement_id) VALUES (?,?,?,?,?)",
                     (old, "wire", "flow" if i % 2 else "flowclose", "x" * 50, eng))
    # NOT disposable: the narrative + evidence, equally old
    for kind in ("action", "output", "reasoning", "note", "callback", "fact"):
        conn.execute("INSERT INTO events (ts,source,kind,text,engagement_id) VALUES (?,?,?,?,?)",
                     (old, "agent", kind, f"{kind}-must-survive", eng))
    # recent wire noise must also survive (the live map needs it)
    conn.execute("INSERT INTO events (ts,source,kind,text,engagement_id) VALUES (?,?,?,?,?)",
                 (db.now(), "wire", "flow", "recent-flow", eng))

    sid = db.upsert_entity(conn, eng, "host", "10.0.0.1")
    db.add_fact(conn, eng, sid, "runs", None, "smb", stage="observed")
    db.insert(conn, "findings", {"engagement_id": eng, "target_id": tid, "title": "f",
                                 "severity": "high", "created_at": db.now()})
    db.insert(conn, "credentials", {"engagement_id": eng, "target_id": tid,
                                    "username": "u", "secret": "s", "kind": "password",
                                    "source": "t"})
    db.add_principal(conn, eng, "admin", target_id=tid)
    db.insert(conn, "evidence", {"engagement_id": eng, "target_id": tid, "kind": "file",
                                 "path": "e.png", "ts": db.now()})
    conn.execute("INSERT INTO flows (engagement_id,src,dst,dport,proto,state,first_seen,last_seen) "
                 "VALUES (?,?,?,?,?,?,?,?)", (eng, "a", "b", 445, "tcp", "closed", old, old))
    conn.execute("INSERT INTO opportunities (engagement_id,title,rule,sig,status,created_at,updated_at) "
                 "VALUES (?,?,?,?,?,?,?)", (eng, "old dismissed", "R1", "s1", "dismissed", old, old))
    conn.execute("INSERT INTO opportunities (engagement_id,title,rule,sig,status,created_at,updated_at) "
                 "VALUES (?,?,?,?,?,?,?)", (eng, "open one", "R1", "s2", "open", old, old))
    conn.commit()
    return conn, eng


def _counts(conn):
    q = lambda s: conn.execute(s).fetchone()[0]  # noqa: E731
    return {
        "wire": q("SELECT count(*) FROM events WHERE kind IN ('flow','flowclose')"),
        "narrative": q("SELECT count(*) FROM events WHERE kind NOT IN ('flow','flowclose')"),
        "facts": q("SELECT count(*) FROM facts"),
        "findings": q("SELECT count(*) FROM findings"),
        "creds": q("SELECT count(*) FROM credentials"),
        "principals": q("SELECT count(*) FROM principals"),
        "evidence": q("SELECT count(*) FROM evidence"),
        "opps": q("SELECT count(*) FROM opportunities"),
        "flows": q("SELECT count(*) FROM flows"),
    }


def test_dry_run_changes_nothing():
    conn, eng = _setup()
    from redops import retention
    before = _counts(conn)
    r = retention.prune(conn, apply=False)
    assert r["applied"] is False
    assert r["wire_events"] == 20, f"plan should see 20 old wire events, saw {r['wire_events']}"
    assert _counts(conn) == before, "a dry run wrote to the database"
    print(f"  dry run: OK — would remove {r['total_rows']} rows, removed 0")


def test_prune_removes_only_noise():
    conn, eng = _setup()
    from redops import retention
    before = _counts(conn)
    retention.prune(conn, apply=True, vacuum=False)
    after = _counts(conn)
    assert after["wire"] == 1, f"recent wire event should survive, wire={after['wire']}"
    assert after["flows"] == 0, "old closed flow should be pruned"
    assert after["opps"] == 1, f"only the dismissed opportunity should go, opps={after['opps']}"
    print(f"  prune: OK — wire {before['wire']}->{after['wire']}, "
          f"flows {before['flows']}->{after['flows']}, opps {before['opps']}->{after['opps']}")


def test_evidence_is_never_touched():
    """The property that matters: retention cannot destroy the deliverable."""
    conn, eng = _setup()
    from redops import retention
    before = _counts(conn)
    retention.prune(conn, apply=True, vacuum=False)
    after = _counts(conn)
    for k in ("facts", "findings", "creds", "principals", "evidence"):
        assert after[k] == before[k], f"{k} changed: {before[k]} -> {after[k]}"
    # every narrative kind survives (+1 for the retention note it writes)
    surviving = {r[0] for r in conn.execute(
        "SELECT DISTINCT kind FROM events WHERE kind NOT IN ('flow','flowclose')")}
    assert {"action", "output", "reasoning", "note", "callback", "fact"} <= surviving, surviving
    print(f"  evidence: OK — facts/findings/creds/principals/evidence untouched, "
          f"narrative kinds intact ({len(surviving)})")


def test_young_engagement_prunes_nothing():
    """On a fresh engagement the correct answer is 'nothing is old enough'."""
    conn, eng = _setup()
    from redops import retention
    r = retention.plan(conn, wire_days=3650, flow_days=3650, opp_days=3650)
    assert r["total_rows"] == 0, f"long retention should find nothing, found {r}"
    print("  young: OK — nothing old enough, prunes nothing")


if __name__ == "__main__":
    n = 0
    for t in (test_dry_run_changes_nothing, test_prune_removes_only_noise,
              test_evidence_is_never_touched, test_young_engagement_prunes_nothing):
        t()
        n += 1
    print(f"\nPASS — {n}/4 retention cases")
    sys.exit(0)
