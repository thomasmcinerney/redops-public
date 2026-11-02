"""Fixture regression for the httpx parser — endpoint(+title)/host/server + the tech
stack as framework nodes, all observed. Plus fail-clean on empty output.

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_httpx
"""
import os
import sys
import tempfile

HERE = os.path.dirname(__file__)


def _text(name):
    with open(os.path.join(HERE, "httpx", name)) as f:
        return f.read()


def test_to_result():
    from redops.parsers import httpx
    r = httpx.to_result(_text("probe.jsonl"), host_hint="192.0.2.14")
    ep = [e for e in r.entities if e["type"] == "endpoint"]
    assert ep and ep[0]["name"] == "192.0.2.14:8080" and ep[0]["label"] == "Example Lab Portal", ep
    frameworks = sorted(e["name"] for e in r.entities if e["type"] == "framework")
    assert frameworks == ["Flask", "Python", "Werkzeug"], frameworks
    assert sum(1 for f in r.facts if f.predicate == "backed-by") == 3
    assert any(f.predicate == "http-server" and "Werkzeug" in f.object_text for f in r.facts)
    assert any(f.predicate == "on-host" for f in r.facts)
    print("  to_result: OK — endpoint(titled) + 3 frameworks backed-by + server, host linked")


def test_empty_fail_clean():
    from redops.parsers import httpx
    r = httpx.to_result("", host_hint="10.0.0.9")
    assert r.status == "unrecognized" and r.facts == [] and r.entities == []
    print("  empty: OK — no output => unrecognized, zero facts")


def test_persist_promotes_claimed_tech():
    # a tech CLAIMED earlier is promoted to observed when httpx observes it
    tmp = tempfile.mkdtemp(prefix="redops-httpx-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db, parsers
    db.use_data_dir(tmp)   # env alone is too late: DATA_DIR binds at import
    from redops.parsers import httpx
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements", {"name": "hx", "scope": "", "notes": "", "created_at": db.now()})
    tid = db.insert(conn, "targets", {"engagement_id": eng, "ip": "192.0.2.14", "hostname": "",
                                      "os": "", "role": "", "status": "unidentified", "meta_json": "{}"})
    conn.commit()
    # seed a CLAIMED backed-by Flask (as if from an /about page)
    ep = db.upsert_entity(conn, eng, "endpoint", "192.0.2.14:8080")
    fw = db.upsert_entity(conn, eng, "framework", "Flask")
    db.add_fact(conn, eng, ep, "backed-by", fw, "", "claimed", "agent")
    conn.commit()
    r = httpx.to_result(_text("probe.jsonl"), host_hint="192.0.2.14")
    parsers.persist(conn, eng, tid, "192.0.2.14", r, stage="observed", source="wire-auto")
    conn.commit()
    flask = db.row(conn, "SELECT stage FROM facts WHERE engagement_id=? AND predicate='backed-by' "
                         "AND object_id=?", (eng, fw))
    assert flask and flask["stage"] == "observed", "claimed Flask promoted to observed by httpx"
    conn.close()
    print("  persist: OK — claimed Flask promoted to observed by httpx fingerprint")


def main():
    tests = [test_to_result, test_empty_fail_clean, test_persist_promotes_claimed_tech]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {e!r}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(tests) - failed}/{len(tests)} httpx cases")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
