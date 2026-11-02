"""B3 regression — canary/honeypot quarantine. Proves detection, that a canary
secret is surfaced as a warning (R15), and that it is WITHHELD from the spray matrix
(r12 counts only real secrets). Non-destructive: the secret still exists, just isn't
sprayed.

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_canary
"""
import os
import sys
import tempfile


def test_detection():
    from redops.correlate import is_canary_secret
    assert is_canary_secret({"value": "honeypot-trap"})
    assert is_canary_secret({"value": "Acme2024!"})            # decoy-password shape
    assert is_canary_secret({"value": "x", "notes": "flagged CANARY by IR"})
    assert is_canary_secret({"value": "TEST"})                 # explicit uppercase marker
    assert not is_canary_secret({"value": "hunter2"})
    assert not is_canary_secret({"value": "Summer2024"})       # no '!' => not the decoy shape
    assert not is_canary_secret({"value": "mytestpassword"})   # lowercase 'test' inside a word
    print("  detection: OK — markers/decoy-shape caught, ordinary passwords pass")


def test_quarantine_and_exclusion():
    tmp = tempfile.mkdtemp(prefix="redops-canary-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db, correlate
    db.use_data_dir(tmp)   # env alone is too late: DATA_DIR binds at import
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements", {"name": "b3", "scope": "", "notes": "", "created_at": db.now()})
    db.insert(conn, "principals", {"engagement_id": eng, "kind": "username", "name": "admin",
                                   "realm": "", "status": "active", "source": "", "created_at": db.now()})
    db.insert(conn, "secrets", {"engagement_id": eng, "kind": "password", "value": "honeypot-trap-2024",
                                "realm": "", "status": "active", "source": "", "origin": "candidate",
                                "created_at": db.now()})
    db.insert(conn, "secrets", {"engagement_id": eng, "kind": "password", "value": "hunter2",
                                "realm": "", "status": "active", "source": "", "origin": "candidate",
                                "created_at": db.now()})
    conn.commit()

    correlate.run(conn, eng)

    opp = db.rows(conn, "SELECT title FROM opportunities WHERE rule='R15' AND engagement_id=?", (eng,))
    assert opp and "canary" in opp[0]["title"].lower(), opp
    lead = db.rows(conn, "SELECT candidate_vector FROM leads WHERE engagement_id=? "
                         "AND observation LIKE 'password-spray%'", (eng,))
    assert lead, "spray matrix should still fire for the real secret"
    assert "× 1 candidate" in lead[0]["candidate_vector"], lead[0]["candidate_vector"]  # × 1, not × 2
    # non-destructive: the canary secret still exists
    n = db.row(conn, "SELECT COUNT(*) c FROM secrets WHERE engagement_id=?", (eng,))["c"]
    assert n == 2, "canary is withheld, not deleted"
    conn.close()
    print("  quarantine: OK — canary flagged (R15), excluded from spray (× 1 candidate), not deleted")


def main():
    tests = [test_detection, test_quarantine_and_exclusion]
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
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(tests) - failed}/{len(tests)} canary cases")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
