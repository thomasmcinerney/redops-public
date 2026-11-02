"""Fixture regression for the nuclei parser — structured findings (cve/severity/
matched_at) + vuln nodes affecting hosts. Empty output = valid (0 findings).

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_nuclei
"""
import os
import sys
import tempfile

HERE = os.path.dirname(__file__)


def _text(name):
    with open(os.path.join(HERE, "nuclei", name)) as f:
        return f.read()


def test_to_result():
    from redops.parsers import nuclei
    r = nuclei.to_result(_text("findings.jsonl"))
    assert len(r.findings) == 2, len(r.findings)
    crit = next(f for f in r.findings if f.severity == "critical")
    assert crit.cve == "CVE-2099-99999" and "logger" in crit.matched_at, (crit.cve, crit.matched_at)
    vulns = sorted(e["name"] for e in r.entities if e["type"] == "vuln")
    assert "CVE-2099-99999" in vulns, vulns
    assert any(f.predicate == "affects" and f.object == "192.0.2.14" for f in r.facts)
    assert "1 critical" in r.summary and "1 low" in r.summary, r.summary
    print("  to_result: OK — 2 findings (cve+matched_at structured), vuln->host affects, sev summary")


def test_empty_is_valid():
    from redops.parsers import nuclei
    r = nuclei.to_result("")
    assert r.status == "empty" and r.findings == [] and r.facts == []
    print("  empty: OK — 0 findings is a valid result, not an error")


def test_persist_structured_findings():
    tmp = tempfile.mkdtemp(prefix="redops-nuclei-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db, parsers
    db.use_data_dir(tmp)   # env alone is too late: DATA_DIR binds at import
    from redops.parsers import nuclei
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements", {"name": "nu", "scope": "", "notes": "", "created_at": db.now()})
    tid = db.insert(conn, "targets", {"engagement_id": eng, "ip": "192.0.2.14", "hostname": "",
                                      "os": "", "role": "", "status": "unidentified", "meta_json": "{}"})
    conn.commit()
    r = nuclei.to_result(_text("findings.jsonl"))
    parsers.persist(conn, eng, tid, "192.0.2.14", r, stage="observed", source="wire-auto")
    conn.commit()
    row = db.row(conn, "SELECT cve, matched_at, severity FROM findings WHERE engagement_id=? "
                       "AND cve!='' LIMIT 1", (eng,))
    assert row and row["cve"] == "CVE-2099-99999" and row["matched_at"], dict(row) if row else None
    assert any(e["type"] == "vuln" for e in db.rows(conn, "SELECT type FROM entities WHERE engagement_id=?", (eng,)))
    conn.close()
    print("  persist: OK — findings.cve/matched_at stored as COLUMNS (v18), vuln node landed")


def main():
    tests = [test_to_result, test_empty_is_valid, test_persist_structured_findings]
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
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(tests) - failed}/{len(tests)} nuclei cases")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
