"""Fixture regression for the nmap parser — proves the D1 contract retrofit
preserves nmap's FULL curation (complete services, interesting/dyn-rpc/
unfingerprinted buckets, role/OS/AD-domain coalescing, status advance, summary).

Run standalone (no pytest):  ./venv/bin/python -m redops.parsers.fixtures.test_nmap
Exits nonzero on any failure. This is the golden regression that catches nmap
output-shape drift and any accidental degradation of the parser.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(__file__)


def _xml(name):
    with open(os.path.join(HERE, "nmap", name)) as f:
        return f.read()


def test_to_result_dc_full():
    from redops.parsers import nmap
    r = nmap.to_result(nmap.parse_string(_xml("dc-full.xml")), "192.0.2.13", has_target=True)

    # complete services table — every open port, structured
    assert len(r.services) == 9, len(r.services)
    assert {s.port for s in r.services} == {53, 88, 135, 139, 389, 445, 3389, 49664, 9999}

    # curated graph: host + 7 interesting service nodes + 1 network(domain)
    et = [e["type"] for e in r.entities]
    assert et.count("host") == 1 and et.count("service") == 7 and et.count("network") == 1, et
    assert any(e["name"] == "examplelab.ai" for e in r.entities)

    # facts: 7 on-host + dyn rollup + unfingerprinted rollup + role + in-domain
    preds = [f.predicate for f in r.facts]
    assert preds.count("on-host") == 7, preds
    exposes = [f.object_text for f in r.facts if f.predicate == "exposes"]
    assert any("dynamic RPC (1 ephemeral" in t for t in exposes), exposes
    assert any("1 open port(s) not fingerprinted: 9999" in t for t in exposes), exposes
    assert any(f.predicate == "role" and f.object_text == "domain-controller" for f in r.facts)
    assert any(f.predicate == "in-domain" and f.object == "examplelab.ai" for f in r.facts)

    # identity coalescing + status advance
    assert r.target_updates.get("role") == "domain-controller"
    assert r.target_updates.get("os") == "Windows"
    assert r.target_updates.get("status_advance") is True

    # summary line
    assert r.summary.startswith("9 open [domain-controller]:"), r.summary
    assert "+1 dyn-rpc" in r.summary and "+1 unfingerprinted" in r.summary
    print("  to_result: OK — 9 services, 7 nodes, dyn+unknown rollups, DC/Windows/domain")


def test_empty_and_error():
    from redops.parsers import nmap
    r = nmap.to_result({"state": "down", "ports": []}, "10.0.0.9", status="done")
    assert r.services == [] and r.facts == [] and r.entities == []
    assert r.summary == "no open ports" and r.status == "empty"
    r2 = nmap.to_result(None, "10.0.0.9", status="error")
    assert r2.facts == [] and r2.summary == "error" and r2.status == "partial"
    print("  edges: OK — empty scan + error emit ZERO facts (fail-clean)")


def test_persist_roundtrip():
    # persist into a THROWAWAY db; assert the graph landed with stage=observed
    tmp = tempfile.mkdtemp(prefix="redops-fix-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db, parsers
    db.use_data_dir(tmp)   # env alone is too late: DATA_DIR binds at import
    from redops.parsers import nmap
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements",
                    {"name": "fix", "scope": "", "notes": "", "created_at": db.now()})
    tid = db.insert(conn, "targets",
                    {"engagement_id": eng, "ip": "192.0.2.13", "hostname": "",
                     "os": "", "role": "", "status": "unidentified", "meta_json": "{}"})
    conn.commit()

    r = nmap.to_result(nmap.parse_string(_xml("dc-full.xml")), "192.0.2.13", has_target=True)
    parsers.persist(conn, eng, tid, "192.0.2.13", r, stage="observed", source="wire-auto")
    conn.commit()

    svc = db.rows(conn, "SELECT port FROM services WHERE target_id=?", (tid,))
    assert len(svc) == 9, len(svc)
    ents = db.rows(conn, "SELECT type FROM entities WHERE engagement_id=?", (eng,))
    et = [e["type"] for e in ents]
    assert et.count("host") == 1 and et.count("service") == 7 and et.count("network") == 1, et
    facts = db.rows(conn, "SELECT predicate, stage FROM facts WHERE engagement_id=?", (eng,))
    assert facts and all(f["stage"] == "observed" for f in facts), "every fact must be observed"
    assert sum(1 for f in facts if f["predicate"] == "on-host") == 7
    t = db.row(conn, "SELECT role, os, status FROM targets WHERE id=?", (tid,))
    assert t["role"] == "domain-controller" and t["os"] == "Windows" and t["status"] == "identified", dict(t)
    conn.close()
    print(f"  persist: OK — 9 services, 9 nodes, {len(facts)} facts@observed, target=DC/Windows/identified")


def main():
    tests = [test_to_result_dc_full, test_empty_and_error, test_persist_roundtrip]
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
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(tests) - failed}/{len(tests)} nmap fixtures")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
