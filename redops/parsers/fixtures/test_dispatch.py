"""Dispatch regression: prove the generic _execute_scanner runs an argv tool
end-to-end — build_argv -> subprocess -> capture -> PARSERS parser (bound by
identity) -> persist -> finalize — with a stub bin that emits a real nmap XML to
stdout. No network, no nmap install needed; exercises the whole generic path.

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_dispatch
"""
import os
import sys
import tempfile

HERE = os.path.dirname(__file__)


def test_generic_executor():
    tmp = tempfile.mkdtemp(prefix="redops-disp-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db, tools
    db.use_data_dir(tmp)   # env alone is too late: DATA_DIR binds at import
    db.init_db()

    # stub bin: emits the nmap DC fixture to stdout, ignoring its target arg
    fixture = os.path.join(HERE, "nmap", "dc-full.xml")
    stub = os.path.join(tmp, "stub-nmap.sh")
    with open(stub, "w") as f:
        f.write(f"#!/bin/sh\ncat {fixture}\n")
    os.chmod(stub, 0o755)

    # a kind:"scanner" spec — declares its machine output goes to stdout, parsed by nmap
    spec = {"kind": "scanner", "bin": stub, "label": "stub", "timeout": 10,
            "options": {}, "presets": {},
            "output": {"dest": "stdout", "parser": "nmap"}}

    conn = db.connect()
    eng = db.insert(conn, "engagements",
                    {"name": "disp", "scope": "", "notes": "", "created_at": db.now()})
    tid = db.insert(conn, "targets",
                    {"engagement_id": eng, "ip": "10.9.9.9", "hostname": "", "os": "",
                     "role": "", "status": "unidentified", "meta_json": "{}"})
    rid = db.insert(conn, "tool_runs",
                    {"engagement_id": eng, "target_id": tid, "tool": "stub-nmap",
                     "command": "", "status": "running", "actor": "user",
                     "started_at": db.now(), "priority": 5})
    conn.commit()
    conn.close()

    summary = tools._execute_scanner(rid, eng, tid, "10.9.9.9", "stub-nmap", spec, {}, "user")

    conn = db.connect()
    svc = db.rows(conn, "SELECT port FROM services WHERE target_id=?", (tid,))
    assert len(svc) == 9, f"services={len(svc)}"
    facts = db.rows(conn, "SELECT stage FROM facts WHERE engagement_id=?", (eng,))
    assert facts and all(f["stage"] == "observed" for f in facts), "facts must be observed"
    run = db.row(conn, "SELECT status, summary, command, finished_at FROM tool_runs WHERE id=?", (rid,))
    assert run["status"] == "done", dict(run)
    assert run["finished_at"], "run must be finalized"
    assert "9 open" in (run["summary"] or ""), run["summary"]
    ev = db.row(conn, "SELECT COUNT(*) c FROM events WHERE engagement_id=? AND kind='output'", (eng,))
    assert ev["c"] >= 1, "an output event must be emitted"
    t = db.row(conn, "SELECT role, os, status FROM targets WHERE id=?", (tid,))
    assert t["role"] == "domain-controller" and t["status"] == "identified", dict(t)
    conn.close()
    print(f"  generic executor: OK — subprocess ran, 9 services, facts@observed, "
          f"tool_run finalized (summary={run['summary']!r})")


def main():
    failed = 0
    for t in [test_generic_executor]:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {e!r}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — dispatch")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
