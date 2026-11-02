"""Escape-hatch regression (tools.run_command): scope enforcement + captured-only.
Proves an out-of-scope target is refused (nothing runs) and an allowed command is
captured but produces ZERO facts (no parser, no correlate) — honest, not faked.

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_run
"""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time


def _setup():
    tmp = tempfile.mkdtemp(prefix="redops-run-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db
    db.use_data_dir(tmp)   # env alone is too late: DATA_DIR binds at import
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements",
                    {"name": "run", "scope": "", "notes": "", "created_at": db.now()})
    db.set_state(conn, f"scope_in:{eng}", json.dumps(["192.0.2.0/24"]))
    db.set_setting(conn, "scope_guard", "1")  # this fixture explicitly exercises the guard
    conn.commit()
    conn.close()
    return eng


def test_scope_block():
    from redops import db, tools
    eng = _setup()
    r = tools.run_command(eng, ["nmap", "203.0.113.1"], actor="agent")
    assert r.get("blocked") is True and "outside the allowed scope" in r.get("reason", ""), r
    conn = db.connect()
    n = db.row(conn, "SELECT COUNT(*) c FROM tool_runs WHERE engagement_id=?", (eng,))["c"]
    conn.close()
    assert n == 0, f"blocked command must not create a run row (got {n})"
    print("  scope-block: OK — out-of-scope target refused, nothing ran")


def test_captured_only():
    from redops import db, tools
    eng = _setup()
    r = tools.run_command(eng, ["echo", "hello-redops"], actor="user")
    assert r["status"] == "done" and "hello-redops" in r["output"], r
    assert r.get("captured_only") is True
    conn = db.connect()
    facts = db.row(conn, "SELECT COUNT(*) c FROM facts WHERE engagement_id=?", (eng,))["c"]
    ents = db.row(conn, "SELECT COUNT(*) c FROM entities WHERE engagement_id=?", (eng,))["c"]
    assert facts == 0 and ents == 0, f"captured-only must create ZERO facts/entities (facts={facts}, ents={ents})"
    run = db.row(conn, "SELECT status, tool FROM tool_runs WHERE engagement_id=? ORDER BY id DESC LIMIT 1", (eng,))
    assert run["status"] == "done" and run["tool"] == "run", dict(run)
    ev = db.row(conn, "SELECT meta_json FROM events WHERE engagement_id=? AND kind='output' ORDER BY id DESC LIMIT 1", (eng,))
    assert ev and json.loads(ev["meta_json"]).get("captured_only") is True, "event must be flagged captured_only"
    conn.close()
    print("  captured-only: OK — echo captured + flagged, ZERO facts/entities, run finalized")


def test_busy_writer_preserves_capture():
    from redops import db, tools
    _setup()
    conn = db.connect()
    rid = db.insert(conn, "tool_runs", {
        "tool": "run", "command": "echo lock-retry-evidence", "status": "running",
        "actor": "agent", "started_at": db.now(),
    })
    conn.close()

    original_connect = db.connect
    attempts = 0

    def short_connect():
        nonlocal attempts
        attempts += 1
        conn = sqlite3.connect(db.DB_PATH, timeout=0.04)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    ready = threading.Event()

    def held_writer():
        conn = original_connect()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE capture_lock_test (value TEXT)")
        ready.set()
        time.sleep(0.25)
        conn.commit()
        conn.close()

    writer = threading.Thread(target=held_writer)
    writer.start()
    assert ready.wait(3), "writer did not start"
    db.connect = short_connect
    try:
        result = tools._exec_command(
            rid, None, "echo lock-retry-evidence", ["echo", "lock-retry-evidence"],
            False, None, "agent", timeout=3,
        )
    finally:
        db.connect = original_connect
        writer.join(timeout=3)
    assert not writer.is_alive(), "writer did not finish"
    assert attempts > 1, f"test did not exercise the busy retry (attempts={attempts})"
    assert result["status"] == "done", result
    conn = db.connect()
    run = db.row(conn, "SELECT status, output FROM tool_runs WHERE id=?", (rid,))
    events = db.rows(conn, "SELECT meta_json FROM events WHERE kind='output'")
    conn.close()
    assert run == {"status": "done", "output": "lock-retry-evidence\n"}, run
    assert len(events) == 1 and json.loads(events[0]["meta_json"])["tool_run"] == rid, events
    print("  busy-writer: OK — retry retained exact output and one event")


def main():
    tests = [test_scope_block, test_captured_only, test_busy_writer_preserves_capture]
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
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(tests) - failed}/{len(tests)} escape-hatch cases")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
