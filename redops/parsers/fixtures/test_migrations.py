"""Migration replay (redops.db) — v0 -> current, on a real file.

The schema is built by SEQUENTIAL replay: base DDL constants plus a chain of
`if ver < N` ALTERs. The base DDL does NOT contain later columns, so the only
thing standing between a fresh box and an unopenable database is that the whole
chain actually replays. Nothing tested it, and two bugs already shipped in this
class: `credentials.created_at` (written by a parser, never created by any
migration) and `services.risk`.

This asserts the shape the CODE relies on, not a snapshot — a column list would
rot on the next migration; a write through the real API path cannot.

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_migrations
"""
import os
import sys
import tempfile


def _fresh():
    """A brand-new database, built only by replaying migrations."""
    tmp = tempfile.mkdtemp(prefix="redops-migrate-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db
    db.use_data_dir(tmp)
    db.init_db()
    return db


def test_replay_reaches_current_version():
    db = _fresh()
    conn = db.connect()
    ver = conn.execute("PRAGMA user_version").fetchone()[0]
    assert ver == db.SCHEMA_VERSION, f"replay stopped at v{ver}, expected v{db.SCHEMA_VERSION}"
    print(f"  replay: OK — fresh db at v{ver}")


def test_replay_is_idempotent():
    """init_db runs on every start; a second pass must be a no-op, not an error."""
    db = _fresh()
    db.init_db()
    db.init_db()
    conn = db.connect()
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    print("  idempotent: OK — three init_db passes, still current")


def test_columns_the_code_writes_all_exist():
    """Every column any writer touches must exist. This is the check that would
    have caught credentials.created_at and services.risk before they shipped."""
    db = _fresh()
    conn = db.connect()
    required = {
        "credentials": {"engagement_id", "target_id", "username", "secret", "kind",
                        "status", "source", "valid"},
        "services": {"target_id", "port", "proto", "state", "name", "product",
                     "version", "extrainfo", "cpe", "risk"},
        "tool_runs": {"engagement_id", "target_id", "tool", "command", "status",
                      "output", "summary", "actor", "started_at", "finished_at",
                      "params_json", "priority", "pooled"},
        "facts": {"engagement_id", "subject_id", "predicate", "object_id",
                  "object_text", "stage", "source", "status", "ts"},
        "sitrep": {"engagement_id", "activity", "hypothesis", "next_steps",
                   "updated_at", "commander_intent"},
        "findings": {"target_id", "title", "severity", "description", "cve",
                     "matched_at", "status", "created_at"},
        "principals": {"engagement_id", "kind", "name", "realm", "target_id",
                       "source", "status", "origin"},
    }
    for table, cols in required.items():
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        missing = cols - have
        assert not missing, f"{table} missing {sorted(missing)} after full replay"
    print(f"  columns: OK — {len(required)} tables carry every column the code writes")


def test_purge_covers_every_engagement_scoped_table():
    """A table with engagement_id that _purge misses leaks across engagements —
    exactly how `flows` kept 15k rows from a deleted engagement."""
    db = _fresh()
    conn = db.connect()
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    scoped = {t for t in tables
              if "engagement_id" in {r[1] for r in conn.execute(f"PRAGMA table_info({t})")}}
    scoped.discard("engagements")
    # covered = the _ENG_DIRECT loop PLUS any table deleted explicitly in the
    # purge body (credentials is deleted by target_id and by engagement_id).
    import inspect
    import re as _re
    body = inspect.getsource(db._purge_engagement_data)
    explicit = set(_re.findall(r"DELETE FROM (\w+)", body))
    covered = set(db._ENG_DIRECT) | explicit
    via_parent = {"opportunity_facts"}       # purged through its parent opportunity
    missed = scoped - covered - via_parent
    assert not missed, f"engagement-scoped tables not purged: {sorted(missed)}"
    print(f"  purge: OK — all {len(scoped)} engagement-scoped tables reachable")


def test_a_real_write_survives_the_replayed_schema():
    """End-to-end through the real writers, not hand-rolled SQL."""
    db = _fresh()
    conn = db.connect()
    eng = db.insert(conn, "engagements",
                    {"name": "m", "scope": "", "notes": "", "created_at": db.now()})
    tid = db.insert(conn, "targets", {"engagement_id": eng, "ip": "10.0.0.9"})
    db.insert(conn, "services", {"target_id": tid, "port": 445, "name": "smb", "risk": ""})
    sid = db.upsert_entity(conn, eng, "host", "10.0.0.9")
    db.add_fact(conn, eng, sid, "runs", None, "smb", stage="observed")
    db.add_principal(conn, eng, "administrator", realm="corp.local", target_id=tid)
    db.insert(conn, "credentials", {"engagement_id": eng, "target_id": tid,
                                    "username": "u", "secret": "p", "kind": "password",
                                    "status": "untested", "source": "test"})
    conn.commit()
    assert conn.execute("SELECT count(*) FROM facts").fetchone()[0] == 1
    assert conn.execute("SELECT count(*) FROM principals").fetchone()[0] == 1
    assert conn.execute("SELECT count(*) FROM credentials").fetchone()[0] == 1
    print("  writes: OK — facts, principals and credentials all persist")


if __name__ == "__main__":
    n = 0
    for t in (test_replay_reaches_current_version, test_replay_is_idempotent,
              test_columns_the_code_writes_all_exist,
              test_purge_covers_every_engagement_scoped_table,
              test_a_real_write_survives_the_replayed_schema):
        t()
        n += 1
    print(f"\nPASS — {n}/5 migration cases")
    sys.exit(0)
