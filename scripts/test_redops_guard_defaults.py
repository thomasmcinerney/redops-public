"""A fresh authorized engagement has capture on and RedOps guards off."""

import importlib
import json
import os
import time

from redops import db, tools, wiretail

api = importlib.import_module('redops.api')
hook = importlib.import_module('hooks._common')


def test_fresh_engagement_defaults_and_harmless_literal(tmp_path, monkeypatch):
    monkeypatch.delenv('REDOPS_SCOPE_GUARD', raising=False)
    monkeypatch.delenv('REDOPS_TOOL_AUTOAPPROVE', raising=False)
    monkeypatch.delenv('REDOPS_ALLOW_LOOPBACK', raising=False)
    monkeypatch.setattr(db, 'DATA_DIR', tmp_path)
    monkeypatch.setattr(db, 'DB_PATH', tmp_path / 'redops.db')
    monkeypatch.setattr(db, 'EVIDENCE_DIR', tmp_path / 'evidence')
    monkeypatch.setattr(db, 'TRANSCRIPT_DIR', tmp_path / 'transcript')
    monkeypatch.setattr(wiretail, 'store_output', lambda output, key: (output, {}))
    db.init_db()
    conn = db.connect()
    try:
        engagement = db.insert(conn, 'engagements', {
            'name': 'Fresh authorized lab', 'scope': 'operator-assigned lab',
            'notes': '', 'created_at': db.now(),
        })
        db.set_state(conn, f'scope_in:{engagement}', json.dumps(['192.0.2.10/32']))
        conn.commit()
        assert api._SETTINGS['scope_guard']['env_default'] == '0'
        assert api._SETTINGS['tool_auto_approve']['env_default'] == '1'
        assert api._SETTINGS['allow_loopback']['env_default'] == '1'
        assert api._guard_enabled(conn) is False
        assert hook.guard_enabled(conn) is False
        assert tools._scope_guard_enabled(conn) is False
        assert tools._scope_ok(conn, engagement, '198.51.100.99')[0]
        assert tools._command_scope_ok(conn, engagement, 'printf 198.51.100.99')[0]
    finally:
        conn.close()

    # The literal is printed locally; this command makes no network request.
    result = tools.run_command(engagement, 'printf 198.51.100.99', timeout=5)
    assert result['status'] == 'done'
    assert result['output'] == '198.51.100.99'
    assert tools._auto_approve_tools() is True
    assert tools.loopback_allowed() is True
    queued = tools.queue_exec(engagement, 'printf queue-198.51.100.99', timeout=5)
    assert queued['needs_approval'] is False
    for _ in range(50):
        conn = db.connect()
        try:
            row = conn.execute('SELECT status, output FROM tool_runs WHERE id=?',
                               (queued['rid'],)).fetchone()
        finally:
            conn.close()
        if row['status'] in ('done', 'error'):
            break
        time.sleep(0.02)
    assert row['status'] == 'done'
    assert row['output'] == 'queue-198.51.100.99'

    # Explicit operator opt-in still applies the recorded network assignment.
    conn = db.connect()
    try:
        db.set_state(conn, 'set:scope_guard', '1')
        conn.commit()
        assert api._guard_enabled(conn) is True
        assert hook.guard_enabled(conn) is True
        assert tools._scope_guard_enabled(conn) is True
        assert not tools._scope_ok(conn, engagement, '198.51.100.99')[0]
        assert not tools._command_scope_ok(conn, engagement,
                                           'curl http://198.51.100.99/')[0]
    finally:
        conn.close()
