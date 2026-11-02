"""A timed out captured run retains output and cannot leave shell children running."""

import importlib
import json
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
server = importlib.import_module('redops.mcp_server')
tools = importlib.import_module('redops.tools')


def test_mcp_run_passes_bounded_timeout(monkeypatch):
    sent = []
    monkeypatch.setattr(server, '_engagement', lambda: 7)
    monkeypatch.setattr(server, 'req',
                        lambda method, path, body: sent.append(body) or {'status': 'queued'})
    server.run('long local agent', background=True, timeout=7200)
    assert sent[0]['timeout'] == 7200
    assert sent[0]['background'] is True
    server.run('ordinary probe')
    assert sent[1]['timeout'] == 1800
    import pytest
    with pytest.raises(ValueError, match='14400'):
        server.run('too long', timeout=14401)


def test_timeout_kills_shell_child_and_keeps_prefix_output(tmp_path, monkeypatch):
    db_path = tmp_path / 'test.sqlite'
    with sqlite3.connect(db_path) as conn:
        conn.execute('CREATE TABLE tool_runs '
                     '(id INTEGER PRIMARY KEY, status TEXT, output TEXT, summary TEXT, finished_at TEXT)')
        conn.execute('INSERT INTO tool_runs(id, status) VALUES (1, "running")')
    monkeypatch.setattr(tools.db, 'connect', lambda: sqlite3.connect(db_path))
    monkeypatch.setattr(tools.db, 'add_event', lambda *args, **kwargs: None)
    monkeypatch.setattr('redops.wiretail.store_output',
                        lambda output, key: (output, {}))
    sentinel = tmp_path / 'orphaned-child'
    command = f"printf 'captured-prefix\\n'; sleep 0.3; touch {sentinel}"
    result = tools._exec_command(1, 7, command, [], True, None, 'agent', timeout=0.05)
    time.sleep(0.4)
    assert result['status'] == 'error'
    assert 'captured-prefix' in result['output']
    assert 'process group killed' in result['output']
    assert not sentinel.exists()
    with sqlite3.connect(db_path) as conn:
        saved = conn.execute('SELECT status, output FROM tool_runs WHERE id=1').fetchone()
    assert saved[0] == 'error'
    assert saved[1] == result['output']

    with sqlite3.connect(db_path) as conn:
        conn.execute('INSERT INTO tool_runs(id, status) VALUES (2, "running")')
    success = tools._exec_command(2, 7, "printf 'complete-output'", [], True,
                                  None, 'agent', timeout=1)
    assert success['status'] == 'done'
    assert success['output'] == 'complete-output'
