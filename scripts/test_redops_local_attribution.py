"""Outer agent runs cannot inherit a target's shared focus into REPORT."""

import asyncio
import importlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'report-kit'))
import report

api = importlib.import_module('redops.api')
server = importlib.import_module('redops.mcp_server')
tools = importlib.import_module('redops.tools')


def test_mcp_run_marks_outer_process_local(monkeypatch):
    sent = []
    monkeypatch.setattr(server, '_engagement', lambda: 7)
    monkeypatch.setattr(server, 'req',
                        lambda method, path, body: sent.append(body) or {'status': 'queued'})
    server.run('grok --prompt-file phase.txt', background=True, timeout=900,
               local=True)
    assert sent[0]['local'] is True
    assert 'target_ip' not in sent[0]
    with pytest.raises(ValueError, match='cannot both'):
        server.run('probe', target_ip='192.0.2.10', local=True)


def test_api_local_overrides_shared_focus(monkeypatch):
    class Request:
        async def json(self):
            return {'command': 'grok --prompt-file phase.txt',
                    'engagement_id': 7, 'local': True, 'timeout': 7200}

    monkeypatch.setattr(api.db, 'connect', lambda: sqlite3.connect(':memory:'))
    monkeypatch.setattr(api, '_is_operator', lambda request: False)
    async def direct(fn, *args, **kwargs):
        return fn(*args, **kwargs)
    monkeypatch.setattr(api, 'run_in_threadpool', direct)
    captured = []
    monkeypatch.setattr(api.tools, 'run_command',
                        lambda *args, **kwargs: captured.append(kwargs) or {'status': 'done'})
    result = asyncio.run(api.tools_exec(Request()))
    assert result['status'] == 'done'
    assert captured[0]['target_id'] is None
    assert captured[0]['timeout'] == 7200


def test_local_run_is_absent_from_target_bulk_import(tmp_path, monkeypatch):
    (tmp_path / 'build').mkdir()
    report.save(tmp_path, {
        'schema': 1, 'created': report.now(), 'title': 'Local attribution test',
        'report_id': 'RPT-PRACTICE', 'scope': '192.0.2.10 only',
        'targets': {'box': {'name': 'Box', 'ip': '192.0.2.10', 'role': 'web',
                            'objective': 'Test import', 'summary': 'Testing',
                            'required_stages': ['recon'], 'scored': False,
                            'proof': None, 'report': {}}},
        'stages': [{'target': 'box', 'kind': 'recon', 'summary': 'Recon'}],
        'events': [], 'review': None, 'gates_required': True,
    })
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE tool_runs '
                 '(id INTEGER, engagement_id INTEGER, target_id INTEGER, '
                 'command TEXT, output TEXT, status TEXT, actor TEXT, started_at TEXT)')
    conn.executemany('INSERT INTO tool_runs VALUES (?,?,?,?,?,?,?,?)', [
        (1, 7, 9, 'curl http://192.0.2.10/', 'target response', 'done', 'agent', ''),
        (2, 7, None, 'grok --prompt-file phase.txt', 'outer response', 'done', 'agent', ''),
    ])
    monkeypatch.setattr(server, '_engagement', lambda: 7)
    monkeypatch.setattr(server, 'find_target', lambda ip: {'id': 9, 'ip': ip})
    def target_runs(ip=None, limit=40, before_id=None, **kwargs):
        return json.dumps(tools.runs(conn, engagement_id=7, target_id=9,
                                     limit=limit, before_id=before_id))
    monkeypatch.setattr(server, 'tool_results', target_runs)
    result = json.loads(server.report_import_runs(str(tmp_path), 'box', 'recon',
                                                '192.0.2.10'))
    assert [item['run_id'] for item in result['imported']] == [1]
    assert all(event.get('source_id') != 2 for event in report.load(tmp_path)['events'])
    conn.close()


def test_guard_off_allows_unassigned_literal_without_skipping_capture():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE wiretail_state (key TEXT PRIMARY KEY, value TEXT)')
    conn.executemany('INSERT INTO wiretail_state VALUES (?,?)', [
        ('scope_in:7', json.dumps(['192.0.2.10/32'])),
        ('set:scope_guard', '0'),
    ])
    assert tools._scope_ok(conn, 7, '8.8.8.8')[0]
    assert tools._command_scope_ok(conn, 7, 'printf 8.8.8.8')[0]
    conn.execute("UPDATE wiretail_state SET value='1' WHERE key='set:scope_guard'")
    assert not tools._scope_ok(conn, 7, '8.8.8.8')[0]
    assert not tools._command_scope_ok(conn, 7, 'curl http://8.8.8.8/')[0]
    conn.close()
