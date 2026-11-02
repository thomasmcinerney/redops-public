#!/usr/bin/env python3
"""Regression for pinned engagement and focused run attribution."""
import asyncio
import importlib
import tempfile
import sys
from pathlib import Path
from fastapi import HTTPException
sys.path.append(str(Path(__file__).resolve().parent.parent))
api = importlib.import_module('redops' + '.api')
db = importlib.import_module('redops' + '.db')
mcp = importlib.import_module('redops' + '.mcp_server')

class Request:
    headers = {}
    def __init__(self, body): self.body = body
    async def json(self): return self.body

async def check_api(a, ta, tb):
    try:
        await api.put_current_target(Request({"engagement_id": a, "target_id": tb}))
        raise AssertionError("cross-engagement focus accepted")
    except HTTPException as exc:
        assert exc.status_code == 404
    await api.put_current_target(Request({"engagement_id": a, "target_id": ta}))
    assert api.get_current_target(a)["target_id"] == ta
    original = api.tools.run_command
    api.tools.run_command = lambda eng, command, actor, target_id: (eng, target_id)
    try:
        assert await api.tools_exec(Request({"engagement_id": a, "command": "echo probe"})) == (a, ta)
        try:
            await api.tools_exec(Request({"engagement_id": a, "target_ip": "missing",
                                          "command": "echo probe"}))
            raise AssertionError("unknown target accepted")
        except HTTPException as exc:
            assert exc.status_code == 404
    finally:
        api.tools.run_command = original

with tempfile.TemporaryDirectory(prefix="fresh-") as scratch:
    db.use_data_dir(Path(scratch))
    db.init_db()
    conn = db.connect()
    a = db.insert(conn, "engagements", {"name": "A", "created_at": db.now()})
    b = db.insert(conn, "engagements", {"name": "B", "created_at": db.now()})
    ta = db.insert(conn, "targets", {"engagement_id": a, "ip": "192.0.2.12", "status": "identified"})
    tb = db.insert(conn, "targets", {"engagement_id": b, "ip": "192.0.2.13", "status": "identified"})
    db.set_state(conn, "active_engagement", str(b))
    conn.execute("INSERT INTO sitrep(engagement_id, activity, hypothesis, next_steps, updated_at) "
                 "VALUES(?,?,?,?,?)", (a, "old", "", "", "2001-01-01T11:11:11"))
    db.add_event(conn, "agent", "action", "maintenance", engagement_id=a)
    db.add_event(conn, "agent", "action", "target work", engagement_id=a, target_id=ta)
    conn.commit()
    assert api.get_sitrep(a)["events_since"] == 1
    correlate = importlib.import_module('redops' + '.correlate')
    src = db.row(conn, "SELECT ip FROM targets WHERE id=?", (ta,))["ip"]
    dst = db.row(conn, "SELECT ip FROM targets WHERE id=?", (tb,))["ip"]
    flow = db.insert(conn, "flows", {
        "engagement_id": a, "src": src, "dst": dst,
        "dport": 4444, "proto": "tcp", "direction": "in", "state": "established",
        "target_id": ta, "opened": int(), "first_seen": db.now(),
        "last_seen": db.now(), "packets": 2, "bytes": 100})
    correlate.run(conn, a)
    assert db.pending_callbacks(conn, a) == []
    assert not db.rows(conn, "SELECT id FROM opportunities WHERE engagement_id=? AND rule='R13' AND status='open'", (a,))
    conn.execute("UPDATE flows SET opened=? WHERE id=?", (1, flow))
    correlate.run(conn, a)
    assert len(db.pending_callbacks(conn, a)) == 1
    assert len(db.rows(conn, "SELECT id FROM opportunities WHERE engagement_id=? AND rule='R13' AND status='open'", (a,))) == 1
    conn.execute("UPDATE flows SET opened=? WHERE id=?", (int(), flow))
    correlate.run(conn, a)
    assert not db.rows(conn, "SELECT id FROM opportunities WHERE engagement_id=? AND rule='R13' AND status='open'", (a,))
    conn.execute("UPDATE flows SET opened=? WHERE id=?", (1, flow))
    correlate.run(conn, a)
    assert len(db.rows(conn, "SELECT id FROM opportunities WHERE engagement_id=? AND rule='R13' AND status='open'", (a,))) == 1
    conn.close()
    asyncio.run(check_api(a, ta, tb))
# MCP wrappers must carry the pinned engagement across ordinary calls.
old_req, old_eng, old_find = mcp.req, mcp._engagement, mcp.find_target
calls = []
def fake_req(method, path, body=None):
    calls.append((method, path, body))
    return {"ok": True}
mcp.req, mcp._engagement, mcp.find_target = fake_req, lambda: a, lambda ip: {"id": ta}
try:
    mcp.focus_target("192.0.2.12")
    assert calls[-1][2]["engagement_id"] == a
    mcp.run("echo probe")
    assert calls[-1][2]["engagement_id"] == a
    mcp.tasks_pending()
    assert "engagement_id=" + str(a) in calls[-1][1]
finally:
    mcp.req, mcp._engagement, mcp.find_target = old_req, old_eng, old_find

tools = importlib.import_module('redops' + '.tools')
assert not tools._targets_redops_api("python -c print(" + chr(48) + ")")
assert tools._targets_redops_api("curl " + chr(48))
print("PASS session freshness")
