"""Shared plumbing for RedOps kimi-code hook scripts.

Hooks must be fast, never crash-loud, and work with the API server down:
they read the SQLite db DIRECTLY, read-only. All paths derive from __file__
so the repo works wherever it is cloned.
"""

import json
import os
import sqlite3
import sys
from pathlib import Path

DATA_DIR = os.environ.get("REDOPS_DATA", str(Path(__file__).resolve().parent.parent / "data"))
DB_PATH = os.path.join(DATA_DIR, "redops.db")


def connect_ro() -> sqlite3.Connection | None:
    """Read-only connection; None if the db is unavailable (fail-open)."""
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=2)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error:
        return None


def read_stdin_json() -> dict:
    try:
        return json.load(open(0))  # stdin
    except Exception:
        return {}


def current_engagement(conn) -> int | None:
    """The operator's ACTIVE engagement (matches the MCP tools / API), falling
    back to the newest. Reading 'newest' alone split-brained the hooks from the
    tools whenever the operator switched active to an older engagement."""
    v = state(conn, "active_engagement", "")
    if v.isdigit() and conn.execute("SELECT 1 FROM engagements WHERE id=?", (int(v),)).fetchone():
        return int(v)
    r = conn.execute("SELECT id FROM engagements ORDER BY id DESC LIMIT 1").fetchone()
    return r["id"] if r else None


def briefing_enabled(conn) -> bool:
    """The [RedOps] context briefing is OPT-IN (off by default) — injecting the
    engagement/worklist on every prompt steers an agent that may be mid-mission.
    DB toggle (Manage -> Settings) wins, else REDOPS_BRIEF env, else off."""
    v = state(conn, "set:brief_on_prompt", "")
    if v == "":
        v = os.environ.get("REDOPS_BRIEF", "")
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def guard_enabled(conn) -> bool:
    """Scope enforcement is opt-in for authorized engagements. DB toggle
    (Manage -> Settings) wins, else REDOPS_SCOPE_GUARD env, else off. Mirrors
    redops.api._guard_enabled so the hook and the exec broker
    cannot diverge."""
    v = state(conn, "set:scope_guard", "")
    if v == "":
        v = os.environ.get("REDOPS_SCOPE_GUARD", "0")
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def engagement_is_empty(conn, eng: int) -> bool:
    """True when the engagement holds no targets and no facts — a fresh slate.
    Used to tell the agent not to carry over a previous engagement's context."""
    try:
        t = conn.execute("SELECT count(*) FROM targets WHERE engagement_id=?", (eng,)).fetchone()[0]
        f = conn.execute("SELECT count(*) FROM facts WHERE engagement_id=?", (eng,)).fetchone()[0]
        return t == 0 and f == 0
    except sqlite3.Error:
        return False


def state(conn, key: str, default: str = "") -> str:
    r = conn.execute("SELECT value FROM wiretail_state WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def focus_ip(conn, eng: int) -> str | None:
    v = state(conn, f"current_target:{eng}")
    if not v or v == "null":
        return None
    r = conn.execute("SELECT ip FROM targets WHERE id=?", (int(v),)).fetchone()
    return r["ip"] if r else None


def scope_lists(conn, eng: int) -> tuple[list[str], list[str]]:
    """Return (scope_in, scope_out) as lists of CIDR strings."""
    def _load(key):
        raw = state(conn, f"{key}:{eng}")
        if not raw:
            return []
        try:
            return [x for x in json.loads(raw) if str(x).strip()]
        except json.JSONDecodeError:
            return []
    return _load("scope_in"), _load("scope_out")


def worklist_top(conn, eng: int, n: int = 5) -> list[str]:
    """Top-N worklist lines for briefings. Fail-open: [] on any error."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from redops import leads as _leads
        lines = []
        for it in _leads.worklist(conn, eng)[:n]:
            det = " [DETECTED]" if it.get("detected") else ""
            title = (it["title"] or "")[:80]
            lines.append(f"  ({it['score']:.1f}) [{it['kind']}/{it['category']}]{det} {title}")
        return lines
    except Exception:
        return []
