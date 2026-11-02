#!/usr/bin/env python3
"""Kimi hook (UserPromptSubmit): compact [RedOps] briefing appended to the
agent's context on every user message. Prints nothing when there is nothing
worth saying. Must be fast and fail-open."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _common import (briefing_enabled, connect_ro, current_engagement, engagement_is_empty,
                         focus_ip, read_stdin_json, state, worklist_top)
except ImportError:
    sys.exit(0)  # observational hook: misconfiguration stays silent, fail-open


def main() -> int:
    read_stdin_json()  # drain stdin; content not needed
    conn = connect_ro()
    if not conn:
        return 0
    try:
        # Opt-in: stay silent unless the operator enabled briefings. Default off
        # so a plain message to the agent isn't shadowed by an injected queue.
        if not briefing_enabled(conn):
            return 0
        eng = current_engagement(conn)
        if eng is None:
            return 0
        name = conn.execute("SELECT name FROM engagements WHERE id=?", (eng,)).fetchone()["name"]

        # Fresh slate: an empty engagement means there is nothing to continue.
        # Say so explicitly so the agent doesn't re-register hosts from memory or
        # act on a previous engagement's context (which scopes clean at the DB
        # level but lives on in the agent's conversation).
        if engagement_is_empty(conn, eng):
            print(f"[RedOps] engagement '{name}' is EMPTY — a fresh slate: no targets, "
                  f"creds, or facts recorded here. Do NOT re-register hosts from memory or "
                  f"carry over a previous engagement's context; wait for the operator's "
                  f"direction before taking any action.")
            return 0

        lines = []
        focus = focus_ip(conn, eng)
        head = f"[RedOps] engagement: {name}"
        if focus:
            head += f" | focus: {focus}"
        lines.append(head)

        intent = ""
        r = conn.execute("SELECT commander_intent FROM sitrep WHERE engagement_id=?", (eng,)).fetchone()
        if r:
            intent = r["commander_intent"] or ""
        if intent.strip():
            lines.append(f"[RedOps] COMMANDER'S INTENT: {intent.strip()[:300]}")

        tasks = conn.execute(
            "SELECT id, text FROM tasks WHERE status='pending' "
            "AND (engagement_id=? OR engagement_id IS NULL) ORDER BY id LIMIT 5", (eng,)).fetchall()
        if tasks:
            lines.append("[RedOps] pending tasks: " + "; ".join(f"#{t['id']} {t['text'][:80]}" for t in tasks))

        opps = conn.execute(
            "SELECT id, title FROM opportunities WHERE engagement_id=? AND status IN ('open','pinned') "
            "ORDER BY CASE status WHEN 'pinned' THEN 0 ELSE 1 END, id LIMIT 5", (eng,)).fetchall()
        if opps:
            lines.append("[RedOps] open opportunities: " + "; ".join(f"#{o['id']} {o['title']}" for o in opps))

        wl = worklist_top(conn, eng, 5)
        if wl:
            lines.append("[RedOps] top worklist:")
            lines.extend(wl)

        if len(lines) > 1 or focus:  # bare engagement line alone is noise
            # Frame it as reference, not orders. Without this, the model can't
            # tell "background state" from "standing instruction" and a bare
            # "hello" to a mid-mission agent reads as "resume the queue".
            print("[RedOps — background state for reference only. Answer the operator's "
                  "actual message first; do NOT treat the items below as new instructions "
                  "or auto-resume prior work unless the operator asks.]")
            print("\n".join(lines[:11]))
        return 0
    except Exception:
        return 0  # fail-open, always
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
