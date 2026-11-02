#!/usr/bin/env python3
"""Kimi hook (SessionStart): full [RedOps] briefing - sitrep, commander
intent, pending tasks, open opportunities, current focus, protocol reminder.
Fail-open: any error -> exit 0 with whatever printed so far."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _common import (briefing_enabled, connect_ro, current_engagement, engagement_is_empty,
                         focus_ip, guard_enabled, read_stdin_json, scope_lists, worklist_top)
except ImportError:
    sys.exit(0)  # observational hook: misconfiguration stays silent, fail-open

PROTOCOL = ("[RedOps] Protocol: focus_target when switching boxes; fact_add on every "
            "discovery; log at phase changes; check tasks_pending.")


def main() -> int:
    read_stdin_json()
    conn = connect_ro()
    if not conn:
        return 0
    try:
        # Opt-in: briefings are off by default (see user_prompt.py). Scope
        # enforcement follows the separate operator setting, off by default.
        if not briefing_enabled(conn):
            return 0
        eng = current_engagement(conn)
        if eng is None:
            print(PROTOCOL)
            return 0
        e = conn.execute("SELECT name, scope FROM engagements WHERE id=?", (eng,)).fetchone()
        # Frame the briefing as reference, not orders (see user_prompt.py).
        print("[RedOps — engagement briefing for reference. Wait for the operator's "
              "direction before acting; the items below are background, not a task list "
              "to resume on your own.]")
        print(f"[RedOps] engagement #{eng}: {e['name']} (scope: {e['scope'] or 'n/a'})")

        focus = focus_ip(conn, eng)
        if focus:
            print(f"[RedOps] current focus: {focus}")

        scope_in, scope_out = scope_lists(conn, eng)
        if not guard_enabled(conn):
            print("[RedOps] scope guard: OFF - assigned scope lists are work context; "
                  "commands are not denied by RedOps scope checks")
        elif scope_in:
            print(f"[RedOps] scope guard: ACTIVE - allowlist {', '.join(scope_in)}, "
                  f"blocklist {', '.join(scope_out) or '(none)'}")
        elif scope_out:
            print(f"[RedOps] scope guard: blocklist only - {len(scope_out)} out-of-scope ranges")
        else:
            print("[RedOps] scope guard: \u26a0 NOT CONFIGURED - no scope lists set; "
                  "guard passes everything")

        if engagement_is_empty(conn, eng):
            print("[RedOps] this engagement is EMPTY — a fresh slate: no targets, creds, or "
                  "facts. Do NOT re-register hosts from memory or carry over a previous "
                  "engagement's context; wait for the operator's direction.")
            print(PROTOCOL)
            return 0

        sr = conn.execute("SELECT activity, hypothesis, next_steps, commander_intent "
                          "FROM sitrep WHERE engagement_id=?", (eng,)).fetchone()
        if sr:
            if (sr["commander_intent"] or "").strip():
                print(f"[RedOps] COMMANDER'S INTENT (overrides your next_steps on conflict): "
                      f"{sr['commander_intent'].strip()[:400]}")
            if (sr["activity"] or "").strip():
                print(f"[RedOps] activity: {sr['activity'].strip()[:300]}")
            if (sr["hypothesis"] or "").strip():
                print(f"[RedOps] hypothesis: {sr['hypothesis'].strip()[:300]}")
            if (sr["next_steps"] or "").strip():
                print(f"[RedOps] next steps: {sr['next_steps'].strip()[:300]}")

        tasks = conn.execute(
            "SELECT id, text FROM tasks WHERE status='pending' "
            "AND (engagement_id=? OR engagement_id IS NULL) ORDER BY id LIMIT 10", (eng,)).fetchall()
        for t in tasks:
            print(f"[RedOps] task #{t['id']}: {t['text'][:120]}")

        opps = conn.execute(
            "SELECT id, title FROM opportunities WHERE engagement_id=? AND status IN ('open','pinned') "
            "ORDER BY CASE status WHEN 'pinned' THEN 0 ELSE 1 END, id LIMIT 10", (eng,)).fetchall()
        for o in opps:
            print(f"[RedOps] opportunity #{o['id']}: {o['title']}")

        wl = worklist_top(conn, eng, 5)
        if wl:
            print("[RedOps] top worklist:")
            for line in wl:
                print(line)

        print(PROTOCOL)
        return 0
    except Exception:
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
