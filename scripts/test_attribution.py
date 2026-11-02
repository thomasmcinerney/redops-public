#!/usr/bin/env python3
"""Regression for the "first message doesn't show in a new engagement's feed"
bug: the event attributor cached a focus pointer from the previous engagement
(30s), so the first prompt+reply after switching engagements were mis-filed onto
the OLD engagement and never appeared in the fresh feed. The attributor now
tracks the ACTIVE engagement and rebuilds the moment it changes.

Usage: cd ~/redops && uv run python scripts/test_attribution.py
"""

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = "/tmp/redops-attr-test"
os.environ["REDOPS_DATA"] = SCRATCH
sys.path.insert(0, str(ROOT))

FAILURES = []


def check(name, cond, detail=""):
    tag = "ok" if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f" - {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def main():
    shutil.rmtree(SCRATCH, ignore_errors=True)
    os.makedirs(SCRATCH, exist_ok=True)
    from redops import db, wiretail
    db.init_db()
    conn = db.connect()

    # engagement A, with a focused target
    a = db.insert(conn, "engagements", {"name": "A", "created_at": db.now()})
    ta = db.insert(conn, "targets", {"engagement_id": a, "ip": "192.0.2.14",
                                     "status": "identified"})
    db.set_state(conn, f"current_target:{a}", str(ta))
    db.set_state(conn, "active_engagement", str(a))
    conn.commit()

    att = wiretail.Attributor()
    att.refresh(conn, force=True)
    check("A: attributor on active engagement", att.eng == a, att.eng)
    check("A: free text sticks to the focused box", att.attribute(conn, "Hello") == ta,
          att.attribute(conn, "Hello"))

    # operator starts a fresh engagement B and immediately says hello — WITHIN the
    # 30s attributor cache window (no sleep). The bug filed this onto A.
    b = db.insert(conn, "engagements", {"name": "B", "created_at": db.now()})
    db.set_state(conn, "active_engagement", str(b))
    conn.commit()

    check("B: attributor switched to the new active engagement immediately",
          att.attribute(conn, "Hello") is None and att.eng == b,
          f"eng={att.eng} attr={att.attribute(conn, 'Hello')}")

    # end-to-end: the acp _emit path tags the event with the FRESH engagement, so
    # it shows in B's feed (not A's).
    tid = att.attribute(conn, "Hello")
    eid = db.add_event(conn, "user", "note", "Hello", target_id=tid)
    row = db.row(conn, "SELECT engagement_id FROM events WHERE id=?", (eid,))
    check("B: 'Hello' event scoped to the fresh engagement", row["engagement_id"] == b,
          f"tagged {row['engagement_id']} want {b}")
    # the agent reply likewise
    rid = db.add_event(conn, "acp", "action", "Still here, standing by.",
                       target_id=att.attribute(conn, "Still here, standing by."))
    rrow = db.row(conn, "SELECT engagement_id FROM events WHERE id=?", (rid,))
    check("B: agent reply scoped to the fresh engagement", rrow["engagement_id"] == b,
          f"tagged {rrow['engagement_id']} want {b}")

    # B's own focus still attributes once it's set (force-refresh past the cache)
    tb = db.insert(conn, "targets", {"engagement_id": b, "ip": "192.0.2.20",
                                     "status": "identified"})
    db.set_state(conn, f"current_target:{b}", str(tb))
    conn.commit()
    att.refresh(conn, force=True)
    check("B: focus within the engagement attributes normally",
          att.attribute(conn, "poke") == tb, att.attribute(conn, "poke"))
    conn.close()

    print("PASS" if not FAILURES else f"FAIL ({len(FAILURES)}): {FAILURES}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
