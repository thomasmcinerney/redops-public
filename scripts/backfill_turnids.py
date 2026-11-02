#!/usr/bin/env python3
"""One-time backfill: stamp turnId/tool into existing events' meta_json.

Reads the wire file(s) (REDOPS_WIRE override, else newest session wire, else
all session wires), builds uuid -> turnId/tool maps (tool.result inherits its
call's turnId via toolCallId), then updates events whose meta_json uuid
matches. Idempotent. Run manually:

    cd ~/redops && ./venv/bin/python scripts/backfill_turnids.py
"""

import glob
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redops import db  # noqa: E402

SESSIONS_GLOB = os.path.expanduser("~/.kimi-code/sessions/**/agents/*/wire.jsonl")


def build_maps(paths: list[str]):
    uuid_turn: dict[str, str] = {}   # content.part/tool.call uuid -> turnId
    call_turn: dict[str, str] = {}   # tool call id -> turnId
    call_tool: dict[str, str] = {}   # tool call id -> tool name
    for p in paths:
        try:
            f = open(p, errors="replace")
        except OSError:
            continue
        with f:
            for line in f:
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if o.get("type") != "context.append_loop_event":
                    continue
                e = o.get("event") or {}
                tid = e.get("turnId")
                if not tid:
                    continue
                et = e.get("type")
                if et == "content.part" and e.get("uuid"):
                    uuid_turn[e["uuid"]] = tid
                elif et == "tool.call":
                    cid = e.get("uuid") or e.get("toolCallId") or ""
                    if cid:
                        uuid_turn[cid] = tid
                        call_turn[cid] = tid
                        call_tool[cid] = e.get("name", "")
    return uuid_turn, call_turn, call_tool


def main() -> int:
    override = os.environ.get("REDOPS_WIRE")
    if override:
        paths = [override]
    else:
        paths = sorted(glob.glob(SESSIONS_GLOB, recursive=True),
                       key=os.path.getmtime, reverse=True)
    if not paths:
        print("no wire files found")
        return 1
    print(f"reading {len(paths)} wire file(s), newest: {paths[0]}")
    uuid_turn, call_turn, call_tool = build_maps(paths)
    print(f"mapped {len(uuid_turn)} uuids, {len(call_turn)} tool calls")

    conn = db.connect()
    updated = 0
    try:
        rows = conn.execute("SELECT id, meta_json FROM events").fetchall()
        for r in rows:
            try:
                meta = json.loads(r["meta_json"] or "{}")
            except json.JSONDecodeError:
                continue
            uid = meta.get("uuid") or ""
            if not uid:
                continue
            changed = False
            if "turnId" not in meta:
                tid = uuid_turn.get(uid)
                if not tid and uid.startswith("result:"):
                    tid = call_turn.get(uid[len("result:"):])
                if not tid and meta.get("tool_call_id"):
                    tid = call_turn.get(meta["tool_call_id"])
                if tid:
                    meta["turnId"] = tid
                    changed = True
            if "tool" not in meta:
                tool = call_tool.get(uid) or call_tool.get(meta.get("tool_call_id", ""))
                if tool:
                    meta["tool"] = tool
                    changed = True
            if changed:
                conn.execute("UPDATE events SET meta_json=? WHERE id=?",
                             (json.dumps(meta), r["id"]))
                updated += 1
        conn.commit()
    finally:
        conn.close()
    print(f"backfilled {updated} events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
