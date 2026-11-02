"""Command-line entry point for the CaseHub correlation ledger."""

from __future__ import annotations

import os
import argparse
import json
import sys
from typing import Sequence

from .ledger import CaseHub, CaseHubError


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python3 -m casehub", description=__doc__)
    p.add_argument("case", help="report.py case directory")
    p.add_argument("--actor", help="actor for ledger writes (defaults to REPORT_ACTOR)")
    commands = p.add_subparsers(dest="command", required=True)
    commands.add_parser("sync", help="mirror case.json events into the searchable evidence index")
    status = commands.add_parser("status", help="show case and collaboration state")
    status.add_argument("--json", action="store_true", help="print the complete context as JSON")
    commands.add_parser("rebuild", help="replay the append-only ledger into projections")
    search = commands.add_parser("search", help="search evidence, entities, and claims")
    search.add_argument("query", nargs="+", metavar="QUERY")
    epoch = commands.add_parser("epoch", help="start a new lab epoch")
    epoch.add_argument("reason", nargs="+", metavar="REASON")
    epoch.add_argument("--label")
    extract = commands.add_parser("extract", help="extract proposals from saved evidence")
    extract.add_argument("--event", action="append", default=[], metavar="ID")
    extract.add_argument("--target", metavar="T")
    extract.add_argument("--dry-run", action="store_true")
    serve = commands.add_parser("serve", help="start the local dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--no-auto-extract", action="store_true",
                       help="sync new evidence without running extraction adapters")
    mcp = commands.add_parser("mcp", help="start the stdio MCP server")
    mcp.add_argument("--capabilities", default="read,propose,coordinate")
    return p


def status_text(context: dict) -> str:
    case, epoch = context["case"], context.get("epoch") or {}
    lines = [f"Case: {case['title']} ({case['report_id']})",
             f"Scope: {case['scope']}",
             f"Epoch: {epoch.get('id', 'none')} ({epoch.get('label', 'unlabeled')})",
             f"Evidence events: {case['events']}", "Targets:"]
    if not context["targets"]:
        lines.append("  none")
    for tid, target in context["targets"].items():
        done = ", ".join(target["stages_done"]) or "none"
        missing = ", ".join(target["stages_missing"]) or "none"
        lines.extend([
            f"  {tid}: {target.get('name') or tid} ({target.get('ip') or 'no IP'})",
            f"    Stages done: {done}; missing: {missing}",
            f"    Proof: {'recorded' if target['proof_recorded'] else 'missing'}; "
            f"ready-submit: {'ready' if target['ready_submit'] else 'missing'}; "
            f"accepted capture: {'yes' if target['accepted_capture'] else 'no'}",
            f"    Commands running: {', '.join(target['running_commands']) or 'none'}; "
            f"unresolved interrupted: {', '.join(target['unresolved_interrupted']) or 'none'}",
            f"    Entities: {target['entities']}; open claims: {target['claims_open']}",
        ])
    lines.append("Actors:")
    lines.extend(f"  {a['actor']}: last heartbeat {a['at']} (task {a.get('task_id') or 'none'})"
                 for a in context["actors"])
    if not context["actors"]:
        lines.append("  none")
    lines.append("Live tasks:")
    live = [t for t in context["tasks"] if t["state"] not in ("done", "cancelled")]
    lines.extend(f"  {t['id']}: {t['state']}, owner {t.get('owner') or 'unassigned'}: {t['objective']}"
                 for t in live)
    if not live:
        lines.append("  none")
    lines.append("Leases:")
    lines.extend(f"  {lease['resource']}: {lease['owner']} until {lease['expires_at']}"
                 f"{' (expired)' if lease['expired'] else ''}" for lease in context["leases"])
    if not context["leases"]:
        lines.append("  none")
    for title, key, render in (
        ("Open decisions", "open_decisions", lambda x: f"{x['id']}: {x['question']}"),
        ("Pending handoffs", "pending_handoffs", lambda x: f"{x['id']}: {x['from_actor']} -> {x.get('to_actor') or 'anyone'}"),
        ("Conflicting claims", "conflicting_claims", lambda x: f"{x['id']}: {x['statement']} (with {', '.join(x['conflicts_with'])})"),
    ):
        lines.append(f"{title}:")
        lines.extend(f"  {render(item)}" for item in context[key])
        if not context[key]:
            lines.append("  none")
    counts = context["entity_counts"]
    lines.append("Inventory: " + (", ".join(f"{kind}={count}" for kind, count in sorted(counts.items())) or "none"))
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    case = os.environ.get("REPORT_CASE")
    if case is not None:
        subcommands = {"sync", "status", "rebuild", "search", "epoch", "extract", "serve", "mcp"}
        index = 0
        while index < len(argv):
            argument = argv[index]
            if argument == "--actor":
                index += 2
            elif argument.startswith("-"):
                index += 1
            else:
                if argument in subcommands:
                    argv.insert(0, case)
                break
    args = parser().parse_args(argv)
    try:
        with CaseHub(args.case, actor=args.actor) as hub:
            if args.command == "sync":
                print(f"Synced {hub.sync_evidence()} evidence event(s)")
            elif args.command == "status":
                hub.sync_evidence()
                context = hub.context()
                print(json.dumps(context, indent=2, ensure_ascii=False) if args.json else status_text(context))
            elif args.command == "rebuild":
                print(f"Rebuilt {hub.rebuild()} ledger record(s)")
            elif args.command == "search":
                hub.sync_evidence()
                print(json.dumps(hub.search(" ".join(args.query)), indent=2, ensure_ascii=False))
            elif args.command == "epoch":
                print(hub.start_epoch(" ".join(args.reason), label=args.label))
            elif args.command == "extract":
                from . import extract
                return extract.main(hub, args) or 0
            elif args.command == "serve":
                from . import dashboard
                return dashboard.main(hub, args) or 0
            elif args.command == "mcp":
                from . import mcp_server
                return mcp_server.main(hub, args) or 0
    except CaseHubError as exc:
        print(f"casehub: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
