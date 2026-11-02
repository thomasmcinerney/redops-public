"""Newline-delimited JSON-RPC MCP server for one CaseHub case."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from .__main__ import status_text
from .ledger import CaseHub, CaseHubError


PROTOCOL_VERSION = "2025-03-26"
CAPABILITIES = frozenset(("read", "propose", "coordinate", "capture"))
EVIDENCE_NOTE = " Observed or verified facts require existing evidence event IDs."
REPORT = Path(__file__).resolve().parent.parent / "report.py"
RUN_EVENT_ID = re.compile(r"^\[REPORT evidence ([0-9a-f]{12}): exit \d+\]$", re.MULTILINE)
RECORD_EVENT_ID = re.compile(r"^Recorded (?:query|browser|note|screenshot|code) ([0-9a-f]{12})$", re.MULTILINE)


@dataclass(frozen=True)
class Tool:
    capability: str
    description: str
    required: tuple[str, ...]
    properties: dict[str, dict]

    def listing(self, name: str) -> dict:
        return {"name": name, "description": self.description + EVIDENCE_NOTE,
                "inputSchema": {"type": "object", "properties": self.properties,
                                "required": list(self.required), "additionalProperties": False}}


def s(description: str = "") -> dict:
    return {"type": "string", "description": description}


def i(description: str = "") -> dict:
    return {"type": "integer", "description": description}


def b(description: str = "") -> dict:
    return {"type": "boolean", "description": description}


def a(description: str = "") -> dict:
    return {"type": "array", "items": {"type": "string"}, "description": description}


def o(description: str = "") -> dict:
    return {"type": "object", "description": description}


TOOLS: dict[str, Tool] = {
    "case_context": Tool("read", "Return the current mission context, targets, gates and collaboration state.", (), {}),
    "case_status_text": Tool("read", "Return a readable mission status summary.", (), {}),
    "inventory_search": Tool("read", "Search saved evidence, entities and claims.", ("query",), {"query": s("Search terms")}),
    "entity_get": Tool("read", "Get one entity with observations, edges and claims.", ("entity_id",), {"entity_id": s()}),
    "entities_list": Tool("read", "List entities with optional type, target and evidence-level filters.", (),
                          {"type": s(), "target": s(), "level": s()}),
    "graph_neighbors": Tool("read", "Get edges and neighboring entities up to the specified hop count.", ("entity_id",),
                            {"entity_id": s(), "hops": i("At least one hop")}),
    "evidence_get": Tool("read", "Get an evidence event and optionally its saved text body.", ("event_id",),
                         {"event_id": s(), "with_body": b()}),
    "evidence_timeline": Tool("read", "List saved evidence events in case order.", (),
                              {"target": s(), "stage": s(), "kind": s(), "actor": s(), "limit": i()}),
    "claims_list": Tool("read", "List claims with optional target and state filters.", (),
                        {"target": s(), "state": s()}),
    "tasks_list": Tool("read", "List tasks with optional state and owner filters.", (),
                       {"state": s(), "owner": s()}),
    "handoffs_list": Tool("read", "List handoffs addressed to an actor or everyone.", (), {"to_actor": s()}),
    "decisions_list": Tool("read", "List open operator decisions.", (), {}),
    "entity_record": Tool("propose", "Record a proposed, observed or verified entity through the ledger.",
                          ("type", "key"), {"type": s(), "key": s(), "label": s(), "attrs": o(),
                                            "source_events": a(), "level": s(), "statement": s(),
                                            "source_span": o(), "extractor": s(), "confidence": {"type": "number"},
                                            "target": s(), "task_id": s(), "applicability": s(),
                                            "idempotency_key": s()}),
    "edge_add": Tool("propose", "Link two existing entities with a supported relation.",
                     ("src", "dst", "relation"), {"src": s(), "dst": s(), "relation": s(),
                                                  "status": s(), "source_events": a(),
                                                  "explanation": s(), "task_id": s()}),
    "claim_propose": Tool("propose", "Propose a hypothesis or observed claim for independent review.",
                          ("statement",), {"statement": s(), "state": s(), "target": s(),
                                           "entity_ids": a(), "supporting_events": a(),
                                           "contrary_events": a(), "impact": s(), "task_id": s()}),
    "claim_review": Tool("propose", "Review a claim as an independent actor, citing its evidence.",
                         ("claim_id", "state", "reason"), {"claim_id": s(), "state": s(), "reason": s(),
                                                           "supporting_events": a(), "contrary_events": a(),
                                                           "narrowed_statement": s()}),
    "task_create": Tool("coordinate", "Create a collaboration task.", ("objective",),
                        {"objective": s(), "target": s(), "deliverable": s(), "owner": s(),
                         "depends_on": a(), "context": o()}),
    "task_claim": Tool("coordinate", "Claim an available collaboration task for this server actor.",
                       ("task_id",), {"task_id": s()}),
    "task_update": Tool("coordinate", "Update task state, checkpoint and structured result.",
                        ("task_id",), {"task_id": s(), "state": s(), "owner": s(), "checkpoint": s(),
                                       "evidence": a(), "result": o(), "reason": s()}),
    "heartbeat": Tool("coordinate", "Record this actor's current activity.", ("note",),
                      {"note": s(), "task_id": s(), "provider": s()}),
    "lease_acquire": Tool("coordinate", "Acquire or renew a named collaboration resource lease.",
                          ("resource",), {"resource": s(), "ttl_seconds": i(), "note": s(), "task_id": s()}),
    "lease_release": Tool("coordinate", "Release a resource lease held by this actor.",
                          ("resource",), {"resource": s()}),
    "handoff_write": Tool("coordinate", "Write a structured handoff packet.", ("packet",),
                          {"packet": o(), "to_actor": s(), "task_id": s()}),
    "handoff_ack": Tool("coordinate", "Acknowledge a handoff for this actor.",
                        ("handoff_id",), {"handoff_id": s()}),
    "decision_ask": Tool("coordinate", "Ask the operator for a decision.", ("question",),
                         {"question": s(), "kind": s(), "context": o()}),
    "decision_answer": Tool("coordinate", "Record an operator decision answer under this actor.",
                            ("decision_id", "answer"), {"decision_id": s(), "answer": s()}),
    "epoch_start": Tool("coordinate", "Start a new case epoch and mark prior entities stale.",
                        ("reason",), {"reason": s(), "label": s(), "fingerprint_value": s()}),
    "report_run": Tool("capture", "Run a command through report.py run and preserve its transcript.",
                     ("target", "stage", "argv"), {"target": s(), "stage": s(), "argv": a(), "cwd": s()}),
    "report_import_capture": Tool("capture", "Import an existing captured command with full output, source IDs, and a rendered image.",
                                ("target", "stage", "capture"),
                                {"target": s(), "stage": s(), "capture": o()}),
    "report_log": Tool("capture", "Record exact browser, query or note text through report.py log.",
                     ("target", "stage", "kind", "text"),
                     {"target": s(), "stage": s(), "kind": s(), "text": s(), "result": s()}),
    "report_screenshot": Tool("capture", "Import a direct image through report.py screenshot.",
                            ("target", "stage", "file", "role", "caption"),
                            {"target": s(), "stage": s(), "file": s(), "role": s(), "caption": s()}),
    "report_code": Tool("capture", "Preserve a script and its provenance through report.py code.",
                      ("target", "stage", "file", "origin", "changes"),
                      {"target": s(), "stage": s(), "file": s(), "origin": s(), "changes": s()}),
}


def _validate(tool: Tool, arguments: Any) -> dict:
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object")
    missing = set(tool.required) - arguments.keys()
    unknown = arguments.keys() - tool.properties.keys()
    if missing:
        raise ValueError(f"Missing argument(s): {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"Unknown argument(s): {', '.join(sorted(unknown))}")
    types: dict[str, Callable[[Any], bool]] = {
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
    }
    for key, value in arguments.items():
        if not types[tool.properties[key]["type"]](value):
            raise ValueError(f"Invalid type for {key}: expected {tool.properties[key]['type']}")
    return arguments


def _needed(hub: CaseHub, value: dict | None, label: str) -> dict:
    if value is None:
        raise CaseHubError(f"Unknown {label}")
    return value


def _report(hub: CaseHub, action: str, args: list[str], result_text: str | None = None) -> dict:
    command = [sys.executable, str(REPORT), action, str(hub.root), *args]
    temp_path: str | None = None
    if result_text is not None:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="casehub-result-",
                                         suffix=".txt", delete=False) as result_file:
            result_file.write(result_text)
            temp_path = result_file.name
        command.extend(["--result-file", temp_path])
    try:
        completed = subprocess.run(command, text=True, capture_output=True,
                                   env={**os.environ, "REPORT_ACTOR": hub.actor}, check=False)
    finally:
        if temp_path is not None:
            Path(temp_path).unlink(missing_ok=True)
    # Parse the wrapper's own output stream, not text emitted by the child command.
    matches = (RUN_EVENT_ID.findall(completed.stderr) if action == "run"
               else RECORD_EVENT_ID.findall(completed.stdout))
    return {"stdout": completed.stdout, "stderr": completed.stderr,
            "exit_code": completed.returncode, "event_id": matches[-1] if matches else None}


def _dispatch(hub: CaseHub, name: str, a: dict) -> Any:
    if name in {n for n, t in TOOLS.items() if t.capability == "read"}:
        hub.sync_evidence()
    if name == "case_context": return hub.context()
    if name == "case_status_text": return status_text(hub.context())
    if name == "inventory_search": return hub.search(a["query"])
    if name == "entity_get": return _needed(hub, hub.entity(a["entity_id"]), "entity")
    if name == "entities_list": return hub.entities(type=a.get("type"), target=a.get("target"), level=a.get("level"))
    if name == "graph_neighbors": return hub.neighbors(a["entity_id"], hops=a.get("hops", 1))
    if name == "evidence_get": return _needed(hub, hub.evidence(a["event_id"], with_body=a.get("with_body", False)), "evidence event")
    if name == "evidence_timeline": return hub.timeline(**a)
    if name == "claims_list": return hub.claims(**a)
    if name == "tasks_list": return hub.tasks(**a)
    if name == "handoffs_list": return hub.handoffs(**a)
    if name == "decisions_list": return hub.decisions()
    if name == "entity_record": return {"entity_id": hub.record_entity(**a)}
    if name == "edge_add": hub.add_edge(**a); return {"added": True}
    if name == "claim_propose": return {"claim_id": hub.propose_claim(**a)}
    if name == "claim_review": hub.review_claim(**a); return {"reviewed": True}
    if name == "task_create": return {"task_id": hub.create_task(**a)}
    if name == "task_claim": hub.claim_task(**a); return {"claimed": True}
    if name == "task_update": hub.update_task(**a); return {"updated": True}
    if name == "heartbeat": hub.heartbeat(**a); return {"recorded": True}
    if name == "lease_acquire": return hub.acquire_lease(**a)
    if name == "lease_release": hub.release_lease(**a); return {"released": True}
    if name == "handoff_write": return {"handoff_id": hub.write_handoff(**a)}
    if name == "handoff_ack": hub.acknowledge_handoff(**a); return {"acknowledged": True}
    if name == "decision_ask": return {"decision_id": hub.ask_decision(**a)}
    if name == "decision_answer": hub.answer_decision(**a); return {"answered": True}
    if name == "epoch_start": return {"epoch_id": hub.start_epoch(**a)}
    if name == "report_run":
        if not a["argv"]:
            raise ValueError("argv must contain a command")
        args = ["--target", a["target"], "--stage", a["stage"]]
        if a.get("cwd") is not None: args.extend(["--cwd", a["cwd"]])
        return _report(hub, "run", [*args, "--", *a["argv"]])
    if name == "report_import_capture":
        from capture_import import import_capture
        event_id = import_capture(hub.root, a["target"], a["stage"], a["capture"])
        hub.sync_evidence()
        return {"event_id": event_id}
    if name == "report_log":
        args = ["--target", a["target"], "--stage", a["stage"], "--kind", a["kind"], "--text", a["text"]]
        return _report(hub, "log", args, result_text=a.get("result"))
    if name == "report_screenshot":
        return _report(hub, "screenshot", ["--target", a["target"], "--stage", a["stage"],
                                          "--file", a["file"], "--role", a["role"], "--caption", a["caption"]])
    if name == "report_code":
        return _report(hub, "code", ["--target", a["target"], "--stage", a["stage"],
                                    "--file", a["file"], "--origin", a["origin"], "--changes", a["changes"]])
    raise ValueError(f"Unknown tool {name}")


def _tool_result(value: Any, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}], "isError": is_error}


def _rpc_error(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class Server:
    def __init__(self, hub: CaseHub, capabilities: set[str]):
        self.hub = hub
        self.capabilities = capabilities

    def handle(self, message: Any) -> dict | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return _rpc_error(message.get("id") if isinstance(message, dict) else None, -32600, "Invalid Request")
        method, request_id = message["method"], message.get("id")
        if "id" not in message:
            return None  # JSON-RPC notifications never receive responses.
        params = message.get("params", {})
        if method == "initialize":
            value = {"protocolVersion": PROTOCOL_VERSION,
                     "serverInfo": {"name": "casehub", "version": "1.0"},
                     "capabilities": {"tools": {"listChanged": False}, "resources": {"listChanged": False}}}
        elif method == "ping": value = {}
        elif method == "tools/list":
            value = {"tools": [tool.listing(name) for name, tool in TOOLS.items()
                               if tool.capability in self.capabilities]}
        elif method == "tools/call":
            if not isinstance(params, dict) or not isinstance(params.get("name"), str):
                return _rpc_error(request_id, -32602, "tools/call needs a tool name")
            name = params["name"]
            tool = TOOLS.get(name)
            if tool is None or tool.capability not in self.capabilities:
                value = _tool_result({"error": f"Unavailable tool: {name}"}, True)
            else:
                try:
                    args = _validate(tool, params.get("arguments", {}))
                    result = _dispatch(self.hub, name, args)
                    value = _tool_result(result, isinstance(result, dict) and result.get("exit_code", 0) != 0)
                except (CaseHubError, ValueError, TypeError, OSError) as exc:
                    value = _tool_result({"error": str(exc)}, True)
        elif method == "resources/list":
            value = {"resources": [{"uri": uri, "name": name, "description": description,
                                    "mimeType": mime} for uri, name, description, mime in (
                ("case://summary", "Case summary", "Readable status for this case", "text/plain"),
                ("case://scope", "Case scope", "Authoritative case scope", "text/plain"),
                ("case://gates", "Evidence gates", "Stage and proof gate state by target", "application/json"))]}
        elif method == "resources/read":
            if not isinstance(params, dict):
                return _rpc_error(request_id, -32602, "resources/read needs a URI")
            uri = params.get("uri")
            if uri not in ("case://summary", "case://scope", "case://gates"):
                return _rpc_error(request_id, -32602, f"Unknown resource: {uri}")
            self.hub.sync_evidence()
            context = self.hub.context()
            if uri == "case://summary": text = status_text(context); mime = "text/plain"
            elif uri == "case://scope": text = context["case"]["scope"]; mime = "text/plain"
            else:
                text = json.dumps({"targets": context["targets"], "gates_required": context["case"]["gates_required"]}, ensure_ascii=False)
                mime = "application/json"
            value = {"contents": [{"uri": uri, "mimeType": mime, "text": text}]}
        else:
            return _rpc_error(request_id, -32601, f"Method not found: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": value}

    def serve(self) -> None:
        for line in sys.stdin:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                response = _rpc_error(None, -32700, "Parse error")
            else:
                try:
                    response = self.handle(message)
                except Exception as exc:
                    print(f"casehub MCP error: {exc}", file=sys.stderr)
                    response = _rpc_error(message.get("id") if isinstance(message, dict) else None,
                                          -32603, "Internal error")
            if response is not None:
                sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
                sys.stdout.flush()


def main(hub: CaseHub, args: argparse.Namespace) -> int:
    capabilities = {part.strip() for part in args.capabilities.split(",") if part.strip()}
    unknown = capabilities - CAPABILITIES
    if unknown:
        raise CaseHubError(f"Unknown MCP capabilities: {', '.join(sorted(unknown))}")
    Server(hub, capabilities).serve()
    return 0


def _standalone(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m casehub.mcp_server", description=__doc__)
    parser.add_argument("case", nargs="?", default=os.environ.get("REPORT_CASE"), help="report.py case directory (default: $REPORT_CASE)")
    parser.add_argument("--actor", help="actor for ledger writes (defaults to REPORT_ACTOR)")
    parser.add_argument("--capabilities", default="read,propose,coordinate",
                        help="comma-separated read,propose,coordinate,capture")
    args = parser.parse_args(argv)
    try:
        with CaseHub(args.case, actor=args.actor) as hub:
            return main(hub, args)
    except CaseHubError as exc:
        print(f"casehub MCP: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_standalone())
