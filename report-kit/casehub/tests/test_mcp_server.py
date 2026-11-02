"""Subprocess tests for the standalone newline-delimited MCP server."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from casehub.ledger import CaseHub


KIT = Path(__file__).resolve().parents[2]
REPORT = KIT / "report.py"


class MCPServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="casehub-mcp-")
        self.addCleanup(self.temp.cleanup)
        self.case = Path(self.temp.name) / "case"
        self.report("init", self.case, "--title", "Synthetic MCP case", "--scope", "Local fixture only")
        self.report("target", self.case, "--id", "demo", "--name", "Demo",
                  "--ip", "127.0.0.1", "--role", "traditional",
                  "--objective", "Review fixture", "--summary", "Synthetic case")
        self.report("stage", self.case, "--target", "demo", "--kind", "recon",
                  "--summary", "Synthetic observations")
        self.report("log", self.case, "--target", "demo", "--stage", "recon",
                  "--kind", "note", "--text", "synthetic MCP evidence")
        self.event_id = json.loads((self.case / "case.json").read_text())["events"][-1]["id"]

    def report(self, *args: object) -> subprocess.CompletedProcess[str]:
        result = subprocess.run([sys.executable, str(REPORT), *(str(x) for x in args)],
                                cwd=KIT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def rpc(self, messages: list[dict], *, capabilities: str = "read,propose,coordinate",
            actor: str | None = "mcp-test", env: dict[str, str] | None = None) -> dict:
        command = [sys.executable, "-m", "casehub.mcp_server", str(self.case),
                   "--capabilities", capabilities]
        if actor is not None:
            command.extend(["--actor", actor])
        body = "".join(json.dumps(m) + "\n" for m in messages)
        result = subprocess.run(command, input=body, cwd=KIT, text=True,
                                capture_output=True, check=False, timeout=20,
                                env=os.environ | (env or {}))
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        return {reply["id"]: reply for reply in replies}

    @staticmethod
    def request(id: int, method: str, params: dict | None = None) -> dict:
        return {"jsonrpc": "2.0", "id": id, "method": method, "params": params or {}}

    @staticmethod
    def call(id: int, name: str, arguments: dict | None = None) -> dict:
        return MCPServerTests.request(id, "tools/call", {"name": name, "arguments": arguments or {}})

    @staticmethod
    def content(reply: dict) -> object:
        return json.loads(reply["result"]["content"][0]["text"])

    def test_imported_capture_is_idempotent(self) -> None:
        capture = {"source_system": "ops", "source_engagement": 7,
                   "source_id": 42, "command": "probe", "output": "captured output"}
        args = {"target": "demo", "stage": "recon", "capture": capture}
        first = self.rpc([self.call(1, "report_import_capture", args)], capabilities="read,capture")
        second = self.rpc([self.call(2, "report_import_capture", args)], capabilities="read,capture")
        event_id = self.content(first[1])["event_id"]
        self.assertEqual(self.content(second[2])["event_id"], event_id)
        with CaseHub(self.case, actor="test") as hub:
            hub.sync_evidence()
            self.assertIsNotNone(hub.evidence(event_id, with_body=True))

    def test_protocol_tools_errors_and_ledger_write(self) -> None:
        replies = self.rpc([
            self.request(1, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                           "clientInfo": {"name": "fixture", "version": "1"}}),
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            self.request(2, "ping"),
            self.request(3, "tools/list"),
            self.call(4, "case_context"),
            self.call(5, "entity_record", {"type": "host", "key": "127.0.0.1", "label": "Fixture host",
                                            "target": "demo", "level": "observed",
                                            "source_events": ["missing-event"]}),
            self.call(6, "entity_record", {"type": "host", "key": "127.0.0.1", "label": "Fixture host",
                                            "target": "demo", "level": "observed",
                                            "source_events": [self.event_id]}),
            self.call(7, "task_create", {"objective": "Review saved fixture", "target": "demo"}),
        ])
        self.assertEqual(set(replies), set(range(1, 8)))  # notification produced no line
        self.assertEqual(replies[1]["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(replies[2]["result"], {})
        names = {t["name"] for t in replies[3]["result"]["tools"]}
        self.assertIn("case_context", names)
        self.assertIn("entity_record", names)
        self.assertIn("task_create", names)
        self.assertNotIn("report_run", names)
        self.assertTrue(all("evidence event IDs" in t["description"] for t in replies[3]["result"]["tools"]))
        self.assertEqual(self.content(replies[4])["case"]["title"], "Synthetic MCP case")
        self.assertTrue(replies[5]["result"]["isError"])
        self.assertIn("Unknown evidence event ID", self.content(replies[5])["error"])
        self.assertFalse(replies[6]["result"]["isError"])
        entity_id = self.content(replies[6])["entity_id"]
        task_id = self.content(replies[7])["task_id"]
        with CaseHub(self.case, actor="inspector") as hub:
            self.assertEqual(hub.entity(entity_id)["actor"], "mcp-test")
            self.assertEqual(hub.entity(entity_id)["source_events"], [self.event_id])
            self.assertEqual(hub.task(task_id)["creator"], "mcp-test")

    def test_resources_and_capability_gate(self) -> None:
        replies = self.rpc([
            self.request(1, "resources/list"),
            self.request(2, "resources/read", {"uri": "case://summary"}),
            self.request(3, "resources/read", {"uri": "case://scope"}),
            self.request(4, "resources/read", {"uri": "case://gates"}),
            self.request(5, "tools/list"),
            self.call(6, "task_create", {"objective": "Must be blocked"}),
        ], capabilities="read")
        self.assertEqual({r["uri"] for r in replies[1]["result"]["resources"]},
                         {"case://summary", "case://scope", "case://gates"})
        self.assertIn("Synthetic MCP case", replies[2]["result"]["contents"][0]["text"])
        self.assertEqual(replies[3]["result"]["contents"][0]["text"], "Local fixture only")
        gates = json.loads(replies[4]["result"]["contents"][0]["text"])
        self.assertIn("demo", gates["targets"])
        self.assertTrue(all(t["name"] not in {"task_create", "entity_record", "report_run"}
                            for t in replies[5]["result"]["tools"]))
        self.assertTrue(replies[6]["result"]["isError"])
        with CaseHub(self.case) as hub:
            self.assertEqual(hub.tasks(), [])

    def test_read_sync_and_filters(self) -> None:
        replies = self.rpc([
            self.call(1, "evidence_get", {"event_id": self.event_id, "with_body": True}),
            self.call(2, "evidence_timeline", {"target": "demo", "kind": "note", "limit": 10}),
            self.call(3, "inventory_search", {"query": "synthetic MCP evidence"}),
            self.call(4, "case_status_text"),
            self.call(5, "entities_list", {"type": "host"}),
        ])
        self.assertIn("synthetic MCP evidence", self.content(replies[1])["body"])
        self.assertEqual([e["id"] for e in self.content(replies[2])], [self.event_id])
        self.assertIn(self.event_id, [e["id"] for e in self.content(replies[3])["evidence"]])
        self.assertIn("Targets:", self.content(replies[4]))
        self.assertEqual(self.content(replies[5]), [])

    def test_capture_uses_report_and_sets_actor(self) -> None:
        replies = self.rpc([
            self.call(1, "report_log", {"target": "demo", "stage": "recon", "kind": "query",
                                      "text": "synthetic question", "result": "synthetic answer"}),
            self.call(2, "report_run", {"target": "demo", "stage": "recon",
                                      "argv": [sys.executable, "-c", "print('synthetic run')"]}),
        ], capabilities="capture", actor="capture-agent")
        for number in (1, 2):
            result = self.content(replies[number])
            self.assertEqual(result["exit_code"], 0, result["stderr"])
            self.assertRegex(result["event_id"], r"^[0-9a-f]{12}$")
            self.assertFalse(replies[number]["result"]["isError"])
        events = json.loads((self.case / "case.json").read_text())["events"]
        captured = {e["id"]: e for e in events}
        self.assertEqual(captured[self.content(replies[1])["event_id"]]["actor"], "capture-agent")
        self.assertEqual(captured[self.content(replies[1])["event_id"]]["result"], "synthetic answer")
        self.assertEqual(captured[self.content(replies[2])["event_id"]]["actor"], "capture-agent")
        self.assertEqual(captured[self.content(replies[2])["event_id"]]["status"], "done")

    def test_actor_environment_fallback_and_failed_capture(self) -> None:
        replies = self.rpc([self.call(1, "task_create", {"objective": "Review fixture"})],
                           actor=None, env={"REPORT_ACTOR": "env-agent"})
        with CaseHub(self.case) as hub:
            self.assertEqual(hub.task(self.content(replies[1])["task_id"])["creator"], "env-agent")
        replies = self.rpc([self.call(2, "report_run", {"target": "demo", "stage": "recon",
                                                        "argv": [sys.executable, "-c", "raise SystemExit(7)"]})],
                           capabilities="capture")
        result = self.content(replies[2])
        self.assertTrue(replies[2]["result"]["isError"])
        self.assertEqual(result["exit_code"], 7)
        self.assertRegex(result["event_id"], r"^[0-9a-f]{12}$")


if __name__ == "__main__":
    unittest.main()
