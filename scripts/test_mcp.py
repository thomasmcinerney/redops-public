#!/usr/bin/env python3
"""Standalone MCP stdio handshake test for the RedOps MCP server.

Spawns venv/bin/python redops/mcp_server.py with pipes and drives a proper
MCP session: initialize -> notifications/initialized -> tools/list ->
tools/call (status, fact_add, opp_list, sitrep_show).

Usage: cd ~/redops && ./venv/bin/python scripts/test_mcp.py
Requires the RedOps API to be running (tools/call hits the HTTP API).
"""

import json
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# uv makes `.venv`; a hand-rolled venv is usually `venv`. Fall back to whatever
# interpreter is running this script (`uv run python scripts/test_mcp.py`).
_PY = next((p for p in (ROOT / ".venv/bin/python", ROOT / "venv/bin/python") if p.exists()),
           Path(sys.executable))
CMD = [str(_PY), str(ROOT / "redops/mcp_server.py")]

PROTOCOL_VERSION = "2024-11-05"


class McpPipe:
    def __init__(self):
        self.proc = subprocess.Popen(CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, cwd=ROOT, text=True, bufsize=1)
        self._id = 0
        self._stderr = []
        self._responses: dict[int, dict] = {}
        self._cond = threading.Condition()
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        threading.Thread(target=self._reader, daemon=True).start()

    def _drain_stderr(self):
        for line in self.proc.stderr:
            self._stderr.append(line.rstrip())

    def _reader(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "id" in msg:
                with self._cond:
                    self._responses[msg["id"]] = msg
                    self._cond.notify_all()

    def _next_id(self):
        self._id += 1
        return self._id

    def _send(self, msg: dict):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def call(self, method: str, params: dict | None = None, timeout: float = 20.0) -> dict:
        rid = self._next_id()
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        with self._cond:
            if not self._cond.wait_for(lambda: rid in self._responses, timeout):
                raise TimeoutError(f"no response id={rid} to {method}; stderr: {self._stderr[-5:]}")
            return self._responses.pop(rid)

    def notify(self, method: str, params: dict | None = None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def unwrap(resp: dict):
    """Return (is_error, text) from a tools/call response."""
    result = resp.get("result", {})
    content = result.get("content", [])
    text = "\n".join(c.get("text", "") for c in content if c.get("type") == "text")
    return result.get("isError", False), text


def main() -> int:
    ok = True
    pipe = McpPipe()
    try:
        init = pipe.call("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "redops-mcp-test", "version": "0.1"}})
        server = init.get("result", {}).get("serverInfo", {})
        print(f"[initialize] server={server.get('name')} v{server.get('version')} "
              f"protocol={init.get('result', {}).get('protocolVersion')}")

        pipe.notify("notifications/initialized")

        tools = pipe.call("tools/list").get("result", {}).get("tools", [])
        names = [t["name"] for t in tools]
        print(f"[tools/list] {len(names)} tools: {', '.join(sorted(names))}")

        expected = {"log", "fact_add", "fact_list", "fact_out", "opp_list", "opp_convert",
                    "opp_dismiss", "tasks_pending", "task_done", "sitrep_set", "sitrep_show",
                    "target_add", "svc_add", "cred_add", "finding_add", "status"}
        missing = expected - set(names)
        if missing:
            print(f"!! missing tools: {missing}")
            ok = False

        for name, args in [
            ("status", {}),
            ("sitrep_show", {}),
            ("fact_add", {"subject": "mcp-test-svc", "predicate": "runs-as",
                          "object": "root", "stype": "service", "confidence": "low"}),
            ("opp_list", {"status": "open"}),
            ("fact_out", {"fact_id": 999999}),  # exercises error path
        ]:
            resp = pipe.call("tools/call", {"name": name, "arguments": args})
            is_err, text = unwrap(resp)
            print(f"[tools/call {name}] {'ERROR' if is_err else 'ok'}: {text[:240]}")
            if name == "fact_out" and not is_err:
                print("!! expected an error for unknown fact_id")
                ok = False
            if name != "fact_out" and is_err:
                ok = False
    finally:
        pipe.close()
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
