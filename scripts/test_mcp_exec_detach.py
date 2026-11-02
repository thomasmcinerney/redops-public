#!/usr/bin/env python3
"""Functional test for the exec auto-detach fix in redops/mcp_server.py.

Drives a real MCP stdio session with REDOPS_MCP_FOREGROUND_BUDGET=5:
  1. short command (timeout=10, runs ~0s)  -> synchronous path, exit_code 0
  2. medium command (timeout=30, sleeps 8s) -> auto-detach, completes in budget
  3. long command (timeout=30, sleeps 30s)  -> auto-detach, returns pending,
     then poll exec_output until the `timeout` wrapper kills it (rc 124)

Requires the RedOps API running on 127.0.0.1:9100.
"""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_PY = next((p for p in (ROOT / ".venv/bin/python", ROOT / "venv/bin/python") if p.exists()), Path(sys.executable))
CMD = [str(_PY), str(ROOT / "redops/mcp_server.py")]
ENV = {**os.environ, "REDOPS_MCP_FOREGROUND_BUDGET": "5"}


class McpPipe:
    def __init__(self):
        self.proc = subprocess.Popen(CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, cwd=ROOT, text=True,
                                     bufsize=1, env=ENV)
        self._id = 0
        self._stderr = []
        self._responses = {}
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

    def call(self, method, params=None, timeout=90.0):
        self._id += 1
        rid = self._id
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}) + "\n")
        self.proc.stdin.flush()
        with self._cond:
            if not self._cond.wait_for(lambda: rid in self._responses, timeout):
                raise TimeoutError(f"no response id={rid} to {method}; stderr: {self._stderr[-5:]}")
            return self._responses.pop(rid)

    def notify(self, method, params=None):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method,
                                          "params": params or {}}) + "\n")
        self.proc.stdin.flush()

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def tool(pipe, name, args, timeout=90.0):
    resp = pipe.call("tools/call", {"name": name, "arguments": args}, timeout)
    result = resp.get("result", {})
    text = "\n".join(c.get("text", "") for c in result.get("content", [])
                     if c.get("type") == "text")
    if result.get("isError"):
        raise RuntimeError(f"{name} -> MCP error: {text[:300]}")
    return json.loads(text)


def main():
    ok = True
    pipe = McpPipe()
    try:
        pipe.call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "exec-detach-test", "version": "0.1"}})
        pipe.notify("notifications/initialized")

        # 1. short command (timeout <= budget) stays synchronous
        t0 = time.monotonic()
        r = tool(pipe, "exec", {"command": "echo sync-ok", "timeout": 3})
        dt = time.monotonic() - t0
        good = bool(r.get("exit_code") == 0 and "sync-ok" in r.get("stdout", "")
                    and not r.get("detached") and not r.get("pending"))
        print(f"[1 sync] {dt:.1f}s -> {r.get('exit_code')} detached={r.get('detached')} "
              f"pending={r.get('pending')} :: {'ok' if good else 'FAIL'}")
        ok = ok and good

        # 2. command longer than its sync budget but shorter than the polling
        #    budget: auto-detach, completes in time, normal-shaped result
        t0 = time.monotonic()
        r = tool(pipe, "exec", {"command": "sleep 2; echo detach-ok", "timeout": 30})
        dt = time.monotonic() - t0
        good = bool(r.get("detached") and r.get("exit_code") == 0
                    and "detach-ok" in r.get("stdout", ""))
        print(f"[2 detach] {dt:.1f}s -> rc={r.get('exit_code')} task={r.get('task_id')} "
              f":: {'ok' if good else 'FAIL'}")
        ok = ok and good

        # 3. command longer than budget AND still running at budget: pending + task_id
        t0 = time.monotonic()
        r = tool(pipe, "exec", {"command": "sleep 30; echo should-be-killed", "timeout": 20})
        dt = time.monotonic() - t0
        good = bool(r.get("pending") and r.get("task_id"))
        print(f"[3 pending] {dt:.1f}s -> {r} :: {'ok' if good else 'FAIL'}")
        ok = ok and good
        task_id = r.get("task_id")

        # 3b. the `timeout 20` wrapper must kill it; poll until not running
        final = None
        for _ in range(15):
            time.sleep(2)
            t = tool(pipe, "exec_output", {"task_id": task_id})
            if t.get("status") != "running":
                final = t
                break
        good = bool(final is not None and final.get("exit_code") == 124
                    and "should-be-killed" not in (final.get("output") or ""))
        print(f"[3b timeout-kill] status={final and final.get('status')} "
              f"rc={final and final.get('exit_code')} :: {'ok' if good else 'FAIL'}")
        ok = ok and good
    finally:
        pipe.close()
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
