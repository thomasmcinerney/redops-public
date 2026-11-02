#!/usr/bin/env python3
"""ACP cockpit spike: drive `kimi acp` from Python over stdio JSON-RPC.

Proves the RedOps-as-ACP-client path end to end:
  initialize -> session/new -> session/prompt, streaming the agent's
  messages + tool calls, and CATCHING session/request_permission (the
  cockpit's whole reason to exist). The spike auto-approves so the run
  completes; the real cockpit surfaces the request in the UI for you to
  answer.

Wire format confirmed against kimi 0.28.1: newline-delimited JSON-RPC 2.0
over stdio (no Content-Length framing).

Run: python3 scripts/acp_spike.py [--prompt "..."]
No RedOps deps. Requires kimi logged in (kimi login) for the LLM to respond.
"""

import argparse
import asyncio
import json
import os
import sys

KIMI = os.path.expanduser("~/.kimi-code/bin/kimi")


class ACPClient:
    def __init__(self, kimi: str, cwd: str):
        self.kimi, self.cwd = kimi, cwd
        self.proc = None
        self._id = 0
        self.pending: dict[int, asyncio.Future] = {}

    async def start(self):
        self.proc = await asyncio.create_subprocess_exec(
            self.kimi, "acp", stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=self.cwd)
        asyncio.create_task(self._read_loop())
        asyncio.create_task(self._stderr_loop())

    async def _send(self, obj: dict):
        self.proc.stdin.write((json.dumps(obj) + "\n").encode())
        await self.proc.stdin.drain()

    async def request(self, method: str, params: dict) -> dict:
        self._id += 1
        rid = self._id
        fut = asyncio.get_event_loop().create_future()
        self.pending[rid] = fut
        await self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        return await fut

    async def respond(self, rid, result=None, error=None):
        msg = {"jsonrpc": "2.0", "id": rid}
        msg["error" if error else "result"] = error or result
        await self._send(msg)

    async def _stderr_loop(self):
        while True:
            line = await self.proc.stderr.readline()
            if not line:
                break
            sys.stderr.write("\033[90m[kimi] " + line.decode(errors="replace") + "\033[0m")

    async def _read_loop(self):
        while True:
            line = await self.proc.stdout.readline()
            if not line:
                print("\n[acp] agent stdout closed")
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                print("[acp] non-json line:", line[:200])
                continue
            await self._dispatch(msg)

    async def _dispatch(self, msg: dict):
        if "id" in msg and ("result" in msg or "error" in msg):   # response to us
            fut = self.pending.pop(msg["id"], None)
            if fut and not fut.done():
                fut.set_result(msg)
            return
        method, params, rid = msg.get("method"), msg.get("params") or {}, msg.get("id")
        if method == "session/update":
            self._print_update(params.get("update") or {})
        elif method == "session/request_permission":
            self._print_permission(params)
            opts = params.get("options") or []
            pick = next((o for o in opts if "allow" in
                         (str(o.get("kind", "")) + str(o.get("name", ""))).lower()),
                        opts[0] if opts else None)
            outcome = ({"outcome": "selected", "optionId": pick["optionId"]}
                       if pick else {"outcome": "cancelled"})
            await self.respond(rid, {"outcome": outcome})
            print(f"[acp] auto-approved -> {outcome}\n")
        elif method == "fs/read_text_file":
            try:
                text = open(params["path"], errors="replace").read()
                await self.respond(rid, {"content": text})
            except Exception as e:
                await self.respond(rid, error={"code": -32000, "message": str(e)})
        elif method == "fs/write_text_file":
            print(f"[acp] agent WRITE request -> {params.get('path')} (spike acks, no write)")
            await self.respond(rid, {})
        elif rid is not None:
            print(f"[acp] unhandled request '{method}' -> null")
            await self.respond(rid, {})
        else:
            print(f"[acp] notification '{method}': {json.dumps(params)[:200]}")

    def _print_update(self, u: dict):
        kind = u.get("sessionUpdate") or u.get("type") or "?"
        if kind in ("agent_message_chunk", "agent_thought_chunk", "user_message_chunk"):
            c = u.get("content") or {}
            text = c.get("text") if isinstance(c, dict) else str(c)
            if kind == "agent_thought_chunk":
                sys.stdout.write("\033[90m" + (text or "") + "\033[0m")
            else:
                sys.stdout.write(text or "")
            sys.stdout.flush()
        elif kind in ("tool_call", "tool_call_update"):
            title = u.get("title") or u.get("kind") or ""
            status = u.get("status", "")
            print(f"\n\033[36m[TOOL {kind}] {title} {status}\033[0m {json.dumps(u)[:200]}")
        else:
            print(f"\n[UPDATE {kind}] {json.dumps(u)[:200]}")

    def _print_permission(self, params: dict):
        print("\n" + "=" * 64)
        print("\033[33mPERMISSION REQUEST  <-- the cockpit surfaces THIS in the UI\033[0m")
        tc = params.get("toolCall") or {}
        print(f"  tool: {tc.get('title') or tc.get('kind') or '?'}")
        print(f"  options: {[o.get('name') for o in params.get('options') or []]}")
        print("=" * 64)


async def run(args) -> int:
    c = ACPClient(args.kimi, args.cwd)
    await c.start()

    print("[acp] -> initialize")
    init = await c.request("initialize", {
        "protocolVersion": 1,
        "clientCapabilities": {"fs": {"readTextFile": True, "writeTextFile": False}}})
    if "error" in init:
        print("[acp] initialize FAILED:", init["error"]); return 1
    ai = init["result"].get("agentInfo", {})
    print(f"[acp] connected: {ai.get('name')} {ai.get('version')}")

    print("[acp] -> session/new")
    sn = await c.request("session/new", {"cwd": args.cwd, "mcpServers": []})
    if "error" in sn:
        print("[acp] session/new FAILED (auth? run `kimi login`):", sn["error"]); return 1
    sid = sn["result"]["sessionId"]
    print(f"[acp] session: {sid}\n--- agent output ---")

    pr = await c.request("session/prompt",
                         {"sessionId": sid, "prompt": [{"type": "text", "text": args.prompt}]})
    print("\n--- end ---")
    if "error" in pr:
        print("[acp] session/prompt FAILED:", pr["error"]); return 1
    print("[acp] stopReason:", pr["result"].get("stopReason"))
    print("\n\033[32mSPIKE OK: RedOps drove kimi over ACP, streamed output, caught permissions.\033[0m")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kimi", default=KIMI)
    ap.add_argument("--cwd", default=os.getcwd())
    ap.add_argument("--prompt", default=(
        "In one short sentence say hello, then run the shell command "
        "`echo acp-spike-ok` and tell me its output."))
    ap.add_argument("--timeout", type=float, default=120)
    args = ap.parse_args()
    try:
        return asyncio.run(asyncio.wait_for(run(args), timeout=args.timeout))
    except asyncio.TimeoutError:
        print(f"\n[acp] timed out after {args.timeout}s")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
