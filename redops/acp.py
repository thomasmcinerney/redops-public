"""RedOps as an ACP client that owns the agent session.

Spawns an ACP agent (`kimi acp` by default) as a subprocess, speaks
newline-delimited JSON-RPC 2.0 over its stdio, and translates the
`session/update` stream into RedOps events via `db.add_event` — the exact
same events wiretail produces, so board / feed / extractor / correlation all
work unchanged. Adds the two things wiretail structurally cannot: a prompt
lane (`session/prompt`) and permission requests (`session/request_permission`).

Runs in its own thread with a dedicated asyncio loop (wiretail is a thread
today; this mirrors that). Synchronous FastAPI handlers bridge into the loop
via `run_coroutine_threadsafe`.

Config:
  REDOPS_CAPTURE        acp | wire | both   (default wire; api.startup reads it)
  REDOPS_ACP_CMD        agent command       (default `<kimi> acp`)
  REDOPS_ACP_AUTOAPPROVE  1 = auto-allow permissions and log the decision
  REDOPS_ACP_CWD        agent working dir   (default server cwd)
"""

import asyncio
import json
import os
import shlex
import sys
import threading
import time
from pathlib import Path

from . import db, wiretail

HOST = os.environ.get("REDOPS_HOST", "127.0.0.1")
PORT = int(os.environ.get("REDOPS_PORT", "9100"))

_KIMI = os.path.expanduser("~/.kimi-code/bin/kimi")
DEFAULT_CMD = os.environ.get("REDOPS_ACP_CMD", f"{_KIMI} acp")

RESPAWN_BACKOFF = 3.0        # seconds between respawn attempts on agent death
# asyncio's default stdio StreamReader buffer is 64 KiB. ACP messages (a big tool
# result, a screenshot, a long agent turn) routinely exceed that on ONE line, and
# an overflow raises out of the read loop and silently kills the session. Give the
# reader real headroom so normal traffic never blows it.
STREAM_LIMIT = 64 * 1024 * 1024   # 64 MiB per line

# Deadlines. Control calls answer immediately or the agent is wedged.
#
# A PROMPT is measured on IDLENESS, not total duration: a turn that runs for
# hours while still emitting events is working. Killing it on wall-clock would
# cut real work off mid-stream. Silence is the only reliable wedge signal.
CONTROL_TIMEOUT = float(os.environ.get("REDOPS_ACP_CONTROL_TIMEOUT", "60"))
# accept the pre-rename name too — silently ignoring an env var someone already
# set is how a deployment ends up running defaults it never asked for
PROMPT_IDLE_TIMEOUT = float(os.environ.get("REDOPS_ACP_PROMPT_IDLE_TIMEOUT")
                            or os.environ.get("REDOPS_ACP_PROMPT_TIMEOUT")
                            or "900")
LIVE_WINDOW = 20.0          # an event this recent -> capture is "live"


# ---------------------------------------------------------------------------
# text extraction from ACP content blocks (defensive: shapes vary by agent)

def _collect_text(obj) -> str:
    """Recursively gather every {type:'text', text:...} payload. Works for the
    single content block on message/thought chunks AND the nested content list
    on tool-call output."""
    out: list[str] = []

    def walk(x):
        if isinstance(x, dict):
            if x.get("type") == "text" and isinstance(x.get("text"), str):
                out.append(x["text"])
            else:
                for v in x.values():
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(obj)
    return "\n".join(p for p in out if p)


def _tool_command(tc: dict) -> str:
    """The command line for exec-style tools (verbatim, per wiretail's
    _tool_summary rule); a name(args) summary otherwise.

    kimi 0.28.1 leaves `rawInput` null through the whole run except one late
    update, streaming the arguments as partial JSON text inside `content`
    instead. So: prefer rawInput, else parse the streamed args JSON, else the
    tool title."""
    title = tc.get("title") or tc.get("kind") or "tool"
    raw = tc.get("rawInput") or tc.get("input")
    args = raw if isinstance(raw, dict) and raw else None
    if args is None:
        blob = _collect_text(tc.get("content"))
        if blob:
            try:
                parsed = json.loads(blob)
                if isinstance(parsed, dict):
                    args = parsed
            except (ValueError, TypeError):
                pass
    if isinstance(args, dict):
        if isinstance(args.get("command"), str):
            return args["command"]
        try:
            return f"{title}({json.dumps(args, ensure_ascii=False)})"
        except (TypeError, ValueError):
            return f"{title}({args})"
    return title


# ---------------------------------------------------------------------------
# health state (persisted so /api/health and the CAPTURE pill can read it)

def _set(conn, key: str, value: str) -> None:
    db.set_state(conn, key, value)


def set_status(status: str, **extra) -> None:
    conn = db.connect()
    try:
        _set(conn, "acp:status", status)
        # stamp WHEN we stalled, so recovery can require an event that postdates
        # it rather than trusting a pid that is alive but not doing anything
        if status == "stalled":
            _set(conn, "acp:stalled_at", db.now())
        for k, v in extra.items():
            _set(conn, f"acp:{k}", "" if v is None else str(v))
    finally:
        conn.close()


def _evented_since_stall() -> bool:
    """True only if an event arrived AFTER the stall was recorded — the sole
    evidence that the agent's loop is running again."""
    conn = db.connect()
    try:
        stalled = db.get_state(conn, "acp:stalled_at") or ""
        last = db.get_state(conn, "acp:last_event_ts") or ""
        return bool(stalled and last and last > stalled)
    finally:
        conn.close()


def _status_now() -> str:
    conn = db.connect()
    try:
        return db.get_state(conn, "acp:status") or "off"
    finally:
        conn.close()


def _pid_alive(pid) -> bool:
    """True only for a LIVE (non-zombie) process — Linux /proc. A crashed agent
    that left a zombie (or is gone) must NOT read as alive."""
    if not pid:
        return False
    try:
        with open(f"/proc/{int(pid)}/stat") as f:
            state = f.read().rsplit(") ", 1)[1].split(" ", 1)[0]
        return state not in ("Z", "X", "x")
    except (FileNotFoundError, ProcessLookupError, ValueError, OSError, IndexError):
        return False


def health() -> dict:
    conn = db.connect()
    try:
        status = db.get_state(conn, "acp:status") or "off"
        # HONESTY: never report "live" for a dead process. The supervisor's wait()
        # can hang in a non-main-thread loop and leave status frozen at "live" even
        # after the agent crashed; the pid check is the ground truth.
        if status == "live" and not _pid_alive(db.get_state(conn, "acp:pid")):
            status = "stalled"
        last = db.get_state(conn, "acp:last_event_ts") or None
        return {
            "status": status,
            "sessionId": db.get_state(conn, "acp:sessionId") or None,
            "lastEvent": last,
            "auth": db.get_state(conn, "acp:auth") or None,
            "error": db.get_state(conn, "acp:error") or None,
            "cmd": db.get_state(conn, "acp:cmd") or None,
            # the turn running RIGHT NOW (so the operator can see what the agent is
            # doing and why) — only trusted while the session is actually live.
            "running": status == "live" and bool(db.get_state(conn, "acp:activeTurn")),
            "prompt": db.get_state(conn, "acp:activePrompt") or None,
            "since": db.get_state(conn, "acp:activeSince") or None,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------

class AcpSession(threading.Thread):
    def __init__(self, cmd: str | None = None, cwd: str | None = None):
        super().__init__(daemon=True, name="acp-session")
        self.cmd = cmd or DEFAULT_CMD
        self.cwd = cwd or os.environ.get("REDOPS_ACP_CWD") or os.getcwd()
        self.autoapprove = os.environ.get("REDOPS_ACP_AUTOAPPROVE", "1") == "1"  # launch default

        self._loop: asyncio.AbstractEventLoop | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._rid = 0
        self._pending: dict[int, asyncio.Future] = {}     # our requests -> response
        self.session_id: str | None = None
        # The engagement this session BELONGS to. Bound at session start/reset and
        # stamped on every event, so a session's activity can never leak into a
        # different engagement just because the operator switched the active one.
        self.engagement_id: int | None = None
        self._stop = False
        # wall-clock of the last event this session emitted. A long turn is not a
        # wedged turn — SILENCE is. The prompt deadline is measured against this,
        # not against total turn duration, so an agent that grinds for two hours
        # while still emitting is left alone.
        self._last_event_at = time.monotonic()

        # kimi 0.28.1 sends no turnId, so we assign one per prompt() and stamp
        # every event of that turn with it, giving the board real turn grouping.
        self._turn_seq = 0
        self._active_turn: str | None = None

        # coalescing: one "current block" per turn, flushed on kind change /
        # tool boundary / turn end. Prevents per-token event + SSE flood.
        self._block: dict[str, dict] = {}                 # turn -> {kind, text}
        self._call_turn: dict[str, str] = {}              # tool_call_id -> turnId
        self._call_emitted: dict[str, bool] = {}          # action event emitted?
        self._out_emitted: set[str] = set()               # output event emitted?

        # permissions: rid (JSON-RPC id of the request) -> record
        self._perms: dict[str, dict] = {}
        self._perms_lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------

    def run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._supervise())
        except Exception as e:  # noqa: BLE001 - top-level guard
            set_status("errors", error=repr(e))
            print(f"[acp] fatal: {e!r}", file=sys.stderr, flush=True)

    async def _supervise(self) -> None:
        """Keep an agent + session alive; respawn on death and resume via
        session/load when we have a saved sessionId."""
        set_status("off", cmd=self.cmd, error=None, auth=None)
        while not self._stop:
            try:
                # A failed init/session leaves the previous process running; without
                # this every ~63s retry leaked another agent.
                self._kill_proc()
                await self._spawn()
                await self._initialize()
                await self._ensure_session()
                set_status("live", error=None)
                # Poll liveness instead of `await self._proc.wait()`: asyncio's
                # child watcher is main-thread-only, so wait() can hang forever in
                # this worker thread and leave a DEAD agent reported "live" with no
                # respawn (the exact "silent and I can't tell" bug).
                pid = self._proc.pid
                while not self._stop and _pid_alive(pid):
                    await asyncio.sleep(2)
                    # Recover from a stall ONLY on evidence of life.
                    #
                    # The first version of this recovered whenever the pid was
                    # alive — but "live pid, dead event loop" is precisely what
                    # stalled means, so it erased every real stall within 2s and
                    # turned a sticky false-positive into a permanent false
                    # NEGATIVE of the one signal the timeout exists to produce.
                    # An event arriving AFTER the stall is the only proof the
                    # loop is running again.
                    if _status_now() == "stalled" and _evented_since_stall():
                        set_status("live", error=None)
                        print("[acp] events flowing again; status live",
                              file=sys.stderr, flush=True)
                if self._stop:
                    break
                self._kill_proc()
                set_status("stalled", error="agent process exited")
                print("[acp] agent exited; respawning", file=sys.stderr, flush=True)
            except _AuthError as e:
                set_status("auth", auth=str(e))
                print(f"[acp] auth required: {e}", file=sys.stderr, flush=True)
                await asyncio.sleep(RESPAWN_BACKOFF * 3)
            except Exception as e:  # noqa: BLE001
                set_status("errors", error=repr(e))
                print(f"[acp] session error: {e!r}", file=sys.stderr, flush=True)
            # drop stale request futures before retry
            for fut in self._pending.values():
                if not fut.done():
                    fut.cancel()
            self._pending.clear()
            self._flush_all()
            if not self._stop:
                await asyncio.sleep(RESPAWN_BACKOFF)

    def _kill_proc(self) -> None:
        """Terminate and reap the current agent process, if any. Idempotent."""
        proc = self._proc
        if not proc:
            return
        pid = getattr(proc, "pid", None)
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
        try:
            if pid:
                os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            pass
        self._proc = None

    async def _spawn(self) -> None:
        argv = shlex.split(self.cmd)
        self._proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, cwd=self.cwd, limit=STREAM_LIMIT)
        conn = db.connect()
        try:
            _set(conn, "acp:pid", str(self._proc.pid))   # ground-truth liveness
        finally:
            conn.close()
        asyncio.ensure_future(self._read_loop())
        asyncio.ensure_future(self._stderr_loop())

    # -- JSON-RPC plumbing --------------------------------------------------

    async def _send(self, obj: dict) -> None:
        if not self._proc or not self._proc.stdin:
            return
        self._proc.stdin.write((json.dumps(obj) + "\n").encode())
        await self._proc.stdin.drain()

    async def request(self, method: str, params: dict, timeout: float | None = None,
                      idle: bool = False) -> dict:
        """A JSON-RPC call with a DEADLINE. Without one, an agent that is alive but
        wedged (pid up, loop dead) leaves the future unresolved forever: the session
        freezes, the turn never ends, and health still reports "live". That is
        exactly the "he's silent again and I cannot tell" failure — a dead process
        we now catch, a dead loop we did not.

        `idle=True` measures the deadline from the last EVENT rather than from the
        call, which is what a prompt needs: long work is fine, silence is not."""
        self._rid += 1
        rid = self._rid
        fut = self._loop.create_future()
        self._pending[rid] = fut
        await self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        secs = timeout if timeout is not None else CONTROL_TIMEOUT
        try:
            if idle:
                return await self._await_idle(fut, secs)
            return await asyncio.wait_for(fut, secs)
        except asyncio.TimeoutError:
            self._pending.pop(rid, None)
            what = "went silent for" if idle else "did not answer in"
            set_status("stalled", error=f"{method} {what} {secs:.0f}s")
            print(f"[acp] {method} timed out after {secs:.0f}s — agent is wedged",
                  file=sys.stderr, flush=True)
            raise

    async def _await_idle(self, fut, idle_limit: float):
        """Wait on `fut`, timing out only after `idle_limit` seconds of SILENCE.

        A turn that runs for hours while still emitting events is working, not
        wedged; a flat wall-clock deadline would kill it mid-stream. What
        actually distinguishes a wedge is that nothing comes out."""
        while True:
            try:
                return await asyncio.wait_for(asyncio.shield(fut),
                                              timeout=min(15.0, idle_limit))
            except asyncio.TimeoutError:
                if fut.done():
                    return fut.result()
                if time.monotonic() - self._last_event_at >= idle_limit:
                    raise

    async def respond(self, rid, result=None, error=None) -> None:
        msg = {"jsonrpc": "2.0", "id": rid}
        msg["error" if error else "result"] = error or (result or {})
        await self._send(msg)

    async def _stderr_loop(self) -> None:
        while self._proc and self._proc.stderr:
            line = await self._proc.stderr.readline()
            if not line:
                break
            print("\033[90m[acp:agent] " + line.decode(errors="replace").rstrip()
                  + "\033[0m", file=sys.stderr, flush=True)

    async def _read_loop(self) -> None:
        while self._proc and self._proc.stdout:
            try:
                line = await self._proc.stdout.readline()
            except (asyncio.LimitOverrunError, ValueError) as e:
                # one line blew even the 64 MiB buffer — the stdio JSON-RPC framing
                # can't be resynced, so kill the process and let the supervisor
                # respawn a clean session rather than leave a silently-dead reader
                # while _proc.wait() blocks forever.
                print(f"[acp] read overflow, forcing respawn: {e!r}", file=sys.stderr, flush=True)
                try:
                    if self._proc:
                        self._proc.kill()
                except ProcessLookupError:
                    pass
                break
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                print(f"[acp] non-json line: {line[:120]!r}", file=sys.stderr, flush=True)
                continue
            try:
                await self._dispatch(msg)
            except Exception as e:  # noqa: BLE001
                print(f"[acp] dispatch error: {e!r}", file=sys.stderr, flush=True)

    async def _dispatch(self, msg: dict) -> None:
        # response to one of our requests
        if "id" in msg and ("result" in msg or "error" in msg) and "method" not in msg:
            fut = self._pending.pop(msg["id"], None)
            if fut and not fut.done():
                fut.set_result(msg)
            return
        method = msg.get("method")
        params = msg.get("params") or {}
        rid = msg.get("id")
        if method == "session/update":
            self._on_update(params.get("update") or {})
        elif method == "session/request_permission":
            await self._on_permission(rid, params)
        elif method == "fs/read_text_file":
            await self._on_fs_read(rid, params)
        elif method == "fs/write_text_file":
            await self._on_fs_write(rid, params)
        elif rid is not None:
            await self.respond(rid, {})   # unknown agent->client request: ack empty

    # -- initialize / session ----------------------------------------------

    async def _initialize(self) -> None:
        resp = await self.request("initialize", {
            "protocolVersion": 1,
            "clientCapabilities": {"fs": {"readTextFile": True, "writeTextFile": True}}})
        if "error" in resp:
            raise RuntimeError(f"initialize failed: {resp['error']}")

    def _mcp_servers(self) -> list[dict]:
        script = str(Path(__file__).resolve().parent / "mcp_server.py")
        url = os.environ.get("REDOPS_URL", f"http://{HOST}:{PORT}")
        return [{
            "name": "redops",
            "command": sys.executable,
            "args": [script],
            "env": [{"name": "REDOPS_URL", "value": url}],
        }]

    def _bind_engagement(self) -> None:
        """Bind this session to the engagement active RIGHT NOW; all its events
        get stamped with it until the next reset.

        PUBLISH it too. The pin used to live only on this object, while the MCP
        server re-resolved the *global* active engagement on every tool call — so
        an operator switching engagements mid-turn sent the agent's ACP events to
        one engagement and its MCP writes to another. Split-brain, silent."""
        conn = db.connect()
        try:
            self.engagement_id = db._active_engagement_id(conn)
            _set(conn, "acp:engagement", str(self.engagement_id or ""))
        finally:
            conn.close()

    def _engagement_for_event(self, conn) -> int | None:
        """The engagement to stamp on an event, or None if the pin is dangling.

        A deleted pinned engagement used to be stamped anyway, so the session's
        events landed in an id no view, export or query returns — they were not
        lost, they were invisible, which is worse. Falling back to the operator's
        active engagement would be worse still (that is the split-brain the pin
        exists to prevent), so stamp NULL and say so: an unattributed event is at
        least findable."""
        eid = self.engagement_id
        if eid is None:
            return None
        if db.row(conn, "SELECT id FROM engagements WHERE id=?", (eid,)):
            return eid
        if not getattr(self, "_warned_dangling", False):
            self._warned_dangling = True
            print(f"[acp] pinned engagement {eid} no longer exists — events will be "
                  f"recorded unattributed until the session rebinds",
                  file=sys.stderr, flush=True)
        return None

    async def _ensure_session(self) -> None:
        # Bind ONCE, when this session first comes up — not on every ensure.
        # Re-deriving it here made the "pin" follow the operator continuously
        # (observed: acp:engagement moved 32 -> 96 within 2s of a UI switch, even
        # with acp_session_per_engagement=0, where opting out is precisely a
        # request NOT to move). A deliberate rebind still happens in new_session.
        if self.engagement_id is None:
            self._bind_engagement()
        conn = db.connect()
        try:
            saved = db.get_state(conn, "acp:sessionId") or None
        finally:
            conn.close()
        if saved:
            resp = await self.request("session/load", {
                "sessionId": saved, "cwd": self.cwd, "mcpServers": self._mcp_servers()})
            if "error" not in resp:
                self.session_id = saved
                set_status("live", sessionId=saved)
                return
            # load failed (expired / unsupported) -> fall through to a new one
        resp = await self.request("session/new", {
            "cwd": self.cwd, "mcpServers": self._mcp_servers()})
        if "error" in resp:
            err = resp["error"]
            if _looks_like_auth(err):
                raise _AuthError("run `kimi login` on this host, then restart capture")
            raise RuntimeError(f"session/new failed: {err}")
        self.session_id = resp["result"]["sessionId"]
        set_status("live", sessionId=self.session_id)
        conn = db.connect()
        try:
            db.set_state(conn, "acp:sessionId", self.session_id)
        finally:
            conn.close()

    # -- stream translation -> events --------------------------------------

    def _emit(self, kind: str, text: str, source: str = "acp", meta: dict | None = None) -> None:
        text = text.strip("\n") if kind in ("reasoning", "action", "note") else text
        if not text:
            return
        meta = dict(meta or {})
        conn = db.connect()
        try:
            if kind == "output":
                uid = meta.get("uuid") or f"acp:{meta.get('tool_call_id', '')}"
                text, extra = wiretail.store_output(text, uid)
                meta.update(extra)
            target_id = wiretail.ATTRIB.attribute(conn, text)
            # stamp the SESSION's engagement, not the live-active one — so this
            # session's events stay in its engagement even after a switch.
            db.add_event(conn, source, kind, text, target_id=target_id, meta=meta,
                         engagement_id=self._engagement_for_event(conn))
            _set(conn, "acp:last_event_ts", db.now())
            self._last_event_at = time.monotonic()   # feeds the idle deadline
            if source == "acp" and kind == "action":
                try:
                    wiretail.ingest_extracted(conn, text)
                except Exception as e:  # noqa: BLE001
                    print(f"[acp] extractor error: {e!r}", file=sys.stderr, flush=True)
        finally:
            conn.close()

    def _chunk(self, turn: str, kind: str, text: str) -> None:
        cur = self._block.get(turn)
        if cur and cur["kind"] != kind:
            self._flush_block(turn)
        self._block.setdefault(turn, {"kind": kind, "text": ""})["text"] += text

    def _flush_block(self, turn: str) -> None:
        cur = self._block.pop(turn, None)
        if not cur:
            return
        src = "user" if cur["kind"] == "note" else "acp"
        meta = {} if turn == "_" else {"turnId": turn}
        self._emit(cur["kind"], cur["text"], source=src, meta=meta)

    def _flush_all(self) -> None:
        for turn in list(self._block):
            self._flush_block(turn)

    def _turn_key(self, u: dict) -> str:
        return str(u.get("turnId") or self._active_turn or "_")

    def _on_update(self, u: dict) -> None:
        kind = u.get("sessionUpdate") or u.get("type")
        turn = self._turn_key(u)
        if kind == "agent_thought_chunk":
            self._chunk(turn, "reasoning", _collect_text(u.get("content")))
        elif kind == "agent_message_chunk":
            self._chunk(turn, "action", _collect_text(u.get("content")))
        elif kind == "user_message_chunk":
            self._chunk(turn, "note", _collect_text(u.get("content")))
        elif kind in ("tool_call", "tool_call_update"):
            self._on_tool(turn, u)
        # available_commands_update and anything else: ignored

    def _on_tool(self, turn: str, u: dict) -> None:
        call_id = u.get("toolCallId") or u.get("id") or ""
        if not call_id:
            return
        self._flush_block(turn)                 # tool boundary flushes prose
        if turn != "_":
            self._call_turn[call_id] = turn
        tid = self._call_turn.get(call_id) or (turn if turn != "_" else None)
        status = u.get("status")
        raw = u.get("rawInput")
        has_args = isinstance(raw, dict) and bool(raw)
        # the command / action — once per call, when the real args materialise
        # (kimi exposes rawInput only on one late update) or at terminal status.
        if not self._call_emitted.get(call_id) and (has_args or status in ("completed", "failed")):
            self._call_emitted[call_id] = True
            self._emit("action", _tool_command(u), source="acp",
                       meta={"tool_call_id": call_id, "tool": u.get("kind", ""),
                             **({"turnId": tid} if tid else {})})
        # the output — once per call, on completion (rawOutput; content fallback)
        if status in ("completed", "failed") and call_id not in self._out_emitted:
            out = u.get("rawOutput")
            if not isinstance(out, str) or not out:
                out = _collect_text(u.get("content"))
            if out:
                self._out_emitted.add(call_id)
                self._emit("output", out, source="acp",
                           meta={"tool_call_id": call_id, "isError": status == "failed",
                                 "uuid": f"acp-result:{call_id}",
                                 **({"turnId": tid} if tid else {})})

    # -- permissions --------------------------------------------------------

    async def _on_permission(self, rid, params: dict) -> None:
        self._flush_all()
        tc = params.get("toolCall") or {}
        options = params.get("options") or []
        pid = str(rid)
        rec = {"id": pid, "rid": rid, "toolCall": tc, "options": options, "ts": db.now()}
        with self._perms_lock:
            self._perms[pid] = rec
        title = tc.get("title") or tc.get("kind") or "tool"
        turn_meta = {"turnId": self._active_turn} if self._active_turn else {}
        self._emit("note", f"permission requested: {_tool_command(tc)}", source="acp",
                   meta={"kind": "permission", "permission_id": pid, "tool": title,
                         "options": [o.get("name") for o in options], **turn_meta})
        # MCP-only lockdown: the agent runs EVERY tool through RedOps. A non-MCP tool
        # request (Bash, web fetch, cron, …) is denied so it can't shell out, curl the
        # control API, or bypass scope/capture. Shell commands go through the `run`
        # MCP tool instead (scope-checked + captured).
        if self._mcp_only_now() and not _is_mcp_call(tc):
            deny = _deny_option(options)
            await self._answer(pid, deny["optionId"] if deny else None, auto=True)
            self._emit("note",
                       f"DENIED (MCP-only mode): {title} is blocked — run every tool through "
                       f"RedOps. For a shell command use the redops `run` tool; there are MCP "
                       f"tools for scans, facts, creds, files and more.", source="acp",
                       meta={"kind": "permission_denied", "tool": title, **turn_meta})
            return
        if self._autoapprove_now():
            pick = _allow_option(options)
            await self._answer(pid, pick["optionId"] if pick else None, auto=True)

    def _autoapprove_now(self) -> bool:
        # live: a Settings toggle (DB) overrides the launch env default.
        conn = db.connect()
        try:
            r = conn.execute("SELECT value FROM wiretail_state WHERE key='set:acp_autoapprove'").fetchone()
            if r is not None:
                return r[0].strip().lower() in ("1", "true", "yes", "on")
        finally:
            conn.close()
        return self.autoapprove

    def _mcp_only_now(self) -> bool:
        # live Settings toggle (DB) overrides the launch env default. When on, only
        # mcp__* tool calls are allowed; everything else is denied.
        conn = db.connect()
        try:
            r = conn.execute("SELECT value FROM wiretail_state WHERE key='set:acp_mcp_only'").fetchone()
            if r is not None:
                return r[0].strip().lower() in ("1", "true", "yes", "on")
        finally:
            conn.close()
        return os.environ.get("REDOPS_ACP_MCP_ONLY", "0") == "1"

    async def _answer(self, pid: str, option_id, auto: bool = False) -> bool:
        with self._perms_lock:
            rec = self._perms.pop(pid, None)
        if not rec:
            return False
        outcome = ({"outcome": "selected", "optionId": option_id} if option_id
                   else {"outcome": "cancelled"})
        await self.respond(rec["rid"], {"outcome": outcome})
        tc = rec["toolCall"]
        name = next((o.get("name") for o in rec["options"]
                     if o.get("optionId") == option_id), option_id or "cancelled")
        who = "auto-approved" if auto else "operator decided"
        turn_meta = {"turnId": self._active_turn} if self._active_turn else {}
        self._emit("note",
                   f"permission {who}: {tc.get('title') or tc.get('kind') or 'tool'} -> {name}",
                   source="acp",
                   meta={"kind": "permission_decision", "permission_id": pid,
                         "optionId": option_id, "auto": auto, **turn_meta})
        return True

    # -- fs/* (we advertised the capability, so we service it) --------------

    async def _on_fs_read(self, rid, params: dict) -> None:
        path = params.get("path", "")
        try:
            text = Path(path).read_text(errors="replace")
            line = params.get("line")
            limit = params.get("limit")
            if line or limit:
                lines = text.splitlines()
                start = max(0, (line or 1) - 1)
                text = "\n".join(lines[start:start + limit] if limit else lines[start:])
            await self.respond(rid, {"content": text})
            self._emit("action", f"fs read {path}", source="acp", meta={"fs": "read"})
        except Exception as e:  # noqa: BLE001
            await self.respond(rid, error={"code": -32000, "message": str(e)})

    async def _on_fs_write(self, rid, params: dict) -> None:
        path = params.get("path", "")
        content = params.get("content", "")
        try:
            Path(path).write_text(content, errors="replace")
            await self.respond(rid, {})
            self._emit("action", f"fs write {path} ({len(content)} bytes)",
                       source="acp", meta={"fs": "write"})
        except Exception as e:  # noqa: BLE001
            await self.respond(rid, error={"code": -32000, "message": str(e)})

    # -- turn driving -------------------------------------------------------

    async def _prompt(self, text: str) -> None:
        if not self.session_id:
            raise RuntimeError("no ACP session")
        self._turn_seq += 1
        self._active_turn = f"t{self._turn_seq}"
        # record the running turn's prompt so the operator can SEE what's executing
        # and why (incl. prompts a cron injected — they run through here too).
        conn = db.connect()
        try:
            db.set_state(conn, "acp:activeTurn", self._active_turn)
            db.set_state(conn, "acp:activePrompt", text[:600])
            db.set_state(conn, "acp:activeSince", db.now())
            conn.commit()
        finally:
            conn.close()
        # kimi does not echo the operator prompt; emit it so the turn has a
        # prompt line (source=user note attaches to the following turn).
        self._emit("note", text, source="user")
        try:
            resp = await self.request("session/prompt", {
                "sessionId": self.session_id,
                "prompt": [{"type": "text", "text": text}]},
                timeout=PROMPT_IDLE_TIMEOUT, idle=True)
        finally:
            self._flush_all()
            self._active_turn = None
            conn = db.connect()
            try:
                for k in ("acp:activeTurn", "acp:activePrompt", "acp:activeSince"):
                    db.set_state(conn, k, "")
                conn.commit()
            finally:
                conn.close()
        if "error" in resp:
            self._emit("note", f"prompt failed: {resp['error']}", source="acp",
                       meta={"kind": "error"})

    async def _cancel(self) -> None:
        if self.session_id:
            await self._send({"jsonrpc": "2.0", "method": "session/cancel",
                              "params": {"sessionId": self.session_id}})

    # -- sync bridge for FastAPI handlers -----------------------------------

    def _run(self, coro, wait: bool = False, timeout: float = 10.0):
        if not self._loop or not self._loop.is_running():
            raise RuntimeError("ACP loop not running")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        if wait:
            return fut.result(timeout=timeout)
        return None

    async def _new_session(self) -> None:
        """Discard the resumed conversation and start a clean agent session, so a
        new engagement (or a plain 'hello') doesn't land on an agent still mid-
        mission from the reloaded history. CANCEL the in-flight turn first — an
        agent mid-mission on the old engagement must be stopped, or its remaining
        tool calls keep writing (into whatever engagement is now active)."""
        await self._cancel()
        self._flush_all()
        self._active_turn = None
        resp = await self.request("session/new",
                                  {"cwd": self.cwd, "mcpServers": self._mcp_servers()})
        if "error" in resp:
            self._emit("note", f"new session failed: {resp['error']}", source="acp")
            return
        self.session_id = resp["result"]["sessionId"]
        self._bind_engagement()   # this session now belongs to the active engagement
        set_status("live", sessionId=self.session_id)
        conn = db.connect()
        try:
            db.set_state(conn, "acp:sessionId", self.session_id)
        finally:
            conn.close()
        self._emit("note", "started a fresh agent session — prior conversation history cleared",
                   source="acp")

    def submit_prompt(self, text: str) -> None:
        if not self.session_id:
            raise RuntimeError("ACP session not ready (check capture health)")
        self._run(self._prompt(text), wait=False)

    def new_session(self) -> str | None:
        self._run(self._new_session(), wait=True, timeout=20.0)
        return self.session_id

    def answer_permission(self, pid: str, option_id) -> bool:
        return bool(self._run(self._answer(pid, option_id), wait=True))

    def cancel(self) -> None:
        self._run(self._cancel(), wait=False)

    def pending_permissions(self) -> list[dict]:
        with self._perms_lock:
            return [dict(r) for r in self._perms.values()]


class _AuthError(Exception):
    pass


def _looks_like_auth(err) -> bool:
    blob = json.dumps(err).lower() if not isinstance(err, str) else err.lower()
    return any(w in blob for w in ("auth", "login", "unauthor", "credential", "token"))


def _is_mcp_call(tc: dict) -> bool:
    """True if this tool call is an MCP tool (mcp__…). Everything else — Bash/exec,
    web fetch, cron, todo, the model's own built-ins — is non-MCP and, in lockdown
    mode, denied so the agent can't bypass RedOps."""
    for k in ("title", "kind", "name", "toolName"):
        v = str(tc.get(k) or "").lower()
        if "mcp__" in v or v.startswith("mcp_"):
            return True
    return False


def _deny_option(options: list[dict]) -> dict | None:
    """Pick an explicit reject/deny option; None -> answer cancels (still denies)."""
    for o in options:
        blob = (str(o.get("kind", "")) + " " + str(o.get("name", ""))).lower()
        if "reject" in blob or "deny" in blob or "disallow" in blob or "no" == blob.strip():
            return o
    return None


def _allow_option(options: list[dict]) -> dict | None:
    """Pick the least-privileged 'allow' option (prefer once over session)."""
    def score(o):
        blob = (str(o.get("kind", "")) + " " + str(o.get("name", ""))).lower()
        if "allow" not in blob and "approve" not in blob:
            return -1
        return 1 if "once" in blob else 0
    ranked = sorted(options, key=score, reverse=True)
    return ranked[0] if ranked and score(ranked[0]) >= 0 else (options[0] if options else None)


# ---------------------------------------------------------------------------
# module singleton

_SESSION: AcpSession | None = None


def start() -> AcpSession:
    global _SESSION
    if _SESSION is None:
        _SESSION = AcpSession()
        _SESSION.start()
    return _SESSION


def session() -> AcpSession | None:
    return _SESSION
