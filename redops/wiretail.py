"""Passive ingestion of kimi-code session wire files into RedOps events.

Follows the newest wire.jsonl under ~/.kimi-code/sessions/**/agents/*/wire.jsonl
(override with REDOPS_WIRE). Persists per-file (inode, offset) so restarts
resume where they left off; a changed inode restarts from offset 0.
"""

import glob
import hashlib
import json
import os
import re
import sys
import threading
import time
from collections import deque
from pathlib import Path

from . import db

SESSIONS_GLOB = os.path.expanduser("~/.kimi-code/sessions/**/agents/*/wire.jsonl")
POLL_INTERVAL = 1.0
RESOLVE_INTERVAL = 15.0
# Zero truncation: content (reasoning/action/output/notes) is never cut. Large
# outputs still get a durable file copy at this size, but the full text stays
# inline too (see store_output).
OVERFLOW_THRESHOLD = 4000   # outputs longer than this ALSO get a data/transcript/ copy
STUCK_AFTER = 30.0          # seconds of "size grows, offset stuck" -> stale-read
ATTR_REFRESH = 30.0


def newest_wire() -> str | None:
    override = os.environ.get("REDOPS_WIRE")
    if override:
        return override if os.path.exists(override) else None
    files = glob.glob(SESSIONS_GLOB, recursive=True)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def _safe_name(uid: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", uid)


def store_output(text: str, uid: str) -> tuple[str, dict]:
    """Zero truncation: the FULL text is always kept inline. Large outputs also
    get a durable file copy under data/transcript/ (a bonus artifact for the
    report / a direct download link), but nothing shown to the user is ever cut.

    Returns (event_text, meta_additions).
    """
    if len(text) <= OVERFLOW_THRESHOLD:
        return text, {}
    fname = _safe_name(uid) + ".txt"
    db.TRANSCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    (db.TRANSCRIPT_DIR / fname).write_text(text, errors="replace")
    return text, {"overflow": fname, "full_len": len(text)}


class Attributor:
    """Cheap target attribution: explicit pointer first, IP-in-text heuristic second."""

    def __init__(self):
        self.eng: int | None = None
        self.pointer: int | None = None
        self.ip_to_id: dict[str, int] = {}
        self.last_refresh = 0.0

    def refresh(self, conn, force: bool = False) -> None:
        # Track the ACTIVE engagement (matches db.add_event's scoping), and
        # rebuild IMMEDIATELY when it changes. Otherwise a stale focus pointer
        # from the previous engagement mis-attributes the new engagement's first
        # events onto the OLD one — they never appear in the fresh feed until the
        # 30s cache expires (the "first message doesn't show" bug).
        active = db._active_engagement_id(conn)
        if active != self.eng:
            force = True
        if not force and time.time() - self.last_refresh < ATTR_REFRESH:
            return
        self.last_refresh = time.time()
        self.eng = active
        self.pointer = None
        self.ip_to_id = {}
        if self.eng is not None:
            v = db.get_state(conn, f"current_target:{self.eng}")
            self.pointer = int(v) if v and v != "null" else None
            for t in db.rows(conn, "SELECT id, ip FROM targets WHERE engagement_id=?", (self.eng,)):
                self.ip_to_id[t["ip"]] = t["id"]

    def attribute(self, conn, text: str) -> int | None:
        self.refresh(conn)
        if self.pointer is not None:
            return self.pointer
        for ip, tid in self.ip_to_id.items():
            if ip in text:
                return tid
        return None


ATTRIB = Attributor()


def _tool_summary(event: dict) -> str:
    name = event.get("name", "?")
    args = event.get("args")
    # Exec-style tools (Bash, etc.): store the raw command verbatim and in
    # full, so the per-box report is copy/paste-runnable. Non-shell tools keep
    # the name(args) summary form.
    if isinstance(args, dict) and isinstance(args.get("command"), str):
        return args["command"]
    try:
        argstr = json.dumps(args, ensure_ascii=False) if args else ""
    except (TypeError, ValueError):
        argstr = str(args)
    return f"{name}({argstr})"


def _msg_uid(o: dict, text: str) -> str:
    raw = f"{o.get('time')}:{text}"
    return "msg:" + hashlib.sha1(raw.encode()).hexdigest()[:16]


def normalize(o: dict) -> list[dict]:
    """Turn one wire JSONL line into zero or more event dicts."""
    out = []
    t = o.get("type")
    if t == "context.append_loop_event":
        e = o.get("event") or {}
        et = e.get("type")
        uid = e.get("uuid")
        if et == "content.part":
            part = e.get("part") or {}
            meta = {"turnId": e.get("turnId")} if e.get("turnId") else {}
            if part.get("type") == "think" and part.get("think"):
                out.append({"source": "wire", "kind": "reasoning",
                            "text": part["think"], "uid": uid, "meta": meta})
            elif part.get("type") == "text" and part.get("text"):
                out.append({"source": "wire", "kind": "action",
                            "text": part["text"], "uid": uid, "meta": meta})
        elif et == "tool.call":
            meta = {"tool": e.get("name", "")}
            if e.get("turnId"):
                meta["turnId"] = e["turnId"]
            out.append({"source": "wire", "kind": "action",
                        "text": _tool_summary(e), "uid": uid, "meta": meta})
        elif et == "tool.result":
            result = e.get("result") or {}
            output = result.get("output")
            if output is None or output == "":
                return out
            if not isinstance(output, str):
                try:
                    output = json.dumps(output, ensure_ascii=False)
                except (TypeError, ValueError):
                    output = str(output)
            call_id = e.get("toolCallId") or e.get("parentUuid") or ""
            out.append({"source": "wire", "kind": "output",
                        "text": output, "uid": f"result:{call_id}" if call_id else None,
                        "meta": {"tool_call_id": call_id,
                                 "isError": bool(result.get("isError"))}})
    elif t == "context.append_message":
        m = o.get("message") or {}
        origin = (m.get("origin") or {}).get("kind", "user")
        if m.get("role") == "user" and origin == "user":
            texts = [c.get("text", "") for c in (m.get("content") or [])
                     if isinstance(c, dict) and c.get("type") == "text"]
            text = "\n".join(x for x in texts if x and not x.startswith("<system"))
            if text.strip():
                out.append({"source": "user", "kind": "note",
                            "text": text.strip(), "uid": _msg_uid(o, text)})
    return out


# ---------------------------------------------------------------------------
# conservative auto-extractors: wire action text -> low-confidence facts.
# High-precision patterns only; skip on ambiguity.

NMAP_HOST_RE = re.compile(r"Nmap scan report for ([\w.-]+)")
NMAP_SVC_RE = re.compile(r"(\d+)/tcp\s+open\s+(\S+)")
URL_PORT_RE = re.compile(r"https?://[\w.-]+:\d+(?:/[\w./?=&%-]*)?")
RUNS_AS_RE = re.compile(
    r"([\w./-]+)\s+(?:ran as|running as|executes as|runs as)\s+"
    r"(root|admin|administrator|system|nt authority\\system)", re.I)
ETC_HOSTS_LINE_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([\w.-]+)\s*$", re.M)
WRITABLE_RE = re.compile(r"(?:writable|we can write(?: to)?|write access to)\s*[:\-]?\s*([\w./\\:-]{3,})", re.I)
NOAUTH_RE = re.compile(r"([\w./:-]{3,})\s+(?:is |has )?(?:no auth|unauthenticated|without authentication)\b", re.I)
CRASH_RE = re.compile(r"([\w./-]{3,})\s+(crashes|respawns)\b", re.I)
HARDCODED_CRED_RE = re.compile(r"(?:hardcoded|leaked|embedded)\s+(?:password|credential|secret|api[_-]?key)\s+(?:in|inside|from)\s+([\w./-]{3,})", re.I)
READ_BY_RE = re.compile(r"([\w ./-]{3,}?)\s+is read by\s+([\w./-]{3,})", re.I)
INGESTS_RE = re.compile(r"([\w./-]{3,})\s+ingests\s+([\w ./-]{3,})", re.I)
HAS_TOOL_RE = re.compile(r"([\w./-]{3,})\s+(?:has tool|exposes tool|can call)\s+([\w./-]{3,})", re.I)


# Precision gate: the extractors are deliberately greedy, so they also grab
# regex debris (bare words, fragments) and RedOps' own traffic. A fact whose
# SUBJECT is not a plausible entity is dropped before it ever reaches the store
# or the correlation engine — greedy capture of well-formed facts, not garbage.
_REDOPS_PORT = os.environ.get("REDOPS_PORT", "9100")
REDOPS_SELF_RE = re.compile(rf"(?:127\.0\.0\.1|localhost):{re.escape(_REDOPS_PORT)}\b")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# common English/verb fragments the regexes capture that are never entities
_STOP_SUBJECTS = {
    "by", "us", "to", "the", "a", "an", "and", "or", "it", "is", "as", "with",
    "in", "from", "on", "at", "of", "no", "auth", "tool", "secret", "credential",
    "password", "file", "service", "config", "binary", "key", "api", "url",
    "data", "user", "root", "admin", "system", "path", "crashes", "respawns",
    "accepts", "ingests", "writable", "unauthenticated", "primitive", "restart",
}


def _clean_subject(name: str) -> str:
    return (name or "").strip().strip("/\\-:.,;\"'() \t").strip()


def _valid_subject(name: str) -> bool:
    """Reject regex debris and RedOps' own endpoints; keep real entities."""
    if REDOPS_SELF_RE.search(name or ""):
        return False
    n = _clean_subject(name)
    if len(n) < 3:
        return False
    if _IP_RE.search(n):                       # IPs / host:port are always real
        return True
    segs = [s for s in re.split(r"[\s/\\:.,\-]+", n.lower()) if s]
    # a real entity has at least one meaningful segment (>=3 chars, not a stopword)
    return any(len(s) >= 3 and s not in _STOP_SUBJECTS for s in segs)


def extract_facts(text: str) -> list[dict]:
    """Extract candidate facts from a wire action text.

    Returns dicts: {subject_name, subject_type, predicate,
                    object_name?, object_type?, object_text?}
    Facts with implausible subjects (regex debris, RedOps' own traffic) are
    dropped by the precision gate before returning.
    """
    out = []

    # NO prose scraping. Regex-extracting facts from the agent's natural language
    # produces garbage subjects ("requires no-auth unauthenticated" — 'requires'
    # is not an entity). Facts now come from structured sources with real
    # subjects: the tool runner (parsed nmap), the agent's own fact_add over MCP,
    # and the analyst pass. The only text extractor kept is the deterministic
    # /etc/hosts parser (a real file format, not prose).

    # /etc/hosts edits: only when the text references /etc/hosts
    if "/etc/hosts" in text:
        for ip, hostname in ETC_HOSTS_LINE_RE.findall(text):
            out.append({"subject_name": hostname, "subject_type": "host",
                        "predicate": "resolves-to", "object_name": ip, "object_type": "host"})
    return [f for f in out if _valid_subject(f["subject_name"])]


def ingest_extracted(conn, text: str) -> int:
    """Insert extracted facts (stage=observed — seen on the wire, source=wire-auto).
    Returns count."""
    try:
        eng = db._active_engagement_id(conn)   # active-first, matches event scoping
    except Exception:
        eng = None
    if not eng:
        return 0
    n = 0
    for f in extract_facts(text):
        sid = db.upsert_entity(conn, eng, f["subject_type"], f["subject_name"])
        oid = db.upsert_entity(conn, eng, f["object_type"], f["object_name"]) if f.get("object_name") else None
        db.add_fact(conn, eng, sid, f["predicate"], oid, f.get("object_text", ""),
                    "observed", "wire-auto")
        n += 1
    if n:
        from . import correlate
        correlate.run(conn, eng)
    return n


class WireTailer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="wiretail")
        self.path: str | None = None
        self.offset = 0
        self.inode: int | None = None
        self.seen: set[str] = set()
        self.last_resolve = 0.0
        # health tracking
        self.line_window: deque[bool] = deque(maxlen=100)  # True = parse/processing error
        self.stuck_since: float | None = None
        self.unreadable = False
        self.call_turns: dict[str, str] = {}  # tool call uuid -> turnId

    def _record_error(self, conn, msg: str) -> None:
        print(f"[wiretail] {msg}", file=sys.stderr, flush=True)
        n = int(db.get_state(conn, "wire:parse_errors", "0") or 0) + 1
        db.set_state(conn, "wire:parse_errors", str(n))

    def _load_state(self, conn, path: str) -> None:
        try:
            inode = os.stat(path).st_ino
        except OSError:
            self.offset, self.inode = 0, None
            return
        saved_inode = db.get_state(conn, f"inode:{path}")
        if saved_inode and int(saved_inode) == inode:
            self.offset = int(db.get_state(conn, f"offset:{path}", "0"))
        else:
            self.offset = 0
        self.inode = inode

    def _save_state(self, conn) -> None:
        if self.path and self.inode is not None:
            db.set_state(conn, f"inode:{self.path}", str(self.inode))
            db.set_state(conn, f"offset:{self.path}", str(self.offset))

    def _switch(self, conn, path: str | None) -> None:
        if path == self.path:
            return
        if self.path:
            self._save_state(conn)
        self.path = path
        self.stuck_since = None
        self.unreadable = False
        if path:
            self._load_state(conn, path)
            db.add_event(conn, "wire", "note", f"wiretail: now following {path}",
                         meta={"kind": "wiretail"})
        db.set_state(conn, "wire:path", path or "")

    def _ingest_event(self, conn, ev: dict) -> None:
        uid = ev.get("uid")
        if uid and uid in self.seen:
            return
        if uid:
            self.seen.add(uid)
        meta = dict(ev.get("meta") or {})
        # track turnId per tool call; stamp it onto the paired tool.result
        if ev["kind"] == "action" and uid and str(uid).startswith("tool_") and meta.get("turnId"):
            self.call_turns[uid] = meta["turnId"]
        if ev["kind"] == "output" and "turnId" not in meta:
            tid = self.call_turns.get(meta.get("tool_call_id", ""))
            if tid:
                meta["turnId"] = tid
        text = ev["text"]
        if ev["kind"] == "output" and uid:
            text, extra = store_output(text, uid)
            meta.update(extra)
        if uid:
            meta.setdefault("uuid", uid)
        target_id = ATTRIB.attribute(conn, text)
        db.add_event(conn, ev["source"], ev["kind"], text, target_id=target_id, meta=meta)
        if ev["source"] == "wire" and ev["kind"] == "action":
            try:
                ingest_extracted(conn, text)
            except Exception as e:
                self._record_error(conn, f"extractor error: {e!r}")

    def _process_new_data(self, conn) -> None:
        if not self.path:
            return
        try:
            st = os.stat(self.path)
        except OSError as e:
            self.unreadable = True
            self._record_error(conn, f"cannot stat {self.path}: {e}")
            return
        self.unreadable = False
        if st.st_ino != self.inode or st.st_size < self.offset:
            # rotated or truncated: start over
            self.offset = 0
            self.inode = st.st_ino
        if st.st_size == self.offset:
            self.stuck_since = None
            return
        try:
            with open(self.path, "r", errors="replace") as f:
                f.seek(self.offset)
                data = f.read()
                new_offset = f.tell()
        except OSError as e:
            self.unreadable = True
            self._record_error(conn, f"cannot read {self.path}: {e}")
            return
        if new_offset == self.offset:
            # size grows but we cannot advance -> stuck
            if self.stuck_since is None:
                self.stuck_since = time.time()
            return
        self.offset = new_offset
        self.stuck_since = None
        db.set_state(conn, "wire:last_read_ts", db.now())
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                self.line_window.append(True)
                self._record_error(conn, f"JSON decode failure on line: {line[:120]!r}")
                continue
            try:
                events = normalize(o)
            except Exception as e:
                self.line_window.append(True)
                self._record_error(conn, f"normalize error: {e!r}")
                continue
            self.line_window.append(False)
            for ev in events:
                self._ingest_event(conn, ev)
        self._save_state(conn)

    def _health_status(self) -> str:
        if not self.path or not os.path.exists(self.path):
            return "no-file"
        if sum(self.line_window) > 10:
            return "parse-errors"
        if self.unreadable:
            return "stale-read"
        if self.stuck_since is not None and time.time() - self.stuck_since > STUCK_AFTER:
            return "stale-read"
        return "ok"

    def run(self) -> None:
        while True:
            try:
                conn = db.connect()
                try:
                    if time.time() - self.last_resolve > RESOLVE_INTERVAL:
                        self.last_resolve = time.time()
                        self._switch(conn, newest_wire())
                    self._process_new_data(conn)
                    db.set_state(conn, "wire:path", self.path or "")
                    db.set_state(conn, "wire:status", self._health_status())
                finally:
                    conn.close()
            except Exception as e:
                print(f"[wiretail] loop error: {e!r}", file=sys.stderr, flush=True)
            time.sleep(POLL_INTERVAL)


class TranscriptTailer(threading.Thread):
    """Tails registered flat text files (vendor-neutral ground-truth logs)
    into events with source=transcript. Offsets persist in wiretail_state."""

    POLL = 2.0

    def __init__(self):
        super().__init__(daemon=True, name="transcriptail")
        self.offsets: dict[str, int] = {}
        self.seen: set[str] = set()

    def _sources(self, conn) -> list[str]:
        return [r["key"][len("tsource:"):] for r in
                db.rows(conn, "SELECT key FROM wiretail_state WHERE key LIKE 'tsource:%'")]

    def _tail(self, conn, path: str) -> None:
        try:
            st = os.stat(path)
        except OSError as e:
            print(f"[transcriptail] cannot stat {path}: {e}", file=sys.stderr, flush=True)
            return
        off_key, ino_key = f"toffset:{path}", f"tinode:{path}"
        saved_ino = db.get_state(conn, ino_key)
        offset = self.offsets.get(path)
        if offset is None:
            if saved_ino and int(saved_ino) == st.st_ino:
                offset = int(db.get_state(conn, off_key, "0"))
            else:
                offset = 0  # new file (or rotated): start at the beginning
        if st.st_size < offset:
            offset = 0  # truncated
        if st.st_size == offset:
            self.offsets[path] = offset
            return
        try:
            with open(path, "r", errors="replace") as f:
                f.seek(offset)
                data = f.read()
                new_offset = f.tell()
        except OSError as e:
            print(f"[transcriptail] cannot read {path}: {e}", file=sys.stderr, flush=True)
            return
        base = os.path.basename(path)
        pos = offset
        for line in data.splitlines(keepends=True):
            text = line.rstrip("\r\n")
            line_start = pos
            pos += len(line.encode("utf-8", errors="replace"))
            if not text.strip():
                continue
            uid = f"transcript:{base}:{line_start}"
            if uid in self.seen:
                continue
            self.seen.add(uid)
            ev_text, extra = store_output(text, uid)
            meta = {"uuid": uid, **extra}
            target_id = ATTRIB.attribute(conn, text)
            db.add_event(conn, "transcript", "output", ev_text, target_id=target_id, meta=meta)
        self.offsets[path] = new_offset
        db.set_state(conn, off_key, str(new_offset))
        db.set_state(conn, ino_key, str(st.st_ino))

    def run(self) -> None:
        while True:
            try:
                conn = db.connect()
                try:
                    ATTRIB.refresh(conn)
                    for path in self._sources(conn):
                        self._tail(conn, path)
                finally:
                    conn.close()
            except Exception as e:
                print(f"[transcriptail] loop error: {e!r}", file=sys.stderr, flush=True)
            time.sleep(self.POLL)


def start() -> tuple[WireTailer, TranscriptTailer]:
    t = WireTailer()
    t.start()
    tt = TranscriptTailer()
    tt.start()
    return t, tt
