"""Append-only correlation ledger and rebuildable projections for one report.py case.

Design rules (see ../REPORT-Multi-Agent-Case-System-Plan.md):
- case.json is evidence truth; it is only ever read here (`sync_evidence`).
- `records` is append-only. Corrections are new records that cite earlier ones.
- Projection tables (entities, edges, claims, tasks, ...) are derived from records
  and can be rebuilt from scratch with `rebuild()`.
- Nothing here stores a raw secret value: secrets are referenced by label and
  SHA-256 fingerprint; the exact value stays in the report.py evidence if captured.
- Every write names an actor. An idempotency key makes retried writes no-ops.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1

ENTITY_TYPES = ("host", "service", "application", "identity", "secret_ref", "credential",
                "auth_test", "network_path", "session", "file", "ai_surface", "finding",
                "objective", "other")
EVIDENCE_LEVELS = ("captured", "proposed", "observed", "verified", "ruled_out")
APPLICABILITY = ("current", "stale", "revoked", "unknown")
EDGE_STATUS = ("observed", "inferred", "verified", "conflicting", "revoked")
CLAIM_STATES = ("hypothesis", "observed", "verified", "ruled_out")
TASK_STATES = ("queued", "running", "waiting_on_target", "waiting_on_operator", "blocked",
               "in_review", "done", "cancelled")

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- Append-only ledger. seq is the authoritative order.
CREATE TABLE IF NOT EXISTS records (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  actor TEXT NOT NULL,
  task_id TEXT,
  epoch_id TEXT,
  idempotency_key TEXT UNIQUE,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS records_kind ON records(kind, seq);

-- Read-only mirror of case.json events (synced, never authored here).
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  ord INTEGER NOT NULL,
  at TEXT NOT NULL,
  target TEXT,
  stage TEXT,
  kind TEXT NOT NULL,
  actor TEXT,
  status TEXT,
  summary TEXT NOT NULL,
  file TEXT,
  sha256 TEXT,
  payload TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5(id UNINDEXED, body);

-- Projections (rebuildable).
CREATE TABLE IF NOT EXISTS epochs (
  id TEXT PRIMARY KEY, started_at TEXT NOT NULL, ended_at TEXT, reason TEXT NOT NULL,
  label TEXT NOT NULL, fingerprint TEXT, current INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, key TEXT NOT NULL, epoch_id TEXT,
  label TEXT NOT NULL, attrs TEXT NOT NULL, level TEXT NOT NULL, applicability TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, source_events TEXT NOT NULL,
  source_records TEXT NOT NULL, actor TEXT NOT NULL, target TEXT,
  UNIQUE(type, key, epoch_id)
);
CREATE INDEX IF NOT EXISTS entities_type ON entities(type, label);
CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY, entity_id TEXT NOT NULL, at TEXT NOT NULL, actor TEXT NOT NULL,
  statement TEXT NOT NULL, attrs TEXT NOT NULL, source_events TEXT NOT NULL,
  source_span TEXT, extractor TEXT, confidence REAL, level TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS observations_entity ON observations(entity_id, at);
CREATE TABLE IF NOT EXISTS edges (
  id TEXT PRIMARY KEY, src TEXT NOT NULL, dst TEXT NOT NULL, relation TEXT NOT NULL,
  status TEXT NOT NULL, at TEXT NOT NULL, actor TEXT NOT NULL, source_events TEXT NOT NULL,
  explanation TEXT, UNIQUE(src, dst, relation)
);
CREATE TABLE IF NOT EXISTS claims (
  id TEXT PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, target TEXT, statement TEXT NOT NULL,
  state TEXT NOT NULL, entity_ids TEXT NOT NULL, supporting_events TEXT NOT NULL,
  contrary_events TEXT NOT NULL, impact TEXT, reviewer TEXT, review_reason TEXT, reviewed_at TEXT,
  task_id TEXT, conflicts_with TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, creator TEXT NOT NULL,
  owner TEXT, target TEXT, objective TEXT NOT NULL, deliverable TEXT, state TEXT NOT NULL,
  reason TEXT, depends_on TEXT NOT NULL, context TEXT NOT NULL, lease TEXT, result TEXT,
  checkpoints TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS handoffs (
  id TEXT PRIMARY KEY, at TEXT NOT NULL, from_actor TEXT NOT NULL, to_actor TEXT,
  task_id TEXT, packet TEXT NOT NULL, acknowledged_by TEXT, acknowledged_at TEXT
);
CREATE TABLE IF NOT EXISTS heartbeats (
  actor TEXT PRIMARY KEY, at TEXT NOT NULL, task_id TEXT, note TEXT NOT NULL, provider TEXT
);
CREATE TABLE IF NOT EXISTS leases (
  resource TEXT PRIMARY KEY, owner TEXT NOT NULL, task_id TEXT, acquired_at TEXT NOT NULL,
  expires_at TEXT NOT NULL, note TEXT
);
CREATE TABLE IF NOT EXISTS decisions (
  id TEXT PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL,
  question TEXT NOT NULL, state TEXT NOT NULL, answer TEXT, answered_by TEXT, answered_at TEXT,
  context TEXT NOT NULL
);
"""


class CaseHubError(Exception):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ident(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _j(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _l(value: str | None) -> Any:
    return json.loads(value) if value else None


def normalize_key(entity_type: str, key: str) -> str:
    key = key.strip()
    if entity_type in ("host", "service", "identity", "file", "application", "ai_surface"):
        key = key.lower()
    return key


class CaseHub:
    """One correlation ledger for one report.py case directory."""

    def __init__(self, root: Path | str, actor: str | None = None):
        if not root:
            raise CaseHubError("No case given; pass the case directory or set REPORT_CASE")
        self.root = Path(root).resolve()
        if not (self.root / "case.json").is_file():
            raise CaseHubError(f"No report.py case at {self.root}")
        self.actor = actor or os.environ.get("REPORT_ACTOR") or "operator"
        self.db_path = self.root / "casehub.db"
        self.db = sqlite3.connect(self.db_path, isolation_level=None, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        self.db.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                        (str(SCHEMA_VERSION),))
        if not self.current_epoch():
            self._ensure_default_epoch()

    # ------------------------------------------------------------------ basics
    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "CaseHub":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def case(self) -> dict:
        return json.loads((self.root / "case.json").read_text(encoding="utf-8"))

    def _tx(self):
        return _Transaction(self.db)

    # ----------------------------------------------------------------- records
    def append(self, kind: str, payload: dict, actor: str | None = None, task_id: str | None = None,
               idempotency_key: str | None = None, epoch_id: str | None = None,
               at: str | None = None) -> str:
        """Append one record and apply it to projections, atomically. Returns record id."""
        actor = actor or self.actor
        with self._tx():
            if idempotency_key:
                row = self.db.execute("SELECT id FROM records WHERE idempotency_key=?",
                                      (idempotency_key,)).fetchone()
                if row:
                    return row["id"]
            rid = ident("rec_")
            at = at or now()
            epoch_id = epoch_id or (self.current_epoch() or {}).get("id")
            self.db.execute(
                "INSERT INTO records(id, at, kind, actor, task_id, epoch_id, idempotency_key, payload) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (rid, at, kind, actor, task_id, epoch_id, idempotency_key, _j(payload)))
            self._apply(rid, at, kind, actor, task_id, epoch_id, payload)
            return rid

    def records(self, kind: str | None = None, since_seq: int = 0, limit: int = 500) -> list[dict]:
        sql = "SELECT * FROM records WHERE seq>?"
        args: list[Any] = [since_seq]
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        sql += " ORDER BY seq LIMIT ?"
        args.append(limit)
        return [self._record_row(r) for r in self.db.execute(sql, args)]

    def _record_row(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["payload"] = _l(d["payload"])
        return d

    def rebuild(self) -> int:
        """Drop every projection and replay the record ledger. Returns records replayed."""
        with self._tx():
            for table in ("epochs", "entities", "observations", "edges", "claims", "tasks",
                          "handoffs", "heartbeats", "leases", "decisions"):
                self.db.execute(f"DELETE FROM {table}")
            count = 0
            for r in self.db.execute("SELECT * FROM records ORDER BY seq"):
                self._apply(r["id"], r["at"], r["kind"], r["actor"], r["task_id"], r["epoch_id"],
                            _l(r["payload"]))
                count += 1
            if not self.current_epoch():
                self._ensure_default_epoch()
            return count

    # ------------------------------------------------------------- projection
    def _apply(self, rid: str, at: str, kind: str, actor: str, task_id: str | None,
               epoch_id: str | None, p: dict) -> None:
        handler = getattr(self, f"_apply_{kind}", None)
        if handler is None:
            return  # Unknown kinds stay in the ledger for later schema versions.
        handler(rid, at, actor, task_id, epoch_id, p)

    def _apply_epoch_start(self, rid, at, actor, task_id, epoch_id, p):
        self.db.execute("UPDATE epochs SET current=0, ended_at=COALESCE(ended_at, ?) WHERE current=1", (at,))
        self.db.execute(
            "INSERT OR REPLACE INTO epochs(id, started_at, ended_at, reason, label, fingerprint, current) "
            "VALUES (?,?,?,?,?,?,1)",
            (p["id"], at, None, p.get("reason", ""), p.get("label", p["id"]), p.get("fingerprint")))
        # Everything observed in a previous epoch becomes stale until re-observed.
        self.db.execute("UPDATE entities SET applicability='stale' WHERE epoch_id IS NOT ? AND applicability='current'",
                        (p["id"],))

    def _apply_entity(self, rid, at, actor, task_id, epoch_id, p):
        etype, key = p["type"], normalize_key(p["type"], p["key"])
        row = self.db.execute("SELECT * FROM entities WHERE type=? AND key=? AND epoch_id IS ?",
                              (etype, key, epoch_id)).fetchone()
        attrs = p.get("attrs") or {}
        events = p.get("source_events") or []
        level = p.get("level", "proposed")
        applicability = p.get("applicability", "current")
        if row:
            merged = _l(row["attrs"]) or {}
            merged.update(attrs)
            all_events = sorted(set((_l(row["source_events"]) or []) + events))
            all_records = (_l(row["source_records"]) or []) + [rid]
            # Evidence level only moves up by explicit statement; never silently down.
            if EVIDENCE_LEVELS.index(level) < EVIDENCE_LEVELS.index(row["level"]) and not p.get("force_level"):
                level = row["level"]
            self.db.execute(
                "UPDATE entities SET label=?, attrs=?, level=?, applicability=?, last_seen=?, "
                "source_events=?, source_records=?, target=COALESCE(?, target) WHERE id=?",
                (p.get("label") or row["label"], _j(merged), level, applicability, at,
                 _j(all_events), _j(all_records), p.get("target"), row["id"]))
            eid = row["id"]
        else:
            # Projection IDs must be derived from the record, not generated while
            # replaying it; callers may retain these IDs across a rebuild.
            eid = p.get("id") or "ent_" + rid.removeprefix("rec_")
            self.db.execute(
                "INSERT INTO entities(id, type, key, epoch_id, label, attrs, level, applicability, first_seen, "
                "last_seen, source_events, source_records, actor, target) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (eid, etype, key, epoch_id, p.get("label") or key, _j(attrs), level, applicability, at, at,
                 _j(sorted(set(events))), _j([rid]), actor, p.get("target")))
        if p.get("statement") or p.get("source_span") or p.get("extractor"):
            self.db.execute(
                "INSERT INTO observations(id, entity_id, at, actor, statement, attrs, source_events, source_span, "
                "extractor, confidence, level) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("obs_" + rid.removeprefix("rec_"), eid, at, actor, p.get("statement") or "", _j(attrs), _j(events),
                 _j(p.get("source_span")) if p.get("source_span") else None, p.get("extractor"),
                 p.get("confidence"), level))

    def _apply_edge(self, rid, at, actor, task_id, epoch_id, p):
        self.db.execute(
            "INSERT INTO edges(id, src, dst, relation, status, at, actor, source_events, explanation) "
            "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(src, dst, relation) DO UPDATE SET status=excluded.status, "
            "at=excluded.at, actor=excluded.actor, source_events=excluded.source_events, "
            "explanation=excluded.explanation",
            ("edge_" + rid.removeprefix("rec_"), p["src"], p["dst"], p["relation"], p.get("status", "observed"), at, actor,
             _j(p.get("source_events") or []), p.get("explanation")))

    def _apply_claim(self, rid, at, actor, task_id, epoch_id, p):
        cid = p.get("id") or ident("claim_")
        self.db.execute(
            "INSERT OR REPLACE INTO claims(id, at, actor, target, statement, state, entity_ids, supporting_events, "
            "contrary_events, impact, task_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (cid, at, actor, p.get("target"), p["statement"], p.get("state", "hypothesis"),
             _j(p.get("entity_ids") or []), _j(p.get("supporting_events") or []),
             _j(p.get("contrary_events") or []), p.get("impact"), task_id))
        self._refresh_conflicts(cid)

    def _apply_claim_review(self, rid, at, actor, task_id, epoch_id, p):
        row = self.db.execute("SELECT * FROM claims WHERE id=?", (p["claim_id"],)).fetchone()
        if not row:
            return
        supporting = sorted(set((_l(row["supporting_events"]) or []) + (p.get("supporting_events") or [])))
        contrary = sorted(set((_l(row["contrary_events"]) or []) + (p.get("contrary_events") or [])))
        self.db.execute(
            "UPDATE claims SET state=?, reviewer=?, review_reason=?, reviewed_at=?, supporting_events=?, "
            "contrary_events=?, statement=COALESCE(?, statement) WHERE id=?",
            (p.get("state", row["state"]), actor, p.get("reason", ""), at, _j(supporting), _j(contrary),
             p.get("narrowed_statement"), row["id"]))
        self._refresh_conflicts(row["id"])

    def _refresh_conflicts(self, cid: str) -> None:
        """Two non-ruled-out claims on the same target that cite contrary evidence of each other conflict."""
        row = self.db.execute("SELECT * FROM claims WHERE id=?", (cid,)).fetchone()
        if not row:
            return
        conflicts = []
        mine_support = set(_l(row["supporting_events"]) or [])
        for other in self.db.execute("SELECT * FROM claims WHERE id<>? AND target IS ? AND state<>'ruled_out'",
                                     (cid, row["target"])):
            if mine_support & set(_l(other["contrary_events"]) or []) or \
                    set(_l(row["contrary_events"]) or []) & set(_l(other["supporting_events"]) or []):
                conflicts.append(other["id"])
                theirs = set(_l(other["conflicts_with"]) or [])
                theirs.add(cid)
                self.db.execute("UPDATE claims SET conflicts_with=? WHERE id=?", (_j(sorted(theirs)), other["id"]))
        self.db.execute("UPDATE claims SET conflicts_with=? WHERE id=?", (_j(sorted(conflicts)), cid))

    def _apply_task(self, rid, at, actor, task_id, epoch_id, p):
        tid = p.get("id") or ident("task_")
        self.db.execute(
            "INSERT OR REPLACE INTO tasks(id, created_at, updated_at, creator, owner, target, objective, deliverable, "
            "state, reason, depends_on, context, lease, result, checkpoints) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, at, at, actor, p.get("owner"), p.get("target"), p["objective"], p.get("deliverable"),
             p.get("state", "queued"), p.get("reason"), _j(p.get("depends_on") or []), _j(p.get("context") or {}),
             p.get("lease"), None, "[]"))

    def _apply_task_update(self, rid, at, actor, task_id, epoch_id, p):
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (p["task_id"],)).fetchone()
        if not row:
            return
        checkpoints = _l(row["checkpoints"]) or []
        if p.get("checkpoint"):
            checkpoints.append({"at": at, "actor": actor, "note": p["checkpoint"],
                                "evidence": p.get("evidence") or []})
        state = p.get("state") or row["state"]
        self.db.execute(
            "UPDATE tasks SET updated_at=?, owner=COALESCE(?, owner), state=?, reason=COALESCE(?, reason), "
            "result=COALESCE(?, result), checkpoints=?, lease=COALESCE(?, lease) WHERE id=?",
            (at, p.get("owner"), state, p.get("reason"), _j(p["result"]) if p.get("result") is not None else None,
             _j(checkpoints), p.get("lease"), row["id"]))

    def _apply_handoff(self, rid, at, actor, task_id, epoch_id, p):
        self.db.execute(
            "INSERT OR REPLACE INTO handoffs(id, at, from_actor, to_actor, task_id, packet) VALUES (?,?,?,?,?,?)",
            (p.get("id") or ident("hand_"), at, actor, p.get("to_actor"), task_id, _j(p["packet"])))

    def _apply_handoff_ack(self, rid, at, actor, task_id, epoch_id, p):
        self.db.execute("UPDATE handoffs SET acknowledged_by=?, acknowledged_at=? WHERE id=?",
                        (actor, at, p["handoff_id"]))

    def _apply_heartbeat(self, rid, at, actor, task_id, epoch_id, p):
        self.db.execute(
            "INSERT OR REPLACE INTO heartbeats(actor, at, task_id, note, provider) VALUES (?,?,?,?,?)",
            (actor, at, task_id, p.get("note", ""), p.get("provider")))

    def _apply_lease(self, rid, at, actor, task_id, epoch_id, p):
        self.db.execute(
            "INSERT OR REPLACE INTO leases(resource, owner, task_id, acquired_at, expires_at, note) "
            "VALUES (?,?,?,?,?,?)",
            (p["resource"], actor, task_id, at, p["expires_at"], p.get("note")))

    def _apply_lease_release(self, rid, at, actor, task_id, epoch_id, p):
        self.db.execute("DELETE FROM leases WHERE resource=?", (p["resource"],))

    def _apply_decision(self, rid, at, actor, task_id, epoch_id, p):
        self.db.execute(
            "INSERT OR REPLACE INTO decisions(id, at, actor, kind, question, state, context) VALUES (?,?,?,?,?,?,?)",
            (p.get("id") or ident("dec_"), at, actor, p.get("kind", "direction"), p["question"], "open",
             _j(p.get("context") or {})))

    def _apply_decision_answer(self, rid, at, actor, task_id, epoch_id, p):
        self.db.execute("UPDATE decisions SET state='answered', answer=?, answered_by=?, answered_at=? WHERE id=?",
                        (p["answer"], actor, at, p["decision_id"]))

    # --------------------------------------------------------------- epochs
    def _ensure_default_epoch(self) -> None:
        self.append("epoch_start", {"id": "epoch_1", "label": "initial", "reason": "case opened"},
                    actor="system", idempotency_key="epoch:epoch_1")

    def current_epoch(self) -> dict | None:
        row = self.db.execute("SELECT * FROM epochs WHERE current=1 ORDER BY started_at DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def start_epoch(self, reason: str, label: str | None = None, fingerprint_value: str | None = None,
                    actor: str | None = None) -> str:
        n = self.db.execute("SELECT COUNT(*) FROM epochs").fetchone()[0] + 1
        eid = f"epoch_{n}"
        self.append("epoch_start", {"id": eid, "label": label or eid, "reason": reason,
                                    "fingerprint": fingerprint_value}, actor=actor, epoch_id=eid)
        return eid

    # ------------------------------------------------------------- evidence
    def sync_evidence(self) -> int:
        """Mirror case.json events and prune removed rows. Return changed row count."""
        data = self.case()
        current_ids = {e["id"] for e in data["events"]}
        known = {r["id"]: (r["sha256"], r["payload"])
                 for r in self.db.execute("SELECT id, sha256, payload FROM evidence")}
        removed_ids = set(known) - current_ids
        added = 0
        with self._tx():
            # The evidence table mirrors case.json. An REPORT correction can remove
            # a misfiled event, so prune both the row and its full-text entry.
            for event_id in sorted(removed_ids):
                self.db.execute("DELETE FROM evidence_fts WHERE id=?", (event_id,))
                self.db.execute("DELETE FROM evidence WHERE id=?", (event_id,))
            for ord_, e in enumerate(data["events"]):
                if e["id"] in known and known[e["id"]] == (e.get("sha256"), _j(e)):
                    self.db.execute("UPDATE evidence SET ord=?, status=? WHERE id=?",
                                    (ord_, e.get("status"), e["id"]))
                    continue
                summary, body = self._evidence_text(e)
                self.db.execute(
                    "INSERT OR REPLACE INTO evidence(id, ord, at, target, stage, kind, actor, status, summary, file, "
                    "sha256, payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (e["id"], ord_, e["at"], e.get("target"), e.get("stage"), e["kind"], e.get("actor"),
                     e.get("status"), summary, e.get("file") or e.get("transcript"), e.get("sha256"), _j(e)))
                self.db.execute("DELETE FROM evidence_fts WHERE id=?", (e["id"],))
                self.db.execute("INSERT INTO evidence_fts(id, body) VALUES (?,?)", (e["id"], body))
                added += 1
            self.db.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('last_sync', ?)", (now(),))
        return added + len(removed_ids)

    def _evidence_text(self, e: dict) -> tuple[str, str]:
        kind = e["kind"]
        if kind == "command":
            summary = e.get("command", "")
            body = summary
            if e.get("transcript"):
                path = self.root / e["transcript"]
                if path.is_file():
                    body += "\n" + path.read_text(encoding="utf-8", errors="replace")[:2_000_000]
        elif kind in ("query", "note", "browser"):
            summary = e.get("text", "")
            body = summary + "\n" + (e.get("result") or "")
        elif kind == "code":
            summary = f"{e.get('filename')} ({e.get('origin')})"
            body = summary + "\n" + (e.get("changes") or "")
            path = self.root / e["file"] if e.get("file") else None
            if path and path.is_file():
                body += "\n" + path.read_text(encoding="utf-8", errors="replace")[:500_000]
        elif kind == "screenshot":
            summary = f"[{e.get('role')}] {e.get('caption', '')}"
            body = summary
        elif kind == "gate":
            summary = f"gate {e.get('gate')} -> {e.get('result')} {e.get('reason') or ''}".strip()
            body = summary
        else:
            summary = _j(e)[:300]
            body = _j(e)
        return summary[:400], body

    def evidence(self, event_id: str, with_body: bool = False) -> dict | None:
        row = self.db.execute("SELECT * FROM evidence WHERE id=?", (event_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["payload"] = _l(d["payload"])
        if with_body:
            body = self.db.execute("SELECT body FROM evidence_fts WHERE id=?", (event_id,)).fetchone()
            d["body"] = body["body"] if body else ""
        return d

    def timeline(self, target: str | None = None, stage: str | None = None, kind: str | None = None,
                 actor: str | None = None, limit: int = 100, before_ord: int | None = None) -> list[dict]:
        sql, args = "SELECT * FROM evidence WHERE 1=1", []
        for col, val in (("target", target), ("stage", stage), ("kind", kind), ("actor", actor)):
            if val:
                sql += f" AND {col}=?"
                args.append(val)
        if before_ord is not None:
            sql += " AND ord<?"
            args.append(before_ord)
        sql += " ORDER BY ord DESC LIMIT ?"
        args.append(limit)
        rows = [dict(r) for r in self.db.execute(sql, args)]
        for r in rows:
            r["payload"] = _l(r["payload"])
        return list(reversed(rows))

    def search(self, query: str, limit: int = 50) -> dict:
        """Full-text search over evidence plus substring search over entities and claims."""
        q = query.strip()
        evidence: list[dict] = []
        if q:
            fts_query = " ".join(f'"{t}"' for t in re.split(r"\s+", q) if t)
            try:
                rows = self.db.execute(
                    "SELECT e.id, e.at, e.target, e.stage, e.kind, e.actor, e.summary, "
                    "snippet(evidence_fts, 1, '[', ']', ' … ', 18) AS snippet FROM evidence_fts f "
                    "JOIN evidence e ON e.id=f.id WHERE evidence_fts MATCH ? ORDER BY e.ord DESC LIMIT ?",
                    (fts_query, limit)).fetchall()
            except sqlite3.OperationalError:
                rows = self.db.execute(
                    "SELECT id, at, target, stage, kind, actor, summary, summary AS snippet FROM evidence "
                    "WHERE summary LIKE ? ORDER BY ord DESC LIMIT ?", (f"%{q}%", limit)).fetchall()
            evidence = [dict(r) for r in rows]
        like = f"%{q}%"
        entities = [self._entity_row(r) for r in self.db.execute(
            "SELECT * FROM entities WHERE label LIKE ? OR key LIKE ? OR attrs LIKE ? ORDER BY last_seen DESC LIMIT ?",
            (like, like, like, limit))]
        claims = [self._claim_row(r) for r in self.db.execute(
            "SELECT * FROM claims WHERE statement LIKE ? ORDER BY at DESC LIMIT ?", (like, limit))]
        return {"query": q, "evidence": evidence, "entities": entities, "claims": claims}

    # ------------------------------------------------------------- entities
    def record_entity(self, type: str, key: str, label: str | None = None, attrs: dict | None = None,
                      source_events: Iterable[str] = (), level: str = "proposed", statement: str | None = None,
                      source_span: dict | None = None, extractor: str | None = None, confidence: float | None = None,
                      target: str | None = None, actor: str | None = None, task_id: str | None = None,
                      applicability: str = "current", idempotency_key: str | None = None) -> str:
        if type not in ENTITY_TYPES:
            raise CaseHubError(f"Unknown entity type {type}; use one of {', '.join(ENTITY_TYPES)}")
        if level not in EVIDENCE_LEVELS:
            raise CaseHubError(f"Unknown evidence level {level}")
        if type == "secret_ref":
            digest = (attrs or {}).get("fingerprint")
            if (not label or not label.strip() or not isinstance(digest, str)
                    or not re.fullmatch(r"[0-9a-fA-F]{64}", digest)
                    or key.lower() != digest.lower() or set(attrs or {}) != {"fingerprint"}
                    or statement):
                raise CaseHubError("secret_ref requires a label and SHA-256 fingerprint only; use the fingerprint as key")
        source_events = sorted(set(source_events))
        if level in ("observed", "verified") and not source_events:
            raise CaseHubError(f"An {level} entity must cite at least one evidence event ID")
        self._check_events_exist(source_events)
        payload = {"type": type, "key": key, "label": label, "attrs": attrs or {}, "source_events": source_events,
                   "level": level, "statement": statement, "source_span": source_span, "extractor": extractor,
                   "confidence": confidence, "target": target, "applicability": applicability}
        self.append("entity", payload, actor=actor, task_id=task_id, idempotency_key=idempotency_key)
        row = self.db.execute("SELECT id FROM entities WHERE type=? AND key=? AND epoch_id IS ?",
                              (type, normalize_key(type, key), (self.current_epoch() or {}).get("id"))).fetchone()
        return row["id"]

    def _check_events_exist(self, event_ids: Iterable[str]) -> None:
        missing = [e for e in event_ids
                   if not self.db.execute("SELECT 1 FROM evidence WHERE id=?", (e,)).fetchone()]
        if missing:
            self.sync_evidence()
            missing = [e for e in missing
                       if not self.db.execute("SELECT 1 FROM evidence WHERE id=?", (e,)).fetchone()]
        if missing:
            raise CaseHubError(f"Unknown evidence event ID(s): {', '.join(missing)}")

    def _entity_row(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        for k in ("attrs", "source_events", "source_records"):
            d[k] = _l(d[k])
        return d

    def entity(self, entity_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone()
        if not row:
            return None
        d = self._entity_row(row)
        d["observations"] = [self._obs_row(o) for o in self.db.execute(
            "SELECT * FROM observations WHERE entity_id=? ORDER BY at", (entity_id,))]
        d["edges"] = self.neighbors(entity_id)
        d["claims"] = [self._claim_row(c) for c in self.db.execute(
            "SELECT * FROM claims WHERE entity_ids LIKE ? ORDER BY at", (f'%"{entity_id}"%',))]
        return d

    def _obs_row(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["attrs"], d["source_events"], d["source_span"] = _l(d["attrs"]), _l(d["source_events"]), _l(d["source_span"])
        return d

    def entities(self, type: str | None = None, target: str | None = None, level: str | None = None,
                 applicability: str | None = None, epoch_id: str | None = None, limit: int = 500) -> list[dict]:
        sql, args = "SELECT * FROM entities WHERE 1=1", []
        for col, val in (("type", type), ("target", target), ("level", level),
                         ("applicability", applicability), ("epoch_id", epoch_id)):
            if val:
                sql += f" AND {col}=?"
                args.append(val)
        sql += " ORDER BY type, label LIMIT ?"
        args.append(limit)
        return [self._entity_row(r) for r in self.db.execute(sql, args)]

    def add_edge(self, src: str, dst: str, relation: str, status: str = "observed",
                 source_events: Iterable[str] = (), explanation: str | None = None,
                 actor: str | None = None, task_id: str | None = None) -> None:
        if status not in EDGE_STATUS:
            raise CaseHubError(f"Unknown edge status {status}")
        for eid in (src, dst):
            if not self.db.execute("SELECT 1 FROM entities WHERE id=?", (eid,)).fetchone():
                raise CaseHubError(f"Unknown entity {eid}")
        source_events = sorted(set(source_events))
        if status in ("observed", "verified") and not source_events:
            raise CaseHubError(f"An {status} edge must cite evidence event IDs")
        self._check_events_exist(source_events)
        self.append("edge", {"src": src, "dst": dst, "relation": relation, "status": status,
                             "source_events": source_events, "explanation": explanation},
                    actor=actor, task_id=task_id)

    def neighbors(self, entity_id: str, hops: int = 1) -> list[dict]:
        seen, frontier, out = {entity_id}, {entity_id}, []
        for _ in range(max(1, hops)):
            nxt = set()
            for eid in frontier:
                for r in self.db.execute("SELECT * FROM edges WHERE src=? OR dst=?", (eid, eid)):
                    d = dict(r)
                    d["source_events"] = _l(d["source_events"])
                    other = d["dst"] if d["src"] == eid else d["src"]
                    if d["id"] not in {o["id"] for o in out}:
                        out.append(d)
                    if other not in seen:
                        seen.add(other)
                        nxt.add(other)
            frontier = nxt
        labels = {}
        for eid in seen:
            row = self.db.execute("SELECT id, type, label, level, applicability FROM entities WHERE id=?", (eid,)).fetchone()
            if row:
                labels[eid] = dict(row)
        for d in out:
            d["src_entity"], d["dst_entity"] = labels.get(d["src"]), labels.get(d["dst"])
        return out

    # ---------------------------------------------------------------- claims
    def propose_claim(self, statement: str, state: str = "hypothesis", target: str | None = None,
                      entity_ids: Iterable[str] = (), supporting_events: Iterable[str] = (),
                      contrary_events: Iterable[str] = (), impact: str | None = None,
                      actor: str | None = None, task_id: str | None = None) -> str:
        if state not in CLAIM_STATES:
            raise CaseHubError(f"Unknown claim state {state}")
        if state == "verified":
            raise CaseHubError("A claim is proposed as hypothesis/observed; 'verified' requires claim_review")
        supporting, contrary = sorted(set(supporting_events)), sorted(set(contrary_events))
        if state == "observed" and not supporting:
            raise CaseHubError("An observed claim must cite supporting evidence event IDs")
        self._check_events_exist(supporting + contrary)
        cid = ident("claim_")
        self.append("claim", {"id": cid, "statement": statement, "state": state, "target": target,
                              "entity_ids": sorted(set(entity_ids)), "supporting_events": supporting,
                              "contrary_events": contrary, "impact": impact}, actor=actor, task_id=task_id)
        return cid

    def review_claim(self, claim_id: str, state: str, reason: str, supporting_events: Iterable[str] = (),
                     contrary_events: Iterable[str] = (), narrowed_statement: str | None = None,
                     actor: str | None = None) -> None:
        if state not in CLAIM_STATES:
            raise CaseHubError(f"Unknown claim state {state}")
        row = self.db.execute("SELECT * FROM claims WHERE id=?", (claim_id,)).fetchone()
        if not row:
            raise CaseHubError(f"Unknown claim {claim_id}")
        actor = actor or self.actor
        if state == "verified":
            if actor == row["actor"]:
                raise CaseHubError("A claim cannot be verified by the actor who proposed it; cross-review is required")
            if not (set(_l(row["supporting_events"]) or []) | set(supporting_events)):
                raise CaseHubError("Verification requires supporting evidence event IDs")
        if not reason.strip():
            raise CaseHubError("A review reason is required")
        self._check_events_exist(list(supporting_events) + list(contrary_events))
        self.append("claim_review", {"claim_id": claim_id, "state": state, "reason": reason,
                                     "supporting_events": sorted(set(supporting_events)),
                                     "contrary_events": sorted(set(contrary_events)),
                                     "narrowed_statement": narrowed_statement}, actor=actor)

    def _claim_row(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        for k in ("entity_ids", "supporting_events", "contrary_events", "conflicts_with"):
            d[k] = _l(d[k]) or []
        return d

    def claims(self, target: str | None = None, state: str | None = None, limit: int = 500) -> list[dict]:
        sql, args = "SELECT * FROM claims WHERE 1=1", []
        if target:
            sql += " AND target=?"
            args.append(target)
        if state:
            sql += " AND state=?"
            args.append(state)
        sql += " ORDER BY at DESC LIMIT ?"
        args.append(limit)
        return [self._claim_row(r) for r in self.db.execute(sql, args)]

    # ----------------------------------------------------------------- tasks
    def create_task(self, objective: str, target: str | None = None, deliverable: str | None = None,
                    owner: str | None = None, depends_on: Iterable[str] = (), context: dict | None = None,
                    actor: str | None = None) -> str:
        if not objective.strip():
            raise CaseHubError("A task needs a concrete objective")
        tid = ident("task_")
        self.append("task", {"id": tid, "objective": objective, "target": target, "deliverable": deliverable,
                             "owner": owner, "depends_on": list(depends_on), "context": context or {},
                             "state": "running" if owner else "queued"}, actor=actor)
        return tid

    def update_task(self, task_id: str, state: str | None = None, owner: str | None = None,
                    checkpoint: str | None = None, evidence: Iterable[str] = (), result: dict | None = None,
                    reason: str | None = None, actor: str | None = None) -> None:
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise CaseHubError(f"Unknown task {task_id}")
        if state and state not in TASK_STATES:
            raise CaseHubError(f"Unknown task state {state}")
        if state in ("blocked", "waiting_on_operator", "waiting_on_target", "cancelled") and not reason:
            raise CaseHubError(f"State {state} requires a reason")
        if state == "done" and result is None and not row["result"]:
            raise CaseHubError("Completing a task requires a structured result")
        if result is not None:
            for key in ("summary", "evidence"):
                if key not in result:
                    raise CaseHubError("A task result needs 'summary' and 'evidence' (event IDs) at minimum")
            self._check_events_exist(result.get("evidence") or [])
        evidence = sorted(set(evidence))
        self._check_events_exist(evidence)
        self.append("task_update", {"task_id": task_id, "state": state, "owner": owner, "checkpoint": checkpoint,
                                    "evidence": evidence, "result": result, "reason": reason},
                    actor=actor, task_id=task_id)

    def claim_task(self, task_id: str, actor: str | None = None) -> None:
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise CaseHubError(f"Unknown task {task_id}")
        actor = actor or self.actor
        if row["owner"] and row["owner"] != actor and row["state"] not in ("queued", "done", "cancelled"):
            raise CaseHubError(f"Task {task_id} is owned by {row['owner']}; ask for a handoff")
        self.update_task(task_id, state="running", owner=actor, checkpoint=f"claimed by {actor}", actor=actor)

    def _task_row(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        for k in ("depends_on", "context", "checkpoints"):
            d[k] = _l(d[k])
        d["result"] = _l(d["result"])
        return d

    def tasks(self, state: str | None = None, owner: str | None = None, target: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM tasks WHERE 1=1", []
        for col, val in (("state", state), ("owner", owner), ("target", target)):
            if val:
                sql += f" AND {col}=?"
                args.append(val)
        sql += " ORDER BY updated_at DESC"
        return [self._task_row(r) for r in self.db.execute(sql, args)]

    def task(self, task_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        return self._task_row(row) if row else None

    # ------------------------------------------------- coordination records
    def heartbeat(self, note: str, task_id: str | None = None, provider: str | None = None,
                  actor: str | None = None) -> None:
        self.append("heartbeat", {"note": note, "provider": provider}, actor=actor, task_id=task_id)

    def acquire_lease(self, resource: str, ttl_seconds: int = 900, note: str | None = None,
                      task_id: str | None = None, actor: str | None = None) -> dict:
        actor = actor or self.actor
        row = self.db.execute("SELECT * FROM leases WHERE resource=?", (resource,)).fetchone()
        if row and row["owner"] != actor and row["expires_at"] > now():
            raise CaseHubError(f"{resource} is leased by {row['owner']} until {row['expires_at']}")
        expires = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() + ttl_seconds,
                                         timezone.utc).isoformat(timespec="seconds")
        self.append("lease", {"resource": resource, "expires_at": expires, "note": note}, actor=actor, task_id=task_id)
        return {"resource": resource, "owner": actor, "expires_at": expires}

    def release_lease(self, resource: str, actor: str | None = None) -> None:
        actor = actor or self.actor
        row = self.db.execute("SELECT * FROM leases WHERE resource=?", (resource,)).fetchone()
        if row and row["owner"] != actor and row["expires_at"] > now():
            raise CaseHubError(f"{resource} is leased by {row['owner']}; only the owner or expiry can release it")
        self.append("lease_release", {"resource": resource}, actor=actor)

    def leases(self) -> list[dict]:
        t = now()
        return [dict(r) | {"expired": r["expires_at"] <= t} for r in self.db.execute("SELECT * FROM leases")]

    def write_handoff(self, packet: dict, to_actor: str | None = None, task_id: str | None = None,
                      actor: str | None = None) -> str:
        required = ("objective", "verified_facts", "open_sessions", "failed_avenues", "next_action")
        missing = [k for k in required if k not in packet]
        if missing:
            raise CaseHubError(f"Handoff packet is missing: {', '.join(missing)}")
        hid = ident("hand_")
        self.append("handoff", {"id": hid, "to_actor": to_actor, "packet": packet}, actor=actor, task_id=task_id)
        return hid

    def acknowledge_handoff(self, handoff_id: str, actor: str | None = None) -> None:
        self.append("handoff_ack", {"handoff_id": handoff_id}, actor=actor)

    def handoffs(self, to_actor: str | None = None, unacknowledged_only: bool = False) -> list[dict]:
        sql, args = "SELECT * FROM handoffs WHERE 1=1", []
        if to_actor:
            sql += " AND (to_actor=? OR to_actor IS NULL)"
            args.append(to_actor)
        if unacknowledged_only:
            sql += " AND acknowledged_at IS NULL"
        sql += " ORDER BY at DESC"
        out = []
        for r in self.db.execute(sql, args):
            d = dict(r)
            d["packet"] = _l(d["packet"])
            out.append(d)
        return out

    def ask_decision(self, question: str, kind: str = "direction", context: dict | None = None,
                     actor: str | None = None) -> str:
        did = ident("dec_")
        self.append("decision", {"id": did, "question": question, "kind": kind, "context": context or {}}, actor=actor)
        return did

    def answer_decision(self, decision_id: str, answer: str, actor: str | None = None) -> None:
        self.append("decision_answer", {"decision_id": decision_id, "answer": answer}, actor=actor)

    def decisions(self, open_only: bool = True) -> list[dict]:
        sql = "SELECT * FROM decisions" + (" WHERE state='open'" if open_only else "") + " ORDER BY at DESC"
        out = []
        for r in self.db.execute(sql):
            d = dict(r)
            d["context"] = _l(d["context"])
            out.append(d)
        return out

    # --------------------------------------------------------------- summary
    def context(self) -> dict:
        """The mission view: what the operator (or a newly started agent) needs first."""
        data = self.case()
        epoch = self.current_epoch()
        targets = {}
        for tid, t in data["targets"].items():
            stages = [s for s in data["stages"] if s["target"] == tid]
            done = [s["kind"] for s in stages]
            missing_stages = [k for k in t.get("required_stages", []) if k not in done]
            events = [e for e in data["events"] if e.get("target") == tid]
            shots = [e for e in events if e["kind"] == "screenshot"]
            gates = [e for e in events if e["kind"] == "gate"]
            open_cmds = [e["id"] for e in events if e["kind"] == "command" and e.get("status") == "running"]
            interrupted = [e["id"] for e in events if e["kind"] == "command" and e.get("status") == "interrupted"
                           and not e.get("resolution")]
            roles = {e.get("role") for e in shots if e.get("provenance", "direct_import") == "direct_import"}
            proof = t.get("proof") or {}
            targets[tid] = {
                "name": t.get("name"), "ip": t.get("ip"), "role": t.get("role"), "scored": t.get("scored", True),
                "objective": t.get("objective"), "stages_done": done, "stages_missing": missing_stages,
                "event_count": len(events), "last_event_at": events[-1]["at"] if events else None,
                "proof_recorded": bool(proof.get("value")),
                "direct_roles": sorted(r for r in roles if r),
                "ready_submit": any(g.get("gate") == "ready_submit" and g.get("result") == "ready" for g in gates),
                "accepted_capture": "accepted" in roles,
                "running_commands": open_cmds, "unresolved_interrupted": interrupted,
                "entities": self.db.execute("SELECT COUNT(*) FROM entities WHERE target=?", (tid,)).fetchone()[0],
                "claims_open": self.db.execute(
                    "SELECT COUNT(*) FROM claims WHERE target=? AND state IN ('hypothesis','observed')", (tid,)).fetchone()[0],
            }
        heartbeats = [dict(r) for r in self.db.execute("SELECT * FROM heartbeats ORDER BY at DESC")]
        return {
            "case": {"title": data["title"], "report_id": data["report_id"], "scope": data["scope"],
                     "created": data["created"], "events": len(data["events"]),
                     "review": data.get("review"), "gates_required": data.get("gates_required", False)},
            "epoch": epoch,
            "targets": targets,
            "actors": heartbeats,
            "tasks": self.tasks(),
            "leases": self.leases(),
            "open_decisions": self.decisions(open_only=True),
            "pending_handoffs": self.handoffs(unacknowledged_only=True),
            "conflicting_claims": [c for c in self.claims() if c["conflicts_with"]],
            "entity_counts": {r["type"]: r["n"] for r in self.db.execute(
                "SELECT type, COUNT(*) AS n FROM entities GROUP BY type")},
            "last_sync": (self.db.execute("SELECT value FROM meta WHERE key='last_sync'").fetchone() or {"value": None})["value"],
        }


class _Transaction:
    """BEGIN IMMEDIATE so concurrent writers serialize cleanly in WAL mode."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.nested = db.in_transaction

    def __enter__(self):
        if not self.nested:
            self.db.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.nested:
            return False
        if exc_type is None:
            self.db.execute("COMMIT")
        else:
            self.db.execute("ROLLBACK")
        return False
