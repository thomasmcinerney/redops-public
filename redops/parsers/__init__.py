"""Structured extraction contract (D1).

A parser is a PURE function  ``parse(envelope) -> ExtractResult``  with NO database
access, so it is unit-testable against fixtures (see ``tests``/``fixtures``). A
separate persist step defaults trust by extraction path.
Individual facts can lower that trust for unverified source claims.

Design rule — the contract is a permissive SUPERSET, never a reducer. It carries
everything the richest tool (nmap: curated node buckets, role/OS/domain coalescing,
status advance, a summary) and a tool that needs something the common shape can't
express supplies a ``persist_extra`` hook rather than being flattened. No tool is
made worse to homogenize; the contract is a floor, not a ceiling.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Fact:
    """One relationship. `object` (an entity, upserted+resolved) XOR `object_text`
    (free text) — never a list jammed into either. `stage` optionally overrides
    the extraction-path default for source claims."""
    subject: str
    predicate: str
    subject_type: str = ""          # "" -> guess_type at persist
    object: str = ""                # entity name; resolved to an id
    object_type: str = ""           # "" -> guess_type
    object_text: str = ""           # free-text object (mutually exclusive with `object`)
    stage: str = ""                 # optional per-fact trust override


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""


@dataclass
class Cred:
    username: str = ""
    secret: str = ""
    kind: str = "password"
    status: str = "untested"
    source: str = ""


@dataclass
class Finding:
    title: str
    severity: str = "info"
    cve: str = ""
    matched_at: str = ""
    description: str = ""


@dataclass
class ExtractResult:
    """What a parser produces from one tool run. Everything typed and structured —
    a parser NEVER dumps raw text into a field. ``status`` is honest about coverage;
    ``unrecognized`` means "I did not understand this output" and MUST carry zero
    facts (a wrong `observed` fact is worse than a missing one)."""
    entities: list = field(default_factory=list)        # [{"type","name","label"?}] standalone nodes
    services: list[Service] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    creds: list[Cred] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    target_updates: dict = field(default_factory=dict)  # {"role","os","status_advance": bool}
    status: str = "ok"                                  # ok | partial | empty | unrecognized
    summary: str = ""
    notes: list[str] = field(default_factory=list)      # operator-facing text, NOT facts
    # Escape valve: tool-specific persistence the common shape can't express. Runs
    # AFTER the generic persist with the same (conn, engagement_id, target_id, ip,
    # name2id). This is how a rich tool keeps its edges instead of being flattened.
    persist_extra: Optional[Callable] = None


def _resolve(conn, engagement_id, name, etype, name2id):
    """Resolve an entity name to an id, upserting if we haven't already this run."""
    from .. import db
    if not name:
        return None
    key = (etype, name)
    if key in name2id:
        return name2id[key]
    if name in name2id:
        return name2id[name]
    eid = db.upsert_entity(conn, engagement_id, etype or db_guess(name), name)
    name2id[key] = eid
    return eid


def db_guess(name):
    # thin indirection so parsers don't import the API's _guess_type; entities
    # default to "other" if the type is unknown (upsert_entity coerces anyway).
    from .. import db
    return "host" if _looks_ip(name) else "other"


def _looks_ip(s):
    import re
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s or ""))


def persist(conn, engagement_id, target_id, ip, result: ExtractResult,
            *, stage: str = "observed", source: str = "wire-auto") -> dict:
    """Apply an ExtractResult to the graph. Trust is stamped HERE, by path: an
    argv-bound deterministic parse is `observed`. Returns small counts for logging.

    This does the *graph* only — services table, entity nodes, facts, creds,
    findings, target identity coalescing. Run bookkeeping (tool_run row, output
    store, feed event, correlate) stays in the runner so every tool shares it."""
    from .. import db
    counts = {"services": 0, "facts": 0, "creds": 0, "findings": 0}

    # 1) services table — complete, structured, upsert-in-place on re-scan
    for s in result.services:
        if not target_id:
            break
        row = db.row(conn, "SELECT id FROM services WHERE target_id=? AND port=? AND proto=?",
                     (target_id, s.port, s.proto))
        fields = {"state": s.state, "name": s.name, "product": s.product,
                  "version": s.version, "extrainfo": s.extrainfo, "cpe": s.cpe}
        if not row:
            db.insert(conn, "services", {"target_id": target_id, "port": s.port,
                                         "proto": s.proto, **fields})
        else:
            sql = "UPDATE services SET " + ", ".join(f"{k}=?" for k in fields) + " WHERE id=?"
            conn.execute(sql, (*fields.values(), row["id"]))
        counts["services"] += 1

    # 2) standalone entity nodes (host, services-as-nodes, …)
    name2id: dict = {}
    for e in result.entities:
        eid = db.upsert_entity(conn, engagement_id, e["type"], e["name"],
                               label=e.get("label", ""), meta=e.get("meta"))
        name2id[(e["type"], e["name"])] = eid
        name2id.setdefault(e["name"], eid)

    # 3) facts — subject/object resolved (upserting on demand); stage stamped by path
    for f in result.facts:
        sid = _resolve(conn, engagement_id, f.subject, f.subject_type, name2id)
        if sid is None:
            continue
        oid = _resolve(conn, engagement_id, f.object, f.object_type, name2id) if f.object else None
        db.add_fact(conn, engagement_id, sid, f.predicate, oid, f.object_text,
                    f.stage or stage, source)
        counts["facts"] += 1

    # 4) credentials + findings (structured, staged)
    for c in result.creds:
        # NB: credentials has no created_at column — inserting one raised
        # OperationalError the moment any parser emitted a Cred (dormant only
        # because none did yet).
        db.insert(conn, "credentials", {
            "engagement_id": engagement_id, "target_id": target_id,
            "username": c.username, "secret": c.secret, "kind": c.kind,
            "status": c.status, "source": c.source or source})
        counts["creds"] += 1
    for fnd in result.findings:
        db.insert(conn, "findings", {
            "engagement_id": engagement_id, "target_id": target_id,
            "title": fnd.title, "severity": fnd.severity, "description": fnd.description,
            "cve": fnd.cve, "matched_at": fnd.matched_at, "created_at": db.now()})
        counts["findings"] += 1

    # 5) target identity — coalesce (advance-only), never overwrite operator intel
    tu = result.target_updates
    if target_id and tu:
        if tu.get("role"):
            conn.execute("UPDATE targets SET role=CASE WHEN role='' THEN ? ELSE role END WHERE id=?",
                         (tu["role"], target_id))
        if tu.get("os"):
            conn.execute("UPDATE targets SET os=CASE WHEN os='' THEN ? ELSE os END WHERE id=?",
                         (tu["os"], target_id))
        if tu.get("status_advance"):
            t = db.row(conn, "SELECT status FROM targets WHERE id=?", (target_id,))
            if t and t["status"] == "unidentified":
                conn.execute("UPDATE targets SET status='identified' WHERE id=?", (target_id,))

    # 6) escape valve — tool-specific persistence the common shape can't express
    if result.persist_extra:
        result.persist_extra(conn, engagement_id, target_id, ip, name2id)

    return counts
