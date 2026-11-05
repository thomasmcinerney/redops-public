"""RedOps API server (FastAPI + SSE). Run: python -m redops.api"""

import asyncio
import base64
import contextlib
import email
import json
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, Response, StreamingResponse)
from fastapi.staticfiles import StaticFiles

from . import (acp, analyst, correlate, db, export, leads, netsensor, retention,
               scope, tools, webscope, wiretail)

HOST = os.environ.get("REDOPS_HOST", "127.0.0.1")
PORT = int(os.environ.get("REDOPS_PORT", "9100"))
STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="RedOps")

TARGET_STATUSES = {"unidentified", "identified", "foothold", "rooted", "flagged"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
EVENT_SOURCES = {"wire", "agent", "user", "transcript", "analyst", "acp"}
EVENT_KINDS = {"action", "reasoning", "note", "objective", "error", "fact", "output", "webchat"}
# legacy one-shot cred vocabulary (kept for the `cred add` sugar / CLI choices);
# these map onto the decomposed principal/secret/binding model below.
CRED_KINDS = {"password", "hash", "ticket", "key", "token", "api-key", "principal"}
CRED_STATUSES = {"untested", "valid", "invalid", "partial"}
# legacy secret-kind -> decomposed SECRET_KINDS
_SECRET_KIND_MAP = {"password": "password", "hash": "hash", "ntlm": "ntlm",
                    "ticket": "ticket", "key": "private-key", "private-key": "private-key",
                    "api-key": "api-key", "token": "token"}
# legacy cred status -> decomposed BINDING_STATUSES
_BINDING_STATUS_MAP = {"partial": "candidate", "untested": "untested",
                       "valid": "valid", "invalid": "invalid", "candidate": "candidate"}
# the confirmation lifecycle — a fact is only as strong as the evidence behind it.
#   claimed   a source asserts it (target self-disclosure, a banner, a config note) — unverified
#   observed  we saw it ourselves (a scan hit, a wire flow, a probe response)
#   confirmed we verified or exploited it (listed the collections, dumped the db, auth succeeded)
FACT_STAGES = {"claimed", "observed", "confirmed"}
FACT_SOURCES = {"agent", "wire-auto", "user", "analyst"}
OPP_STATUSES = {"open", "pinned", "dismissed", "converted"}
PAYLOAD_OUTCOMES = {"untried", "worked", "failed", "blocked"}
POISON_STORES = {"kb-db", "rag", "minio", "agent-card", "registry", "file", "other"}
IMG_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
TXT_EXTS = {".txt", ".log", ".md", ".out", ".csv", ".json", ".xml", ".html"}

# Per-engagement workdir sandbox: the agent stages scripts/exploits/wordlists
# here via /api/fs/write and runs them via /api/exec. A locked-down agent has no
# native file access, so this IS its filesystem — confined to one directory per
# engagement so one engagement's loot can't leak into another's.
WORK_DIR = Path(os.environ.get("REDOPS_WORK_DIR", db.DATA_DIR / "work"))
# Operator-side downloads for /api/fetch (a locked agent has no web fetch).
DOWNLOADS_DIR = db.DATA_DIR / "downloads"
FETCH_ALLOW_DEFAULT = ("raw.githubusercontent.com,github.com,"
                       "objects.githubusercontent.com,gitlab.com,exploit-db.com")


@app.on_event("startup")
def startup() -> None:
    db.init_db()
    conn = db.connect()
    try:
        correlate.run(conn)  # catch up over all existing facts
    finally:
        conn.close()
    tools.reset_orphans()  # clear runs left 'running' by a prior process (zombies)
    tools.pump()           # then drain anything left 'ready' across the restart
    _exec_reaper_start()   # reap background exec_tasks as they exit
    # Capture mechanism: acp | wire | both. ACP is the default now (it owns the
    # kimi session); set REDOPS_CAPTURE=wire (or REDOPS_ACP=0) to fall back to
    # wiretail. If kimi isn't logged in, acp.start() degrades to "capture off"
    # gracefully rather than crashing the server.
    capture = os.environ.get("REDOPS_CAPTURE", "").lower()
    if not capture:
        capture = "wire" if os.environ.get("REDOPS_ACP") == "0" else "acp"
    wire_on = capture in ("wire", "both") and os.environ.get("REDOPS_NO_WIRETAIL") != "1"
    if wire_on:
        wiretail.WireTailer().start()
    if capture in ("acp", "both"):
        acp.start()
    wiretail.TranscriptTailer().start()  # external transcript sources always run
    analyst.maybe_start(f"http://{HOST}:{PORT}")  # only when REDOPS_ANALYST_URL set


# ---------------------------------------------------------------------------
# helpers

def _patch(table: str, row_id: int, allowed: set[str], body: dict):
    fields = {k: v for k, v in body.items() if k in allowed}
    if not fields:
        raise HTTPException(400, "no updatable fields supplied")
    conn = db.connect()
    try:
        if not db.row(conn, f"SELECT id FROM {table} WHERE id=?", (row_id,)):
            raise HTTPException(404, f"{table} row {row_id} not found")
        sql = f"UPDATE {table} SET " + ", ".join(f"{k}=?" for k in fields) + " WHERE id=?"
        conn.execute(sql, (*fields.values(), row_id))
        conn.commit()
        return db.row(conn, f"SELECT * FROM {table} WHERE id=?", (row_id,))
    finally:
        conn.close()


def _parse_multipart(ctype: str, body: bytes):
    """Dependency-free multipart parser (python-multipart is not installed)."""
    msg = email.message_from_bytes(
        b"Content-Type: " + ctype.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
    fields, files = {}, {}
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename:
            files[name] = (filename, payload)
        else:
            fields[name] = payload.decode(errors="replace")
    return fields, files


def _workdir(eng: int) -> Path:
    d = WORK_DIR / str(eng)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_workpath(eng: int, rel: str) -> Path:
    """Resolve rel inside the engagement workdir; refuse escapes."""
    base = _workdir(eng).resolve()
    p = (base / rel.lstrip("/")).resolve()
    if base not in p.parents and p != base:
        raise HTTPException(400, "path escapes workdir")
    return p


# ---------------------------------------------------------------------------
# engagement scoping helpers

def _active_or_newest(conn) -> int | None:
    """The engagement new data belongs to: the operator's ACTIVE engagement,
    else the newest. Single source of truth (db._active_engagement_id) so every
    resolver agrees — mismatches here are the root of engagement desync. Also
    validates the active id still exists (a stale pointer falls back to newest)."""
    return db._active_engagement_id(conn)


def _operator_token() -> str:
    """Shared secret proving a request came from the operator's own UI/CLI rather
    than from the agent. Generated once, kept 0600 beside the DB.

    HONEST LIMIT: the agent runs as the same user on the same box, so if it ever
    regains arbitrary local shell it can read this file. This raises the bar for a
    confused or drifting agent — it is NOT a boundary against a hostile one. That
    needs RPT-level separation (own user/container), which is a bigger change."""
    p = db.DATA_DIR / "operator.token"
    try:
        return p.read_text().strip()
    except FileNotFoundError:
        import secrets as _s
        tok = _s.token_urlsafe(32)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(tok)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        return tok


def _is_operator(request: Request) -> bool:
    tok = request.headers.get("x-redops-operator", "")
    return bool(tok) and secrets.compare_digest(tok, _operator_token())


_OWNED_TABLES = {"facts", "leads", "opportunities", "principals", "secrets",
                 "findings", "evidence", "tasks", "credentials", "cred_bindings",
                 "payloads", "detection_rules", "poison", "tool_runs"}


def _owned_or_404(table: str, rid: int) -> None:
    """Guard a by-id read/mutation: the row must belong to the ACTIVE engagement.
    Scoping the LIST endpoints closed the leak reached by query; a bare row id is
    the same leak reached by id, and for a mutation it's worse — a cross-engagement
    WRITE. Rows with a NULL engagement_id are legacy/global and stay reachable."""
    if table not in _OWNED_TABLES:                       # never interpolate freely
        raise HTTPException(500, f"unguardable table {table!r}")
    conn = db.connect()
    try:
        row = db.row(conn, f"SELECT engagement_id FROM {table} WHERE id=?", (rid,))
        if not row or row["engagement_id"] not in (None, _active_or_newest(conn)):
            raise HTTPException(404, "not found")
    finally:
        conn.close()


def _default_engagement() -> int | None:
    """The active engagement, opening its own connection — for list endpoints to
    default to it instead of leaking every engagement's data."""
    conn = db.connect()
    try:
        return _active_or_newest(conn)
    finally:
        conn.close()


def _engagement_for_target(conn, target_id) -> int | None:
    if not target_id:
        return None
    r = db.row(conn, "SELECT engagement_id FROM targets WHERE id=?", (target_id,))
    return r["engagement_id"] if r else None


# ---------------------------------------------------------------------------
# engagements

@app.get("/api/engagements")
def list_engagements(include_archived: int = 0, with_counts: int = 0):
    conn = db.connect()
    try:
        sql = "SELECT * FROM engagements"
        if not include_archived:
            sql += " WHERE archived_at IS NULL"
        sql += " ORDER BY id DESC"
        rows = db.rows(conn, sql)
        if with_counts:
            for e in rows:
                e["counts"] = db.engagement_counts(conn, e["id"])
        return rows
    finally:
        conn.close()


@app.post("/api/engagements", status_code=201)
async def create_engagement(request: Request):
    b = await request.json()
    if not b.get("name"):
        raise HTTPException(400, "name required")
    import ipaddress
    conn = db.connect()
    try:
        scope_text = b.get("scope", "")
        src = b.get("copy_scope_from")
        # "copy scope from" — carry the source engagement's free-text scope column
        # forward when the caller didn't type its own. The structured allow/block
        # lists are copied below, once the row exists.
        if src and not scope_text:
            srow = db.row(conn, "SELECT scope FROM engagements WHERE id=?", (src,))
            if srow:
                scope_text = srow["scope"] or ""
        rid = db.insert(conn, "engagements", {
            "name": b["name"], "scope": scope_text,
            "notes": b.get("notes", ""), "created_at": db.now()})
        # The scope box is what the operator typed as the engagement's boundary —
        # so make it the actual boundary the rest of the app reads: the scope_in
        # ALLOWLIST (guard, exec broker, netsensor BPF, the board's scope panel all
        # read this state key, not the engagements.scope column). Previously the
        # value sat only in that column and nothing on screen reflected it.
        nets, web_pages = [], []
        for tok in (b.get("scope") or "").replace(",", " ").split():
            if tok.startswith(("http://", "https://")):
                try:
                    web_pages.append(webscope.canonical_url(tok))
                except ValueError as exc:
                    raise HTTPException(400, str(exc)) from exc
                continue
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                raise HTTPException(400, f"invalid scope entry: {tok!r}")
        if nets:
            db.set_state(conn, f"scope_in:{rid}", json.dumps([str(n) for n in nets]))
        if web_pages:
            db.set_state(conn, f"web_scope:{rid}",
                         json.dumps(webscope.normalize_scope(web_pages, [])))
        # A scope entry that is a single host (/32, /128) is a target — surface it
        # on the map. A multi-host range is a boundary, not a target, so it only
        # sets scope. Loopback is excluded unless opted in.
        for n in nets:
            if n.num_addresses == 1:
                ip = str(n.network_address)
                if tools.is_loopback(ip) and not tools.loopback_allowed():
                    continue
                if not db.row(conn, "SELECT id FROM targets WHERE engagement_id=? AND ip=?",
                              (rid, ip)):
                    db.insert(conn, "targets", {"engagement_id": rid, "ip": ip,
                              "status": "unidentified", "meta_json": "{}"})
                    _ensure_host_entity(conn, rid, ip, "", "unidentified")
        if src:
            _copy_scope(conn, src, rid)
            _copy_targets(conn, src, rid)
        # a brand-new engagement becomes active AND resets the agent session — same
        # isolation as an explicit switch, so a new engagement never inherits an
        # agent mid-mission on the old one.
        _activate_engagement(conn, rid)
        return db.row(conn, "SELECT * FROM engagements WHERE id=?", (rid,))
    finally:
        conn.close()


@app.patch("/api/engagements/{rid}")
def patch_engagement(rid: int, body: dict):
    if body.get("outcome") and body["outcome"] not in db.ENGAGEMENT_OUTCOMES:
        raise HTTPException(400, f"outcome must be one of {sorted(db.ENGAGEMENT_OUTCOMES)}")
    return _patch("engagements", rid,
                  {"name", "scope", "notes", "outcome", "outcome_note", "lab_time"}, body)


@app.get("/api/active_engagement")
def get_active_engagement():
    conn = db.connect()
    try:
        v = db.get_state(conn, "active_engagement", "")
        return {"id": int(v) if v else None}
    finally:
        conn.close()


def _activate_engagement(conn, eid) -> None:
    """Flip the active engagement AND isolate the agent: cancel the old session's
    in-flight turn BEFORE the switch (so its last tool calls resolve to the OLD
    engagement), then spawn a fresh session bound to the new one. Used by both
    create and explicit-switch so an agent can never carry work across engagements.
    Opt out per Manage -> Settings (acp_session_per_engagement=0)."""
    s = acp.session()
    reset = s is not None and db.setting(
        conn, "acp_session_per_engagement", default="1"
    ).strip().lower() not in ("0", "false", "no", "off")
    if reset:
        try:
            s.cancel()
        except Exception:  # noqa: BLE001
            pass
    db.set_state(conn, "active_engagement", "" if eid is None else str(eid))
    if reset:
        import threading
        threading.Thread(target=s.new_session, daemon=True).start()


@app.put("/api/active_engagement")
def set_active_engagement(body: dict):
    eid = body.get("id")
    conn = db.connect()
    try:
        if eid is not None and not db.row(conn, "SELECT id FROM engagements WHERE id=?", (eid,)):
            raise HTTPException(404, "engagement not found")
        _activate_engagement(conn, eid)
        return {"id": eid}
    finally:
        conn.close()


def _reassign_active_if(conn, eid: int) -> int | None:
    """If `eid` is the active engagement, move active to the newest remaining
    non-archived one (else null). Returns the new active id."""
    cur = db.get_state(conn, "active_engagement", "")
    if not cur or int(cur) != eid:
        return int(cur) if cur else None
    nxt = db.row(conn, "SELECT id FROM engagements WHERE id!=? AND archived_at IS NULL "
                       "ORDER BY id DESC LIMIT 1", (eid,))
    new_id = nxt["id"] if nxt else None
    db.set_state(conn, "active_engagement", "" if new_id is None else str(new_id))
    return new_id


@app.delete("/api/engagements/{rid}")
def delete_engagement(rid: int):
    conn = db.connect()
    try:
        if not db.row(conn, "SELECT id FROM engagements WHERE id=?", (rid,)):
            raise HTTPException(404, "engagement not found")
        new_active = _reassign_active_if(conn, rid)
        db.delete_engagement(conn, rid)
        return {"deleted": rid, "active_engagement": new_active}
    finally:
        conn.close()


@app.post("/api/engagements/{rid}/reset")
def reset_engagement(rid: int):
    conn = db.connect()
    try:
        if not db.row(conn, "SELECT id FROM engagements WHERE id=?", (rid,)):
            raise HTTPException(404, "engagement not found")
        db.reset_engagement(conn, rid)
        return {"reset": rid}
    finally:
        conn.close()


@app.post("/api/engagements/{rid}/archive")
def archive_engagement(rid: int):
    conn = db.connect()
    try:
        if not db.row(conn, "SELECT id FROM engagements WHERE id=?", (rid,)):
            raise HTTPException(404, "engagement not found")
        new_active = _reassign_active_if(conn, rid)
        db.set_archived(conn, rid, True)
        return {"archived": rid, "active_engagement": new_active}
    finally:
        conn.close()


@app.post("/api/engagements/{rid}/unarchive")
def unarchive_engagement(rid: int):
    conn = db.connect()
    try:
        if not db.row(conn, "SELECT id FROM engagements WHERE id=?", (rid,)):
            raise HTTPException(404, "engagement not found")
        db.set_archived(conn, rid, False)
        return {"unarchived": rid}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# targets / services / credentials / findings

@app.get("/api/targets")
def list_targets(engagement_id: int | None = None):
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)   # never leak every engagement's hosts
        return db.rows(conn, "SELECT * FROM targets WHERE engagement_id=? ORDER BY ip", (eng,))
    finally:
        conn.close()


def _ensure_host_entity(conn, eng, ip, hostname="", status="identified"):
    """A registered host should be its own node. Materialize a `host` entity for
    any identified+ target so its drill-in shows the host itself even before any
    fact references it (fogged/unidentified hosts stay off the entity graph).
    Skips hosts already represented by some entity (e.g. a descriptively-named
    DC node) so we never double a host on the graph."""
    if eng is None or status == "unidentified":
        return
    if db.row(conn, "SELECT id FROM entities WHERE engagement_id IS ? AND name LIKE ?",
              (eng, f"%{ip}%")):
        return
    db.upsert_entity(conn, eng, "host", ip, label=hostname or "")


@app.post("/api/targets", status_code=201)
async def create_target(request: Request):
    b = await request.json()
    if not b.get("ip"):
        raise HTTPException(400, "ip required")
    if tools.is_loopback(b["ip"]) and not tools.loopback_allowed():
        raise HTTPException(400, f"{b['ip']} is loopback (your own box) — excluded by default. "
                                 f"Set REDOPS_ALLOW_LOOPBACK=1 to add it as a target on purpose.")
    status = b.get("status", "unidentified")
    if status not in TARGET_STATUSES:
        raise HTTPException(400, f"status must be one of {sorted(TARGET_STATUSES)}")
    eng = b.get("engagement_id")
    conn = db.connect()
    try:
        # Idempotent by (engagement, ip): re-registering a host updates it rather
        # than duplicating, so the agent can report state as it works. Status
        # only advances (never downgrades on a re-register); flagged always wins.
        existing = db.row(conn, "SELECT * FROM targets WHERE engagement_id IS ? AND ip=?",
                          (eng, b["ip"])) if eng is not None else None
        if existing:
            fields = {}
            for k in ("hostname", "os", "role"):
                if b.get(k):
                    fields[k] = b[k]
            rank = {"unidentified": 0, "identified": 1, "foothold": 2, "rooted": 3}
            cur = existing["status"]
            if status == "flagged" or (rank.get(status, 0) > rank.get(cur, 0)):
                fields["status"] = status
            if b.get("meta") is not None:
                fields["meta_json"] = json.dumps(b["meta"])
            if fields:
                sql = "UPDATE targets SET " + ", ".join(f"{k}=?" for k in fields) + " WHERE id=?"
                conn.execute(sql, (*fields.values(), existing["id"]))
                conn.commit()
            final = db.row(conn, "SELECT * FROM targets WHERE id=?", (existing["id"],))
            _ensure_host_entity(conn, eng, final["ip"], final["hostname"], final["status"])
            return final
        rid = db.insert(conn, "targets", {
            "engagement_id": eng, "ip": b["ip"],
            "hostname": b.get("hostname", ""), "os": b.get("os", ""),
            "role": b.get("role", ""), "status": status,
            "meta_json": json.dumps(b.get("meta", {}))})
        _ensure_host_entity(conn, eng, b["ip"], b.get("hostname", ""), status)
        return db.row(conn, "SELECT * FROM targets WHERE id=?", (rid,))
    finally:
        conn.close()


@app.patch("/api/targets/{rid}")
def patch_target(rid: int, body: dict):
    if "status" in body and body["status"] not in TARGET_STATUSES:
        raise HTTPException(400, f"status must be one of {sorted(TARGET_STATUSES)}")
    if "meta" in body:
        body["meta_json"] = json.dumps(body.pop("meta"))
    t = _patch("targets", rid, {"engagement_id", "ip", "hostname", "os", "role", "status", "meta_json"}, body)
    conn = db.connect()
    try:
        _ensure_host_entity(conn, t["engagement_id"], t["ip"], t["hostname"], t["status"])
    finally:
        conn.close()
    return t


@app.get("/api/services")
def list_services(target_id: int | None = None, engagement_id: int | None = None):
    conn = db.connect()
    try:
        if target_id is not None:
            return db.rows(conn, "SELECT * FROM services WHERE target_id=? ORDER BY port", (target_id,))
        eng = engagement_id or _active_or_newest(conn)
        return db.rows(conn, "SELECT s.* FROM services s JOIN targets t ON t.id=s.target_id "
                             "WHERE t.engagement_id=? ORDER BY s.target_id, s.port", (eng,))
    finally:
        conn.close()


@app.put("/api/services/risk")
async def set_service_risk(request: Request):
    """Flag a service as risky to touch — the operator judgement that arbitrary
    shell can't be classified for. '' clears, 'fragile' gates writes to it,
    'gated' gates everything. Enforced at the command chokepoint, so reaching for
    a different tool can't dodge it."""
    b = await request.json()
    risk = (b.get("risk") or "").strip()
    if risk not in ("", "fragile", "gated"):
        raise HTTPException(400, "risk must be '', 'fragile' or 'gated'")
    ip, port = b.get("ip"), b.get("port")
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        if b.get("service_id"):
            rows = conn.execute("UPDATE services SET risk=? WHERE id=?",
                                (risk, b["service_id"])).rowcount
        elif ip and port is not None:
            rows = conn.execute(
                "UPDATE services SET risk=? WHERE port=? AND target_id IN "
                "(SELECT id FROM targets WHERE engagement_id=? AND ip=?)",
                (risk, int(port), eng, ip)).rowcount
        else:
            raise HTTPException(400, "service_id, or ip + port, required")
        if not rows:
            raise HTTPException(404, "no matching service")
        db.add_event(conn, "user", "note",
                     f"[risk] {ip or ('service #' + str(b.get('service_id')))}"
                     f"{':' + str(port) if port is not None else ''} marked "
                     f"{risk or 'normal'}", engagement_id=eng)
        conn.commit()
        return {"ok": True, "risk": risk, "services": rows}
    finally:
        conn.close()


@app.get("/api/services/risk")
def list_service_risk(engagement_id: int | None = None):
    """Assets currently flagged risky, and what that gates."""
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        return [{"ip": ip, "port": port, "risk": risk}
                for ip, port, risk in tools.fragile_assets(conn, eng)]
    finally:
        conn.close()


@app.post("/api/services", status_code=201)
async def create_service(request: Request):
    b = await request.json()
    if b.get("target_id") is None or b.get("port") is None:
        raise HTTPException(400, "target_id and port required")
    conn = db.connect()
    try:
        # upsert, not insert — the same port registered twice (bare, then after a
        # version scan) is ONE service that gained detail, not two services.
        rid = db.upsert_service(conn, b["target_id"], int(b["port"]), b.get("proto", "tcp"), {
            "state": b.get("state", "open"),
            "name": b.get("name", ""), "product": b.get("product", ""),
            "version": b.get("version", ""), "extrainfo": b.get("extrainfo", ""),
            "cpe": b.get("cpe", "")})
        # the target's observable surface may have moved — expire any proof taken
        # against the old fingerprint and record the demotion on the feed, so a
        # finding never silently changes grade under the operator.
        moved = db.refresh_target_staleness(conn, b["target_id"])
        for fid in moved:
            fr = db.row(conn, "SELECT title, confidence FROM findings WHERE id=?", (fid,))
            db.add_event(conn, "user", "trust", f"[trust] {fr['title']!r} demoted to "
                         f"{fr['confidence']} — service banner changed since it was verified",
                         target_id=b["target_id"])
        return db.row(conn, "SELECT * FROM services WHERE id=?", (rid,))
    finally:
        conn.close()


def _mask(v: str) -> str:
    v = v or ""
    return (v[:6] + "…") if len(v) > 7 else v


def _recorrelate(conn, eng) -> list[dict]:
    """Run the correlation engine after any pool/binding change and surface new
    opportunities on the feed. Idempotent (dedup by sig) so safe to call often —
    this is what makes the spray matrix update live as principals/secrets land."""
    if eng is None:
        return []
    new_opps = correlate.run(conn, eng)
    for o in new_opps:
        db.add_event(conn, "user", "note", f"opportunity: {o['title']} (rule {o['rule']})",
                     meta={"opportunity_id": o["id"]}, engagement_id=eng)
    leads.recompute_scores(conn, eng)
    return new_opps


def _binding_label(bv: dict) -> str:
    """Display/entity name for a binding: the principal, else the masked secret."""
    if bv.get("username"):
        return bv["username"]
    return _mask(bv.get("secret") or "") or f"cred#{bv.get('id')}"


def _link_cred_material(conn, eng, ent_id, kind, realm, target_id):
    """Auto-draw the STRUCTURAL edges for a principal/secret so pool nodes cluster
    under their realm/source instead of floating: member-of / candidate-in a realm,
    and found-on its source host. Deterministic — the system owns these, not the
    agent. Links to an existing realm entity of that name (the recon domain node)
    when one exists, else creates it."""
    if realm:
        r = db.row(conn, "SELECT id FROM entities WHERE engagement_id IS ? AND name=? "
                         "ORDER BY id LIMIT 1", (eng, realm))
        rid = r["id"] if r else db.upsert_entity(conn, eng, "network", realm)
        if rid != ent_id:
            db.add_fact(conn, eng, ent_id, "member-of" if kind == "principal" else "candidate-in",
                        rid, "", "observed", "wire-auto")
    if target_id:
        t = db.row(conn, "SELECT ip FROM targets WHERE id=?", (target_id,))
        if t and t["ip"]:
            hid = db.upsert_entity(conn, eng, "host", t["ip"])
            if hid != ent_id:
                db.add_fact(conn, eng, ent_id, "found-on", hid, "", "observed", "wire-auto")


def _secret_label(s) -> str:
    """The graph label IS the full value — this is your localhost engagement and
    hiding your own recovered material from you serves nothing."""
    return s["value"] or f"secret#{s.get('id')}"


def _upsert_principal_entity(conn, eng, p) -> int:
    # meta carries provenance so the inspector can answer "says who?" — origin,
    # source, and the row id to fetch the full record on demand.
    eid = db.upsert_entity(conn, eng, "principal", p["name"], meta={
        "kind": p.get("kind") or "username", "realm": p.get("realm") or "",
        "origin": p.get("origin") or "observed", "source": p.get("source") or "", "pid": p["id"]})
    _link_cred_material(conn, eng, eid, "principal", p.get("realm") or "", p.get("target_id"))
    return eid


def _upsert_secret_entity(conn, eng, s) -> int:
    eid = db.upsert_entity(conn, eng, "secret", _secret_label(s) or f"secret#{s['id']}", meta={
        "kind": s.get("kind") or "password", "origin": s.get("origin") or "observed",
        "source": s.get("source") or "", "sid": s["id"]})
    _link_cred_material(conn, eng, eid, "secret", s.get("realm") or "", s.get("target_id"))
    return eid


def _bridge_binding(conn, bid: int) -> list[dict]:
    """Mirror a binding (and its parts) into the entity/fact graph so the board
    shows them and R3/R8 keep working: `principal`/`secret` nodes (auto-linked to
    their realm/host) for the pools, and — when the binding is confirmed valid on
    a known host — a `credential` node with a `valid-on` fact. Then re-correlate."""
    bv = db.binding_view(conn, "WHERE b.id=?", (bid,))
    if not bv:
        return []
    bv = bv[0]
    eng = bv["engagement_id"]
    if bv.get("principal_id"):
        p = db.row(conn, "SELECT * FROM principals WHERE id=?", (bv["principal_id"],))
        if p:
            _upsert_principal_entity(conn, eng, p)
    if bv.get("secret_id"):
        s = db.row(conn, "SELECT * FROM secrets WHERE id=?", (bv["secret_id"],))
        if s:
            _upsert_secret_entity(conn, eng, s)
    tid = bv.get("target_id")
    if tid and bv.get("status") == "valid":
        cid = db.upsert_entity(conn, eng, "credential", _binding_label(bv))
        t = db.row(conn, "SELECT ip FROM targets WHERE id=?", (tid,))
        if t and t["ip"]:
            hid = db.upsert_entity(conn, eng, "host", t["ip"])
            db.add_fact(conn, eng, cid, "valid-on", hid, "", "confirmed", "user")
    return _recorrelate(conn, eng)


def _secret_kind(legacy: str) -> str:
    return _SECRET_KIND_MAP.get(legacy, "password")


def _infer_origin(source: str, explicit: str | None = None) -> str:
    """Classify how material entered, from an explicit value or the source text —
    so a spray guess never gets the same confidence as recovered loot."""
    if explicit in db.CRED_ORIGINS:
        return explicit
    s = (source or "").lower()
    if any(k in s for k in ("spray", "wordlist", "guess", " list", "rockyou", "common")):
        return "candidate"
    if any(k in s for k in ("config", "dump", "memory", "disassembl", ".txt", "file", "backup", "env")):
        return "recovered"
    return "observed"


@app.get("/api/credentials")
def list_credentials(target_id: int | None = None, engagement_id: int | None = None):
    """Compat view: bindings rendered in the classic {username, secret, kind,
    status, valid} shape. `id` is the binding id (PATCH targets it)."""
    conn = db.connect()
    try:
        if target_id is not None:
            return db.binding_view(conn, "WHERE b.target_id=? ORDER BY b.id", (target_id,))
        # default to the ACTIVE engagement — never leak every engagement's creds.
        eng = engagement_id or _active_or_newest(conn)
        return db.binding_view(conn, "WHERE b.engagement_id=? ORDER BY b.id", (eng,))
    finally:
        conn.close()


@app.post("/api/credentials", status_code=201)
async def create_credential(request: Request):
    """One-shot sugar over the decomposed model. Give a username and/or a secret;
    this creates the principal, the secret and the binding that ties them. Partial
    is first-class: a bare token (secret only) or a username lead (no secret)."""
    b = await request.json()
    username = (b.get("username") or "").strip()
    secret = b.get("secret")
    secret = "" if secret is None else str(secret)
    if not username and not secret:
        raise HTTPException(400, "at least one of username or secret is required")
    kind = b.get("kind", "password")
    realm = b.get("realm", "") or ""
    status = b.get("status")
    conn = db.connect()
    try:
        eng = (b.get("engagement_id") or _engagement_for_target(conn, b.get("target_id"))
               or _active_or_newest(conn))
        tid = b.get("target_id")
        src = b.get("source", "")
        origin = _infer_origin(src, b.get("origin"))
        sev = b.get("source_event_id")
        pid = sid = None
        if username:
            # legacy kind 'principal' meant a username-only lead
            pkind = "service-account" if kind == "principal" else "username"
            pid = db.add_principal(conn, eng, username, kind=pkind, realm=realm,
                                   target_id=tid, source=src, origin=origin, source_event_id=sev)
        if secret:
            sid = db.add_secret(conn, eng, secret, kind=_secret_kind(kind), realm=realm,
                                target_id=tid, source=src, origin=origin, source_event_id=sev)
        bstatus = _BINDING_STATUS_MAP.get(status) if status else (
            "untested" if (pid and sid) else "candidate")
        bid = db.add_binding(conn, eng, principal_id=pid, secret_id=sid, target_id=tid,
                             status=bstatus, source=src)
        new_opps = _bridge_binding(conn, bid)
        out = db.binding_view(conn, "WHERE b.id=?", (bid,))[0]
        out["new_opportunities"] = [o["id"] for o in new_opps]
        return out
    finally:
        conn.close()


@app.patch("/api/credentials/{rid}")
def patch_credential(rid: int, body: dict):
    """Update a binding (id from the compat list). status/target flip it toward
    confirmation; username/secret edits rewrite the linked principal/secret."""
    _owned_or_404('cred_bindings', rid)
    conn = db.connect()
    try:
        bv = db.binding_view(conn, "WHERE b.id=?", (rid,))
        if not bv:
            raise HTTPException(404, f"credential/binding {rid} not found")
        bv = bv[0]
        fields = {}
        if "status" in body or "valid" in body:
            st = body.get("status")
            if st is None and "valid" in body:
                st = "invalid" if not body["valid"] else "valid"
            st = _BINDING_STATUS_MAP.get(st, st)
            if st not in db.BINDING_STATUSES:
                raise HTTPException(400, f"status must map to one of {sorted(db.BINDING_STATUSES)}")
            fields["status"] = st
        if "target_id" in body:
            fields["target_id"] = body["target_id"]
        if "source" in body:
            fields["source"] = body["source"]
        if fields:
            sql = "UPDATE cred_bindings SET " + ", ".join(f"{k}=?" for k in fields) + " WHERE id=?"
            conn.execute(sql, (*fields.values(), rid))
            conn.commit()
        if body.get("username") and bv.get("principal_id"):
            conn.execute("UPDATE principals SET name=? WHERE id=?",
                         (body["username"].strip(), bv["principal_id"]))
            conn.commit()
        if body.get("secret"):
            if bv.get("secret_id"):
                conn.execute("UPDATE secrets SET value=? WHERE id=?",
                             (str(body["secret"]), bv["secret_id"]))
            else:
                # A principal-only binding GAINING a secret is the normal shape of
                # a spray hit. The old code required an existing secret_id, so the
                # secret was silently dropped while status could still flip to
                # 'valid' — leaving a "valid credential" with no secret, which is
                # a lie in the store. Create and attach instead.
                sid = db.add_secret(conn, bv.get("engagement_id"), str(body["secret"]),
                                    kind=body.get("kind") or "password",
                                    realm=bv.get("realm") or "",
                                    target_id=bv.get("target_id"),
                                    source=body.get("source") or "operator")
                conn.execute("UPDATE cred_bindings SET secret_id=? WHERE id=?", (sid, rid))
                bv["secret_id"] = sid
            conn.commit()
        # INVARIANT: a binding cannot be 'valid' without both halves. Refuse the
        # write rather than storing a credential that cannot be used.
        cur = db.row(conn, "SELECT principal_id, secret_id, status FROM cred_bindings "
                           "WHERE id=?", (rid,))
        if cur and cur["status"] == "valid" and not (cur["principal_id"] and cur["secret_id"]):
            conn.execute("UPDATE cred_bindings SET status='partial' WHERE id=?", (rid,))
            conn.commit()
            raise HTTPException(
                400, "a binding cannot be 'valid' without both a principal and a secret — "
                     "supply the missing half (status left as 'partial')")
        _bridge_binding(conn, rid)
        return db.binding_view(conn, "WHERE b.id=?", (rid,))[0]
    finally:
        conn.close()


# --- decomposed credential endpoints: principals / secrets / bindings -------

@app.get("/api/principals")
def list_principals(engagement_id: int | None = None, target_id: int | None = None):
    conn = db.connect()
    try:
        if target_id is not None:
            return db.rows(conn, "SELECT * FROM principals WHERE target_id=? ORDER BY id", (target_id,))
        eng = engagement_id or _active_or_newest(conn)
        return db.rows(conn, "SELECT * FROM principals WHERE engagement_id=? AND status='active' "
                       "ORDER BY id", (eng,))
    finally:
        conn.close()


@app.post("/api/principals", status_code=201)
async def create_principal(request: Request):
    """Record an identity (a harvested username, account, email, key-id) with no
    secret yet — raw feed for the spray matrix."""
    b = await request.json()
    name = (b.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    conn = db.connect()
    try:
        eng = (b.get("engagement_id") or _engagement_for_target(conn, b.get("target_id"))
               or _active_or_newest(conn))
        pid = db.add_principal(conn, eng, name, kind=b.get("kind", "username"),
                               realm=b.get("realm", "") or "", target_id=b.get("target_id"),
                               source=b.get("source", ""), notes=b.get("notes", ""),
                               origin=_infer_origin(b.get("source", ""), b.get("origin")),
                               source_event_id=b.get("source_event_id"))
        _upsert_principal_entity(conn, eng, db.row(conn, "SELECT * FROM principals WHERE id=?", (pid,)))
        new_opps = _recorrelate(conn, eng)
        out = db.row(conn, "SELECT * FROM principals WHERE id=?", (pid,))
        out["new_opportunities"] = [o["id"] for o in new_opps]
        return out
    finally:
        conn.close()


@app.patch("/api/principals/{pid}")
def patch_principal(pid: int, body: dict):
    p = _patch("principals", pid,
               {"name", "kind", "realm", "target_id", "source", "notes", "status", "origin"}, body)
    conn = db.connect()
    try:
        _recorrelate(conn, p["engagement_id"])
    finally:
        conn.close()
    return p


@app.delete("/api/principals/{pid}", status_code=204)
def delete_principal(pid: int):
    _owned_or_404('principals', pid)
    conn = db.connect()
    try:
        conn.execute("DELETE FROM cred_bindings WHERE principal_id=?", (pid,))
        conn.execute("DELETE FROM principals WHERE id=?", (pid,))
        conn.commit()
    finally:
        conn.close()


@app.get("/api/secrets")
def list_secrets(engagement_id: int | None = None, target_id: int | None = None):
    conn = db.connect()
    try:
        if target_id is not None:
            return db.rows(conn, "SELECT * FROM secrets WHERE target_id=? ORDER BY id", (target_id,))
        eng = engagement_id or _active_or_newest(conn)
        return db.rows(conn, "SELECT * FROM secrets WHERE engagement_id=? AND status='active' "
                       "ORDER BY id", (eng,))
    finally:
        conn.close()


@app.post("/api/secrets", status_code=201)
async def create_secret(request: Request):
    """Record auth material (a password candidate, hash, ticket, key, token) with
    no owning identity yet — the other axis of the spray matrix."""
    b = await request.json()
    value = b.get("value")
    value = "" if value is None else str(value)
    if not value:
        raise HTTPException(400, "value is required")
    conn = db.connect()
    try:
        eng = (b.get("engagement_id") or _engagement_for_target(conn, b.get("target_id"))
               or _active_or_newest(conn))
        skind = b.get("kind", "password")
        skind = skind if skind in db.SECRET_KINDS else _secret_kind(skind)
        sid = db.add_secret(conn, eng, value, kind=skind, realm=b.get("realm", "") or "",
                            target_id=b.get("target_id"), source=b.get("source", ""),
                            notes=b.get("notes", ""),
                            origin=_infer_origin(b.get("source", ""), b.get("origin")),
                            source_event_id=b.get("source_event_id"))
        _upsert_secret_entity(conn, eng, db.row(conn, "SELECT * FROM secrets WHERE id=?", (sid,)))
        new_opps = _recorrelate(conn, eng)
        out = db.row(conn, "SELECT * FROM secrets WHERE id=?", (sid,))
        out["new_opportunities"] = [o["id"] for o in new_opps]
        return out
    finally:
        conn.close()


@app.patch("/api/secrets/{sid}")
def patch_secret(sid: int, body: dict):
    s = _patch("secrets", sid,
               {"value", "kind", "realm", "target_id", "source", "notes", "status", "origin"}, body)
    conn = db.connect()
    try:
        _recorrelate(conn, s["engagement_id"])
    finally:
        conn.close()
    return s


@app.delete("/api/secrets/{sid}", status_code=204)
def delete_secret(sid: int):
    _owned_or_404('secrets', sid)
    conn = db.connect()
    try:
        conn.execute("DELETE FROM cred_bindings WHERE secret_id=?", (sid,))
        conn.execute("DELETE FROM secrets WHERE id=?", (sid,))
        conn.commit()
    finally:
        conn.close()


@app.get("/api/bindings")
def list_bindings(engagement_id: int | None = None):
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        return db.binding_view(conn, "WHERE b.engagement_id=? ORDER BY b.id", (eng,))
    finally:
        conn.close()


@app.post("/api/bindings", status_code=201)
async def create_binding(request: Request):
    """Assert a pairing between an existing principal and/or secret (confirm a
    spray hit, or record a known credential from its parts)."""
    b = await request.json()
    pid, sid = b.get("principal_id"), b.get("secret_id")
    if not pid and not sid:
        raise HTTPException(400, "principal_id and/or secret_id is required")
    conn = db.connect()
    try:
        eng = b.get("engagement_id")
        if eng is None:
            ref = db.row(conn, "SELECT engagement_id FROM principals WHERE id=?", (pid,)) if pid \
                else db.row(conn, "SELECT engagement_id FROM secrets WHERE id=?", (sid,))
            eng = (ref or {}).get("engagement_id") or _active_or_newest(conn)
        status = _BINDING_STATUS_MAP.get(b.get("status"), b.get("status") or "untested")
        bid = db.add_binding(conn, eng, principal_id=pid, secret_id=sid,
                             target_id=b.get("target_id"), status=status, source=b.get("source", ""))
        new_opps = _bridge_binding(conn, bid)
        out = db.binding_view(conn, "WHERE b.id=?", (bid,))[0]
        out["new_opportunities"] = [o["id"] for o in new_opps]
        return out
    finally:
        conn.close()


@app.patch("/api/bindings/{bid}")
def patch_binding(bid: int, body: dict):
    return patch_credential(bid, body)


# ---------------------------------------------------------------------------
# AI-artifact stores: payloads / detection rules / poison (schema v10)

@app.get("/api/payloads")
def list_payloads(engagement_id: int | None = None):
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        return db.rows(conn, "SELECT * FROM payloads WHERE engagement_id=? ORDER BY id DESC", (eng,))
    finally:
        conn.close()


@app.post("/api/payloads", status_code=201)
async def create_payload(request: Request):
    b = await request.json()
    if not b.get("technique"):
        raise HTTPException(400, "technique required")
    outcome = b.get("outcome", "untried")
    if outcome not in PAYLOAD_OUTCOMES:
        raise HTTPException(400, f"outcome must be one of {sorted(PAYLOAD_OUTCOMES)}")
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        rid = db.insert(conn, "payloads", {
            "engagement_id": eng, "technique": b["technique"],
            "target_model": b.get("target_model", ""), "target_ref": b.get("target_ref", ""),
            "guardrail_defeated": b.get("guardrail_defeated", ""), "body": b.get("body", ""),
            "outcome": outcome, "notes": b.get("notes", ""), "created_at": db.now()})
        return db.row(conn, "SELECT * FROM payloads WHERE id=?", (rid,))
    finally:
        conn.close()


@app.patch("/api/payloads/{rid}")
def patch_payload(rid: int, body: dict):
    if "outcome" in body and body["outcome"] not in PAYLOAD_OUTCOMES:
        raise HTTPException(400, f"outcome must be one of {sorted(PAYLOAD_OUTCOMES)}")
    return _patch("payloads", rid, {"technique", "target_model", "target_ref",
                  "guardrail_defeated", "body", "outcome", "notes", "engagement_id"}, body)


@app.get("/api/detection_rules")
def list_detection_rules(engagement_id: int | None = None):
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        return db.rows(conn, "SELECT * FROM detection_rules WHERE engagement_id=? ORDER BY id", (eng,))
    finally:
        conn.close()


@app.post("/api/detection_rules", status_code=201)
async def create_detection_rule(request: Request):
    b = await request.json()
    if not b.get("name"):
        raise HTTPException(400, "name required")
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        rid = db.insert(conn, "detection_rules", {
            "engagement_id": eng, "name": b["name"],
            "source_system": b.get("source_system", ""),
            "match_mechanism": b.get("match_mechanism", ""),
            "blind_spot": b.get("blind_spot", ""), "evasion": b.get("evasion", ""),
            "fired": 1 if b.get("fired") else 0, "notes": b.get("notes", ""),
            "created_at": db.now()})
        if b.get("fired") and eng:
            correlate.update_detected(conn, eng)
        return db.row(conn, "SELECT * FROM detection_rules WHERE id=?", (rid,))
    finally:
        conn.close()


@app.patch("/api/detection_rules/{rid}")
def patch_detection_rule(rid: int, body: dict):
    row = _patch("detection_rules", rid, {"name", "source_system", "match_mechanism",
                 "blind_spot", "evasion", "fired", "notes", "engagement_id"}, body)
    if body.get("fired") and row.get("engagement_id"):
        conn = db.connect()
        try:
            correlate.update_detected(conn, row["engagement_id"])
        finally:
            conn.close()
    return row


@app.get("/api/poison")
def list_poison(engagement_id: int | None = None):
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        return db.rows(conn, "SELECT * FROM poison WHERE engagement_id=? ORDER BY id DESC", (eng,))
    finally:
        conn.close()


@app.post("/api/poison", status_code=201)
async def create_poison(request: Request):
    b = await request.json()
    if not b.get("location"):
        raise HTTPException(400, "location required (where you planted it)")
    store = b.get("store_type", "other")
    if store not in POISON_STORES:
        raise HTTPException(400, f"store_type must be one of {sorted(POISON_STORES)}")
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        rid = db.insert(conn, "poison", {
            "engagement_id": eng, "store_type": store, "location": b["location"],
            "payload_id": b.get("payload_id"), "planted_at": db.now(),
            "live": 1 if b.get("live", True) else 0,
            "verify_method": b.get("verify_method", ""),
            "cleanup_done": 1 if b.get("cleanup_done") else 0, "notes": b.get("notes", "")})
        return db.row(conn, "SELECT * FROM poison WHERE id=?", (rid,))
    finally:
        conn.close()


@app.patch("/api/poison/{rid}")
def patch_poison(rid: int, body: dict):
    if "store_type" in body and body["store_type"] not in POISON_STORES:
        raise HTTPException(400, f"store_type must be one of {sorted(POISON_STORES)}")
    return _patch("poison", rid, {"store_type", "location", "payload_id", "live",
                  "verify_method", "cleanup_done", "notes", "engagement_id"}, body)


@app.get("/api/findings")
def list_findings(target_id: int | None = None, engagement_id: int | None = None):
    conn = db.connect()
    try:
        if target_id is not None:
            return db.rows(conn, "SELECT * FROM findings WHERE target_id=? ORDER BY id", (target_id,))
        eng = engagement_id or _active_or_newest(conn)
        return db.rows(conn, "SELECT * FROM findings WHERE engagement_id=? ORDER BY id", (eng,))
    finally:
        conn.close()


@app.post("/api/findings", status_code=201)
async def create_finding(request: Request):
    b = await request.json()
    if not b.get("title"):
        raise HTTPException(400, "title required")
    sev = b.get("severity", "info")
    if sev not in SEVERITIES:
        raise HTTPException(400, f"severity must be one of {sorted(SEVERITIES)}")
    status = b.get("status", "open")
    if status not in db.FINDING_STATUSES:
        raise HTTPException(400, f"status must be one of {sorted(db.FINDING_STATUSES)} — "
                            "confidence (claimed/observed/live-verified) is derived from "
                            "verifications, not typed here")
    mech = (b.get("mechanism") or "").strip()
    if mech and mech not in db.MECHANISMS:
        raise HTTPException(400, f"mechanism must be one of {sorted(db.MECHANISMS)}")
    conn = db.connect()
    try:
        eng = (b.get("engagement_id") or _engagement_for_target(conn, b.get("target_id"))
               or _active_or_newest(conn))
        rid = db.insert(conn, "findings", {
            "engagement_id": eng, "target_id": b.get("target_id"), "title": b["title"],
            "severity": sev, "description": b.get("description", ""),
            "status": status, "mechanism": mech, "created_at": db.now()})
        return db.row(conn, "SELECT * FROM findings WHERE id=?", (rid,))
    finally:
        conn.close()


@app.patch("/api/findings/{rid}")
def patch_finding(rid: int, body: dict):
    _owned_or_404('findings', rid)
    if "severity" in body and body["severity"] not in SEVERITIES:
        raise HTTPException(400, f"severity must be one of {sorted(SEVERITIES)}")
    if "status" in body and body["status"] not in db.FINDING_STATUSES:
        raise HTTPException(400, f"status must be one of {sorted(db.FINDING_STATUSES)}")
    if body.get("mechanism") and body["mechanism"] not in db.MECHANISMS:
        raise HTTPException(400, f"mechanism must be one of {sorted(db.MECHANISMS)}")
    # `confidence` and `stale` are DERIVED from verification events, never typed.
    # Accepting them on this patch is how a source-only claim gets to read as
    # proven with nothing backing it — the exact failure the verification table
    # exists to prevent. Silently drop them; use /verify to move trust.
    return _patch("findings", rid,
                  {"target_id", "title", "severity", "description", "status", "mechanism"}, body)


@app.get("/api/findings/{rid}/verifications")
def finding_verifications(rid: int):
    conn = db.connect()
    try:
        return db.rows(conn, "SELECT * FROM verifications WHERE finding_id=? "
                       "ORDER BY ts DESC, id DESC", (rid,))
    finally:
        conn.close()


@app.post("/api/findings/{rid}/verify", status_code=201)
async def verify_finding(rid: int, request: Request):
    """Record a verification event and re-derive the finding's trust. `method`
    'callback' cites an observed inbound flow (`flow_id`) as the out-of-band
    proof the effect fired — the live-network analogue of a lab RestartCount.
    Status is NOT changed here: recording that a callback fired is an
    observation; concluding the finding is refuted or verified is a judgement,
    kept as a separate deliberate transition."""
    b = await request.json()
    result = b.get("result")
    if not result:
        raise HTTPException(400, "result required: reproduced | not-reproduced | partial | errored")
    flow_id = b.get("flow_id")
    conn = db.connect()
    try:
        # all callback/flow validation (flow required, inbound, established, same
        # target + engagement) lives in db.add_verification so the CLI, MCP and
        # this endpoint enforce it identically — one gate, not three.
        try:
            v = db.add_verification(conn, rid, result,
                                    method=b.get("method", "manual"), note=b.get("note", ""),
                                    agent=b.get("agent", "user"), flow_id=flow_id)
        except ValueError as e:
            raise HTTPException(400, str(e))
        except sqlite3.IntegrityError:
            raise HTTPException(409, f"flow {flow_id} is already cited as proof of another "
                                "finding — one callback proves one claim")
        f = db.row(conn, "SELECT title, target_id FROM findings WHERE id=?", (rid,))
        cite = f" (callback flow #{flow_id})" if b.get("method") == "callback" else ""
        contested = " — CONTESTED (fired and did not reproduce)" if v.get("contested") else ""
        db.add_event(conn, b.get("agent", "user"), "verify",
                     f"[verify] {f['title']!r}: {v['result']} via {v['method']}{cite} "
                     f"— now {v['confidence']}{contested}", target_id=f["target_id"])
        return v
    finally:
        conn.close()


@app.get("/api/callbacks")
def pending_callbacks(engagement_id: int | None = None):
    """Observed inbound flows not yet cited as proof of anything — a queue, not
    an inference. Each carries the open findings on the same target as candidate
    claims it might prove; where exactly one exists it is suggested, but the
    operator or agent decides. Guessing which claim a packet proves is the
    overclaim this whole path is built to avoid."""
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        if not eng:
            return []
        return db.pending_callbacks(conn, eng)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# events + SSE

@app.get("/api/events")
def list_events(limit: int = 200, source: str | None = None, kind: str | None = None,
                target_id: int | None = None, before_id: int | None = None,
                engagement_id: int | None = None, feed: bool = False):
    # scope to the active engagement by default so the feed clears/refilters on a
    # switch and never mixes engagements (a target_id query is its own scope).
    if engagement_id is None and target_id is None:
        engagement_id = _default_engagement()
    sql, params = "SELECT * FROM events WHERE 1=1", []
    if feed:
        # the text feed excludes map-only wire churn (flow open/close) — a packet
        # flood must not bury the agent's activity in the window.
        sql += " AND kind NOT IN ('flow','flowclose')"
    if source:
        sql += " AND source=?"; params.append(source)
    if kind:
        sql += " AND kind=?"; params.append(kind)
    if target_id is not None:
        sql += " AND target_id=?"; params.append(target_id)
    if engagement_id is not None:
        sql += " AND engagement_id=?"; params.append(engagement_id)
    if before_id is not None:
        sql += " AND id<?"; params.append(before_id)
    sql += " ORDER BY id DESC LIMIT ?"; params.append(min(limit, 1000))
    conn = db.connect()
    try:
        return db.rows(conn, sql, params)
    finally:
        conn.close()


@app.post("/api/webchat/capture", status_code=201)
async def capture_webchat(request: Request):
    """Store a complete browser exchange for one engagement-scoped page."""
    b = await request.json()
    eid = b.get("engagement_id")
    if not isinstance(eid, int):
        raise HTTPException(400, "engagement_id required")
    source_id = str(b.get("source_id") or "").strip()
    if not source_id or len(source_id) > 160:
        raise HTTPException(400, "source_id required (max 160 characters)")
    page_url = str(b.get("page_url") or "")
    action = b.get("action")
    if not isinstance(action, dict):
        raise HTTPException(400, "action object required")
    conn = db.connect()
    try:
        if not db.row(conn, "SELECT id FROM engagements WHERE id=?", (eid,)):
            raise HTTPException(404, "engagement not found")
        raw_scope = db.get_state(conn, f"web_scope:{eid}", "")
        web = json.loads(raw_scope) if raw_scope else {"pages": [], "api_prefixes": []}
        if not webscope.page_allowed(page_url, web):
            raise HTTPException(403, "page URL outside web-chat scope")
        if action.get("type") == "api" and not webscope.api_allowed(
                str(action.get("url") or ""), web):
            raise HTTPException(403, "API URL outside web-chat scope")
        payload = {"source_id": source_id, "page_url": page_url,
                   "action": action, "output": b.get("output"),
                   "network": b.get("network"), "artifact_hashes": b.get("artifact_hashes")}
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        previous = db.row(conn, """SELECT * FROM events
            WHERE engagement_id=? AND kind='webchat'
              AND json_extract(meta_json, '$.source_id')=? LIMIT 1""",
                          (eid, source_id))
        if previous:
            if previous["text"] != text:
                raise HTTPException(409, "source_id already has different content")
            return previous
        rid = db.add_event(conn, "agent", "webchat", text,
                           meta={"source_id": source_id, "page_url": page_url},
                           engagement_id=eid)
        return db.row(conn, "SELECT * FROM events WHERE id=?", (rid,))
    finally:
        conn.close()


@app.post("/api/events", status_code=201)
async def create_event(request: Request):
    b = await request.json()
    if not b.get("text"):
        raise HTTPException(400, "text required")
    source = b.get("source", "agent")
    kind = b.get("kind", "note")
    if source not in EVENT_SOURCES:
        raise HTTPException(400, f"source must be one of {sorted(EVENT_SOURCES)}")
    if kind not in EVENT_KINDS:
        raise HTTPException(400, f"kind must be one of {sorted(EVENT_KINDS)}")
    conn = db.connect()
    try:
        rid = db.add_event(conn, source, kind, b["text"],
                           target_id=b.get("target_id"), meta=b.get("meta"))
        return db.row(conn, "SELECT * FROM events WHERE id=?", (rid,))
    finally:
        conn.close()


def _change_sig(conn) -> str:
    t = conn.execute("SELECT group_concat(id || ':' || status, ',') FROM tasks").fetchone()[0] or ""
    o = conn.execute("SELECT group_concat(id || ':' || status || ':' || value, ',') FROM objectives").fetchone()[0] or ""
    f = conn.execute("SELECT coalesce(max(id),0) || ':' || group_concat(DISTINCT status) FROM facts").fetchone()[0] or ""
    p = conn.execute("SELECT group_concat(id || ':' || status, ',') FROM opportunities").fetchone()[0] or ""
    l = conn.execute("SELECT group_concat(id || ':' || status || ':' || score, ',') FROM leads").fetchone()[0] or ""
    s = conn.execute("SELECT group_concat(engagement_id || ':' || updated_at, ',') FROM sitrep").fetchone()[0] or ""
    return "|".join((t, o, f, p, l, s))


@app.get("/api/stream")
async def stream():
    async def gen():
        conn = db.connect()
        try:
            last_id = (conn.execute("SELECT max(id) FROM events").fetchone()[0] or 0)
            last_sig = _change_sig(conn)
            last_beat = asyncio.get_event_loop().time()
            yield ": connected\n\n"
            while True:
                rows = db.rows(conn, "SELECT * FROM events WHERE id>? ORDER BY id", (last_id,))
                for r in rows:
                    last_id = r["id"]
                    yield f"data: {json.dumps({'type': 'event', 'event': r})}\n\n"
                sig = _change_sig(conn)
                if sig != last_sig:
                    last_sig = sig
                    yield f"data: {json.dumps({'type': 'change', 'what': 'tasks/objectives/intel'})}\n\n"
                now = asyncio.get_event_loop().time()
                if now - last_beat >= 15:
                    last_beat = now
                    yield ": ping\n\n"
                await asyncio.sleep(1)
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            conn.close()

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# evidence

@app.post("/api/evidence", status_code=201)
async def upload_evidence(request: Request):
    ctype = request.headers.get("content-type", "")
    if "multipart/form-data" not in ctype:
        raise HTTPException(400, "multipart/form-data required")
    fields, files = _parse_multipart(ctype, await request.body())
    if "file" not in files:
        raise HTTPException(400, "file field required")
    filename, payload = files["file"]
    ext = Path(filename).suffix.lower()
    kind = fields.get("kind") or ("screenshot" if ext in IMG_EXTS else
                                  "output" if ext in TXT_EXTS else "file")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name) or "blob"
    stored = f"{uuid.uuid4().hex[:12]}_{safe}"
    (db.EVIDENCE_DIR / stored).write_bytes(payload)
    conn = db.connect()
    try:
        fid = int(fields["finding_id"]) if fields.get("finding_id") else None
        tid = int(fields["target_id"]) if fields.get("target_id") else None
        eng = int(fields["engagement_id"]) if fields.get("engagement_id") else None
        if eng is None and tid:
            eng = _engagement_for_target(conn, tid)
        if eng is None and fid:
            fr = db.row(conn, "SELECT target_id FROM findings WHERE id=?", (fid,))
            eng = _engagement_for_target(conn, fr["target_id"]) if fr else None
        if eng is None:
            eng = _active_or_newest(conn)
        rid = db.insert(conn, "evidence", {
            "engagement_id": eng, "finding_id": fid, "target_id": tid,
            "kind": kind, "path": stored,
            "caption": fields.get("caption", ""), "ts": db.now()})
        return db.row(conn, "SELECT * FROM evidence WHERE id=?", (rid,))
    finally:
        conn.close()


@app.get("/api/evidence")
def list_evidence(finding_id: int | None = None, target_id: int | None = None,
                  engagement_id: int | None = None):
    # a finding/target query is its own scope; otherwise default to the engagement
    if finding_id is None and target_id is None and engagement_id is None:
        engagement_id = _default_engagement()
    sql, params = "SELECT * FROM evidence WHERE 1=1", []
    if finding_id is not None:
        sql += " AND finding_id=?"; params.append(finding_id)
    if target_id is not None:
        sql += " AND target_id=?"; params.append(target_id)
    if engagement_id is not None:
        sql += " AND engagement_id=?"; params.append(engagement_id)
    sql += " ORDER BY id DESC"
    conn = db.connect()
    try:
        return db.rows(conn, sql, params)
    finally:
        conn.close()


@app.get("/api/evidence/{rid}/file")
def evidence_file(rid: int):
    _owned_or_404('evidence', rid)
    conn = db.connect()
    try:
        ev = db.row(conn, "SELECT * FROM evidence WHERE id=?", (rid,))
    finally:
        conn.close()
    if not ev:
        raise HTTPException(404, "evidence not found")
    path = (db.EVIDENCE_DIR / ev["path"]).resolve()
    if not path.is_file() or db.EVIDENCE_DIR.resolve() not in path.parents:
        raise HTTPException(404, "file not found")
    return FileResponse(path)


# ---------------------------------------------------------------------------
# objectives / tasks

@app.get("/api/objectives")
def list_objectives(engagement_id: int | None = None):
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        return db.rows(conn, "SELECT * FROM objectives WHERE engagement_id=? ORDER BY id", (eng,))
    finally:
        conn.close()


@app.post("/api/objectives", status_code=201)
async def create_objective(request: Request):
    b = await request.json()
    if not b.get("text"):
        raise HTTPException(400, "text required")
    conn = db.connect()
    try:
        rid = db.insert(conn, "objectives", {
            "engagement_id": b.get("engagement_id"), "text": b["text"],
            "status": b.get("status", "open"), "value": b.get("value", ""),
            "target_id": b.get("target_id"), "evidence_id": b.get("evidence_id")})
        return db.row(conn, "SELECT * FROM objectives WHERE id=?", (rid,))
    finally:
        conn.close()


@app.patch("/api/objectives/{rid}")
def patch_objective(rid: int, body: dict):
    return _patch("objectives", rid,
                  {"text", "status", "value", "engagement_id", "target_id", "evidence_id"}, body)


@app.get("/api/tasks")
def list_tasks(status: str | None = None, engagement_id: int | None = None):
    engagement_id = engagement_id or _default_engagement()   # scope; keep global (null) tasks
    sql, params = "SELECT * FROM tasks WHERE 1=1", []
    if status:
        sql += " AND status=?"; params.append(status)
    if engagement_id is not None:
        sql += " AND (engagement_id=? OR engagement_id IS NULL)"; params.append(engagement_id)
    sql += " ORDER BY id" + ("" if status else " DESC")
    conn = db.connect()
    try:
        return db.rows(conn, sql, params)
    finally:
        conn.close()


@app.post("/api/tasks", status_code=201)
async def create_task(request: Request):
    b = await request.json()
    if not b.get("text"):
        raise HTTPException(400, "text required")
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        rid = db.insert(conn, "tasks", {
            "engagement_id": eng, "author": b.get("author", "user"), "text": b["text"],
            "status": "pending", "created_at": db.now(), "done_at": None})
        return db.row(conn, "SELECT * FROM tasks WHERE id=?", (rid,))
    finally:
        conn.close()


@app.post("/api/tasks/{rid}/done")
def task_done(rid: int):
    _owned_or_404('tasks', rid)
    conn = db.connect()
    try:
        if not db.row(conn, "SELECT id FROM tasks WHERE id=?", (rid,)):
            raise HTTPException(404, f"task {rid} not found")
        conn.execute("UPDATE tasks SET status='done', done_at=? WHERE id=?", (db.now(), rid))
        conn.commit()
        return db.row(conn, "SELECT * FROM tasks WHERE id=?", (rid,))
    finally:
        conn.close()


@app.get("/api/turns")
def get_turns(limit: int = 20, before_turn: str | None = None,
              engagement_id: int | None = None):
    """Recent agent turns, assembled from events: wire events grouped by
    meta.turnId; a source=user note becomes its following turn's prompt;
    everything else lands in an 'ungrouped' pseudo-turn."""
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)   # this engagement's turns only
        rows = db.rows(conn, "SELECT * FROM events WHERE engagement_id=? OR engagement_id IS NULL "
                             "ORDER BY id", (eng,))
    finally:
        conn.close()
    groups: dict[str, list] = {}
    user_notes, ungrouped = [], []
    for e in rows:
        try:
            meta = json.loads(e.pop("meta_json") or "{}")
        except json.JSONDecodeError:
            meta = {}
        e["meta"] = meta
        tid = meta.get("turnId")
        if e["source"] in ("wire", "acp") and tid:
            groups.setdefault(str(tid), []).append(e)
        elif e["source"] == "user" and e["kind"] == "note":
            user_notes.append(e)
        else:
            ungrouped.append(e)

    turn_min = {t: min(e["id"] for e in evs) for t, evs in groups.items()}
    sorted_mins = sorted(turn_min.values())
    user_text: dict[str, str] = {}
    min_to_turn = {m: t for t, m in turn_min.items()}
    for n in user_notes:
        nxt = next((m for m in sorted_mins if m > n["id"]), None)
        if nxt is not None and nxt in min_to_turn:
            user_text.setdefault(min_to_turn[nxt], n["text"])
        else:
            ungrouped.append(n)

    if ungrouped:
        groups["ungrouped"] = ungrouped
        # sort the catch-all by its NEWEST event so live unattributed events surface
        turn_min["ungrouped"] = max(e["id"] for e in ungrouped)

    if before_turn is not None and before_turn in turn_min:
        cutoff = turn_min[before_turn]
        groups = {t: evs for t, evs in groups.items() if turn_min[t] < cutoff}

    turns = sorted(groups.items(), key=lambda kv: -turn_min[kv[0]])[:max(1, min(limit, 100))]
    return {"turns": [{"turn_id": t, "user_text": user_text.get(t, ""), "events": evs}
                      for t, evs in turns]}


# ---------------------------------------------------------------------------
# leads + worklist (v6)

LEAD_STATUSES = {"open", "promoted", "ruled-out", "dismissed"}


@app.get("/api/leads")
def list_leads(engagement_id: int | None = None, status: str | None = None,
               category: str | None = None):
    engagement_id = engagement_id or _default_engagement()   # never leak all engagements
    sql, params = "SELECT * FROM leads WHERE 1=1", []
    if engagement_id is not None:
        sql += " AND engagement_id=?"; params.append(engagement_id)
    if status:
        sql += " AND status=?"; params.append(status)
    if category:
        sql += " AND category=?"; params.append(category)
    sql += " ORDER BY score DESC, id DESC LIMIT 500"
    conn = db.connect()
    try:
        return db.rows(conn, sql, params)
    finally:
        conn.close()


@app.post("/api/leads", status_code=201)
async def create_lead(request: Request):
    b = await request.json()
    if not b.get("observation"):
        raise HTTPException(400, "observation required")
    cat = b.get("category", "anomaly")
    if cat not in leads.CATEGORIES:
        raise HTTPException(400, f"category must be one of {sorted(leads.CATEGORIES)}")
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _current_engagement(conn)
        rid = db.insert(conn, "leads", {
            "engagement_id": eng, "observation": b["observation"], "category": cat,
            "candidate_vector": b.get("candidate_vector", ""),
            "source": b.get("source", "agent"), "source_event_id": b.get("source_event_id"),
            "fact_ids": json.dumps(b.get("fact_ids", [])), "status": "open",
            "created_at": db.now(), "updated_at": db.now()})
        leads.recompute_scores(conn, eng)
        return db.row(conn, "SELECT * FROM leads WHERE id=?", (rid,))
    finally:
        conn.close()


def _set_lead_status(rid: int, status: str):
    conn = db.connect()
    try:
        l = db.row(conn, "SELECT * FROM leads WHERE id=?", (rid,))
        if not l:
            raise HTTPException(404, f"lead {rid} not found")
        conn.execute("UPDATE leads SET status=?, updated_at=? WHERE id=?", (status, db.now(), rid))
        conn.commit()
        if l["engagement_id"]:
            leads.recompute_scores(conn, l["engagement_id"])
        return db.row(conn, "SELECT * FROM leads WHERE id=?", (rid,))
    finally:
        conn.close()


@app.post("/api/leads/{rid}/dismiss")
def lead_dismiss(rid: int):
    _owned_or_404('leads', rid)
    return _set_lead_status(rid, "dismissed")


@app.post("/api/leads/{rid}/rule-out")
def lead_rule_out(rid: int):
    _owned_or_404('leads', rid)
    return _set_lead_status(rid, "ruled-out")


@app.post("/api/leads/{rid}/promote")
async def lead_promote(rid: int, request: Request):
    """Structure a hunch into fact(s) - never duplicates an existing fact
    (fact insert dedups). Returns the lead and new opportunity ids."""
    b = await request.json() if (await request.body()) else {}
    conn = db.connect()
    try:
        lead = db.row(conn, "SELECT * FROM leads WHERE id=?", (rid,))
        if not lead:
            raise HTTPException(404, f"lead {rid} not found")
        eng = lead["engagement_id"] or _current_engagement(conn)
        fids = set(json.loads(lead["fact_ids"] or "[]"))
        for fdef in b.get("facts", []):
            sid = db.upsert_entity(conn, eng, fdef.get("subject_type") or _guess_type(fdef["subject_name"]),
                                   fdef["subject_name"])
            oid = None
            if fdef.get("object_name"):
                oid = db.upsert_entity(conn, eng, fdef.get("object_type") or _guess_type(fdef["object_name"]),
                                       fdef["object_name"])
            fid = db.add_fact(conn, eng, sid, fdef["predicate"], oid,
                              fdef.get("object_text", ""), fdef.get("stage", "claimed"),
                              "agent")
            fids.add(fid)
        if not fids:
            raise HTTPException(400, "nothing to promote: pass facts or link fact_ids first")
        conn.execute("UPDATE leads SET status='promoted', fact_ids=?, updated_at=? WHERE id=?",
                     (json.dumps(sorted(fids)), db.now(), rid))
        conn.commit()
        new_opps = correlate.run(conn, eng)
        if lead["engagement_id"]:
            leads.recompute_scores(conn, lead["engagement_id"])
        out = db.row(conn, "SELECT * FROM leads WHERE id=?", (rid,))
        out["new_opportunities"] = [o["id"] for o in new_opps]
        return out
    finally:
        conn.close()


@app.get("/api/worklist")
def get_worklist(engagement_id: int | None = None):
    conn = db.connect()
    try:
        eng = engagement_id or _current_engagement(conn)
        if eng is None:
            return []
        return leads.worklist(conn, eng)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# intel layer: entities / facts / opportunities / sitrep / graph

@app.get("/api/entities")
def list_entities(engagement_id: int | None = None):
    conn = db.connect()
    try:
        if engagement_id is not None:
            return db.rows(conn, "SELECT * FROM entities WHERE engagement_id=? ORDER BY type, name",
                           (engagement_id,))
        return db.rows(conn, "SELECT * FROM entities ORDER BY engagement_id, type, name")
    finally:
        conn.close()


@app.post("/api/entities", status_code=201)
async def create_entity(request: Request):
    b = await request.json()
    if not b.get("name"):
        raise HTTPException(400, "name required")
    conn = db.connect()
    try:
        rid = db.upsert_entity(conn, b.get("engagement_id"), b.get("type", "other"),
                               b["name"], b.get("label", ""), b.get("meta"))
        return db.row(conn, "SELECT * FROM entities WHERE id=?", (rid,))
    finally:
        conn.close()


def _guess_type(value: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "host"
    if value.startswith(("http://", "https://")):
        return "endpoint"
    if value.startswith("/"):
        return "file"
    if re.match(r"^[\w.-]+:\d{1,5}$", value):
        return "service"
    return "other"


def _fact_feed_text(f: dict) -> str:
    obj = f["object_name"] or f["object_text"] or "?"
    return f"fact: {f['subject_name']} -{f['predicate']}-> {obj}"


@app.get("/api/facts")
def list_facts(engagement_id: int | None = None, subject: str | None = None,
               predicate: str | None = None, status: str | None = None,
               polarity: str | None = None):
    engagement_id = engagement_id or _default_engagement()
    sql, params = db.FACT_SQL + " WHERE 1=1", []
    if engagement_id is not None:
        sql += " AND f.engagement_id=?"; params.append(engagement_id)
    if subject:
        sql += " AND (s.name LIKE ? OR o.name LIKE ?)"
        params += [f"%{subject}%", f"%{subject}%"]
    if predicate:
        sql += " AND f.predicate=?"; params.append(predicate)
    if status:
        sql += " AND f.status=?"; params.append(status)
    if polarity:
        sql += " AND f.polarity=?"; params.append(polarity)
    sql += " ORDER BY f.id DESC LIMIT 1000"
    conn = db.connect()
    try:
        return db.rows(conn, sql, params)
    finally:
        conn.close()


_HOSTPORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)(.*)$")


def _link_hierarchy(conn, eng, ent_id, name):
    """Deterministically connect host:port[/path] entities so they don't float:
    an endpoint/file under a service → the service (on-service), and a service →
    its host (on-host). Creates the parent when absent so the whole chain forms.
    The system owns these structural edges — the agent shouldn't have to draw them."""
    m = _HOSTPORT_RE.match((name or "").strip())
    if not m:
        return
    ip, port, rest = m.group(1), m.group(2), m.group(3).strip()
    host = db.upsert_entity(conn, eng, "host", ip)
    svc = db.upsert_entity(conn, eng, "service", f"{ip}:{port}")
    if svc != host:
        db.add_fact(conn, eng, svc, "on-host", host, "", "observed", "wire-auto")
    if rest and ent_id != svc:   # this entity is a path/endpoint under the service
        db.add_fact(conn, eng, ent_id, "on-service", svc, "", "observed", "wire-auto")


@app.post("/api/facts", status_code=201)
async def create_fact(request: Request):
    b = await request.json()
    if not b.get("subject_name") or not b.get("predicate"):
        raise HTTPException(400, "subject_name and predicate required")
    if not (b.get("object_name") or b.get("object_text")):
        raise HTTPException(400, "object_name or object_text required")
    stage = b.get("stage", "claimed")   # guilty until proven — a bare assertion is only a claim
    if stage not in FACT_STAGES:
        raise HTTPException(400, f"stage must be one of {sorted(FACT_STAGES)}")
    source = b.get("source", "agent")
    if source not in FACT_SOURCES:
        raise HTTPException(400, f"source must be one of {sorted(FACT_SOURCES)}")
    polarity = b.get("polarity", "affirm")
    if polarity not in db.FACT_POLARITIES:
        raise HTTPException(400, f"polarity must be one of {sorted(db.FACT_POLARITIES)}")
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        sid = db.upsert_entity(conn, eng, b.get("subject_type") or _guess_type(b["subject_name"]),
                               b["subject_name"])
        oid = None
        if b.get("object_name"):
            otype = b.get("object_type") or _guess_type(b["object_name"])
            oid = db.upsert_entity(conn, eng, otype, b["object_name"])
        # auto-draw structural parent edges (endpoint→service→host)
        _link_hierarchy(conn, eng, sid, b["subject_name"])
        if oid:
            _link_hierarchy(conn, eng, oid, b["object_name"])
        existed = db.row(conn,
            "SELECT id FROM facts WHERE engagement_id IS ? AND subject_id=? AND predicate=? "
            "AND object_id IS ? AND object_text=? AND status='active' AND polarity=?",
            (eng, sid, b["predicate"], oid, b.get("object_text", ""), polarity))
        fid = db.add_fact(conn, eng, sid, b["predicate"], oid,
                          b.get("object_text", ""), stage, source, b.get("source_event_id"),
                          polarity=polarity)
        f = db.row(conn, db.FACT_SQL + " WHERE f.id=?", (fid,))
        new_opps = []
        if not existed:
            ev_source = "wire" if source == "wire-auto" else source
            txt = _fact_feed_text(f)
            if polarity == "absent":
                txt = f"checked, NOT present — {txt}"
            db.add_event(conn, ev_source, "fact", txt, meta={"fact_id": fid})
            new_opps = correlate.run(conn, eng)
            for o in new_opps:
                db.add_event(conn, ev_source, "note", f"opportunity: {o['title']} (rule {o['rule']})",
                             meta={"opportunity_id": o["id"]})
            leads.recompute_scores(conn, eng)
        f["new_opportunities"] = [o["id"] for o in new_opps]
        f["duplicate"] = bool(existed)
        return f
    finally:
        conn.close()


@app.patch("/api/facts/{rid}")
def patch_fact(rid: int, body: dict):
    _owned_or_404('facts', rid)
    if "status" in body and body["status"] not in ("active", "ruled-out"):
        raise HTTPException(400, "status must be active or ruled-out")
    if "stage" in body and body["stage"] not in FACT_STAGES:
        raise HTTPException(400, f"stage must be one of {sorted(FACT_STAGES)}")
    return _patch("facts", rid, {"status", "stage", "predicate", "object_text"}, body)


@app.get("/api/mechanisms")
def list_mechanisms():
    """The controlled mechanism vocabulary, with current corpus usage."""
    conn = db.connect()
    try:
        used = {r["mechanism"]: r["n"] for r in db.rows(
            conn, "SELECT mechanism, count(*) n FROM findings WHERE mechanism<>'' "
                  "GROUP BY mechanism")}
        return [{"mechanism": m, "findings": used.get(m, 0)} for m in sorted(db.MECHANISMS)]
    finally:
        conn.close()


@app.get("/api/precedent")
def get_precedent(engagement_id: int | None = None, limit: int = 5,
                  include_open: bool = False):
    """Past engagements that look like this one. Suggests, never declares —
    every row carries the terms it matched on so the ranking can be argued with."""
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        return {"engagement_id": eng,
                "signature": {k: sorted(v, key=str)
                              for k, v in db.engagement_signature(conn, eng).items()},
                "precedents": db.precedent(conn, eng, limit=limit, include_open=include_open)}
    finally:
        conn.close()


@app.get("/api/opportunities")
def list_opportunities(engagement_id: int | None = None, status: str | None = None):
    engagement_id = engagement_id or _default_engagement()   # never leak all engagements
    sql, params = "SELECT * FROM opportunities WHERE 1=1", []
    if engagement_id is not None:
        sql += " AND engagement_id=?"; params.append(engagement_id)
    if status:
        sql += " AND status=?"; params.append(status)
    sql += " ORDER BY CASE status WHEN 'pinned' THEN 0 WHEN 'open' THEN 1 ELSE 2 END, id DESC"
    conn = db.connect()
    try:
        opps = db.rows(conn, sql, params)
        for o in opps:
            o["facts"] = db.rows(conn, db.FACT_SQL +
                                 " JOIN opportunity_facts of2 ON of2.fact_id=f.id WHERE of2.opportunity_id=?",
                                 (o["id"],))
        return opps
    finally:
        conn.close()


def _set_opp_status(rid: int, status: str):
    conn = db.connect()
    try:
        o = db.row(conn, "SELECT engagement_id FROM opportunities WHERE id=?", (rid,))
        if not o:
            raise HTTPException(404, f"opportunity {rid} not found")
        conn.execute("UPDATE opportunities SET status=?, updated_at=? WHERE id=?",
                     (status, db.now(), rid))
        conn.commit()
        leads.recompute_scores(conn, o["engagement_id"])
        return db.row(conn, "SELECT * FROM opportunities WHERE id=?", (rid,))
    finally:
        conn.close()


@app.post("/api/opportunities/{rid}/pin")
def opp_pin(rid: int):
    _owned_or_404('opportunities', rid)
    return _set_opp_status(rid, "pinned")


@app.post("/api/opportunities/{rid}/dismiss")
def opp_dismiss(rid: int):
    _owned_or_404('opportunities', rid)
    return _set_opp_status(rid, "dismissed")


@app.post("/api/opportunities/{rid}/convert")
def opp_convert(rid: int):
    conn = db.connect()
    try:
        o = db.row(conn, "SELECT * FROM opportunities WHERE id=?", (rid,))
        if not o:
            raise HTTPException(404, f"opportunity {rid} not found")
        if o["status"] != "converted":
            db.insert(conn, "tasks", {
                "engagement_id": o["engagement_id"],
                "author": "redops", "text": f"[opp #{o['id']}] {o['title']}: {o['rationale']}",
                "status": "pending", "created_at": db.now(), "done_at": None})
            conn.execute("UPDATE opportunities SET status='converted', updated_at=? WHERE id=?",
                         (db.now(), rid))
            conn.commit()
        return db.row(conn, "SELECT * FROM opportunities WHERE id=?", (rid,))
    finally:
        conn.close()


@app.get("/api/sitrep/{engagement_id}")
def get_sitrep(engagement_id: int):
    conn = db.connect()
    try:
        row = db.row(conn, "SELECT * FROM sitrep WHERE engagement_id=?", (engagement_id,)) or {
            "engagement_id": engagement_id, "activity": "", "hypothesis": "",
            "next_steps": "", "updated_at": None}
        # Count target-attributed work only; unfocused repository maintenance
        # must not make an engagement briefing appear stale.
        row["events_since"] = conn.execute(
            "SELECT COUNT(*) FROM events WHERE engagement_id=? "
            "AND target_id IS NOT NULL AND kind IN ('action','output','tool_call') AND ts > ?",
            (engagement_id, row.get("updated_at") or "")).fetchone()[0] if row.get("updated_at") else 0
        return row
    finally:
        conn.close()


@app.put("/api/sitrep/{engagement_id}")
async def put_sitrep(engagement_id: int, request: Request):
    b = await request.json()
    conn = db.connect()
    try:
        existing = db.row(conn, "SELECT * FROM sitrep WHERE engagement_id=?", (engagement_id,))
        vals = {
            "activity": b.get("activity", existing["activity"] if existing else ""),
            "hypothesis": b.get("hypothesis", existing["hypothesis"] if existing else ""),
            "next_steps": b.get("next_steps", existing["next_steps"] if existing else ""),
        }
        conn.execute("INSERT INTO sitrep (engagement_id, activity, hypothesis, next_steps, updated_at) "
                     "VALUES (?,?,?,?,?) ON CONFLICT(engagement_id) DO UPDATE SET "
                     "activity=excluded.activity, hypothesis=excluded.hypothesis, "
                     "next_steps=excluded.next_steps, updated_at=excluded.updated_at",
                     (engagement_id, vals["activity"], vals["hypothesis"], vals["next_steps"], db.now()))
        conn.commit()
        return db.row(conn, "SELECT * FROM sitrep WHERE engagement_id=?", (engagement_id,))
    finally:
        conn.close()


@app.put("/api/sitrep/{engagement_id}/intent")
async def put_sitrep_intent(engagement_id: int, request: Request):
    """Commander's intent - user channel only. The agent-facing PUT /api/sitrep
    never touches this field."""
    b = await request.json()
    conn = db.connect()
    try:
        existing = db.row(conn, "SELECT * FROM sitrep WHERE engagement_id=?", (engagement_id,))
        conn.execute("INSERT INTO sitrep (engagement_id, activity, hypothesis, next_steps, "
                     "commander_intent, updated_at) VALUES (?,?,?,?,?,?) "
                     "ON CONFLICT(engagement_id) DO UPDATE SET "
                     "commander_intent=excluded.commander_intent, updated_at=excluded.updated_at",
                     (engagement_id,
                      existing["activity"] if existing else "",
                      existing["hypothesis"] if existing else "",
                      existing["next_steps"] if existing else "",
                      b.get("text", ""), db.now()))
        conn.commit()
        return db.row(conn, "SELECT * FROM sitrep WHERE engagement_id=?", (engagement_id,))
    finally:
        conn.close()


@app.get("/api/scope/{engagement_id}")
def get_scope(engagement_id: int):
    conn = db.connect()
    try:
        def load(key):
            raw = db.get_state(conn, f"{key}:{engagement_id}")
            try:
                return json.loads(raw) if raw else []
            except json.JSONDecodeError:
                return []
        web_raw = db.get_state(conn, f"web_scope:{engagement_id}", "")
        try:
            web = json.loads(web_raw) if web_raw else {"pages": [], "api_prefixes": []}
        except json.JSONDecodeError:
            web = {"pages": [], "api_prefixes": []}
        return {"engagement_id": engagement_id, "in": load("scope_in"),
                "out": load("scope_out"), "web": web}
    finally:
        conn.close()


@app.put("/api/scope/{engagement_id}")
async def put_scope(engagement_id: int, request: Request):
    import ipaddress
    b = await request.json()

    def clean(lst, field):
        if not isinstance(lst, list):
            raise HTTPException(400, f"{field} must be a list of CIDRs/IPs")
        out = []
        for x in lst:
            x = str(x).strip()
            if not x:
                continue
            try:
                out.append(str(ipaddress.ip_network(x, strict=False)))
            except ValueError:
                raise HTTPException(400, f"invalid CIDR/IP: {x!r}")
        return out

    conn = db.connect()
    try:
        result = {"engagement_id": engagement_id}
        if "in" in b:
            result["in"] = clean(b["in"], "in")
            db.set_state(conn, f"scope_in:{engagement_id}", json.dumps(result["in"]))
        if "out" in b:
            result["out"] = clean(b["out"], "out")
            db.set_state(conn, f"scope_out:{engagement_id}", json.dumps(result["out"]))
        if "web" in b:
            try:
                result["web"] = webscope.normalize_scope(
                    b["web"].get("pages", []), b["web"].get("api_prefixes", []))
            except (AttributeError, ValueError) as exc:
                raise HTTPException(400, str(exc)) from exc
            db.set_state(conn, f"web_scope:{engagement_id}", json.dumps(result["web"]))
        else:
            raw_web = db.get_state(conn, f"web_scope:{engagement_id}", "")
            result["web"] = json.loads(raw_web) if raw_web else {"pages": [], "api_prefixes": []}
        # return the full picture
        for key in ("in", "out"):
            if key not in result:
                raw = db.get_state(conn, f"scope_{key}:{engagement_id}")
                try:
                    result[key] = json.loads(raw) if raw else []
                except json.JSONDecodeError:
                    result[key] = []
        return result
    finally:
        conn.close()


def _copy_scope(conn, src_id, dst_id) -> None:
    """Copy the scope — the structured in/out allow/block lists — from one
    engagement to another."""
    for key in ("scope_in", "scope_out", "web_scope"):
        raw = db.get_state(conn, f"{key}:{src_id}")
        if raw:
            db.set_state(conn, f"{key}:{dst_id}", raw)


def _copy_targets(conn, src_id, dst_id) -> int:
    """Clone the host inventory (targets: IP/hostname/OS/role/status) from one
    engagement to another, so a copied engagement starts with the same target set.
    Deeper recon — services, facts, creds — is NOT copied; re-run it fresh."""
    n = 0
    for t in db.rows(conn, "SELECT ip, hostname, os, role, status, meta_json FROM targets "
                           "WHERE engagement_id=?", (src_id,)):
        db.insert(conn, "targets", {
            "engagement_id": dst_id, "ip": t["ip"], "hostname": t["hostname"] or "",
            "os": t["os"] or "", "role": t["role"] or "",
            "status": t["status"] or "unidentified", "meta_json": t["meta_json"] or "{}"})
        n += 1
    return n


def _scope_cidrs(conn, engagement_id) -> list[str]:
    """CIDRs/IPs to scope the capture to: the in-scope allowlist, else the
    engagement's own scope column."""
    raw = db.get_state(conn, f"scope_in:{engagement_id}")
    try:
        allow = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        allow = []
    if allow:
        return allow
    r = db.row(conn, "SELECT scope FROM engagements WHERE id=?", (engagement_id,))
    return [c.strip() for c in (r["scope"] or "").replace(",", " ").split()] if r else []


def _scope_out(conn, engagement_id) -> list[str]:
    raw = db.get_state(conn, f"scope_out:{engagement_id}")
    try:
        return json.loads(raw) if raw else []
    except json.JSONDecodeError:
        return []


# Operator-side addresses that are NEVER a scope violation — your own box is not a
# target. Loopback (from the scope module), every LOCAL interface IP, the VPN
# source range, and any declared callback address (REDOPS_CALLBACK — for a lab
# that NATs you onto the target subnet, where your LHOST isn't a local IP). This
# is what stops `msfvenom LHOST=<you> ...` and reverse-shell one-liners from being
# blocked: LHOST is your callback, not a host you're attacking.
import ipaddress as _ipaddr


def _never_block():
    nb = list(scope.DEFAULT_NEVER_BLOCK)
    # every local interface IP (eth0, tun0, …) — discovered, so it tracks the VPN
    for ip in netsensor.all_local_ips():
        try:
            nb.append(_ipaddr.ip_network(ip + "/32", strict=False))
        except ValueError:
            pass
    for var in ("REDOPS_VPN_NET", "REDOPS_CALLBACK"):
        default = ""
        for cidr in (os.environ.get(var, default) or "").split(","):
            cidr = cidr.strip()
            if cidr:
                try:
                    nb.append(_ipaddr.ip_network(cidr, strict=False))
                except ValueError:
                    pass
    return nb


def _exec_run_foreground(cmd: str, cwd: str | None, timeout: int):
    """The blocking half of /api/exec — runs in a worker thread (asyncio.to_thread)
    so a long command can't wedge the async event loop. Run in a NEW SESSION (own
    process group) so a detached child — `nmap … &`, nohup, `setsid` — cannot
    outlive the call and act invisibly after we've returned. On exit or timeout we
    signal the whole group, so nothing keeps running off-feed. (Capture
    completeness: the broker's whole point is that no action escapes the record.)"""
    import signal
    out, err, rc = "", "", 0
    proc = None
    try:
        proc = subprocess.Popen(["bash", "-lc", cmd], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, cwd=cwd,
                                start_new_session=True)
        try:
            out, err = proc.communicate(timeout=timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            # kill the group, then drain whatever the command produced before the
            # deadline — a timed-out scan's partial output is still evidence.
            with contextlib.suppress(OSError, ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            try:
                out, err = proc.communicate(timeout=5)
            except Exception:
                out, err = "", ""
            err = (err or "") + f"\n[exec] timed out after {timeout}s (killed)"
            rc = 124
    except OSError as e:
        out, err, rc = "", f"[exec] failed to launch: {e}", 127
    finally:
        if proc and proc.poll() is None:
            try:
                out2, err2 = proc.communicate(timeout=1)
                out, err = (out or out2), (err or err2)
            except Exception:
                pass
        if proc is not None:
            # start_new_session=True makes proc.pid the process-GROUP id, and the
            # group survives the (reaped) leader while a detached child lives — so
            # kill by proc.pid directly. getpgid(proc.pid) would fail here: the
            # leader is already reaped by communicate(), which silently skipped the
            # kill and let `sleep & ` escape.
            with contextlib.suppress(OSError, ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)               # reap the whole group
    return out, err, rc


@app.post("/api/exec")
async def exec_command(request: Request):
    """The execution broker runs a command on the RedOps host and captures it
    as attributed feed events. Scope checking is an explicit operator opt-in.
    Loopback-only API; the command runs with the server's privileges.

    When enabled, the guard analyzes command text and catches literal targets;
    it cannot see a target built at runtime.
    """
    b = await request.json()
    cmd = (b.get("command") or b.get("cmd") or "").strip()
    if not cmd:
        raise HTTPException(400, "command required")
    why = (b.get("why") or "").strip()
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        if not eng:
            raise HTTPException(400, "no active engagement")
        scope_in = _scope_cidrs(conn, eng)
        if _guard_enabled(conn):
            decision = scope.check_command(cmd, scope_in, _scope_out(conn, eng),
                                           never_block=_never_block(),
                                           cwd=b.get("cwd"))
        else:
            # Guard toggled off (Manage -> Settings / REDOPS_SCOPE_GUARD=0): no
            # static scope analysis at all. The command is still captured to the
            # feed — off means no CONTAINMENT, not no record.
            decision = scope.Decision(True, "scope guard disabled")
        # No strict cage any more: check_command's verdict is total, so there is
        # no "allowed but unproven" state left for the broker to escalate. It used
        # to refuse anything with a non-empty decision.undetermined, which is how
        # an unresolvable-but-harmless token (a filename, a `-m` module path) became
        # an unexplained block. A name outside the allowlist is now refused by the
        # check itself — deterministically, and with a reason that says how to fix it.
        block_reason = decision.reason if decision.blocked else None
        cur = db.get_state(conn, f"current_target:{eng}")
        focus_tid = int(cur) if cur and cur.isdigit() else None
        if block_reason:
            db.add_event(conn, "user", "error",
                         f"[exec] BLOCKED — {block_reason}: {cmd}", target_id=focus_tid,
                         engagement_id=eng, meta={"exec": True, "blocked": True,
                         "reason": block_reason, "command": cmd})
            return {"blocked": True, "reason": block_reason,
                    "targets": decision.targets, "undetermined": decision.undetermined}
        task_id = None
        if b.get("background"):
            # Row FIRST: we need the id for the feed line and the output file
            # name. The process itself is spawned below, after this conn closes.
            task_id = db.insert(conn, "exec_tasks", {
                "engagement_id": eng, "target_id": focus_tid, "command": cmd,
                "why": why, "status": "running", "started_at": db.now()})
        db.add_event(conn, "agent", "action",
                     f"[exec] {cmd}" + (f"   # {why}" if why else "")
                     + (f"   # background task {task_id}" if task_id is not None else ""),
                     target_id=focus_tid, engagement_id=eng,
                     meta={"exec": True, "command": cmd, "task_id": task_id,
                           "undetermined": decision.undetermined})
    finally:
        conn.close()

    cwd = b.get("cwd") or os.environ.get("REDOPS_EXEC_CWD") or None
    if task_id is not None:
        # BACKGROUND: detached, output streams to a per-task log file, no 600s
        # cap — this is how hours-long exploit loops and `nc -lvp` listeners run
        # through the broker. The reaper thread (started in startup()) finalizes
        # the row when the process exits; the agent polls /api/exec_tasks/<id>
        # and kills via /api/exec_tasks/<id>/stop. Same new-session discipline
        # as foreground, so stop can signal the whole group.
        out_file = _workdir(eng) / f"exec-{task_id}.log"
        try:
            fp = open(out_file, "wb")
            try:
                proc = subprocess.Popen(["bash", "-lc", cmd], stdout=fp,
                                        stderr=subprocess.STDOUT, cwd=cwd,
                                        start_new_session=True)
            finally:
                fp.close()  # the child holds its own dup of the fd
        except OSError as e:
            conn = db.connect()
            try:
                conn.execute("UPDATE exec_tasks SET status='failed', finished_at=? WHERE id=?",
                             (db.now(), task_id))
                conn.commit()
            finally:
                conn.close()
            raise HTTPException(500, f"[exec] failed to launch background task: {e}")
        conn = db.connect()
        try:
            conn.execute("UPDATE exec_tasks SET pid=?, output_file=? WHERE id=?",
                         (proc.pid, str(out_file), task_id))
            conn.commit()
        finally:
            conn.close()
        return {"blocked": False, "background": True, "task_id": task_id, "pid": proc.pid}

    timeout = max(1, min(int(b.get("timeout") or 120), 600))
    # The blocking run lives in a worker thread: communicate() is synchronous,
    # so awaiting it in the event loop wedges EVERY other request (board, MCP
    # status, tool queue) for the whole timeout. The 1296-request fuzz that
    # stalled the API for minutes was this — a long foreground exec made the
    # server unreachable even though it was healthy.
    out, err, rc = await asyncio.to_thread(_exec_run_foreground, cmd, cwd, timeout)

    combined = out + (f"\n--- stderr ---\n{err}" if err.strip() else "")
    text, meta = wiretail.store_output(combined, f"exec-{db.now()}")
    conn = db.connect()
    try:
        db.add_event(conn, "agent", "output", text, target_id=focus_tid, engagement_id=eng,
                     meta={"exec": True, "exit_code": rc, "command": cmd, **meta})
    finally:
        conn.close()
    return {"blocked": False, "exit_code": rc, "stdout": out, "stderr": err,
            "targets": decision.targets, "undetermined": decision.undetermined}


def _exec_reap_row(conn, t: dict) -> dict:
    """Finalize a 'running' exec_task whose process has exited. Our own children
    are reaped with waitpid (real exit code); orphans of a restarted server only
    get a liveness check, so their exit_code stays NULL — we honestly don't know.
    The UPDATE is guarded on status='running' so the reaper thread and a lazy
    reap from exec_task_get can't double-finalize (and double-log) the same row."""
    if t["status"] != "running" or not t["pid"]:
        return t
    pid, rc, alive = t["pid"], None, True
    try:
        wpid, wstatus = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            alive = False
            if os.WIFEXITED(wstatus):
                rc = os.WEXITSTATUS(wstatus)
            elif os.WIFSIGNALED(wstatus):
                rc = -os.WTERMSIG(wstatus)
    except ChildProcessError:
        # not our child (server restarted since spawn): liveness is all we get
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            alive = False
    if alive:
        return t
    status = "done" if rc == 0 else ("failed" if rc is not None else "done")
    upd = conn.execute("UPDATE exec_tasks SET status=?, exit_code=?, finished_at=? "
                       "WHERE id=? AND status='running'",
                       (status, rc, db.now(), t["id"]))
    conn.commit()
    if upd.rowcount:
        # short line for the feed; the full output stays in the task's log file
        db.add_event(conn, "agent", "output",
                     f"[exec task {t['id']}] exited rc={rc if rc is not None else '?'}: {t['command']}",
                     target_id=t["target_id"], engagement_id=t["engagement_id"],
                     meta={"exec": True, "task_id": t["id"], "exit_code": rc,
                           "command": t["command"]})
    return db.row(conn, "SELECT * FROM exec_tasks WHERE id=?", (t["id"],))


def _exec_reaper() -> None:
    """Background-exec janitor: every 5s, reap exited tasks so their rows (and
    the feed) reflect reality without the agent having to poll. Must never die —
    a dead reaper strands every task 'running' forever."""
    while True:
        try:
            conn = db.connect()
            try:
                for t in db.rows(conn, "SELECT * FROM exec_tasks WHERE status='running' "
                                       "AND pid IS NOT NULL"):
                    _exec_reap_row(conn, t)
            finally:
                conn.close()
        except Exception:
            pass
        time.sleep(5)


def _exec_reaper_start() -> None:
    threading.Thread(target=_exec_reaper, daemon=True, name="exec-reaper").start()


@app.get("/api/exec_tasks")
def exec_tasks_list(engagement_id: int | None = None):
    conn = db.connect()
    try:
        if engagement_id:
            return db.rows(conn, "SELECT * FROM exec_tasks WHERE engagement_id=? "
                                 "ORDER BY id DESC", (engagement_id,))
        return db.rows(conn, "SELECT * FROM exec_tasks ORDER BY id DESC")
    finally:
        conn.close()


@app.get("/api/exec_tasks/{task_id}")
def exec_task_get(task_id: int, tail: int = 4000):
    conn = db.connect()
    try:
        t = db.row(conn, "SELECT * FROM exec_tasks WHERE id=?", (task_id,))
        if not t:
            raise HTTPException(404, f"exec task {task_id} not found")
        t = _exec_reap_row(conn, t)  # lazy-reap so a poll sees the final state
    finally:
        conn.close()
    out = ""
    f = t.get("output_file") or ""
    if f and os.path.isfile(f):
        size = os.path.getsize(f)
        with open(f, "rb") as fp:
            fp.seek(max(0, size - max(0, tail)))
            out = fp.read().decode(errors="replace")
    return {**t, "output": out}


@app.post("/api/exec_tasks/{task_id}/stop")
def exec_task_stop(task_id: int):
    conn = db.connect()
    try:
        t = db.row(conn, "SELECT * FROM exec_tasks WHERE id=?", (task_id,))
        if not t:
            raise HTTPException(404, f"exec task {task_id} not found")
        if t["status"] == "running" and t["pid"]:
            # kill the whole group (spawned with start_new_session=True), same
            # discipline as the foreground path — a listener's children die too.
            with contextlib.suppress(OSError, ProcessLookupError):
                os.killpg(t["pid"], signal.SIGKILL)
            conn.execute("UPDATE exec_tasks SET status='stopped', finished_at=? WHERE id=?",
                         (db.now(), task_id))
            conn.commit()
            db.add_event(conn, "agent", "action",
                         f"[exec task {task_id}] stopped: {t['command']}",
                         target_id=t["target_id"], engagement_id=t["engagement_id"],
                         meta={"exec": True, "task_id": task_id, "stopped": True})
        return db.row(conn, "SELECT * FROM exec_tasks WHERE id=?", (task_id,))
    finally:
        conn.close()


@app.post("/api/fs/write")
async def fs_write(request: Request):
    """Stage a file inside the engagement workdir sandbox. A locked-down agent
    has no native file access — this is how it drops exploit source, scripts,
    and wordlists it can then run via /api/exec (cwd or absolute path)."""
    b = await request.json()
    rel = (b.get("path") or "").strip()
    if not rel:
        raise HTTPException(400, "path required")
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        if not eng:
            raise HTTPException(400, "no active engagement")
    finally:
        conn.close()
    p = _safe_workpath(eng, rel)
    if b.get("content_b64"):
        try:
            data = base64.b64decode(b["content_b64"], validate=True)
        except Exception:
            raise HTTPException(400, "content_b64 is not valid base64")
    else:
        data = (b.get("content") or "").encode()
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(413, "refusing write over 50 MiB")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return {"path": str(p), "bytes": len(data)}


@app.get("/api/fs/read")
def fs_read(path: str, engagement_id: int | None = None, max_bytes: int = 1048576):
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        if not eng:
            raise HTTPException(400, "no active engagement")
    finally:
        conn.close()
    p = _safe_workpath(eng, path)
    if not p.is_file():
        raise HTTPException(404, f"not found in workdir: {path}")
    data = p.read_bytes()[:max(1, max_bytes)]
    return {"path": str(p), "size": p.stat().st_size,
            "content_b64": base64.b64encode(data).decode()}


@app.post("/api/fetch")
async def fetch_url(request: Request):
    """Download a URL operator-side into data/downloads/. A locked agent has no
    web access; this replaces it. When the optional scope guard is enabled,
    REDOPS_FETCH_ALLOW limits domains (comma list, suffix-matched)."""
    b = await request.json()
    url = (b.get("url") or "").strip()
    if not url:
        raise HTTPException(400, "url required")
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise HTTPException(400, "only http(s) URLs are fetchable")
    allow = [d.strip().lower() for d in
             os.environ.get("REDOPS_FETCH_ALLOW", FETCH_ALLOW_DEFAULT).split(",")
             if d.strip()]
    conn = db.connect()
    try:
        guard_on = _guard_enabled(conn)
    finally:
        conn.close()
    if guard_on and not scope._host_match(u.hostname, allow):
        raise HTTPException(403, f"{u.hostname} is not in REDOPS_FETCH_ALLOW")
    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    base = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(u.path.rstrip("/")) or "index.html")
    dest = DOWNLOADS_DIR / f"{u.hostname}-{base}"
    n = 0
    while dest.exists():  # never clobber an earlier fetch — dedupe with -1, -2…
        n += 1
        dest = DOWNLOADS_DIR / f"{u.hostname}-{base}.{n}"
    proc = subprocess.run(["curl", "-fsSL", "--max-time", "60", "-o", str(dest), url],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        dest.unlink(missing_ok=True)  # don't leave curl's partial file behind
        raise HTTPException(502, f"curl failed (rc={proc.returncode}): {proc.stderr.strip()[:400]}")
    conn = db.connect()
    try:
        db.add_event(conn, "agent", "action", f"[fetch] {url} -> {dest}",
                     engagement_id=b.get("engagement_id") or _active_or_newest(conn),
                     meta={"fetch": True, "url": url, "path": str(dest)})
    finally:
        conn.close()
    return {"path": str(dest), "size": dest.stat().st_size, "url": url}


@app.get("/api/netsensor")
def netsensor_status():
    return netsensor.status()


@app.get("/api/netsensor/interfaces")
def netsensor_interfaces(engagement_id: int | None = None):
    """Interfaces available to sniff, plus which one actually routes to this
    engagement's scope (the recommended vantage point) — feeds the selector."""
    import ipaddress
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        cidrs = _scope_cidrs(conn, eng) if eng else []
    finally:
        conn.close()
    rec_iface = rec_src = None
    if cidrs:
        try:
            net = ipaddress.ip_network(cidrs[0], strict=False)
            probe = str(next(net.hosts())) if net.num_addresses > 2 else str(net.network_address)
            rec_iface, rec_src = netsensor.route_iface(probe)
        except (ValueError, StopIteration):
            pass
    return {"interfaces": netsensor.list_interfaces(), "scope": cidrs,
            "recommended": rec_iface, "recommended_src": rec_src,
            "status": netsensor.status()}


@app.post("/api/netsensor/start")
async def netsensor_start(request: Request):
    raw = await request.body()
    b = json.loads(raw) if raw else {}
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        if not eng:
            raise HTTPException(400, "no active engagement")
        cidrs = _scope_cidrs(conn, eng)
    finally:
        conn.close()
    try:
        return netsensor.start(eng, cidrs, iface=b.get("iface"))
    except RuntimeError as e:
        raise HTTPException(400, str(e))


@app.post("/api/netsensor/stop")
def netsensor_stop():
    return netsensor.stop()


@app.get("/api/flows")
def flows(engagement_id: int | None = None, direction: str | None = None,
          opened_only: bool = False, known_target_only: bool = False):
    conn = db.connect()
    try:
        eng = engagement_id or _active_or_newest(conn)
        sql = "SELECT * FROM flows WHERE engagement_id=?"
        params = [eng]
        if direction:
            sql += " AND direction=?"; params.append(direction)
        if opened_only:
            sql += " AND opened=1"
        if known_target_only:
            sql += " AND target_id IS NOT NULL"
        sql += " ORDER BY last_seen DESC LIMIT 500"
        return db.rows(conn, sql, tuple(params))
    finally:
        conn.close()


@app.post("/api/netsensor/replay", status_code=202)
async def netsensor_replay(request: Request):
    """Dev/demo: feed synthetic tcpdump lines into the active engagement so the
    board's flow layer can be seen without a privileged live capture. Body:
    {"lines": ["<tcpdump line>", ...], "local_ips": ["10.10.14.5"]}."""
    b = await request.json()
    lines = b.get("lines") or []
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        if not eng:
            raise HTTPException(400, "no active engagement")
    finally:
        conn.close()
    local = set(b.get("local_ips") or ([netsensor.primary_ip()] if netsensor.primary_ip() else []))
    new = netsensor.ingest_lines(lines, eng, local)
    return {"new_flows": len(new), "local_ips": sorted(local)}


@app.get("/api/graph")
def graph(engagement_id: int | None = None):
    conn = db.connect()
    try:
        if engagement_id is None:
            engagement_id = _active_or_newest(conn) or -1
        nodes = []
        for e in db.rows(conn, "SELECT * FROM entities WHERE engagement_id=?", (engagement_id,)):
            try:
                meta = json.loads(e["meta_json"] or "{}")
            except (ValueError, TypeError):
                meta = {}
            nodes.append({"id": e["id"], "type": e["type"], "name": e["name"], "label": e["label"],
                          "meta": meta, "first_seen": e["first_seen"], "last_seen": e["last_seen"]})
        fact_rows = db.rows(conn, "SELECT * FROM facts WHERE engagement_id=?", (engagement_id,))
        edges = [{"id": f["id"], "from": f["subject_id"], "predicate": f["predicate"],
                  "to": f["object_id"], "to_text": f["object_text"], "status": f["status"],
                  "stage": f["stage"]}
                 for f in fact_rows]
        opp_edges = set()
        for o in db.rows(conn, "SELECT id FROM opportunities WHERE engagement_id=? AND status IN ('open','pinned')",
                         (engagement_id,)):
            for fid in db.rows(conn, "SELECT fact_id FROM opportunity_facts WHERE opportunity_id=?", (o["id"],)):
                opp_edges.add(fid["fact_id"])
        for e in edges:
            e["in_opportunity"] = e.pop("id") in opp_edges
        return {"nodes": nodes, "edges": edges}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# transcript capture: overflow files, external sources, focus pointer, health

@app.get("/api/transcript/sources")
def list_transcript_sources():
    conn = db.connect()
    try:
        out = []
        for r in db.rows(conn, "SELECT key, value FROM wiretail_state WHERE key LIKE 'tsource:%'"):
            path = r["key"][len("tsource:"):]
            out.append({"path": path, "registered_at": r["value"],
                        "offset": int(db.get_state(conn, f"toffset:{path}", "0"))})
        return out
    finally:
        conn.close()


@app.post("/api/transcript/sources", status_code=201)
async def add_transcript_source(request: Request):
    b = await request.json()
    path = os.path.abspath(os.path.expanduser((b.get("path") or "").strip()))
    if not path or not os.path.isfile(path):
        raise HTTPException(400, f"path must be an existing file (got {b.get('path')!r})")
    conn = db.connect()
    try:
        db.set_state(conn, f"tsource:{path}", db.now())
        return {"path": path, "registered_at": db.get_state(conn, f"tsource:{path}")}
    finally:
        conn.close()


@app.get("/api/transcript/{filename}")
def transcript_file(filename: str):
    name = os.path.basename(filename)  # strip any directory components
    path = (db.TRANSCRIPT_DIR / name).resolve()
    if not name or not path.is_file() or path.parent != db.TRANSCRIPT_DIR.resolve():
        raise HTTPException(404, "transcript file not found")
    return FileResponse(path, media_type="text/plain; charset=utf-8")


def _current_engagement(conn) -> int | None:
    # Alias of _active_or_newest — was newest-only, which desynced leads/worklist/
    # objectives/graph from the active engagement. Now active-first like the rest.
    return db._active_engagement_id(conn)


@app.get("/api/current_target")
def get_current_target(engagement_id: int | None = None):
    conn = db.connect()
    try:
        eng = engagement_id or _current_engagement(conn)
        v = db.get_state(conn, f"current_target:{eng}") if eng else ""
        tid = int(v) if v and v != "null" else None
        t = db.row(conn, "SELECT id, ip, hostname FROM targets WHERE id=? AND engagement_id=?",
                   (tid, eng)) if tid else None
        return {"engagement_id": eng, "target_id": t["id"] if t else None,
                "ip": t["ip"] if t else None}
    finally:
        conn.close()


@app.put("/api/current_target")
async def put_current_target(request: Request):
    b = await request.json()
    tid = b.get("target_id")
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _current_engagement(conn)
        if eng is None:
            raise HTTPException(400, "no engagement exists")
        if tid is not None:
            if not db.row(conn, "SELECT id FROM targets WHERE id=? AND engagement_id=?",
                          (tid, eng)):
                raise HTTPException(404, f"target {tid} not found in engagement {eng}")
            db.set_state(conn, f"current_target:{eng}", str(tid))
        else:
            db.set_state(conn, f"current_target:{eng}", "null")
        wiretail.ATTRIB.refresh(conn, force=True)
        return {"engagement_id": eng, "target_id": tid}
    finally:
        conn.close()


@app.get("/api/health")
def health():
    conn = db.connect()
    try:
        wire = {
            "path": db.get_state(conn, "wire:path") or None,
            "last_read_ts": db.get_state(conn, "wire:last_read_ts") or None,
            "parse_errors": int(db.get_state(conn, "wire:parse_errors", "0") or 0),
            "status": db.get_state(conn, "wire:status") or (
                "disabled" if os.environ.get("REDOPS_NO_WIRETAIL") == "1" else "no-file"),
        }
    finally:
        conn.close()
    acp_h = acp.health()
    # The CAPTURE pill reads `capture` — the active mechanism. ACP wins when a
    # session is live/pending; otherwise the pill reflects wiretail.
    active = "acp" if acp_h["status"] not in ("off", None) else "wire"
    capture = ({"mechanism": "acp", "status": acp_h["status"]}
               if active == "acp" else {"mechanism": "wire", "status": wire["status"]})
    return {"capture": capture, "wire": wire, "acp": acp_h}


# ---------------------------------------------------------------------------
# settings (live, runtime) + status (read-only)

# key -> env var it falls back to. Bool settings are "1"/"0".
_SETTINGS = {
    "allow_loopback":  {"env": "REDOPS_ALLOW_LOOPBACK", "type": "bool", "env_default": "1"},
    "tool_net":        {"env": "REDOPS_TOOL_NET",       "type": "str"},
    "acp_autoapprove": {"env": "REDOPS_ACP_AUTOAPPROVE", "type": "bool", "env_default": "1"},
    # Agent-queued tools run automatically by default in authorized labs.
    # The operator can opt into approval from Settings when needed.
    "tool_auto_approve": {"env": "REDOPS_TOOL_AUTOAPPROVE", "type": "bool", "env_default": "1"},
    # off by default: the per-prompt/session briefing steers the agent; opt in
    # only when you want the queue injected into its context.
    "brief_on_prompt": {"env": "REDOPS_BRIEF",          "type": "bool"},
    # OFF by default for authorized engagements; the assigned targets remain
    # context and evidence labels. The operator can explicitly enable it.
    "scope_guard":     {"env": "REDOPS_SCOPE_GUARD",    "type": "bool", "env_default": "0"},
}


def _guard_enabled(conn) -> bool:
    """The ONE place the broker asks "is the scope guard on": runtime toggle
    (Manage -> Settings) wins, else REDOPS_SCOPE_GUARD env, else OFF. Mirrors
    hooks/_common.guard_enabled so the Bash hook and this broker cannot
    diverge."""
    override = db.row(conn, "SELECT value FROM wiretail_state WHERE key=?", ("set:scope_guard",))
    raw = override["value"] if override is not None else os.environ.get("REDOPS_SCOPE_GUARD", "0")
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


@app.get("/api/settings")
def get_settings():
    conn = db.connect()
    try:
        out = {}
        for key, spec in _SETTINGS.items():
            override = db.row(conn, "SELECT value FROM wiretail_state WHERE key=?", (f"set:{key}",))
            env_raw = os.environ.get(spec["env"])
            if override is not None:
                val, source = override["value"], "runtime"
            elif env_raw is not None:
                val, source = env_raw, "env"
            else:
                val, source = spec.get("env_default", ""), "default"
            if spec["type"] == "bool":
                val = str(val).strip().lower() in ("1", "true", "yes", "on")
            out[key] = {"value": val, "source": source, "env": spec["env"]}
        return out
    finally:
        conn.close()


@app.put("/api/settings")
async def put_settings(request: Request):
    # This writes tool_auto_approve. Gating /approve while leaving the master
    # switch open is locking the door and leaving the window up: flip it true and
    # every agent-queued run lands 'ready' without anyone calling /approve.
    if not _is_operator(request):
        raise HTTPException(403, "changing settings requires the operator token")
    body = await request.json()
    conn = db.connect()
    try:
        for key, raw in body.items():
            if key not in _SETTINGS:
                continue
            spec = _SETTINGS[key]
            if spec["type"] == "bool":
                val = "1" if (raw is True or str(raw).strip().lower() in ("1", "true", "yes", "on")) else "0"
            else:
                val = str(raw).strip()
            db.set_setting(conn, key, val)
        return get_settings()
    finally:
        conn.close()


@app.get("/api/status")
def get_status():
    conn = db.connect()
    try:
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        counts = {
            "engagements": conn.execute("SELECT count(*) FROM engagements").fetchone()[0],
            "targets": conn.execute("SELECT count(*) FROM targets").fetchone()[0],
            "facts": conn.execute("SELECT count(*) FROM facts").fetchone()[0],
            "events": conn.execute("SELECT count(*) FROM events").fetchone()[0],
            "tool_runs": conn.execute("SELECT count(*) FROM tool_runs").fetchone()[0],
        }
    finally:
        conn.close()
    db_path = str(db.DB_PATH)
    try:
        db_size = os.path.getsize(db_path)
    except OSError:
        db_size = None
    commit = ""
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                                capture_output=True, text=True, timeout=2,
                                cwd=os.path.dirname(os.path.dirname(__file__))).stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    cap = health()["capture"]
    return {
        "capture": cap,
        "schema_version": ver, "db_path": db_path, "db_size": db_size,
        "data_dir": str(db.DATA_DIR), "host": HOST, "port": PORT,
        "commit": commit, "counts": counts,
    }


# ---------------------------------------------------------------------------
# ACP cockpit — session / prompt / permissions / cancel

def _acp_or_503():
    s = acp.session()
    if s is None:
        raise HTTPException(503, "ACP capture not enabled (set REDOPS_CAPTURE=acp)")
    return s


@app.post("/api/acp/session")
def acp_ensure_session():
    """Ensure a session exists for the active engagement. The supervisor thread
    owns the session lifecycle; this reports its current state."""
    _acp_or_503()
    return acp.health()


@app.post("/api/acp/prompt")
async def acp_prompt(request: Request):
    s = _acp_or_503()
    b = await request.json()
    text = (b.get("text") or "").strip()
    if not text:
        raise HTTPException(400, "text required")
    try:
        s.submit_prompt(text)
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    return {"ok": True, "sessionId": s.session_id}


@app.get("/api/acp/permissions")
def acp_permissions():
    s = acp.session()
    return {"pending": s.pending_permissions() if s else []}


@app.post("/api/acp/permission/{pid}")
async def acp_answer_permission(pid: str, request: Request):
    s = _acp_or_503()
    b = await request.json()
    option_id = b.get("optionId")
    if not s.answer_permission(pid, option_id):
        raise HTTPException(404, f"permission {pid} not pending")
    return {"ok": True}


@app.post("/api/acp/cancel")
def acp_cancel():
    _acp_or_503().cancel()
    return {"ok": True}


@app.post("/api/acp/new_session")
def acp_new_session():
    """Start a fresh agent conversation (session/new), discarding the resumed
    history — so a prompt lands on a clean agent, not one still mid-mission."""
    s = _acp_or_503()
    try:
        sid = s.new_session()
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    return {"ok": True, "sessionId": sid}


# ---------------------------------------------------------------------------
# export

@app.get("/api/export/{engagement_id}")
def export_report(engagement_id: int, fmt: str = "md"):
    if fmt not in ("md", "html"):
        raise HTTPException(400, "fmt must be md or html")
    try:
        content, media = export.export(engagement_id, fmt)
    except ValueError as e:
        raise HTTPException(404, str(e))
    # The report is built from TARGET-CONTROLLED text and is served same-origin
    # with the board, which carries the operator token in the page. Escaping is
    # the primary defence and it has already failed once, so deny the second step
    # too: no script may run in the report, and the browser is told to download
    # rather than render it in our origin. Defence in depth for a confused-deputy
    # chain — attacker text -> operator opens report -> script reads the token
    # from /board.html -> approves its own held destructive run.
    return Response(
        content, media_type=media + "; charset=utf-8",
        headers={
            "Content-Security-Policy": ("default-src 'none'; img-src data:; "
                                        "style-src 'unsafe-inline'; sandbox"),
            "Content-Disposition": f'attachment; filename="redops-{engagement_id}.{fmt}"',
            "X-Content-Type-Options": "nosniff",
        })


# ---------------------------------------------------------------------------
# tool capture: deterministic tools run directly (no LLM), results shared

@app.post("/api/maintenance/prune")
async def maintenance_prune(request: Request):
    """Bounded growth. DRY RUN unless apply=true, and operator-only — the agent
    has no business deleting capture data. Never touches facts, findings,
    evidence, credentials, targets, services or tool runs; see redops/retention.py
    for what each category is and why it is disposable."""
    b = await request.json() if await request.body() else {}
    if b.get("apply") and not _is_operator(request):
        raise HTTPException(403, "pruning requires the operator token")
    conn = db.connect()
    try:
        return retention.prune(
            conn,
            wire_days=float(b.get("wire_days", 2)),
            flow_days=float(b.get("flow_days", 2)),
            opp_days=float(b.get("opp_days", 14)),
            engagement_id=b.get("engagement_id"),
            apply=bool(b.get("apply")))
    finally:
        conn.close()


@app.get("/api/agent_engagement")
def agent_engagement():
    """The engagement the AGENT must write to — the one its ACP session is pinned
    to, not whatever the operator is looking at now. Switching engagements in the
    UI mid-turn must not silently redirect the agent's writes; the pin only moves
    when the session rebinds. Falls back to the active engagement when no session
    is bound (CLI-driven or capture-off runs)."""
    conn = db.connect()
    try:
        pinned = (db.get_state(conn, "acp:engagement") or "").strip()
        if pinned.isdigit():
            row = db.row(conn, "SELECT id FROM engagements WHERE id=?", (int(pinned),))
            if row:
                return {"id": int(pinned), "pinned": True}
            # FAIL CLOSED. Falling back to the operator's active engagement here
            # would silently redirect every agent write into a different
            # engagement — the exact bug the pin exists to prevent, re-entered
            # through the error path. Refuse until a session rebinds.
            raise HTTPException(
                409, f"agent session is pinned to engagement {pinned}, which no longer "
                     f"exists. Restart the ACP session to rebind; writes are refused "
                     f"until then rather than landing in the wrong engagement.")
        return {"id": _active_or_newest(conn), "pinned": False}
    finally:
        conn.close()


@app.get("/api/tools/available")
def tools_available():
    return tools.available()


@app.get("/api/tools/specs")
def tools_specs():
    """Full typed registry (options + presets + defaults) for the board menu."""
    return tools.available()


@app.get("/api/tools/runs")
def tools_runs(engagement_id: int | None = None, target_id: int | None = None,
               limit: int = 40, before_id: int | None = None):
    conn = db.connect()
    try:
        # default to the ACTIVE engagement — an unscoped call returned every
        # engagement's runs, captured output included.
        return tools.runs(conn, engagement_id or _active_or_newest(conn),
                          target_id, limit=limit, before_id=before_id)
    finally:
        conn.close()


@app.get("/api/tools/queue")
def tools_queue(engagement_id: int | None = None):
    conn = db.connect()
    try:
        if engagement_id is None:
            engagement_id = _active_or_newest(conn)
        return tools.queue(conn, engagement_id)
    finally:
        conn.close()


@app.get("/api/tools/run/{rid}")
def tools_run_detail(rid: int):
    conn = db.connect()
    try:
        r = db.row(conn, "SELECT * FROM tool_runs WHERE id=?", (rid,))
        # a bare run id must not hand back another engagement's captured output
        if r and r["engagement_id"] not in (None, _active_or_newest(conn)):
            r = None
    finally:
        conn.close()
    if not r:
        raise HTTPException(404, "run not found")
    return r


@app.post("/api/tools/run", status_code=202)
async def tools_run(request: Request):
    """Enqueue a tool run. Accepts tool (spec id or legacy id), preset, opts
    (typed option overrides), priority, and actor. Operator runs auto-run;
    agent runs wait for approval unless auto-approve is on."""
    b = await request.json()
    tool = b.get("tool")
    if tool not in tools.tool_names():
        raise HTTPException(400, f"unknown tool; have {sorted(tools.tool_names())}")
    conn = db.connect()
    try:
        tid = b.get("target_id")
        ip = b.get("ip")
        if tid and not ip:
            t = db.row(conn, "SELECT ip FROM targets WHERE id=?", (tid,))
            if t:
                ip = t["ip"]
        if not ip:
            raise HTTPException(400, "ip or target_id required")
        # The scan belongs to the ACTIVE engagement. Re-derive the target within
        # it by IP so a stale cross-engagement target_id (lab IPs recur) can't
        # file the run under the wrong engagement.
        eng = b.get("engagement_id") or _active_or_newest(conn)
        row = db.row(conn, "SELECT id FROM targets WHERE engagement_id=? AND ip=?", (eng, ip))
        tid = row["id"] if row else None
    finally:
        conn.close()
    res = tools.enqueue(eng, tid, ip, tool,
                        actor=("operator" if _is_operator(request) else "agent"),
                        preset=b.get("preset"), opts=b.get("opts"),
                        priority=b.get("priority"), port=b.get("port"))
    if res.get("error"):
        raise HTTPException(400, res["error"])
    # a scan is about to put packets on the wire — make sure the sensor is
    # capturing so it shows on the map (best-effort; no-op if it can't/already is).
    try:
        conn = db.connect()
        try:
            netsensor.ensure(eng, _scope_cidrs(conn, eng))
        finally:
            conn.close()
    except Exception:
        pass
    return res


@app.post("/api/tools/exec")
async def tools_exec(request: Request):
    """Escape hatch — run an arbitrary command through RedOps: captured only
    (no parser, no facts), with optional scope checking. The bridge for tools not yet in the
    registry; prefer /api/tools/run (a real, parsed tool) whenever one fits.
    Returns the captured output synchronously; background=true instead queues it
    onto the shared pool and returns a run id immediately."""
    b = await request.json()
    command = b.get("command")
    if not command:
        raise HTTPException(400, "command required")
    try:
        timeout = int(b.get("timeout", 1800))
    except (TypeError, ValueError):
        raise HTTPException(400, "timeout must be an integer")
    if not 1 <= timeout <= 14400:
        raise HTTPException(400, "timeout must be between 1 and 14400 seconds")
    local = b.get("local", False)
    if not isinstance(local, bool):
        raise HTTPException(400, "local must be a boolean")
    if local and b.get("target_ip"):
        raise HTTPException(400, "local and target_ip cannot both be set")
    conn = db.connect()
    try:
        eng = b.get("engagement_id") or _active_or_newest(conn)
        if not eng:
            raise HTTPException(400, "no active engagement")
        tid = None
        if local:
            tid = None
        elif b.get("target_ip"):
            row = db.row(conn, "SELECT id FROM targets WHERE engagement_id=? AND ip=?",
                         (eng, b["target_ip"]))
            if not row:
                raise HTTPException(404, "target not found in engagement")
            tid = row["id"]
        else:
            # A focused host should attribute ordinary MCP run output too.
            cur = db.get_state(conn, f"current_target:{eng}")
            if cur.isdigit():
                row = db.row(conn, "SELECT id FROM targets WHERE id=? AND engagement_id=?",
                             (int(cur), eng))
                tid = row["id"] if row else None
    finally:
        conn.close()
    # actor is ATTRIBUTION, not authorization. It arrives in the request body
    # with nothing verifying it, and the destructive gate keys on
    # actor != "operator" — so an unverified actor="operator" would walk straight
    # through. Honour the operator claim only from a request carrying the
    # operator token; everything else is an agent.
    actor = "operator" if _is_operator(request) else "agent"
    if b.get("background"):
        return tools.queue_exec(eng, command, actor=actor, target_id=tid,
                                priority=b.get("priority", 5), timeout=timeout)
    # subprocess.run BLOCKS. This endpoint is async, so running it inline would
    # stall the whole event loop — freezing SSE, board polling and health for the
    # life of a bounded command. Off to a worker thread.
    return await run_in_threadpool(tools.run_command, eng, command,
                                   actor=actor, target_id=tid, timeout=timeout)


def _run_in_active_engagement(rid: int) -> None:
    """Approving/cancelling is an ACTION, not a read — a bare run id must never
    release another engagement's held command."""
    conn = db.connect()
    try:
        r = db.row(conn, "SELECT engagement_id FROM tool_runs WHERE id=?", (rid,))
        if not r or r["engagement_id"] not in (None, _active_or_newest(conn)):
            raise HTTPException(404, "run not found")
    finally:
        conn.close()


@app.post("/api/tools/runs/{rid}/approve")
def tools_run_approve(rid: int, request: Request):
    # Approving is the WHOLE point of the gate. Without this check anything that
    # reaches the API could release its own held destructive run, which made the
    # rest of the gating decorative.
    if not _is_operator(request):
        raise HTTPException(403, "approving a held run requires the operator token")
    _run_in_active_engagement(rid)
    r = tools.approve_run(rid)
    if not r:
        raise HTTPException(404, "run not found")
    return dict(r) if not isinstance(r, dict) else r


@app.post("/api/tools/runs/{rid}/cancel")
def tools_run_cancel(rid: int, request: Request):
    # cancel is not privilege escalation, but letting the agent silently drop a
    # run the operator is waiting to review hides work; keep it operator-only too.
    if not _is_operator(request):
        raise HTTPException(403, "cancelling a queued run requires the operator token")
    _run_in_active_engagement(rid)
    r = tools.cancel_run(rid)
    if not r:
        raise HTTPException(404, "run not found")
    return dict(r) if not isinstance(r, dict) else r


# The frontend is a live dev tool we edit constantly; browsers were heuristically
# caching the single-file board.html and serving stale CSS+JS (edits looked like
# no-ops). Force revalidation on every frontend fetch — with ETag/Last-Modified
# still set, an unchanged file 304s (cheap), a changed one is refetched (fresh).
@app.middleware("http")
async def _revalidate_frontend(request, call_next):
    resp = await call_next(request)
    if not request.url.path.startswith("/api"):
        resp.headers["Cache-Control"] = "no-cache, must-revalidate"
    return resp


@app.get("/board.html", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
@app.get("/", include_in_schema=False)
def _frontend(request: Request):
    """Serve the operator UI with the operator token injected. The browser can't
    read a 0600 file, and fetching the token over the API would just re-open the
    hole the token exists to close — so the server stamps it into the page it
    already serves to the operator."""
    name = os.path.basename(request.url.path) or "index.html"
    path = STATIC_DIR / (name if name.endswith(".html") else "index.html")
    if not path.is_file():
        raise HTTPException(404, "not found")
    html = path.read_text(encoding="utf-8")
    tag = f'<script>window.REDOPS_OPERATOR_TOKEN={json.dumps(_operator_token())};</script>'
    html = html.replace("</head>", tag + "</head>", 1) if "</head>" in html else tag + html
    return HTMLResponse(html, headers={"Cache-Control": "no-cache, must-revalidate"})


# static frontend (mounted last so /api wins)
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


def main() -> None:
    import uvicorn
    db.init_db()
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
