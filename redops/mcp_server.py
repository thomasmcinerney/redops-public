"""RedOps MCP server (stdio) - native tools for the Kimi Code CLI agent.

Thin wrappers over the running RedOps HTTP API (same single source of truth
as the CLI). Registered in ~/.kimi-code/mcp.json; loads in new Kimi sessions.

Run directly: python -m redops.mcp_server
"""

import base64
import ipaddress
import json
import os
import re
import shlex
import sys
import time

try:
    from redops.client import (ApiError, START_HINT, default_engagement,
                               find_target, guess_type, post_multipart, req,
                               set_engagement_resolver)
except ImportError:  # executed as a plain script: put the project root on sys.path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from redops.client import (ApiError, START_HINT, default_engagement,
                               find_target, guess_type, post_multipart, req,
                               set_engagement_resolver)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("redops")


def _j(x) -> str:
    return json.dumps(x, ensure_ascii=False)


# MCP clients cancel a tool call that blocks too long (Kimi: ~60s, -32001), so
# a foreground exec must never wait past this budget — longer commands are
# auto-detached to a background task and polled. Override with
# REDOPS_MCP_FOREGROUND_BUDGET.
FOREGROUND_BUDGET = int(os.environ.get("REDOPS_MCP_FOREGROUND_BUDGET", "45"))
MCP_SOURCE_MTIME = os.path.getmtime(__file__)


def _poll_exec_task(task_id: int, deadline: float) -> dict | None:
    """Poll a background exec task until it leaves 'running' or the deadline
    (time.monotonic) passes. Returns the final task row (with output), or None
    if it is still running at the deadline."""
    first = True
    while time.monotonic() < deadline:
        time.sleep(1 if first else 2)
        first = False
        t = req("GET", f"/api/exec_tasks/{task_id}?tail=1048576")
        if t.get("status") != "running":
            return t
    return None


def _engagement() -> int:
    """The engagement THIS agent session is pinned to. Not `default_engagement()`
    — that resolves whatever is globally active, so an operator switching
    engagements mid-turn would silently redirect the agent's writes away from the
    engagement its own ACP events are still being stamped with."""
    try:
        eid = (req("GET", "/api/agent_engagement") or {}).get("id")
        if eid:
            return eid
    except ApiError:
        raise
    return default_engagement()


# every client.py helper that resolves an engagement (find_target, and through it
# a dozen target-bound writes) must use the PIN, not the global active one.
set_engagement_resolver(_engagement)


_IDENT_RE = re.compile(r"^[A-Za-z0-9][\w.$@\\/-]{0,60}$")


def _looks_like_entity_list(text: str) -> list[str] | None:
    """A comma/space/newline-separated list of 3+ IDENTIFIER-like tokens (usernames,
    hosts, ports) — the thing that must be structured, not jammed into one field.
    Returns the tokens, or None for genuine prose (tokens with spaces/parens)."""
    raw = re.split(r"[,\n;]+", text)
    parts = [p.strip().strip("()") for p in raw if p.strip()]
    if len(parts) < 3:
        return None
    identish = [p for p in parts if _IDENT_RE.match(p)]
    # most parts must be bare identifiers; prose ("MongoDB metadata", "vector DB")
    # has spaces and fails _IDENT_RE, so it won't trip this.
    return identish if len(identish) >= 3 and len(identish) >= 0.7 * len(parts) else None


# --- sitrep drift -----------------------------------------------------------
# The operator sees sitrep staleness as a badge on the board. The agent has no
# eyes on the board, so a standing "update it at every phase change" rule has no
# trigger behind it and silently decays — observed: a full night of work with the
# briefing 1338 events behind. Ride the signal on tool results the agent already
# reads, which is the only channel that reaches it during autonomous work.
_NUDGE_AFTER = 40          # hands-on events since the last sitrep write
_NUDGE_EVERY = 90.0        # seconds between checks — one request/min, not per call
_nudge_last = [0.0, ""]


def _sitrep_nudge() -> str:
    now = time.monotonic()
    if now - _nudge_last[0] < _NUDGE_EVERY:
        return _nudge_last[1]
    _nudge_last[0] = now
    try:
        s = req("GET", f"/api/sitrep/{_engagement()}")     # already parsed
        n = int((s or {}).get("events_since") or 0)
    except Exception:                                    # never break a tool call
        n = 0
    _nudge_last[1] = ("" if n < _NUDGE_AFTER else
                      f"\n\n[redops] SITREP is {n} events stale — the operator reads "
                      f"it first and it no longer matches the board. Call sitrep_set "
                      f"with your current activity / hypothesis / next_steps.")
    return _nudge_last[1]


def _jn(payload) -> str:
    """_j plus a sitrep-drift reminder when the briefing has fallen behind."""
    return _j(payload) + _sitrep_nudge()


@mcp.tool()
def log(text: str, kind: str = "reasoning", target_ip: str | None = None) -> str:
    """Narrate into the ops feed. Call at every phase change and before/after
    significant actions. kind: reasoning (why/plan) | action (what you did) | note.
    Keep it first-person, terse, why-focused."""
    if kind not in ("reasoning", "action", "note"):
        raise ApiError("kind must be reasoning, action or note")
    body = {"source": "agent", "kind": kind, "text": text}
    if target_ip:
        body["target_id"] = find_target(target_ip)["id"]
    return _jn(req("POST", "/api/events", body))


@mcp.tool()
def fact_add(subject: str, predicate: str, object: str, stype: str | None = None,
             otype: str | None = None, stage: str = "claimed") -> str:
    """Record a recon discovery as a structured fact (subject -predicate-> object).
    Call IMMEDIATELY on every discovery - open ports, services, users, creds,
    writable files, who runs as what. Facts feed the correlation engine that
    surfaces attack opportunities. Entities auto-upsert; types auto-guess
    (IP->host, URL->endpoint, path->file, host:port->service).
    `stage` is the confirmation lifecycle — be honest about your evidence:
      claimed   (default) a source ASSERTS it — a page/banner/config says so, you
                haven't verified it. A tech stack read off an /about page is claimed.
      observed  YOU saw it — a scan hit, a wire flow, a response you got back.
      confirmed you verified or EXPLOITED it — listed the collections, dumped the db.
    Re-recording a fact with a stronger stage promotes it (claimed->observed->
    confirmed); it never regresses. Don't stamp `confirmed` on something you only read.
    A fact holds ONE relationship, not a list — if you found several usernames/
    hosts/ports, record each as its own entity (principal_add takes a comma list),
    then fact_add links them. Don't jam a comma-separated list into `object`.
    To record a discovered tech component (vector DB, model, datastore, framework)
    use stack_add — it becomes a typed NODE, not a text blob on a fact."""
    items = _looks_like_entity_list(object)
    if items:
        raise ApiError(
            f"`object` looks like a list of {len(items)} items ({', '.join(items[:5])}"
            f"{'…' if len(items) > 5 else ''}) — a fact is ONE relationship, not a list. "
            f"Record each as an entity (usernames: principal_add takes a comma list in "
            f"one call), then fact_add to link them — structured and queryable, not "
            f"buried in text.")
    body = {"subject_name": subject, "predicate": predicate, "stage": stage,
            "source": "agent", "engagement_id": _engagement()}
    body["subject_type"] = stype or guess_type(subject)
    if otype or " " not in object:
        body["object_name"] = object
        body["object_type"] = otype or guess_type(object)
    else:
        body["object_text"] = object
    return _jn(req("POST", "/api/facts", body))


@mcp.tool()
def fact_absent(subject: str, predicate: str, object: str, stype: str | None = None,
                otype: str | None = None) -> str:
    """Record that you CHECKED for something and it is NOT there. Same shape as
    fact_add; the difference is that this narrows the space instead of asserting
    a path.

    Call this every time a check comes back empty — no default creds on the
    admin panel, version is patched, /upload returns 403 not 500, no anonymous
    FTP, no writable path in the web root. On a timeboxed box most of what you
    learn is negative, and a negative that only lives in your context window is
    lost the moment the run ends.

    These never reach the correlation engine, so an absence can never complete
    an attack chain. They are read by `precedent`, which compares this box
    against every box the fleet has already run."""
    body = {"subject_name": subject, "predicate": predicate, "polarity": "absent",
            "stage": "confirmed", "source": "agent", "engagement_id": _engagement()}
    body["subject_type"] = stype or guess_type(subject)
    if otype or " " not in object:
        body["object_name"] = object
        body["object_type"] = otype or guess_type(object)
    else:
        body["object_text"] = object
    return _j(req("POST", "/api/facts", body))


@mcp.tool()
def fact_list(status: str = "active", predicate: str | None = None,
              polarity: str | None = None) -> str:
    """List recorded intel facts for the engagement. status: active|ruled-out.
    polarity: affirm (what is true) | absent (what was checked and is not there)."""
    path = f"/api/facts?engagement_id={_engagement()}"
    if status:
        path += f"&status={status}"
    if predicate:
        path += f"&predicate={predicate}"
    if polarity:
        path += f"&polarity={polarity}"
    return _j(req("GET", path))


@mcp.tool()
def mechanisms() -> str:
    """The controlled vocabulary of exploitation mechanisms, with how many
    findings in the whole corpus carry each one. Read this before calling
    finding_mechanism so you pick an existing class rather than inventing a
    synonym — a mechanism only earns its keep when it matches another box."""
    return _j(req("GET", "/api/mechanisms"))


@mcp.tool()
def finding_mechanism(finding_id: int, mechanism: str) -> str:
    """Label a finding with HOW it was exploited, from the `mechanisms` list.

    This is the field that transfers between boxes. A CVE id joins to exactly
    one product version; `setup-wizard-exposed` joined BarracudaDrive and
    FuguHub, which are different products with the same bug. Label every finding
    you actually exploited, and every finding you identified but could not
    drive home — the parked ones are what make the next box faster."""
    return _j(req("PATCH", f"/api/findings/{finding_id}", {"mechanism": mechanism}))


@mcp.tool()
def precedent(limit: int = 5) -> str:
    """Past engagements that look like this one, ranked, with the terms they
    matched on.

    CALL THIS EARLY — right after the first scan, before committing to a line of
    attack. The fleet has already run this tooling against many boxes under the
    same budget; a match on mechanism, product or absence pattern tells you what
    worked there and what was a dead end.

    Treat it as a prior, not an answer. It reports why it matched so you can
    disagree with it. A precedent that anchors you onto a path this box does not
    have costs more than no precedent at all."""
    return _j(req("GET", f"/api/precedent?engagement_id={_engagement()}&limit={limit}"))


@mcp.tool()
def engagement_outcome(outcome: str, note: str = "", lab_time: str = "") -> str:
    """Record how this engagement ended: solved | parked | abandoned | open.

    `note` is the one line that matters to the next run — the mechanism that
    worked, or the specific blocker that stopped you. `lab_time` like "5m32".
    Without an outcome this engagement is invisible to `precedent`."""
    body = {"outcome": outcome}
    if note:
        body["outcome_note"] = note
    if lab_time:
        body["lab_time"] = lab_time
    return _j(req("PATCH", f"/api/engagements/{_engagement()}", body))


@mcp.tool()
def fact_out(fact_id: int) -> str:
    """Rule out a fact that turned out to be a dead end (kept for history,
    hidden from active views and the engine)."""
    return _j(req("PATCH", f"/api/facts/{fact_id}", {"status": "ruled-out"}))


@mcp.tool()
def fact_confirm(fact_id: int, stage: str = "confirmed") -> str:
    """Advance a fact along the confirmation lifecycle once you gather evidence for
    it. stage: observed (you saw it yourself now) | confirmed (you verified or
    exploited it). Use this when a CLAIMED lead pans out — e.g. the /about page
    claimed Qdrant, and you've now hit its API on :6333 (-> observed) and listed a
    collection (-> confirmed). A fact only moves forward, never back."""
    if stage not in ("observed", "confirmed"):
        raise ApiError("stage must be 'observed' or 'confirmed'")
    return _j(req("PATCH", f"/api/facts/{fact_id}", {"stage": stage}))


@mcp.tool()
def stack_add(host: str, components: str, stage: str = "claimed") -> str:
    """Record an application/AI tech stack as first-class NODES, linked to the host
    or service that runs them — never as free text. Pass `components` as a
    comma/newline list of `type:name` pairs; each becomes a typed entity node and a
    `backed-by` fact from the host/service to it. Types:
      rag-store  (vector DB: Qdrant, Chroma, Weaviate, Milvus, pgvector)
      model      (LLM / embedding model behind the app)
      service    (datastore/broker: MongoDB, Postgres, Redis, Elasticsearch)
      collection (a named index/collection inside a store)
      framework  (Flask, FastAPI, Django, Next.js)
      endpoint   (an API route the app exposes)
    Assessmentple: stack_add("example portal",
                       "rag-store:Qdrant, service:MongoDB, framework:Flask")
    `stage` defaults to `claimed` — a stack read off an /about page is unverified
    until you actually touch each component (then fact_confirm the backed-by fact)."""
    parts = [p.strip() for p in re.split(r"[,\n;]+", components) if p.strip()]
    if not parts:
        raise ApiError("stack_add needs at least one `type:name` component")
    made = []
    for p in parts:
        if ":" not in p:
            raise ApiError(f"component {p!r} must be `type:name` (e.g. rag-store:Qdrant)")
        ctype, cname = (x.strip() for x in p.split(":", 1))
        if not cname:
            raise ApiError(f"component {p!r} is missing a name")
        req("POST", "/api/facts", {
            "subject_name": host, "predicate": "backed-by",
            "object_name": cname, "object_type": ctype,
            "stage": stage, "source": "agent", "engagement_id": _engagement()})
        made.append({"type": ctype, "name": cname})
    return _jn({"host": host, "stage": stage, "components": made})


@mcp.tool()
def opp_list(status: str = "open") -> str:
    """List correlation-engine attack opportunities. CHECK THIS before starting
    new work - the engine joins your facts into suggested attack paths
    (privesc, cred reuse, exfil, poisoning). status: open|pinned|dismissed|converted."""
    return _j(req("GET", f"/api/opportunities?engagement_id={_engagement()}&status={status}"))


@mcp.tool()
def opp_convert(opp_id: int) -> str:
    """Convert an opportunity you will pursue into a pending task."""
    return _j(req("POST", f"/api/opportunities/{opp_id}/convert"))


@mcp.tool()
def opp_dismiss(opp_id: int) -> str:
    """Dismiss an opportunity that is not worth pursuing."""
    return _j(req("POST", f"/api/opportunities/{opp_id}/dismiss"))


@mcp.tool()
def tasks_pending() -> str:
    """List pending tasks queued by the operator. CHECK THIS (with opp_list)
    before starting new work, and at every phase boundary."""
    return _j(req("GET", f"/api/tasks?status=pending&engagement_id={_engagement()}"))


@mcp.tool()
def task_done(task_id: int) -> str:
    """Mark a queued task done after completing it."""
    return _j(req("POST", f"/api/tasks/{task_id}/done"))


@mcp.tool()
def sitrep_set(activity: str | None = None, hypothesis: str | None = None,
               next_steps: str | None = None) -> str:
    """Update the situation report the operator reads first. Set at every phase
    change: current activity, working hypothesis, next steps. Terse and honest."""
    body = {k: v for k, v in {"activity": activity, "hypothesis": hypothesis,
                              "next_steps": next_steps}.items() if v is not None}
    if not body:
        raise ApiError("pass at least one of activity/hypothesis/next_steps")
    return _j(req("PUT", f"/api/sitrep/{_engagement()}", body))


@mcp.tool()
def sitrep_show() -> str:
    """Show the current situation report (activity / hypothesis / next steps).
    `events_since` is how many hands-on events have landed since you last wrote
    it — anything above ~40 means your briefing no longer matches the board and
    the operator is reading a stale picture. Refresh it with sitrep_set."""
    return _j(req("GET", f"/api/sitrep/{_engagement()}"))


@mcp.tool()
def target_add(ip: str, hostname: str = "", os: str = "", role: str = "",
               status: str = "identified") -> str:
    """Register a host, or update its state as you progress. Idempotent by IP
    (safe to re-call); status only advances (identified->foothold->rooted), so
    call it the moment a host is discovered, when you get a foothold, and when
    you get root. This is what lifts the fog and colours the host on the live
    board. status: unidentified|identified|foothold|rooted|flagged."""
    return _jn(req("POST", "/api/targets", {
        "ip": ip, "hostname": hostname, "os": os, "role": role, "status": status,
        "engagement_id": _engagement()}))


@mcp.tool()
def svc_add(ip: str, port: int, proto: str = "tcp", name: str = "", product: str = "",
            version: str = "", extrainfo: str = "") -> str:
    """Register an open port/service on a known target immediately after discovery.
    Store the fields SEPARATELY — name (e.g. ssh), product (OpenSSH), version (9.5),
    extrainfo (protocol 2.0) — not one mashed banner string. Calling it again for
    the same port REFRESHES that service (e.g. adding product/version after a -sV);
    it never creates a second entry, and blank fields don't erase what's known."""
    t = find_target(ip)
    return _jn(req("POST", "/api/services", {
        "target_id": t["id"], "port": port, "proto": proto, "name": name,
        "product": product, "version": version, "extrainfo": extrainfo}))


@mcp.tool()
def cred_add(username: str = "", secret: str = "", target_ip: str | None = None,
             kind: str = "password", source: str = "", status: str | None = None) -> str:
    """Register a recovered credential immediately. PARTIAL creds are fine — pass
    only what you have: a bare token/key (secret, no username) or a username seen
    before its secret (username, no secret); at least one is required.
    kind: password|hash|ticket|key|token|api-key|principal (use token/api-key for
    bare secrets like xoxb-…, gldt-…, sk_live_…; principal for a username-only lead).
    status: untested|valid|invalid|partial (default: partial if half-known).
    Recording a valid cred on a known host feeds the reuse/spray engine.
    source: where it came from (e.g. 'config file on web01')."""
    if not (username or secret):
        raise ApiError("cred_add needs at least a username or a secret")
    body = {"username": username, "secret": secret, "kind": kind, "source": source}
    if status:
        body["status"] = status
    if target_ip:
        body["target_id"] = find_target(target_ip)["id"]
    return _jn(req("POST", "/api/credentials", body))


@mcp.tool()
def principal_add(name: str, kind: str = "username", realm: str = "",
                  target_ip: str | None = None, source: str = "") -> str:
    """Record one or MANY identities in one call — pass a comma/newline-separated
    list ('r.chen, m.silva, j.park, ts_svc') and EACH becomes its own structured
    principal. This is the RIGHT way to capture an enumerated user list (never a
    fact blob): the spray-matrix rule then cross-joins every principal against every
    candidate secret in the realm. kind: username|account|email|service-account|
    key-id. realm groups the matrix (e.g. an AD domain). source: where it came from."""
    names = [n.strip() for n in re.split(r"[,\n;]+", name) if n.strip()]
    if not names:
        raise ApiError("principal_add needs at least one name")
    tid = find_target(target_ip)["id"] if target_ip else None
    created = []
    for n in names:
        body = {"name": n, "kind": kind, "realm": realm, "source": source}
        if tid:
            body["target_id"] = tid
        created.append(req("POST", "/api/principals", body))
    return _jn({"created": len(created), "principals": [p.get("name") for p in created]})


@mcp.tool()
def secret_add(value: str, kind: str = "password", realm: str = "",
               target_ip: str | None = None, source: str = "") -> str:
    """Record AUTH MATERIAL with no owner yet — a candidate password, hash, ticket,
    private-key, api-key, or token. Use this for a spray LIST (call once per
    candidate password): the spray-matrix rule pairs each secret with every
    principal in the same realm. kind: password|hash|ntlm|ticket|private-key|
    api-key|token. realm groups the matrix. source: where it came from."""
    if not value:
        raise ApiError("secret_add needs a value")
    body = {"value": value, "kind": kind, "realm": realm, "source": source}
    if target_ip:
        body["target_id"] = find_target(target_ip)["id"]
    return _jn(req("POST", "/api/secrets", body))


@mcp.tool()
def binding_add(principal_id: int | None = None, secret_id: int | None = None,
                target_ip: str | None = None, status: str = "valid", source: str = "") -> str:
    """Pair a principal with a secret into a usable credential — record a CONFIRMED
    spray hit. Pass the principal_id and secret_id (from principal_list/secret_list
    or the ids returned by *_add). status valid on a known host asserts valid-on
    and feeds the reuse/spray (R3/R8) engine. At least one id is required."""
    if not (principal_id or secret_id):
        raise ApiError("binding_add needs a principal_id and/or secret_id")
    body = {"principal_id": principal_id, "secret_id": secret_id,
            "status": status, "source": source}
    if target_ip:
        body["target_id"] = find_target(target_ip)["id"]
    return _j(req("POST", "/api/bindings", body))


@mcp.tool()
def principal_list() -> str:
    """List harvested identities (principals) in the active engagement with ids."""
    return _j(req("GET", f"/api/principals?engagement_id={_engagement()}"))


@mcp.tool()
def secret_list() -> str:
    """List harvested auth material (secrets) in the active engagement with ids."""
    return _j(req("GET", f"/api/secrets?engagement_id={_engagement()}"))


@mcp.tool()
def finding_add(target_ip: str, title: str, severity: str = "medium",
                description: str = "") -> str:
    """Register a vulnerability finding on a target.
    severity: info|low|medium|high|critical."""
    t = find_target(target_ip)
    return _jn(req("POST", "/api/findings", {
        "target_id": t["id"], "title": title, "severity": severity,
        "description": description}))


@mcp.tool()
def exec(command: str, why: str = "", cwd: str | None = None, timeout: int = 120,
         background: bool = False) -> str:
    """Run a shell command. This is your execution surface — RedOps runs it,
    captures the command and its output to
    the ops feed, and returns the result. Use it for everything you'd run in a
    terminal (scanners, curl, scripts).

    `why`: one terse first-person clause on intent — it lands in the feed next to
    the command, so the operator sees your reasoning, not just your keystrokes.

    `background: true` detaches the command past the foreground 600s cap and
    returns a task_id — this is how you run long exploit loops and `nc -lvp`
    listeners. Poll output with exec_output(task_id), kill with exec_stop(task_id).

    Long FOREGROUND commands (timeout > FOREGROUND_BUDGET) are auto-detached:
    the MCP client cancels any tool call that blocks past ~60s, so the command
    is submitted as a `timeout`-wrapped background task and polled within the
    budget. If it finishes in time you get the normal result; if not you get
    {"pending": true, "task_id": N} — poll exec_output(N) from there.

    If the operator opts into the scope guard, a command outside its lists is
    refused. With the guard off (default), no RedOps scope denial runs.
    Returns {exit_code, stdout, stderr}.
    Output is captured in full and attributed to your focus_target, so you do not
    need to separately log what you ran."""
    body = {"command": command, "why": why, "timeout": timeout}
    if cwd:
        body["cwd"] = cwd
    if background:
        body["background"] = True
        return _j(req("POST", "/api/exec", body))

    timeout = max(1, min(int(timeout), 600))
    body["timeout"] = timeout
    if timeout <= FOREGROUND_BUDGET:
        # Foreground: the HTTP call must outlive the server-side run, so give
        # it the requested timeout + slack. Without this the shared client's
        # short default kills the call long before the command finishes.
        return _j(req("POST", "/api/exec", body, timeout=timeout + 30))

    # Auto-detach: an MCP client cancels the tool call around ~60s (-32001),
    # so a synchronous wait for a longer command always fails client-side even
    # when the API is healthy. Run it as a background task instead — wrapped in
    # `timeout` so it still self-terminates (the background path has no cap) —
    # and poll within the client-safe budget.
    body["background"] = True
    body["command"] = f"timeout {timeout} bash -lc {shlex.quote(command)}"
    r = req("POST", "/api/exec", body, timeout=30)
    if r.get("blocked"):
        return _j(r)
    task_id = r["task_id"]
    t = _poll_exec_task(task_id, time.monotonic() + FOREGROUND_BUDGET)
    if t is None:
        return _j({"blocked": False, "pending": True, "task_id": task_id,
                   "note": f"still running past the {FOREGROUND_BUDGET}s MCP "
                           f"client budget; poll exec_output({task_id}), kill "
                           f"with exec_stop({task_id})"})
    return _j({"blocked": False, "detached": True, "task_id": task_id,
               "exit_code": t.get("exit_code"), "status": t.get("status"),
               "stdout": t.get("output", ""), "stderr": ""})


@mcp.tool()
def exec_output(task_id: int, tail: int = 4000) -> str:
    """Poll a background exec task: status, exit_code, and the last `tail` bytes
    of its output file. The task_id comes from exec(..., background=true)."""
    return _j(req("GET", f"/api/exec_tasks/{task_id}?tail={tail}"))


@mcp.tool()
def exec_stop(task_id: int) -> str:
    """Kill a background exec task (the whole process group — a listener's
    children die too). Use when a listener has served its purpose or an exploit
    loop needs to stop."""
    return _j(req("POST", f"/api/exec_tasks/{task_id}/stop"))


@mcp.tool()
def write_file(path: str, content: str = "", content_b64: str = "") -> str:
    """Stage a file (exploit source, script, wordlist) inside the per-engagement
    workdir — you have no native file access, this is your filesystem. `path` is
    relative to the workdir; the returned absolute path can be used as `cwd` or
    in exec commands. Use content_b64 for binary payloads."""
    body = {"path": path, "engagement_id": _engagement()}
    if content_b64:
        body["content_b64"] = content_b64
    else:
        body["content"] = content
    return _j(req("POST", "/api/fs/write", body))


@mcp.tool()
def read_file(path: str, max_bytes: int = 1048576) -> str:
    """Read a file back from the per-engagement workdir (capped at max_bytes).
    Returns the decoded text when it is valid UTF-8, else the raw base64
    payload with a note."""
    r = req("GET", f"/api/fs/read?path={path}&max_bytes={max_bytes}"
            f"&engagement_id={_engagement()}")
    raw = base64.b64decode(r.get("content_b64", ""))
    try:
        r["content"] = raw.decode("utf-8")
        del r["content_b64"]
    except UnicodeDecodeError:
        r["note"] = "binary content — returning base64, decode before use"
    return _j(r)


@mcp.tool()
def fetch_url(url: str) -> str:
    """Download a tool/exploit/wordlist operator-side into data/downloads/ —
    this replaces web fetching, which a locked-down agent does not have.
    Allowed domains come from REDOPS_FETCH_ALLOW (default: github, gitlab,
    exploit-db sources); anything else is refused. Then read it in with
    write_file/exec as needed."""
    return _j(req("POST", "/api/fetch", {"url": url, "engagement_id": _engagement()}))


@mcp.tool()
def callbacks_pending() -> str:
    """Observed inbound connections (callbacks) that no finding has cited yet.

    A callback is a target opening a connection to YOU that you did not solicit —
    a reverse shell, a C2 beacon, or a blind-command side effect calling home. It
    is ground truth off the wire, not an agent claim, so it is the out-of-band
    confirmation that an effect actually FIRED. Each entry lists the open findings
    on that source host as candidate claims the callback might prove. Cite one
    with finding_verify(method='callback', flow_id=...). Do NOT guess: if no
    finding matches, the callback may be an effect you have not filed yet."""
    return _j(req("GET", f"/api/callbacks?engagement_id={_engagement()}"))


@mcp.tool()
def finding_verify(finding_id: int, result: str, method: str = "manual",
                   flow_id: int | None = None, note: str = "") -> str:
    """Record that a finding was TESTED, and what happened. This is how a claim's
    trust moves — confidence is derived from these events, never typed. You must
    state the `result`; there is no default, because 'I ran it' and 'it worked'
    are different claims.

    result: reproduced | not-reproduced | partial | errored.
    method: 'callback' cites an observed inbound flow (flow_id from
    callbacks_pending) as out-of-band proof the effect fired — the strongest
    evidence available on a live target. It REQUIRES a flow_id, the flow must be
    an established inbound connection, and it must be on this finding's own host;
    a callback from another box does not prove this claim. 'tool'/'manual' record
    a test whose proof is elsewhere (attach it with evidence_add).

    A `reproduced` callback moves the finding to live-verified. A
    `not-reproduced` result marks it CONTESTED — the record that stops the next
    agent re-filing a plausible-but-false bug; file it even when the effect did
    NOT fire. None of this changes the finding's status; that is a separate
    deliberate call."""
    body = {"result": result, "method": method, "note": note}
    if flow_id is not None:
        body["flow_id"] = flow_id
    return _j(req("POST", f"/api/findings/{finding_id}/verify", body))


@mcp.tool()
def evidence_add(file_path: str, finding_id: int | None = None, target_ip: str | None = None,
                 caption: str = "") -> str:
    """Attach PROOF to a finding/target — a screenshot or command-output file.
    Write the artifact to a file first (e.g. a .png shell screenshot or a .txt of
    the output), then call this with its path. Attach it to a finding (finding_id
    from finding_add) and/or a host (target_ip). This is how a claim becomes
    evidence in the report — do it on every proof (AGENTS.md §3)."""
    if not os.path.isfile(file_path):
        raise ApiError(f"file not found: {file_path} (write the artifact to disk first)")
    fields = {"caption": caption, "engagement_id": _engagement()}
    if finding_id is not None:
        fields["finding_id"] = finding_id
    if target_ip:
        fields["target_id"] = find_target(target_ip)["id"]
    return _j(post_multipart("/api/evidence", fields, "file", file_path))


@mcp.tool()
def objective_add(text: str, value: str = "", target_ip: str | None = None) -> str:
    """Record an OBJECTIVE / captured flag — the engagement's win condition. Use
    when you recover the thing the assessment is after (a flag, a deploy token, a
    password answer). value = the flag/answer itself; target_ip = the host the
    proof lives on. Returns the objective id; close it later with objective_done."""
    if not text.strip():
        raise ApiError("objective_add needs a text description")
    body = {"text": text, "value": value, "engagement_id": _engagement()}
    if target_ip:
        body["target_id"] = find_target(target_ip)["id"]
    return _j(req("POST", "/api/objectives", body))


@mcp.tool()
def objective_done(objective_id: int, value: str | None = None, evidence_id: int | None = None) -> str:
    """Mark an objective captured/complete. Optionally set the final value and link
    an evidence_id (from evidence_add) as proof."""
    body = {"status": "done"}
    if value is not None:
        body["value"] = value
    if evidence_id is not None:
        body["evidence_id"] = evidence_id
    return _j(req("PATCH", f"/api/objectives/{objective_id}", body))


# ---- READ PARITY: everything the operator sees on the board, the agent can query
# by the same name. When the operator points at something ("this callback", "that
# finding", "the valid cred"), fetch the SAME data they're looking at. -----------

@mcp.tool()
def host_list() -> str:
    """Every host in the engagement with its dossier — ip, hostname, os, role
    (domain-controller/web/database/linux-host), status. These are the host cards
    on the scope map; read this to see what the operator sees when they name a host."""
    return _j(req("GET", f"/api/targets?engagement_id={_engagement()}"))


@mcp.tool()
def svc_list(ip: str | None = None) -> str:
    """Discovered services (structured: port/proto/name/product/version/cpe) — the
    whole engagement, or one host's if you pass its ip."""
    if ip:
        return _j(req("GET", f"/api/services?target_id={find_target(ip)['id']}"))
    return _j(req("GET", f"/api/services?engagement_id={_engagement()}"))


@mcp.tool()
def finding_list(ip: str | None = None) -> str:
    """Findings/vulns recorded on the host cards — the whole engagement, or one
    host's if you pass its ip. Read before finding_add so you don't duplicate."""
    if ip:
        return _j(req("GET", f"/api/findings?target_id={find_target(ip)['id']}"))
    return _j(req("GET", f"/api/findings?engagement_id={_engagement()}"))


@mcp.tool()
def cred_list() -> str:
    """Credentials the operator sees — username + secret + kind + status
    (untested/valid/invalid/partial). This is where you check WHICH creds actually
    authenticated, not just which identities/secrets exist (principal_list/secret_list
    are the raw pools; this is the paired, tested view)."""
    return _j(req("GET", f"/api/credentials?engagement_id={_engagement()}"))


@mcp.tool()
def objective_list() -> str:
    """The engagement's objectives / win conditions and whether each is captured —
    the mission list the operator tracks. Read it to know what you're actually after."""
    return _j(req("GET", f"/api/objectives?engagement_id={_engagement()}"))


@mcp.tool()
def callbacks() -> str:
    """Unsolicited INBOUND connections the wire sensor observed — a target opened a
    connection to YOU (reverse shell, C2 beacon, exfil, or a blind-command side
    effect calling home). This is ground truth off the wire, the high-signal
    out-of-band confirmation an effect fired. When the operator asks about "the
    callback", this is what they mean — NOT any scheduled job of yours."""
    return _j(req("GET", f"/api/flows?engagement_id={_engagement()}"
                  "&direction=in&opened_only=true&known_target_only=true"))


@mcp.tool()
def flows(direction: str | None = None) -> str:
    """Observed network flows off the wire sensor (tcpdump ground truth), one row
    per (src,dst,dport,proto). direction: 'in' (callbacks — target->you), 'out'
    (you->target), 'transit', or omit for all. Unlike facts, these are packets we
    actually saw, not claims."""
    q = f"/api/flows?engagement_id={_engagement()}"
    if direction:
        q += f"&direction={direction}"
    return _j(req("GET", q))


@mcp.tool()
def feed(kind: str | None = None, limit: int = 40) -> str:
    """Read the live event feed the operator is watching — actions, tool output,
    notes, wire flows/callbacks — including events YOU didn't author (operator runs,
    wire-auto, other tools). kind filters (e.g. 'callback', 'flow', 'output',
    'note'). Use this to catch up on what happened out-of-band."""
    q = f"/api/events?engagement_id={_engagement()}&limit={int(limit)}"
    if kind:
        q += f"&kind={kind}"
    return _j(req("GET", q))


@mcp.tool()
def map() -> str:
    """The scope map itself — graph nodes (typed entities: hosts, services,
    rag-stores, models, principals…) and edges (facts, each with its stage:
    claimed/observed/confirmed). The topology the operator is looking at."""
    return _j(req("GET", f"/api/graph?engagement_id={_engagement()}"))


@mcp.tool()
def lead_dismiss(lead_id: int) -> str:
    """Dismiss a lead that turned out to be a dead end — keeps it out of the
    worklist. (You are a sensor, not a judge: rule OUT dead ends too, not just
    add new ones, or the worklist fills with noise.)"""
    return _j(req("POST", f"/api/leads/{lead_id}/dismiss"))


@mcp.tool()
def payload_add(technique: str, body: str = "", target_model: str = "", target_ref: str = "",
                guardrail_defeated: str = "", outcome: str = "untried", notes: str = "") -> str:
    """Save an injection payload/technique to the reusable library. Record it the
    moment you try one — success is model-dependent, so a library keyed by
    (technique, model, guardrail) saves re-deriving what worked.
    technique: e.g. char-spacing | crescendo | cross-doc-fragmentation |
    css-concealment | import-resolution | descriptive-db-poison.
    target_model: the model you hit (e.g. qwen2.5-7b) — evasions vary by model.
    guardrail_defeated: which rule/filter this got past.
    outcome: untried|worked|failed|blocked."""
    return _j(req("POST", "/api/payloads", {
        "technique": technique, "body": body, "target_model": target_model,
        "target_ref": target_ref, "guardrail_defeated": guardrail_defeated,
        "outcome": outcome, "notes": notes}))


@mcp.tool()
def payload_list(outcome: str | None = None) -> str:
    """List saved payloads for the engagement (reuse what worked). Optionally
    filter by outcome (worked|failed|blocked|untried)."""
    items = req("GET", f"/api/payloads?engagement_id={_engagement()}")
    if outcome:
        items = [p for p in items if p.get("outcome") == outcome]
    return _j(items)


@mcp.tool()
def rule_add(name: str, source_system: str = "", match_mechanism: str = "",
             blind_spot: str = "", evasion: str = "", fired: bool = False,
             notes: str = "") -> str:
    """Record a detection rule you enumerated (the core loop: read the rule,
    evade by mechanism). Log it after the naive attempt shows which rule fired.
    name: e.g. 'AIM3: Prompt Injection Keywords in Agent Input'.
    source_system: elk | phoenix | ... . match_mechanism: how it matches (exact
    substring / keyword density / per-file scan). blind_spot: what it misses.
    evasion: the technique that beats it. fired: did it trip on your attempt."""
    return _j(req("POST", "/api/detection_rules", {
        "name": name, "source_system": source_system, "match_mechanism": match_mechanism,
        "blind_spot": blind_spot, "evasion": evasion, "fired": fired, "notes": notes}))


@mcp.tool()
def rule_list() -> str:
    """List the detection-rule catalog for the engagement (what to evade)."""
    return _j(req("GET", f"/api/detection_rules?engagement_id={_engagement()}"))


@mcp.tool()
def poison_add(location: str, store_type: str = "other", verify_method: str = "",
               payload_id: int | None = None, notes: str = "") -> str:
    """Track something you planted so you can verify it and clean up later.
    location: where (db table/row, doc name, bucket key, URL, agent-card host).
    store_type: kb-db | rag | minio | agent-card | registry | file | other.
    verify_method: how to confirm it's live (often 'query the agent', not the DB).
    payload_id: link to the payload you planted, if saved."""
    body = {"location": location, "store_type": store_type,
            "verify_method": verify_method, "notes": notes}
    if payload_id is not None:
        body["payload_id"] = payload_id
    return _j(req("POST", "/api/poison", body))


@mcp.tool()
def poison_list() -> str:
    """List planted poison for the engagement (provenance + cleanup tracking).
    Review before wrap-up so nothing planted is left behind."""
    return _j(req("GET", f"/api/poison?engagement_id={_engagement()}"))


@mcp.tool()
def poison_mark_cleaned(poison_id: int, note: str = "") -> str:
    """Mark a planted item cleaned after independently verifying its removal."""
    rows = json.loads(poison_list())
    item = next((row for row in rows if row["id"] == poison_id), None)
    if item is None:
        raise ApiError("poison item not found in pinned engagement")
    body = {"live": 0, "cleanup_done": 1}
    if note:
        body["notes"] = (item.get("notes") or "") + "\nCleanup: " + note
    return _j(req("PATCH", f"/api/poison/{poison_id}", body))


@mcp.tool()
def lead_add(observation: str, category: str = "anomaly", candidate_vector: str = "") -> str:
    """Record a hunch or expansion item as a lead (NOT for structured facts -
    use fact_add for those). category: one of the 13 (write-primitive,
    priv-context, restart-trigger, auth-gap, reachability-pivot,
    secret-exposure, read-exfil, anomaly, llm-read-sink, action-tool,
    trust-edge, detection-tripwire, guardrail-blindspot). When in doubt: anomaly."""
    return _jn(req("POST", "/api/leads", {
        "observation": observation, "category": category,
        "candidate_vector": candidate_vector, "source": "agent"}))


@mcp.tool()
def worklist(status: str = "open") -> str:
    """The ranked worklist: open opportunities + open leads + lone interesting
    facts, score-descending. Review this at every phase boundary."""
    eng = _engagement()          # the agent's PIN, not the operator's selection
    items = req("GET", f"/api/worklist?engagement_id={eng}")
    return _j(items)


@mcp.tool()
def lead_promote(lead_id: int, facts: list | None = None) -> str:
    """Promote a lead: structure the hunch into fact(s) (never duplicates),
    then re-correlate. Returns new opportunity ids."""
    return _j(req("POST", f"/api/leads/{lead_id}/promote", {"facts": facts or []}))


@mcp.tool()
def focus_target(ip: str | None = None) -> str:
    """Set the box you're currently working; all captured wire/transcript
    output is attributed to it until changed. Call whenever you switch boxes.
    Pass no argument (or None) to clear the pointer."""
    eng = _engagement()
    if ip is None:
        return _j(req("PUT", "/api/current_target",
                      {"engagement_id": eng, "target_id": None}))
    t = find_target(ip)
    return _j(req("PUT", "/api/current_target",
                  {"engagement_id": eng, "target_id": t["id"]}))


@mcp.tool()
def tool_results(ip: str | None = None, run_id: int | None = None,
                 limit: int = 40, before_id: int | None = None) -> str:
    """Read captured output for one run or a page of runs. For historical
    runs, pass before_id from the oldest returned id; limit is capped at 200.
    The active engagement always bounds the list and any single run."""
    eng = _engagement()
    if run_id is not None:
        row = req("GET", f"/api/tools/run/{run_id}")
        if row.get("engagement_id") != eng:
            raise ValueError("run does not belong to the active engagement")
        return _j(row)
    query = f"engagement_id={eng}&limit={max(1, min(limit, 200))}"
    if before_id is not None:
        query += f"&before_id={before_id}"
    if ip:
        t = find_target(ip)
        query += f"&target_id={t['id']}"
    return _j(req("GET", f"/api/tools/runs?{query}"))


@mcp.tool()
def tool_specs() -> str:
    """List runnable tools with their typed options and presets. Call this before
    tool_run so you pass valid preset/opts. nmap presets: quick|service|full|rag."""
    return _j(req("GET", "/api/tools/specs"))


@mcp.tool()
def tool_run(ip: str, tool: str = "nmap", preset: str | None = None,
             opts: dict | None = None, priority: int | None = None,
             port: int | None = None) -> str:
    """QUEUE a deterministic tool against a host; result lands in the shared store
    (read tool_results). Agent runs auto-start by default in a parallel,
    priority-ordered pool — set priority (1=low..9=high) to jump the line.
    Scope denial and approval are optional operator settings.
    tool: nmap (preset quick|service|full|rag, or opts like {"ports":"custom",
    "custom_ports":"6333,6334","versions":true}); agent-card | agent-probe for A2A
    recon (pass port or ip as 'host:port'). Legacy ids quick-scan|port-scan|full-scan
    still work. See tool_specs for the full option list. Prefer these over shelling out."""
    t = find_target(ip)
    body = {"tool": tool, "target_id": t["id"], "ip": ip, "actor": "agent"}
    if preset is not None:
        body["preset"] = preset
    if opts is not None:
        body["opts"] = opts
    if priority is not None:
        body["priority"] = priority
    if port is not None:
        body["port"] = port
    return _j(req("POST", "/api/tools/run", body))


@mcp.tool()
def run(command: str, background: bool = False, target_ip: str | None = None,
        timeout: int = 1800, local: bool = False) -> str:
    """Run an ARBITRARY command through RedOps — the escape hatch for tools not yet
    first-class. Captured to
    the board, but the output is NOT parsed into facts — so record real findings
    yourself with fact_add / svc_add / cred_add / stack_add afterwards. Prefer a
    dedicated tool (tool_run, the *_add tools) whenever one fits; this is the bridge
    for the long tail, not a substitute. Scope denial is off by default and
    can be explicitly enabled by the operator.
    Shell operators work — pipes, redirects, &&, globs (run through sh -c when
    present), so `curl -s http://h/ | head -80` is fine as-is. The real exit code
    is reported: exit code 0 = success, anything else comes back as status error.

    background=True queues the command on the shared pool and returns a run id
    IMMEDIATELY instead of blocking your turn. Use it for anything slow (full-port
    scans, brute force, long fetches) so you can work several avenues at once —
    track them with queue_show and read the captured output with tool_results
    once done. Keep background=False for the quick interactive loop where you
    need the output to decide the next step. The bounded timeout can be raised
    to 14400 seconds for a long AI CLI session; a timeout kills its process group
    and preserves output observed before the deadline. Set target_ip to attribute the
    captured run to a known host for reporting and evidence import. Set
    local=True for local diagnostics: it forces no
    target attribution even if another agent has set shared focus. It does not
    skip scope review or command capture."""
    if not 1 <= timeout <= 14400:
        raise ValueError('timeout must be between 1 and 14400 seconds')
    if local and target_ip:
        raise ValueError('local and target_ip cannot both be set')
    body = {"command": command, "actor": "agent", "background": bool(background),
            "engagement_id": _engagement(), "timeout": timeout, "local": local}
    if target_ip:
        body["target_ip"] = target_ip
    return _j(req("POST", "/api/tools/exec",
                  body))


def _report_case_modules():
    kit = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'report-kit')
    if kit not in sys.path:
        sys.path.append(kit)
    import report
    from capture_import import import_capture
    from casehub import CaseHub
    from pathlib import Path
    return report, import_capture, CaseHub, Path


def _report_engagement_case():
    """Return the one REPORT case reserved for this pinned RedOps engagement."""
    report, _, _, Path = _report_case_modules()
    engagement = _engagement()
    root = Path(__file__).resolve().parents[1] / 'data' / 'work' / str(engagement) / 'report-case'
    return report, engagement, root


def _report_loaded_engagement_case():
    report, engagement, root = _report_engagement_case()
    try:
        case = report.load(root)
    except SystemExit as exc:
        raise ValueError(str(exc)) from exc
    bound = case.get('redops_engagement_id')
    if bound is not None and bound != engagement:
        raise ValueError('REPORT case belongs to another engagement')
    return report, engagement, root, case


def _report_apply(action, **kwargs):
    """Use the same case lock and validation as the REPORT CLI."""
    from argparse import Namespace
    report, engagement, root, _ = _report_loaded_engagement_case()
    try:
        with report.case_lock(root):
            action(Namespace(root=str(root), **kwargs))
    except SystemExit as exc:
        raise ValueError(str(exc)) from exc
    return root, engagement


@mcp.tool()
def report_case_init(title: str, scope: str, report_id: str = 'RPT-PRACTICE') -> str:
    """Create the REPORT case for this pinned engagement at
    data/work/<engagement>/report-case. Give the exact current authorization in
    scope; the generic agent guide never supplies target addresses. An exact
    retry is safe. The case path is returned for evidence-import tools."""
    from argparse import Namespace
    report, engagement, root = _report_engagement_case()
    if not title.strip() or not scope.strip():
        raise ValueError('title and scope are required')
    root.parent.mkdir(parents=True, exist_ok=True)
    if (root / 'case.json').is_file():
        _, _, _, case = _report_loaded_engagement_case()
        if (case.get('title'), case.get('scope'), case.get('report_id')) != (title, scope, report_id):
            raise ValueError('REPORT case already exists with different metadata')
        return _j({'case_dir': str(root), 'engagement_id': engagement,
                   'created': False})
    try:
        report.do_init(Namespace(root=str(root), title=title, scope=scope, report_id=report_id))
    except SystemExit as exc:
        raise ValueError(str(exc)) from exc
    with report.case_lock(root):
        case = report.load(root)
        case['redops_engagement_id'] = engagement
        report.save(root, case)
    return _j({'case_dir': str(root), 'engagement_id': engagement,
               'created': True})


@mcp.tool()
def report_target_add(target: str, name: str, ip: str, role: str,
                    objective: str, summary: str, unscored: bool = False,
                    required_stages: str | None = None) -> str:
    """Add one assigned target to this engagement's REPORT case. The IP must
    already be a target in the pinned RedOps engagement. Use unscored only for
    a genuinely unscored/supporting host; scored targets keep proof gates."""
    report, engagement, root, case = _report_loaded_engagement_case()
    find_target(ip)
    existing = case['targets'].get(target)
    if existing:
        if existing.get('ip') != ip:
            raise ValueError('REPORT target ID already belongs to another IP')
        return _j({'case_dir': str(root), 'engagement_id': engagement,
                   'target': target, 'created': False})
    root, engagement = _report_apply(
        report.do_target, id=target, name=name, ip=ip, role=role,
        objective=objective, summary=summary, unscored=unscored,
        required_stages=required_stages)
    return _j({'case_dir': str(root), 'engagement_id': engagement,
               'target': target, 'created': True})


@mcp.tool()
def report_stage_add(target: str, kind: str, summary: str,
                   analysis: str = '') -> str:
    """Open a documented REPORT stage. REPORT enforces stage order and direct
    screenshot gates before advancing scored targets."""
    report, _, _, _ = _report_loaded_engagement_case()
    root, engagement = _report_apply(report.do_stage, target=target,
                                    kind=kind, summary=summary, analysis=analysis)
    return _j({'case_dir': str(root), 'engagement_id': engagement,
               'target': target, 'stage': kind})


@mcp.tool()
def report_stage_revise(target: str, kind: str, summary: str,
                      analysis: str = '') -> str:
    """Update a stage's summary and observed-result analysis after capture."""
    report, _, _, _ = _report_loaded_engagement_case()
    root, engagement = _report_apply(report.do_revise_stage, target=target,
                                    kind=kind, summary=summary, analysis=analysis)
    return _j({'case_dir': str(root), 'engagement_id': engagement,
               'target': target, 'stage': kind})


@mcp.tool()
def report_narrative_set(target: str, entry_point: str, vulnerability: str,
                       attack_path: str, impact: str, reproduction: str) -> str:
    """Write the five required per-target assessment-report narrative fields from
    observed evidence. Do not claim a foothold or proof without capture."""
    report, _, _, _ = _report_loaded_engagement_case()
    root, engagement = _report_apply(
        report.do_narrative, target=target, entry_point=entry_point,
        vulnerability=vulnerability, attack_path=attack_path, impact=impact,
        reproduction=reproduction)
    return _j({'case_dir': str(root), 'engagement_id': engagement,
               'target': target})


@mcp.tool()
def report_proof_set(target: str, path: str, value: str) -> str:
    """Record an exact proof path and value in the pinned engagement's REPORT
    case. The proof stage must already exist. Preserve every byte of the value;
    direct proof and control-panel captures are separate required steps."""
    report, engagement, root, _ = _report_loaded_engagement_case()
    if not path.strip() or not value.strip():
        raise ValueError('proof path and value are required')
    try:
        with report.case_lock(root):
            case = report.load(root)
            report.stage(case, target, 'proof')
            case['targets'][target]['proof'] = {
                'path': path, 'value': value, 'recorded': report.now()}
            case['review'] = None
            report.save(root, case)
    except SystemExit as exc:
        raise ValueError(str(exc)) from exc
    return _j({'case_dir': str(root), 'engagement_id': engagement,
               'target': target, 'proof_path': path,
               'proof_sha256': report.text_sha256(value)})


@mcp.tool()
def report_browser_screenshot(target: str, stage: str, url: str, caption: str,
                            role: str = 'evidence', vhost: str | None = None) -> str:
    """Capture a real Chromium screenshot of one assigned HTTP(S) target and
    attach it to the REPORT case as direct evidence. With scope_guard off, the
    browser loads normal page resources. With the guard on, a target-only proxy
    applies. For a virtual host, set vhost to the URL hostname. Portal
    submission screenshots require operator capture."""
    from argparse import Namespace
    from pathlib import Path
    from urllib.parse import urlsplit
    from redops.scoped_browser import capture, capture_unrestricted
    report, engagement, root, case = _report_loaded_engagement_case()
    try:
        ip = case['targets'][target]['ip']
        report.stage(case, target, stage)
        address = ipaddress.ip_address(ip)
    except (KeyError, ValueError, SystemExit) as exc:
        raise ValueError(f'invalid REPORT target or stage: {exc}') from exc
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError('browser target must be an assigned non-local IP')
    find_target(ip)
    guard_on = bool(req('GET', '/api/settings').get('scope_guard', {}).get('value'))
    if guard_on:
        scoped = req('GET', f'/api/scope/{engagement}')
        allow = [ipaddress.ip_network(item, strict=False) for item in scoped.get('in', [])]
        block = [ipaddress.ip_network(item, strict=False) for item in scoped.get('out', [])]
        if not allow or not any(address in network for network in allow) or any(
                address in network for network in block):
            raise ValueError('target IP is outside the engagement allowlist')
    parsed = urlsplit(url)
    host = (parsed.hostname or '').lower().rstrip('.')
    if parsed.scheme not in ('http', 'https') or not host or parsed.username or parsed.password:
        raise ValueError('a plain HTTP(S) target URL is required')
    if host != ip.lower():
        if vhost is None or host != vhost.lower().rstrip('.') or not re.fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9_.-]*', vhost):
            raise ValueError('URL hostname must be the target IP or explicit vhost')
    if role not in ('evidence', 'proof_file', 'proof_value'):
        raise ValueError('target browser capture cannot claim a Portal role')
    if not caption.strip():
        raise ValueError('screenshot caption is required')
    build = root / 'build'
    build.mkdir(exist_ok=True)
    import contextlib
    import io
    import tempfile
    with tempfile.TemporaryDirectory(prefix='browser-', dir=build) as tmp:
        source = Path(tmp) / 'target.png'
        observed = (capture(url, ip, host, source) if guard_on
                    else capture_unrestricted(url, source))
        if guard_on and not observed['allowed_connections']:
            raise ValueError('browser never connected to the assigned target')
        if guard_on and observed['blocked_connections']:
            raise ValueError('page requested out-of-scope destinations; screenshot '
                             'was not attached: ' + ', '.join(observed['blocked_connections']))
        with report.case_lock(root):
            output = io.StringIO()
            try:
                with contextlib.redirect_stdout(output):
                    report.do_screenshot(Namespace(root=str(root), target=target,
                                                stage=stage, file=str(source),
                                                role=role, caption=caption,
                                                actor='redops-browser'))
            except SystemExit as exc:
                raise ValueError(str(exc)) from exc
            case = report.load(root)
            shot = case['events'][-1]
            report.add_event(root, case, {
                'target': target, 'stage': stage, 'kind': 'browser',
                'text': f'Open {url} through scoped Chromium proxy',
                'result': json.dumps({
                    'screenshot_id': shot['id'],
                    'connection_mode': observed['connection_mode'],
                    'allowed_connections': observed['allowed_connections'],
                    'blocked_connections': observed['blocked_connections'],
                    'browser_stdout': observed['browser_stdout'],
                    'browser_stderr': observed['browser_stderr']},
                    ensure_ascii=False)}, actor='redops-browser')
    with _report_case_modules()[2](root, actor='redops-browser') as hub:
        hub.sync_evidence()
    log(f'Captured direct REPORT browser screenshot {shot["id"]} '
        f'for {url} (sha256 {shot["sha256"]})', kind='action', target_ip=ip)
    return _j({'case_dir': str(root), 'engagement_id': engagement,
               'target': target, 'stage': stage, 'screenshot_id': shot['id'],
               'sha256': shot['sha256'], 'file': str(root / shot['file']),
               'connection_mode': observed['connection_mode'],
               'allowed_connections': observed['allowed_connections'],
               'blocked_connections': observed['blocked_connections']})


def _report_import_row(row: dict, case_dir: str, target: str, stage: str,
                     sync_casehub: bool = True) -> dict:
    engagement = _engagement()
    if row.get('engagement_id') != engagement:
        raise ValueError('run does not belong to the active engagement')
    if row.get('status') not in ('done', 'error'):
        raise ValueError('run is not complete')
    report, import_capture, CaseHub, Path = _report_case_modules()
    root = Path(case_dir).resolve()
    case = report.load(root)
    prior_engagements = {str(e.get('source_engagement') or
                             (e.get('source_key', '').split(':') + [''])[1])
                         for e in case['events'] if e.get('source_system') == 'redops'}
    if prior_engagements and prior_engagements != {str(engagement)}:
        raise ValueError('case already contains runs from another engagement')
    match = re.search(r'exit code (-?\d+)', row.get('summary') or '')
    exit_code = row.get('exit_code')
    if exit_code is None and match:
        exit_code = int(match.group(1))
    capture = {'source_system': 'redops', 'source_engagement': engagement,
               'source_id': row['id'], 'command': row['command'],
               'output': row.get('output') or '', 'status': row['status'],
               'exit_code': exit_code, 'actor': row.get('actor') or 'agent',
               'recorded_at': row.get('started_at') or ''}
    try:
        event_id = import_capture(root, target, stage, capture)
    except SystemExit as exc:
        raise ValueError(str(exc)) from exc
    if sync_casehub:
        with CaseHub(root, actor='redops-bridge') as hub:
            hub.sync_evidence()
    return {'evidence_id': event_id, 'run_id': row['id'], 'exit_code': exit_code}


@mcp.tool()
def report_import_run(run_id: int, case_dir: str, target: str, stage: str) -> str:
    """Import one completed run from this engagement into an existing REPORT
    target and stage. The transcript, rendered image, and CaseHub index are
    updated together. Repeated imports keep the same evidence ID."""
    row = json.loads(tool_results(run_id=run_id))
    return _j(_report_import_row(row, case_dir, target, stage))


@mcp.tool()
def report_import_runs(case_dir: str, target: str, stage: str, target_ip: str,
                     after_run_id: int = 0) -> str:
    """Import every completed, focused run for one host into one REPORT stage.
    Pages through the whole engagement history, not just the latest 40 runs.
    Call at each phase boundary; repeating it is safe. after_run_id lets you
    limit the import to work since a known phase boundary."""
    report, _, _, Path = _report_case_modules()
    case = report.load(Path(case_dir).resolve())
    report.stage(case, target, stage)
    if case['targets'][target].get('ip') != target_ip:
        raise ValueError('case target IP does not match target_ip')
    find_target(target_ip)
    rows = []
    before_id = None
    while True:
        page = json.loads(tool_results(ip=target_ip, limit=40, before_id=before_id))
        if before_id is not None and page and page[-1]['id'] >= before_id:
            raise RuntimeError('run-history cursor was ignored; restart the API server')
        rows.extend(row for row in page if row['id'] > after_run_id)
        if len(page) < 40 or page[-1]['id'] <= after_run_id:
            break
        before_id = page[-1]['id']
    prior = {}
    for event in case['events']:
        if event.get('source_system') != 'redops' or event.get('kind') != 'command':
            continue
        source_id = event.get('source_id') or event.get('source_key', '').rsplit(':', 1)[-1]
        if str(source_id).isdigit():
            prior[int(source_id)] = event
    imported, already_imported = [], []
    try:
        for row in sorted(rows, key=lambda item: item['id']):
            if row.get('status') not in ('done', 'error'):
                continue
            old = prior.get(row['id'])
            if old and (old['target'], old['stage']) != (target, stage):
                already_imported.append({'run_id': row['id'], 'target': old['target'],
                                         'stage': old['stage']})
                continue
            imported.append(_report_import_row(row, case_dir, target, stage,
                                             sync_casehub=False))
    finally:
        with _report_case_modules()[2](Path(case_dir).resolve(), actor='redops-bridge') as hub:
            hub.sync_evidence()
    pending = [row['id'] for row in rows if row.get('status') not in ('done', 'error')]
    return _j({'engagement_id': _engagement(), 'target': target, 'stage': stage,
               'imported': imported, 'already_imported': already_imported,
               'pending_run_ids': pending})


@mcp.tool()
def report_build(case_dir: str) -> str:
    """Check REPORT evidence gates and build its searchable PDF. Returns the
    exact blockers or the PDF path and SHA256. Visual review and packaging
    remain separate operator steps."""
    report, _, CaseHub, Path = _report_case_modules()
    root = Path(case_dir).resolve()
    with report.case_lock(root):
        case = report.load(root)
        errors = report.validate(root, case)
        if errors:
            return _j({'ready': False, 'blockers': errors})
        import contextlib
        import io
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                pdf = report.build_pdf(root, case)
        except SystemExit:
            return _j({'ready': False, 'blockers': [output.getvalue().strip() or
                       'PDF build or text verification failed']})
        case['review'] = None
        report.save(root, case)
    with CaseHub(root, actor='redops-bridge') as hub:
        hub.sync_evidence()
    return _j({'ready': True, 'pdf': str(pdf), 'sha256': report.digest(pdf),
               'bytes': pdf.stat().st_size,
               'next': 'Visually review every PDF page and screenshot, then run REPORT review and package.'})


@mcp.tool()
def risk_show() -> str:
    """Assets the operator flagged as risky to touch, and what that gates.
    'fragile' = a command that WRITES to it (POST/PUT/DELETE/--data) is held for
    operator approval; 'gated' = anything touching it is held. Check this before
    planning exploitation: a held command is not a failure, it's waiting on the
    operator. Reaching for a different tool will NOT bypass it — the gate is on
    the asset, not the tool."""
    return _j(req("GET", f"/api/services/risk?engagement_id={_engagement()}"))


@mcp.tool()
def risk_set(ip: str, port: int, risk: str = "fragile") -> str:
    """Flag a service as risky to touch: risk='fragile' (writes need approval),
    'gated' (everything needs approval), or '' to clear. Use this when you learn
    that exploiting something would crash or destroy it — record the judgement so
    neither you nor a future session fires it by accident."""
    return _j(req("PUT", "/api/services/risk",
                  {"ip": ip, "port": port, "risk": risk,
                   "engagement_id": _engagement()}))


@mcp.tool()
def queue_show() -> str:
    """Show the live tool queue for the active engagement (queued/ready/running),
    highest priority first. Approval is an optional operator setting."""
    return _j(req("GET", f"/api/tools/queue?engagement_id={_engagement()}"))


@mcp.tool()
def scope_show() -> str:
    """Show the active engagement's scope — allowlist (in) and blocklist (out),
    plus whether the scope guard is on. Guard-off is the default for authorized
    engagements: lists remain work context without automatic scope denial."""
    out = req("GET", f"/api/scope/{_engagement()}")
    g = req("GET", "/api/settings").get("scope_guard", {})
    out["guard"] = "on" if g.get("value") else "off"
    return _j(out)


@mcp.tool()
def scope_set(allow: list[str] | None = None, block: list[str] | None = None,
              replace: bool = False, guard: str | None = None) -> str:
    """Record the active engagement's assigned networks (CIDRs/IPs). With the
    optional guard on, `allow` and `block` become an enforcement policy. With
    the guard off (default), they are context for work and reporting. By default
    this ADDS to the current lists; pass replace=True
    to overwrite. An omitted list is left unchanged. `guard` = 'on'/'off' toggles
    scope enforcement itself (default off). Verify with scope_show."""
    if allow is None and block is None and guard is None:
        raise ApiError("pass allow and/or block (lists of CIDRs/IPs), or guard='on'/'off'")
    eng = _engagement()
    out = {}
    if guard is not None:
        g = str(guard).strip().lower()
        if g not in ("on", "off"):
            raise ApiError("guard must be 'on' or 'off'")
        out["settings"] = req("PUT", "/api/settings", {"scope_guard": g == "on"}).get("scope_guard")
    if allow is not None or block is not None:
        cur = {"in": [], "out": []} if replace else req("GET", f"/api/scope/{eng}")
        body = {}
        if allow is not None:
            body["in"] = allow if replace else sorted(set(cur.get("in", [])) | set(allow))
        if block is not None:
            body["out"] = block if replace else sorted(set(cur.get("out", [])) | set(block))
        out["scope"] = req("PUT", f"/api/scope/{eng}", body)
    return _j(out)


@mcp.tool()
def cve_lookup(product: str, version: str = "", vendor: str = "", target_ip: str | None = None) -> str:
    """Deterministic CVE lookup via NVD with VERSION-RANGE matching — use this
    INSTEAD of web-searching for CVEs. It returns only CVEs whose applicability
    actually includes the given version, so it won't flag a bug that was fixed
    before your version (web-search + judgement gets this wrong). Records a finding
    per CVE (severity from CVSS) and a `vuln` entity on the host. Fingerprint the
    service first (tool_run nmap preset=service, i.e. -sV) to get product+version.
    product e.g. 'qdrant', version e.g. '1.12.4', vendor optional (defaults to product)."""
    if not product.strip():
        raise ApiError("cve_lookup needs a product")
    body = {"tool": "nvd-lookup", "actor": "agent",
            "opts": {"product": product, "version": version, "vendor": vendor}}
    if target_ip:
        t = find_target(target_ip)
        body["target_id"] = t["id"]; body["ip"] = target_ip
    return _j(req("POST", "/api/tools/run", body))


@mcp.tool()
def engagement_add(name: str, scope: str, notes: str = "") -> str:
    """Create an isolated engagement with an explicit scope boundary.

    Use for a new lab or assessment. The new engagement becomes active; check
    session_brief before continuing target work.
    """
    if not name.strip() or not scope.strip():
        raise ApiError("name and scope are required")
    try:
        nets = [str(ipaddress.ip_network(part, strict=False))
                for part in re.split(r"[\s,]+", scope.strip()) if part]
    except ValueError as exc:
        raise ApiError(f"invalid CIDR in scope: {exc}") from exc
    return _j(req("POST", "/api/engagements",
                  {"name": name.strip(), "scope": ", ".join(nets), "notes": notes}))


@mcp.tool()
def session_brief() -> str:
    """One-call start and phase-boundary brief for the pinned engagement.

    Read scope, guard, sitrep freshness, operator tasks, opportunities and
    top worklist items before target activity.
    """
    state = json.loads(status())
    opps = json.loads(opp_list())
    tasks = json.loads(tasks_pending())
    return _j({"engagement_id": _engagement(),
               "scope": json.loads(scope_show()),
               "focus": req("GET", f"/api/current_target?engagement_id={_engagement()}"),
               "sitrep": json.loads(sitrep_show()),
               "pending_tasks": tasks[:10], "pending_task_count": len(tasks),
               "open_opportunities": opps[:10], "open_opportunity_count": len(opps),
               "worklist": json.loads(worklist())[:10],
               "targets": state["targets"], "facts": state["facts"],
               "mcp_source_changed": os.path.getmtime(__file__) > MCP_SOURCE_MTIME})


@mcp.tool()
def status() -> str:
    """Health check: is the RedOps API reachable, and how much is recorded FOR
    THE ACTIVE ENGAGEMENT? Call first if unsure the dashboard is up. All counts
    are scoped to the active engagement — a fresh engagement reads 0 targets /
    0 facts even if other engagements hold data, so do NOT infer prior state
    from these numbers or re-register hosts from memory."""
    engs = req("GET", "/api/engagements")
    # read from the SAME engagement the agent writes to — reading a worklist from
    # the operator's selection while filing intel into the pin is split-brain
    try:
        eng = _engagement()
    except ApiError:
        eng = None
    targets = req("GET", f"/api/targets?engagement_id={eng}") if eng else []
    facts = req("GET", f"/api/facts?engagement_id={eng}") if eng else []
    opps = req("GET", f"/api/opportunities?engagement_id={eng}&status=open") if eng else []
    return _j({"api": os.environ.get("REDOPS_URL", "http://127.0.0.1:9100"),
               "reachable": True, "engagements": len(engs), "active_engagement": eng,
               "targets": len(targets), "facts": len(facts), "open_opportunities": len(opps),
               "start_hint": START_HINT,
               "mcp_source_changed": os.path.getmtime(__file__) > MCP_SOURCE_MTIME})


if __name__ == "__main__":
    mcp.run()  # stdio transport
