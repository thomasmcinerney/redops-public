# casehub build brief

Context for any coding agent working in `outputs/report-kit/`. This is **kit development**, not a lab task; the REPORT lab protocol in the workspace `AGENTS.md` (route commands through `report.py run`) does not apply to building and testing this software. Do not touch anything under `../../work/` except read-only copies you make under `/tmp`.

## Purpose

`report.py` is the evidence authority for one REPORT case: `case.json`, `transcripts/`, `evidence/`, `code/`, `build/`. It is the only writer of evidence and it must keep working exactly as its `selftest.py` checks.

`casehub/` is a correlation layer so several agents (Codex, Claude, Kimi) and one operator can work the same case: shared inventory, claims with evidence, tasks, handoffs, and a dashboard. It never modifies `case.json`. It stores its own append-only ledger in `<case>/casehub.db`.

Read `casehub/ledger.py` first. `CaseHub` is the only API to the database; every module calls it and nothing else opens the database directly. Read `../REPORT-Multi-Agent-Case-System-Plan.md` sections 5, 7.2, 7.4, 8.2 for intended behavior when this brief is silent.

## Hard rules

1. Python 3.13 standard library only (plus Pillow/pypdf/weasyprint already used by report.py). No new dependencies.
2. Every write names an actor (`CaseHub(root, actor=...)`, default from `$REPORT_ACTOR`).
3. Observed or verified facts must cite evidence event IDs that exist in `case.json`. `CaseHub` enforces this; never bypass it.
4. No raw secret values in entities, notifications, or dashboard lists. `secret_ref` entities hold a label and SHA-256 fingerprint only.
5. Target actions never originate in casehub. Extraction runs only over saved evidence. The MCP capture tools shell out to `report.py` so capture stays on the evidence path.
6. Bind network listeners to `127.0.0.1` only.
7. Every module ships with tests in `casehub/tests/` runnable by `python3 -m unittest discover -s casehub/tests -t .` from `report-kit/`. Tests build a synthetic case with `report.py` (see `selftest.py` for the sequence) in a temporary directory; they never read `../../work/`.
8. Keep `python3 selftest.py` passing. Do not change `report.py` unless the brief for your module says so.
9. Do not leave work half-done: a module is finished when its tests pass and its `main(hub, args)` entry works from the CLI.

## Module contracts

### `casehub/__main__.py` (CLI)

`python3 -m casehub <case> [--actor NAME] <command>`. Opens `CaseHub(root, actor)` and dispatches. Commands: `sync`, `status [--json]`, `rebuild`, `search QUERY...`, `epoch REASON... [--label]`, `extract [--event ID]... [--target T] [--dry-run]`, `serve [--host 127.0.0.1] [--port 8765]`, `mcp [--capabilities read,propose,coordinate,capture]`. `extract`, `serve`, `mcp` import `casehub.extract`, `casehub.dashboard`, `casehub.mcp_server` lazily and call their `main(hub, args)`. `status` prints a readable summary of `hub.context()`: per target stages done/missing, proof/ready/accepted flags, running or unresolved commands, entity and open-claim counts; then actors (heartbeats), live tasks, leases, open decisions, pending handoffs, conflicting claims, inventory counts. Exit non-zero with a one-line message on `CaseHubError`.

### `casehub/tests/test_ledger.py`

Covers: sync idempotency; entity upsert merges attrs and never lowers evidence level silently; observed entity without events is rejected; unknown event ID rejected; edge requires existing entities; claim proposed as verified is rejected; self-verification rejected, cross-review accepted; conflicting claims detected via contrary evidence; task lifecycle incl. done requires result; lease held by another actor rejected until expiry; handoff packet validation; epoch start marks prior entities stale; `rebuild()` reproduces identical projections (compare table dumps before and after); FTS search finds transcript content.

### `casehub/extract.py`

`main(hub, args)` plus `extract_event(hub, event: dict, body: str) -> list[dict]` returning proposed entities (dicts matching `record_entity` kwargs, with `source_span` `{"start": int, "end": int, "line": int}` and `extractor` `"name@version"`, `confidence` 0..1, `level` `"proposed"`). Adapters, each a function registered in a list: IPv4/IPv6 addresses and hostnames → `host`; `PORT STATE SERVICE VERSION` style scanner lines → `service` keyed `host|proto|port` with attrs state/product/version, and an edge `service -runs_on-> host`; URLs → `application` keyed by origin plus `file` for path; `user@host`, `DOMAIN\user`, `user:` prompts → `identity` keyed `realm\name` (realm `local` when unknown); file paths (`/etc/...`, `C:\...`) → `file`; HTTP titles/server headers → application attrs. Dedupe within one run. `--dry-run` prints proposals without writing. Record with `idempotency_key=f"extract:{extractor}:{event_id}:{type}:{key}"` so reruns are no-ops. Target for each entity is the event's target. Tests include a synthetic scanner transcript, a browser log with a URL and title, and a prompt line with a username; assert entities, edges, spans, and idempotency.

### `casehub/mcp_server.py`

A stdio MCP server with **no external dependency**: JSON-RPC 2.0 over stdin/stdout, one message per line (newline-delimited JSON, as Codex, Claude Code and Kimi speak to stdio servers). Implement `initialize` (protocolVersion "2025-03-26", serverInfo, capabilities tools+resources), `notifications/initialized`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`. Tool results are `{"content":[{"type":"text","text": json}], "isError": bool}`. Log to stderr only.

Tools, gated by `--capabilities`:
- read: `case_context`, `case_status_text`, `inventory_search {query}`, `entity_get {entity_id}`, `entities_list {type?,target?,level?}`, `graph_neighbors {entity_id,hops?}`, `evidence_get {event_id, with_body?}`, `evidence_timeline {target?,stage?,kind?,actor?,limit?}`, `claims_list {target?,state?}`, `tasks_list {state?,owner?}`, `handoffs_list {to_actor?}`, `decisions_list`.
- propose: `entity_record`, `edge_add`, `claim_propose`, `claim_review`.
- coordinate: `task_create`, `task_claim`, `task_update` (checkpoint/state/result), `heartbeat`, `lease_acquire`, `lease_release`, `handoff_write`, `handoff_ack`, `decision_ask`, `decision_answer`, `epoch_start`.
- capture (off by default): `report_run {target,stage,argv[],cwd?}`, `report_log {target,stage,kind,text,result?}`, `report_screenshot {target,stage,file,role,caption}`, `report_code {target,stage,file,origin,changes}`. These run `report.py` as a subprocess with `REPORT_ACTOR` set to the server's actor and return its stdout/stderr/exit code and the new event ID parsed from output. They never run anything else.
Resources: `case://summary` (status text), `case://scope`, `case://gates`. Every tool's description states what the tool does and that evidence IDs are required for observed/verified facts. The server actor comes from `--actor`/`$REPORT_ACTOR`. Call `hub.sync_evidence()` before read tools. Tests drive the server as a subprocess over pipes: initialize, list tools, call a read tool, a propose tool with a bad event ID (expect isError), and a coordinate tool; verify the record landed in the ledger.

### `casehub/dashboard.py`

`main(hub, args)` runs `http.server.ThreadingHTTPServer` on `args.host:args.port` (loopback). JSON API: `GET /api/context`, `/api/entities?type=&target=`, `/api/entity/<id>`, `/api/timeline?target=&stage=&kind=&limit=`, `/api/evidence/<id>` (with body), `/api/search?q=`, `/api/claims`, `/api/tasks`, `/api/report` (runs `report.validate` on the case and returns errors plus build/review/package state from `case.json` and `build/`). Each API call does `hub.sync_evidence()` first; open a fresh `CaseHub` per request (SQLite connections are per thread). `GET /` serves one self-contained HTML page (inline CSS/JS, no CDN) with four tabs: **Mission** (scope, epoch, per-target cards with stage/gate flags, actors with last heartbeat age, live tasks, leases, open decisions, pending handoffs, conflicting claims), **Inventory** (filterable table by type/target/level/applicability; click → entity detail with observations, neighbors, claims), **Evidence** (timeline with filters; click → full text and screenshot thumbnail via `/evidence-file/<id>`), **Report** (validation errors, gate states, build/review/package/upload states as separate labels). Poll `/api/context` every 5 s. Status words always accompany colors. Mask anything whose entity type is `secret_ref` to label + fingerprint prefix. Never render raw `attrs` of `secret_ref`. Tests: start the server on an ephemeral port in a thread against a synthetic case, fetch each endpoint, assert JSON shapes and that `/` contains the four tab names.

### `report.py` changes (only for the module assigned this)

Add actor attribution: every `add_event` stamps `"actor"` from `--actor` (global option on the base parser) else `$REPORT_ACTOR` else `"operator"`. Show the actor in each ledger line of the PDF (`render_html`) and in `status`. Add `report.py status <case>` that prints the per-target summary without casehub (stages done/missing, proof/ready/accepted, running/interrupted commands, last three events). Extend `selftest.py` to assert the actor appears on events and in extracted PDF text. Keep every existing command and flag unchanged.

## Definition of done for the whole layer

From `report-kit/`: `python3 selftest.py` passes; `python3 -m unittest discover -s casehub/tests -t .` passes; `python3 -m casehub <synthetic case> status` prints a summary; `extract` populates hosts/services from a scanner transcript; the MCP server answers `tools/list` over stdio; the dashboard serves `/` and `/api/context` on 127.0.0.1.
