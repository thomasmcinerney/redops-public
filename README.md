# RedOps

A self-hosted cockpit for running a red-team engagement **with** an AI agent
instead of just watching one. You connect the dots; the agent does the legwork.
Both of you read and write the same store, so nothing the agent finds is hidden
from you and nothing you run is hidden from it.

RedOps captures everything the agent does (over ACP, or by tailing its session
log), extracts structured facts from that activity, runs a correlation engine
that surfaces attack vectors, and renders it all as a game-ified **live board** —
fog-of-war scope map, drill-in target views, a ranked worklist of vectors, and a
prompt lane to drive the agent. Deterministic tools (nmap) run directly, no LLM
in the loop. Engagements keep it all scoped and exportable to a self-contained
report.

> **Lab tool. Localhost-only, no auth. Do not expose it.** It runs scanners and
> auto-approves agent actions by default — only point it at systems you are
> authorized to test.

## Quickstart

The project is managed with [`uv`](https://docs.astral.sh/uv/).

```sh
uv run python -m redops.api          # serves http://127.0.0.1:9100
# then open http://127.0.0.1:9100
```

Background:

```sh
uv run python -m redops.api > data/server.log 2>&1 &
```

The CLI is the `redops` console script:

```sh
uv run redops --help
```

Data lives in `data/` — SQLite at `data/redops.db`, uploaded evidence in
`data/evidence/`, ground-truth transcripts in `data/transcript/`. Point
`REDOPS_DATA` elsewhere to keep engagements separate.

## The two surfaces

**Dashboard** (`/`) — the working desk. Tabs for Sitrep, Map, Intel (facts),
Leads (worklist), Feed, Targets, Objectives & Tasks, Evidence, Report, and
**⚙ Manage**. This is where you read detail and record structure.

**Live Board** (`/board.html`) — the situational view. A fog-of-war **scope map**
of hosts that lifts as recon identifies them; click a host to **drill into** its
entity graph; click any node for an **inspector** with details *and* actions
("port-scan this", ask the agent to enumerate); a ranked **VECTORS** rail; a
live **feed** of agent + tool activity; and a **prompt lane** to drive the agent
(ACP capture required). The prompt lane shows which engagement it targets and has
a **NEW** button that starts a fresh agent conversation (`session/new`) — so a
prompt lands on a clean agent instead of resuming the previous run's history. The
header names the active engagement.

## Core concepts

**Engagements** scope everything — targets, facts, events, findings, the feed,
the board. The active engagement is what the board and new data attach to.
Create, rename, archive, reset, or delete them in **Manage** (below).

**The event substrate.** Every action, agent thought, tool result, and fact
becomes a row in `events`, streamed to the UI over SSE (`/api/stream`) and scoped
to its engagement. This shared log is what makes the human/agent co-op work.

**Facts & correlation.** Activity is distilled into structured facts
(`subject —predicate→ object`, stage `claimed → observed → confirmed`, and source `wire-auto|agent|analyst`). Checked absences use `polarity=absent` and never feed affirmative correlation rules.
The correlation engine (`redops/correlate.py`, rules **R1–R11**) reads facts and
*suggests* opportunities — it never declares. Highlights: R2 privesc via
config/binary hijack, R3 credential reuse across hosts, R7 foothold pivot,
R8 spray matrix, R9 primitive generalization (SSRF→IMDS etc.), R10 sink×tool
(indirect prompt injection), R11 cover-tracks + a `detected` stealth flag.

**Leads & worklist.** One evidence store (facts), one ranked worklist (a *view*,
not a store): open opportunities + open leads + un-joined interesting facts. A
lone `writable-by` fact shows up immediately and rises when a partner fact lands.
Leads are hunches; promoting one structures it into facts. Review the worklist at
phase boundaries.

**The tool runner.** Tools are tools — nmap doesn't need an LLM. RedOps runs
`quick-scan`/`port-scan`/`full-scan` directly, stores raw output in `tool_runs`,
and parses ports into services + facts. Deterministic **AI recon** rides the same
runner: `agent-card`/`agent-probe` fetch `/.well-known/agent.json` (+ `/health`,
`/openapi.json`) in-process and parse them into `agent`/`model` entities and
`runs-model`/`has-skill`/`exposes` facts (pass a port, or an `ip` as `host:port`).
Both you (board actions, `POST /api/tools/run`) and the agent (MCP `tool_run`)
trigger runs and read each other's results — the agent enumerates blind off your
scans, no answers handed over. Loopback (`127.0.0.1`) is excluded unless you opt in.

**AI-native storage.** Beyond hosts/services, the graph has first-class entity
types for `agent`, `model`, `rag-store`, `collection`, `token`, `prompt`.
Credentials are partial-friendly: store a bare token/key (secret, no username) or
a username-only lead (no secret yet), with a `status` lifecycle
(`untested|valid|invalid|partial`) — and a valid cred on a known host feeds the
reuse/spray engine automatically. The **Arsenal** tab adds three authored stores:
a **payload library** (technique × model × guardrail, worked/failed), a
**detection-rule catalog** (read the rule → evade by mechanism; a fired rule named
in an opportunity's rationale flips its `detected` flag), and **planted-poison**
provenance with a cleanup checklist. All three land in the exported report.

**Absence, mechanism, precedent (v20).** Three additions that make correlation
work *between* engagements rather than inside one. On a corpus of timeboxed
single-box runs there is nothing to join within an engagement — a real 92-run
corpus had a median of 5 facts per engagement and `correlate.py` raised zero
opportunities across all of them, because the predicates its rules join on
(`writable-by`, `no-auth`, `is-read-by`) were never recorded once. The workload
ends at the moment those rules would start being useful.

- **Absence** — a fact carries a `polarity` of `affirm` or `absent`. An absent
  fact records that something was *checked and is not there*: version current,
  no default creds, 403 not 500. That is most of what a timeboxed run learns and
  none of it used to be representable (the same corpus had one ruled-out fact in
  986). Absent facts are **invisible to `correlate.py`** by construction — an
  absent `writable-by` completing R1/R2 would manufacture an attack path out of
  its own negation.
- **Mechanism** — findings carry one term from a controlled vocabulary
  (`redops mech list`, 37 terms) describing *how* it was exploited. `affects`
  points at CVE ids, which join to exactly one product version; mechanism joins
  across the corpus. BarracudaDrive and FuguHub were the same bug —
  `setup-wizard-exposed` — solved weeks apart with nothing able to see it.
- **Precedent** — `redops precedent` ranks past engagements that look like this
  one, by shared mechanism, product, uncommon port and absence pattern, with IDF
  weighting so port 80 counts for nothing. Deterministic set overlap, no model:
  every row reports the terms it matched on, because an unexplained precedent
  anchors an agent the way a recalled writeup anchored one run onto a CVE the
  target had already patched. Engagements need `redops outcome` set to appear.

```sh
uv run python scripts/test_precedent.py   # smoke test (needs the API running)
```

**Capture.** Two mechanisms feed the substrate:

- **ACP** (default) — RedOps spawns the agent as an [Agent Client
  Protocol](https://agentclientprotocol.com) subprocess and owns the session.
  The `session/update` stream maps to events; you get the prompt lane and
  permission cards. Requires the agent logged in first (`kimi login`); the
  CAPTURE pill shows `login needed` otherwise.
- **Wire tailing** (fallback) — passively tails the agent's session log
  (`wire.jsonl`). Agent reasoning → `wire/reasoning`, tool calls → `wire/action`,
  tool results → `kind=output`. Position persists per file, so restarts resume
  without duplicating.

Set `REDOPS_CAPTURE=acp|wire|both` (or `REDOPS_ACP=0` to force wire). Capture
health is on `/api/health` and the CAPTURE pill; outputs are stored in full
(large ones overflow to `data/transcript/<uid>.txt`, served at
`/api/transcript/<file>`) — nothing is lossy-capped.

## Manage (app administration)

The **⚙ Manage** tab is the control panel.

**Engagements** — a table with per-engagement counts (hosts/facts/events/
findings) and row actions: set-active, inline rename/scope edit, **archive**
(hide without deleting), **reset** (wipe the data, keep the shell), and
**delete** (type-to-confirm; cascades every scoped table). Deleting or archiving
the active engagement auto-reassigns active to another, so the app never points
at nothing.

**Settings** — *live* toggles that take effect without a restart (a value set
here overrides its launch env var, and shows its source):

| Setting | Effect |
|---|---|
| Include loopback targets | allow `127.0.0.1` in scans/targets (default off) |
| Docker tool-network | run scanners inside a docker network so real container IPs are reachable on macOS |
| ACP auto-approve | auto-allow + log agent permission prompts |
| Inject [RedOps] briefing | feed the agent the engagement/worklist on every prompt (default **off** — see hooks below) |

**System status** — capture mechanism, schema version, build commit, DB size,
data dir, server address, and global counts (read-only).

API: `GET/PUT /api/settings`, `GET /api/status`, `DELETE /api/engagements/{id}`,
`POST /api/engagements/{id}/{archive,unarchive,reset}`.

## Driving the agent

**MCP server.** `redops/mcp_server.py` is a stdio MCP server (FastMCP) exposing
RedOps as native tools, registered in `~/.kimi-code/mcp.json` under
`mcpServers.redops` (a new agent session is required to load it; tools appear as
`mcp__redops__*`). Tools: `log`, `fact_add`, `fact_absent`, `fact_list`, `fact_out`, `mechanisms`,
`finding_mechanism`, `precedent`, `engagement_outcome`, `opp_list`,
`opp_convert`, `opp_dismiss`, `tasks_pending`, `task_done`, `sitrep_set`,
`sitrep_show`, `scope_show`, `scope_set`, `target_add`, `svc_add`, `cred_add`,
`principal_add`, `principal_list`, `secret_add`, `secret_list`, `binding_add`,
`finding_add`, `evidence_add`, `objective_add`, `objective_done`, `lead_add`,
`lead_promote`, `lead_dismiss`, `worklist`, `focus_target`, `tool_specs`,
`tool_run`, `tool_results`, `queue_show`, `cve_lookup`, `payload_add`,
`payload_list`, `rule_add`, `rule_list`, `poison_add`, `poison_list`, `status`.

```sh
uv run python scripts/test_mcp.py    # protocol smoke test (needs the API running)
```

**Hooks** (Kimi Code integration, in `hooks/`, registered in
`~/.kimi-code/config.toml`, effective in **new** sessions). They read the SQLite
DB directly, read-only, and are fail-open — guardrails, not cages:

- `user_prompt.py` (UserPromptSubmit) — appends a compact `[RedOps]` briefing
  (engagement, focus, commander's intent, pending tasks, open opportunities).
  **Opt-in — off by default** (enable via Manage → Settings or `REDOPS_BRIEF=1`):
  the cockpit ACP session is persistent, so injecting the queue on every prompt
  steers an agent that may be mid-mission. When on, the briefing is framed as
  background reference, and an empty engagement is flagged as a fresh slate.
- `session_start.py` (SessionStart) — fuller briefing plus scope-guard status;
  same opt-in flag. Scope enforcement is separately opt-in and off by default.
- `scope_guard.py` (PreToolUse, Bash) — when enabled, enforces scope per IP in each Bash
  command (IPv4 literals and resolved hostnames). `NEVER_BLOCK` ranges pass;
  blocklisted IPs are blocked (exit 2); with an allowlist set, anything outside
  it is blocked. With the guard off, assigned targets remain report context and
  no RedOps scope denial runs.

**Commander's intent & scope.** The sitrep has a user-owned `commander_intent`
the agent can't overwrite; it overrides the agent's next_steps on conflict.
Scope lists are per-engagement (`redops scope`), enforced by the guard and shown
on the Sitrep tab.

## CLI cheat sheet

```sh
uv run redops engage add "CORP-EXT-2026" --scope "10.10.10.0/24"
uv run redops engage list

uv run redops target add 10.10.10.5 --hostname web01 --os linux --role web --engagement 1
uv run redops svc add 10.10.10.5 443 tcp --name https --banner "nginx 1.24"
uv run redops cred add administrator 'P@ssw0rd!' --target 10.10.10.5 --kind password --source "smb spray"
uv run redops cred add '' 'gldt-Rk7Xp3Nm9Qw' --kind token --source "session MC-20260320-0006"  # bare token, no username
uv run redops cred add jira_svc_automation --kind principal   # username-only lead (secret not known yet)
uv run redops cred list; uv run redops cred set 3 --status valid
uv run redops finding add --target 10.10.10.5 --title "Default creds on Tomcat" --sev high --desc "..."

# AI arsenal: payloads, detection rules, planted poison, objectives with proof
uv run redops payload add char-spacing --model qwen2.5-7b --guardrail "output filter" --outcome worked
uv run redops rule add "AIM3: Prompt Injection Keywords" --source elk --match "exact substring" --evade char-spacing --fired
uv run redops poison add "examplecorp_wiki.kb_articles id=5" --store kb-db --verify "query the agent"
uv run redops objective add "Recover GitLab deploy token" --value gldt-... --target 10.10.10.5

# AI recon (deterministic, no LLM): read an A2A agent card into the graph
uv run redops target add 192.0.2.21 --engagement 1
# then from the board/agent: tool_run agent-probe on 192.0.2.21:8001

# structured facts: subject -predicate-> object (entities auto-upsert)
uv run redops fact add qdrant runs-as admin --stype service
uv run redops fact add "qdrant config" writable-by us --stype config
uv run redops fact list --status active
uv run redops fact out 12                 # dead end -> ruled-out

# absence: what you checked and did NOT find (never reaches the engine)
uv run redops fact absent 10.10.10.5 no-auth "/admin returns 401, not 500"
uv run redops fact list --polarity absent

# mechanism: the join key that transfers between boxes
uv run redops mech list                   # controlled vocabulary + corpus usage
uv run redops mech set 7 setup-wizard-exposed

# precedent: past engagements that look like this one
uv run redops precedent
uv run redops outcome 12 solved --note "wizard -> admin -> RCE" --time 6m58
uv run redops outcome 13 parked --note "SSTI confirmed, no egress for callback"

uv run redops opp list                    # correlation suggestions
uv run redops lead add "denied path implies a privileged guard" --category anomaly
uv run redops lead promote 4              # structure a hunch into facts
uv run redops worklist                    # the ranked view

uv run redops log "Trying password reuse against WinRM — same admin group on both hosts" \
  --kind reasoning --target 10.10.10.5
uv run redops focus 10.10.10.5            # attribute captured output to this box
uv run redops evidence add 1 ./shot.png --caption "tomcat admin panel"

uv run redops sitrep set --activity "root on db01" --hypothesis "creds reused from web01"
uv run redops export 1 --fmt md   > report.md
uv run redops export 1 --fmt html > report.html
```

Exit code is non-zero on API errors, so it is safe to script.

### Analyst (optional out-of-band LLM pass, off by default)

`redops/analyst.py` runs inside the API process **only** when
`REDOPS_ANALYST_URL` is set (OpenAI-compatible chat completions). It reads
events since its cursor and posts facts/leads with `source=analyst`. Use a
**local** model — restricted networks may block external services and engagement data should
not leave the box:

```sh
# LM Studio (Developer tab → start server)
REDOPS_ANALYST_URL=http://127.0.0.1:1234/v1 \
REDOPS_ANALYST_MODEL=qwen/qwen3.6-35b-a3b \
  uv run python -m redops.api

# Ollama
REDOPS_ANALYST_URL=http://127.0.0.1:11434/v1 \
REDOPS_ANALYST_MODEL=qwen3.6:35b-a3b \
  uv run python -m redops.api
```

**It does not read the whole feed.** `netsensor` writes every flow into the same
`events` table as `flow`/`flowclose`, telemetry growth is unbounded (hardening
spec R7) and claim-bearing events are not — so an unfiltered 200-row window
fills with per-flow rows and the model never sees the reasoning it exists to
read. `ANALYST_KINDS` is an allowlist (`reasoning`, `action`, `output`, `note`,
`fact`, `verify`, `trust`, `error`, `callback`); a new event kind is excluded
until it is deliberately added. `callback` is kept because a fresh inbound
connection is the highest-signal thing the sensor produces.

**Output is schema-constrained, not parsed hopefully.** The request carries a
JSON Schema, which a capable server compiles to a grammar and enforces at
sample time. It degrades: `json_schema` + `reasoning_effort=none` →
`json_schema` → `json_object`, since "OpenAI-compatible" is a range rather than
a specification. Note that Qwen3.6 is a reasoning model and LM Studio returns
the constrained answer in `reasoning_content` with `content` empty unless
thinking is disabled, so the client reads both.

**Precision is measured** — `uv run python scripts/eval_analyst.py` scores this
code path on eight labelled windows, and reports recall, how much of the output
uses predicates a rule can read, how many unsupported facts it invents, and
whether its own output run back through `correlate.py` actually raises the rule
the window is about. Measured across six local models, best result: 82% recall,
100% usable predicates, ~1 unsupported fact per window, and the full R2/R10
chain firing in at most 1 of 2 cases. Treat it as a recall aid over the
deterministic path, and review `source=analyst` facts before acting — an
unsupported fact here does not just add noise, it manufactures an opportunity.

`uv run python scripts/eval_refusal.py` answers the other question: whether a
model will do offensive work at all. Result worth knowing — of six models, the
only one that refused anything was the *uncensored* 3B fine-tune, which declined
to write a **detection rule**.

## Reports

`/api/export/{engagement_id}?fmt=md|html` builds a single self-contained report:
title block, summary counts, per-target sections (services, credentials,
findings with evidence images embedded as base64), a chronological attack
narrative from target-linked events, and an evidence appendix. PDF is a manual
step:

```sh
uv run redops export 1 --fmt html > report.html && weasyprint report.html report.pdf
# or: pandoc report.md -o report.pdf
```

## Configuration

Most of these are launch-time. The three marked **(live)** are also editable at
runtime in **Manage → Settings**, where the DB value overrides the env var.

| Var | Default | Meaning |
|---|---|---|
| `REDOPS_HOST` / `REDOPS_PORT` | `127.0.0.1` / `9100` | server bind address |
| `REDOPS_URL` | `http://127.0.0.1:9100` | CLI base URL |
| `REDOPS_DATA` | `./data` | data directory |
| `REDOPS_CAPTURE` | `acp` | capture mechanism: `acp`, `wire`, or `both` |
| `REDOPS_ACP` | — | set `0` to force wire capture |
| `REDOPS_ACP_CMD` | `~/.kimi-code/bin/kimi acp` | ACP agent command (any ACP agent) |
| `REDOPS_ACP_CWD` | server cwd | working directory for the ACP agent |
| `REDOPS_ACP_AUTOAPPROVE` **(live)** | `1` | auto-approve + log agent permission requests |
| `REDOPS_BRIEF` **(live)** | `0` | inject the `[RedOps]` briefing into the agent on every prompt (off by default) |
| `REDOPS_ALLOW_LOOPBACK` **(live)** | `0` | include `127.0.0.1` in scans/targets |
| `REDOPS_TOOL_NET` **(live)** | — | docker network to run scanners inside (macOS real container IPs) |
| `REDOPS_WIRE` | newest `~/.kimi-code/**/wire.jsonl` | wire file to tail |
| `REDOPS_NO_WIRETAIL` | — | set `1` to disable wire tailing |
| `REDOPS_ANALYST_URL` / `_KEY` / `_MODEL` / `_INTERVAL` | — | optional analyst pass (off unless URL set) |

## Layout

```
redops/
  api.py            FastAPI app: REST + SSE + static hosting
  db.py             SQLite schema, migrations, helpers
  acp.py            ACP session manager (spawns + drives the agent)
  wiretail.py       session-log tailer + fact extraction
  tools.py          deterministic tool runner (nmap)
  correlate.py      correlation engine (R1–R11)
  mcp_server.py     stdio MCP server for the agent
  cli.py            the `redops` CLI
  static/           dashboard (index.html/app.js) + live board (board.html)
hooks/              Kimi Code lifecycle hooks (briefing + scope guard)
scripts/            smoke tests + spikes
```

## Engagement reports

RedOps captures every command and its complete output in the engagement ledger. Use the Report tab or `redops export` for a readable Markdown or HTML overview. For a full evidence PDF with exact commands, complete output, scripts, screenshots, and proof values, use the bundled [report kit](report-kit/README.md) and [integration guide](REPORT_INTEGRATION.md). Review the output before sharing it.

## Browser chatbot engagements

RedOps supports exact HTTPS page scope alongside IP/CIDR scope. Create a new
engagement with the chatbot page URL in `scope`, then use MCP `web_scope_show`
and `web_scope_set` to inspect or set `pages` and observed messaging
`api_prefixes`. The `webchat_capture.py` adapter in the companion Grok runner
checks that scope before driving a browser or replaying a direct API action.
Its `/api/webchat/capture` endpoint stores the exact action, widget output,
network exchange, and artifact hashes under the engagement. Reusing a source
ID with changed content is rejected. The report kit's `webchat_import.py`
imports completed browser actions and direct screenshots into a case. See
[report-kit/README.md](report-kit/README.md) and the
[Grok runner guide](https://github.com/thomasmcinerney/grok-redops-runner).

The browser scope is enforced by the adapter and capture endpoint. Shell
command scope remains a separate IP/hostname guard; use the browser adapter
for chatbot actions.
