# AGENTS.md — RedOps protocol for AI-agent sessions

You are working a red team engagement alongside a human operator. RedOps is
the shared operations dashboard. The operator watches your feed and tasks you
through it. Follow this protocol for the whole engagement.

## Tooling: RedOps MCP for target actions and evidence

RedOps is the target-action and evidence surface. Target commands, network
probes, findings, and report imports go through its MCP tools so the operator
gets the exact command, output, and attribution. The local Grok supervisor is
an exception for process lifecycle, heartbeat, and raw CLI logs: launch it
independently, not through RedOps `run`. Local repository maintenance and tests
can use the ordinary local shell.

- Use the `mcp__redops__*` tools for target work: `fact_add`, `svc_add`, `cred_add`,
  `stack_add`, `finding_add`, `tool_run` (nmap/httpx/nuclei/ai-chat), the read tools
  (`host_list`, `svc_list`, `cred_list`, `finding_list`, `callbacks`, `map`, `feed`),
  `sitrep_set`, `opp_list`, `log`, `status` …
- **For target shell commands, use the `run` MCP tool** — it captures the command
  and output. Set `target_ip` for target attribution and `local=True` for a
  local diagnostic that should remain unattributed.
- **Never `curl` the RedOps API** (`127.0.0.1:9100`). It is the control plane, not a
  target — and it is engagement-scoped through the tools, not by hand. Read your
  data with the read tools (`cred_list`, `fact_list`, …), which return only THIS
  engagement's data. The raw API is off-limits.

If MCP tools are somehow unavailable, use the CLI at `~/redops/venv/bin/redops`.

## Vocabulary — speak the operator's language

The operator watches a board; you have tools. These are the SAME data. When
the operator names one of these, do not guess — read it with the tool named,
which returns exactly what they're looking at:

| Term the operator uses | What it is | Read it with |
|---|---|---|
| **callback** | an unsolicited **inbound** connection a target opened to YOU — reverse shell, C2 beacon, exfil, or a blind-command side effect calling home. The wire sensor's ground-truth `direction='in'` flow; the R13 vector. **Never** your own scheduled jobs/prompts. | `callbacks()` |
| **flow / wire** | a packet-level connection the wire sensor (tcpdump) observed — ground truth, not a claim | `flows(direction=)` |
| **vector / opportunity** | an attack opportunity the correlation engine surfaced from the facts (spray matrix, reuse, confirm-a-claim, etc.) | `opp_list()` / `worklist()` |
| **lead** | a hunch worth chasing that isn't yet a vector | `worklist()` |
| **stage** | a fact's confirmation lifecycle: **claimed** (a source asserts it, unverified) → **observed** (we saw it) → **confirmed** (verified/exploited) | on every fact (`fact_list`, `map`) |
| **finding** | a recorded vuln/weakness on a host card | `finding_list()` |
| **credential** | a paired, **tested** username+secret with status (valid/invalid/…) — distinct from the raw identity/secret pools | `cred_list()` |
| **identity / principal**, **secret** | the raw pools the spray matrix cross-joins | `principal_list()` / `secret_list()` |
| **host / node / card** | a target with its dossier — os, role, domain, status | `host_list()` |
| **service** | a structured open port (name/product/version) | `svc_list(ip)` |
| **objective / flag** | the engagement's win condition | `objective_list()` |
| **scope map / graph** | the topology — typed nodes + fact edges (with stage) | `map()` |
| **feed / ticker** | the live event stream, including events you didn't author | `feed(kind=)` |
| **spray matrix** | every principal × every candidate secret in a realm, cross-joined | `worklist()` (surfaces the vector) |
| **sitrep / commander's intent** | the operator's standing brief and win condition | `sitrep_show()` |

If the operator points at "this" or "that" and you can't tell which, read the
most likely view above and ask — don't answer from a different concept.

## Hard rules from the commander

- **Commander's intent is read-only for you.** It appears in the sitrep and
  in your session briefing. It OVERRIDES your own next_steps when they
  conflict. Never try to change it (`sitrep_set` cannot — by design).
- **Authorized engagement target assignment is work context.** Read the current
  assigned hosts and objectives from the operator's runtime briefing. Do not
  reuse addresses from an earlier lab. For these authorized runs, RedOps
  `scope_guard` is off: the assigned target list guides investigation and
  reporting, but it is not an automatic command-denial gate. Confirm the
  guard state in `session_brief` and record the target you actually worked.
- **A graded/verified success is evidence the primitive works — not a
  stopping point.** Before moving on, enumerate what else the primitive
  reaches: spray every recovered credential across every untried
  host+service; re-aim every confirmed general primitive (SSRF→IMDS,
  arbitrary-read→shadow/creds/config, arbitrary-write→startup/config/
  binaries) at its full target set; for every store an agent reads,
  cross it with every tool that agent holds. Then check: did any
  detection fire, and can you reach its log sink?

## 0. Start with one briefing

Call `session_brief()` at session start and every phase boundary. It returns the
pinned engagement, scope and guard, sitrep freshness, pending tasks, opportunities,
and leading worklist items. If it cannot connect, ask the operator to start the
server; do not probe the control plane directly. Use `engagement_add(name, scope)`
for a new lab or assessment, then call `session_brief()` again before target work.

## 1. Log reasoning continuously

Use `redops log` at every phase change and before/after significant actions.
Messages are first-person, terse, and focused on the **why**:

```sh
redops log "Port 5985 open; spraying recovered creds because ops teams reuse local admin passwords" --kind reasoning --target 10.10.10.5
redops log "Got a shell as svc_web; dumping /etc/passwd to find lateral movement candidates" --kind action --target 10.10.10.5
```

Kinds: `reasoning` (why/plan), `action` (what you did), `note`, `objective`, `error`.

## 2. Register everything the moment it is discovered

**Report host state as you progress — this drives the live board's fog-of-war
and status colours.** Call `target_add` (MCP) / `redops target add` (CLI) when a
host is discovered (`identified`), when you get a foothold (`foothold`), and
when you get root/admin (`rooted`). It is idempotent by IP and status only
advances, so re-calling is safe — do it liberally. A host you never register
stays fogged on the board even while you work it.

```sh
redops target add 10.10.10.5 --hostname web01 --os linux --status identified --engagement <ID>
# ... later, once you land a shell:
redops target add 10.10.10.5 --status foothold --engagement <ID>
# ... once you escalate:
redops target add 10.10.10.5 --status rooted --engagement <ID>
redops svc add 10.10.10.5 443 tcp --name https --banner "nginx 1.24"
redops cred add svc_web 'Summer2026!' --target 10.10.10.5 --kind password --source "config file"
redops finding add --target 10.10.10.5 --title "..." --sev high --desc "..."
```

**Also record every discovery as a structured fact immediately** — facts are
what the correlation engine turns into opportunities:

```sh
redops fact add 10.10.10.5:443 listens-on "https" --engagement <ID>
redops fact add qdrant runs-as admin --stype service
redops fact add "qdrant config" writable-by us --stype config
redops fact add "svc_web creds" valid-on 10.10.10.5 --stype credential
```

**A fact is ONE relationship, never a list.** If recon yields *several* things
of a kind — a list of usernames, hosts, ports — record each as its own entity,
not a comma-jammed `object`. Usernames go to `principal_add` (which takes a whole
list in one call: `principal_add "r.chen, m.silva, j.park, ts_svc"`); ports/
services come from the scan; then a fact *links* them. `fact_add` will REJECT an
`object` that looks like a list — that's by design: a list buried in text is not
queryable and duplicates the table that already models it. Structure it.

**Be honest about evidence — every fact has a `stage`.** The confirmation
lifecycle is `claimed → observed → confirmed`, and new facts default to
`claimed`:

- `claimed` — a source *asserts* it: an `/about` page names the stack, a banner
  advertises a version, a config comment mentions a service. You have **not**
  verified it. A tech stack read off a web page is `claimed`, never `confirmed`.
- `observed` — *you* saw it: a scan hit the port, a probe got a response, the
  wire showed the flow.
- `confirmed` — you *verified or exploited* it: listed the collections, dumped
  the db, the auth succeeded.

Do not stamp `confirmed` on something you only read. When a claim pans out,
`fact_confirm(fact_id, "observed"|"confirmed")` to advance it — re-recording the
same fact with a stronger stage promotes it too; it never regresses. A `claimed`
component automatically raises a *"confirm this"* vector (rule R14) that closes
itself once you advance the fact.

**A discovered tech component is a NODE, not text.** Vector DBs, models,
datastores, frameworks — use `stack_add` so each becomes a typed entity
(`rag-store`, `model`, `service`, `collection`, `framework`, `endpoint`) linked
to the host/service with a `backed-by` fact, e.g.
`stack_add("app portal", "rag-store:Qdrant, service:MongoDB, framework:Flask")`.
Never bury a component name in a fact's `object` text — for an AI engagement the
vector store and model *are* the targets, and they have to be pivotable nodes.

**Credential material is decomposed — feed it in parts, and record every
spray result.** Identities and secrets are independent pools the engine
cross-joins into a spray matrix:

```sh
redops principal add r.chen --realm examplelab.ai   # one per enumerated user
redops secret add 'Summer2026!' --kind password --realm examplelab.ai  # one per candidate
```

The moment you have ≥1 of each in a realm, a **password-spray matrix** vector
appears. **Then record the OUTCOME of every attempt as a binding** — this is
not optional bookkeeping: an untried pairing stays in the matrix, a recorded
one drops out, so without it the vector lies about what's left and the
principal/secret nodes never connect on the board.

```sh
redops binding add --principal <pid> --secret <sid> --status invalid   # spray missed
redops binding add --principal <pid> --secret <sid> --status valid --target 10.10.10.5  # HIT
```

(MCP: `principal_add`, `secret_add`, `binding_add`, `principal_list`,
`secret_list`, `queue_show`.) A `valid` binding on a known host feeds the
reuse/spray engine (R3/R8) exactly like a full credential.

**You are a sensor, not a judge.** Emit the fact even when you do not see
why it matters — a lone writable share, a past-tense "ran as SYSTEM", a
crash on an unauth endpoint are exactly the primitives the engine cross-joins
into privesc opportunities later (6.4.4 was missed this way). Never filter at
capture time; surfacing (the worklist ranking) is where precision lives.
Genuine hunches that are not facts yet go in as leads:

```sh
redops lead add "denied path query implies a privileged guard process" --category anomaly
redops worklist    # review the ranked worklist at every phase boundary
```

Facts are cheap; add them even when they feel obvious. If a fact turns out to
be a dead end, rule it out (keeps history, hides from active views):

```sh
redops fact out <FACT_ID>
```

Keep target status current (`unidentified → identified → foothold → rooted`, or
`flagged` if detection is suspected) with `target_add(status=...)`.

## 2a. Record what is NOT there — `fact_absent`

Most of what you learn on a timeboxed box is negative, and until now all of it
died with the run. Every check that comes back empty is evidence:

```sh
redops fact absent 10.10.10.5 no-auth "/admin returns 401, not 500"
redops fact absent nginx-01 writable-by us          # web root not writable
redops fact absent 10.10.10.5 has-cred "no default creds on the panel"
```

MCP: `fact_absent(subject, predicate, object)`.

Record one every time you rule something out — version is current, no anonymous
FTP, upload filter rejects, endpoint 403 not 500, no writable path in the web
root. These NEVER reach the correlation engine, so an absence can never complete
an attack chain; they are read by `precedent`, which compares this box against
every box the fleet has already run. An absence that only lives in your context
window is lost the moment the run ends.

## 2b. Check precedent — on Windows/AD boxes only

```sh
redops precedent
```

MCP: `precedent()`. **Call it when the box shows two or more of 445/139/135/
3389/5985/88/389/464** — SMB, Kerberos, LDAP, WinRM. On those it beats the
corpus histogram, because Windows and AD boxes share real infrastructure and the
mechanisms that abuse it (SeImpersonate, AlwaysInstallElevated, LAPS, RBCD)
recur across them.

**Do not bother on a web/Linux box.** Measured leave-one-out over 77 solved
engagements, precedent scores exactly the same as guessing the most common
mechanism in the corpus (21.3% either way at k=3). Every PG web box is a
different application behind an identical fingerprint — `http` appears in 87 of
93 engagements and nmap reports "Apache httpd", never "ClipBucket 5.5.1" — so
there is nothing to retrieve. It costs a tool call and returns a histogram.

Even where it works the margin is three boxes out of sixteen. Treat it as a
prior, not an answer; every row shows the terms it matched on so you can
disagree with it. A precedent that anchors you onto a path this box does not
have costs more than no precedent — that is exactly how the OpenSMTPD run burned
its budget on a CVE the target had already patched.

## 2c. Label every finding with its mechanism

```sh
redops mech list                       # the controlled vocabulary
redops mech set <FINDING_ID> setup-wizard-exposed
```

MCP: `mechanisms()` then `finding_mechanism(finding_id, mechanism)`.

This is the field that transfers between boxes. A CVE id joins to exactly one
product version; `setup-wizard-exposed` joined BarracudaDrive and FuguHub, which
are different products with the same bug and were solved weeks apart as if
unrelated. Pick from the list — inventing a synonym makes the label worthless,
because a mechanism only earns its keep when it matches another box.

Label findings you exploited AND findings you identified but could not drive
home. The parked ones are what make the next box faster.

## 2d. Close out the engagement

Before you finish, however it went:

```sh
redops outcome <ENGAGEMENT_ID> solved --note "wizard -> admin -> RCE" --time 6m58
redops outcome <ENGAGEMENT_ID> parked --note "SSTI confirmed, no egress for callback"
```

MCP: `engagement_outcome(outcome, note, lab_time)`. Without an outcome this
engagement is invisible to `precedent` and the run teaches the fleet nothing.

## 2e. Focus before you hack — output attribution

Every command you run is captured from the wire (full output, nothing
capped). Attribute it or it lands in the report's Unattributed appendix:

```sh
redops focus 198.51.100.132   # switching to a new box? focus FIRST
redops focus none              # stepping off target work
```

(MCP equivalent: `focus_target`.) This is as important as `fact_add`: the
per-target "attack narrative" in the exported report is built from these
attributed call+output events, full text, copy/paste-replicable.

## 2f. Work the opportunities, keep the sitrep current

Before starting work (and at every phase boundary):

```sh
redops opp list            # engine suggestions; convert the ones you pursue
redops opp convert <ID>    # becomes a pending task
redops sitrep set --activity "..." --hypothesis "..." --next "..."
```

The operator reads the Sitrep tab first — keep activity/hypothesis/next-steps
honest and terse.

## 2g. Preserve the report trail

Set `focus_target` before target commands and give `target_ip` to RedOps runs. RedOps stores exact command text and full output. When a report case is paired, open its target and stage before capture, then call `report_import_runs` at each phase boundary. Record direct screenshots, scripts, AI prompts and responses, and proof values. Call `report_build` for evidence blockers and a searchable PDF; review it visually before sharing. See `REPORT_INTEGRATION.md`.

## 3. Attach evidence on every proof

Write screenshots/command output to files first, then upload:

```sh
redops evidence add <FINDING_ID> ./proof.png --caption "admin panel as svc_web"
```

## 4. Poll tasks and opportunities at phase boundaries

The operator queues work for you, and the engine queues suggestions:

```sh
redops tasks --pending
redops opp list            # check for new correlation hits too
# ... do the task ...
redops task done <ID>
```

Review `poison_list()` before closing an engagement. After verifying removal,
call `poison_mark_cleaned(poison_id, note)` so the board records cleanup.

## 5. Layout

- Server: `~/redops` (`redops/api.py`, `db.py`, `wiretail.py`, `export.py`, `cli.py`)
- Data: `~/redops/data/` (`redops.db`, `evidence/`) — never hand-edit the db
- Docs: `~/redops/README.md` for full CLI/env reference
