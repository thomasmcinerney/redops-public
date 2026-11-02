# casehub operator runbook

One case, one evidence authority (`report.py`), one correlation ledger (`casehub.db`), several agents. This runbook is the order of operations for a lab or assessment day. Paths below assume `KIT=/path/to/redops/report-kit`.

## 0. Before the day starts (once)

```sh
cd "$KIT" && python3 selftest.py && python3 -m unittest discover -s casehub/tests -t .
```

Both must pass. MCP registration is already done for Codex (`codex mcp list`), Claude Code (`claude mcp get casehub`), and Kimi (`~/.kimi-code/mcp.json`). Each registration passes its own `--actor` name, so writes are attributed per agent.

## 1. Open the case

```sh
python3 "$KIT/report.py" init "$CASE" --title '...' --report_id RPT-XXXXX --scope '...'
mkdir -p ~/.config/report && echo "$CASE" > ~/.config/report/current-case
export REPORT_CASE="$CASE"
```

The pointer file is what the MCP launcher reads, so every agent's `casehub` server opens the same case without per-case reconfiguration. Add targets and the first stages with `report.py target` and `report.py stage` as before.

## 2. Start the dashboard

```sh
cd "$KIT" && python3 -m casehub "$CASE" serve --port 8765
```

Open http://127.0.0.1:8765/ . It binds to loopback only. Mission shows targets, gate flags, actors, tasks, leases, decisions, and handoffs; Inventory, Evidence, and Report are the other tabs. It polls every five seconds.

## 3. Start each agent with an actor name

In every agent shell:

```sh
export REPORT_ACTOR=codex    # or claude, kimi
export REPORT_CASE="$CASE"
```

`report.py` stamps `REPORT_ACTOR` on every event it records. The MCP server uses the actor from its registration. Each agent's MCP registration already carries its actor name, so `REPORT_ACTOR` only matters for `report.py` commands the agent runs in its shell. Give each agent the following standing instruction only in standalone case mode:

> Work the case at `$REPORT_CASE`. Record every terminal command with `report.py run` or `tty`, and every browser, search, and AI action with `report.py log`, before doing anything else with the result. Use the `casehub` MCP tools to read the shared state (`case_status_text`, `inventory_search`, `evidence_timeline`), to propose what you found (`entity_record`, `claim_propose`, citing evidence IDs), and to coordinate (`task_claim`, `task_update`, `heartbeat`, `handoff_write`, `decision_ask`). Never mark anything verified yourself; another actor reviews with `claim_review`. Before ending a shell, listener, or tunnel, or stopping or reverting a machine, write a `decision_ask` and wait for the operator.

In combined mode, execute target actions only through the operations MCP
(`run` or `tool_run`), keep `focus_target` current, and import completed
captures with `report_import_runs` at each stage boundary. The import syncs
CaseHub automatically. Use `report_build` for PDF preflight and build.
See the root `REPORT_INTEGRATION.md` for the full sequence. Do not execute a
target command a second time through `report.py run` merely to capture it.

## 4. Roles for the day

- **Operator (you):** the only one who answers `decision_ask`, runs `ready-submit`, submits in the Portal, reviews the PDF, and packages.
- **Codex (execution owner):** in combined mode, runs target actions through the operations MCP and imports completed captures into REPORT; claims tasks, holds resource leases (`lease_acquire` on a shell, browser session, or listener name).
- **Claude and Kimi (advisers and reviewers):** read evidence and inventory, propose entities and claims, review the other agents' claims with `claim_review`, write handoff packets, and never run target actions unless you assign a task and lease.

## 5. The coordination loop

1. `task_create` an objective with a concrete deliverable; an agent `task_claim`s it.
2. The agent captures evidence with `report.py` in standalone mode or imports operations MCP runs in combined mode, then records findings with `entity_record` (level `proposed` or `observed` with event IDs) and `claim_propose`.
3. Run `python3 -m casehub "$CASE" extract` after noisy output to propose hosts, services, applications, identities, and files automatically; proposals stay `proposed` until an actor confirms them.
4. A different actor reviews each consequential claim with `claim_review` to `verified` or `ruled_out`, with a reason.
5. `task_update` with checkpoints; `heartbeat` every few minutes so the Mission view shows who is alive.
6. On a handoff, `handoff_write` with objective, verified facts, open sessions, failed avenues, and next action; the receiver `handoff_ack`s.
7. After a lab reset, revert, or relaunch: `python3 -m casehub "$CASE" epoch "reason"`. Prior observations become `stale` until re-observed.

## 6. Quick commands

```sh
python3 "$KIT/report.py" status "$CASE"                       # per-target evidence and gate state, no casehub needed
python3 -m casehub "$CASE" status                           # mission summary incl. actors, tasks, leases, decisions
python3 -m casehub "$CASE" search 'text'                    # evidence, entities, and claims
python3 -m casehub "$CASE" extract --dry-run                # preview automatic proposals
python3 -m casehub "$CASE" rebuild                          # replay the ledger into fresh projections
```

## 7. Report time

Unchanged: `report.py check`, `build`, review every page, `review --checked`, `package`, upload, `verify-upload`. Gate events and the actor on each ledger line appear in the PDF. casehub records are not part of the PDF; the report is built only from evidence.

## 8. If something is off

- Dashboard shows nothing new: run `python3 -m casehub "$CASE" sync`; the API syncs on each request, but a case path mismatch is the usual cause. Check `cat ~/.config/report/current-case` and `$REPORT_CASE`.
- An agent's MCP server fails to connect: run the launcher by hand, `"$KIT/casehub-mcp" --actor test`, and read its stderr.
- Suspect projections: `rebuild` is safe; the record ledger is never modified.
- `casehub.db` lives inside the case directory next to `case.json`; it is excluded from nothing by `report.py` and does not affect `check` or `build`.

## 9. Non-interactive agent invocation (verified in the dry run)

- **Claude Code one-shot:** With `--allowedTools 'mcp__casehub__*'`, pass the prompt on stdin; the option is variadic and swallows a trailing prompt argument. Assessmentple: `claude -p --output-format text --allowedTools 'mcp__casehub__*' < prompt.txt`.
- **Codex one-shot:** MCP tool calls under `codex exec` need `--approve-for-me`; interactive `codex` prompts normally. Always redirect stdin from `/dev/null` when running `codex exec` in the background or it waits for input.
- **Kimi one-shot:** `kimi -p 'prompt'` works without extra flags and prints a session id to resume.
