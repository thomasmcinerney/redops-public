"""Analyst (spec §3d): out-of-band LLM pass over the transcript window.

ACTIVE ONLY when REDOPS_ANALYST_URL is set (OpenAI-compatible chat
completions endpoint; REDOPS_ANALYST_KEY, REDOPS_ANALYST_MODEL,
REDOPS_ANALYST_INTERVAL=120s). Run it against a LOCAL model - some engagement networks are
egress-restricted and engagement data should not leave the box:

    LM Studio   REDOPS_ANALYST_URL=http://127.0.0.1:1234/v1
                REDOPS_ANALYST_MODEL=qwen/qwen3.6-35b-a3b
    Ollama      REDOPS_ANALYST_URL=http://127.0.0.1:11434/v1
                REDOPS_ANALYST_MODEL=qwen3.6:35b-a3b

Reads events newer than its cursor (wiretail_state analyst:cursor) and of a
kind worth reading (ANALYST_KINDS - netsensor's flow telemetry shares this
table and would otherwise crowd out everything else), prompts with the
13-category checklist + few-shot examples, gets back JSON constrained by
RESPONSE_SCHEMA, and posts facts/leads via the HTTP API with source=analyst.
Any error -> server log, keep cursor, retry next tick.

The 120s interval means latency is nearly free here: a 30B-class local model
answering in 20s is indistinguishable from one answering in 2s.

PRECISION IS MEASURED, AND IT IS NOT GOOD ENOUGH TO TRUST UNSUPERVISED.
scripts/eval_analyst.py scores this code path on eight labelled windows. The
best local model tested reads ~82% of the facts a window supports, keeps 100% of
its predicates inside the vocabulary the rules join on, and still emits about
one unsupported fact per case. Most importantly, on the two windows that
describe a complete R2/R10 chain, its raw output fires the rule in at most one
of them: it names the same thing differently across facts, and a relation that
does not join is inert.

So it is a recall aid on top of the deterministic path, not a replacement for
reading the transcript. It writes into the store correlate.py reasons over,
where an unsupported fact does not merely add noise but manufactures an
opportunity - review `source=analyst` facts before acting on them.
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request

from . import correlate, db

ANALYST_URL = os.environ.get("REDOPS_ANALYST_URL", "")
ANALYST_KEY = os.environ.get("REDOPS_ANALYST_KEY", "local")
ANALYST_MODEL = os.environ.get("REDOPS_ANALYST_MODEL", "qwen/qwen3.6-35b-a3b")
INTERVAL = int(os.environ.get("REDOPS_ANALYST_INTERVAL", "120"))
MAX_WINDOW_CHARS = 12000
WINDOW_ROWS = 200
CURSOR_KEY = "analyst:cursor"

# Which event kinds the analyst reads.
#
# netsensor writes every observed flow into this same events table as
# `flow`/`flowclose`/`callback`, and telemetry growth is unbounded (see
# claudedocs/hardening-spec.md R7) while claim-bearing events are not. Left
# unfiltered, a 200-row window and a 12k-char budget meant for agent reasoning
# and tool output fill with per-flow rows instead, and the model spends its
# context restating traffic that correlate.py already handles deterministically
# and without a token cost.
#
# This is an allowlist rather than a denylist on purpose: an unclassified new
# kind should default to *excluded*, because the failure it guards against is
# flooding. A new semantic kind going unread is a quiet loss of recall; a new
# telemetry kind going unfiltered is the analyst reading nothing else.
#
# `callback` is deliberately kept. A fresh inbound connection is the highest-
# signal thing the sensor produces — the code already pushes one onto the
# worklist the moment it lands — and there are few of them.
# `fact` is deliberately NOT here. Posting a fact writes a `fact` event, so
# reading them back feeds the analyst its own output — and the prompt's "do not
# restate what is already a structured fact" is the instruction a model is most
# likely to ignore. Measured against a live lab: of four facts it posted, all
# four restated existing deterministic facts under new predicate names
# (`uses-model` beside `runs-model`, `runs-service` beside `on-host`,
# `exposes-port` beside the nmap service) and the next window then contained
# those four as input. The structured store is what the analyst writes to, not
# what it reads from.
ANALYST_KINDS = ("reasoning", "action", "output", "note", "verify",
                 "trust", "error", "callback")

CATEGORIES = ("write-primitive, priv-context, restart-trigger, auth-gap, "
              "reachability-pivot, secret-exposure, read-exfil, anomaly, "
              "llm-read-sink, action-tool, trust-edge, detection-tripwire, "
              "guardrail-blindspot")

PROMPT = """You are an analyst reviewing red-team operation transcript events.
From the events below, extract NEW structured intelligence as strict JSON.

Categories: {categories}

Emit ONLY JSON (no prose, no markdown fence):
{{"facts": [{{"subject": "...", "predicate": "...", "object": "..."}}],
  "leads": [{{"observation": "...", "category": "...", "candidate_vector": "..."}}]}}

Allowed predicates (use exactly these): {predicates}

Rules: facts are concrete relations (subject -predicate-> object); leads are hunches
worth chasing. Everything you extract is recorded as an unverified `claimed` fact —
an inference from reading this window, NOT ground truth. The deterministic tool
parsers and the operator promote it to observed/confirmed; you do not assign stage.
Prefer precision; emit empty lists when nothing qualifies. Do not restate what is
already a structured fact.

Assessmentple 1:
events: "22/tcp open ssh", "config.toml contains password=hunter2"
output: {{"facts": [{{"subject": "config.toml", "predicate": "has-cred", "object": "hunter2"}}], "leads": []}}

Assessmentple 2:
events: "the agent denied my path query, something privileged must guard it"
output: {{"facts": [], "leads": [{{"observation": "denied path query implies a privileged guard process worth reversing", "category": "anomaly", "candidate_vector": "reverse the guard"}}]}}

Assessmentple 3:
events: "the /about page says the app is built on Qdrant + MongoDB"
output: {{"facts": [{{"subject": "app", "predicate": "backed-by", "object": "Qdrant"}}, {{"subject": "app", "predicate": "backed-by", "object": "MongoDB"}}], "leads": []}}

KNOWN ENTITIES already in the graph, as `name [type]`. When a fact concerns one
of these, the subject or object MUST be the name copied character for character.
Do not qualify it, pluralise it, or describe it: "kb-store documents", "the
kb-store" and "kb-store (RAG)" are three new nodes that connect to nothing,
while "kb-store" joins the graph. If a fact is not about anything listed, name
the new entity as tersely as the existing ones are named.
{entities}

EVENTS:
{window}
"""


# The response shape, as an actual schema rather than a hope.
#
# A local server that supports json_schema compiles this to a grammar and masks
# invalid tokens at sample time, so the model cannot emit anything that fails to
# parse. That is strictly better than asking for `json_object` and repairing the
# answer afterwards, which is what this used to do.
#
# Not every OpenAI-compatible server implements json_schema, so `_chat` falls
# back to json_object and keeps the fence-stripping for that path.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "facts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "subject": {"type": "string"},
                    # Constrained to the vocabulary correlate.py joins on.
                    # A free-string predicate is why this produced `exposes-tool`
                    # beside the engine's `has-tool` and left a textbook R10
                    # unfired: plausible, well-formed, and inert. The schema is
                    # compiled to a grammar, so the model cannot pick a
                    # predicate no rule reads.
                    "predicate": {"type": "string",
                                  "enum": list(correlate.CORRELATED_PREDICATES)},
                    "object": {"type": "string"},
                },
                "required": ["subject", "predicate", "object"],
                "additionalProperties": False,
            },
        },
        "leads": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "observation": {"type": "string"},
                    "category": {"type": "string"},
                    "candidate_vector": {"type": "string"},
                },
                "required": ["observation", "category", "candidate_vector"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["facts", "leads"],
    "additionalProperties": False,
}


JSON_SCHEMA_FORMAT = {"type": "json_schema",
                      "json_schema": {"name": "analyst_output", "strict": True,
                                      "schema": RESPONSE_SCHEMA}}


def _post(body: dict) -> str:
    """One call; returns the assistant's text.

    Reads `reasoning_content` when `content` is empty. Qwen3.6 is a reasoning
    model, and against LM Studio the schema-constrained answer arrives in
    `reasoning_content` with `content` empty whenever thinking is left on —
    which parses as '' and raises. Servers that do not split the two are
    unaffected by this.
    """
    req = urllib.request.Request(
        ANALYST_URL.rstrip("/") + "/chat/completions", data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {ANALYST_KEY}"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        msg = json.loads(resp.read())["choices"][0]["message"]
    return (msg.get("content") or msg.get("reasoning_content") or "").strip()


def _chat(window: str, known: list[str] | None = None) -> dict:
    """One chat-completions call; returns parsed JSON dict or raises.

    Walks down a ladder of capabilities, because "OpenAI-compatible" is a range
    rather than a specification:

      1. json_schema + reasoning_effort=none — constrained decoding with
         thinking off. The server compiles the schema to a grammar and masks
         invalid tokens at sample time, so the model *cannot* emit unparseable
         output, and no tokens are burned reasoning about a shape it is already
         being held to.
      2. json_schema alone — for servers that reject the unknown parameter
         rather than ignoring it.
      3. json_object — for servers with no schema support at all. This is the
         only rung where the answer can come back malformed, so it is also the
         only one that keeps the fence-stripping repair.
    """
    base = {
        "model": ANALYST_MODEL,
        # A schema guarantees valid JSON only if generation FINISHES. Left
        # unset, the server's default cap truncated the reply mid-string and
        # every tick died on JSONDecodeError — and enriching the window with
        # real tool output made replies longer, so the fix that improved recall
        # is what exposed this. Budget for the whole fact list.
        "max_tokens": MAX_RESPONSE_TOKENS,
        "messages": [{"role": "user",
                      "content": PROMPT.format(
                          categories=CATEGORIES, window=window,
                          predicates=", ".join(correlate.CORRELATED_PREDICATES),
                          entities=("\n".join(f"- {n}  [{t}]" for n, t in known)
                                    if known else "(none yet)"))}],
        "temperature": 0,
    }
    for body in ({**base, "response_format": JSON_SCHEMA_FORMAT,
                  "reasoning_effort": "none"},
                 {**base, "response_format": JSON_SCHEMA_FORMAT}):
        try:
            return json.loads(_post(body))
        except urllib.error.HTTPError:
            continue
    content = _post({**base, "response_format": {"type": "json_object"}})
    if content.startswith("```"):
        content = content.strip("`").split("\n", 1)[-1].rsplit("```", 1)[0]
    return json.loads(content)


TOOL_OUTPUT_CHARS = 4000
MAX_KNOWN_ENTITIES = 80
MAX_RESPONSE_TOKENS = int(os.environ.get("REDOPS_ANALYST_MAX_TOKENS", "3000"))

# Does the analyst write FACTS, or only LEADS? Default: leads only.
#
# Facts feed correlate.py directly, so a wrong one does not add noise — it
# manufactures an opportunity, and an operator chases an attack path that does
# not exist. Leads are hunches on a worklist that a human reads and promotes.
# The blast radius is the difference between "this was a bad suggestion" and
# "this was a bad suggestion wearing the costume of evidence".
#
# The default is off because the analyst has not earned it. Measured on the lab
# against the same target: the deterministic path alone produced 5 R10
# opportunities; with the analyst also writing facts, 3 — and among its facts
# were `is-read-by` with the direction reversed and `runs-as ->
# qwen2.5-7b-instruct`, which is a model rather than a principal. Nothing it
# contributed there was absent from structured output a parser can read.
#
# Set REDOPS_ANALYST_FACTS=1 when an eval on YOUR transcripts says it is safe.
WRITE_FACTS = os.environ.get("REDOPS_ANALYST_FACTS", "0") == "1"


def _known_entities(conn, engagement_id) -> list[tuple[str, str]]:
    """Entity names already in the graph, most recently seen first.

    Constraining the predicate vocabulary stopped facts orphaning on the
    predicate; they then orphaned on the subject instead. A live run wrote
    `is-read-by` against `kb-store` and `accepts` against `/kb/upload` — the
    same sink under two names — and R10 stayed silent, because
    `_sink_influenceable` looks for an influence fact on the *same subject id*
    as the read. Showing the model what already exists is the cheap half of the
    fix; `_canonical_name` below is the other half.
    """
    rows = db.rows(
        conn,
        # id breaks ties: last_seen has second resolution, and a burst of
        # entities from one tool run all share a timestamp. Ordering on the
        # timestamp alone makes "most recent" arbitrary inside a burst, so the
        # newest entity can fall outside the cap and the model never sees the
        # very thing it is most likely to be writing about.
        "SELECT name, type FROM entities WHERE engagement_id IS ? "
        "ORDER BY last_seen DESC, id DESC LIMIT ?",
        (engagement_id, MAX_KNOWN_ENTITIES))
    return [(r["name"], r["type"]) for r in rows]


def _norm(name: str) -> str:
    """Fold the cosmetic differences only: case, surrounding whitespace, path
    slashes, and the -_ / space separators. Deliberately NOT fuzzy — this
    decides whether two claims land on one node in a store the correlation
    engine reasons over, so a wrong merge invents an attack path that does not
    exist. Missing a merge only costs recall."""
    s = (name or "").strip().lower().strip("/")
    for ch in ("_", "-", " ", "."):
        s = s.replace(ch, "")
    return s


def _canonical(name: str, known: list[tuple[str, str]]) -> tuple[str, str]:
    """(name, type) of the existing entity this denotes, else (name, "").

    Carrying the type matters as much as the name. `upsert_entity` keys on
    (engagement, type, name), so a fact posted without one gets `_guess_type`,
    and a guess of `other` for a name already stored as `agent` creates a second
    node with the same name. That is exactly what happened on the live run:
    `examplecorp-support-assistant` existed twice, once as `agent` from
    agent-probe and once as `other` from the analyst, and the two halves of an
    R10 chain hung off different nodes."""
    if not name:
        return name, ""
    n = _norm(name)
    if not n:
        return name, ""
    for k, t in known:
        if _norm(k) == n:
            return k, t
    return name, ""


def _canonical_name(name: str, known) -> str:
    """Name-only view of `_canonical`, for callers that do not set a type."""
    pairs = known if (known and isinstance(known[0], tuple)) else [(k, "") for k in known]
    return _canonical(name, pairs)[0]


def _window_text(events: list[dict], conn=None) -> str:
    """Render the window, substituting a tool run's real output for its headline.

    A tool event's text is a one-line summary — `[tool] agent-probe host: agent
    'x' - model y - 16 facts` — while the thing worth reading (the agent card,
    the port table) sits in `tool_runs.output`. Given only the summary the model
    has nothing to extract from and starts mining the summary itself: against a
    live lab it turned RedOps' own "16 facts" tally into
    `support-assistant -has-context-> 16 facts`, and filed a lead claiming that
    tally implied a preloaded system. Meanwhile the endpoints that actually
    mattered — an unauthenticated `/kb/upload` read back by `/chat`, an
    `exec_sql` skill, a token in `/admin/config` — were in the output it never
    saw, so it could not produce the `is-read-by`/`has-tool`/`no-auth` facts R10
    needs to fire.
    """
    lines = []
    for e in events:
        head = f"[{e['ts']}] ({e['source']}/{e['kind']}) {e['text']}"
        run_id = None
        if conn is not None:
            try:
                run_id = (json.loads(e.get("meta_json") or "{}") or {}).get("tool_run")
            except (ValueError, TypeError):
                run_id = None
        if run_id:
            row = db.row(conn, "SELECT output FROM tool_runs WHERE id=?", (run_id,))
            if row and row["output"]:
                head += f"\n--- tool_run {run_id} output ---\n{row['output'][:TOOL_OUTPUT_CHARS]}"
        lines.append(head)
    return "\n".join(lines)[:MAX_WINDOW_CHARS]


def tick(base_url: str) -> dict:
    """One analyst pass against the API at base_url. Returns a small report."""
    from . import client  # late import: honors REDOPS_URL env
    client.BASE = base_url
    conn = db.connect()
    try:
        cursor = int(db.get_state(conn, CURSOR_KEY, "0") or 0)
        marks = ",".join("?" * len(ANALYST_KINDS))
        events = db.rows(
            conn,
            f"SELECT * FROM events WHERE id>? AND kind IN ({marks}) "
            f"ORDER BY id LIMIT {WINDOW_ROWS}",
            (cursor, *ANALYST_KINDS))
        if not events:
            # Nothing to read, but telemetry may still have advanced the table by
            # thousands of rows. Move the watermark past them, or every future
            # tick re-scans a growing prefix looking for events that are not
            # there.
            head = db.rows(conn, "SELECT MAX(id) AS m FROM events")[0]["m"] or cursor
            if head > cursor:
                db.set_state(conn, CURSOR_KEY, str(head))
            return {"skipped": "no new events", "cursor": head}
        eng_id = db._active_engagement_id(conn)
        eng = {"id": eng_id} if eng_id else None
        known = _known_entities(conn, eng_id)
        parsed = _chat(_window_text(events, conn), known)
        posted = {"facts": 0, "leads": 0}
        anchored = demoted = 0
        for f in parsed.get("facts", []) or []:
            if not (f.get("subject") and f.get("predicate") and f.get("object")):
                continue
            if not WRITE_FACTS:
                # Demote to a lead: same observation, no path into the
                # correlation engine until a human promotes it.
                client.req("POST", "/api/leads", {
                    "engagement_id": eng["id"] if eng else None,
                    "observation": f"{f['subject']} {f['predicate']} {f['object']}",
                    "category": "anomaly", "candidate_vector": "",
                    "source": "analyst"})
                demoted += 1
                continue
            subject, stype = _canonical(f["subject"], known)
            if subject != f["subject"]:
                anchored += 1
            body = {"engagement_id": eng["id"] if eng else None,
                    "subject_name": subject, "predicate": f["predicate"],
                    "stage": "claimed", "source": "analyst"}
            if stype:
                body["subject_type"] = stype
            if " " in f["object"]:
                body["object_text"] = f["object"]
            else:
                obj, otype = _canonical(f["object"], known)
                if obj != f["object"]:
                    anchored += 1
                body["object_name"] = obj
                if otype:
                    body["object_type"] = otype
            client.req("POST", "/api/facts", body)
            posted["facts"] += 1
        for l in parsed.get("leads", []) or []:
            if not l.get("observation"):
                continue
            client.req("POST", "/api/leads", {
                "engagement_id": eng["id"] if eng else None,
                "observation": l["observation"], "category": l.get("category", "anomaly"),
                "candidate_vector": l.get("candidate_vector", ""), "source": "analyst"})
            posted["leads"] += 1
        # If the window came back full there are more matching rows behind it,
        # so stop at the last one read. If it did not, this drained the queue and
        # the watermark can jump past any trailing telemetry in one step.
        new_cursor = events[-1]["id"]
        if len(events) < WINDOW_ROWS:
            head = db.rows(conn, "SELECT MAX(id) AS m FROM events")[0]["m"] or new_cursor
            new_cursor = max(new_cursor, head)
        db.set_state(conn, CURSOR_KEY, str(new_cursor))
        return {"posted": posted, "cursor": new_cursor, "read": len(events),
                "anchored": anchored, "demoted": demoted}
    finally:
        conn.close()


class Analyst(threading.Thread):
    def __init__(self, base_url: str):
        super().__init__(daemon=True, name="analyst")
        self.base_url = base_url

    def run(self) -> None:
        time.sleep(5)  # let the API come up
        while True:
            try:
                report = tick(self.base_url)
                if "posted" in report:
                    print(f"[analyst] posted {report['posted']} cursor={report['cursor']}",
                          flush=True)
            except Exception as e:
                # keep cursor, retry next tick
                print(f"[analyst] error (cursor kept, will retry): {e!r}", flush=True)
            time.sleep(INTERVAL)


def maybe_start(base_url: str) -> Analyst | None:
    if not ANALYST_URL:
        return None
    a = Analyst(base_url)
    a.start()
    return a
