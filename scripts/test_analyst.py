"""Analyst window/cursor/transport tests. Run:

    uv run python scripts/test_analyst.py    (or pytest)

No model and no network: the HTTP layer is stubbed. These cover the plumbing
around the model, which is where the bugs were — what the analyst is allowed to
read, how far its cursor moves, and what shapes of server response it survives.

They deliberately do NOT test whether the model extracts *true* facts. That
needs a labelled eval set built from data/transcript/, and until it exists the
analyst's precision is unmeasured. See the module docstring in analyst.py.

Locked here:

  * netsensor writes flow telemetry into the same `events` table the analyst
    reads. Unfiltered, a 200-row window fills with per-flow rows and the model
    never sees the reasoning it exists to read.
  * a filtered window that never matches must still advance its watermark, or
    every tick re-scans a growing prefix of telemetry forever.
  * Qwen3.6 is a reasoning model; against LM Studio the schema-constrained
    answer arrives in `reasoning_content` with `content` empty, which parses as
    '' and raises.
"""

import json
import os
import sys
import tempfile
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_TMP = tempfile.mkdtemp(prefix="redops-analyst-test-")
os.environ["REDOPS_DATA"] = _TMP

from redops import analyst, db  # noqa: E402  (must follow REDOPS_DATA)

db.init_db()


def _fresh():
    db.use_data_dir(_TMP)
    db.init_db()
    conn = db.connect()
    conn.execute("DELETE FROM events")
    conn.commit()
    db.set_state(conn, analyst.CURSOR_KEY, "0")
    return conn


def _add(conn, kind, text="x", source="agent"):
    return db.add_event(conn, source, kind, text)


# ------------------------------------------------------------- the window

def test_flow_telemetry_is_not_read():
    conn = _fresh()
    for _ in range(500):
        _add(conn, "flow", "10.0.0.5:44100 > 10.0.0.9:443", source="user")
    _add(conn, "reasoning", "trying password reuse against WinRM")
    conn.commit()
    rows = db.rows(
        conn,
        "SELECT * FROM events WHERE id>? AND kind IN (%s) ORDER BY id LIMIT 200"
        % ",".join("?" * len(analyst.ANALYST_KINDS)), (0, *analyst.ANALYST_KINDS))
    kinds = {r["kind"] for r in rows}
    assert kinds == {"reasoning"}, kinds
    assert len(rows) == 1, "500 flow rows must not crowd out the one real event"


def test_callback_is_kept():
    """A fresh inbound connection is the highest-signal thing the sensor
    emits — the code already pushes one straight onto the worklist."""
    assert "callback" in analyst.ANALYST_KINDS
    assert "flow" not in analyst.ANALYST_KINDS
    assert "flowclose" not in analyst.ANALYST_KINDS


def test_semantic_kinds_are_all_allowed():
    for k in ("reasoning", "action", "output", "note", "verify",
              "trust", "error"):
        assert k in analyst.ANALYST_KINDS, k


def test_analyst_does_not_read_its_own_facts():
    """Posting a fact writes a `fact` event. Reading those back feeds the
    analyst its own output, and "do not restate what is already a structured
    fact" is the prompt instruction a model is most likely to ignore — measured
    against a live lab, all four facts it posted were restatements, and the next
    window contained all four as input."""
    assert "fact" not in analyst.ANALYST_KINDS


def test_window_substitutes_real_tool_output_for_the_headline():
    """A tool event's text is a one-line summary; the evidence is in
    tool_runs.output. Given only the summary the model mines the summary — it
    turned RedOps' own "16 facts" tally into a fact about the target."""
    conn = _fresh()
    try:
        conn.execute(
            "INSERT INTO tool_runs (id, tool, status, command, started_at, output) "
            "VALUES (77, 'agent-probe', 'done', 'GET /', ?, ?)",
            (db.now(), '{"skills":[{"name":"exec_sql"}],"paths":{"/kb/upload":{}}}'))
        conn.commit()
        eid = db.add_event(conn, "user", "output",
                           "[tool] agent-probe 10.0.0.1:8000: agent 'x' - 16 facts",
                           meta={"tool_run": 77})
        conn.commit()
        ev = db.rows(conn, "SELECT * FROM events WHERE id=?", (eid,))
        text = analyst._window_text(list(ev), conn)
    finally:
        conn.close()
    assert "exec_sql" in text, "the real output must reach the model"
    assert "/kb/upload" in text
    assert "16 facts" in text, "the summary line is still useful context"


def test_window_without_a_conn_is_just_headlines():
    conn = _fresh()
    eid = db.add_event(conn, "agent", "reasoning", "plain text")
    conn.commit()
    ev = db.rows(conn, "SELECT * FROM events WHERE id=?", (eid,))
    conn.close()
    assert "plain text" in analyst._window_text(list(ev))


# ------------------------------------------------------------- the cursor

def test_cursor_jumps_past_trailing_telemetry():
    """With no matching rows, the watermark must still clear the flow rows or
    every future tick re-scans a growing prefix."""
    conn = _fresh()
    for _ in range(300):
        _add(conn, "flow", "noise", source="user")
    conn.commit()
    head = db.rows(conn, "SELECT MAX(id) AS m FROM events")[0]["m"]
    conn.close()

    rep = analyst.tick("http://127.0.0.1:1")     # no matching rows -> no HTTP
    assert rep.get("skipped"), rep
    assert rep["cursor"] == head, f"cursor {rep['cursor']} should have reached {head}"


def test_cursor_stops_at_last_read_when_window_is_full():
    """A full window means there is more behind it; jumping the watermark would
    skip events that were never read."""
    conn = _fresh()
    for i in range(analyst.WINDOW_ROWS + 50):
        _add(conn, "output", f"line {i}")
    conn.commit()
    conn.close()

    real_chat = analyst._chat
    analyst._chat = lambda w, known=None: {"facts": [], "leads": []}
    try:
        rep = analyst.tick("http://127.0.0.1:1")
    finally:
        analyst._chat = real_chat
    assert rep["read"] == analyst.WINDOW_ROWS
    conn = db.connect()
    remaining = db.rows(
        conn, "SELECT COUNT(*) AS c FROM events WHERE id>?", (rep["cursor"],))[0]["c"]
    conn.close()
    assert remaining == 50, f"{remaining} unread events should remain, not 0"


def test_cursor_is_kept_when_the_model_fails():
    conn = _fresh()
    _add(conn, "reasoning", "something worth reading")
    conn.commit()
    conn.close()

    def boom(window, known=None):
        raise urllib.error.URLError("connection refused")

    real_chat = analyst._chat
    analyst._chat = boom
    try:
        analyst.tick("http://127.0.0.1:1")
        raise AssertionError("tick should propagate; the thread loop catches it")
    except urllib.error.URLError:
        pass
    finally:
        analyst._chat = real_chat
    conn = db.connect()
    assert int(db.get_state(conn, analyst.CURSOR_KEY, "0")) == 0, \
        "a failed pass must not consume its events"
    conn.close()


# ---------------------------------------------------------------- transport

class _FakeResp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _stub_urlopen(message, record=None):
    def _open(req, timeout=None):
        if record is not None:
            record.append(json.loads(req.data))
        return _FakeResp({"choices": [{"message": message}]})
    return _open


def test_reads_reasoning_content_when_content_is_empty():
    """Qwen3.6 on LM Studio puts the constrained answer in reasoning_content
    and leaves content empty; json.loads('') raises."""
    import urllib.request
    real = urllib.request.urlopen
    payload = {"facts": [], "leads": []}
    urllib.request.urlopen = _stub_urlopen(
        {"content": "", "reasoning_content": json.dumps(payload)})
    try:
        analyst.ANALYST_URL = "http://127.0.0.1:1/v1"
        assert analyst._chat("events") == payload
    finally:
        urllib.request.urlopen = real


def test_prefers_content_over_reasoning_content():
    import urllib.request
    real = urllib.request.urlopen
    urllib.request.urlopen = _stub_urlopen(
        {"content": json.dumps({"facts": [{"subject": "a"}], "leads": []}),
         "reasoning_content": json.dumps({"facts": [], "leads": []})})
    try:
        analyst.ANALYST_URL = "http://127.0.0.1:1/v1"
        assert analyst._chat("events")["facts"] == [{"subject": "a"}]
    finally:
        urllib.request.urlopen = real


def test_first_attempt_asks_for_schema_and_no_thinking():
    import urllib.request
    real, seen = urllib.request.urlopen, []
    urllib.request.urlopen = _stub_urlopen(
        {"content": json.dumps({"facts": [], "leads": []})}, record=seen)
    try:
        analyst.ANALYST_URL = "http://127.0.0.1:1/v1"
        analyst._chat("events")
    finally:
        urllib.request.urlopen = real
    assert len(seen) == 1, "a working server must not be retried"
    assert seen[0]["response_format"]["type"] == "json_schema"
    assert seen[0]["reasoning_effort"] == "none"


def test_falls_back_when_the_server_rejects_the_format():
    """Walks json_schema+no-thinking -> json_schema -> json_object."""
    import urllib.request
    real, seen = urllib.request.urlopen, []

    def _open(req, timeout=None):
        body = json.loads(req.data)
        seen.append(body)
        if len(seen) < 3:
            raise urllib.error.HTTPError(req.full_url, 400, "bad", {}, None)
        return _FakeResp({"choices": [{"message": {
            "content": "```json\n" + json.dumps({"facts": [], "leads": []}) + "\n```"}}]})

    urllib.request.urlopen = _open
    try:
        analyst.ANALYST_URL = "http://127.0.0.1:1/v1"
        assert analyst._chat("events") == {"facts": [], "leads": []}
    finally:
        urllib.request.urlopen = real
    assert [b["response_format"]["type"] for b in seen] == \
        ["json_schema", "json_schema", "json_object"], seen
    assert "reasoning_effort" not in seen[1]


def test_predicate_is_constrained_to_the_engine_vocabulary():
    """A free-string predicate produces facts no rule can join. Measured: the
    analyst emitted `exposes-tool` beside the engine's `has-tool` and left a
    textbook R10 unfired."""
    from redops import correlate
    enum = analyst.RESPONSE_SCHEMA["properties"]["facts"]["items"] \
        ["properties"]["predicate"].get("enum")
    assert enum, "predicate must be an enum, not a free string"
    assert set(enum) == set(correlate.CORRELATED_PREDICATES)
    for needed in ("has-tool", "is-read-by", "no-auth", "writable-by", "runs-as"):
        assert needed in enum, needed
    assert "exposes-tool" not in enum, "the invented predicate must be unreachable"


def test_prompt_lists_the_allowed_predicates():
    from redops import correlate
    body = analyst.PROMPT.format(categories=analyst.CATEGORIES, window="x",
                                 predicates=", ".join(correlate.CORRELATED_PREDICATES),
                                 entities="- kb-store  [rag-store]")
    assert "has-tool" in body and "is-read-by" in body
    assert "kb-store" in body, "known entities must reach the model"


# ------------------------------------------------------- entity resolution

def test_canonical_carries_the_existing_type():
    """upsert_entity keys on (engagement, type, name), so a fact posted without
    a type gets _guess_type — and a guess of `other` for a name already stored
    as `agent` creates a second node with the same name. Live run: the assistant
    existed twice and the two halves of an R10 chain hung off different nodes."""
    known = [("examplecorp-support-assistant", "agent"), ("10.99.7.10", "host")]
    assert analyst._canonical("MEGACORP-Support-Assistant", known) == \
        ("examplecorp-support-assistant", "agent")
    assert analyst._canonical("brand-new", known) == ("brand-new", "")


def test_tick_sends_the_existing_type_with_the_fact():
    analyst.WRITE_FACTS = True
    conn = _fresh()
    try:
        db.upsert_entity(conn, None, "agent", "assistant-x")
        db.add_event(conn, "agent", "reasoning", "assistant-x can run sql")
        conn.commit()
    finally:
        conn.close()
    real = analyst._chat
    analyst._chat = lambda w, known=None: {"facts": [
        {"subject": "Assistant_X", "predicate": "has-tool", "object": "exec_sql",
         "confidence": "confirmed"}], "leads": []}
    posted = []
    from redops import client
    real_req = client.req
    client.req = lambda m, p, b=None: posted.append(b)
    try:
        analyst.tick("http://127.0.0.1:1")
    finally:
        analyst._chat, client.req = real, real_req
    assert posted[0]["subject_name"] == "assistant-x", posted
    assert posted[0]["subject_type"] == "agent", posted
    analyst.WRITE_FACTS = False


def test_canonical_name_folds_cosmetic_drift():
    known = ["kb-store", "examplecorp-support-assistant", "10.99.7.10"]
    for variant in ("KB-Store", "kb store", "kb_store", "/kb-store/", " kb-store "):
        assert analyst._canonical_name(variant, known) == "kb-store", variant


def test_canonical_name_does_not_merge_different_things():
    """Wrong merges invent attack paths; missed merges only cost recall. An
    endpoint is not the store behind it, and this must not guess that it is."""
    known = ["kb-store", "examplecorp-support-assistant"]
    for distinct in ("/kb/upload", "kb-cache", "support-assistant-v2"):
        assert analyst._canonical_name(distinct, known) == distinct, distinct


def test_canonical_name_passes_through_unknowns():
    assert analyst._canonical_name("brand-new-thing", ["a", "b"]) == "brand-new-thing"
    assert analyst._canonical_name("", ["a"]) == ""


def test_known_entities_is_bounded_and_recent_first():
    conn = _fresh()
    try:
        for i in range(analyst.MAX_KNOWN_ENTITIES + 25):
            db.upsert_entity(conn, None, "host", f"h{i}")
        conn.commit()
        names = analyst._known_entities(conn, None)
    finally:
        conn.close()
    assert len(names) == analyst.MAX_KNOWN_ENTITIES, len(names)
    assert all(isinstance(x, tuple) and len(x) == 2 for x in names)


def test_tick_anchors_a_drifted_subject_onto_the_existing_entity():
    analyst.WRITE_FACTS = True
    conn = _fresh()
    try:
        db.upsert_entity(conn, None, "rag-store", "kb-store")
        db.add_event(conn, "agent", "reasoning", "the kb accepts anonymous writes")
        conn.commit()
    finally:
        conn.close()
    real = analyst._chat
    analyst._chat = lambda w, known=None: {
        "facts": [{"subject": "KB_Store", "predicate": "accepts",
                   "object": "anonymous writes", "confidence": "confirmed"}],
        "leads": []}
    posted = []
    from redops import client
    real_req = client.req
    client.req = lambda m, p, b=None: posted.append(b)
    try:
        rep = analyst.tick("http://127.0.0.1:1")
    finally:
        analyst._chat, client.req = real, real_req
    assert posted and posted[0]["subject_name"] == "kb-store", posted
    assert rep["anchored"] == 1
    analyst.WRITE_FACTS = False


def test_facts_are_demoted_to_leads_by_default():
    """Facts feed correlate.py directly, so a wrong one manufactures an
    opportunity rather than merely adding noise. Until an eval on real
    transcripts says otherwise, the analyst files hunches a human promotes."""
    assert analyst.WRITE_FACTS is False, "shipped default must not write facts"
    conn = _fresh()
    try:
        db.add_event(conn, "agent", "reasoning", "the guard rejected our path query")
        conn.commit()
    finally:
        conn.close()
    real = analyst._chat
    analyst._chat = lambda w, known=None: {"facts": [
        {"subject": "guard", "predicate": "no-auth", "object": "x",
         "confidence": "confirmed"}], "leads": []}
    paths = []
    from redops import client
    real_req = client.req
    client.req = lambda m, p, b=None: paths.append(p)
    try:
        rep = analyst.tick("http://127.0.0.1:1")
    finally:
        analyst._chat, client.req = real, real_req
    assert paths == ["/api/leads"], paths
    assert rep["demoted"] == 1 and rep["posted"]["facts"] == 0, rep


def test_schema_matches_the_documented_shape():
    props = analyst.RESPONSE_SCHEMA["properties"]
    assert set(props) == {"facts", "leads"}
    assert set(props["facts"]["items"]["properties"]) == \
        {"subject", "predicate", "object"}
    assert set(props["leads"]["items"]["properties"]) == \
        {"observation", "category", "candidate_vector"}


def test_disabled_unless_url_is_set():
    assert analyst.maybe_start.__doc__ is None or True
    saved = analyst.ANALYST_URL
    analyst.ANALYST_URL = ""
    try:
        assert analyst.maybe_start("http://127.0.0.1:9100") is None
    finally:
        analyst.ANALYST_URL = saved


if __name__ == "__main__":
    import shutil
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {type(e).__name__}: {e}")
    shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
