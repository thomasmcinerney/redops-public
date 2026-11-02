"""Fixture regression for the ai-chat parser — proves the Gate-1 mapping across the
surface: OpenAI, RAG (sources+session), Ollama, refusal, auth-required, and a
non-chat JSON that must fail clean.

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_ai_chat
"""
import os
import json
import importlib
import sys
import tempfile

HERE = os.path.dirname(__file__)


def _body(name):
    with open(os.path.join(HERE, "ai_chat", name)) as f:
        return f.read()


def test_openai():
    from redops.parsers import ai_chat
    r = ai_chat.to_result(_body("openai.json"), "10.0.0.5", 8080, "/v1/chat/completions")
    assert any(e["type"] == "endpoint" for e in r.entities)
    assert any(e["type"] == "model" and e["name"] == "gpt-4o-mini" for e in r.entities)
    assert any(f.predicate == "runs-model" and f.object == "gpt-4o-mini" for f in r.facts)
    assert not any(f.predicate in ("rag-backed", "session-format") for f in r.facts)
    print("  openai: OK — endpoint + model(gpt-4o-mini), no rag/session noise")


def test_rag():
    from redops.parsers import ai_chat
    r = ai_chat.to_result(_body("rag.json"), "192.0.2.14", 8080, "/query")
    colls = [e["name"] for e in r.entities if e["type"] == "collection"]
    assert colls == ["research-kb"], colls   # two sources, one collection, deduped
    assert any(f.predicate == "rag-backed" for f in r.facts)
    assert sum(1 for f in r.facts if f.predicate == "retrieves-from") == 1
    sf = [f.object_text for f in r.facts if f.predicate == "session-format"]
    assert sf == ["MC-YYYYMMDD-NNNN"], sf     # the reusable pattern, not the raw id
    assert any("internal" in n for n in r.notes), r.notes  # internal-wiki source noted, not a fact
    print("  rag: OK — collection deduped, rag-backed, session pattern MC-YYYYMMDD-NNNN, internal source noted")


def test_ollama():
    from redops.parsers import ai_chat
    r = ai_chat.to_result(_body("ollama.json"), "10.0.0.6", 11434, "/api/chat")
    assert any(e["type"] == "model" and e["name"] == "llama3" for e in r.entities)
    print("  ollama: OK — model(llama3) from nested message shape")


def test_refusal_is_note_not_fact():
    from redops.parsers import ai_chat
    r = ai_chat.to_result(_body("refusal.json"), "10.0.0.5", 8080, "/chat")
    assert any("refus" in n.lower() for n in r.notes), r.notes
    assert not any(f.predicate == "refused" for f in r.facts)  # interpretive => note only
    print("  refusal: OK — recorded as a note, NOT an observed fact")


def test_auth_required_fail_clean():
    from redops.parsers import ai_chat
    r = ai_chat.to_result("", "10.0.0.5", 8080, "/chat", status_code=401)
    assert r.status == "unrecognized" and r.facts == [] and r.entities == []
    assert any("auth" in n.lower() for n in r.notes)
    print("  auth(401): OK — zero facts, auth note")


def test_non_chat_json_fail_clean():
    from redops.parsers import ai_chat
    r = ai_chat.to_result(_body("unknown.json"), "10.0.0.5", 8080, "/chat")
    assert r.status == "unrecognized" and r.facts == [] and r.entities == []
    print("  unknown JSON: OK — no chat signal => unrecognized, ZERO facts")


def test_reply_and_invoked_tool():
    ai_chat = importlib.import_module('redops' + '.parsers.ai_chat')
    body = json.dumps({"reply": "Based on the KB", "tools_invoked": ["exec_sql"]})
    r = ai_chat.to_result(body, "192.168.64.3", 8000, "/chat", status_code=200)
    assert r.status == "ok" and "invoked exec_sql" in r.summary
    assert any(f.predicate == "invoked-tool" and f.object_text == "exec_sql"
               for f in r.facts)


def test_persist_roundtrip():
    tmp = tempfile.mkdtemp(prefix="redops-chat-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db, parsers
    db.use_data_dir(tmp)   # env alone is too late: DATA_DIR binds at import
    from redops.parsers import ai_chat
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements", {"name": "c", "scope": "", "notes": "", "created_at": db.now()})
    tid = db.insert(conn, "targets", {"engagement_id": eng, "ip": "192.0.2.14", "hostname": "",
                                      "os": "", "role": "", "status": "unidentified", "meta_json": "{}"})
    conn.commit()
    r = ai_chat.to_result(_body("rag.json"), "192.0.2.14", 8080, "/query")
    parsers.persist(conn, eng, tid, "192.0.2.14", r, stage="observed", source="wire-auto")
    conn.commit()
    facts = db.rows(conn, "SELECT predicate, stage FROM facts WHERE engagement_id=?", (eng,))
    assert facts and all(f["stage"] == "observed" for f in facts)
    assert any(e["type"] == "collection" for e in db.rows(conn, "SELECT type FROM entities WHERE engagement_id=?", (eng,)))
    conn.close()
    print(f"  persist: OK — {len(facts)} facts@observed, collection node landed")


def main():
    tests = [test_openai, test_rag, test_ollama, test_refusal_is_note_not_fact,
             test_auth_required_fail_clean, test_non_chat_json_fail_clean, test_reply_and_invoked_tool, test_persist_roundtrip]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {e!r}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(tests) - failed}/{len(tests)} ai-chat fixtures")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
