"""Fixture regression for the agent-card/A2A/OpenAPI parser — proves the D1 retrofit
preserves it (agent node WITH host/port meta, model fingerprint, skills, exposed
endpoints, status advance, summary).

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_http
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(__file__)


def _results():
    def rd(name):
        with open(os.path.join(HERE, "http", name)) as f:
            return f.read()
    return {
        "/.well-known/agent.json": (200, rd("agent.json")),
        "/openapi.json": (200, rd("openapi.json")),
        "/health": (200, rd("health.json")),
    }


def test_to_result():
    from redops.parsers import http
    r = http.to_result(_results(), "192.0.2.14", 8080, has_target=True)
    # agent + host + model nodes; agent carries host/port meta
    agent = [e for e in r.entities if e["type"] == "agent"]
    assert agent and agent[0]["name"] == "ResearchAssistant"
    assert agent[0].get("meta", {}).get("port") == 8080, agent[0]
    assert any(e["type"] == "host" and e["name"] == "192.0.2.14" for e in r.entities)
    assert any(e["type"] == "model" and e["name"] == "gpt-4o-mini" for e in r.entities)
    preds = [f.predicate for f in r.facts]
    assert preds.count("on-host") == 1 and preds.count("runs-model") == 1
    assert preds.count("has-skill") == 3 and preds.count("has-tool") == 3, preds        # search, summarize, ingest
    assert preds.count("exposes") == 4, preds          # /chat /ingest /query /health
    assert {f.object_text for f in r.facts if f.predicate == "exposes"} == {"/chat", "/ingest", "/query", "/health"}
    assert r.target_updates.get("status_advance") is True
    assert r.summary == "agent 'ResearchAssistant' · model gpt-4o-mini · 12 facts", r.summary
    print("  to_result: OK — agent(+meta)/model/3 skills/4 endpoints, summary exact")


def test_rag_backend():
    from redops.parsers import http
    results = _results()
    results["/health"] = (200, json.dumps({"agent": "ResearchAssistant",
                                           "rag": "qdrant@backend:6333"}))
    r = http.to_result(results, "local", 8080)
    store = next(e for e in r.entities if e["type"] == "rag-store")
    assert store["name"] == "qdrant"
    assert store["meta"]["endpoint"] == "backend:6333"
    assert any(f.subject == "qdrant" and f.predicate == "is-read-by"
               and f.object == "ResearchAssistant" for f in r.facts)
    assert any(f.subject == "qdrant" and f.predicate == "on-host"
               and f.object == "backend" for f in r.facts)


def test_no_card():
    from redops.parsers import http
    r = http.to_result({"/health": (404, "not found")}, "10.0.0.9", 80)
    assert r.entities == [] and r.facts == [] and r.status == "empty"
    assert r.summary == "no agent card found"
    print("  edges: OK — no card => zero facts, honest summary")


def test_persist_roundtrip():
    tmp = tempfile.mkdtemp(prefix="redops-fix-http-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db, parsers
    db.use_data_dir(tmp)   # env alone is too late: DATA_DIR binds at import
    from redops.parsers import http
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements",
                    {"name": "fix", "scope": "", "notes": "", "created_at": db.now()})
    tid = db.insert(conn, "targets",
                    {"engagement_id": eng, "ip": "192.0.2.14", "hostname": "",
                     "os": "", "role": "", "status": "unidentified", "meta_json": "{}"})
    conn.commit()
    r = http.to_result(_results(), "192.0.2.14", 8080, has_target=True)
    parsers.persist(conn, eng, tid, "192.0.2.14", r, stage="observed", source="wire-auto")
    conn.commit()

    agent = db.row(conn, "SELECT meta_json FROM entities WHERE engagement_id=? AND type='agent'", (eng,))
    assert agent and json.loads(agent["meta_json"]).get("port") == 8080, "agent meta preserved"
    facts = db.rows(conn, "SELECT predicate, stage FROM facts WHERE engagement_id=?", (eng,))
    assert facts and sum(f["stage"] == "observed" for f in facts) == 1, "host response observed"
    assert all(f["stage"] == "claimed" for f in facts if f["predicate"] != "on-host"), "advertised relationships remain claims"
    assert len(facts) == 12, len(facts)
    t = db.row(conn, "SELECT status FROM targets WHERE id=?", (tid,))
    assert t["status"] == "identified", dict(t)
    conn.close()
    print(f"  persist: OK — agent meta preserved, {len(facts)} facts with claim stages, target identified")


def main():
    tests = [test_to_result, test_no_card, test_persist_roundtrip]
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
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(tests) - failed}/{len(tests)} http fixtures")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
