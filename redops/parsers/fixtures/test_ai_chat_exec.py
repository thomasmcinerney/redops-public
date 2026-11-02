"""End-to-end test for the ai-chat executor: a local stub HTTP server answers the
POST with the RAG fixture; _execute_chat sends the message, parses the reply, and
persists. Proves the kind:"chat" executor path (POST -> parse -> persist -> finalize).

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_ai_chat_exec
"""
import http.server
import os
import socket
import sys
import tempfile
import threading

HERE = os.path.dirname(__file__)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_executor_against_stub():
    with open(os.path.join(HERE, "ai_chat", "rag.json")) as f:
        rag = f.read()
    port = _free_port()

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(rag.encode())

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        tmp = tempfile.mkdtemp(prefix="redops-chatx-")
        os.environ["REDOPS_DATA"] = tmp
        from redops import db, tools
        db.use_data_dir(tmp)   # env alone is too late: DATA_DIR binds at import
        db.init_db()
        conn = db.connect()
        eng = db.insert(conn, "engagements", {"name": "cx", "scope": "", "notes": "", "created_at": db.now()})
        tid = db.insert(conn, "targets", {"engagement_id": eng, "ip": "127.0.0.1", "hostname": "",
                                          "os": "", "role": "", "status": "unidentified", "meta_json": "{}"})
        rid = db.insert(conn, "tool_runs", {"engagement_id": eng, "target_id": tid, "tool": "ai-chat",
                                            "command": "", "status": "running", "actor": "user",
                                            "started_at": db.now(), "priority": 3})
        conn.commit()
        conn.close()

        spec = tools.TOOL_SPECS["ai-chat"]
        summary = tools._execute_chat(rid, eng, tid, "127.0.0.1", port, "ai-chat", spec,
                                      {"path": "/query", "body_shape": "query", "message": "hi"}, "user")

        conn = db.connect()
        ents = [e["type"] for e in db.rows(conn, "SELECT type FROM entities WHERE engagement_id=?", (eng,))]
        assert "endpoint" in ents and "collection" in ents, ents
        facts = db.rows(conn, "SELECT predicate, stage FROM facts WHERE engagement_id=?", (eng,))
        assert facts and all(f["stage"] == "observed" for f in facts)
        assert any(f["predicate"] == "session-format" for f in facts), "session pattern extracted"
        run = db.row(conn, "SELECT status, summary, finished_at FROM tool_runs WHERE id=?", (rid,))
        assert run["status"] == "done" and run["finished_at"], dict(run)
        conn.close()
        print(f"  executor: OK — POST->parse->persist, endpoint+collection nodes, "
              f"session-format fact@observed, run finalized ({summary})")
    finally:
        srv.shutdown()


def main():
    failed = 0
    for t in [test_executor_against_stub]:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {e!r}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — ai-chat executor")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
