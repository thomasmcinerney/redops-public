"""Web chatbot scope and evidence import gates."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from redops import webscope


class WebScopeTest(unittest.TestCase):
    def test_exact_page_and_path_bounded_api(self):
        scope = webscope.normalize_scope(
            ["https://chat.example.test/help"],
            ["https://messages.example.test/v1/conversations"])
        self.assertTrue(webscope.page_allowed("https://chat.example.test/help", scope))
        self.assertFalse(webscope.page_allowed("https://chat.example.test/admin", scope))
        self.assertFalse(webscope.page_allowed("https://other.example.test/help", scope))
        self.assertTrue(webscope.api_allowed(
            "https://messages.example.test/v1/conversations/1", scope))
        self.assertFalse(webscope.api_allowed(
            "https://messages.example.test/v1/conversations-other", scope))
        self.assertFalse(webscope.api_allowed(
            "https://messages.example.test/v1/conversations/%2e%2e/admin", scope))
        self.assertFalse(webscope.api_allowed("http://messages.example.test/v1/conversations", scope))


class WebCaptureApiTest(unittest.TestCase):
    def test_scoped_idempotent_capture(self):
        from unittest.mock import patch
        from fastapi.testclient import TestClient
        from redops import api, db

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (patch.object(db, "DATA_DIR", root),
                  patch.object(db, "DB_PATH", root / "redops.db"),
                  patch.object(db, "EVIDENCE_DIR", root / "evidence"),
                  patch.object(db, "TRANSCRIPT_DIR", root / "transcript")):
                db.init_db()
                with TestClient(api.app) as client:
                    response = client.post("/api/engagements", json={
                        "name": "Synthetic chatbot",
                        "scope": "https://chat.example.test/help"})
                    self.assertEqual(response.status_code, 201, response.text)
                    eid = response.json()["id"]
                    web = client.get(f"/api/scope/{eid}").json()["web"]
                    self.assertEqual(web["pages"], ["https://chat.example.test/help"])
                    payload = {"engagement_id": eid,
                               "page_url": "https://chat.example.test/help",
                               "source_id": "run:001",
                               "action": {"type": "message", "input": "hello"},
                               "output": "hi", "network": [], "artifact_hashes": {}}
                    first = client.post("/api/webchat/capture", json=payload)
                    self.assertEqual(first.status_code, 201, first.text)
                    second = client.post("/api/webchat/capture", json=payload)
                    self.assertEqual(second.json()["id"], first.json()["id"])
                    changed = dict(payload, output="changed")
                    self.assertEqual(client.post("/api/webchat/capture", json=changed).status_code, 409)
                    outside = dict(payload, source_id="run:002",
                                   page_url="https://chat.example.test/admin")
                    self.assertEqual(client.post("/api/webchat/capture", json=outside).status_code, 403)
                    direct = dict(payload, source_id="run:003",
                                  action={"type": "api", "url": "https://chat.example.test/admin"})
                    self.assertEqual(client.post("/api/webchat/capture", json=direct).status_code, 403)


class ReportImportTest(unittest.TestCase):
    def test_idempotent_import_rejects_changed_capture(self):
        root = Path(__file__).resolve().parent.parent / "report-kit"
        sys.path.insert(0, str(root))
        import report
        from webchat_import import import_run

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            case = base / "case"
            for args in [
                ["init", str(case), "--title", "Chat assessment", "--scope", "Synthetic widget"],
                ["target", str(case), "--id", "chat", "--name", "Chatbot",
                 "--ip", "https://chat.example.test/help", "--role", "web-chat",
                 "--objective", "Assess data boundary", "--summary", "Synthetic",
                 "--unscored"],
                ["stage", str(case), "--target", "chat", "--kind", "recon",
                 "--summary", "Observed chat", "--analysis", "Synthetic response"],
            ]:
                run = subprocess.run([sys.executable, str(root / "report.py"), *args],
                                     capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
            capture = base / "capture"
            (capture / "network").mkdir(parents=True)
            (capture / "screenshots").mkdir()
            (capture / "network" / "001.jsonl").write_text(
                '{"type":"response","body_b64":"aGk="}\n')
            from PIL import Image
            Image.new("RGB", (80, 40), "white").save(capture / "screenshots" / "001.png")
            manifest = {
                "schema": "redops-webchat-v1", "run_id": "synthetic",
                "page_url": "https://chat.example.test/help",
                "events": [{
                    "id": "001", "type": "message", "input": "hello",
                    "output": "hi", "network_path": "network/001.jsonl",
                    "screenshot_path": "screenshots/001.png",
                }],
            }
            path = capture / "manifest.json"
            path.write_text(json.dumps(manifest))
            first = import_run(case, "chat", "recon", path)
            second = import_run(case, "chat", "recon", path)
            self.assertEqual(first, second)
            data = report.load(case)
            self.assertEqual(len(data["events"]), 2)
            self.assertEqual(data["events"][0]["result"], "hi")
            manifest["events"][0]["output"] = "changed"
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "changed reimport"):
                import_run(case, "chat", "recon", path)


if __name__ == "__main__":
    unittest.main()
