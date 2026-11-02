"""HTTP dashboard tests using a synthetic report.py case only."""

from __future__ import annotations

import hashlib
import io
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import urlopen

from PIL import Image

from casehub import CaseHub
from casehub.dashboard import _handler, create_server


KIT = Path(__file__).resolve().parents[2]
REPORT = KIT / "report.py"


def report(*args: object) -> None:
    result = subprocess.run([sys.executable, str(REPORT), *(str(arg) for arg in args)],
                            cwd=KIT, capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="casehub-dashboard-")
        cls.root = Path(cls.temp.name)
        cls.case = cls.root / "case"
        report("init", cls.case, "--title", "Dashboard fixture", "--report_id", "RPT-PRACTICE",
             "--scope", "Local synthetic fixture only")
        report("target", cls.case, "--id", "demo", "--name", "Demo", "--ip", "127.0.0.1",
             "--role", "traditional", "--objective", "Review saved evidence",
             "--summary", "Synthetic test", "--unscored")
        report("stage", cls.case, "--target", "demo", "--kind", "recon",
             "--summary", "Saved synthetic evidence")
        report("run", cls.case, "--target", "demo", "--stage", "recon", "--",
             "printf", "dashboardmarker 127.0.0.1 443/tcp open https\\n")
        response_file = cls.root / "response.txt"
        response_file.write_text("Synthetic response", encoding="utf-8")
        report("log", cls.case, "--target", "demo", "--stage", "recon", "--kind", "browser",
             "--text", "Viewed synthetic page", "--result", response_file)
        screenshot = cls.root / "screenshot.png"
        Image.new("RGB", (32, 32), (31, 94, 120)).save(screenshot)
        report("screenshot", cls.case, "--target", "demo", "--stage", "recon",
             "--file", screenshot, "--role", "evidence", "--caption", "Synthetic screenshot")
        events = json.loads((cls.case / "case.json").read_text(encoding="utf-8"))["events"]
        cls.command_id = next(e["id"] for e in events if e["kind"] == "command")
        cls.image_id = next(e["id"] for e in events if e["kind"] == "screenshot")
        cls.event_count = len(events)
        cls.fingerprint = hashlib.sha256(b"fixture-only-password").hexdigest()
        with CaseHub(cls.case, actor="dashboard-test") as hub:
            hub.sync_evidence()
            cls.host_id = hub.record_entity("host", "127.0.0.1", target="demo",
                                            level="observed", source_events=[cls.command_id],
                                            statement="Host in saved transcript")
            cls.secret_id = hub.record_entity("secret_ref", cls.fingerprint,
                                              label="Fixture credential",
                                              attrs={"fingerprint": cls.fingerprint}, target="demo")
            hub.propose_claim("Synthetic service visible", target="demo",
                              state="observed", supporting_events=[cls.command_id],
                              entity_ids=[cls.host_id])
            hub.create_task("Review synthetic evidence", target="demo")
            hub.heartbeat("Reviewing fixture")
        try:
            cls.server = create_server(cls.case, actor="dashboard-test", port=0)
        except PermissionError:
            cls.server = None
            cls.handler = type("MemoryHandler", (_handler(cls.case, "dashboard-test"),), {"wbufsize": 1})
            cls.base = "http://127.0.0.1"
        else:
            cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
            cls.thread.start()
            cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=3)
        cls.temp.cleanup()

    def fetch(self, path: str) -> tuple[bytes, str]:
        if self.server is None:
            class Capture(io.BytesIO):
                def close(self):
                    pass

            class Request:
                def __init__(self):
                    self.input = io.BytesIO(f"GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode())
                    self.output = Capture()

                def makefile(self, mode, *_args):
                    return self.input if mode == "rb" else self.output

            request = Request()
            self.handler(request, ("local", 0), SimpleNamespace())
            head, body = request.output.getvalue().split(b"\r\n\r\n", 1)
            lines = head.decode().split("\r\n")
            status = int(lines[0].split()[1])
            headers = dict(line.split(": ", 1) for line in lines[1:])
            if status >= 400:
                raise HTTPError(self.base + path, status, lines[0], headers, None)
            return body, headers["Content-Type"]
        with urlopen(self.base + path, timeout=3) as response:
            return response.read(), response.headers["Content-Type"]

    def get_json(self, path: str):
        body, content_type = self.fetch(path)
        self.assertIn("application/json", content_type)
        return json.loads(body)

    def test_page_has_four_tabs_and_local_assets(self) -> None:
        body, content_type = self.fetch("/")
        page = body.decode()
        self.assertIn("text/html", content_type)
        for tab in ("Mission", "Inventory", "Evidence", "Report"):
            self.assertIn(f">{tab}</button>", page)
        self.assertIn("/api/context", page)
        self.assertIn("5000", page)
        self.assertNotIn("https://", page)

    def test_all_json_endpoints_and_filters(self) -> None:
        context = self.get_json("/api/context")
        self.assertEqual(context["case"]["scope"], "Local synthetic fixture only")
        self.assertIn("demo", context["targets"])
        self.assertEqual(context["entity_counts"]["host"], 1)
        entities = self.get_json("/api/entities?type=host&target=demo")
        self.assertEqual([e["id"] for e in entities], [self.host_id])
        entity = self.get_json(f"/api/entity/{self.host_id}")
        self.assertEqual(entity["observations"][0]["statement"], "Host in saved transcript")
        self.assertIn("edges", entity)
        self.assertIn("claims", entity)
        timeline = self.get_json("/api/timeline?target=demo&stage=recon&kind=command&limit=1")
        self.assertEqual([e["id"] for e in timeline], [self.command_id])
        evidence = self.get_json(f"/api/evidence/{self.command_id}")
        self.assertIn("dashboardmarker", evidence["body"])
        self.assertEqual(evidence["payload"]["kind"], "command")
        search = self.get_json("/api/search?q=dashboardmarker")
        self.assertIn(self.command_id, [e["id"] for e in search["evidence"]])
        self.assertEqual(len(self.get_json("/api/claims")), 1)
        self.assertEqual(len(self.get_json("/api/tasks")), 1)
        report = self.get_json("/api/report")
        self.assertIn("errors", report)
        self.assertIn("demo", report["gates"])
        for state in ("build", "review", "package", "upload"):
            self.assertEqual(report[state]["state"], "missing")

    def test_secret_reference_is_masked_in_lists_search_and_detail(self) -> None:
        entities = self.get_json("/api/entities?type=secret_ref")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0]["label"], "Fixture credential")
        self.assertEqual(entities[0]["fingerprint_prefix"], self.fingerprint[:12])
        detail = self.get_json(f"/api/entity/{self.secret_id}")
        search = self.get_json("/api/search?q=Fixture")
        for item in (entities[0], detail, search["entities"][0]):
            self.assertNotIn("key", item)
            self.assertNotIn("attrs", item)
            self.assertNotIn(self.fingerprint, json.dumps(item))

    def test_screenshot_thumbnail_and_errors(self) -> None:
        body, content_type = self.fetch(f"/evidence-file/{self.image_id}")
        self.assertEqual(content_type, "image/png")
        self.assertTrue(body.startswith(b"\x89PNG"))
        for path, expected in (("/api/entity/missing", 404),
                               ("/api/evidence/missing", 404),
                               ("/evidence-file/" + self.command_id, 404),
                               ("/api/timeline?limit=0", 400)):
            with self.assertRaises(HTTPError) as error:
                self.fetch(path)
            self.assertEqual(error.exception.code, expected)

    def test_each_request_syncs_and_extracts_new_evidence(self) -> None:
        report("log", self.case, "--target", "demo", "--stage", "recon", "--kind", "note",
             "--text", "Observed https://auto-extract.example.com:9443/status")
        context = self.get_json("/api/context")
        self.assertEqual(context["case"]["events"], self.event_count + 1)
        self.assertEqual(context["entity_counts"]["host"], 2)
        with CaseHub(self.case, actor="dashboard-test") as hub:
            self.assertTrue(any(
                record["actor"] == "extractor"
                and record["payload"].get("type") == "host"
                and record["payload"].get("key") == "auto-extract.example.com"
                for record in hub.records(kind="entity")))
        timeline = self.get_json("/api/timeline?kind=note")
        self.assertEqual(len(timeline), 1)

    def test_extraction_failure_is_best_effort(self) -> None:
        report("log", self.case, "--target", "demo", "--stage", "recon", "--kind", "note",
             "--text", "Observed failure-path.example.com")
        from unittest.mock import patch
        with patch("casehub.extract.extract_events", side_effect=RuntimeError("synthetic failure")), \
                patch("sys.stderr", new_callable=io.StringIO) as stderr:
            context = self.get_json("/api/context")
        self.assertEqual(context["case"]["events"], self.event_count + 2)
        self.assertIn("automatic extraction failed: synthetic failure", stderr.getvalue())

    def test_standalone_module_starts(self) -> None:
        help_result = subprocess.run([sys.executable, "-m", "casehub.dashboard", "--help"],
                                     cwd=KIT, capture_output=True, text=True)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("--no-auto-extract", help_result.stdout)
        serve_help = subprocess.run(
            [sys.executable, "-m", "casehub", str(self.case), "serve", "--help"],
            cwd=KIT, capture_output=True, text=True)
        self.assertEqual(serve_help.returncode, 0, serve_help.stderr)
        self.assertIn("--no-auto-extract", serve_help.stdout)
        if self.server is None:
            return
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen([sys.executable, "-m", "casehub.dashboard", str(self.case),
                                    "--port", str(port)], cwd=KIT, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with urlopen(f"http://127.0.0.1:{port}/api/context", timeout=.3) as response:
                        self.assertEqual(response.status, 200)
                    break
                except OSError:
                    time.sleep(.05)
            else:
                self.fail(f"standalone dashboard failed: {process.poll()}")
        finally:
            process.terminate()
            process.communicate(timeout=3)

    def test_rejects_non_loopback_bind(self) -> None:
        with self.assertRaisesRegex(ValueError, "127.0.0.1"):
            create_server(self.case, host="0.0.0.0", port=0)


if __name__ == "__main__":
    unittest.main()
