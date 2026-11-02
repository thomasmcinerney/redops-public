"""Extraction from synthetic report.py evidence, with no live target activity."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from casehub import CaseHub, CaseHubError
from casehub.extract import extract_event, main


KIT = Path(__file__).resolve().parents[2]
REPORT = KIT / "report.py"
REAL_CASE = Path("/tmp/claude-1000/-home-lain-Documents-Codex-2026-10-26-do-x20-outputs/"
                 "1facdea4-c3f1-45b8-a6b4-9f3150c820b4/scratchpad/cases/db6b")
BAD_IDENTITIES = {"again\\n", "bak\\n", "created.\\n", "exit\\n", "passwd\\n",
                  "proof.txt\\n", "local\\through", "local\\without", "local\\usage",
                  "local\\authentication"}
BAD_HOSTS = {"sys.argv", "urllib.parse", "response.read", "u.username", "login.defs",
             "directories.jbrofuzz", "u.info", "user.info"}
GOOD_HOSTS = {"192.168.220.219", "access.redhat.com", "github.com", "nmap.org",
              "firefart.at"}
GOOD_IDENTITIES = {"local\\root", "local\\www-data", "local\\firefart"}


def report(*args: object) -> None:
    process = subprocess.run([sys.executable, str(REPORT), *(str(arg) for arg in args)],
                             text=True, capture_output=True, check=False)
    if process.returncode:
        raise AssertionError(f"report.py failed: {process.stdout}{process.stderr}")


class ExtractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_dir = tempfile.TemporaryDirectory(prefix="casehub-extract-fixture-")
        cls.fixture = Path(cls.fixture_dir.name) / "case"
        report("init", cls.fixture, "--title", "Synthetic extractor case", "--report_id", "RPT-TEST",
             "--scope", "Synthetic local fixtures only")
        report("target", cls.fixture, "--id", "demo", "--name", "Demo", "--ip", "192.0.2.10",
             "--role", "traditional", "--objective", "Test saved evidence extraction",
             "--summary", "Synthetic target", "--unscored")
        report("stage", cls.fixture, "--target", "demo", "--kind", "recon",
             "--summary", "Synthetic inputs")
        scan = ("Nmap scan report for scan.example.com (192.0.2.10)\n"
                "PORT STATE SERVICE VERSION\n"
                "22/tcp open ssh OpenSSH 9.2p1\n"
                "443/tcp open https nginx 1.24.0\n")
        report("run", cls.fixture, "--target", "demo", "--stage", "recon", "--",
             sys.executable, "-c", f"print({scan!r}, end='')")
        report("log", cls.fixture, "--target", "demo", "--stage", "recon", "--kind", "browser",
             "--text", "Visited https://app.example.com/admin/login?token=private\n"
                       "<title>Demo Portal</title>\nServer: nginx/1.24.0")
        report("log", cls.fixture, "--target", "demo", "--stage", "recon", "--kind", "note",
             "--text", "Password for alice:\nalice@workstation:~$\nCORP\\bob\n"
                       "Read /etc/hosts and C:\\Windows\\System32\\drivers\\etc\\hosts")
        noise = ("directory-list-2.3-medium.txt\napache-user-enum-1.0.txt\ncheck.php\n"
                 "db.png\ncowroot.sh\nhta.zip\nbox\n::\n0.0.0.0\n"
                 "user: again\nlogin: bak\nexit:\nid:\npasswd:\nproof.txt:\ncreated.:\n"
                 "-rw-r--r-- 1 user user 12 Oct 29 10:00 archive.example.com\n"
                 "Read /etc/passwd\nRead /etc/passwd\n")
        report("log", cls.fixture, "--target", "demo", "--stage", "recon", "--kind", "note",
             "--text", noise)
        positive = ("valid.example.com\nroot@node.example.com:/home/root$\n"
                    "CORP\\bob\nuid=1000(charlie)\nPassword for dana:\nPassword for ivan\n"
                    "/home/erin/notes\nlogin as frank\nsu grace\nssh -u heidi\n"
                    "192.0.2.44:8443\nhttps://portal.example.com:9443/status\n"
                    "Host: 192.0.2.45 Ports: 22/open/tcp//ssh///, "
                    "443/open/tcp//https///, 8080\n")
        report("log", cls.fixture, "--target", "demo", "--stage", "recon", "--kind", "note",
             "--text", positive)
        events = json.loads((cls.fixture / "case.json").read_text(encoding="utf-8"))["events"]
        cls.scan_event = next(e["id"] for e in events if e["kind"] == "command")
        cls.browser_event = next(e["id"] for e in events if e["kind"] == "browser")
        cls.prompt_event = next(e["id"] for e in events if e["kind"] == "note")
        cls.noise_event, cls.positive_event = [e["id"] for e in events if e["kind"] == "note"][1:]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_dir.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="casehub-extract-")
        self.case = Path(self.temp.name) / "case"
        shutil.copytree(self.fixture, self.case)
        self.hub = CaseHub(self.case, actor="extract-test")
        self.hub.sync_evidence()

    def tearDown(self) -> None:
        self.hub.close()
        self.temp.cleanup()

    def run_extract(self, **kwargs: object) -> str:
        args = Namespace(event=kwargs.get("event", []), target=kwargs.get("target"),
                         dry_run=kwargs.get("dry_run", False),
                         min_confidence=kwargs.get("min_confidence", 0.5))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(self.hub, args), 0)
        return output.getvalue()

    def test_scanner_proposals_have_exact_spans_and_proposed_level(self) -> None:
        event = self.hub.evidence(self.scan_event, with_body=True)
        proposals = extract_event(self.hub, event, event["body"])
        services = [p for p in proposals if p["type"] == "service"]
        self.assertEqual({p["key"] for p in services},
                         {"192.0.2.10|tcp|22", "192.0.2.10|tcp|443"})
        self.assertEqual(next(p for p in services if p["attrs"]["port"] == 443)["attrs"],
                         {"host": "192.0.2.10", "proto": "tcp", "port": 443,
                          "state": "open", "service": "https", "product": "nginx",
                          "version": "1.24.0"})
        self.assertTrue(any(p["type"] == "host" and p["key"] == "192.0.2.10"
                            for p in proposals))
        self.assertEqual(len({(p["type"], p["key"]) for p in proposals}), len(proposals))
        for proposal in proposals:
            span = proposal["source_span"]
            self.assertEqual(proposal["source_events"], [self.scan_event])
            self.assertEqual(proposal["level"], "proposed")
            self.assertIn("@", proposal["extractor"])
            self.assertGreaterEqual(proposal["confidence"], 0)
            self.assertLessEqual(proposal["confidence"], 1)
            self.assertEqual(span["line"], event["body"].count("\n", 0, span["start"]) + 1)
            self.assertTrue(event["body"][span["start"]:span["end"]])

    def test_recorded_entities_edges_and_rerun_idempotency(self) -> None:
        self.run_extract(event=[self.scan_event])
        services = self.hub.entities(type="service")
        self.assertEqual(len(services), 2)
        self.assertTrue(all(s["target"] == "demo" and s["level"] == "proposed"
                            for s in services))
        host = next(h for h in self.hub.entities(type="host") if h["key"] == "192.0.2.10")
        edges = self.hub.neighbors(host["id"])
        self.assertEqual(len(edges), 2)
        self.assertTrue(all(e["relation"] == "runs_on" and e["status"] == "inferred"
                            and e["source_events"] == [self.scan_event] for e in edges))
        self.assertEqual(self.hub.entity(services[0]["id"])["observations"][0]["source_events"],
                         [self.scan_event])
        service_records = [r for r in self.hub.records(kind="entity")
                           if r["payload"]["type"] == "service"]
        self.assertTrue(all(r["idempotency_key"] ==
                            f"extract:scanner@1:{self.scan_event}:service:{r['payload']['key']}"
                            and r["actor"] == "extract-test" for r in service_records))
        before = len(self.hub.records())
        self.run_extract(event=[self.scan_event])
        self.assertEqual(len(self.hub.records()), before)
        self.assertEqual(len(self.hub.neighbors(host["id"])), 2)

    def test_prior_epoch_reextract_is_noop(self) -> None:
        self.run_extract(event=[self.scan_event])
        self.hub.start_epoch("Synthetic reset")
        before = len(self.hub.records())
        self.run_extract(event=[self.scan_event])
        self.assertEqual(len(self.hub.records()), before)
        self.assertEqual(self.hub.entities(epoch_id="epoch_2"), [])

    def test_browser_url_title_and_prompt_usernames(self) -> None:
        self.run_extract(event=[self.browser_event, self.prompt_event])
        app = next(a for a in self.hub.entities(type="application")
                   if a["key"] == "https://app.example.com")
        self.assertEqual(app["attrs"]["title"], "Demo Portal")
        self.assertEqual(app["attrs"]["server"], "nginx/1.24.0")
        self.assertEqual(app["target"], "demo")
        self.assertTrue(any(f["key"] == "https://app.example.com/admin/login"
                            for f in self.hub.entities(type="file")))
        self.assertTrue(any(h["key"] == "app.example.com" for h in self.hub.entities(type="host")))
        self.assertEqual({i["key"] for i in self.hub.entities(type="identity")},
                         {"workstation\\alice", "corp\\bob"})
        files = {f["key"] for f in self.hub.entities(type="file")}
        self.assertIn("/etc/hosts", files)
        self.assertIn(r"c:\windows\system32\drivers\etc\hosts", files)
        self.assertNotIn("private", json.dumps(self.hub.entities()))

    def test_dry_run_prints_proposals_without_records(self) -> None:
        output = self.run_extract(event=[self.scan_event], dry_run=True)
        lines = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
        self.assertTrue(any("entity" in line and line["entity"]["type"] == "service"
                            for line in lines))
        self.assertTrue(any("edge" in line and line["edge"]["relation"] == "runs_on"
                            for line in lines))
        self.assertEqual(self.hub.entities(), [])
        self.assertEqual(self.hub.records(kind="entity"), [])

    def test_target_filter_and_unknown_event(self) -> None:
        self.run_extract(event=[self.scan_event], target="other")
        self.assertEqual(self.hub.entities(), [])
        with self.assertRaisesRegex(CaseHubError, "Unknown evidence event ID"):
            self.run_extract(event=["evt_missing"])

    def test_ipv6_and_standalone_cli(self) -> None:
        fake = {"id": self.prompt_event, "target": "demo"}
        body = "Host: [2001:db8::1]\n2001:db8::2\n"
        proposals = extract_event(self.hub, fake, body)
        self.assertEqual({p["key"] for p in proposals if p["type"] == "host"},
                         {"2001:db8::1", "2001:db8::2"})
        run = subprocess.run([sys.executable, "-m", "casehub.extract", str(self.case),
                              "--actor", "cli-test", "--event", self.scan_event, "--dry-run"],
                             cwd=KIT, text=True, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('"type": "service"', run.stdout)
        integrated = subprocess.run([sys.executable, "-m", "casehub", str(self.case),
                                     "--actor", "cli-test", "extract", "--event",
                                     self.scan_event, "--dry-run"],
                                    cwd=KIT, text=True, capture_output=True)
        self.assertEqual(integrated.returncode, 0, integrated.stderr)
        self.assertIn('"type": "service"', integrated.stdout)
        self.assertEqual(self.hub.entities(), [])

    def test_false_positive_samples_are_not_recorded(self) -> None:
        self.run_extract(event=[self.noise_event])
        hosts = {h["key"] for h in self.hub.entities(type="host")}
        self.assertFalse(hosts & {"directory-list-2.3-medium.txt", "apache-user-enum-1.0.txt",
                                  "check.php", "db.png", "cowroot.sh", "hta.zip", "box",
                                  "::", "0.0.0.0", "archive.example.com"})
        self.assertEqual(self.hub.entities(type="identity"), [])
        files = [f["key"] for f in self.hub.entities(type="file")]
        self.assertEqual(files.count("/etc/passwd"), 1)
        self.assertFalse(any("\n" in key for key in files))

    def test_real_identity_and_service_patterns_and_confidence_filter(self) -> None:
        event = self.hub.evidence(self.positive_event, with_body=True)
        proposals = extract_event(self.hub, event, event["body"])
        flag_user = next(p for p in proposals if p["key"] == "local\\heidi")
        self.assertGreaterEqual(flag_user["confidence"], 0.5)
        self.assertTrue(all(p["key"] == p["key"].strip() and p["label"] == p["label"].strip()
                            for p in proposals))
        self.run_extract(event=[self.positive_event])
        identities = {i["key"] for i in self.hub.entities(type="identity")}
        self.assertTrue({"node.example.com\\root", "corp\\bob", "local\\charlie",
                         "local\\erin", "local\\frank", "local\\grace", "local\\heidi"}
                        <= identities)
        self.assertFalse({"local\\dana", "local\\ivan"} & identities)
        hosts = {h["key"] for h in self.hub.entities(type="host")}
        self.assertTrue({"valid.example.com", "node.example.com", "192.0.2.44",
                         "192.0.2.45"} <= hosts)
        services = {s["key"] for s in self.hub.entities(type="service")}
        self.assertTrue({"192.0.2.44|tcp|8443", "portal.example.com|tcp|9443",
                         "192.0.2.45|tcp|22",
                         "192.0.2.45|tcp|443", "192.0.2.45|tcp|8080"} <= services)
        high = subprocess.run([sys.executable, "-m", "casehub.extract", str(self.case),
                               "--event", self.positive_event, "--min-confidence", "0.99",
                               "--dry-run"], cwd=KIT, text=True, capture_output=True)
        self.assertEqual(high.returncode, 0, high.stderr)
        self.assertNotIn('"entity"', high.stdout)

    def test_precision_regression_inline_evidence(self) -> None:
        body = (
            "import urllib.parse\nif len(sys.argv) != 2:\nresponse.read()\n"
            "u.username\nlogin.defs\ndirectories.jbrofuzz\n"
            "u.user_id, u.group_id, u.info, u.home_dir\nuser.info = 'pwned'\n"
            "printf 'cat /etc/passwd\\n'\nprintf 'exit\\n'\n"
            "printf 'cat /root/proof.txt\\n'\n"
            "again\\n bak\\n created.\\n passwd\\n proof.txt\\n\n"
            "su through\nsu without\nsu usage\nsu authentication\nsu at all\n"
            "through:\nwithout:\nusage:\nauthentication:\nagain:\nexit:\nid:\n"
            "bak:\ncreated:\nPassword for alice:\ngobuster -u http://192.168.220.219/\n"
            "local\\through local\\without local\\usage local\\authentication\n"
            "Host: 192.168.220.219\naccess.redhat.com github.com nmap.org firefart.at\n"
            "Nmap scan report for 192.168.220.219\n80/tcp open http Apache\n"
            "uid=0(root) uid=33(www-data) uid=0(firefart)\n"
            "CORP\\bob corp.example.com\\charlie\n"
            "login as: dave\nsudo -u erin\nsu frank\n/home/grace/notes\n"
            "henry@box.local:~$\n"
            "method.com() other.com.attribute\n"
        )
        event = {"id": self.positive_event, "target": "demo"}
        proposals = extract_event(self.hub, event, body)
        by_type = {kind: {p["key"] for p in proposals if p["type"] == kind}
                   for kind in ("host", "identity", "service", "file")}
        self.assertFalse(by_type["host"] & BAD_HOSTS)
        self.assertFalse(by_type["identity"] & BAD_IDENTITIES)
        self.assertFalse({"local\\through", "local\\without", "local\\usage",
                          "local\\authentication", "local\\alice", "local\\at",
                          "local\\http"} & by_type["identity"])
        self.assertTrue(GOOD_HOSTS <= by_type["host"])
        self.assertTrue(GOOD_IDENTITIES <= by_type["identity"])
        self.assertTrue({"corp\\bob", "corp.example.com\\charlie", "local\\dave",
                         "local\\erin", "local\\frank", "local\\grace",
                         "box.local\\henry"} <= by_type["identity"])
        self.assertIn("192.168.220.219|tcp|80", by_type["service"])
        self.assertIn("/etc/passwd", by_type["file"])
        self.assertNotIn("/etc/passwd\\n", by_type["file"])
        self.assertFalse({"method.com", "other.com"} & by_type["host"])
        for proposal in proposals:
            self.assertEqual(proposal["key"], proposal["key"].strip())
            self.assertEqual(proposal["label"], proposal["label"].strip())
            if proposal["type"] in {"host", "identity"}:
                self.assertFalse(any(c.isspace() for c in proposal["key"] + proposal["label"]))
        exception_keys = {p["key"] for p in extract_event(
            self.hub, event, "uid=1(through)\nthrough@box.local:~$\n")
                          if p["type"] == "identity"}
        self.assertIn("local\\through", exception_keys)
        self.assertIn("box.local\\through", exception_keys)

    def test_literal_command_escapes_do_not_become_domain_users(self) -> None:
        body = (r'''sh -c 'printf "PORT STATE SERVICE VERSION\n80/tcp open http\n"' '''
                "\n" + r"VERSION\r3 VERSION\t4 CORP\1alice" + "\nCORP\\bob\n")
        event = {"id": self.positive_event, "target": "demo"}
        identities = {p["key"] for p in extract_event(self.hub, event, body)
                      if p["type"] == "identity"}
        self.assertEqual(identities, {"corp\\bob"})

    def test_single_label_user_at_host_has_identity_without_host(self) -> None:
        body = "alice@localhost\nbob@node\ncharlie@workstation:~$\n"
        event = {"id": self.positive_event, "target": "demo"}
        proposals = extract_event(self.hub, event, body)
        identities = {p["key"]: p for p in proposals if p["type"] == "identity"}
        self.assertEqual(set(identities), {"localhost\\alice", "node\\bob",
                                           "workstation\\charlie"})
        for key, realm, source in (("localhost\\alice", "localhost", "alice@localhost"),
                                   ("node\\bob", "node", "bob@node"),
                                   ("workstation\\charlie", "workstation",
                                    "charlie@workstation:~$")):
            proposal = identities[key]
            self.assertEqual(proposal["attrs"]["realm"], realm)
            span = proposal["source_span"]
            self.assertEqual(body[span["start"]:span["end"]], source)
        self.assertFalse({"localhost", "node"} &
                         {p["key"] for p in proposals if p["type"] == "host"})

    @unittest.skipUnless(REAL_CASE.is_dir(), "read-only real case fixture unavailable")
    def test_precision_regression_real_case_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casehub-real-extract-") as directory:
            case = Path(directory) / "db6b"
            shutil.copytree(REAL_CASE, case)
            for db_file in case.glob("casehub.db*"):
                db_file.unlink()
            result = subprocess.run(
                [sys.executable, "-m", "casehub", str(case), "--actor",
                 "extract-real-test", "extract"], cwd=KIT, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            with CaseHub(case, actor="extract-real-test") as hub:
                entities = hub.entities(limit=100000)
            by_type = {kind: {e["key"] for e in entities if e["type"] == kind}
                       for kind in ("host", "identity", "service", "file")}
            bad_identity_forms = BAD_IDENTITIES | {s.replace("\\n", "\n")
                                                   for s in BAD_IDENTITIES}
            self.assertFalse(by_type["identity"] & bad_identity_forms)
            self.assertFalse(by_type["host"] & BAD_HOSTS)
            self.assertFalse(by_type["file"] & {"/etc/passwd\\n", "/etc/passwd\n"})
            self.assertTrue(GOOD_HOSTS <= by_type["host"])
            self.assertTrue(GOOD_IDENTITIES <= by_type["identity"])
            self.assertIn("192.168.220.219|tcp|80", by_type["service"])
            for entity in entities:
                self.assertEqual(entity["key"], entity["key"].strip())
                self.assertEqual(entity["label"], entity["label"].strip())
                if entity["type"] in {"host", "identity"}:
                    self.assertFalse(any(c.isspace() for c in entity["key"] + entity["label"]))


if __name__ == "__main__":
    unittest.main()
