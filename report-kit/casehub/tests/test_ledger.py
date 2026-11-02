"""Synthetic report.py case fixtures for the CaseHub ledger and CLI."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from casehub import CaseHub, CaseHubError


KIT = Path(__file__).resolve().parents[2]
REPORT = KIT / "report.py"
PROJECTIONS = ("epochs", "entities", "observations", "edges", "claims", "tasks",
               "handoffs", "heartbeats", "leases", "decisions")


def report(*args: object) -> str:
    process = subprocess.run([sys.executable, str(REPORT), *(str(arg) for arg in args)],
                             text=True, capture_output=True, check=False)
    if process.returncode:
        raise AssertionError(f"report.py failed ({process.returncode}): {process.stdout}{process.stderr}")
    return process.stdout


class LedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_dir = tempfile.TemporaryDirectory(prefix="casehub-fixture-")
        cls.fixture = Path(cls.fixture_dir.name) / "case"
        report("init", cls.fixture, "--title", "Synthetic CaseHub test", "--report_id", "RPT-PRACTICE",
             "--scope", "Local synthetic fixture only")
        report("target", cls.fixture, "--id", "demo", "--name", "Demo", "--ip", "127.0.0.1",
             "--role", "traditional", "--objective", "Test correlation",
             "--summary", "Synthetic fixture", "--unscored")
        report("stage", cls.fixture, "--target", "demo", "--kind", "recon",
             "--summary", "Synthetic saved transcript")
        report("run", cls.fixture, "--target", "demo", "--stage", "recon", "--",
             "printf", "casehubscanmarker 127.0.0.1 443/tcp open https\\n")
        report("log", cls.fixture, "--target", "demo", "--stage", "recon", "--kind", "browser",
             "--text", "Synthetic browser viewed http://127.0.0.1/")
        events = json.loads((cls.fixture / "case.json").read_text(encoding="utf-8"))["events"]
        cls.command_event = next(e["id"] for e in events if e["kind"] == "command")
        cls.browser_event = next(e["id"] for e in events if e["kind"] == "browser")
        cls.event_count = len(events)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_dir.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="casehub-ledger-")
        self.case = Path(self.temp.name) / "case"
        shutil.copytree(self.fixture, self.case)
        self.hub = CaseHub(self.case, actor="alice")

    def tearDown(self) -> None:
        self.hub.close()
        self.temp.cleanup()

    def host(self, **kwargs: object) -> str:
        return self.hub.record_entity("host", "127.0.0.1", target="demo", **kwargs)

    def test_sync_idempotency_and_new_event(self) -> None:
        self.assertEqual(self.hub.sync_evidence(), self.event_count)
        self.assertEqual(self.hub.sync_evidence(), 0)
        report("log", self.case, "--target", "demo", "--stage", "recon", "--kind", "note",
             "--text", "new synthetic evidence")
        self.assertEqual(self.hub.sync_evidence(), 1)
        self.assertEqual(self.hub.sync_evidence(), 0)

    def test_sync_prunes_removed_evidence_and_fts(self) -> None:
        self.assertEqual(self.hub.sync_evidence(), self.event_count)
        self.assertIsNotNone(self.hub.evidence(self.browser_event))
        case_file = self.case / "case.json"
        data = json.loads(case_file.read_text(encoding="utf-8"))
        data["events"] = [e for e in data["events"] if e["id"] != self.browser_event]
        case_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

        self.assertEqual(self.hub.sync_evidence(), 1)
        self.assertIsNone(self.hub.evidence(self.browser_event))
        self.assertFalse(any(e["id"] == self.browser_event for e in self.hub.timeline()))
        self.assertEqual(self.hub.db.execute(
            "SELECT COUNT(*) FROM evidence_fts WHERE id=?", (self.browser_event,)
        ).fetchone()[0], 0)
        self.assertEqual(self.hub.sync_evidence(), 0)

        data["events"] = []
        case_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(self.hub.sync_evidence(), self.event_count - 1)
        self.assertEqual(self.hub.db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)
        self.assertEqual(self.hub.db.execute("SELECT COUNT(*) FROM evidence_fts").fetchone()[0], 0)

    def test_entity_upsert_merges_attrs_and_preserves_level(self) -> None:
        entity_id = self.host(attrs={"address": "127.0.0.1"}, level="observed",
                              source_events=[self.command_event], statement="Host shown in scan")
        self.assertEqual(entity_id, self.host(attrs={"role": "fixture"}, level="proposed"))
        entity = self.hub.entity(entity_id)
        self.assertEqual(entity["attrs"], {"address": "127.0.0.1", "role": "fixture"})
        self.assertEqual(entity["level"], "observed")
        self.assertEqual(entity["source_events"], [self.command_event])
        self.assertEqual(len(entity["observations"]), 1)

    def test_observed_entity_requires_real_evidence(self) -> None:
        with self.assertRaisesRegex(CaseHubError, "must cite"):
            self.host(level="observed")
        with self.assertRaisesRegex(CaseHubError, "Unknown evidence event"):
            self.host(level="observed", source_events=["evt_missing"])
        self.assertEqual(self.hub.entities(), [])

    def test_secret_reference_stores_only_label_and_fingerprint(self) -> None:
        digest = hashlib.sha256(b"synthetic-only-secret").hexdigest()
        with self.assertRaisesRegex(CaseHubError, "fingerprint only"):
            self.hub.record_entity("secret_ref", "synthetic-only-secret", label="fixture secret",
                                   attrs={"fingerprint": digest, "password": "synthetic-only-secret"})
        secret = self.hub.record_entity("secret_ref", digest, label="fixture secret",
                                        attrs={"fingerprint": digest})
        entity = self.hub.entity(secret)
        self.assertEqual(entity["key"], digest)
        self.assertEqual(entity["label"], "fixture secret")
        self.assertEqual(entity["attrs"], {"fingerprint": digest})

    def test_edge_requires_existing_entities_and_evidence(self) -> None:
        host = self.host()
        with self.assertRaisesRegex(CaseHubError, "Unknown entity"):
            self.hub.add_edge(host, "ent_missing", "runs_on", source_events=[self.command_event])
        service = self.hub.record_entity("service", "127.0.0.1|tcp|443")
        with self.assertRaisesRegex(CaseHubError, "must cite"):
            self.hub.add_edge(service, host, "runs_on")
        self.hub.add_edge(service, host, "runs_on", source_events=[self.command_event])
        self.assertEqual(self.hub.neighbors(host)[0]["source_events"], [self.command_event])

    def test_claim_review_requires_independent_actor(self) -> None:
        with self.assertRaisesRegex(CaseHubError, "requires claim_review"):
            self.hub.propose_claim("Service is reachable", state="verified")
        claim = self.hub.propose_claim("Service is reachable", state="observed", target="demo",
                                       supporting_events=[self.command_event])
        with self.assertRaisesRegex(CaseHubError, "cross-review"):
            self.hub.review_claim(claim, "verified", "Checked the scan")
        self.hub.review_claim(claim, "verified", "Independent review of saved scan", actor="bob")
        reviewed = next(c for c in self.hub.claims() if c["id"] == claim)
        self.assertEqual((reviewed["state"], reviewed["reviewer"]), ("verified", "bob"))

    def test_claims_conflict_on_contrary_evidence(self) -> None:
        first = self.hub.propose_claim("Service open", target="demo",
                                       supporting_events=[self.command_event])
        second = self.hub.propose_claim("Service closed", target="demo",
                                        supporting_events=[self.browser_event],
                                        contrary_events=[self.command_event])
        claims = {c["id"]: c for c in self.hub.claims()}
        self.assertEqual(claims[first]["conflicts_with"], [second])
        self.assertEqual(claims[second]["conflicts_with"], [first])

    def test_task_lifecycle_and_structured_result(self) -> None:
        task = self.hub.create_task("Review saved scan", target="demo")
        self.assertEqual(self.hub.task(task)["state"], "queued")
        self.hub.claim_task(task)
        self.assertEqual(self.hub.task(task)["owner"], "alice")
        self.hub.update_task(task, checkpoint="Found port 443", evidence=[self.command_event])
        self.assertEqual(self.hub.task(task)["state"], "running")
        self.assertEqual(self.hub.task(task)["checkpoints"][1]["evidence"], [self.command_event])
        with self.assertRaisesRegex(CaseHubError, "structured result"):
            self.hub.update_task(task, state="done")
        result = {"summary": "Reviewed scan", "evidence": [self.command_event]}
        self.hub.update_task(task, state="done", result=result)
        self.assertEqual(self.hub.task(task)["result"], result)

    def test_lease_blocks_other_actor_until_expiry(self) -> None:
        self.hub.acquire_lease("synthetic-browser", ttl_seconds=300)
        with self.assertRaisesRegex(CaseHubError, "leased by alice"):
            self.hub.acquire_lease("synthetic-browser", actor="bob")
        self.hub.acquire_lease("synthetic-browser", ttl_seconds=-1, actor="alice")
        self.assertTrue(self.hub.leases()[0]["expired"])
        self.assertEqual(self.hub.acquire_lease("synthetic-browser", actor="bob")["owner"], "bob")

    def test_handoff_packet_validation_and_ack(self) -> None:
        with self.assertRaisesRegex(CaseHubError, "Handoff packet is missing"):
            self.hub.write_handoff({"objective": "Review scan"}, to_actor="bob")
        packet = {"objective": "Review scan", "verified_facts": [], "open_sessions": [],
                  "failed_avenues": [], "next_action": "Inspect transcript"}
        handoff = self.hub.write_handoff(packet, to_actor="bob")
        self.assertEqual(self.hub.handoffs(to_actor="bob", unacknowledged_only=True)[0]["packet"], packet)
        self.hub.acknowledge_handoff(handoff, actor="bob")
        self.assertEqual(self.hub.handoffs(unacknowledged_only=True), [])

    def test_epoch_marks_prior_entities_stale(self) -> None:
        old_id = self.host(level="observed", source_events=[self.command_event])
        epoch = self.hub.start_epoch("Synthetic reset", label="second launch")
        self.assertEqual(epoch, "epoch_2")
        self.assertEqual(self.hub.entity(old_id)["applicability"], "stale")
        new_id = self.host(level="observed", source_events=[self.browser_event])
        self.assertNotEqual(old_id, new_id)
        self.assertEqual(self.hub.entity(new_id)["applicability"], "current")

    def test_rebuild_reproduces_identical_projections(self) -> None:
        host = self.host(level="observed", source_events=[self.command_event],
                         statement="Host in transcript")
        service = self.hub.record_entity("service", "127.0.0.1|tcp|443", target="demo")
        self.hub.add_edge(service, host, "runs_on", source_events=[self.command_event])
        claim = self.hub.propose_claim("Service found", target="demo",
                                       supporting_events=[self.command_event])
        self.hub.review_claim(claim, "verified", "Independent check", actor="bob")
        task = self.hub.create_task("Document scan")
        self.hub.update_task(task, checkpoint="Reviewed", evidence=[self.command_event])
        self.hub.heartbeat("Working")
        self.hub.acquire_lease("review", ttl_seconds=300)
        self.hub.write_handoff({"objective": "Review", "verified_facts": [], "open_sessions": [],
                                "failed_avenues": [], "next_action": "Continue"}, to_actor="bob")
        self.hub.ask_decision("Continue review?")
        self.hub.start_epoch("Synthetic reset")
        before = self.projection_dump()
        record_count = len(self.hub.records())
        self.assertEqual(self.hub.rebuild(), record_count)
        self.assertEqual(self.projection_dump(), before)

    def projection_dump(self) -> dict:
        return {table: sorted((dict(row) for row in self.hub.db.execute(f"SELECT * FROM {table}")),
                              key=lambda row: json.dumps(row, sort_keys=True)) for table in PROJECTIONS}

    def test_fts_finds_transcript_content(self) -> None:
        self.hub.sync_evidence()
        hits = self.hub.search("casehubscanmarker")["evidence"]
        self.assertIn(self.command_event, [hit["id"] for hit in hits])

    def test_cli_status_and_one_line_error(self) -> None:
        command = [sys.executable, "-m", "casehub", str(self.case), "--actor", "cli-test", "status"]
        good = subprocess.run(command, cwd=KIT, text=True, capture_output=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        for expected in ("Targets:", "Stages done:", "Proof:", "Live tasks:", "Inventory:"):
            self.assertIn(expected, good.stdout)
        bad = subprocess.run([sys.executable, "-m", "casehub", str(Path(self.temp.name) / "missing"), "status"],
                             cwd=KIT, text=True, capture_output=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(len(bad.stderr.strip().splitlines()), 1)

    def test_cli_status_uses_report_case(self) -> None:
        env = os.environ.copy()
        env["REPORT_CASE"] = str(self.case)
        result = subprocess.run([sys.executable, "-m", "casehub", "status"],
                                cwd=KIT, env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Case: Synthetic CaseHub test", result.stdout)


if __name__ == "__main__":
    unittest.main()
