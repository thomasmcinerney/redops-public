"""Practice graded actions and local captures stay honest in the REPORT ledger."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

import report


class PracticeObjectivesTest(unittest.TestCase):
    def test_graded_action_has_full_narrative_without_fake_flag_or_stage_screenshots(self):
        # Another integration fixture replaces report.validate globally; load an
        # isolated copy so this test checks the real report gate in any order.
        spec = importlib.util.spec_from_file_location("report_practice_fresh", report.__file__)
        fresh = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fresh)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transcript = root / "local.txt"
            transcript.write_text("complete local diagnostic output\n", encoding="utf-8")
            case = {
                "title": "Practice case", "report_id": "RPT-PRACTICE", "scope": "one assigned target",
                "gates_required": True, "review": None,
                "targets": {"web": {
                    "name": "web", "ip": "192.0.2.10", "role": "web",
                    "objective": "Portal graded action", "summary": "Testing in progress",
                    "required_stages": ["recon"], "scored": False, "proof": None,
                    "report": {field: "Observed evidence is pending." for field in report.REPORT_FIELDS},
                }},
                "stages": [{"target": "web", "kind": "recon", "summary": "HTTP observed",
                            "analysis": "The service responded."}],
                "events": [
                    {"id": "E1", "at": "2026-10-30T00:00:00Z", "actor": "agent",
                     "target": "web", "stage": "recon", "kind": "note",
                     "text": "HTTP responded"},
                    {"id": "L1", "at": "2026-10-30T00:00:01Z", "actor": "agent",
                     "target": None, "stage": None, "kind": "command",
                     "command": "echo local", "status": "done", "exit_code": 0,
                     "transcript": "local.txt", "sha256": report.digest(transcript),
                     "source_key": "redops:7:42",
                     "provenance_note": "Local diagnostic, no target contact."},
                ],
                "practice_objectives": [{"task": 1, "portal_task_id": "123",
                                         "description": "Portal graded action.",
                                         "target_ids": ["web"],
                                         "proof_type": "graded_action",
                                         "status": "pending", "evidence_ids": []}],
            }
            self.assertEqual(fresh.validate(root, case), [])
            html = report.render_html(root, case, output_chars=0)
            self.assertIn("Portal graded action.", html)
            self.assertIn("Unattributed / local operations", html)
            self.assertIn("complete local diagnostic output", html)
            self.assertIn("redops:7:42", html)
            self.assertNotIn("Proof file</h3>", html)
            case["practice_objectives"][0]["status"] = "verified"
            self.assertIn("verified status needs a cited direct Portal acceptance screenshot",
                          "\n".join(fresh.validate(root, case)))


if __name__ == "__main__":
    unittest.main()
