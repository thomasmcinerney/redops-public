"""Local, network-free smoke tests for the detached Grok supervisor."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


RUNNER = Path(__file__).with_name("runner.py")


def wait_done(state_dir: Path) -> dict:
    path = state_dir / "state.json"
    for _ in range(100):
        if path.exists():
            state = json.loads(path.read_text())
            if state.get("status") in {"completed", "failed", "stopped"}:
                return state
        time.sleep(0.1)
    raise AssertionError("supervisor did not finish within ten seconds")


class RunnerTest(unittest.TestCase):
    def test_stop_terminates_active_child_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "fake-grok"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import time\n"
                "print('ready', flush=True)\n"
                "time.sleep(60)\n"
            )
            fake.chmod(0o755)
            prompt = root / "prompt.txt"
            prompt.write_text("bounded stop test\n")
            state_dir = root / "state"
            launch = subprocess.run(
                [sys.executable, str(RUNNER), "start", "--state-dir", str(state_dir),
                 "--prompt-file", str(prompt), "--session-id", str(uuid.uuid4()),
                 "--cwd", str(root), "--grok-bin", str(fake),
                 "--max-restarts", "0"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(launch.returncode, 0, launch.stderr)
            stopped = subprocess.run(
                [sys.executable, str(RUNNER), "stop", "--state-dir", str(state_dir)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(stopped.returncode, 0, stopped.stderr)
            state = wait_done(state_dir)
            self.assertEqual(state["status"], "stopped")
            self.assertLess(state["attempts"][0]["exit_code"], 0)

    def test_start_and_resume_preserve_prompts_and_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_dir = root / "state"
            case_dir = root / "case"
            case_dir.mkdir()
            (case_dir / "case.json").write_text(json.dumps({
                "schema": 1, "targets": {}, "stages": [], "events": [], "review": None,
            }))
            fake = root / "fake-grok"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "args=sys.argv[1:]\n"
                "prompt=pathlib.Path(args[args.index('--prompt-file')+1]).read_text()\n"
                "mode='resume' if '--resume' in args else 'start'\n"
                "print(json.dumps({'type':'result','mode':mode,'prompt':prompt}), flush=True)\n"
            )
            fake.chmod(0o755)
            session = str(uuid.uuid4())
            for mode, content in (("start", "first exact prompt\n"),
                                  ("resume", "second exact prompt\n")):
                prompt = root / f"{mode}.txt"
                prompt.write_text(content)
                started = subprocess.run(
                    [sys.executable, str(RUNNER), mode, "--state-dir", str(state_dir),
                     "--prompt-file", str(prompt), "--session-id", session,
                     "--cwd", str(root), "--grok-bin", str(fake),
                     "--report-case", str(case_dir),
                     "--max-restarts", "0"],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(started.returncode, 0, started.stderr)
                state = wait_done(state_dir)
                self.assertEqual(state["status"], "completed")
                self.assertEqual(state["session_id"], session)
                self.assertEqual(Path(state["prompt_path"]).read_text(), content)
                run_dir = Path(state["run_dir"])
                self.assertEqual(json.loads((run_dir / "final_state.json").read_text())["status"],
                                 "completed")
                self.assertGreater(len((run_dir / "heartbeat.jsonl").read_text().splitlines()), 1)
                attempt = state["attempts"][0]
                output = json.loads(Path(attempt["stdout_path"]).read_text())
                self.assertEqual(output, {"type": "result", "mode": mode, "prompt": content})
                events = json.loads((case_dir / "case.json").read_text())["events"]
                self.assertEqual(len(events), 1 if mode == "start" else 2)
                self.assertEqual(events[-1]["text"], content)
                self.assertEqual(events[-1]["result"], Path(attempt["stdout_path"]).read_text())
                self.assertEqual(events[-1]["target"], None)
                self.assertEqual(events[-1]["stage"], None)
                self.assertEqual(attempt["report_event_id"], events[-1]["id"])
                self.assertNotIn("casehub_sync_error", attempt)
                self.assertIn("--resume" if mode == "resume" else "--session-id",
                              attempt["command"])
                self.assertNotIn("MCPTool(redops__engagement_add)", attempt["command"])
                self.assertEqual(attempt["stderr_bytes"], 0)

    def test_abnormal_exit_automatically_resumes_same_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "fake-grok"
            marker = root / "first-exit"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "import sys\n"
                f"marker=Path({str(marker)!r})\n"
                "if not marker.exists():\n"
                "    marker.write_text('1')\n"
                "    print('interrupted', flush=True)\n"
                "    sys.exit(2)\n"
                "print('resumed', flush=True)\n"
            )
            fake.chmod(0o755)
            prompt = root / "prompt.txt"
            prompt.write_text("scope supplied at runtime\n")
            session = str(uuid.uuid4())
            state_dir = root / "state"
            started = subprocess.run(
                [sys.executable, str(RUNNER), "start", "--state-dir", str(state_dir),
                 "--prompt-file", str(prompt), "--session-id", session,
                 "--cwd", str(root), "--grok-bin", str(fake),
                 "--max-restarts", "1"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(started.returncode, 0, started.stderr)
            state = wait_done(state_dir)
            self.assertEqual(state["status"], "completed")
            self.assertEqual([a["exit_code"] for a in state["attempts"]], [2, 0])
            self.assertIn("--resume", state["attempts"][1]["command"])
            self.assertEqual(state["attempts"][1]["mode"], "resume")
            self.assertIn("scope supplied at runtime",
                          Path(state["attempts"][1]["prompt_path"]).read_text())


if __name__ == "__main__":
    unittest.main()
