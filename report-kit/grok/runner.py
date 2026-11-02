#!/usr/bin/env python3
"""Supervise a headless Grok session without routing the CLI through RedOps.

Grok's target tools still come from the project RedOps MCP configuration. This
runner only starts the local CLI and records its exact inputs, output, and life
cycle. It has no target network or RedOps control-plane access.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def atomic_json(path: Path, value: dict) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def record_state(state_path: Path, run_dir: Path, state: dict) -> None:
    """Keep a current snapshot and an append-only supervisor heartbeat trail."""
    atomic_json(state_path, state)
    entry = {key: state.get(key) for key in
             ("run_id", "status", "heartbeat_at", "last_output_at", "child_pid",
              "stdout_bytes", "stderr_bytes", "exit_code")}
    entry["recorded_at"] = now()
    with (run_dir / "heartbeat.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")
    if state.get("status") in {"completed", "failed", "stopped"}:
        atomic_json(run_dir / "final_state.json", state)


def alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def command(spec: dict, prompt: Path, resume: bool) -> list[str]:
    argv = [spec["grok_bin"], "--trust", "--cwd", spec["cwd"]]
    argv += ["--resume" if resume else "--session-id", spec["session_id"]]
    argv += ["--prompt-file", str(prompt), "--tools", "", "--disable-web-search",
             "--no-subagents", "--permission-mode", "dontAsk"]
    argv += ["--allow", "MCPTool(redops__*)"]
    for rule in ("MCPTool(casehub__*)",
                 "Bash", "WebFetch", "WebSearch"):
        argv += ["--deny", rule]
    argv += ["--max-turns", str(spec["max_turns"]), "--output-format", spec["output_format"]]
    return argv


def log_report_attempt(spec: dict, item: dict) -> str | None:
    """Optionally file exact CLI interaction bytes in a local REPORT case.

    The raw files remain authoritative if the JSON ledger cannot represent a
    non-UTF-8 byte. A source key makes retries idempotent.
    """
    if not spec.get("report_case"):
        return None
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import report  # imported only for opt-in local report recording
    from casehub import CaseHub

    root = Path(spec["report_case"])
    source_key = f"grok:{spec['session_id']}:{spec['run_id']}:{item['number']}"
    prompt = Path(item["prompt_path"]).read_bytes()
    stdout = Path(item["stdout_path"]).read_bytes()
    stderr = Path(item["stderr_path"]).read_bytes()
    with report.case_lock(root):
        case = report.load(root)
        for event in case["events"]:
            if event.get("source_key") == source_key:
                eid = event["id"]
                break
        else:
            eid = report.add_event(root, case, {
                "target": None, "stage": None, "kind": "query",
                "text": prompt.decode("utf-8", "replace"),
                "result": stdout.decode("utf-8", "replace"),
                "stderr": stderr.decode("utf-8", "replace"),
                "source_key": source_key,
                "runner": {
                    "run_id": spec["run_id"], "attempt": item["number"],
                    "session_id": spec["session_id"], "exit_code": item["exit_code"],
                    "prompt_path": item["prompt_path"],
                    "stdout_path": item["stdout_path"],
                    "stderr_path": item["stderr_path"],
                    "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                },
            }, actor="grok-cli-runner")
    try:
        with CaseHub(root, actor="grok-cli-runner") as hub:
            hub.sync_evidence()
    except Exception as exc:
        item["casehub_sync_error"] = str(exc)
    return eid


def monitor(spec_path: Path) -> int:
    spec = read_json(spec_path)
    state_path = Path(spec["state_dir"]) / "state.json"
    run_dir = Path(spec["run_dir"])
    stopping = False
    child: subprocess.Popen[bytes] | None = None

    def request_stop(_sig: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    state = {
        "run_id": spec["run_id"], "session_id": spec["session_id"],
        "mode": spec["mode"], "status": "starting", "started_at": now(),
        "heartbeat_at": now(), "heartbeat_source": "supervisor_process_poll",
        "grok_checkins": "RedOps MCP log/sitrep; not inferred from heartbeat",
        "supervisor_pid": os.getpid(), "state_dir": spec["state_dir"],
        "run_dir": spec["run_dir"], "prompt_path": spec["prompt_path"],
        "prompt_sha256": spec["prompt_sha256"], "attempts": [],
    }
    record_state(state_path, run_dir, state)
    original_prompt = Path(spec["prompt_path"])
    for attempt in range(spec["max_restarts"] + 1):
        if stopping:
            break
        resume = spec["mode"] == "resume" or attempt > 0
        prompt = original_prompt
        if attempt:
            prompt = run_dir / f"resume-{attempt:02d}.txt"
            prompt.write_text(
                "The Grok CLI process was interrupted. Continue the SAME authorized "
                "session and runtime scope. Check session history and RedOps captured "
                "runs before any action; do not repeat a completed target command or "
                "claim success from an interrupted command. Complete a short phase and "
                "report exact evidence.\n\n" + original_prompt.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            prompt.chmod(0o600)
        stdout_path = run_dir / f"attempt-{attempt:02d}.stdout"
        stderr_path = run_dir / f"attempt-{attempt:02d}.stderr"
        argv = command(spec, prompt, resume)
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            try:
                child = subprocess.Popen(argv, cwd=spec["cwd"], stdin=subprocess.DEVNULL,
                                         stdout=stdout, stderr=stderr, start_new_session=True)
            except OSError as exc:
                stderr.write(f"runner launch error: {exc}\n".encode())
                state.update(status="failed", error=str(exc), finished_at=now())
                record_state(state_path, run_dir, state)
                return 1
            item = {
                "number": attempt, "mode": "resume" if resume else "start",
                "command": argv, "prompt_path": str(prompt),
                "stdout_path": str(stdout_path), "stderr_path": str(stderr_path),
                "child_pid": child.pid, "started_at": now(),
            }
            state["attempts"].append(item)
            state.update(status="running", child_pid=child.pid, heartbeat_at=now())
            record_state(state_path, run_dir, state)
            previous_sizes = (0, 0)
            while child.poll() is None:
                if stopping:
                    request_stop(signal.SIGTERM, None)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                sizes = (stdout_path.stat().st_size, stderr_path.stat().st_size)
                if sizes != previous_sizes:
                    state["last_output_at"] = now()
                    previous_sizes = sizes
                state.update(heartbeat_at=now(), stdout_bytes=sizes[0],
                             stderr_bytes=sizes[1])
                record_state(state_path, run_dir, state)
                time.sleep(2)
            item.update(exit_code=child.returncode, finished_at=now(),
                        stdout_bytes=stdout_path.stat().st_size,
                        stderr_bytes=stderr_path.stat().st_size)
            try:
                report_id = log_report_attempt(spec, item)
                if report_id:
                    item["report_event_id"] = report_id
            except Exception as exc:
                item["report_log_error"] = str(exc)
            state.update(heartbeat_at=now(), child_pid=None,
                         stdout_bytes=item["stdout_bytes"], stderr_bytes=item["stderr_bytes"])
            record_state(state_path, run_dir, state)
            if stopping:
                state.update(status="stopped", finished_at=now(), exit_code=child.returncode)
                record_state(state_path, run_dir, state)
                return 0
            if child.returncode == 0:
                state.update(status="completed", finished_at=now(), exit_code=0,
                             result_scope="CLI process only; engagement outcome is separate")
                record_state(state_path, run_dir, state)
                return 0
    state.update(status="failed", finished_at=now(),
                 exit_code=state["attempts"][-1]["exit_code"] if state["attempts"] else None)
    record_state(state_path, run_dir, state)
    return 1


def launch(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir).expanduser().resolve()
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    with (state_dir / "launch.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = read_json(state_dir / "state.json")
        if previous.get("status") in {"starting", "running"} and alive(previous.get("supervisor_pid")):
            raise SystemExit(f"runner already active: PID {previous['supervisor_pid']}")
        cwd = Path(args.cwd).expanduser().resolve()
        source = Path(args.prompt_file).expanduser().resolve()
        if not source.is_file():
            raise SystemExit(f"prompt file not found: {source}")
        grok_bin = shutil.which(args.grok_bin)
        if not grok_bin:
            raise SystemExit(f"Grok binary not found: {args.grok_bin}")
        session_id = str(uuid.UUID(args.session_id))
        run_id = str(uuid.uuid4())
        run_dir = state_dir / "runs" / run_id
        run_dir.mkdir(parents=True, mode=0o700)
        prompt_path = run_dir / "prompt.txt"
        shutil.copyfile(source, prompt_path)
        prompt_path.chmod(0o600)
        spec = {
            "run_id": run_id, "session_id": session_id, "mode": args.action,
            "state_dir": str(state_dir), "run_dir": str(run_dir),
            "cwd": str(cwd), "grok_bin": grok_bin,
            "prompt_path": str(prompt_path),
            "prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
            "max_turns": args.max_turns, "max_restarts": args.max_restarts,
            "output_format": args.output_format,
            "report_case": str(Path(args.report_case).expanduser().resolve())
                         if args.report_case else None,
        }
        spec_path = run_dir / "spec.json"
        atomic_json(spec_path, spec)
        spec_path.chmod(0o600)
        with (run_dir / "monitor.log").open("ab") as log:
            supervisor = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "_monitor", str(spec_path)],
                cwd=cwd, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True, close_fds=True,
            )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            current = read_json(state_dir / "state.json")
            if current.get("run_id") == run_id:
                print(json.dumps(current, indent=2))
                return 0
            if supervisor.poll() is not None:
                break
            time.sleep(0.1)
        raise SystemExit(f"supervisor did not start; see {run_dir / 'monitor.log'}")


def status(args: argparse.Namespace) -> int:
    state = read_json(Path(args.state_dir).expanduser().resolve() / "state.json")
    if not state:
        raise SystemExit("no runner state found")
    if state.get("status") in {"starting", "running"} and not alive(state.get("supervisor_pid")):
        state["effective_status"] = "supervisor_missing"
    print(json.dumps(state, indent=2))
    return 0


def stop(args: argparse.Namespace) -> int:
    state = read_json(Path(args.state_dir).expanduser().resolve() / "state.json")
    pid = state.get("supervisor_pid")
    if state.get("status") not in {"starting", "running"} or not alive(pid):
        print("runner is not active")
        return 0
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    if "runner.py _monitor" not in cmdline or state["state_dir"] not in cmdline:
        raise SystemExit(f"PID {pid} is not this runner monitor")
    os.kill(pid, signal.SIGTERM)
    print(f"stop requested for supervisor PID {pid}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("start", "resume"):
        p = sub.add_parser(name, help=f"launch a detached Grok {name} process")
        p.add_argument("--state-dir", required=True)
        p.add_argument("--prompt-file", required=True)
        p.add_argument("--session-id", required=True)
        p.add_argument("--cwd", default=str(Path(__file__).parent))
        p.add_argument("--grok-bin", default="grok")
        p.add_argument("--report-case", help="optional local REPORT case for exact AI interaction logging")
        p.add_argument("--max-turns", type=int, default=8)
        p.add_argument("--max-restarts", type=int, default=1)
        p.add_argument("--output-format", choices=("plain", "json", "streaming-json"),
                       default="streaming-json")
        p.set_defaults(func=launch)
    for name in ("status", "checkin", "stop"):
        p = sub.add_parser(name)
        p.add_argument("--state-dir", required=True)
        p.set_defaults(func=stop if name == "stop" else status)
    p = sub.add_parser("_monitor", help=argparse.SUPPRESS)
    p.add_argument("spec_path")
    p.set_defaults(func=lambda args: monitor(Path(args.spec_path)))
    args = parser.parse_args()
    if args.action in {"start", "resume"} and (args.max_turns < 1 or args.max_restarts < 0):
        parser.error("max-turns must be positive and max-restarts cannot be negative")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
