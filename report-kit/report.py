#!/usr/bin/env python3
"""Fail-closed evidence capture and PDF packaging for authorized REPORT practice."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


STAGE_KINDS = ("recon", "validation", "exploit", "foothold", "privilege", "pivot", "proof", "submission")
DEFAULT_STAGES = ("recon", "validation", "exploit", "proof")
SCREEN_ROLES = ("evidence", "proof_file", "proof_value", "control_panel", "accepted")
REPORT_FIELDS = ("entry_point", "vulnerability", "attack_path", "impact", "reproduction")
SCORED_DISPOSITIONS = ("solved", "attempted_unsolved")
MAX_ARCHIVE = 100 * 1024 * 1024


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def data_path(root: Path) -> Path:
    return root / "case.json"


def report_stem(data: dict) -> str:
    if re.fullmatch(r"RPT-\d+", data["report_id"]):
        return f"REPORT-{data['report_id']}-Assessment-Report"
    slug = re.sub(r"[^A-Za-z0-9]+", "-", data["title"]).strip("-")[:48]
    return f"REPORT-PRACTICE-{slug}-Report"


def load(root: Path) -> dict:
    try:
        data = json.loads(data_path(root).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"No case at {root}; run init first")
    if data.get("schema") != 1:
        raise SystemExit("Unsupported case schema")
    return data


def save(root: Path, data: dict) -> None:
    root.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".case-", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, data_path(root))
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def case_lock(root: Path):
    """Exclusive lock for one short read-modify-write of case.json."""
    with (root / ".case.lock").open("a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


# These actions run a child process that may live for hours; they take the lock only
# around their own ledger writes so log/screenshot/proof can commit meanwhile.
SELF_LOCKING_ACTIONS = ("run", "tty")


def ident() -> str:
    return uuid.uuid4().hex[:12]


def text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def original_code_origin(value: str) -> bool:
    """Accept a specific original-script description as well as the short form."""
    return bool(re.match(r"(?i)^original(?:\b|$)", value.strip()))


def target(data: dict, tid: str) -> dict:
    if tid not in data["targets"]:
        raise SystemExit(f"Unknown target: {tid}")
    return data["targets"][tid]


def target_disposition(t: dict) -> str:
    """Old scored cases stay fail-closed until explicitly marked attempted."""
    return t.get("disposition") or ("solved" if t.get("scored", True) else "supporting")


def stage(data: dict, tid: str, kind: str) -> dict:
    target(data, tid)
    for item in data["stages"]:
        if item["target"] == tid and item["kind"] == kind:
            return item
    raise SystemExit(f"Missing {tid}/{kind} stage; add it before recording evidence")


def add_event(root: Path, data: dict, event: dict, keep_review: bool = False,
              actor: str | None = None) -> str:
    event["id"] = ident()
    event["at"] = now()
    event["actor"] = actor or os.environ.get("REPORT_ACTOR") or "operator"
    data["events"].append(event)
    if not keep_review:
        data["review"] = None
    save(root, data)
    return event["id"]


def start_command(root: Path, a: argparse.Namespace, command: str, cwd: Path) -> str:
    """Commit the intent to run before execution, holding the lock only for the write."""
    with case_lock(root):
        data = load(root)
        stage(data, a.target, a.stage)
        return add_event(root, data, {"target": a.target, "stage": a.stage, "kind": "command",
                                      "command": command, "cwd": str(cwd), "status": "running"},
                         actor=a.actor)


def finish_command(root: Path, eid: str, update: dict, render: bool) -> None:
    """Reload the ledger (other writers may have committed meanwhile) and close the event."""
    with case_lock(root):
        data = load(root)
        matches = [e for e in data["events"] if e["id"] == eid]
        if len(matches) != 1:
            raise SystemExit(f"Command event {eid} vanished from the ledger; transcript kept on disk")
        event = matches[0]
        event.update(update)
        data["review"] = None
        save(root, data)
        if render:
            capture_console(root, data, event)


def render_console_image(root: Path, command_event: dict) -> Path:
    """Render a view of the recorded command output as a labeled evidence image."""
    from PIL import Image, ImageDraw, ImageFont

    log = root / command_event["transcript"]
    output = clean_terminal(log.read_text(encoding="utf-8", errors="replace"))
    source_lines = [f"$ {command_event['command']}", *output.splitlines()]
    wrapped: list[str] = []
    for line in source_lines:
        wrapped.extend(textwrap.wrap(line, width=138, replace_whitespace=False,
                                     drop_whitespace=False) or [""])
    shown = wrapped[-72:]
    try:
        font = ImageFont.truetype("DejaVuSansMono.ttf", 16)
        small = ImageFont.truetype("DejaVuSansMono.ttf", 13)
    except OSError:
        font = ImageFont.load_default()
        small = font
    width = 1600
    line_height = 22
    height = max(360, 160 + line_height * len(shown))
    img = Image.new("RGB", (width, height), "#101820")
    draw = ImageDraw.Draw(img)
    draw.rectangle((0, 0, width, 100), fill="#1d2b35")
    draw.text((24, 17), "REPORT RECORDED CONSOLE CAPTURE", font=font, fill="#9ce4bc")
    draw.text((24, 46), f"Evidence {command_event['id']}  |  {command_event['at']}  |  exit {command_event.get('exit_code', '?')}",
              font=small, fill="#d8e7ee")
    draw.text((24, 70), "Rendered from the captured terminal transcript; full text is in the case source, SHA256 in the ledger.",
              font=small, fill="#c5d0d6")
    for i, line in enumerate(shown):
        draw.text((24, 120 + i * line_height), line, font=font, fill="#eaf3f6")
    path = root / "evidence" / f"{command_event['id']}-console.png"
    img.save(path)
    return path


def is_rendered_console_image(path: Path) -> bool:
    """Recognize this kit's generated console image even after it is copied."""
    from PIL import Image
    try:
        with Image.open(path) as img:
            if img.width != 1600 or img.height < 360:
                return False
            rgb = img.convert("RGB")
            return (rgb.getpixel((0, 0)) == (29, 43, 53) and
                    rgb.getpixel((1599, 50)) == (29, 43, 53) and
                    rgb.getpixel((0, 120)) == (16, 24, 32))
    except (OSError, ValueError):
        return False


def is_direct_capture(root: Path, event: dict,
                      rendered_hashes: set[str] | None = None) -> bool:
    if event.get("kind") != "screenshot" or event.get("provenance") != "direct_import":
        return False
    if rendered_hashes and event.get("sha256") in rendered_hashes:
        return False
    path = root / event.get("file", "")
    if not path.is_file() or digest(path) != event.get("sha256"):
        return False
    return not is_rendered_console_image(path)



def capture_console(root: Path, data: dict, command_event: dict) -> None:
    path = render_console_image(root, command_event)
    add_event(root, data, {"target": command_event["target"], "stage": command_event["stage"],
                           "kind": "screenshot", "role": "evidence", "provenance": "rendered_transcript",
                           "caption": f"Rendered from captured terminal transcript for command {command_event['id']}",
                           "file": str(path.relative_to(root)), "sha256": digest(path)},
              actor=command_event.get("actor"))


def do_refresh_rendered_screenshots(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    commands = {e["id"]: e for e in data["events"] if e["kind"] == "command"}
    count = 0
    for e in data["events"]:
        if e["kind"] != "screenshot" or e.get("provenance") != "rendered_transcript":
            continue
        command_id = Path(e["file"]).name.split("-console.png")[0]
        if command_id not in commands:
            raise SystemExit(f"Missing command for rendered screenshot {e['id']}")
        path = render_console_image(root, commands[command_id])
        if str(path.relative_to(root)) != e["file"]:
            raise SystemExit(f"Unexpected rendered screenshot path {e['file']}")
        e["sha256"] = digest(path)
        count += 1
    data["review"] = None
    save(root, data)
    print(f"Refreshed {count} rendered console images from unchanged transcripts")


def do_init(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    if root.exists() and any(root.iterdir()):
        raise SystemExit(f"Directory is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    for name in ("evidence", "transcripts", "code", "build"):
        (root / name).mkdir()
    data = {"schema": 1, "created": now(), "title": a.title, "report_id": a.report_id,
            "scope": a.scope, "targets": {}, "stages": [], "events": [], "review": None,
            "gates_required": True}
    save(root, data)
    print(f"Initialized {root}")


def do_target(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    if a.id in data["targets"]:
        raise SystemExit(f"Target already exists: {a.id}")
    selected = a.required_stages or ("recon" if a.unscored else ",".join(DEFAULT_STAGES))
    required = [s.strip() for s in selected.split(",") if s.strip()]
    if any(s not in STAGE_KINDS for s in required):
        raise SystemExit(f"Stages must be from: {', '.join(STAGE_KINDS)}")
    if not a.unscored:
        for s in DEFAULT_STAGES:
            if s not in required:
                raise SystemExit(f"Required stages must include {s}")
    data["targets"][a.id] = {"name": a.name, "ip": a.ip, "role": a.role,
                              "objective": a.objective, "summary": a.summary,
                              "required_stages": required, "scored": not a.unscored,
                              "disposition": "supporting" if a.unscored else "solved",
                              "proof": None, "report": {}}
    data["review"] = None
    save(root, data)
    print(f"Added target {a.id}")


def do_disposition(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    t = target(data, a.target)
    if not t.get("scored", True):
        raise SystemExit("Disposition applies only to assigned scored targets")
    note = a.note.strip()
    if not note:
        raise SystemExit("Disposition needs a nonempty observed-result note")
    if a.status == "attempted_unsolved" and (t.get("proof") or {}).get("value"):
        raise SystemExit("A target with captured proof cannot be marked attempted_unsolved")
    if a.status == "attempted_unsolved" and any(
            s["target"] == a.target and s["kind"] == "proof" for s in data["stages"]):
        raise SystemExit("A target with a proof stage cannot be marked attempted_unsolved")
    t["disposition"] = a.status
    t["disposition_note"] = note
    t["disposition_at"] = now()
    data["review"] = None
    save(root, data)
    print(f"Updated {a.target} disposition to {a.status}")


def do_summary(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    target(data, a.target)["summary"] = a.text
    data["review"] = None
    save(root, data)
    print(f"Updated {a.target} summary")


def do_narrative(a: argparse.Namespace) -> None:
    """Save the per-target technical narrative used at the front of the report."""
    root = Path(a.root).resolve()
    data = load(root)
    t = target(data, a.target)
    t["report"] = {field: getattr(a, field).strip() for field in REPORT_FIELDS}
    if any(not value for value in t["report"].values()):
        raise SystemExit("All narrative fields are required")
    data["review"] = None
    save(root, data)
    print(f"Updated {a.target} attack narrative")


def do_revise_stage(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    matches = [s for s in data["stages"] if s["target"] == a.target and s["kind"] == a.kind]
    if len(matches) != 1 or not a.summary.strip():
        raise SystemExit("Existing stage and non-empty summary required")
    matches[0]["summary"] = a.summary.strip()
    if a.analysis is not None:
        matches[0]["analysis"] = a.analysis.strip()
    data["review"] = None
    save(root, data)
    print(f"Updated {a.target}/{a.kind} stage")


def do_stage(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    t = target(data, a.target)
    if a.kind not in STAGE_KINDS:
        raise SystemExit("Invalid stage kind")
    if t.get("scored", True) and target_disposition(t) == "attempted_unsolved" and a.kind in ("proof", "submission"):
        raise SystemExit("Mark target solved before opening proof or submission")
    if any(s["target"] == a.target and s["kind"] == a.kind for s in data["stages"]):
        raise SystemExit("Stage already exists")
    required = [kind for kind in data["targets"][a.target]["required_stages"]
                if kind != "submission"]
    created = {s["kind"] for s in data["stages"] if s["target"] == a.target}
    if a.kind in required:
        expected = next((kind for kind in required if kind not in created), None)
        if a.kind != expected:
            raise SystemExit(f"Cannot skip a required stage; next is {expected}")
    previous = [s for s in data["stages"] if s["target"] == a.target
                and s["kind"] != "submission"]
    if previous:
        last = previous[-1]["kind"]
        events = [e for e in data["events"] if e["target"] == a.target and e["stage"] == last]
        if not any(e["kind"] in ("command", "query", "note", "browser", "code") for e in events):
            raise SystemExit(f"Cannot advance: {a.target}/{last} needs text evidence")
        if (data["targets"][a.target].get("scored", True) and
                not any(e["kind"] == "screenshot" and is_direct_capture(root, e)
                        for e in events)):
            raise SystemExit(f"Cannot advance: {a.target}/{last} needs a direct screenshot")
        if last == "proof":
            proof = data["targets"][a.target].get("proof")
            if not proof or not proof.get("value"):
                raise SystemExit(f"Cannot advance: {a.target} needs proof path and contents")
            if not any(e.get("role") in ("proof_file", "proof_value")
                       and is_direct_capture(root, e) for e in events):
                raise SystemExit(f"Cannot advance: {a.target} needs a proof-value screenshot")
    data["stages"].append({"target": a.target, "kind": a.kind,
                           "summary": a.summary.strip(), "analysis": (a.analysis or "").strip()})
    data["review"] = None
    save(root, data)
    print(f"Added {a.target}/{a.kind}")


def do_run(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    argv = a.command
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        raise SystemExit("Supply a command after --")
    cwd = Path(a.cwd).resolve() if a.cwd else Path.cwd()
    if not cwd.is_dir():
        raise SystemExit(f"Working directory does not exist: {cwd}")
    eid = start_command(root, a, " ".join(shlex_quote(x) for x in argv), cwd)
    log = root / "transcripts" / f"{eid}.txt"
    try:
        with log.open("wb") as output:
            proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            assert proc.stdout is not None
            for chunk in iter(lambda: proc.stdout.read(4096), b""):
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                output.write(chunk)
            code = proc.wait()
    except BaseException as exc:
        update = {"status": "interrupted", "error": repr(exc)}
        if log.exists():
            update.update(transcript=str(log.relative_to(root)), sha256=digest(log))
        finish_command(root, eid, update, render=False)
        raise
    finish_command(root, eid, {"status": "done", "exit_code": code,
                               "transcript": str(log.relative_to(root)), "sha256": digest(log)},
                   render=True)
    print(f"\n[REPORT evidence {eid}: exit {code}]", file=sys.stderr)
    if code:
        raise SystemExit(code)


def do_tty(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    cwd = Path(a.cwd).resolve() if a.cwd else Path.cwd()
    if not cwd.is_dir():
        raise SystemExit(f"Working directory does not exist: {cwd}")
    eid = start_command(root, a, f"interactive session: {a.command}", cwd)
    log = root / "transcripts" / f"{eid}.tty.txt"
    try:
        code = subprocess.run(["script", "-q", "-f", "-e", "-c", a.command, str(log)],
                              cwd=cwd, check=False).returncode
    except BaseException as exc:
        update = {"status": "interrupted", "error": repr(exc)}
        if log.exists():
            update.update(transcript=str(log.relative_to(root)), sha256=digest(log))
        finish_command(root, eid, update, render=False)
        raise
    finish_command(root, eid, {"status": "done", "exit_code": code,
                               "transcript": str(log.relative_to(root)), "sha256": digest(log)},
                   render=True)
    print(f"\n[REPORT interactive evidence {eid}: exit {code}]", file=sys.stderr)
    if code:
        raise SystemExit(code)


def do_resolve_interrupted(a: argparse.Namespace) -> None:
    """Document an interrupted recording without inventing a child exit code."""
    root = Path(a.root).resolve()
    data = load(root)
    matches = [e for e in data["events"] if e["id"] == a.id]
    if len(matches) != 1 or matches[0].get("kind") != "command" or matches[0].get("status") != "interrupted":
        raise SystemExit("ID must identify one interrupted command")
    if not a.reason.strip():
        raise SystemExit("A concrete interruption reason is required")
    matches[0]["resolution"] = a.reason.strip()
    data["review"] = None
    save(root, data)
    print(f"Reviewed interrupted command {a.id}")


def shlex_quote(value: str) -> str:
    import shlex
    return shlex.quote(value)


def do_log(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    stage(data, a.target, a.stage)
    body = Path(a.text_file).read_text(encoding="utf-8") if a.text_file else a.text
    if not body or not body.strip():
        raise SystemExit("Log text is required")
    result = Path(a.result_file).read_text(encoding="utf-8") if a.result_file else ""
    eid = add_event(root, data, {"target": a.target, "stage": a.stage, "kind": a.kind,
                                 "text": body, "result": result}, actor=a.actor)
    print(f"Recorded {a.kind} {eid}")


def copy_evidence(root: Path, source: Path, subdir: str) -> tuple[str, str]:
    if not source.is_file():
        raise SystemExit(f"File does not exist: {source}")
    dest = root / subdir / f"{ident()}{source.suffix.lower()}"
    shutil.copy2(source, dest)
    return str(dest.relative_to(root)), digest(dest)


def do_screenshot(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    stage(data, a.target, a.stage)
    source = Path(a.file).resolve()
    if source.suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp"):
        raise SystemExit("Screenshot must be PNG, JPEG, or WebP")
    from PIL import Image
    with Image.open(source) as img:
        img.verify()
    if is_rendered_console_image(source):
        raise SystemExit("Generated REPORT console image cannot be imported as a direct screenshot")
    path, sha = copy_evidence(root, source, "evidence")
    eid = add_event(root, data, {"target": a.target, "stage": a.stage, "kind": "screenshot",
                                 "role": a.role, "provenance": "direct_import", "caption": a.caption,
                                 "file": path, "sha256": sha}, actor=a.actor)
    print(f"Recorded screenshot {eid}")


def do_drop_duplicate_screenshot(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    matches = [e for e in data["events"] if e["id"] == a.id]
    if len(matches) != 1 or matches[0]["kind"] != "screenshot":
        raise SystemExit("Screenshot event ID not found")
    item = matches[0]
    if not any(e["id"] != a.id and e["kind"] == "screenshot"
               and e["sha256"] == item["sha256"] for e in data["events"]):
        raise SystemExit("Only duplicate screenshots may be removed")
    data["events"].remove(item)
    data["review"] = None
    save(root, data)
    print(f"Removed duplicate screenshot event {a.id}; source image remains on disk")


def do_code(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    stage(data, a.target, a.stage)
    if not original_code_origin(a.origin) and not a.changes.strip():
        raise SystemExit("Describe all modifications to an existing script, or state 'none'")
    source = Path(a.file).resolve()
    path, sha = copy_evidence(root, source, "code")
    eid = add_event(root, data, {"target": a.target, "stage": a.stage, "kind": "code",
                                 "origin": a.origin, "changes": a.changes, "file": path,
                                 "filename": source.name, "sha256": sha}, actor=a.actor)
    print(f"Recorded code {eid}")


def do_proof(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    t = target(data, a.target)
    if t.get("scored", True) and target_disposition(t) == "attempted_unsolved":
        raise SystemExit("Mark target solved before recording proof")
    stage(data, a.target, "proof")
    value = Path(a.value_file).read_text(encoding="utf-8").strip() if a.value_file else sys.stdin.read().strip()
    if not value:
        raise SystemExit("Proof value is empty")
    t["proof"] = {"path": a.path, "value": value, "recorded": now()}
    data["review"] = None
    save(root, data)
    print(f"Recorded proof for {a.target}; capture a direct screenshot showing the original proof value")


def do_ready_submit(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    t = target(data, a.target)
    stage(data, a.target, "proof")

    def block(reason: str) -> None:
        # A blocked readiness check is itself evidence of the gate running.
        add_event(root, data, {"target": a.target, "stage": "proof", "kind": "gate",
                               "gate": "proof_documented", "result": "blocked", "reason": reason,
                               "checked_visual": bool(a.checked_visual)}, actor=a.actor)
        raise SystemExit(f"BLOCKED: {reason}")

    if not t.get("proof") or not t["proof"].get("value"):
        block("proof path and value are missing")
    if not a.checked_visual:
        block("visually confirm the direct proof screenshot shows the exact value, then use --checked-visual")
    screenshots: list[dict] = []
    matches = [e for e in data["events"] if e["target"] == a.target
               and e["stage"] == "proof" and e["kind"] == "screenshot"
               and e["role"] in ("proof_file", "proof_value") and is_direct_capture(root, e)]
    if not matches:
        block("direct proof-value screenshot is missing")
    for e in matches:
        file = root / e["file"]
        if not file.is_file() or digest(file) != e["sha256"]:
            block(f"{e['role']} screenshot file is missing or changed")
        screenshots.append({"id": e["id"], "role": e["role"], "sha256": e["sha256"]})
    eid = add_event(root, data, {"target": a.target, "stage": "proof", "kind": "gate",
                                 "gate": "proof_documented", "result": "ready", "checked_visual": True,
                                 "proof_path": t["proof"]["path"],
                                 "proof_sha256": text_sha256(t["proof"]["value"]),
                                 "screenshots": screenshots}, actor=a.actor)
    print(f"PROOF DOCUMENTED: {a.target} has original proof text and direct screenshot "
          f"(optional review event {eid})")


def validate_practice_objectives(root: Path, data: dict) -> list[str]:
    """Validate optional Portal tasks without treating a pending grade as proof."""
    errors: list[str] = []
    objectives = data.get("practice_objectives", [])
    if not isinstance(objectives, list):
        return ["Practice objectives must be a list"]
    events = {e.get("id"): e for e in data.get("events", []) if isinstance(e, dict)}
    seen_tasks: set[int] = set()
    seen_portal_ids: set[str] = set()
    for item in objectives:
        if not isinstance(item, dict):
            errors.append("Practice objective entry must be an object")
            continue
        task = item.get("task")
        portal_id = str(item.get("portal_task_id") or "")
        prefix = f"Portal task {task}"
        if not isinstance(task, int) or isinstance(task, bool) or task < 1 or task in seen_tasks:
            errors.append(f"{prefix}: task number is missing or repeated")
        else:
            seen_tasks.add(task)
        if not portal_id or portal_id in seen_portal_ids:
            errors.append(f"{prefix}: Portal task ID is missing or repeated")
        seen_portal_ids.add(portal_id)
        if not str(item.get("description") or "").strip():
            errors.append(f"{prefix}: description is missing")
        if item.get("proof_type") not in ("graded_action", "proof_file"):
            errors.append(f"{prefix}: proof type must be graded_action or proof_file")
        if item.get("status") not in ("pending", "in_progress", "verified"):
            errors.append(f"{prefix}: status must be pending, in_progress, or verified")
        targets = item.get("target_ids")
        if not isinstance(targets, list) or not targets or any(t not in data["targets"] for t in targets):
            errors.append(f"{prefix}: target mapping is missing or unknown")
            targets = []
        refs = item.get("evidence_ids")
        if not isinstance(refs, list) or any(ref not in events for ref in refs):
            errors.append(f"{prefix}: evidence references are missing or unknown")
            refs = []
        if any(events[ref].get("target") not in targets for ref in refs):
            errors.append(f"{prefix}: cited evidence belongs to another target")
        if item.get("status") == "in_progress" and not refs:
            errors.append(f"{prefix}: in-progress status needs captured evidence")
        if item.get("status") == "verified":
            accepted = [events[ref] for ref in refs if ref in events and
                        events[ref].get("kind") == "screenshot" and
                        events[ref].get("role") == "accepted" and
                        events[ref].get("target") in targets and
                        is_direct_capture(root, events[ref])]
            if not accepted:
                errors.append(f"{prefix}: verified status needs a cited direct Portal acceptance screenshot")
            if item.get("proof_type") == "proof_file" and not any(
                    (data["targets"][tid].get("proof") or {}).get("path") and
                    (data["targets"][tid].get("proof") or {}).get("value")
                    for tid in targets):
                errors.append(f"{prefix}: verified flag needs recorded proof path and value")
    return errors


def validate(root: Path, data: dict, require_report_id: bool = False) -> list[str]:
    errors: list[str] = []
    rendered_hashes = {e["sha256"] for e in data["events"]
                       if e["kind"] == "screenshot" and
                       e.get("provenance") == "rendered_transcript"}
    if not data["scope"].strip():
        errors.append("Authorized scope is missing")
    if not data["targets"]:
        errors.append("No targets recorded")
    if require_report_id and not re.fullmatch(r"RPT-\d+", data["report_id"]):
        errors.append("Real REPORT_ID in format RPT-XXXXX is required for packaging")
    if require_report_id and not any(t.get("scored", True) and target_disposition(t) == "solved"
                                for t in data["targets"].values()):
        errors.append("Assessment package needs at least one solved scored target")
    for tid, t in data["targets"].items():
        disposition = target_disposition(t)
        attempted = t.get("scored", True) and disposition == "attempted_unsolved"
        if t.get("scored", True) and disposition not in SCORED_DISPOSITIONS:
            errors.append(f"{tid}: invalid scored-target disposition {disposition}")
        if attempted:
            if not str(t.get("disposition_note") or "").strip():
                errors.append(f"{tid}: attempted_unsolved disposition needs an observed-result note")
            if (t.get("proof") or {}).get("value"):
                errors.append(f"{tid}: captured proof cannot be marked attempted_unsolved")
        if not t["summary"].strip():
            errors.append(f"{tid}: exploitation overview is missing")
        required_stages = (("recon", "validation") if attempted else
                           [kind for kind in t["required_stages"] if kind != "submission"])
        for kind in required_stages:
            matches = [s for s in data["stages"] if s["target"] == tid and s["kind"] == kind]
            if len(matches) != 1 or not matches[0]["summary"].strip():
                errors.append(f"{tid}/{kind}: stage with summary is missing")
        for s in [x for x in data["stages"] if x["target"] == tid]:
            kind = s["kind"]
            if kind == "submission":
                # Historical control-panel placeholders are optional operator
                # notes, not a condition for assessment-report completeness.
                continue
            if attempted and kind == "proof":
                errors.append(f"{tid}/proof: attempted_unsolved target cannot have a proof stage")
                continue
            if not s["summary"].strip():
                errors.append(f"{tid}/{kind}: stage summary is missing")
            events = [e for e in data["events"] if e["target"] == tid and e["stage"] == kind]
            if not any(e["kind"] in ("command", "query", "note", "browser", "code") for e in events):
                errors.append(f"{tid}/{kind}: text evidence is missing")
            if t.get("scored", True):
                if not str(s.get("analysis") or "").strip():
                    errors.append(f"{tid}/{kind}: observed result and analysis are missing")
                if not any(is_direct_capture(root, e, rendered_hashes) for e in events):
                    errors.append(f"{tid}/{kind}: direct screenshot is missing")
        if t.get("scored", True):
            report = t.get("report") or {}
            for field in REPORT_FIELDS:
                if not str(report.get(field, "")).strip():
                    errors.append(f"{tid}: report {field.replace('_', ' ')} is missing")
            if not attempted:
                proof = t.get("proof")
                if not proof or not proof.get("path") or not proof.get("value"):
                    errors.append(f"{tid}: proof file path/content is missing")
                for roles, required_stage in ((("proof_file", "proof_value"), "proof"),):
                    if not any(e["target"] == tid and e["stage"] == required_stage
                               and e.get("role") in roles and
                               is_direct_capture(root, e, rendered_hashes)
                               for e in data["events"]):
                        errors.append(f"{tid}/{required_stage}: {' or '.join(roles)} screenshot is missing")
        elif data.get("practice_objectives"):
            # A Portal-graded action still needs a reproducible host narrative;
            # it simply has no per-host proof-file value to submit.
            report = t.get("report") or {}
            for field in REPORT_FIELDS:
                if not str(report.get(field, "")).strip():
                    errors.append(f"{tid}: report {field.replace('_', ' ')} is missing")
    screenshot_hashes: dict[str, str] = {}
    for e in data["events"]:
        if e["kind"] == "command" and e.get("status") != "done":
            if e.get("status") != "interrupted" or not e.get("resolution", "").strip() or not e.get("transcript"):
                errors.append(f"{e['id']}: command recording is incomplete")
        if (e["kind"] == "command" and
                data["targets"].get(e.get("target"), {}).get("scored", True) and
                re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD) https?://", e["command"]) and
                not str(e.get("reproduce") or "").strip()):
            errors.append(f"{e['id']}: typed HTTP action needs a copy/paste reproduction command")
        if e["kind"] == "code":
            origin = str(e.get("origin") or "").strip()
            changes = str(e.get("changes") or "").strip()
            if not origin:
                errors.append(f"{e['id']}: code origin is missing")
            elif not original_code_origin(origin):
                if not changes:
                    errors.append(f"{e['id']}: code modification notes are missing")
                if not re.match(r"^https?://", origin):
                    errors.append(f"{e['id']}: existing code needs a source URL")
            if not str(e.get("filename") or "").strip():
                errors.append(f"{e['id']}: code filename is missing")
        if e["kind"] == "query" and not e.get("result", "").strip():
            errors.append(f"{e['id']}: query response text is missing")
        if e["kind"] == "screenshot":
            if (e.get("provenance") == "direct_import" and
                    (e["sha256"] in rendered_hashes or
                     is_rendered_console_image(root / e.get("file", "")))):
                errors.append(f"{e['id']}: generated console image mislabeled as direct screenshot")
            previous = screenshot_hashes.setdefault(e["sha256"], e["id"])
            if previous != e["id"]:
                errors.append(f"{e['id']}: screenshot duplicates {previous}; capture the actual stage")
        if "file" in e or "transcript" in e:
            rel = e.get("file", e.get("transcript"))
            p = root / rel
            if not p.is_file() or digest(p) != e.get("sha256"):
                errors.append(f"{e['id']}: evidence file missing or changed: {rel}")
    errors.extend(validate_practice_objectives(root, data))
    return errors


def do_check(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    errors = validate(root, data, a.package)
    if errors:
        print("BLOCKED:")
        for error in errors:
            print(f"- {error}")
        raise SystemExit(1)
    if not re.fullmatch(r"RPT-\d+", data["report_id"]) or not any(
            t.get("scored", True) and target_disposition(t) == "solved"
            for t in data["targets"].values()):
        print("PASS: practice evidence gates satisfied; NOT an assessment submission")
    else:
        print("PASS: scored-case evidence gates satisfied; visual PDF review still required")


def do_status(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    print(f"Case: {data['title']} ({data['report_id']})")
    for tid, t in data["targets"].items():
        stages = [s["kind"] for s in data["stages"] if s["target"] == tid]
        missing = [kind for kind in t["required_stages"]
                   if kind != "submission" and kind not in stages]
        events = [e for e in data["events"] if e.get("target") == tid]
        proof = t.get("proof") or {}
        running = [e for e in events if e["kind"] == "command" and e.get("status") == "running"]
        interrupted = [e for e in events if e["kind"] == "command" and e.get("status") == "interrupted"]
        print(f"Target {tid}: {t['name']} ({t['ip']})")
        print(f"  Disposition: {target_disposition(t)}")
        if t.get("disposition_note"):
            print(f"  Disposition note: {t['disposition_note']}")
        print(f"  Stages done: {', '.join(stages) or 'none'}")
        print(f"  Stages missing: {', '.join(missing) or 'none'}")
        print(f"  Proof recorded: {'yes' if proof.get('path') and proof.get('value') else 'no'}")
        print("  Running commands: " + (", ".join(
            f"{e['id']} (actor {e.get('actor') or 'operator'})" for e in running) or "none"))
        print("  Interrupted commands: " + (", ".join(
            f"{e['id']} (actor {e.get('actor') or 'operator'}, "
            f"{'resolved' if e.get('resolution') else 'unresolved'})" for e in interrupted) or "none"))
        print("  Last 3 events:")
        for e in events[-3:]:
            detail = e["kind"]
            if e["kind"] == "command":
                detail += f" ({e.get('status', 'unknown')})"
            elif e["kind"] == "gate":
                detail += f" ({e.get('gate', 'unknown')}: {e.get('result', 'unknown')})"
            elif e["kind"] == "screenshot":
                detail += f" ({e.get('role', 'evidence')})"
            print(f"    {e['id']} · {e['at']} · actor {e.get('actor') or 'operator'} "
                  f"· {e.get('stage') or 'case'}/{detail}")
        if not events:
            print("    none")


CSS = """
@page {
  size: A4;
  margin: 18mm 17mm 18mm;
  @bottom-left { content: "REPORT assessment report"; color: #64748b; font: 8pt DejaVu Sans; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); color: #64748b; font: 8pt DejaVu Sans; }
}
body { font-family: DejaVu Sans, sans-serif; font-size: 9pt; line-height: 1.45; color: #17232e; }
h1 { font-size: 22pt; line-height: 1.2; margin: 0 0 4mm; color: #102a43; }
h2 { font-size: 14pt; margin: 8mm 0 3mm; color: #17324d; border-bottom: 1px solid #9cb3c6; padding-bottom: 1.5mm; break-after: avoid; }
h3 { font-size: 11pt; margin: 6mm 0 2mm; color: #17324d; break-after: avoid; }
h4 { font-size: 9pt; margin: 3mm 0 1mm; color: #315a78; break-after: avoid; }
p { margin: 2mm 0 3mm; }
pre { font-family: DejaVu Sans Mono, monospace; font-size: 7.3pt; line-height: 1.35; white-space: pre-wrap; overflow-wrap: anywhere; background: #f3f6f8; border-left: 2px solid #abc2d3; padding: 2.5mm 3mm; break-inside: avoid; }
img { max-width: 100%; max-height: 175mm; object-fit: contain; }
figure { margin: 4mm 0 6mm; break-inside: avoid; }
figcaption { font-size: 8pt; color: #456; }
.meta { color: #526677; font-size: 8pt; }
.practice { padding: 3mm; border: 1px solid #a84141; color: #8b2020; font-weight: bold; }
.report-table { width: 100%; border-collapse: collapse; margin: 3mm 0 5mm; }
.report-table th, .report-table td { border-bottom: 1px solid #d8e1e8; padding: 2mm 2mm; text-align: left; vertical-align: top; }
.report-table th { color: #315a78; background: #f3f6f8; }
.stage { margin-top: 5mm; }
.stage-ref { color: #526677; font-size: 8pt; }
.attack-narrative { margin: 5mm 0; }
.ledger { font-size: 7.5pt; line-height: 1.35; margin: 3mm 0 5mm; overflow-wrap: anywhere; }
.ledger-title { font-weight: bold; }
.evidence-detail { margin: 2mm 0 4mm; }
.reproduce-label { font-weight: bold; color: #17324d; }
.page-break { break-before: page; }
"""



def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def clean_terminal(value: str) -> str:
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    value = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", value)
    value = value.replace("\x08", "").replace("\r", "\n")
    return re.sub(r"[\x00-\x07\x0b\x0c\x0e-\x1f\x7f]", lambda m: f"\\x{ord(m.group()):02x}", value)


DEFAULT_OUTPUT_CHARS = 0


def squash(value: str) -> str:
    """Whitespace-free form used to compare case text with extracted PDF text."""
    return re.sub(r"\s+", "", clean_terminal(value))


def excerpt(value: str, limit: int, label: str) -> str:
    """Bound console output by characters and lines, naming its complete transcript.

    Commands, queries, prompts, responses, and code never pass through here.
    """
    value = clean_terminal(value)
    if limit <= 0:
        return value
    lines = value.splitlines(keepends=True)
    if len(value) <= limit and len(lines) <= 60:
        return value
    head = "".join(lines[:40])[: limit * 2 // 3]
    tail_budget = limit - len(head)
    tail = "".join(lines[-20:])[-tail_budget:] if tail_budget else ""
    if len(head) + len(tail) >= len(value):
        return value
    omitted = len(value) - len(head) - len(tail)
    return (f"{head}\n[... {omitted} characters omitted from this excerpt; the complete output "
            f"is {label} in the case source ...]\n{tail}")


def gate_summary(e: dict) -> str:
    if e.get("gate") == "ready_submit":
        shots = ", ".join(f"{s['role']} {s['id']} sha256 {s['sha256'][:12]}…" for s in e.get("screenshots", []))
        detail = (f"proof path {e.get('proof_path')} · proof sha256 {e.get('proof_sha256')} · "
                  f"visually checked: {e.get('checked_visual')} · screenshots: {shots or 'none'}")
    elif e.get("gate") == "verify_upload":
        detail = (f"archive {e.get('archive')} · local MD5 {e.get('local_md5')} · "
                  f"Portal MD5 {e.get('portal_md5')}")
    else:
        detail = json.dumps({k: v for k, v in e.items() if k not in ("id", "at", "kind", "gate", "result")})
    reason = f" · reason: {e['reason']}" if e.get("reason") else ""
    return f"gate {e.get('gate')} → {e.get('result')}{reason} · {detail}"


def render_html(root: Path, data: dict, output_chars: int = DEFAULT_OUTPUT_CHARS) -> str:
    # Every command, query, prompt, response, script, and proof value is rendered in
    # full as selectable text. Only captured console output may be excerpted, and
    # the excerpt marker states how much was omitted and where the full text lives.
    # Show every direct capture. Several distinct required captures can belong to
    # the same stage (for example, the control panel and accepted submission).
    # For stages without a direct capture, keep one rendered console image.
    rendered_choice = {}
    direct_image_ids = set()
    direct_image_stages = set()
    for e in data["events"]:
        if e["kind"] == "screenshot":
            k = (e["target"], e["stage"])
            if is_direct_capture(root, e):
                direct_image_ids.add(e["id"])
                direct_image_stages.add(k)
            else:
                rendered_choice[k] = e["id"]
    selected_image_ids = direct_image_ids | {
        eid for k, eid in rendered_choice.items() if k not in direct_image_stages
    }

    def pre(value: str) -> str:
        return f"<pre class='evidence-detail'>{esc(value)}</pre>"

    output_note = ("Console output over "
                   f"{output_chars} characters or 60 lines is shown as a head/tail excerpt "
                   "with a counted omission marker."
                   if output_chars > 0 else "Console output is reproduced in full.")
    parts = [f"<html><head><meta charset='utf-8'><style>{CSS}</style></head><body>",
             f"<h1>{esc(data['title'])}</h1>",
             f"<p class='meta'>REPORT_ID: {esc(data['report_id'])} · Generated: {esc(now())}</p>",
             ("<p class='practice'>PRACTICE EVIDENCE ARCHIVE - NOT AN ASSESSMENT SUBMISSION</p>"
              if not re.fullmatch(r"RPT-\d+", data["report_id"]) or
              not any(t.get("scored", True) and target_disposition(t) == "solved"
                      for t in data["targets"].values()) else ""),
             f"<h2>Authorized scope</h2><p>{esc(data['scope'])}</p>",
             "<h2>Engagement overview</h2>",
             "<p class='meta'>This report is generated from the case ledger. Every command, query, "
             "prompt, response, script, and proof value appears in full as selectable text. "
             f"{esc(output_note)} Transcripts, scripts, screenshots, and SHA256 hashes are preserved "
             "in the local case directory and referenced by evidence ID.</p>"]
    parts.append("<table class='report-table'><thead><tr><th>Target</th><th>Role</th>"
                 "<th>Disposition</th><th>Observed result</th></tr></thead><tbody>")
    for tid, t in data["targets"].items():
        disposition = target_disposition(t)
        label = {"solved": "Solved", "attempted_unsolved": "Attempted — unsolved",
                 "supporting": "Supporting"}.get(disposition, disposition)
        parts.append(f"<tr><td><b>{esc(tid)} — {esc(t['name'])}</b><br>{esc(t['ip'])}</td>"
                     f"<td>{esc(t['role'])}</td><td>{esc(label)}</td>"
                     f"<td>{esc(t['summary'])}</td></tr>")
    parts.append("</tbody></table>")
    objectives = sorted(data.get("practice_objectives", []), key=lambda item: item["task"])
    if objectives:
        parts.append("<h2>Portal objective ledger</h2><p class='meta'>"
                     "The status is taken from the case ledger. A pending task is not a verified result. "
                     "Evidence IDs identify captured actions; verified tasks require a cited direct acceptance capture."
                     "</p>")
        if data.get("practice_objective_source"):
            parts.append(f"<p class='meta'>Source: {esc(data['practice_objective_source'])}</p>")
        if data.get("practice_gate_note"):
            parts.append(f"<p class='meta'>{esc(data['practice_gate_note'])}</p>")
        parts.append("<table class='report-table'><thead><tr><th>Task</th><th>Objective</th>"
                     "<th>Related targets</th><th>Proof type</th><th>Status</th><th>Evidence IDs</th>"
                     "</tr></thead><tbody>")
        for item in objectives:
            refs = ", ".join(item["evidence_ids"]) or "none"
            targets = ", ".join(item["target_ids"])
            parts.append(f"<tr><td>{item['task']}</td><td>{esc(item['description'])}</td>"
                         f"<td>{esc(targets)}</td><td>{esc(item['proof_type'])}</td>"
                         f"<td>{esc(item['status'])}</td><td>{esc(refs)}</td></tr>")
        parts.append("</tbody></table>")
    for tid, t in data["targets"].items():
        disposition = target_disposition(t)
        label = {"solved": "Solved", "attempted_unsolved": "Attempted — unsolved",
                 "supporting": "Supporting"}.get(disposition, disposition)
        parts.append(f"<section class='page-break'><h2>{esc(tid)} — {esc(t['name'])}</h2>")
        parts.append(f"<p><b>Address:</b> {esc(t['ip'])}<br><b>Role:</b> {esc(t['role'])}<br>"
                     f"<b>Objective:</b> {esc(t['objective'])}<br><b>Disposition:</b> {esc(label)}"
                     f"<br><b>Summary:</b> {esc(t['summary'])}</p>")
        if t.get("disposition_note"):
            parts.append(f"<p><b>Disposition evidence:</b> {esc(t['disposition_note'])}</p>")
        report = t.get("report") or {}
        if report:
            parts.append("<div class='attack-narrative'><h3>Attack narrative</h3>")
            for field, label in (("entry_point", "Entry point"),
                                 ("vulnerability", "Vulnerability"),
                                 ("attack_path", "Attack path"),
                                 ("impact", "Observed impact"),
                                 ("reproduction", "Reproduction procedure")):
                if report.get(field):
                    parts.append(f"<h4>{label}</h4><p>{esc(report[field])}</p>")
            parts.append("</div>")
        for s in [x for x in data["stages"] if x["target"] == tid]:
            if s["kind"] == "submission":
                continue
            parts.append(f"<h3>{esc(s['kind'].title())}</h3><p>{esc(s['summary'])}</p>")
            if s.get("analysis"):
                parts.append(f"<p><b>Observed result and analysis:</b> {esc(s['analysis'])}</p>")
            stage_events = [e for e in data["events"]
                            if e["target"] == tid and e["stage"] == s["kind"]]
            if stage_events:
                refs = ", ".join(esc(e["id"]) for e in stage_events)
                parts.append(f"<p class='stage-ref'>Evidence IDs: {refs}. Full commands, output, "
                             "scripts, queries, and provenance appear in the evidence appendix.</p>")
            for e in stage_events:
                if e["kind"] == "screenshot" and e["id"] in selected_image_ids:
                    uri = (root / e["file"]).resolve().as_uri()
                    parts.append(f"<figure><img src='{esc(uri)}'><figcaption>"
                                 f"Evidence {esc(e['id'])} · {esc(e['role'])}: "
                                 f"{esc(e['caption'])}</figcaption></figure>")
        proof = t.get("proof")
        if proof:
            parts.append(f"<h3>Proof file</h3><pre>Path: {esc(proof['path'])}\nContents: {esc(proof['value'])}</pre>")
        parts.append("</section>")
    parts.append("<section class='page-break'><h2>Evidence appendix</h2>"
                 "<p class='meta'>Events appear in stage order. Commands, queries, responses, "
                 "and scripts are selectable text; captured output may be excerpted as noted "
                 "above. Evidence IDs connect these records to the narrative and screenshots.</p>")
    for tid, t in data["targets"].items():
        parts.append(f"<h3>{esc(tid)} — {esc(t['name'])}</h3>")
        for s in [x for x in data["stages"] if x["target"] == tid]:
            parts.append(f"<h4>{esc(s['kind'].title())} evidence</h4>")
            for e in [x for x in data["events"] if x["target"] == tid and x["stage"] == s["kind"]]:
                parts.append(f"<div class='ledger'><b>Evidence {esc(e['id'])}</b> "
                             f"· {esc(e['kind'])} · {esc(e['at'])} "
                             f"· actor {esc(e.get('actor') or 'operator')}<br>")
                if e["kind"] == "command":
                    outcome = (f"exit {e.get('exit_code') if e.get('exit_code') is not None else 'unknown'}" if e.get("status") == "done"
                               else f"interrupted; reviewed: {e.get('resolution', 'unresolved')}")
                    source_ref = f" · source ref {esc(e['source_key'])}" if e.get('source_key') else ""
                    parts.append(f"[{esc(outcome)}] · cwd {esc(e.get('cwd', '?'))} "
                                 f"· transcript {esc(e.get('transcript', 'none'))} "
                                 f"· SHA256 {esc(e.get('sha256', 'none'))}"
                                 f" · source {esc(e.get('source_system', 'local'))}"
                                 f"{source_ref}"
                                 f" · source status {esc(e.get('source_status', e.get('status', 'unknown')))}")
                    parts.append(pre(f"$ {clean_terminal(e['command'])}"))
                    if e.get("reproduce") and e["reproduce"] != e["command"]:
                        parts.append("<p class='reproduce-label'>Copy/paste reproduction commands:</p>")
                        parts.append(pre(e["reproduce"]))
                    if e.get("transcript") and (root / e["transcript"]).is_file():
                        output = (root / e["transcript"]).read_text(encoding="utf-8", errors="replace")
                        if output.strip():
                            parts.append(pre(excerpt(output, output_chars, f"transcript {e['transcript']}")))
                elif e["kind"] in ("query", "note", "browser"):
                    parts.append(pre(e["text"]))
                    if e.get("result"):
                        parts.append("Response:")
                        parts.append(pre(e["result"]))
                elif e["kind"] == "code":
                    parts.append(f"{esc(e['filename'])} · source {esc(e['origin'])} "
                                 f"· SHA256 {esc(e['sha256'])}<br>Modifications: {esc(e['changes'] or 'none stated')}")
                    code_path = root / e["file"]
                    if code_path.is_file():
                        parts.append(pre(code_path.read_text(encoding="utf-8", errors="replace")))
                elif e["kind"] == "gate":
                    parts.append(esc(gate_summary(e)))
                elif e["kind"] == "screenshot":
                    parts.append(f"{esc(e['caption'])} · SHA256 {esc(e['sha256'])}")
                    if e.get("provenance") == "direct_import" and not is_direct_capture(root, e):
                        issue = ("Generated console image, not a direct capture." if
                                 is_rendered_console_image(root / e.get("file", "")) else
                                 "Direct screenshot provenance could not be verified.")
                        parts.append(f"<b>{issue}</b>")
                parts.append("</div>")
    local_events = [e for e in data["events"]
                    if e.get("target") not in data["targets"] and e["kind"] != "gate"]
    if local_events:
        parts.append("<h3>Unattributed / local operations</h3><p class='meta'>"
                     "These captures are preserved in full but are not part of a target attack narrative."
                     "</p>")
        for e in local_events:
            parts.append(f"<div class='ledger'><b>Evidence {esc(e['id'])}</b> "
                         f"· {esc(e['kind'])} · {esc(e['at'])} "
                         f"· actor {esc(e.get('actor') or 'operator')}<br>")
            if e.get("provenance_note"):
                parts.append(f"Provenance: {esc(e['provenance_note'])}<br>")
            if e["kind"] == "command":
                parts.append(f"Source ref: {esc(e.get('source_key', 'local'))} "
                             f"· transcript {esc(e.get('transcript', 'none'))} "
                             f"· SHA256 {esc(e.get('sha256', 'none'))}")
                parts.append(pre(f"$ {clean_terminal(e['command'])}"))
                if e.get("reproduce") and e["reproduce"] != e["command"]:
                    parts.append(pre(e["reproduce"]))
                if e.get("transcript") and (root / e["transcript"]).is_file():
                    parts.append(pre((root / e["transcript"]).read_text(
                        encoding="utf-8", errors="replace")))
            elif e["kind"] in ("query", "note", "browser"):
                parts.append(pre(e.get("text", "")))
                if e.get("result"):
                    parts.append(pre(e["result"]))
            elif e["kind"] == "screenshot":
                parts.append(f"{esc(e.get('caption', ''))} · SHA256 {esc(e.get('sha256', ''))}")
                if e.get("file") and (root / e["file"]).is_file():
                    uri = (root / e["file"]).resolve().as_uri()
                    parts.append(f"<figure><img src='{esc(uri)}'></figure>")
            elif e["kind"] == "code":
                path = root / e["file"]
                parts.append(pre(path.read_text(encoding="utf-8", errors="replace")))
            parts.append("</div>")
    parts.append("</section>")
    gates = [e for e in data["events"] if e["kind"] == "gate"]
    if gates:
        parts.append("<section class='page-break'><h2>Gate record</h2>"
                     "<p class='meta'>Durable readiness and upload-verification events, in ledger order. "
                     "A readiness gate is bound to the proof value hash and screenshot hashes it checked.</p>")
        for e in gates:
            parts.append(f"<div class='ledger'><b>Evidence {esc(e['id'])}</b> · {esc(e['at'])} "
                         f"· target {esc(e.get('target') or 'case')} "
                         f"· actor {esc(e.get('actor') or 'operator')}<br>{esc(gate_summary(e))}</div>")
        parts.append("</section>")
    parts.append("</body></html>")
    return "\n".join(parts)


def pdf_text_gaps(root: Path, data: dict, full_text: str) -> list[str]:
    """Return every required text item that did not survive PDF text extraction intact."""
    # Page furniture can interrupt a long selectable pre block at a page break.
    content_text = re.sub(r"REPORT assessment report Page \d+ of \d+", "", full_text)
    haystack = squash(content_text)
    gaps: list[str] = []
    for e in data["events"]:
        if e["id"] not in full_text:
            gaps.append(f"evidence {e['id']} is absent")
            continue
        required: list[tuple[str, str]] = []
        if e["kind"] == "command":
            required.append(("command text", e["command"]))
            if e.get("reproduce") and e["reproduce"] != e["command"]:
                required.append(("reproduction command", e["reproduce"]))
            if e.get("source_key"):
                required.append(("source reference", e["source_key"]))
        elif e["kind"] in ("query", "note", "browser"):
            required.append((f"{e['kind']} text", e["text"]))
            if e.get("result"):
                required.append((f"{e['kind']} response", e["result"]))
        elif e["kind"] == "code":
            code_path = root / e["file"]
            if code_path.is_file():
                required.append(("script contents", code_path.read_text(encoding="utf-8", errors="replace")))
        for label, value in required:
            if squash(value) not in haystack:
                gaps.append(f"{label} of {e['id']} is incomplete in the PDF")
    for tid, t in data["targets"].items():
        if t.get("disposition_note") and squash(t["disposition_note"]) not in haystack:
            gaps.append(f"disposition note of {tid} is incomplete in the PDF")
        for field, value in (t.get("report") or {}).items():
            if value and squash(value) not in haystack:
                gaps.append(f"report {field} of {tid} is incomplete in the PDF")
        for item in data["stages"]:
            if item["target"] == tid and item.get("analysis") and squash(item["analysis"]) not in haystack:
                gaps.append(f"analysis of {tid}/{item['kind']} is incomplete in the PDF")
        if t.get("proof") and t["proof"]["value"] not in full_text:
            gaps.append(f"proof value of {tid} is absent")
    return gaps


def build_pdf(root: Path, data: dict, output_chars: int = DEFAULT_OUTPUT_CHARS,
              allow_text_gaps: bool = False) -> Path:
    from pypdf import PdfReader
    from weasyprint import HTML
    html_path = root / "build" / "report.html"
    html_path.write_text(render_html(root, data, output_chars), encoding="utf-8")
    pdf_path = root / "build" / f"{report_stem(data)}.pdf"
    HTML(filename=str(html_path), base_url=str(root)).write_pdf(str(pdf_path))
    reader = PdfReader(str(pdf_path))
    if not reader.pages:
        raise SystemExit("PDF has no pages")
    full_text = "\n".join(page.extract_text() or "" for page in reader.pages)
    gaps = pdf_text_gaps(root, data, full_text)
    if gaps:
        for gap in gaps:
            print(f"PDF text check {'WARNING' if allow_text_gaps else 'failed'}: {gap}")
        if not allow_text_gaps:
            raise SystemExit(1)
        print(f"WARNING: built with {len(gaps)} text gap(s) by explicit override; "
              "inspect those items in the PDF before review")
    return pdf_path


def report_input_sha(data: dict) -> str:
    """Hash report inputs while ignoring the review record written after build."""
    stable = dict(data)
    stable["review"] = None
    encoded = (json.dumps(stable, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def gate_module_path() -> Path:
    return Path(__file__).with_name("report_prebuild_unified_gate.py")


def run_integrity_gate(root: Path) -> None:
    from report_prebuild_unified_gate import evaluate
    result = evaluate(root, data_path(root))
    if result["status"] != "PASS":
        raise SystemExit(f"Evidence integrity gate blocked: {result['blocker_count']} findings")


def verify_integrity_receipt(root: Path, data: dict, pdf: Path) -> None:
    receipt_path = root / "build" / "evidence-integrity-receipt.json"
    if not receipt_path.is_file() or not gate_module_path().is_file():
        raise SystemExit("Build a gate-validated PDF before packaging")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        raise SystemExit("Evidence integrity receipt is unreadable")
    expected = {
        "schema": 1,
        "case_sha256": report_input_sha(data),
        "pdf_sha256": digest(pdf),
        "gate_module_sha256": digest(gate_module_path()),
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise SystemExit("Evidence integrity receipt is stale; rebuild and review the PDF")
    run_integrity_gate(root)


def do_build(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    errors = validate(root, data)
    if errors:
        for error in errors:
            print(f"BLOCKED: {error}")
        raise SystemExit(1)
    data["review"] = None
    save(root, data)
    run_integrity_gate(root)
    pdf = build_pdf(root, data, a.output_chars, a.allow_text_gaps)
    try:
        run_integrity_gate(root)
    except SystemExit:
        pdf.unlink(missing_ok=True)
        (root / "build" / "report.html").unlink(missing_ok=True)
        raise
    receipt = {
        "schema": 1,
        "case_sha256": report_input_sha(data),
        "pdf_sha256": digest(pdf),
        "gate_module_sha256": digest(gate_module_path()),
    }
    (root / "build" / "evidence-integrity-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Built {pdf} ({pdf.stat().st_size} bytes, SHA256 {digest(pdf)})")


def do_review(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    pdf = root / "build" / f"{report_stem(data)}.pdf"
    if not pdf.is_file():
        raise SystemExit("Build the PDF first")
    if not a.checked:
        raise SystemExit("Use --checked only after visually reviewing every PDF page and screenshot")
    data["review"] = {"at": now(), "reviewer": a.reviewer, "pdf_sha256": digest(pdf)}
    save(root, data)
    print("Recorded visual PDF review")


def do_package(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    errors = validate(root, data, not a.practice)
    if errors:
        for error in errors:
            print(f"BLOCKED: {error}")
        raise SystemExit(1)
    pdf = root / "build" / f"{report_stem(data)}.pdf"
    if not pdf.is_file() or not data.get("review") or data["review"]["pdf_sha256"] != digest(pdf):
        raise SystemExit("PDF must be built and visually reviewed after the last evidence change")
    verify_integrity_receipt(root, data, pdf)
    archive = root / "build" / f"{report_stem(data)}.7z"
    if archive.exists():
        archive.unlink()
    subprocess.run(["7z", "a", "-t7z", "-mhe=off", str(archive), pdf.name],
                   cwd=pdf.parent, check=True, stdout=subprocess.DEVNULL)
    if archive.stat().st_size > MAX_ARCHIVE:
        archive.unlink()
        raise SystemExit("Archive exceeds 100 MB")
    listing = subprocess.run(["7z", "l", "-slt", str(archive)], capture_output=True,
                             text=True, check=True).stdout
    names = re.findall(r"^Path = (.+)$", listing, re.MULTILINE)
    if names[-1:] != [pdf.name] or len(names) != 2:
        archive.unlink()
        raise SystemExit("Archive contents failed the PDF-only check")
    md5 = hashlib.md5(archive.read_bytes()).hexdigest()
    receipt = {"archive": archive.name, "bytes": archive.stat().st_size,
               "md5": md5, "pdf_sha256": digest(pdf), "review": data["review"]}
    (root / "build" / "package-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    label = "PRACTICE PACKAGE PASS" if a.practice else "PACKAGE PASS"
    print(f"{label}: {archive}\nMD5: {md5}")
    if not a.practice:
        print("Compare this MD5 with the Portal after upload.")


def do_verify_upload(a: argparse.Namespace) -> None:
    root = Path(a.root).resolve()
    data = load(root)
    archive = root / "build" / f"{report_stem(data)}.7z"
    if not archive.is_file():
        raise SystemExit("Archive is missing")
    local = hashlib.md5(archive.read_bytes()).hexdigest()
    matched = local.lower() == a.portal_md5.strip().lower()
    # Case-level gate event: no target/stage, and it does not invalidate the PDF review
    # because it adds nothing the reviewed report had to contain.
    eid = add_event(root, data, {"target": None, "stage": None, "kind": "gate",
                                 "gate": "verify_upload", "result": "verified" if matched else "mismatch",
                                 "archive": archive.name, "archive_bytes": archive.stat().st_size,
                                 "local_md5": local, "portal_md5": a.portal_md5.strip()},
                    keep_review=True, actor=a.actor)
    if not matched:
        raise SystemExit(f"MD5 MISMATCH: local {local}, Portal {a.portal_md5}; re-upload (gate event {eid})")
    print(f"UPLOAD VERIFIED: Portal MD5 matches local archive ({local}); gate event {eid}")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--actor", help="event actor; defaults to REPORT_ACTOR or operator")
    sub = p.add_subparsers(dest="action", required=True)
    def base(name: str, help_text: str) -> argparse.ArgumentParser:
        x = sub.add_parser(name, help=help_text)
        x.add_argument("root", help="case directory")
        return x
    x = base("init", "create a case")
    x.add_argument("--title", required=True)
    x.add_argument("--report_id", default="RPT-PRACTICE")
    x.add_argument("--scope", required=True)
    x.set_defaults(func=do_init)
    x = base("target", "add a target")
    for flag in ("id", "name", "ip", "role", "objective", "summary"):
        x.add_argument(f"--{flag}", required=True)
    x.add_argument("--required-stages", help="comma-separated stages; default is full chain or recon for unscored")
    x.add_argument("--unscored", action="store_true", help="non-vulnerable or unscored host: no proof required")
    x.set_defaults(func=do_target)
    x = base("disposition", "record a scored target as solved or attempted and unsolved")
    x.add_argument("--target", required=True)
    x.add_argument("--status", choices=SCORED_DISPOSITIONS, required=True)
    x.add_argument("--note", required=True, help="observed result supporting this disposition")
    x.set_defaults(func=do_disposition)
    x = base("narrative", "write the target's assessment report narrative")
    x.add_argument("--target", required=True)
    for field in REPORT_FIELDS:
        x.add_argument("--" + field.replace("_", "-"), dest=field, required=True)
    x.set_defaults(func=do_narrative)
    x = base("summary", "update a target's results overview")
    x.add_argument("--target", required=True)
    x.add_argument("--text", required=True)
    x.set_defaults(func=do_summary)
    x = base("revise-stage", "update an existing stage summary")
    x.add_argument("--target", required=True)
    x.add_argument("--kind", choices=STAGE_KINDS, required=True)
    x.add_argument("--summary", required=True)
    x.add_argument("--analysis", help="observed result and why it matters")
    x.set_defaults(func=do_revise_stage)
    x = base("stage", "add a documented attack stage")
    x.add_argument("--target", required=True)
    x.add_argument("--kind", choices=STAGE_KINDS, required=True)
    x.add_argument("--summary", required=True)
    x.add_argument("--analysis", help="observed result and why it matters")
    x.set_defaults(func=do_stage)
    x = base("run", "run and capture a command")
    x.add_argument("--target", required=True)
    x.add_argument("--stage", choices=STAGE_KINDS, required=True)
    x.add_argument("--cwd", help="working directory; defaults to current directory")
    x.add_argument("command", nargs="+", help="command and arguments after --")
    x.set_defaults(func=do_run)
    x = base("tty", "record an interactive terminal session")
    x.add_argument("--target", required=True)
    x.add_argument("--stage", choices=STAGE_KINDS, required=True)
    x.add_argument("--cwd", help="working directory; defaults to current directory")
    x.add_argument("--command", required=True, help="interactive command, such as 'zsh -i'")
    x.set_defaults(func=do_tty)
    x = base("resolve-interrupted", "document an interrupted command without inventing an exit code")
    x.add_argument("--id", required=True)
    x.add_argument("--reason", required=True)
    x.set_defaults(func=do_resolve_interrupted)
    x = base("log", "record a browser action, AI query, or note")
    x.add_argument("--target", required=True)
    x.add_argument("--stage", choices=STAGE_KINDS, required=True)
    x.add_argument("--kind", choices=("query", "browser", "note"), required=True)
    group = x.add_mutually_exclusive_group(required=True)
    group.add_argument("--text")
    group.add_argument("--text-file")
    x.add_argument("--result-file")
    x.set_defaults(func=do_log)
    x = base("screenshot", "import a screenshot and label its role")
    x.add_argument("--target", required=True)
    x.add_argument("--stage", choices=STAGE_KINDS, required=True)
    x.add_argument("--file", required=True)
    x.add_argument("--role", choices=SCREEN_ROLES, default="evidence")
    x.add_argument("--caption", required=True)
    x.set_defaults(func=do_screenshot)
    x = base("drop-duplicate-screenshot", "remove redundant screenshot event, retaining its file")
    x.add_argument("--id", required=True)
    x.set_defaults(func=do_drop_duplicate_screenshot)
    x = base("refresh-rendered-screenshots", "rerender captured console images from their transcripts")
    x.set_defaults(func=do_refresh_rendered_screenshots)
    x = base("code", "preserve a script and its provenance")
    x.add_argument("--target", required=True)
    x.add_argument("--stage", choices=STAGE_KINDS, required=True)
    x.add_argument("--file", required=True)
    x.add_argument("--origin", required=True, help="original or source URL")
    x.add_argument("--changes", default="")
    x.set_defaults(func=do_code)
    x = base("proof", "record exact proof path and contents; value from stdin or file")
    x.add_argument("--target", required=True)
    x.add_argument("--path", required=True)
    x.add_argument("--value-file")
    x.set_defaults(func=do_proof)
    x = base("ready-submit", "optionally verify original proof text and a direct target screenshot")
    x.add_argument("--target", required=True)
    x.add_argument("--checked-visual", action="store_true",
                   help="affirm that the direct proof screenshot visibly shows the exact value")
    x.set_defaults(func=do_ready_submit)
    x = base("check", "show missing evidence")
    x.add_argument("--package", action="store_true")
    x.set_defaults(func=do_check)
    x = base("status", "show per-target case progress")
    x.set_defaults(func=do_status)
    x = base("build", "create and text-check PDF; blocks on missing evidence")
    x.add_argument("--output-chars", type=int, default=DEFAULT_OUTPUT_CHARS,
                   help="console output over this character count or 60 lines is excerpted; 0 = full output")
    x.add_argument("--allow-text-gaps", action="store_true",
                   help="emergency override: report PDF text-extraction gaps as warnings instead of blocking")
    x.set_defaults(func=do_build)
    x = base("review", "record required visual PDF review")
    x.add_argument("--reviewer", required=True)
    x.add_argument("--checked", action="store_true")
    x.set_defaults(func=do_review)
    x = base("package", "create and verify final .7z")
    x.add_argument("--practice", action="store_true", help="label the archive as practice and allow RPT-PRACTICE")
    x.set_defaults(func=do_package)
    x = base("verify-upload", "compare Portal MD5 to local archive")
    x.add_argument("--portal-md5", required=True)
    x.set_defaults(func=do_verify_upload)
    return p


if __name__ == "__main__":
    parser_obj = parser()
    arguments = parser_obj.parse_args()
    if arguments.action == "init":
        arguments.func(arguments)
    else:
        case_root = Path(arguments.root).resolve()
        if not case_root.is_dir():
            raise SystemExit(f"No case at {case_root}; run init first")
        if arguments.action in SELF_LOCKING_ACTIONS:
            arguments.func(arguments)
        else:
            with case_lock(case_root):
                arguments.func(arguments)
