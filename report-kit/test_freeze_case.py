#!/usr/bin/env python3
"""Focused regression for immutable REPORT report snapshots."""
import hashlib
import json
import tempfile
from pathlib import Path

from freeze_case import freeze, sha256


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


with tempfile.TemporaryDirectory(prefix="report-freeze-test-") as temp:
    base = Path(temp)
    source = base / "live"
    source.mkdir()
    transcript = source / "transcripts" / "E1.txt"
    image = source / "evidence" / "S1.png"
    extra = source / "code" / "unused.py"
    write(transcript, b"full captured output\n")
    write(image, b"synthetic image bytes")
    write(extra, b"print('retained')\n")
    events = [
        {"id": "E1", "kind": "command", "target": "H1", "transcript": "transcripts/E1.txt",
         "sha256": sha256(transcript)},
        {"id": "S1", "kind": "screenshot", "target": "H1", "file": "evidence/S1.png",
         "sha256": sha256(image)},
    ]
    case = {"schema": 1, "targets": {"H1": {"name": "Synthetic"}}, "events": events}
    case_path = source / "case.json"
    write(case_path, (json.dumps(case, sort_keys=True) + "\n").encode())
    archive = base / "runs.jsonl"
    write(archive, b'{"id":1,"command":"id","output":"uid=1000"}\n')
    original = {p.relative_to(source).as_posix(): sha256(p) for p in source.rglob("*") if p.is_file()}

    first = freeze(source, base / "snapshot-a", archive)
    second = freeze(source, base / "snapshot-b", archive)
    assert first["manifest_sha256"] == second["manifest_sha256"]
    assert first["file_count"] == 5
    assert first["archive_sha256"] == sha256(archive)
    assert (base / "snapshot-a" / "code" / "unused.py").read_bytes() == extra.read_bytes()
    assert original == {p.relative_to(source).as_posix(): sha256(p) for p in source.rglob("*") if p.is_file()}

    write(transcript, b"changed output\n")
    try:
        freeze(source, base / "snapshot-tampered")
    except ValueError as error:
        assert "hash mismatch" in str(error)
    else:
        raise AssertionError("changed transcript was accepted")

    write(transcript, b"full captured output\n")
    case["events"][0]["transcript"] = "../outside.txt"
    write(case_path, (json.dumps(case, sort_keys=True) + "\n").encode())
    try:
        freeze(source, base / "snapshot-escape")
    except ValueError as error:
        assert "escapes" in str(error)
    else:
        raise AssertionError("escaping path was accepted")

print("freeze_case: repeat, complete copy, source integrity, and path checks passed")
