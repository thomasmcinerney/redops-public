#!/usr/bin/env python3
"""Full-fidelity REPORT prebuild integrity checks on synthetic evidence."""
import hashlib
import json
import tempfile
from pathlib import Path

import report_prebuild_unified_gate as gate


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


with tempfile.TemporaryDirectory(prefix="report-integrity-") as temp:
    root = Path(temp)
    for folder in ("transcripts", "evidence", "code"):
        (root / folder).mkdir()
    pem = b"-----BEGIN SYNTHETIC TEST KEY-----\nSYNTHETIC-COPY-PASTE\n-----END SYNTHETIC TEST KEY-----\n"
    token = b"glpat-SYNTHETIC123456789012345"
    (root / "transcripts/C1.txt").write_bytes(pem + token + b"\n")
    (root / "evidence/S1.jpg").write_bytes(b"synthetic direct image")
    (root / "evidence/orphan-console.png").write_bytes(b"synthetic console image")
    (root / "code/D1.py").write_bytes(b"print('exact code')\n")
    case = {
        "schema": 1,
        "targets": {"H1": {"name": "Synthetic", "ip": "127.0.0.1"}},
        "events": [
            {"id": "C1", "kind": "command", "target": "H1", "status": "done",
             "command": "cat /synthetic/key", "transcript": "transcripts/C1.txt",
             "sha256": sha((root / "transcripts/C1.txt").read_bytes())},
            {"id": "S1", "kind": "screenshot", "target": "H1",
             "provenance": "direct_import", "file": "evidence/S1.jpg",
             "sha256": sha((root / "evidence/S1.jpg").read_bytes())},
            {"id": "D1", "kind": "code", "target": "H1", "file": "code/D1.py",
             "sha256": sha((root / "code/D1.py").read_bytes())},
            {"id": "G1", "kind": "screenshot", "target": "H1",
             "provenance": "rendered_transcript", "file": "evidence/orphan-console.png",
             "sha256": sha((root / "evidence/orphan-console.png").read_bytes())},
        ],
    }
    path = root / "case.json"
    path.write_text(json.dumps(case))
    result = gate.evaluate(root)
    assert result["status"] == "PASS", result["blockers"]
    assert result["counts"]["events"] == 4
    assert any(x["kind"] == "rendered-console-source-unlinked" for x in result["warnings"])
    assert pem.decode() in path.read_text() or "SYNTHETIC-COPY-PASTE" in (
        root / "transcripts/C1.txt").read_text()
    (root / "evidence/S1.jpg").write_bytes(b"changed image")
    result = gate.evaluate(root)
    assert result["status"] == "BLOCK"
    assert any(x["kind"] == "artifact-hash-mismatch" for x in result["blockers"])
    (root / "evidence/S1.jpg").write_bytes(b"synthetic direct image")
    (root / "transcripts/C1.txt").unlink()
    result = gate.evaluate(root)
    assert result["status"] == "BLOCK"
    assert any(x["kind"] == "artifact-file-missing" for x in result["blockers"])
    (root / "transcripts/C1.txt").write_bytes(pem + token + b"\n")
    case["events"].append(dict(case["events"][0]))
    path.write_text(json.dumps(case))
    result = gate.evaluate(root)
    assert result["status"] == "BLOCK"
    assert any(x["kind"] == "event-id-duplicate" for x in result["blockers"])
print("integrity gate PASS: full key/token content retained; hash/path changes block; unlinked image warns")
