#!/usr/bin/env python3
"""A 75/100 assessment case may include documented, unsolved assigned hosts."""

import copy
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from PIL import Image
from pypdf import PdfReader

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report


SCORES = {
    "external_a": 15, "internal_a1": 15, "internal_a2": 10,
    "external_b": 15, "internal_b1": 15, "internal_b2": 10,
    "standalone": 15, "dc": 5,
}
SOLVED = {"external_a", "internal_a1", "internal_a2", "external_b", "internal_b1", "dc"}


def fixture(root: Path) -> dict:
    (root / "evidence").mkdir(parents=True)
    (root / "transcripts").mkdir()
    (root / "build").mkdir()
    data = {
        "schema": 1, "created": report.now(), "title": "Synthetic 75-point assessment case",
        "report_id": "RPT-12345", "scope": "Eight assigned synthetic machines",
        "targets": {}, "stages": [], "events": [], "review": None,
        "gates_required": True,
    }

    def screenshot(tid: str, kind: str, role: str) -> dict:
        name = f"{tid}-{kind}-{role}.png"
        path = root / "evidence" / name
        # Distinct direct-camera stand-ins; unlike REPORT rendered console images.
        color = (len(data["events"]) % 190 + 30, len(tid) * 16, len(kind) * 19)
        Image.new("RGB", (96, 64), color).save(path)
        event = {
            "id": f"shot-{tid}-{kind}-{role}", "kind": "screenshot", "target": tid,
            "stage": kind, "at": report.now(), "role": role, "provenance": "direct_import",
            "caption": f"Synthetic {tid} {kind} {role} capture", "file": f"evidence/{name}",
            "sha256": report.digest(path),
        }
        data["events"].append(event)
        return event

    for number, (tid, points) in enumerate(SCORES.items(), start=1):
        solved = tid in SOLVED
        stages = list(report.DEFAULT_STAGES) if solved else ["recon", "validation", "exploit"]
        data["targets"][tid] = {
            "name": tid, "ip": f"192.0.2.{number}", "role": "synthetic assigned host",
            "objective": "Synthetic proof", "summary": "Proof captured" if solved else "Attempted; no proof captured",
            "required_stages": list(report.DEFAULT_STAGES), "scored": True,
            "disposition": "solved" if solved else "attempted_unsolved",
            "disposition_note": "No access or flag after documented probes" if not solved else "Original proof captured",
            "proof": {"path": "/original/flag.txt", "value": f"OS{{synthetic-{tid}}}"} if solved else None,
            "report": {field: f"{tid} {field} observed and reproducible" for field in report.REPORT_FIELDS},
            "points": points,
        }
        for kind in stages:
            data["stages"].append({"target": tid, "kind": kind,
                                   "summary": f"{tid} {kind} result", "analysis": f"{tid} {kind} observed analysis"})
            transcript_path = root / "transcripts" / f"{tid}-{kind}.txt"
            transcript_path.write_text(f"{tid} {kind} captured output\n", encoding="utf-8")
            data["events"].append({
                "id": f"run-{tid}-{kind}", "kind": "command", "target": tid, "stage": kind,
                "at": report.now(), "status": "done", "command": f"printf '{tid} {kind}'",
                "transcript": f"transcripts/{tid}-{kind}.txt", "sha256": report.digest(transcript_path),
            })
            if kind == "proof":
                screenshot(tid, kind, "proof_value")
            else:
                screenshot(tid, kind, "evidence")
    report.save(root, data)
    return data


def has(errors: list[str], fragment: str) -> bool:
    return any(fragment in error for error in errors)


with tempfile.TemporaryDirectory(prefix="report-partial-pass-") as temp:
    root = Path(temp)
    data = fixture(root)
    assert sum(SCORES.values()) == 100
    assert sum(SCORES[tid] for tid in SOLVED) == 75
    assert report.validate(root, data, require_report_id=True) == []
    legacy_submission = copy.deepcopy(data)
    for tid in SOLVED:
        legacy_submission["targets"][tid]["required_stages"].append("submission")
        legacy_submission["stages"].append({"target": tid, "kind": "submission",
                                            "summary": "Historical empty Portal placeholder", "analysis": ""})
    assert report.validate(root, legacy_submission, require_report_id=True) == []
    html = report.render_html(root, data)
    assert "Attempted — unsolved" in html
    assert "No access or flag after documented probes" in html
    assert html.count("Contents: OS{synthetic-") == len(SOLVED)
    assert "control_panel" not in html and "accepted" not in html
    pdf = report.build_pdf(root, data)
    pdf_text = "\n".join(page.extract_text() or "" for page in PdfReader(str(pdf)).pages)
    assert "Attempted" in pdf_text and "No access or flag after documented probes" in pdf_text

    missing_proof = copy.deepcopy(data)
    missing_proof["targets"]["dc"]["proof"] = None
    assert has(report.validate(root, missing_proof), "dc: proof file path/content is missing")
    legacy_scored = copy.deepcopy(data)
    legacy_scored["targets"]["standalone"].pop("disposition")
    assert has(report.validate(root, legacy_scored), "standalone: proof file path/content is missing")
    missing_recon_shot = copy.deepcopy(data)
    missing_recon_shot["events"] = [e for e in missing_recon_shot["events"]
                                    if e["id"] != "shot-standalone-recon-evidence"]
    assert has(report.validate(root, missing_recon_shot), "standalone/recon: direct screenshot is missing")
    missing_note = copy.deepcopy(data)
    missing_note["targets"]["standalone"]["disposition_note"] = ""
    assert has(report.validate(root, missing_note), "standalone: attempted_unsolved disposition needs")
    hidden_success = copy.deepcopy(data)
    hidden_success["targets"]["standalone"]["proof"] = {"path": "/flag", "value": "OS{test}"}
    assert has(report.validate(root, hidden_success), "standalone: captured proof cannot be marked")

    args = SimpleNamespace(root=str(root), target="standalone", status="attempted_unsolved",
                           note="No access or flag after documented probes")
    report.do_disposition(args)
    assert report.load(root)["targets"]["standalone"]["disposition"] == "attempted_unsolved"
    assert not any(e["kind"] == "screenshot" and e["role"] == "accepted"
                   for e in data["events"])

print("Partial-pass report PASS: 75/100 scored fixture renders; solved proof and attempted evidence gates hold")
