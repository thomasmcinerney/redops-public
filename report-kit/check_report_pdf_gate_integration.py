#!/usr/bin/env python3
"""Synthetic REPORT PDF integrity receipt and full-content acceptance test."""
import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from pypdf import PdfWriter

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report


report.validate = lambda root, data, package=False: []
build_calls = []


def fake_build_pdf(root, data, output_chars, allow_text_gaps):
    build_calls.append((str(root), output_chars))
    folder = root / "build"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "report.html").write_text("<html><body>Synthetic fixture</body></html>")
    pdf = folder / f"{report.report_stem(data)}.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    with pdf.open("wb") as handle:
        writer.write(handle)
    return pdf


report.build_pdf = fake_build_pdf


def make_case(root):
    root.mkdir()
    image = root / "evidence" / "proof.jpg"
    image.parent.mkdir()
    image.write_bytes(b"synthetic direct image")
    event = {
        "id": "shot1", "kind": "screenshot", "provenance": "direct_import",
        "file": "evidence/proof.jpg", "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        "target": "synthetic",
    }
    data = {
        "schema": 1, "report_id": "RPT-PRACTICE", "title": "Synthetic Integrity",
        "review": None, "events": [event],
        "targets": {"synthetic": {"name": "Synthetic", "ip": "127.0.0.1"}},
        "stages": [],
    }
    report.save(root, data)
    return image


def expect_block(fn, fragment):
    try:
        fn()
    except SystemExit as exc:
        assert fragment in str(exc), str(exc)
    else:
        raise AssertionError("expected build/package block: " + fragment)


assert report.DEFAULT_OUTPUT_CHARS == 0, "full PDF output is not the default"
with tempfile.TemporaryDirectory(prefix="report-pdf-integrity-") as temp:
    base = Path(temp)
    root = base / "clean"
    image = make_case(root)
    build_args = SimpleNamespace(root=str(root), output_chars=0, allow_text_gaps=False)
    package_args = SimpleNamespace(root=str(root), practice=True)
    report.do_build(build_args)
    pdf = root / "build" / f"{report.report_stem(report.load(root))}.pdf"
    receipt = root / "build" / "evidence-integrity-receipt.json"
    assert pdf.is_file() and receipt.is_file() and len(build_calls) == 1
    data = report.load(root)
    data["review"] = {"at": "2026-10-30T00:00:00Z", "reviewer": "synthetic-test",
                      "pdf_sha256": report.digest(pdf)}
    report.save(root, data)
    report.do_package(package_args)
    assert (root / "build" / f"{report.report_stem(data)}.7z").is_file()
    saved = copy.deepcopy(data)
    data["events"].append({"id": "note1", "kind": "note", "text": "later edit"})
    report.save(root, data)
    expect_block(lambda: report.do_package(package_args), "receipt is stale")
    report.save(root, saved)
    image.write_bytes(b"changed image")
    expect_block(lambda: report.do_package(package_args), "Evidence integrity gate blocked")
    image.write_bytes(b"synthetic direct image")

    key_root = base / "full-content"
    make_case(key_root)
    transcript = key_root / "transcripts" / "key.txt"
    transcript.parent.mkdir()
    pem = "-----BEGIN SYNTHETIC TEST KEY-----\nSYNTHETIC-COPY-PASTE\n-----END SYNTHETIC TEST KEY-----\n"
    transcript.write_text(pem, encoding="utf-8")
    key_case = report.load(key_root)
    key_case["events"].append({
        "id": "key", "kind": "command", "target": "synthetic", "status": "done",
        "command": "cat /synthetic/key", "transcript": "transcripts/key.txt",
        "sha256": report.digest(transcript),
    })
    report.save(key_root, key_case)
    report.do_build(SimpleNamespace(root=str(key_root), output_chars=0, allow_text_gaps=False))
    assert len(build_calls) == 2, "full key content was blocked"

    missing_root = base / "missing-artifact"
    make_case(missing_root)
    missing_case = report.load(missing_root)
    missing_case["events"].append({
        "id": "missing", "kind": "command", "target": "synthetic", "status": "done",
        "command": "cat /synthetic/missing", "transcript": "transcripts/missing.txt",
        "sha256": "0" * 64,
    })
    report.save(missing_root, missing_case)
    expect_block(
        lambda: report.do_build(SimpleNamespace(root=str(missing_root), output_chars=0,
                                              allow_text_gaps=False)),
        "Evidence integrity gate blocked",
    )
    assert len(build_calls) == 2 and not (missing_root / "build").exists()
print("PDF integrity integration PASS: full key allowed; stale case/image and missing artifact block")
