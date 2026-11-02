"""End-to-end checks for the captured-run to REPORT PDF handoff."""
import importlib
from argparse import Namespace
import json
import sqlite3
import sys
from pathlib import Path

import pytest
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "report-kit"))
import report
from casehub import CaseHub
from capture_import import import_capture
server = importlib.import_module("redops.mcp_server")


def make_case(root):
    (root / "build").mkdir(exist_ok=True)
    report.save(root, {
        "schema": 1, "created": report.now(), "title": "Bridge test",
        "report_id": "RPT-PRACTICE", "scope": "synthetic local case",
        "targets": {"box": {
            "name": "Box", "ip": "192.0.2.10", "role": "test",
            "objective": "Record a captured run", "summary": "Synthetic overview",
            "required_stages": ["recon"], "scored": False, "proof": None,
        }},
        "stages": [{"target": "box", "kind": "recon", "summary": "Synthetic recon"}],
        "events": [], "review": None, "gates_required": True,
    })


def test_import_to_searchable_pdf_and_casehub(tmp_path, monkeypatch):
    make_case(tmp_path)
    row = {
        "id": 42, "engagement_id": 7, "command": "printf bridge-marker",
        "output": "bridge-marker\n", "status": "done", "actor": "agent",
        "summary": "captured 14 bytes; exit code 0",
    }
    monkeypatch.setattr(server, "_engagement", lambda: 7)
    monkeypatch.setattr(server, "tool_results", lambda **kwargs: json.dumps(row))
    imported = json.loads(server.report_import_run(42, str(tmp_path), "box", "recon"))
    assert imported["exit_code"] == 0
    assert json.loads(server.report_import_run(42, str(tmp_path), "box", "recon")) == imported
    events = report.load(tmp_path)["events"]
    assert len(events) == 2
    assert events[0]["source_engagement"] == 7
    assert events[0]["source_id"] == 42
    with CaseHub(tmp_path, actor="test") as hub:
        assert hub.search("bridge-marker")["evidence"]
    built = json.loads(server.report_build(str(tmp_path)))
    assert built["ready"] is True
    assert Path(built["pdf"]).is_file()
    pdf_text = "\n".join(page.extract_text() or "" for page in PdfReader(built["pdf"]).pages)
    assert "bridge-marker" in pdf_text
    assert "exit 0" in pdf_text
    assert "source redops" in pdf_text
    assert "redops:7:42" in pdf_text
    assert report.load(tmp_path)["review"] is None


def test_import_preserves_failed_exit_and_rejects_other_engagement(tmp_path, monkeypatch):
    make_case(tmp_path)
    row = {
        "id": 43, "engagement_id": 7, "command": "false",
        "output": "failed attempt", "status": "error", "actor": "agent",
        "summary": "captured 14 bytes; exit code 2",
    }
    monkeypatch.setattr(server, "_engagement", lambda: 7)
    monkeypatch.setattr(server, "tool_results", lambda **kwargs: json.dumps(row))
    server.report_import_run(43, str(tmp_path), "box", "recon")
    assert "exit 2" in report.render_html(tmp_path, report.load(tmp_path))
    row["engagement_id"] = 8
    with pytest.raises(ValueError, match="active engagement"):
        server.report_import_run(43, str(tmp_path), "box", "recon")


def test_import_missing_stage_returns_error_instead_of_system_exit(tmp_path, monkeypatch):
    make_case(tmp_path)
    row = {
        "id": 44, "engagement_id": 7, "command": "true",
        "output": "done", "status": "done", "actor": "agent",
        "summary": "captured 4 bytes; exit code 0",
    }
    monkeypatch.setattr(server, "_engagement", lambda: 7)
    monkeypatch.setattr(server, "tool_results", lambda **kwargs: json.dumps(row))
    with pytest.raises(ValueError, match="Missing box/exploit stage"):
        server.report_import_run(44, str(tmp_path), "box", "exploit")


def test_bulk_import_pages_beyond_recent_40(tmp_path, monkeypatch):
    make_case(tmp_path)
    monkeypatch.setattr(server, "_engagement", lambda: 7)
    monkeypatch.setattr(server, "find_target", lambda ip: {"id": 9, "ip": ip})
    rows = [{"id": n, "engagement_id": 7, "status": "done"}
            for n in range(41, 0, -1)]
    def page(**kwargs):
        before = kwargs.get("before_id")
        eligible = [row for row in rows if before is None or row["id"] < before]
        return json.dumps(eligible[:40])
    seen = []
    monkeypatch.setattr(server, "tool_results", page)
    monkeypatch.setattr(server, "_report_import_row",
                        lambda row, *args, **kwargs: seen.append(row["id"]) or {"run_id": row["id"]})
    result = json.loads(server.report_import_runs(str(tmp_path), "box", "recon", "192.0.2.10"))
    assert len(result["imported"]) == 41
    assert seen == list(range(1, 42))


def test_run_history_pagination_keeps_engagement_and_target_bounds():
    tools = importlib.import_module("red" + "ops.tools")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE tool_runs(id INTEGER, engagement_id INTEGER, target_id INTEGER)")
    conn.executemany("INSERT INTO tool_runs VALUES (?,?,?)",
                     [(n, 7, 9) for n in range(1, 51)] +
                     [(100, 8, 9), (101, 7, 10)])
    first = tools.runs(conn, engagement_id=7, target_id=9, limit=40)
    second = tools.runs(conn, engagement_id=7, target_id=9,
                        limit=40, before_id=first[-1]["id"])
    assert [r["id"] for r in first] == list(range(50, 10, -1))
    assert [r["id"] for r in second] == list(range(10, 0, -1))


def test_report_build_lists_missing_evidence(tmp_path):
    make_case(tmp_path)
    result = json.loads(server.report_build(str(tmp_path)))
    assert result["ready"] is False
    assert any("text evidence is missing" in item for item in result["blockers"])
    assert not list((tmp_path / "build").glob("*.pdf"))


def test_bulk_import_skips_runs_filed_in_an_earlier_stage(tmp_path, monkeypatch):
    make_case(tmp_path)
    import_capture(tmp_path, "box", "recon", {
        "source_system": "redops", "source_engagement": 7, "source_id": 1,
        "command": "probe", "output": "observed", "status": "done", "exit_code": 0,
    })
    case = report.load(tmp_path)
    case["stages"].append({"target": "box", "kind": "validation", "summary": "Validate"})
    report.save(tmp_path, case)
    monkeypatch.setattr(server, "_engagement", lambda: 7)
    monkeypatch.setattr(server, "find_target", lambda ip: {"id": 9, "ip": ip})
    monkeypatch.setattr(server, "tool_results",
                        lambda **kwargs: json.dumps([{"id": 1, "status": "done"}]))
    monkeypatch.setattr(server, "_report_import_row",
                        lambda *args: pytest.fail("earlier stage run was imported again"))
    result = json.loads(server.report_import_runs(
        str(tmp_path), "box", "validation", case["targets"]["box"]["ip"]))
    assert result["imported"] == []
    assert result["already_imported"] == [{"run_id": 1, "target": "box", "stage": "recon"}]


def test_scored_case_rejects_rendered_only_screenshots_and_missing_narrative(tmp_path):
    make_case(tmp_path)
    case = report.load(tmp_path)
    case["report_id"] = "RPT-12345"
    case["targets"]["box"]["scored"] = True
    report.save(tmp_path, case)
    import_capture(tmp_path, "box", "recon", {
        "source_system": "ops", "source_engagement": 7, "source_id": 88,
        "command": "printf observed", "output": "observed", "status": "done",
    })
    errors = report.validate(tmp_path, report.load(tmp_path))
    assert any("direct screenshot is missing" in error for error in errors)
    assert any("report entry point is missing" in error for error in errors)
    assert any("observed result and analysis are missing" in error for error in errors)


def test_unscored_case_cannot_be_assessment_package(tmp_path):
    make_case(tmp_path)
    case = report.load(tmp_path)
    case["report_id"] = "RPT-12345"
    report.save(tmp_path, case)
    assert "PRACTICE EVIDENCE ARCHIVE" in report.render_html(tmp_path, case)
    assert "Assessment package needs at least one solved scored target" in report.validate(
        tmp_path, case, require_report_id=True)

def test_typed_http_import_survives_pdf_as_copy_paste_commands(tmp_path):
    make_case(tmp_path)
    imported = import_capture(tmp_path, "box", "recon", {
        "source_system": "redops", "source_engagement": 7, "source_id": 89,
        "command": "GET http://example.invalid:8000 /health /openapi.json",
        "output": "HTTP 200", "status": "done", "exit_code": 0,
    })
    case = report.load(tmp_path)
    event = next(e for e in case["events"] if e["id"] == imported)
    assert event["reproduce"] == (
        "curl -sS --max-time 10 -X GET http://example.invalid:8000/health\n"
        "curl -sS --max-time 10 -X GET http://example.invalid:8000/openapi.json")
    pdf = report.build_pdf(tmp_path, case)
    full_text = "\n".join(page.extract_text() or "" for page in PdfReader(str(pdf)).pages)
    assert "Copy/paste reproduction commands" in full_text
    assert report.squash(event["reproduce"]) in report.squash(full_text)


def test_scored_typed_http_capture_needs_reproduction(tmp_path):
    make_case(tmp_path)
    case = report.load(tmp_path)
    case["targets"]["box"]["scored"] = True
    report.save(tmp_path, case)
    imported = import_capture(tmp_path, "box", "recon", {
        "source_system": "redops", "source_engagement": 7, "source_id": 90,
        "command": "GET http://example.invalid:8000 /health?broken",
        "output": "HTTP 200", "status": "done",
    })
    case = report.load(tmp_path)
    event = next(e for e in case["events"] if e["id"] == imported)
    event["reproduce"] = ""
    report.save(tmp_path, case)
    errors = report.validate(tmp_path, case)
    assert any("typed HTTP action needs a copy/paste reproduction command" in error for error in errors)

def test_long_script_survives_page_breaks_and_pdf_text_gate(tmp_path):
    make_case(tmp_path)
    import_capture(tmp_path, "box", "recon", {
        "source_system": "redops", "source_engagement": 7, "source_id": 92,
        "command": "printf observed", "output": "observed", "status": "done",
    })
    code_dir = tmp_path / "code"
    code_dir.mkdir()
    code = code_dir / "payload.py"
    code.write_text(chr(10).join(
        "print('synthetic unique statement %03d')" % number
        for number in range(240)) + chr(10), encoding="utf-8")
    case = report.load(tmp_path)
    case["events"].append({
        "id": "long-script-92", "at": report.now(), "actor": "tester",
        "target": "box", "stage": "recon", "kind": "code",
        "filename": "payload.py", "origin": "original",
        "changes": "none", "file": "code/payload.py",
        "sha256": report.digest(code),
    })
    report.save(tmp_path, case)
    pdf = report.build_pdf(tmp_path, case)
    pages = PdfReader(str(pdf)).pages
    assert len(pages) >= 4
    text = chr(10).join(page.extract_text() or "" for page in pages)
    assert not report.pdf_text_gaps(tmp_path, case, text)

def test_rendered_console_copy_never_counts_as_direct_capture(tmp_path):
    make_case(tmp_path)
    event_id = import_capture(tmp_path, "box", "recon", {
        "source_system": "redops", "source_engagement": 7, "source_id": 93,
        "command": "printf observed", "output": "observed", "status": "done",
    })
    case = report.load(tmp_path)
    case["targets"]["box"]["scored"] = True
    console = next(e for e in case["events"]
                   if e["kind"] == "screenshot" and e["file"].endswith(event_id + "-console.png"))
    assert report.is_rendered_console_image(tmp_path / console["file"])
    with pytest.raises(SystemExit, match="cannot be imported as a direct screenshot"):
        report.do_screenshot(Namespace(root=str(tmp_path), target="box", stage="recon",
                                    file=str(tmp_path / console["file"]), role="evidence",
                                    caption="Copied console", actor="tester"))
    copied = dict(console, id="copied-console", provenance="direct_import", role="proof_value")
    case["events"].append(copied)
    report.save(tmp_path, case)
    errors = report.validate(tmp_path, case)
    assert any("copied-console: generated console image mislabeled" in error for error in errors)
    assert any("box/recon: direct screenshot is missing" in error for error in errors)
    with pytest.raises(SystemExit, match="needs a direct screenshot"):
        report.do_stage(Namespace(root=str(tmp_path), target="box", kind="validation",
                                summary="Follow-up", analysis="Expected result"))
