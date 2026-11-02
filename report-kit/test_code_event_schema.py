"""Malformed imported code evidence should fail the report gate cleanly."""

from pathlib import Path
import tempfile

import report


def test_code_event_missing_fields_reports_errors_instead_of_crashing():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        source = root / "decoder.py"
        source.write_text("print('test')\n", encoding="utf-8")
        event = {
            "id": "legacy-code", "target": None, "stage": None,
            "kind": "code", "file": "decoder.py", "sha256": report.digest(source),
        }
        case = {"scope": "authorized practice lab", "targets": {},
                "stages": [], "events": [event]}

        errors = report.validate(root, case)

        assert "legacy-code: code origin is missing" in errors
        assert "legacy-code: code filename is missing" in errors
        event.update(origin="https://example.test/decoder.py", filename="decoder.py")
        assert "legacy-code: code modification notes are missing" in report.validate(root, case)
        event.update(origin="original", changes="", filename="decoder.py")
        assert not any("legacy-code:" in error for error in report.validate(root, case))
        event.update(origin="Original REPORT diagnostic payload")
        assert not any("legacy-code:" in error for error in report.validate(root, case))
