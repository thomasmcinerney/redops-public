"""Report regression (redops.export): the client-facing deliverable.

Covers the three defects found on 2026-07-24, all of which shipped silently
because export.py had no test at all:
  1. unattributed captures leaked EVERY engagement's events into one report
  2. captured output containing ``` closed its own fence, after which the rest
     was parsed as markdown — a git-status capture became an 83 KB top-level
     section of an unrelated engagement's report
  3. no truncation anywhere: one engagement rendered 2.6 MB

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_export
"""
import os
import re
import sys
import tempfile


def _setup():
    tmp = tempfile.mkdtemp(prefix="redops-export-")
    os.environ["REDOPS_DATA"] = tmp
    from redops import db
    db.use_data_dir(tmp)   # env alone is too late: DATA_DIR binds at import
    db.init_db()
    conn = db.connect()
    ours = db.insert(conn, "engagements",
                     {"name": "ours", "scope": "", "notes": "", "created_at": db.now()})
    other = db.insert(conn, "engagements",
                      {"name": "other", "scope": "", "notes": "", "created_at": db.now()})
    tid = db.insert(conn, "targets", {"engagement_id": ours, "ip": "10.10.0.1"})
    conn.commit()
    return conn, ours, other, tid


def test_no_cross_engagement_leak():
    from redops import db, export
    conn, ours, other, tid = _setup()
    db.add_event(conn, "wire", "output", "SECRET-FROM-OTHER-ENGAGEMENT",
                 engagement_id=other)
    db.add_event(conn, "wire", "output", "ours-only-capture", engagement_id=ours)
    conn.commit()
    md = export.build_markdown(ours)
    assert "SECRET-FROM-OTHER-ENGAGEMENT" not in md, \
        "another engagement's capture leaked into the report"
    assert "ours-only-capture" in md, "our own unattributed capture went missing"
    print("  leak: OK — other engagement's captures absent, ours present")


def test_output_cannot_forge_report_structure():
    from redops import db, export
    conn, ours, other, tid = _setup()
    # a capture that tries to close its fence and inject a top-level section
    hostile = "benign line\n```\n## Forged Section\nattacker text\n"
    db.add_event(conn, "wire", "output", hostile, target_id=tid, engagement_id=ours)
    conn.commit()
    md = export.build_markdown(ours)
    # the markdown source legitimately CONTAINS "## Forged Section" as fenced
    # content — what matters is the RENDERED document, so assert on the HTML.
    html = export.md_to_html(md)
    headings = re.findall(r"<h[12][^>]*>(.*?)</h[12]>", html)
    assert "Forged Section" not in headings, \
        f"captured output forged a report heading: {headings}"
    assert "Forged Section" in html, "the text itself should still be present, in a code block"
    # and the fence must be sized past the hostile content
    assert re.search(r"^\s*`{4,}", md, re.M), "block was not fenced past its content"
    print("  injection: OK — rendered as code, not a heading; headings=%s" % headings)


def test_output_is_truncated():
    from redops import db, export
    conn, ours, other, tid = _setup()
    huge = "A" * 50_000
    db.add_event(conn, "wire", "output", huge, target_id=tid, engagement_id=ours)
    conn.commit()
    md = export.build_markdown(ours)
    assert "A" * 50_000 not in md, "a 50 KB capture was rendered untruncated"
    assert "truncated" in md, "truncation happened but was not disclosed"
    print(f"  truncation: OK — 50 KB capture bounded, report {len(md):,}B")


def test_caption_cannot_inject_an_attribute():
    """The report is opened in a browser. _inline escaped with quote=False and
    then interpolated into alt=""/src="", so a caption of `" onerror="alert(1)`
    became a live handler."""
    from html.parser import HTMLParser

    from redops import export

    class _Attrs(HTMLParser):
        def __init__(self):
            super().__init__()
            self.found = set()

        def handle_starttag(self, tag, attrs):
            self.found |= {a for a, _ in attrs}

    out = export._inline('![" onerror="alert(1)](x.png)')
    # The escaped text legitimately CONTAINS "onerror=" inside the alt value, so
    # grepping the string gives a false positive — parse it and ask the parser
    # which attributes the tag actually has.
    p = _Attrs()
    p.feed(out)
    assert p.found <= {"alt", "src", "style"}, f"injected attributes {p.found} in {out}"
    assert "&quot;" in out, f"quotes were not escaped: {out}"
    out2 = export._inline("[click](javascript:alert(1))")
    href = re.search(r'href="([^"]*)"', out2)
    assert href and not href.group(1).lower().startswith("javascript:"), \
        f"script URL survived: {out2}"
    print(f"  attribute injection: OK — tag attrs={sorted(p.found)}, javascript: neutralised")


def test_overflow_path_cannot_escape_the_transcript_dir():
    """meta_json is attacker-influenced (POST /api/events takes arbitrary meta),
    so an overflow pointing outside data/transcript/ would read that file into
    the report — the operator token, for instance."""
    from redops import db, export
    conn, ours, other, tid = _setup()
    secret = db.DATA_DIR / "operator.token"
    secret.write_text("SUPER-SECRET-OPERATOR-TOKEN")
    db.add_event(conn, "wire", "output", "placeholder", target_id=tid,
                 engagement_id=ours, meta={"overflow": "../operator.token"})
    db.add_event(conn, "wire", "output", "placeholder2", target_id=tid,
                 engagement_id=ours, meta={"overflow": str(secret)})
    conn.commit()
    md = export.build_markdown(ours)
    assert "SUPER-SECRET-OPERATOR-TOKEN" not in md, \
        "overflow path escaped the transcript dir and leaked a file into the report"
    print("  overflow traversal: OK — token not embedded in the report")


def test_payload_body_cannot_forge_structure():
    from redops import db, export
    conn, ours, other, tid = _setup()
    db.insert(conn, "payloads", {"engagement_id": ours, "technique": "t",
                                 "body": "x\n```\n## Forged By Payload\ny",
                                 "created_at": db.now()})
    conn.commit()
    html = export.md_to_html(export.build_markdown(ours))
    heads = re.findall(r"<h[12][^>]*>(.*?)</h[12]>", html)
    assert "Forged By Payload" not in heads, f"payload forged a heading: {heads}"
    print("  payload fence: OK — hostile payload body stays inside its block")


def test_report_still_has_its_content():
    """The fixes must not gut the report."""
    from redops import db, export
    conn, ours, other, tid = _setup()
    db.add_event(conn, "agent", "reasoning", "pivoting to the DC", target_id=tid,
                 engagement_id=ours)
    db.insert(conn, "findings", {"engagement_id": ours, "target_id": tid,
                                 "title": "anonymous LDAP bind", "severity": "high",
                                 "description": "null bind permitted",
                                 "created_at": db.now()})
    conn.commit()
    md = export.build_markdown(ours)
    for must in ("10.10.0.1", "anonymous LDAP bind", "pivoting to the DC"):
        assert must in md, f"report lost {must!r}"
    print("  content: OK — targets, findings and reasoning all present")


if __name__ == "__main__":
    n = 0
    for t in (test_no_cross_engagement_leak, test_output_cannot_forge_report_structure,
              test_output_is_truncated, test_caption_cannot_inject_an_attribute,
              test_overflow_path_cannot_escape_the_transcript_dir,
              test_payload_body_cannot_forge_structure,
              test_report_still_has_its_content):
        t()
        n += 1
    print(f"\nPASS — {n}/7 report cases")
    sys.exit(0)
