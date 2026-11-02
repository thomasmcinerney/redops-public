"""Envelope contract (D1) — the seam where the opts bug shipped.

Every parser fixture tested `to_result(...)` directly, so nothing exercised the
envelope the EXECUTOR actually builds. `_execute_scanner` never populated
`params["opts"]`, so ldapsearch and smb read an empty dict, concluded every run
was anonymous, and fabricated "Anonymous LDAP bind" / "SMB null session"
findings into reports — the exact direction that manufactures false positives.

So this asserts the seam, not the parsers: whatever the executor puts in the
envelope is what parse() reads, and an AUTHENTICATED run must not be reported as
anonymous.

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_envelope
"""
import os
import sys

from redops import tools

LDIF = """\
dn: CN=Administrator,CN=Users,DC=corp,DC=local
objectClass: user
sAMAccountName: Administrator
"""

SMB = """\
        backups                                                 READ, WRITE     dumps
"""


def test_executor_actually_passes_opts_through():
    """RUN the executor and capture what the parser receives.

    The first version of this test regexed inspect.getsource() for the key name —
    which passes with `"opts": {}` and would not have caught the bug it was
    written for. Reading source is one layer off the real path, the exact
    criticism that motivated this file. So: register a fake tool, stub the
    subprocess, and assert on the envelope the parser is HANDED."""
    import subprocess as sp
    import tempfile

    from redops import db

    seen = {}

    def _spy(envelope):
        seen.update(envelope)
        from redops.parsers import ExtractResult
        return ExtractResult(status="empty", summary="spy")

    os.environ["REDOPS_DATA"] = tempfile.mkdtemp(prefix="redops-env-")
    db.use_data_dir(os.environ["REDOPS_DATA"])
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements",
                    {"name": "e", "scope": "", "notes": "", "created_at": db.now()})
    tid = db.insert(conn, "targets", {"engagement_id": eng, "ip": "10.0.0.5"})
    rid = db.insert(conn, "tool_runs", {"engagement_id": eng, "target_id": tid,
                                        "tool": "spytool", "command": "", "status": "running",
                                        "actor": "operator", "started_at": db.now()})
    conn.commit()

    spec = {"kind": "scanner", "bin": "echo", "label": "spy", "timeout": 5,
            "default_port": 389, "target": {"flag": "-H", "url": True, "scheme": "ldap"},
            "output": {"dest": "stdout", "parser": "spy"},
            "options": {"binddn": {"type": "str", "default": "", "label": "b", "arg": "-D",
                                   "pattern": r"^.{0,80}$"}},
            "presets": {}}
    tools.PARSERS["spy"] = _spy
    tools.TOOL_SPECS["spytool"] = spec
    real_run = sp.run
    sp.run = lambda *a, **k: sp.CompletedProcess(a[0] if a else [], 0, "out", "")
    try:
        tools._execute_scanner(rid, eng, tid, "10.0.0.5", "spytool", spec,
                               {"binddn": "CN=svc"}, "operator")
    finally:
        sp.run = real_run
        tools.PARSERS.pop("spy", None)
        tools.TOOL_SPECS.pop("spytool", None)

    params = seen.get("params") or {}
    assert params.get("opts", {}).get("binddn") == "CN=svc", (
        f"the executor did not pass opts VALUES through: params={params} — a parser "
        f"that stamps trust from invocation flags would silently mis-stamp")
    assert params.get("ip") == "10.0.0.5", params
    print(f"  envelope: OK — parser received opts={params['opts']}")


def test_authenticated_ldap_is_not_reported_anonymous():
    env = {"tool": "ldapsearch", "status": "done", "output": LDIF,
           "params": {"ip": "10.0.0.1", "has_target": True,
                      "opts": {"binddn": "CN=svc,DC=corp,DC=local"}}}
    r = tools.PARSERS["ldapsearch"](env)
    titles = [f.title for f in r.findings]
    assert not any("Anonymous" in t for t in titles), \
        f"authenticated bind reported as anonymous: {titles}"
    # and the anonymous case still IS a finding
    env["params"]["opts"] = {}
    r2 = tools.PARSERS["ldapsearch"](env)
    assert any("Anonymous" in f.title for f in r2.findings), \
        "anonymous bind should still be a finding"
    print("  ldapsearch: OK — bind DN suppresses the anonymous finding, absence keeps it")


def test_authenticated_smb_is_not_reported_null_session():
    env = {"tool": "smb", "status": "done", "output": SMB,
           "params": {"ip": "10.0.0.1", "has_target": True,
                      "opts": {"user": "corp\\svc"}}}
    r = tools.PARSERS["smb"](env)
    titles = [f.title for f in r.findings]
    assert not any("null session" in t.lower() for t in titles), \
        f"authenticated SMB reported as a null session: {titles}"
    env["params"]["opts"] = {}
    r2 = tools.PARSERS["smb"](env)
    assert any("null session" in f.title.lower() for f in r2.findings), \
        "null session should still be a finding"
    print("  smb: OK — user suppresses the null-session finding, absence keeps it")


def test_every_scanner_parser_survives_a_bare_envelope():
    """A parser must not explode when a key it wants is absent — it should degrade
    to its safe reading, never crash the executor mid-run."""
    for name, fn in tools.PARSERS.items():
        r = fn({"tool": name, "status": "done", "output": "", "params": {}})
        assert r is not None, f"{name} returned None on a bare envelope"
        assert not r.facts, f"{name} invented facts from empty output"
        assert not r.findings, f"{name} invented findings from empty output"
    print(f"  bare envelope: OK — all {len(tools.PARSERS)} parsers degrade without facts")


if __name__ == "__main__":
    n = 0
    for t in (test_executor_actually_passes_opts_through,
              test_authenticated_ldap_is_not_reported_anonymous,
              test_authenticated_smb_is_not_reported_null_session,
              test_every_scanner_parser_survives_a_bare_envelope):
        t()
        n += 1
    print(f"\nPASS — {n}/4 envelope cases")
    sys.exit(0)
