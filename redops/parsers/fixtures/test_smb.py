"""SMB share parser fixtures (D1) — pure parse, no DB.

Three tools, three formats, one question: what can I reach without credentials.
Proves a writable share becomes a write-primitive fact (what the engine scores),
and that smbclient's VISIBLE-but-unproven listing is not claimed as readable.

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_smb
"""
import sys

from redops.parsers import smb as P

SMBCLIENT = """\

\tSharename       Type      Comment
\t---------       ----      -------
\tADMIN$          Disk      Remote Admin
\tC$              Disk      Default share
\tIPC$            IPC       Remote IPC
\tbackups         Disk      nightly dumps
SMB1 disabled -- no workgroup available
"""

SMBMAP = """\
[+] IP: 192.0.2.13:445\tName: DC01.examplelab.ai
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        backups                                                 READ, WRITE     nightly dumps
        shared                                                  READ ONLY       team share
"""

NXC = """\
SMB         192.0.2.13  445    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:examplelab.ai) (signing:True)
SMB         192.0.2.13  445    DC01             [+] examplelab.ai\\:
SMB         192.0.2.13  445    DC01             Share           Permissions     Remark
SMB         192.0.2.13  445    DC01             backups         READ,WRITE      nightly dumps
SMB         192.0.2.13  445    DC01             shared          READ            team share
"""


def _facts(r, pred):
    return [f for f in r.facts if f.predicate == pred]


def test_smbmap_write_is_a_primitive():
    r = P.to_result(SMBMAP, host_hint="192.0.2.13")
    w = _facts(r, "writable-by")
    assert len(w) == 1 and "backups" in w[0].subject, f"writable share not a fact: {r.facts}"
    assert _facts(r, "readable-by"), "readable share missing"
    assert r.findings and r.findings[0].severity == "critical", \
        f"writable null-session share must be critical: {r.findings}"
    print(f"  smbmap: OK — {r.summary}")


def test_nxc_banner_and_shares():
    r = P.to_result(NXC, host_hint="192.0.2.13")
    names = {e["name"] for e in r.entities}
    assert "examplelab.ai" in names, f"domain not parsed from banner: {names}"
    assert r.target_updates.get("os") == "Windows", r.target_updates
    assert any("backups" in f.subject for f in _facts(r, "writable-by")), r.facts
    assert r.services and r.services[0].port == 445, "smb service not recorded"
    print(f"  nxc: OK — {r.summary}")


def test_nxc_status_lines_are_not_shares():
    """ABSENCE assertion — the class of bug presence-only tests cannot see.
    nxc's [+]/[-]/[*] status lines sit in the share-name column, so a line was
    parsed as a share literally named '[+]'. The old test asserted the real
    shares were present and never that junk was absent; its own output said
    '3 shares' for 2."""
    r = P.to_result(NXC, host_hint="192.0.2.13")
    shares = {e["name"].rsplit("/", 1)[-1] for e in r.entities if e["type"] == "file"}
    junk = {s for s in shares if s.startswith(("[", "-")) or s in ("Share", "-----")}
    assert not junk, f"status/header lines parsed as shares: {junk}"
    assert shares == {"backups", "shared"}, f"expected exactly the 2 real shares: {shares}"
    assert "2 shares" in r.summary, f"share count wrong: {r.summary}"
    print(f"  nxc junk: OK — shares={sorted(shares)}, {r.summary}")


def test_smbclient_does_not_claim_access():
    """`smbclient -L` proves shares are VISIBLE, not readable. Claiming otherwise
    would stamp an observed fact we have no evidence for."""
    r = P.to_result(SMBCLIENT, host_hint="192.0.2.13")
    assert not _facts(r, "readable-by"), "smbclient listing must not claim readability"
    assert not _facts(r, "writable-by"), "smbclient listing must not claim writability"
    assert _facts(r, "shares"), "shares should still be recorded as nodes"
    assert not r.findings, "a bare listing with no proven access is not a finding"
    print(f"  smbclient: OK — {r.summary} (visible, no access claimed)")


def test_unparseable_yields_no_facts():
    r = P.to_result("NT_STATUS_ACCESS_DENIED listing \\\\*\n")
    assert r.status == "unrecognized", r.status
    assert not r.facts and not r.findings, "unrecognized must carry nothing"
    print("  refusal: OK — access denied produced zero facts")


if __name__ == "__main__":
    n = 0
    for t in (test_smbmap_write_is_a_primitive, test_nxc_banner_and_shares,
              test_nxc_status_lines_are_not_shares,
              test_smbclient_does_not_claim_access, test_unparseable_yields_no_facts):
        t()
        n += 1
    print(f"\nPASS — {n}/5 smb cases")
    sys.exit(0)
