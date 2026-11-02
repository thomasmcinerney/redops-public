"""Unified scope-decision tests. No network needed except a couple that resolve
localhost; the IP-literal and hostname-parse paths are pure. Run:
    uv run python scripts/test_scope.py   (or pytest)

These lock the holes Kimi found in the old split implementations: IPv6 bypass
(nmap -6 sailed through the IPv4-only hook) and hostname handling.
"""
from redops import scope


def D(cmd, sin, sout, **kw):
    return scope.check_command(cmd, sin, sout, resolve=kw.get("resolve", False))


def test_ipv4_out_of_scope_blocked():
    d = scope.check_command("nmap -sV 8.8.8.8", ["10.0.0.0/24"], [], resolve=False)
    assert d.blocked and "8.8.8.8" in d.reason


def test_ipv4_in_scope_allowed():
    assert scope.check_command("nmap 10.0.0.5", ["10.0.0.0/24"], [], resolve=False).allowed


def test_ipv6_out_of_scope_blocked():
    """The bypass: an IPv6 target used to slip the IPv4-only guard entirely."""
    d = scope.check_command("nmap -6 2001:4860:4860::8888", ["10.0.0.0/24"], [], resolve=False)
    assert d.blocked, "IPv6 target must be judged, not ignored"


def test_ipv6_bracketed_extracted():
    assert "2001:db8::1" in scope.extract_ips("curl 'http://[2001:db8::1]:8080/'")


def test_ipv6_in_scope_allowed():
    assert scope.check_command("nmap -6 2001:db8::5", ["2001:db8::/48"], [], resolve=False).allowed


def test_blocklist_wins():
    d = scope.check_command("nmap 10.0.0.5", [], ["10.0.0.5/32"], resolve=False)
    assert d.blocked


def test_no_scope_allows():
    assert scope.check_command("nmap 10.0.0.5", [], [], resolve=False).allowed


def test_loopback_never_blocked():
    # allowlist that excludes loopback still lets localhost control traffic pass
    assert scope.check_command("curl http://127.0.0.1:9100/", ["10.0.0.0/24"], [],
                               resolve=False).allowed


def test_hostname_extraction_ignores_flags_and_paths():
    names = scope.extract_hostnames("nmap -sV --script=http-title example.com /tmp/out.txt")
    assert names == ["example.com"]


def test_hostname_from_url():
    assert scope.extract_hostnames("curl https://user@app.example.com:8443/x") == ["app.example.com"]


def test_hostname_blocklist_by_name_no_dns():
    """A blocklisted domain is caught by NAME even if it never resolves."""
    d = scope.check_command("curl http://evil.example.com/", ["10.0.0.0/24"],
                            ["evil.example.com"], resolve=False)
    assert d.blocked and "evil.example.com" in d.reason


def test_bare_ip_hostname_only_allowlist_blocked():
    # a hostname-only allowlist can't prove a bare IP in scope -> refuse outright,
    # and say what would fix it. (Was: allowed-but-undetermined, left to the cage.)
    d = scope.check_command("nmap 10.0.0.5", ["app.example.com"], [], resolve=False)
    assert d.blocked and "scope_set" in d.reason
    assert d.undetermined == []


def test_unresolved_hostname_blocked_not_deferred():
    d = scope.check_command("curl http://nonexistent.invalid/", ["10.0.0.0/24"], [],
                            resolve=True)
    # not in the allowlist -> out of scope, decided by name with no DNS involved
    assert d.blocked and "nonexistent.invalid" in d.reason
    assert d.undetermined == []


def test_decision_lists_targets():
    d = scope.check_command("nmap 10.0.0.5 10.0.0.9", ["10.0.0.0/24"], [], resolve=False)
    assert d.allowed and len([t for t in d.targets if t[1] == "in"]) == 2


# --- regression guards for Kimi's exec-broker security review ---------------

def _blocked(cmd, sin=("198.51.100.0/24",), sout=()):
    return scope.check_command(cmd, list(sin), list(sout), resolve=False).blocked


def test_F1_decimal_ip_blocked():
    assert _blocked("nmap 134744072")            # = 8.8.8.8


def test_F2_hex_ip_blocked():
    assert _blocked("nmap 0x8080808")            # = 8.8.8.8


def test_F3_octal_dotted_blocked():
    # nmap reads 010.0.0.5 as 10.0.0.5, libc as 8.0.0.5 — both OOS here, and the
    # non-canonical form is refused as evasion regardless.
    assert _blocked("nmap 010.0.0.5")


def test_F4_v6_mapped_hex_blocked():
    assert _blocked("nmap -6 ::ffff:0808:0808")  # = ::ffff:8.8.8.8 -> 8.8.8.8


def test_F4_v6_mapped_blocklist_mode():
    # blocklist-only: a v4-mapped v6 must match a v4 blocklist entry
    assert scope.check_command("curl http://[::ffff:8.8.8.8]/", [], ["8.8.8.0/24"],
                               resolve=False).blocked


def test_F5_encoding_in_chain_blocked():
    assert _blocked("echo ok; nmap 134744072")


def test_encoded_in_scope_still_allowed():
    # a numeric encoding of an IN-scope address is fine
    d = scope.check_command("nmap 3232294404", ["198.51.100.0/24"], [], resolve=False)
    assert d.allowed          # 3232294404 = 198.51.100.4


def test_no_false_positive_on_ports_rates_timing():
    for cmd in ["nmap -p 22 198.51.100.5", "nmap --max-rate 100000 198.51.100.5",
                "nmap -T4 -p80,443 198.51.100.5", "ping -c 4 198.51.100.5"]:
        assert not _blocked(cmd), cmd


def test_F1_numeric_host_in_url_blocked():
    for cmd in ["curl http://134744072/", "wget http://0x08080808/",
                "curl http://10.0.0.5@134744072/", "curl 'http://134744072:8080/x'"]:
        assert _blocked(cmd, sin=("10.0.0.0/24",)), cmd


def test_F2_boolean_flag_no_longer_skips_target():
    # -n (no-DNS) and -s (silent) are boolean; the encoded target after them must
    # still be judged now that the flag list is gone.
    for cmd in ["nmap -n 134744072", "curl -s 134744072", "ping -n 134744072"]:
        assert _blocked(cmd, sin=("10.0.0.0/24",)), cmd


def test_F3_cidr_breadth_judged():
    # a /24 is not in scope of a /25 — 128 hosts out
    assert scope.check_command("nmap 10.0.0.0/24", ["10.0.0.0/25"], [], resolve=False).blocked
    # a subnet fully inside scope is fine
    assert scope.check_command("nmap 10.0.0.0/26", ["10.0.0.0/24"], [], resolve=False).allowed
    # a range overlapping a blocklist entry is refused
    assert scope.check_command("nmap 10.0.0.0/24", [], ["10.0.0.5/32"], resolve=False).blocked


def test_F5_nat64_mapped_to_v4():
    assert scope.check_command("ping 64:ff9b::8.8.8.8", [], ["8.8.8.0/24"],
                               resolve=False).blocked


def test_large_number_arg_is_accepted_cost_of_dropping_flaglist():
    # small numeric args (ports/rates/counts) still fine via the 0/8 drop
    for cmd in ["nmap -p 22 10.0.0.5", "nmap --max-rate 100000 10.0.0.5",
                "sleep 30", "head -30 f", "chmod 0755 x"]:
        assert not _blocked(cmd, sin=("10.0.0.0/24",)), cmd


def test_explicit_blocklist_beats_never_block():
    # loopback is in DEFAULT_NEVER_BLOCK, but an explicit scope_out entry wins
    assert scope.check_command("curl http://127.0.0.1/", [], ["127.0.0.0/8"],
                               resolve=False).blocked


# --- determinism: the verdict may not depend on DNS -------------------------

class _patched_resolver:
    """Swap scope.resolve_all for the duration of a with-block."""

    def __init__(self, fn):
        self.fn = fn

    def __enter__(self):
        self.orig = scope.resolve_all
        scope.resolve_all = self.fn

    def __exit__(self, *exc):
        scope.resolve_all = self.orig


def _explode(names):
    raise AssertionError("DNS must not be consulted on this path")


def test_allow_path_never_resolves():
    # allowlist-only engagement (the normal case): no blocklist for a name to
    # resolve into, so nothing may call DNS even with resolve=True.
    with _patched_resolver(_explode):
        assert scope.check_command("nmap 198.51.100.5", ["198.51.100.0/24"], [],
                                   resolve=True).allowed
        assert scope.check_command("curl https://app.example.com/",
                                   ["app.example.com"], [], resolve=True).allowed
        assert scope.check_command("curl https://evil.example.com/",
                                   ["app.example.com"], [], resolve=True).blocked


def test_dns_can_block_but_never_allow():
    hit = {"app.example.com": {"10.0.0.5"}}
    # NEVER ALLOW: resolving into the allowed net does not put a name in scope —
    # the operator has to name it, or the verdict would change with the DNS reply.
    with _patched_resolver(lambda names: hit):
        d = scope.check_command("curl http://app.example.com/", ["10.0.0.0/24"], [],
                                resolve=True)
        assert d.blocked and "scope_set" in d.reason
    # CAN BLOCK: in blocklist-only mode a name resolving into a blocked range is
    # still caught — that is the one thing resolution is kept for.
    with _patched_resolver(lambda names: {"dns.example": {"8.8.8.8"}}):
        assert scope.check_command("curl http://dns.example/", [], ["8.8.8.0/24"],
                                   resolve=True).blocked


def test_same_command_same_verdict():
    cmds = ["nmap -sV 198.51.100.5", "curl http://vault.devarmor.lab/",
            "python3 -m http.server 8000", "nmap 134744072"]
    for cmd in cmds:
        seen = {(scope.check_command(cmd, ["198.51.100.0/24"], [],
                                     resolve=True).allowed) for _ in range(5)}
        assert len(seen) == 1, f"{cmd} gave mixed verdicts: {seen}"


def test_undetermined_is_always_empty():
    for cmd in ["curl http://nonexistent.invalid/", "nmap 10.0.0.5", "ls -la"]:
        for sin in (["198.51.100.0/24"], ["app.example.com"], []):
            d = scope.check_command(cmd, list(sin), [], resolve=False)
            assert d.undetermined == [], (cmd, sin, d.undetermined)


# --- false positives that blocked real engagement work ----------------------

def test_module_arg_is_not_a_hostname():
    for cmd in ["python3 -m http.server 8000", "python3 -m json.tool out",
                "./venv/bin/python -m redops.api"]:
        assert scope.extract_hostnames(cmd) == [], cmd
        assert not _blocked(cmd), cmd


def test_search_pattern_is_not_a_hostname():
    for cmd in ["grep -r urllib.request src/", "grep 192.168.188 hosts",
                "rg example.com", "sed -n s/a.b/c/p"]:
        assert scope.extract_hostnames(cmd) == [], cmd
    # no DNS name means no name-based block; a numeric pattern is still judged as
    # an IP (see test_grep_pattern_skip_does_not_hide_an_ip) and that is intended.
    for cmd in ["grep -r urllib.request src/", "rg example.com", "sed -n s/a.b/c/p"]:
        assert not _blocked(cmd), cmd


def test_numeric_last_label_is_not_a_hostname():
    # version strings and partial IPs end in a numeric label; a TLD never does,
    # so none of these are DNS names any more
    for cmd in ["searchsploit openssh 9.6", "echo whistle 2.9.98", "ls 1.2.3"]:
        assert scope.extract_hostnames(cmd) == [], cmd


def test_version_string_still_judged_as_ip_known_cost():
    """DOCUMENTED, DELIBERATE false positive — do not 'fix' this by relaxing the
    numeric rule. `9.6` decodes to 9.0.0.6 and `2.9.98` to 2.9.0.98 exactly as
    `nmap 8.2056` decodes to 8.0.8.8, and that short-form encoding is the bypass
    class the numeric check exists to close. Static text cannot tell a version
    from a short-form address, so an out-of-scope decode is refused either way.
    The block is now at least deterministic and self-explaining; the workaround
    is to drop the version from the command."""
    for cmd in ["searchsploit openssh 9.6", "echo whistle 2.9.98"]:
        d = scope.check_command(cmd, ["198.51.100.0/24"], [], resolve=False)
        assert d.blocked and "numeric" in d.reason, cmd


def test_local_artifact_tokens_are_not_hostnames():
    for cmd in ["unzip backup.zip", "ssh -i key.pem 198.51.100.5",
                "python3 fire39930.py", "nmap 198.51.100.5 > scan.log"]:
        assert not _blocked(cmd), cmd


def test_grep_pattern_skip_does_not_hide_an_ip():
    # the skips above suppress HOSTNAME extraction only — a real IP target in a
    # skipped position is still judged, so neither is a bypass.
    assert _blocked("grep 8.8.8.8 hosts")
    assert _blocked("python3 -m http.server --bind 8.8.8.8")
    assert _blocked("grep 134744072 hosts")


def test_vhost_in_scope_by_name():
    # the real workflow: operator scopes the lab domain, subdomains follow
    d = scope.check_command("curl -H 'Host: vault.devarmor.lab' http://vault.devarmor.lab/",
                            ["198.51.100.0/24", "devarmor.lab"], [], resolve=False)
    assert d.allowed


def test_tool_paths_honor_scope_guard_toggle():
    import json
    import sqlite3
    from redops import tools

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE wiretail_state (key TEXT PRIMARY KEY, value TEXT)")
    conn.executemany(
        "INSERT INTO wiretail_state (key, value) VALUES (?, ?)",
        [("scope_in:1", json.dumps(["192.168.117.30/32"])),
         ("set:scope_guard", "0")],
    )
    assert tools._command_scope_ok(conn, 1, "printf os.popen")[0]
    assert tools._scope_ok(conn, 1, "8.8.8.8")[0]

    conn.execute("UPDATE wiretail_state SET value=? WHERE key=?",
                 ("1", "set:scope_guard"))
    assert not tools._command_scope_ok(conn, 1, "printf os.popen")[0]
    assert not tools._scope_ok(conn, 1, "8.8.8.8")[0]
    conn.close()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
