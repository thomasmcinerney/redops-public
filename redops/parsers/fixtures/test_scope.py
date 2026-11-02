"""Regression for the shared scope verdict (redops/scope.py) — proves the extracted
library enforces exactly what the scope_guard hook did. resolve=False keeps tests
DNS-free and deterministic (name-level checks still apply).

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_scope
"""
import sys


def _v(cmd, sin, sout):
    from redops import scope
    return scope.command_verdict(cmd, sin, sout, resolve=False)


def test_no_scope_allows():
    ok, _ = _v("nmap 8.8.8.8", [], [])
    assert ok, "empty scope => allowed"


def test_blocklist_ip():
    ok, why = _v("curl http://10.10.10.5/x", [], ["10.10.10.0/24"])
    assert not ok and "out of scope" in why, why


def test_allowlist_ip():
    ok, _ = _v("nmap 192.0.2.13", ["192.0.2.0/24"], [])
    assert ok, "in-allowlist IP allowed"
    ok2, why = _v("nmap 192.168.99.9", ["192.0.2.0/24"], [])
    assert not ok2 and "outside the allowed scope" in why, why


def test_never_block_loopback():
    # loopback passes even under an allowlist that doesn't include it
    ok, _ = _v("nmap 127.0.0.1", ["192.0.2.0/24"], [])
    assert ok, "loopback is NEVER_BLOCK"


def test_hostname_blocklist_by_name():
    # no DNS: blocked purely by name suffix match
    ok, why = _v("curl https://evil.corp.example/x", [], ["corp.example"])
    assert not ok and "blocklist" in why, why


def test_hostname_allowlist_suffix():
    ok, _ = _v("curl http://app.examplecorp.ai/", ["examplecorp.ai"], [])
    assert ok, "subdomain of an allowed host is in scope"
    ok2, why = _v("curl http://app.other.ai/", ["examplecorp.ai"], [])
    assert not ok2 and "outside the allowed scope" in why, why


def test_local_command_passes():
    # a command with no network target isn't gated by scope
    ok, _ = _v("whoami", ["192.0.2.0/24"], [])
    assert ok, "non-networked command allowed"


def main():
    tests = [test_no_scope_allows, test_blocklist_ip, test_allowlist_ip,
             test_never_block_loopback, test_hostname_blocklist_by_name,
             test_hostname_allowlist_suffix, test_local_command_passes]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {e!r}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(tests) - failed}/{len(tests)} scope cases")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
