#!/usr/bin/env python3
"""Kimi hook (PreToolUse, matcher Bash): scope enforcement.

Reads tool_input.command from stdin JSON and applies the ONE scope decision —
`redops.scope.check_command` — exiting 2 to block.

This file used to carry its OWN copy of the extraction and matching logic, and
it rotted exactly the way redops/scope.py's header warns about: IPv4-only
regex (an `nmap -6` target sailed straight through), no numeric-encoding check
(`nmap 134744072` reached 8.8.8.8), no CIDR breadth check, no v4-mapped-v6
handling. Every hardening round went into scope.py and none of it reached here,
so the hook silently enforced a weaker policy than the broker. Importing the
shared module is the fix; do NOT reintroduce a local implementation.

Fail-open on any error — this hook is observational, layered in front of the
exec broker, which fails closed. But MISCONFIGURATION screams on stderr, never
silent: a guard that is quietly not running is worse than no guard.
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))                 # _common
sys.path.insert(0, str(_HERE.parent))          # repo root, for `redops.scope`
try:
    from _common import connect_ro, current_engagement, guard_enabled, read_stdin_json, scope_lists
except ImportError as e:
    print(f"[RedOps scope_guard] MISCONFIGURED - cannot import _common ({e}); "
          f"failing open, NO scope enforcement active", file=sys.stderr)
    sys.exit(0)
try:
    from redops import scope
except ImportError as e:
    print(f"[RedOps scope_guard] MISCONFIGURED - cannot import redops.scope ({e}); "
          f"failing open, NO scope enforcement active", file=sys.stderr)
    sys.exit(0)

import ipaddress
import os
import re
import subprocess


# Operator-side addresses that are never blocked, even in allowlist mode — your
# own box is not a target. Loopback + VPN range + every local interface IP + any
# declared callback (REDOPS_CALLBACK, for a lab that NATs you onto the target
# subnet). This is what stops `msfvenom LHOST=<you>` and reverse-shell one-liners
# from being blocked: LHOST is your callback address, not a host you're attacking.
def _own_networks():
    nets = list(scope.DEFAULT_NEVER_BLOCK)
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True,
                             text=True, timeout=5).stdout
        for ip in re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out):
            nets.append(ipaddress.ip_network(ip + "/32"))
    except (OSError, subprocess.SubprocessError):
        pass
    for var in ("REDOPS_VPN_NET", "REDOPS_CALLBACK"):
        for cidr in (os.environ.get(var, "") or "").split(","):
            cidr = cidr.strip()
            if cidr:
                try:
                    nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
    return nets


def main() -> int:
    data = read_stdin_json()
    tool_input = data.get("tool_input") or {}
    command = tool_input.get("command") or ""
    if not command:
        return 0
    conn = connect_ro()
    if not conn:
        return 0
    try:
        eng = current_engagement(conn)
        if eng is None:
            return 0
        if not guard_enabled(conn):
            return 0                        # toggled off: no scope enforcement
        scope_in, scope_out = scope_lists(conn, eng)
        decision = scope.check_command(command, scope_in, scope_out,
                                       never_block=_own_networks(),
                                       cwd=tool_input.get("cwd"))
        if decision.blocked:
            print(f"[RedOps scope_guard] BLOCKED: {decision.reason}. Do not retry "
                  f"it against the same target; check `redops scope` if you "
                  f"believe this is wrong.", file=sys.stderr)
            return 2
        return 0
    except Exception:
        return 0  # fail-open
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
