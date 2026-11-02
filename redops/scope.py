"""The ONE scope decision for RedOps — used by the exec broker, the tool runner,
and the agent hook, so they cannot diverge (they used to: the hook was IPv4-only
and the runner judged bare IPs only, each with different holes).

`check_command` extracts every target it can see in a command — IPv4 AND IPv6
literals, numeric-encoded IPs, and CIDR ranges — and returns a structured
Decision.

THE DECISION IS DETERMINISTIC: the same command against the same scope always
gets the same verdict. That is a hard requirement, not a nicety — an agent that
is blocked at random cannot tell "out of scope" from "unlucky", and burns the
engagement working around its own guard. Two rules keep it true:

  * DNS IS NEVER CONSULTED TO ALLOW. A name is in scope because the operator put
    it in scope, not because it happens to resolve into an allowed range today.
    Resolution is BLOCK-ONLY evidence, and it runs only when an IP blocklist
    exists for a name to resolve into — so the common allowlist-only engagement
    does no DNS at all.
  * EVERY NAME GETS A VERDICT. With an allowlist set, a name that matches
    nothing is out of scope, with a message saying how to put it in. There is no
    third "could not tell" state: `Decision.undetermined` is retained only so the
    JSON response shape stays stable, and is always empty.

The cost is honest and deliberate: a hostname that resolves into the allowed
range but was never named in scope is now refused until the operator adds it.
That is the right trade for an engagement tool — the fix is one `scope_set` call
and it is the same every time.

HONEST LIMITATION: static command-text analysis is guardrails, not a cage. A
target constructed at runtime (`python3 -c 'socket.connect(...)'`, a loop over
`10.0.0.$i`, a target read from a file) is invisible here. Real containment is
network-level (run the command in a scope-restricted netns/firewall); this module
is the fast pre-filter and the enforcement for the common literal-target case.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field

# IPv4 dotted-quad, and IPv6 (bracketed [::1] or bare, including a leading `::`).
# The v6 form must capture the WHOLE address (the old regex dropped the leading
# `::` of `::ffff:0808:0808`, so it failed to parse and was silently ignored).
_IP4 = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
_IP6 = r"\[[0-9A-Fa-f:.]+\]|(?<![:.\w])(?:::)?(?:[0-9A-Fa-f]{1,4}:){1,}[0-9A-Fa-f:.]*"
_IP_RE = re.compile(f"{_IP4}|{_IP6}")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                      r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.?$")

# A numeric-IP candidate: 1–4 dot-parts, each a decimal / 0-octal / 0x-hex integer.
# Scanners accept ALL of these and resolve them via inet_aton to a real address
# (`nmap 134744072` -> 8.8.8.8), so the guard must too — the single biggest
# bypass class was these sailing through unjudged.
_NUM_PART = r"(?:0[xX][0-9A-Fa-f]+|\d+)"
_NUMERIC_IP = re.compile(rf"^{_NUM_PART}(?:\.{_NUM_PART}){{0,3}}$")
_CANON_QUAD = re.compile(r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$")

# NAT64 well-known prefix (RFC 6052): 64:ff9b::/96 embeds a v4 address in its low
# 32 bits and is translated to it on a NAT64 network.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

# Never blocked, even in allowlist mode: loopback + link-local + the UNSPECIFIED
# ("any") address. 0.0.0.0/:: appear in commands as BIND addresses (`nc -l`,
# `python3 -m http.server --bind 0.0.0.0`, `ssh -L 0.0.0.0:...`), which open a
# listener on the operator's own box — they contact no remote host, so judging
# them as targets false-blocks every listener command. Operator VPN ranges are
# added by the caller (they are environment-specific). Loopback here does NOT
# mean loopback is a valid target — the engagement scope decides that; it means
# the guard won't block localhost control traffic.
DEFAULT_NEVER_BLOCK = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/32"),
    ipaddress.ip_network("::/128"),
]

_RESOLVE_BUDGET = 2.0     # seconds, total, per command
_MAX_NAMES = 8

# Bare tokens ending in these are local artifacts a command reads/writes, not
# network targets. Applied only to tokens that are not URLs and contain no
# path separator, so `http://host/shell.php` is still judged by its host.
_LOCAL_FILE_EXTS = (
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".log", ".txt", ".md", ".csv", ".json", ".jsonl", ".xml", ".yml", ".yaml",
    ".py", ".sh", ".php", ".pl", ".rb", ".js", ".ps1", ".bat", ".exe", ".dll",
    ".bin", ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".ovpn", ".conf",
    ".cfg", ".ini", ".sql", ".db", ".sqlite", ".bak", ".old", ".dat", ".dump",
    ".img", ".iso", ".pcap", ".pcapng", ".har", ".out", ".err", ".html", ".htm",
    # build/dev artifacts: `build.gradle`, `pom.properties`, `app.jar` are files
    # a command edits or compiles, not hosts — their last label passes the TLD
    # check (`gradle`, `properties`, `jar` are alphabetic), so extension is the
    # only signal that separates them from real hostnames.
    ".java", ".jar", ".class", ".gradle", ".properties", ".jsp", ".jspx",
    ".ftl", ".groovy", ".war", ".ear", ".so", ".o", ".a", ".go", ".rs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".toml", ".lock", ".ts", ".tsx",
    ".jsx", ".vue", ".lua", ".proto", ".tf", ".tfvars", ".hcl", ".sbt", ".kt",
    ".kts", ".scala", ".ipynb", ".vm", ".j2", ".tpl", ".cmake", ".mk",
)

# `-m mod.path` is a MODULE, not a host: `python3 -m http.server`, `-m json.tool`,
# `-m redops.api` were all DNS-resolved as hostnames and blocked.
_MODULE_FLAGS = {"-m", "--module"}

# The first non-flag argument of these is a PATTERN, not a target:
# `grep urllib.request src/`, `grep 192.168.188 hosts.txt`.
_PATTERN_TOOLS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk"}

# Skipping a token for either reason above cannot open a hole: it suppresses only
# HOSTNAME extraction, and an IP after `-m` or a grep pattern is still judged by
# extract_ips / numeric_ip_targets, which do no token skipping whatsoever.

# A real TLD is alphabetic (or an `xn--` IDN label) — never numeric. This is what
# separates a hostname from a dotted non-host: `192.168.188` (a grep pattern),
# `9.6` and `2.9.98` (version strings), `1.2.3` all end in a numeric label and
# used to be resolved as names. A trailing numeric label cannot be a hostname, so
# there is no target to lose.
_TLD_RE = re.compile(r"^(?:[A-Za-z]{2,24}|xn--[A-Za-z0-9-]{2,59})$")


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    # every target the check saw, as (label, in_or_out_verdict) — for the feed
    targets: list = field(default_factory=list)
    # DEPRECATED, ALWAYS EMPTY. Every target now gets a real verdict (see the
    # module docstring), so there is nothing for a caller to escalate. Retained
    # so the /api/exec response shape does not change under old clients — do not
    # branch on it, and do not start filling it again.
    undetermined: list = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return not self.allowed


def _v4_interpretations(token: str) -> set[str]:
    """Every canonical IPv4 a numeric token could mean to a scanner. Empty if the
    token is not a numeric-IP candidate. Computes BOTH the libc inet_aton reading
    (octal/hex/short forms honored) AND the all-decimal dotted reading — because
    nmap and libc DISAGREE on forms like `010.0.0.5` (nmap=10.0.0.5, libc=8.0.0.5),
    so the caller can block if ANY reading is out of scope."""
    if not _NUMERIC_IP.match(token):
        return set()
    forms: set[str] = set()
    try:
        forms.add(socket.inet_ntoa(socket.inet_aton(token)))   # libc semantics
    except OSError:
        pass
    parts = token.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):     # all-decimal reading
        try:
            if all(0 <= int(p, 10) <= 255 for p in parts):
                forms.add(".".join(str(int(p, 10)) for p in parts))
        except ValueError:
            pass
    # Drop interpretations in 0.0.0.0/8 ("this network", non-routable): a bare
    # count/duration/mode (`sleep 30`, `chmod 0755`, `head -30`) decodes there and
    # is NOT a reachable target — so it must not be judged or it false-blocks
    # every command with a small number. Any decimal below 2^24 lands here, which
    # is exactly the range that can't encode a routable target anyway; the real
    # bypasses (134744072 -> 8.8.8.8) decode above it and are kept.
    return {f for f in forms if not f.startswith("0.")}


def _mapped_v4(ip: "ipaddress._BaseAddress"):
    """The embedded IPv4 of a v4-mapped / v4-compatible / 6to4 / NAT64 IPv6
    address, else None — so `::ffff:8.8.8.8` and `64:ff9b::8.8.8.8` are judged
    against the v4 scope, not treated as an unrelated v6 no v4 rule can match."""
    if ip.version == 6:
        m = getattr(ip, "ipv4_mapped", None) or getattr(ip, "sixtofour", None)
        if m is None and ip in _NAT64:                          # NAT64 (RFC 6052)
            m = ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
        if m is None and int(ip) >> 32 == 0 and int(ip) != 0:   # ::a.b.c.d compat
            m = ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
        return m
    return None


def _host_of(token: str) -> str:
    """Reduce a token to its bare host: strip scheme://, userinfo@, path, port,
    and v6 brackets — so a numeric host hidden in a URL (`http://134744072/`) is
    exposed to the numeric check instead of skipped as 'a URL'."""
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", token)   # scheme
    t = t.split("/")[0].split("?")[0]                        # path/query
    t = t.split("@")[-1]                                     # userinfo
    if t.startswith("["):                                    # [v6]:port
        t = t[1:].split("]")[0]
    else:
        t = re.sub(r":\d+$", "", t)                          # host:port
    return t.strip()


def extract_ips(text: str) -> set[str]:
    out = set()
    for m in _IP_RE.finditer(text):
        tok = m.group().strip("[]").rstrip(":")
        # Context filter: a dotted-quad glued to the RIGHT of a word+colon is a
        # version or coordinate (`org.x:plugin:1.5.8.1`, `jruby-complete:9.2.4.0`),
        # not a host. A real host:port pair has the IP BEFORE the colon
        # (`1.2.3.4:8080`), and URLs/users put `/` or `@` before it — so a
        # `word:` prefix means "not a target". Static text analysis cannot do
        # better than this heuristic; the alternative (judging every quad) blocks
        # routine build-file edits mid-engagement.
        start = m.start()
        if m.group().count(".") == 3 and start >= 2 \
                and text[start - 1] == ":" and text[start - 2].isalnum():
            continue
        try:
            ipaddress.ip_address(tok)
            out.add(tok)
        except ValueError:
            continue
    return out


def numeric_ip_targets(command: str):
    """Scan the command for NUMERIC-encoded IPv4 targets and CIDR ranges that
    `extract_ips` (canonical dotted-quads only) misses. Returns
    (targets, networks, suspicious):
      targets    = {canonical_ip: label}   — numeric-decoded single IPs to judge
      networks   = [(ip_network, label)]   — CIDR targets whose BREADTH must be
                   checked (nmap 10.0.0.0/24 covers 256 hosts, not one)
      suspicious = [tokens]                — non-canonical dotted numeric forms,
                   blocked on sight as evasion.

    NO flag-based skipping: every token's host is decoded and judged. The old
    curated numeric-value-flag list was unwinnable — a boolean flag in it (`-n`,
    `-s`) skipped a real target, a valued flag missing from it false-blocked. The
    `0.0.0.0/8` drop in _v4_interpretations already suppresses the small-number
    false positives (ports/rates/counts) that list existed to prevent."""
    try:
        import shlex
        toks = shlex.split(command, posix=True)
    except ValueError:
        toks = command.split()
    targets: dict[str, str] = {}
    networks: list = []
    suspicious: list[str] = []
    for tok in toks:
        if tok.startswith("-"):
            continue
        # CIDR on the RAW token first — _host_of would strip `/24` as a URL path.
        # Judge the whole range's breadth, not just its base address.
        if "/" in tok and "://" not in tok:
            base, _, prefix = tok.partition("/")
            if prefix.isdigit() and 0 <= int(prefix) <= 128 and \
                    (_NUMERIC_IP.match(base) or ":" in base):
                try:
                    networks.append((ipaddress.ip_network(tok, strict=False), tok))
                    continue
                except ValueError:
                    pass
        host = _host_of(tok)
        if not host or _CANON_QUAD.match(host):     # clean quad -> extract_ips has it
            continue
        forms = _v4_interpretations(host)
        if not forms:
            continue
        if "." in host and not _CANON_QUAD.match(host):
            suspicious.append(host)
        for ip in forms:
            targets.setdefault(ip, f"{host} ({ip})" if ip != host else ip)
    return targets, networks, suspicious


def _command_base_dir(tokens: list[str], cwd: str | None) -> str | None:
    """Where the command actually runs, for resolving relative paths: the explicit
    cwd if the caller has one, else the first `cd DIR` before a command chain
    (`cd /x && grep foo build.gradle` — `build.gradle` exists in /x even when it
    does not in the guard's own cwd)."""
    if cwd:
        return cwd
    for i, tok in enumerate(tokens[:-1]):
        if tok == "cd":
            return tokens[i + 1]
    return None


def _exists_local(tok: str, base_dir: str | None) -> bool:
    if os.path.exists(tok):
        return True
    if base_dir and not os.path.isabs(tok):
        return os.path.exists(os.path.join(base_dir, tok))
    return False


def extract_hostnames(text: str, base_dir: str | None = None) -> list[str]:
    """DNS-looking tokens: contain a dot, valid charset, not a path/flag/IP.

    A false hostname here is now a hard BLOCK rather than a soft 'undetermined',
    so the exclusions matter. NOT hostnames: the token after a shell redirection
    (`> out.log`), a path that exists on disk, a bare token ending in a common
    artifact extension (`backup.zip`, `key.pem`), a `-m` module path, a grep/sed
    pattern, and anything whose last label is not TLD-shaped (`192.168.188`,
    `9.6`). Every one of these was observed blocking real engagement work."""
    try:
        import shlex
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()
    # output files: the token following a redirection operator
    redir_targets = {tokens[i + 1] for i, t in enumerate(tokens[:-1])
                     if re.fullmatch(r"\d?>>?|&>", t)}
    # module paths and search patterns, by index (the value, not the flag)
    skip_idx: set[int] = set()
    expect_pattern = False
    for i, tok in enumerate(tokens):
        if tok in _MODULE_FLAGS:
            skip_idx.add(i + 1)
            expect_pattern = False
        elif os.path.basename(tok) in _PATTERN_TOOLS:
            expect_pattern = True
        elif expect_pattern and not tok.startswith("-"):
            skip_idx.add(i)                 # the pattern; later args are files
            expect_pattern = False
    names = []
    if base_dir is None:
        base_dir = _command_base_dir(tokens, None)
    for i, tok in enumerate(tokens):
        if i in skip_idx or tok in redir_targets:
            continue
        if tok.startswith("-") or "=" in tok.split("/")[0]:
            continue
        if _exists_local(tok, base_dir):
            continue                                          # existing local path
        bare = "://" not in tok and "/" not in tok            # not a URL or path
        tok = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", tok)   # strip scheme
        tok = tok.split("@")[-1].split("/")[0]                  # userinfo, path
        tok = re.sub(r":\d+$", "", tok).strip(".")              # trailing :port
        if not tok or tok.startswith(("~", ".")) or "." not in tok:
            continue
        if bare and tok.lower().endswith(_LOCAL_FILE_EXTS):
            continue
        if not _TLD_RE.match(tok.rsplit(".", 1)[-1]):
            continue                                          # no TLD -> no host
        if _IP_RE.fullmatch(tok):
            continue
        if _HOST_RE.match(tok):
            names.append(tok.rstrip(".").lower())
    return list(dict.fromkeys(names))[:_MAX_NAMES]


def resolve_all(names: list[str]) -> dict[str, set[str]]:
    """name -> set of IPs (v4 AND v6 via AF_UNSPEC). Bounded, best-effort.

    BLOCK-ONLY: `check_command` calls this solely to catch a name resolving INTO
    a blocklisted range, and only when such a range exists. A result here can
    never make a command allowed, so a DNS failure can never turn a refusal into
    a pass — nor a pass into a refusal, since the allow path does not call it."""
    out: dict[str, set[str]] = {}
    if not names:
        return out

    def _one(name):
        try:
            return name, {ai[4][0] for ai in socket.getaddrinfo(name, None)}
        except (socket.gaierror, socket.timeout, OSError):
            return name, set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(names)) as pool:
        futs = [pool.submit(_one, n) for n in names]
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=_RESOLVE_BUDGET):
                name, ips = fut.result()
                out[name] = ips
        except concurrent.futures.TimeoutError:
            pass
    return out


def partition(entries: list[str]):
    """Scope entries -> (ip_networks, hostname_suffixes). A hostname entry
    (app.example.com, *.example.com) becomes a suffix pattern."""
    nets, hosts = [], []
    for x in entries or []:
        try:
            nets.append(ipaddress.ip_network(str(x).strip(), strict=False))
        except ValueError:
            h = str(x).strip().lower().lstrip("*.").rstrip(".")
            if h:
                hosts.append(h)
    return nets, hosts


def _host_match(name: str, patterns: list[str]) -> bool:
    n = name.strip().lower().rstrip(".")
    return any(n == p or n.endswith("." + p) for p in patterns)


def check_command(command: str, scope_in: list[str], scope_out: list[str],
                  never_block: list | None = None, resolve: bool = True,
                  cwd: str | None = None) -> Decision:
    """Decide whether a command may run against the engagement scope.

    scope_in  = allowlist (empty => blocklist-only mode: allow unless in scope_out)
    scope_out = blocklist (always wins)
    cwd       = the directory the command will run in, if the caller knows it —
                used to resolve relative paths (a token that names a file THERE
                is a local artifact, not a hostname)

    Deterministic (see the module docstring): the verdict is a pure function of
    the command text and the scope lists. `resolve` gates the block-only DNS
    lookup; even left on, it runs only when there is an IP blocklist to match.
    """
    command = command or ""
    nb = list(never_block) if never_block is not None else list(DEFAULT_NEVER_BLOCK)
    in_nets, in_hosts = partition(scope_in)
    out_nets, out_hosts = partition(scope_out)
    if not (in_nets or in_hosts or out_nets or out_hosts):
        return Decision(True, "no scope set")          # nothing to enforce
    has_in = bool(in_nets or in_hosts)

    names = extract_hostnames(command, base_dir=cwd)
    # The ONLY DNS in the decision, and it can only ever produce a block: without
    # an IP blocklist there is nothing a resolved address could prove.
    resolved = resolve_all(names) if (resolve and names and out_nets) else {}
    targets: list = []

    # 1) hostname-level scope, decided by NAME alone — total and DNS-free.
    for name in names:
        if _host_match(name, out_hosts):
            return Decision(False, f"{name} is blocklisted for this engagement",
                            targets + [(name, "out")])
        if has_in and not _host_match(name, in_hosts):
            # Not "we could not resolve it" — it is simply not in scope. Say how
            # to fix it, because the fix is one call and the agent can make it.
            allowed = ", ".join([str(n) for n in in_nets] + in_hosts)
            return Decision(False,
                            f"{name} is not in the engagement scope ({allowed}) — "
                            "if it is in scope add the NAME with scope_set, "
                            "otherwise target its IP directly",
                            targets + [(name, "out")])
        targets.append((name, "in"))

    # 2) numeric-encoded IPs (decimal/octal/hex): a dotted numeric form that isn't
    #    a clean canonical quad is an evasion — block on sight, no legitimate use.
    num_targets, networks, suspicious = numeric_ip_targets(command)
    if suspicious:
        return Decision(False, f"{suspicious[0]} is a non-canonical numeric IP form "
                        "(octal/hex/short) — refused as scope evasion; use dotted-quad",
                        targets + [(suspicious[0], "out")])

    # 2b) CIDR targets: judge the whole range's BREADTH. A range is in scope only
    #     if it is entirely within an allowed net and touches no blocklisted net —
    #     `nmap 10.0.0.0/24` against a /25 allowlist scans 128 hosts out of scope.
    for net, label in networks:
        for on in out_nets:
            if net.version == on.version and net.overlaps(on):
                return Decision(False, f"{label} overlaps out-of-scope {on}",
                                targets + [(label, "out")])
        same = [n for n in in_nets if n.version == net.version]
        if has_in and not any(net.subnet_of(n) for n in same):
            allowed = ", ".join([str(n) for n in in_nets] + in_hosts)
            return Decision(False, f"{label} extends outside the allowed scope ({allowed})",
                            targets + [(label, "out")])
        targets.append((label, "in"))

    # 3) IP-level scope: canonical literals + numeric-decoded + resolved IPs. IPs of
    #    an in-scope-by-name host are exempt from the net allowlist.
    #    IRREDUCIBLE FALSE POSITIVE (documented): a dotted-quad in prose or an arg —
    #    a version string `1.2.3.4`, `git tag 1.2.3.4` — is judged as a target and
    #    blocked if out of scope. Static text analysis cannot tell a version from an
    #    address. This is a real usability cost with no clean static fix; layer-2
    #    (netns) removes it entirely because it judges packets, not command text.
    labelled = [(ip, ip, False) for ip in extract_ips(command)]
    labelled += [(ip, label, False) for ip, label in num_targets.items()]
    # A resolved IP is BLOCK-ONLY evidence: it is checked against the blocklist
    # below but exempt from the allowlist, because the name it came from already
    # passed the allowlist by name and DNS must never be what grants access.
    for name, ips in resolved.items():
        labelled += [(ip, f"{name} ({ip})", True) for ip in ips]

    for ip_s, label, exempt in labelled:
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            continue
        # a v4-mapped/compatible v6 target is judged as its embedded v4 too
        judged = [ip]
        mapped = _mapped_v4(ip)
        if mapped is not None:
            judged.append(mapped)
        for jip in judged:
            # an EXPLICIT blocklist entry wins even over never_block: if the
            # operator wrote a range into scope_out, honor it over the default.
            for net in out_nets:
                if jip in net:
                    return Decision(False, f"{label} is out of scope ({net})",
                                    targets + [(label, "out")])
            if any(jip in n for n in nb):
                continue                         # never_block exempts from the allowlist
            if has_in and not exempt:
                if in_nets:
                    # IP scope is defined: the target must fall in an allowed net of
                    # its own family. Missing it — wrong range OR a family (v6) the
                    # operator never allowlisted — is out of scope.
                    if not any(jip in n for n in in_nets if n.version == jip.version):
                        allowed = ", ".join([str(n) for n in in_nets] + in_hosts)
                        return Decision(False, f"{label} is outside the allowed scope ({allowed})",
                                        targets + [(label, "out")])
                else:
                    # Allowlist names hosts only, so no net can contain this IP —
                    # a decision, not a shrug: refuse and say what would fix it.
                    return Decision(False,
                                    f"{label} cannot be proven in scope — the "
                                    f"allowlist names hosts only ({', '.join(in_hosts)}); "
                                    "add its network with scope_set to target it by IP",
                                    targets + [(label, "out")])
        targets.append((label, "in"))

    return Decision(True, "in scope", targets)


def command_verdict(command: str, scope_in_raw, scope_out_raw, *,
                    never_block=None, resolve: bool = True) -> tuple[bool, str]:
    """Compatibility adapter for existing callers."""
    decision = check_command(command, scope_in_raw, scope_out_raw,
                             never_block=never_block, resolve=resolve)
    reason = decision.reason.replace("is not in the engagement scope",
                                     "is outside the allowed scope")
    return decision.allowed, reason
