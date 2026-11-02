"""Deterministic tool runner + capture (redops/tools.py).

Tools are just tools — nmap does not need an LLM to run it. RedOps runs them
directly, stores raw output in the `tool_runs` table, and parses results into
services + facts. Both the operator (UI) and the agent (MCP) trigger runs and
read from the same store: the operator sees what the agent ran, the agent reads
what the operator ran and reasons about it — blind, no answers handed over.

Only reasoning belongs to the LLM; scanning does not.
"""

import ipaddress
import json
import os
import re
import signal
import shlex
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from . import db, parsers
from .parsers import http as http_parser
from .parsers import httpx as httpx_parser
from .parsers import nmap as nmap_parser
from .parsers import nuclei as nuclei_parser
from .parsers import ldapsearch as ldap_parser
from .parsers import smb as smb_parser
from .scope import command_verdict

def is_loopback(ip: str) -> bool:
    """THE canonical 'is this our own box' test — one implementation, used by the
    typed-tool path, the free-form command guard and the API alike.

    It used to be a regex (`127\\.\\d+\\.\\d+\\.\\d+|::1|localhost`), which missed
    every shorthand a shell accepts: 127.1, 0x7f000001, 0177.0.0.1, and `0` —
    and on Linux connecting to 0.0.0.0 or `0` reaches a 127.0.0.1 listener, so
    the UNSPECIFIED address is self too. Normalize, then ask ipaddress."""
    h = (ip or "").strip().strip("[]").lower()
    if not h:
        return False
    if h in ("localhost", "localhost.localdomain"):
        return True
    try:
        import socket
        h = socket.inet_ntoa(socket.inet_aton(h))       # 127.1 / 0 / 0x7f000001
    except (OSError, ValueError):
        pass
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        return False
    # v4-mapped IPv6 (::ffff:127.0.0.1) must be judged on the embedded v4
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return addr.is_loopback or addr.is_unspecified


def loopback_allowed() -> bool:
    conn = db.connect()
    try:
        raw = db.setting(conn, "allow_loopback", "REDOPS_ALLOW_LOOPBACK", "1")
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    finally:
        conn.close()


def tool_net() -> str:
    conn = db.connect()
    try:
        return db.setting(conn, "tool_net", "REDOPS_TOOL_NET", "").strip()
    finally:
        conn.close()

# We drive nmap with -oX (XML) and parse that — NOT the human text. nmap's XML
# schema is stable and complete, so no regex fragility and no lost ports.
def _scaninfo_ports(root):
    """What nmap SCANNED, from <scaninfo protocol=... services="...">, keyed by
    PROTOCOL — because a scan probes one protocol's ports, not the other's. A TCP
    scan reporting 53/tcp closed says NOTHING about a live 53/udp service. Returns
    (scanned:set of (proto,port), protos:set of protocols scanned)."""
    scanned, protos = set(), set()
    for si in root.findall("scaninfo"):
        proto = si.get("protocol", "tcp")
        protos.add(proto)
        for tok in (si.get("services") or "").split(","):
            tok = tok.strip()
            if "-" in tok:
                a, _, b = tok.partition("-")
                if a.isdigit() and b.isdigit():
                    scanned.update((proto, n) for n in range(int(a), int(b) + 1))
            elif tok.isdigit():
                scanned.add((proto, int(tok)))
    return scanned, protos


def _parse_nmap_xml(path: str) -> dict | None:
    """Parse nmap XML into structured results:
      {state, ports:[open services], scanned:set((proto,port) probed),
       nonopen:{(proto,port): 'closed'|'filtered'}, extra_state, extra_proto}
    `scanned` + `extra_state` let a caller detect a service that DIED even on a
    default scan, where dead ports collapse into <extraports> instead of per-port
    elements. All keyed by (proto,port) so a TCP scan never touches a UDP row.
    Only OPEN ports carry service detail in `ports`."""
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, FileNotFoundError, OSError):
        return None
    scanned, protos = _scaninfo_ports(root)
    host = root.find("host")
    if host is None:
        return {"state": "down", "ports": [], "scanned": scanned, "nonopen": {},
                "extra_state": None, "extra_proto": None}
    st = host.find("status")
    ports, nonopen = [], {}
    for p in host.findall("./ports/port"):
        state = p.find("state")
        pstate = state.get("state") if state is not None else None
        key = (p.get("protocol", "tcp"), int(p.get("portid")))
        if pstate != "open":
            if pstate in ("closed", "filtered"):
                nonopen[key] = pstate        # closed=death, filtered=undetermined
            continue
        svc = p.find("service")
        g = (lambda k: svc.get(k, "") if svc is not None else "")
        cpe = svc.find("cpe").text if (svc is not None and svc.find("cpe") is not None) else ""
        ports.append({"port": key[1], "proto": key[0],
                      "name": g("name"), "product": g("product"), "version": g("version"),
                      "extra": g("extrainfo"), "cpe": cpe or ""})
    # <extraports> collapses the bulk category. Attribute it to a protocol ONLY
    # when the scan probed exactly one (single bulk state AND single protocol);
    # anything ambiguous attributes nothing, so we never bulk-close the wrong
    # protocol's ports.
    bulk = {ep.get("state") for ep in host.findall("./ports/extraports")}
    extra_state = next(iter(bulk)) if len(bulk) == 1 else None
    extra_proto = next(iter(protos)) if len(protos) == 1 else None
    return {"state": st.get("state") if st is not None else "unknown", "ports": ports,
            "scanned": scanned, "nonopen": nonopen,
            "extra_state": extra_state, "extra_proto": extra_proto}


# Ports/services that matter for attack become graph nodes; everything else —
# especially the ephemeral Windows RPC range — rolls up so a DC's 26 open ports
# don't explode into 26 near-identical nodes. Full list still lands in `services`.
_HIGH_VALUE_PORTS = {21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 389,
                     443, 445, 464, 465, 512, 513, 514, 515, 548, 554, 587, 623,
                     636, 993, 995, 1080, 1099, 1433, 1521, 2049, 2375, 2379, 3268,
                     3269, 3306, 3389, 5432, 5601, 5900, 5985, 5986, 6379, 6333,
                     6334, 8000, 8080, 8443, 9200, 9389, 11211, 27017}
_INTERESTING_NAME = re.compile(
    r"http|ssh|smb|ldap|kerbero|winrm|wsman|rdp|ms-wbt|mssql|ms-sql|mysql|postgre|"
    r"redis|mongo|ftp|vnc|rpcbind|nfs|telnet|smtp|imap|snmp|qdrant|elastic|kibana", re.I)


def _is_dynamic_rpc(s: dict) -> bool:
    """CONFIRMED dynamic RPC — nmap named it msrpc/ncacn_http in the ephemeral
    range. We only claim 'RPC' when nmap actually said so."""
    return s["port"] >= 49152 and (
        "rpc" in (s["name"] or "").lower() or (s["name"] or "").lower() == "ncacn_http")


def _is_interesting(s: dict) -> bool:
    if s["port"] in _HIGH_VALUE_PORTS:
        return True
    return bool(_INTERESTING_NAME.search((s["name"] or "") + " " + (s["product"] or "")))


def _infer_role(ports: set[int]) -> str:
    """Deterministic host-role guess from the open-port signature — distil 26 ports
    into the one label that says what this box IS."""
    if {88, 389} <= ports and (445 in ports or 636 in ports):
        return "domain-controller"
    if ports & {1433, 3306, 5432, 6379, 27017, 1521, 6333, 6334, 9200}:
        return "database"
    if ports & {80, 443, 8080, 8000, 8443}:
        return "web"
    if 445 in ports or 139 in ports or 3389 in ports:
        return "windows-host"
    if 22 in ports:
        return "linux-host"
    return ""


def _host_os(ports) -> str:
    """Coalesce the OS from the structured service fields — the intel is already
    there ('for_Windows', 'Microsoft Windows', 'Ubuntu'…), just never captured."""
    blob = " ".join((s.get("product", "") + " " + s.get("name", "") + " " + s.get("extra", ""))
                    for s in ports).lower()
    if any(k in blob for k in ("for_windows", "microsoft windows", "ms-wbt", "windows rpc",
                               "netbios", "httpapi")):
        return "Windows"
    if any(k in blob for k in ("ubuntu", "debian", "for_linux", " linux", "centos", "red hat",
                               "fedora", "for_ubuntu")):
        return "Linux"
    if any(k in blob for k in ("darwin", "mac os", "macos")):
        return "macOS"
    return ""


_DOMAIN_RE = re.compile(r"Domain:\s*([A-Za-z0-9][A-Za-z0-9.\-]{1,60})")


def _host_domain(ports) -> str:
    """The AD domain, straight out of the LDAP/Kerberos extrainfo field."""
    for s in ports:
        m = _DOMAIN_RE.search(s.get("extra") or "")
        if m:
            return m.group(1).rstrip(".,")
    return ""

# Typed tool registry. Each tool declares TYPED options (with defaults) and named
# presets; argv is BUILT from the resolved options, never hand-written. One
# definition drives the board menu, the MCP schema and the runner, so operator
# toggles and agent params can't drift. argv is a list — no shell, no injection.
#
# option types:  bool  -> emits `on` tokens when true
#                enum  -> emits choices[value] tokens
#                str   -> emits [arg, value] when set (value checked vs `pattern`)
# `when` gates an option on another option's value (custom_ports only if ports=custom).
TOOL_SPECS = {
    "nmap": {
        "kind": "nmap", "bin": "nmap", "label": "Nmap port/service scan",
        "timeout": 900, "default_priority": 5,
        "options": {
            # -Pn: some hosts drop ICMP; without it nmap
            # calls a live host "down" and scans nothing. Targets here are already
            # known to exist, so skipping host discovery is correct.
            "assume_up": {"type": "bool", "default": True, "label": "Assume host up (-Pn)",
                          "on": ["-Pn"]},
            # connect (-sT) is the safe default: -sS needs root and a firewall often returns SYN scans as "filtered".
            "scan_type": {"type": "enum", "default": "connect", "label": "Scan type",
                          "choices": {"connect": ["-sT"], "syn": ["-sS"], "udp": ["-sU"]}},
            "ports": {"type": "enum", "default": "top1000", "label": "Ports",
                      "choices": {"top100": ["-F"], "top1000": ["--top-ports", "1000"],
                                  "all": ["-p-"], "custom": []}},
            "custom_ports": {"type": "str", "default": "", "label": "Custom ports",
                             "pattern": r"^[0-9]{1,5}(?:[,-][0-9]{1,5})*$", "arg": "-p",
                             "when": {"ports": "custom"}},
            "versions": {"type": "bool", "default": True, "label": "Version detection (-sV)",
                         "on": ["-sV"]},
            "scripts": {"type": "bool", "default": False, "label": "Default scripts (-sC)",
                        "on": ["-sC"]},
            "timing": {"type": "enum", "default": "T4", "label": "Timing",
                       "choices": {"T2": ["-T2"], "T3": ["-T3"], "T4": ["-T4"], "T5": ["-T5"]}},
        },
        "presets": {
            "quick":   {"label": "Quick — top 100", "opts": {"ports": "top100", "versions": False}},
            "service": {"label": "Service — top 1000 +ver", "opts": {"ports": "top1000", "versions": True}},
            "full":    {"label": "Full TCP — all ports", "opts": {"ports": "all", "versions": True}},
            "rag":     {"label": "RAG/Qdrant ports", "opts": {"ports": "custom",
                        "custom_ports": "80,443,6333,6334,8000,8080"}},
        },
    },
    "agent-card": {
        "kind": "http", "bin": None, "label": "A2A agent card",
        "paths": ["/.well-known/agent.json"], "default_port": 8000, "timeout": 10,
        "default_priority": 3, "options": {}, "presets": {},
    },
    "agent-probe": {
        "kind": "http", "bin": None, "label": "Probe agent (card + health + openapi)",
        "paths": ["/.well-known/agent.json", "/health", "/openapi.json"],
        "default_port": 8000, "timeout": 15, "default_priority": 3,
        "options": {}, "presets": {},
    },
    "nuclei": {
        # templated vuln scanner (projectdiscovery). argv-based -> scanner path;
        # -jsonl to stdout parsed into structured findings + vuln nodes.
        "kind": "scanner", "bin": "nuclei", "label": "Vuln scan (nuclei)",
        "timeout": 600, "default_priority": 4, "default_port": 80,
        "target": {"flag": "-u", "url": True, "scheme": "http"},
        "output": {"dest": "stdout", "parser": "nuclei"},
        "options": {
            "jsonl":    {"type": "bool", "default": True, "label": "JSONL output", "on": ["-jsonl"]},
            "silent":   {"type": "bool", "default": True, "label": "Silent (findings only)", "on": ["-silent"]},
            "severity": {"type": "str", "default": "", "label": "Severity filter (e.g. critical,high)",
                         "pattern": r"^[a-z,]{0,60}$", "arg": "-severity"},
            "tags":     {"type": "str", "default": "", "label": "Template tags (e.g. cve,rce)",
                         "pattern": r"^[a-z0-9,\-]{0,80}$", "arg": "-tags"},
        },
        "presets": {
            "cve":  {"label": "CVEs only", "opts": {"tags": "cve"}},
            "high": {"label": "High+critical", "opts": {"severity": "critical,high"}},
        },
    },
    "httpx": {
        # HTTP fingerprint (projectdiscovery httpx). argv-based -> generic scanner
        # executor; -json to stdout, parsed to endpoint/framework/server nodes.
        "kind": "scanner", "bin": "httpx", "label": "HTTP fingerprint (httpx)",
        "timeout": 60, "default_priority": 4, "default_port": 80,
        "target": {"flag": "-u", "url": True, "scheme": "http"},
        "output": {"dest": "stdout", "parser": "httpx"},
        "options": {
            "json":   {"type": "bool", "default": True, "label": "JSON output", "on": ["-json"]},
            "tech":   {"type": "bool", "default": True, "label": "Tech detection", "on": ["-td"]},
            "title":  {"type": "bool", "default": True, "label": "Page title", "on": ["-title"]},
            "server": {"type": "bool", "default": True, "label": "Server header", "on": ["-server"]},
            "status": {"type": "bool", "default": True, "label": "Status code", "on": ["-sc"]},
            "follow": {"type": "bool", "default": False, "label": "Follow redirects", "on": ["-fr"]},
        },
        "presets": {"fingerprint": {"label": "Fingerprint (tech+title+server)", "opts": {}}},
    },
    "ldapsearch": {
        # AD identity enumeration. An anonymous bind that answers is both the
        # finding AND the principal pool the spray matrix runs on — which is why
        # this belongs in the registry rather than in the unparsed escape hatch.
        "kind": "scanner", "bin": "ldapsearch", "label": "LDAP enumerate (ldapsearch)",
        "timeout": 120, "default_priority": 5, "default_port": 389,
        "target": {"flag": "-H", "url": True, "scheme": "ldap"},
        "output": {"dest": "stdout", "parser": "ldapsearch"},
        "options": {
            "simple":  {"type": "bool", "default": True, "label": "Simple auth (-x)", "on": ["-x"]},
            "scope":   {"type": "enum", "default": "sub", "label": "Search scope",
                        "choices": {"base": ["-s", "base"], "one": ["-s", "one"],
                                    "sub": ["-s", "sub"]}},
            "basedn":  {"type": "str", "default": "", "label": "Base DN (e.g. DC=corp,DC=local)",
                        "pattern": r"^[A-Za-z0-9=,. _-]{0,200}$", "arg": "-b"},
            "binddn":  {"type": "str", "default": "", "label": "Bind DN (omit = anonymous)",
                        "pattern": r"^[A-Za-z0-9=,.@\\ _-]{0,200}$", "arg": "-D"},
            "filter":  {"type": "str", "default": "", "label": "LDAP filter",
                        "pattern": r"^[A-Za-z0-9()=*&|.,_ -]{0,200}$", "arg": None,
                        "positional": True},
        },
        "presets": {
            "rootdse": {"label": "RootDSE (naming contexts, DC name)",
                        "opts": {"scope": "base"}},
            "users":   {"label": "Users (anonymous bind)",
                        "opts": {"scope": "sub", "filter": "(objectClass=user)"}},
        },
    },
    "smb-shares": {
        # null-session share enumeration. A writable share is a write-primitive,
        # which is exactly what the correlation engine scores highest.
        "kind": "scanner", "bin": "smbclient", "label": "SMB shares (null session)",
        "timeout": 90, "default_priority": 5, "default_port": 445,
        "target": {"flag": "-L", "url": False},
        "output": {"dest": "stdout", "parser": "smb"},
        "options": {
            "noauth": {"type": "bool", "default": True, "label": "No password (-N)", "on": ["-N"]},
            "user":   {"type": "str", "default": "", "label": "Username (omit = null session)",
                       "pattern": r"^[A-Za-z0-9._@\\-]{0,80}$", "arg": "-U"},
        },
        "presets": {"null": {"label": "Null session", "opts": {}}},
    },
    "ai-chat": {
        # the primitive of AI recon: POST a message, parse the reply into
        # endpoint/model/collections/session-pattern. In-process HTTP POST.
        "kind": "chat", "bin": None, "label": "Chat probe (send a message, parse the reply)",
        "default_port": 8080, "timeout": 20, "default_priority": 3,
        "options": {
            "message": {"type": "str", "default": "Hello, what can you help me with?",
                        "label": "Message to send", "pattern": r"^.{1,2000}$"},
            "path": {"type": "enum", "default": "/chat", "label": "Endpoint path",
                     "choices": {"/chat": [], "/v1/chat/completions": [], "/api/chat": [],
                                 "/query": [], "/completion": [], "/generate": []}},
            "body_shape": {"type": "enum", "default": "message", "label": "Request body shape",
                           "choices": {"message": [], "openai": [], "query": [], "prompt": []}},
        },
        "presets": {
            "openai": {"label": "OpenAI chat completions",
                       "opts": {"path": "/v1/chat/completions", "body_shape": "openai"}},
            "rag":    {"label": "RAG /query", "opts": {"path": "/query", "body_shape": "query"}},
        },
    },
    "nvd-lookup": {
        # deterministic CVE match: NVD version-range matching, not LLM vibes.
        # returns only CVEs whose applicability config includes the given version.
        "kind": "cve", "bin": None, "label": "CVE lookup (NVD, version-matched)",
        "timeout": 20, "default_priority": 4,
        "options": {
            "product": {"type": "str", "default": "", "label": "Product (e.g. qdrant)",
                        "pattern": r"^[A-Za-z0-9._+\- ]{0,60}$"},
            "version": {"type": "str", "default": "", "label": "Version (e.g. 1.12.4)",
                        "pattern": r"^[A-Za-z0-9._\-]{0,40}$"},
            "vendor":  {"type": "str", "default": "", "label": "Vendor (optional; defaults to product)",
                        "pattern": r"^[A-Za-z0-9._+\- ]{0,60}$"},
        },
        "presets": {},
    },
}

# legacy tool ids (board buttons, old callers, MCP) → (spec_id, preset)
LEGACY = {"quick-scan": ("nmap", "quick"), "port-scan": ("nmap", "service"),
          "full-scan": ("nmap", "full")}


def _resolve_tool(tool: str, preset: str | None):
    """Map a tool name (spec id OR legacy id) to (spec_id, spec, preset)."""
    if tool in LEGACY:
        sid, lpreset = LEGACY[tool]
        return sid, TOOL_SPECS.get(sid), preset or lpreset
    return tool, TOOL_SPECS.get(tool), preset


def resolve_opts(spec: dict, preset: str | None = None, overrides: dict | None = None) -> dict:
    opts = {k: o["default"] for k, o in spec.get("options", {}).items()}
    if preset and preset in spec.get("presets", {}):
        opts.update(spec["presets"][preset].get("opts", {}))
    for k, v in (overrides or {}).items():
        if k in opts:
            opts[k] = v
    return opts


def validate_opts(spec: dict, opts: dict) -> None:
    for k, o in spec.get("options", {}).items():
        v = opts.get(k, o["default"])
        if o["type"] == "enum" and v not in o["choices"]:
            raise ValueError(f"{k} must be one of {sorted(o['choices'])}")
        if o["type"] == "str" and v and o.get("pattern") and not re.fullmatch(o["pattern"], str(v)):
            raise ValueError(f"{k}={v!r} is not allowed")
        if o["type"] == "bool" and not isinstance(v, bool):
            raise ValueError(f"{k} must be a boolean")


def build_argv(spec: dict, opts: dict, ip: str) -> list[str]:
    argv = [spec["bin"]]
    for k, o in spec.get("options", {}).items():
        when = o.get("when")
        if when and any(opts.get(wk) != wv for wk, wv in when.items()):
            continue
        v = opts.get(k, o["default"])
        if o["type"] == "bool":
            if v:
                argv += o.get("on", [])
        elif o["type"] == "enum":
            argv += o["choices"].get(v, [])
        elif o["type"] == "str":
            if v:
                argv += ([o["arg"], str(v)] if o.get("arg") else [str(v)])
    # target passing: bare positional (nmap) or behind a flag (httpx/nuclei need -u).
    # `ip` is the already-rendered target string (a URL for url-target tools).
    tgt = spec.get("target", {})
    if tgt.get("flag"):
        argv += [tgt["flag"], ip]
    else:
        argv.append(ip)
    return argv


def available():
    """Full registry for the board menu + MCP: options, presets, defaults."""
    out = []
    for sid, spec in TOOL_SPECS.items():
        out.append({"name": sid, "label": spec["label"], "kind": spec["kind"],
                    "default_priority": spec.get("default_priority", 5),
                    "options": spec.get("options", {}),
                    "presets": {p: {"label": v.get("label", p), "opts": v.get("opts", {})}
                                for p, v in spec.get("presets", {}).items()}})
    return out


def tool_names() -> set[str]:
    return set(TOOL_SPECS) | set(LEGACY)


def runs(conn, engagement_id=None, target_id=None, limit=40, before_id=None):
    sql, p = "SELECT * FROM tool_runs WHERE 1=1", []
    # AND, not elif: a target_id must never widen the query past its engagement.
    if target_id is not None:
        sql += " AND target_id=?"; p.append(target_id)
    if engagement_id is not None:
        sql += " AND engagement_id=?"; p.append(engagement_id)
    if before_id is not None:
        sql += " AND id<?"; p.append(before_id)
    sql += " ORDER BY id DESC LIMIT ?"; p.append(max(1, min(limit, 200)))
    return db.rows(conn, sql, p)


# parser registry: name -> pure parse(envelope) -> ExtractResult. A TOOL_SPEC of
# kind "scanner" names one here; the generic executor binds output to it BY IDENTITY
# (it ran the tool, so no output-sniffing). New argv tools = a spec + a parser here.
PARSERS = {
    "nmap": nmap_parser.parse,
    "httpx": httpx_parser.parse,
    "nuclei": nuclei_parser.parse,
    "ldapsearch": ldap_parser.parse,
    "smb": smb_parser.parse,
}


def _finalize_run(conn, engagement_id, target_id, label, tool, rid, actor, summary, out,
                  status="done"):
    """Shared run bookkeeping every executor calls after persist: store the raw
    output, close the tool_runs row, emit the feed event, run correlation. Keeping
    it here (not per-tool) is why adding a tool is a parser, not a pipeline."""
    from . import correlate, wiretail
    src = "agent" if actor == "agent" else "user"
    otext, meta = wiretail.store_output(out, f"tool_{rid}")
    conn.execute("UPDATE tool_runs SET status=?, output=?, summary=?, finished_at=? WHERE id=?",
                 (status, otext, summary, db.now(), rid))
    db.add_event(conn, src, "output", f"[tool] {tool} {label}: {summary}",
                 target_id=target_id, meta={"tool_run": rid, **meta}, engagement_id=engagement_id)
    conn.commit()
    correlate.run(conn, engagement_id)
    conn.commit()


def _persist_results(conn, engagement_id, target_id, ip, parsed, out, status, rid, actor, tool):
    """Persist a structured nmap parse through the extraction contract: the pure
    mapper (parsers/nmap.to_result) builds the ExtractResult with nmap's full
    curation (complete services list, the interesting/dyn-rpc/unfingerprinted
    buckets, role/OS/AD-domain coalescing, status advance, summary); parsers.persist
    applies it and stamps stage=observed. Run bookkeeping (tool_run row, output
    store, feed event, correlate) via the shared _finalize_run."""
    ports = parsed["ports"] if (parsed and status == "done") else []
    result = nmap_parser.to_result(parsed if (parsed and status == "done") else None, ip,
                                   has_target=bool(target_id), status=status)
    parsers.persist(conn, engagement_id, target_id, ip, result,
                    stage="observed", source="wire-auto")
    if target_id and parsed and status == "done":
        scanned = parsed.get("scanned") or set()
        nonopen = parsed.get("nonopen") or {}
        extra_state = parsed.get("extra_state")
        extra_proto = parsed.get("extra_proto")
        open_now = {(svc["proto"], svc["port"]) for svc in ports}
        for svc in db.rows(conn, "SELECT port, proto, state FROM services WHERE target_id=?",
                           (target_id,)):
            key = (svc["proto"], svc["port"])
            if svc["state"] != "open" or key in open_now or key not in scanned:
                continue
            state = nonopen.get(key)
            if not state and extra_state and svc["proto"] == extra_proto:
                state = extra_state
            if state == "closed":
                db.upsert_service(conn, target_id, svc["port"], svc["proto"],
                                  {"state": "closed"})
        for fid in db.refresh_target_staleness(conn, target_id):
            fr = db.row(conn, "SELECT title, confidence FROM findings WHERE id=?", (fid,))
            db.add_event(conn, "user", "trust",
                         f"[trust] {fr['title']!r} demoted to {fr['confidence']} after service drift",
                         target_id=target_id, engagement_id=engagement_id)
    _finalize_run(conn, engagement_id, target_id, ip, tool, rid, actor, result.summary, out, status)
    return result.summary, len(ports)


def _split_host_port(ip, default_port=None):
    """Accept 'host' or 'host:port' (not IPv6) — returns (host, port|default)."""
    ip = (ip or "").strip()
    if ip.count(":") == 1 and not ip.startswith("["):
        h, _, p = ip.partition(":")
        return h, (int(p) if p.isdigit() else default_port)
    return ip, default_port


def _http_get(url, timeout):
    """Fetch a URL, from inside REDOPS_TOOL_NET when that is set.

    AI recon fetches in-process, which means it resolves and routes from the
    *host*. On macOS the host cannot reach a docker container IP at all, so
    agent-card/agent-probe against a containerised target returned "no agent
    card found" no matter what REDOPS_TOOL_NET said — the setting only ever
    reached nmap. Route through a throwaway curl container on the same network
    so both halves of the recon see the same topology."""
    net = tool_net()
    if net:
        return _http_get_via_docker(url, timeout, net)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.getcode(), r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode(errors="replace") if e.fp else "")
    except Exception as e:
        return None, f"{e!r}"


def _http_post(url, body: dict, timeout):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode(errors="replace") if e.fp else "")
    except Exception as e:
        return None, f"{e!r}"


def _chat_body(shape: str, message: str) -> dict:
    """Request body per the endpoint family (Gate-0 surface)."""
    if shape == "openai":
        return {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": message}]}
    if shape == "query":
        return {"query": message}
    if shape == "prompt":
        return {"prompt": message}
    return {"message": message}
# curl writes the body to stdout and we ask for the status code on the last
# line, so one process yields both without a second request.
_CURL_MARK = "\n__redops_status__:"


def _http_get_via_docker(url, timeout, net):
    try:
        p = subprocess.run(
            ["docker", "run", "--rm", "--network", net, "curlimages/curl:latest",
             "-s", "-S", "--max-time", str(timeout),
             "-w", _CURL_MARK + "%{http_code}", url],
            capture_output=True, text=True, timeout=timeout + 20)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return None, f"{e!r}"
    body, _, code = p.stdout.rpartition(_CURL_MARK)
    if not code.strip().isdigit():
        return None, (p.stderr or p.stdout or "no response").strip()
    status = int(code.strip())
    return (status if status else None), body



def _persist_http_results(conn, engagement_id, target_id, host, port, results, rid, actor, tool):
    """Parse fetched agent-card / health / openapi JSON into agent/model/endpoint
    entities + facts via the extraction contract (parsers/http.to_result builds the
    ExtractResult — agent node with host/port meta, model, skills, exposed endpoints;
    parsers.persist applies it at stage=observed). Deterministic, no LLM."""
    result = http_parser.to_result(results, host, port, has_target=bool(target_id))
    parsers.persist(conn, engagement_id, target_id, host, result,
                    stage="observed", source="wire-auto")
    _finalize_run(conn, engagement_id, target_id, f"{host}:{port}", tool, rid, actor,
                  result.summary, http_parser.raw_output(results))
    return result.summary



def _execute_http(rid, engagement_id, target_id, ip, port, tool, spec, actor):
    """Deterministic agent-card / agent-probe recon (in-process HTTP fetch),
    executed against the pre-created run row `rid`."""
    host, port = _split_host_port(ip, port or spec.get("default_port", 8000))
    base = f"http://{host}:{port}"
    conn = db.connect()
    conn.execute("UPDATE tool_runs SET command=? WHERE id=?",
                 (f"GET {base} " + " ".join(spec["paths"]), rid))
    conn.commit(); conn.close()

    results = {p: _http_get(base + p, spec["timeout"]) for p in spec["paths"]}
    conn = db.connect()
    try:
        summary = _persist_http_results(conn, engagement_id, target_id, host, port,
                                        results, rid, actor, tool)
    finally:
        conn.close()
    return {"id": rid, "status": "done", "summary": summary}


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cvss(cve: dict):
    """(severity, score) from NVD metrics, preferring CVSS v3.1 → v3.0 → v2."""
    m = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if m.get(key):
            d = m[key][0].get("cvssData", {})
            return (d.get("baseSeverity", "") or "").lower(), d.get("baseScore")
    if m.get("cvssMetricV2"):
        d = m["cvssMetricV2"][0]
        sc = d.get("cvssData", {}).get("baseScore")
        sev = "high" if (sc or 0) >= 7 else "medium" if (sc or 0) >= 4 else "low"
        return sev, sc
    return "info", None


def _execute_cve(rid, engagement_id, target_id, ip, tool, spec, opts, actor):
    """Deterministic CVE lookup against NVD with version-range matching. Records
    a finding per applicable CVE (severity from CVSS) and a `vuln` entity linked
    to the host. No LLM — the version match is what makes it correct."""
    product = (opts.get("product") or "").strip().lower().replace(" ", "_")
    version = (opts.get("version") or "").strip()
    vendor = ((opts.get("vendor") or "").strip().lower().replace(" ", "_") or product)
    src = "agent" if actor == "agent" else "user"
    if not product:
        conn = db.connect()
        conn.execute("UPDATE tool_runs SET status='error', summary=?, finished_at=? WHERE id=?",
                     ("nvd-lookup needs a product", db.now(), rid))
        conn.commit(); conn.close()
        return {"id": rid, "status": "error"}
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}" if version else f"cpe:2.3:a:{vendor}:{product}"
    url = f"{NVD_URL}?virtualMatchString={urllib.parse.quote(cpe)}&resultsPerPage=50"
    conn = db.connect()
    conn.execute("UPDATE tool_runs SET command=? WHERE id=?", (f"GET NVD {cpe}", rid))
    conn.commit(); conn.close()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "redops-nvd-lookup"})
        with urllib.request.urlopen(req, timeout=spec["timeout"]) as r:
            data = json.loads(r.read().decode(errors="replace"))
    except Exception as e:
        conn = db.connect()
        conn.execute("UPDATE tool_runs SET status='done', output=?, summary=?, finished_at=? WHERE id=?",
                     (f"NVD unreachable: {e!r}", "NVD unreachable (egress-restricted?)", db.now(), rid))
        db.add_event(conn, src, "output", f"[tool] nvd-lookup {product} {version}: NVD unreachable",
                     target_id=target_id, meta={"tool_run": rid}, engagement_id=engagement_id)
        conn.commit(); conn.close()
        return {"id": rid, "status": "done", "summary": "NVD unreachable"}

    from . import correlate, wiretail
    vulns = data.get("vulnerabilities", [])
    conn = db.connect()
    hid = db.upsert_entity(conn, engagement_id, "host", ip.split(":")[0]) if ip else None
    lines, recorded = [], 0
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for v in sorted(vulns, key=lambda v: sev_rank.get(_cvss(v.get("cve", {}))[0], 0), reverse=True):
        cve = v.get("cve", {}); cid = cve.get("id")
        if not cid:
            continue
        sev, score = _cvss(cve)
        sev = sev if sev in ("info", "low", "medium", "high", "critical") else "info"
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        # dedup findings by CVE id; version-matched, so no false "unverified" flags
        if not db.row(conn, "SELECT id FROM findings WHERE engagement_id=? AND title LIKE ?",
                      (engagement_id, f"%{cid}%")):
            db.insert(conn, "findings", {
                "engagement_id": engagement_id, "target_id": target_id,
                "title": f"{cid} — {product} {version or '(any)'} [{sev} {score or '?'}]",
                "severity": sev, "description": desc[:600], "status": "open",
                "created_at": db.now()})
            recorded += 1
        ve = db.upsert_entity(conn, engagement_id, "vuln", cid)
        if hid and ve != hid:
            db.add_fact(conn, engagement_id, ve, "affects", hid, "", "observed", "wire-auto")
        lines.append(f"{cid}\t{sev}\t{score}\t{desc[:90]}")
    summary = (f"{len(vulns)} CVE(s) match {product} {version or '(any)'}; {recorded} new finding(s)"
               if vulns else f"no CVEs for {product} {version or '(any)'} in NVD (version not in range)")
    otext, meta = wiretail.store_output("\n".join(lines) or "no results", f"tool_{rid}")
    conn.execute("UPDATE tool_runs SET status='done', output=?, summary=?, finished_at=? WHERE id=?",
                 (otext, summary, db.now(), rid))
    db.add_event(conn, src, "output", f"[tool] nvd-lookup {product} {version}: {summary}",
                 target_id=target_id, meta={"tool_run": rid, **meta}, engagement_id=engagement_id)
    conn.commit(); correlate.run(conn, engagement_id); conn.commit(); conn.close()
    return {"id": rid, "status": "done", "summary": summary}


def _execute_chat(rid, engagement_id, target_id, ip, port, tool, spec, opts, actor):
    """ai-chat: POST a message to the target's chat endpoint, capture the reply, and
    parse it via the ai_chat parser (endpoint/model/collections/session-pattern). An
    in-process HTTP POST (like agent-card), not a subprocess."""
    from .parsers import ai_chat
    host, port = _split_host_port(ip, port or spec.get("default_port", 8080))
    path = opts.get("path", "/chat")
    body = _chat_body(opts.get("body_shape", "message"), opts.get("message", "Hello"))
    url = f"http://{host}:{port}{path}"
    code, text = _http_post(url, body, spec["timeout"])

    conn = db.connect()
    conn.execute("UPDATE tool_runs SET command=? WHERE id=?",
                 (f"POST {url} {json.dumps(body)}", rid))
    conn.commit()
    conn.close()

    envelope = {"tool": tool, "status": "done" if code else "error", "output": text or "",
                "params": {"host": host, "port": port, "path": path, "ip": ip,
                           "has_target": bool(target_id), "status_code": code}}
    result = ai_chat.parse(envelope)

    out = f"# POST {url}\n# body: {json.dumps(body)}\n# -> {code}\n{text or ''}"
    conn = db.connect()
    try:
        parsers.persist(conn, engagement_id, target_id, ip, result, stage="observed", source="wire-auto")
        _finalize_run(conn, engagement_id, target_id, f"{host}:{port}{path}", tool, rid, actor,
                      result.summary, out, "done" if code else "error")
    finally:
        conn.close()
    return result.summary


def run_command(engagement_id, argv, actor="agent", target_id=None, timeout=1800):
    """Escape hatch — run an ARBITRARY argv command through RedOps: optionally
    scope-checked when the operator enables the guard, and CAPTURED-ONLY —
    no parser, no auto-facts, no correlate. Everything funnels through RedOps so the
    board sees every tool call; unparsed output stays honest (stored + surfaced,
    never faked into structure). Prefer a real registry tool when one exists; this
    is the bridge for the long tail, not a substitute for building the tool right."""
    parsed = _parse_command(argv)
    if "error" in parsed:
        return parsed
    command_str, argv, use_shell = parsed["command_str"], parsed["argv"], parsed["use_shell"]
    src = "agent" if actor == "agent" else "user"

    conn = db.connect()
    try:
        ok, reason = _command_scope_ok(conn, engagement_id, command_str)
        if not ok:
            db.add_event(conn, src, "note", f"[run] BLOCKED (out of scope): {reason}",
                         engagement_id=engagement_id)
            conn.commit()
            return {"blocked": True, "reason": reason}
        tier, why = command_risk(conn, engagement_id, command_str)
        # a destructive command is NEVER auto-run, whatever tool_auto_approve
        # says — it's the class of action no dedupe/merge pass can undo.
        gated = (tier == "destructive" and actor != "operator"
                 and _scope_guard_enabled(conn))
        if not gated:
            # pooled=0: a synchronous run is NOT scheduled by pump(), so it must
            # not count against the pool — otherwise a long curl silently shrinks
            # the 4-wide pool and starves the queue.
            rid = db.insert(conn, "tool_runs",
                            {"engagement_id": engagement_id, "target_id": target_id,
                             "tool": "run", "command": command_str, "status": "running",
                             "actor": actor, "started_at": db.now(), "priority": 5,
                             "pooled": 0})
            conn.commit()
    finally:
        conn.close()
    if gated:
        return queue_exec(engagement_id, command_str, actor=actor,
                          target_id=target_id, force_approval=(tier, why),
                          timeout=timeout)
    return _exec_command(rid, engagement_id, command_str, argv, use_shell,
                         target_id, src, timeout)


def _parse_command(argv):
    """Split a command into (command_str, argv, use_shell). Shell operators
    (pipe/redirect/&&/glob/subshell) only work through a shell; `run` is scope-checked
    on the FULL command string, so a shell doesn't widen the guard — it just stops the
    agent hand-wrapping everything in `sh -c`. Plain argv still execs directly."""
    raw = argv if isinstance(argv, str) else None
    if isinstance(argv, str):
        argv = shlex.split(argv)
    if not argv:
        return {"error": "empty command"}
    use_shell = raw is not None and any(ch in raw for ch in "|&;<>()$`*?")
    return {"command_str": raw if use_shell else " ".join(shlex.quote(a) for a in argv),
            "argv": argv, "use_shell": use_shell}


API_PORT = os.environ.get("REDOPS_PORT", "9100")

# ---------------------------------------------------------------------------
# Self-targeting guard.
#
# WHAT THIS IS: drift resistance. The realistic failure mode — observed on this
# engagement — is an agent that reaches for curl out of habit and ends up talking
# to RedOps' own API, where `actor` used to be self-declared. This stops that.
#
# WHAT THIS IS NOT: containment. The agent runs as the same OS user, can read
# data/operator.token, and can write and execute its own scripts. Nothing at this
# layer changes that; only separate OS users or a container would. Do not treat a
# pass here as proof the agent could not have reached the API — treat it as
# proof it did not do so by accident.
_URLISH = re.compile(r"(?:https?://)?(\[[0-9a-fA-F:]+\]|[\w.-]+)(?::(\d+))?", re.I)
_API_PATH = re.compile(r"/api/(tools|settings|engagements|acp|maintenance)\b", re.I)
# the CLI talks to the same API and asserts REDOPS_OPERATOR=1 — invoking it from
# `run` would hand the agent the operator token by proxy.
_REDOPS_CLI = re.compile(r"(^|[\s/])redops(\s|$)|redops\.cli\b", re.I)


def _targets_redops_api(command_str: str) -> bool:
    # one loopback implementation, not two: the typed-tool path and this guard
    # disagreeing is how tool_run(ip="127.1") sailed through while the same host
    # was blocked in a free-form command.
    if _API_PATH.search(command_str) or _REDOPS_CLI.search(command_str):
        return True
    for m in _URLISH.finditer(command_str):
        host = m.group(1)
        if not is_loopback(host):
            continue
        port = m.group(2)
        # Bare numeric zero is a destination for network tools but also
        # appears throughout source code and timestamps.
        if host == "\x30" and port is None:
            prefix = command_str[:m.start()]
            segment = re.split(r"[;&|\n]", prefix)[-1].strip()
            command = os.path.basename(next(iter(segment.split()), ""))
            if command not in {"curl", "wget", "nc", "ncat", "netcat",
                               "nmap", "ping", "ssh", "telnet", "socat"}:
                continue
        # int() normalizes ":09100"; a bare loopback reference is refused too
        if port is None or (port.isdigit() and int(port) == int(API_PORT)):
            return True
    return False


def _scope_guard_enabled(conn) -> bool:
    """Use the same runtime override/env/default as the exec broker and hook."""
    raw = db.setting(conn, "scope_guard", "REDOPS_SCOPE_GUARD", "0")
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _command_scope_ok(conn, engagement_id, command_str):
    """Scope verdict for a free-form command — the chokepoint EVERY path through
    `run` passes, sync or pooled."""
    if _scope_guard_enabled(conn) and _targets_redops_api(command_str):
        return False, ("targets the RedOps API itself — use the MCP tools, not HTTP. "
                       "Reaching the API over the wire would let a self-declared "
                       "actor bypass the approval gate.")
    if not _scope_guard_enabled(conn):
        return True, ""
    sin, sout = _scope_lists(conn, engagement_id)
    return command_verdict(command_str, sin, sout)


# A state-changing HTTP call is the reliable signal that a command is doing more
# than looking. Not a general shell classifier — that problem is unsolvable — just
# the narrow case that matters: exploit delivery against a fragile service.
_WRITE_RE = re.compile(r"(-X\s*(POST|PUT|DELETE|PATCH)\b|--data\b|--data-\w+\b|"
                       r"--upload-file\b|\s-d\s|\s-T\s|--form\b|\s-F\s)", re.I)


def fragile_assets(conn, engagement_id):
    """Services the operator flagged as risky to touch: [(ip, port, risk), ...].
    risk 'fragile' = writes need approval; 'gated' = anything touching it does."""
    return [(r["ip"], r["port"], r["risk"]) for r in db.rows(
        conn, "SELECT DISTINCT t.ip AS ip, s.port AS port, s.risk AS risk FROM services s "
              "JOIN targets t ON s.target_id=t.id "
              "WHERE t.engagement_id=? AND COALESCE(s.risk,'') <> '' "
              "ORDER BY t.ip, s.port", (engagement_id,))]


def asset_risk(conn, engagement_id, ip, port, writes=False):
    """Risk tier for a KNOWN ip/port — the typed-tool counterpart of
    command_risk. `writes` marks a tool that changes state (an exploit), which is
    what 'fragile' gates; 'gated' holds everything."""
    if not ip:
        return "safe", ""
    host = str(ip).split(":")[0]
    for f_ip, f_port, risk in fragile_assets(conn, engagement_id):
        if f_ip != host:
            continue
        if risk == "gated":
            return "destructive", f"{f_ip}:{f_port} is gated — every run needs approval"
        if port is not None and int(port) == int(f_port) and writes:
            return "destructive", f"{f_ip}:{f_port} is fragile and this tool writes to it"
    return "safe", ""


def command_risk(conn, engagement_id, command_str):
    """Risk tier for a free-form command: (tier, reason).

    You cannot reliably classify arbitrary shell — so don't try. Classify the
    ASSET instead (a one-time human judgement: "exploiting Qdrant :6333 crashes
    it"), and gate at this chokepoint, which every path through `run` passes.
    Choosing a different tool can't dodge it, which is the whole point: the CVE
    that motivated this is an HTTP POST, trivially expressible as a curl."""
    low = command_str.lower()
    for ip, port, risk in fragile_assets(conn, engagement_id):
        if ip not in command_str:
            continue
        # the port must actually appear, else every command to the host is caught
        if str(port) not in command_str and risk != "gated":
            continue
        if risk == "gated":
            return "destructive", f"{ip}:{port} is gated — every command needs approval"
        if _WRITE_RE.search(low):
            return "destructive", f"{ip}:{port} is fragile and this command writes to it"
        return "loud", f"{ip}:{port} is fragile — read-only, flagged"
    return "safe", ""


def _exec_command(rid, engagement_id, command_str, argv, use_shell, target_id, src,
                  timeout=1800):
    """Execute one already-recorded `run` row and finalize it. Shared by the
    synchronous path and the pooled background worker."""
    rc = None
    proc = None
    try:
        proc = subprocess.Popen(command_str if use_shell else argv, shell=use_shell,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
        stdout, stderr = proc.communicate(timeout=timeout)
        out = stdout + (("\n[stderr]\n" + stderr) if stderr.strip() else "")
        rc = proc.returncode
        # HONEST exit: a command that ran but failed (curl 6, nmap 1, grep 1…) is
        # NOT "done". Only a zero exit is success; the real code is surfaced below.
        status = "done" if rc == 0 else "error"
    except FileNotFoundError:
        out, status = f"{argv[0]} not found on PATH", "error"
    except subprocess.TimeoutExpired:
        # A shell command may have spawned a long-lived child (for example an
        # AI CLI). Kill the complete process group and retain output observed
        # before the deadline; neither an orphan nor missing output is honest.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = proc.communicate()
        out = (stdout or "") + (("\n[stderr]\n" + stderr) if stderr else "")
        out += f"\n[run] timed out after {timeout}s; process group killed"
        status = "error"
    except Exception as e:  # noqa: BLE001
        out, status = f"error: {e!r}", "error"

    from . import wiretail
    otext, meta = wiretail.store_output(out, f"tool_{rid}")
    exit_desc = f"code {rc}" if rc is not None else status
    summary = f"captured {len(out)} bytes · exit {exit_desc}"
    # A parallel agent may hold the single SQLite writer slot just as this
    # command exits. Retry finalization on a fresh connection so the command's
    # output is not discarded after it has already run.
    for attempt in range(3):
        conn = None
        try:
            conn = db.connect()
            conn.execute("UPDATE tool_runs SET status=?, output=?, summary=?, finished_at=? WHERE id=?",
                         (status, otext, summary, db.now(), rid))
            # CAPTURED-ONLY: an output event, flagged; NO parser, NO facts, NO correlate.
            db.add_event(conn, src, "output", f"[run] {command_str}: {summary}", target_id=target_id,
                         meta={"tool_run": rid, "captured_only": True, **meta},
                         engagement_id=engagement_id)
            conn.commit()
            break
        except sqlite3.OperationalError as exc:
            if conn is not None:
                conn.rollback()
            if "locked" not in str(exc).lower() or attempt == 2:
                raise
            time.sleep(0.1 * (2 ** attempt))
        finally:
            if conn is not None:
                conn.close()
    return {"status": status, "rid": rid, "summary": summary,
            "output": out[:4000], "captured_only": True}


def queue_exec(engagement_id, command, actor="agent", target_id=None, priority=5,
               force_approval=None, timeout=1800):
    """Background escape hatch — queue an arbitrary command onto the SHARED pool
    instead of blocking the caller. Same scope chokepoint and same captured-only
    honesty as run_command; the difference is only who waits. Returns a run id
    immediately so the agent can fire several avenues and keep reasoning."""
    parsed = _parse_command(command)
    if "error" in parsed:
        return parsed
    command_str = parsed["command_str"]
    src = "agent" if actor == "agent" else "user"
    conn = db.connect()
    try:
        ok, reason = _command_scope_ok(conn, engagement_id, command_str)
        if not ok:
            db.add_event(conn, src, "note", f"[run] BLOCKED (out of scope): {reason}",
                         engagement_id=engagement_id)
            conn.commit()
            return {"blocked": True, "reason": reason}
        tier, why = force_approval or command_risk(conn, engagement_id, command_str)
        if tier == "destructive" and actor != "operator" and _scope_guard_enabled(conn):
            status, ready = "queued", False       # gate wins over auto-approve
        else:
            ready = actor == "operator" or _auto_approve_tools()
            status = "ready" if ready else "queued"
        rid = db.insert(conn, "tool_runs", {
            "engagement_id": engagement_id, "target_id": target_id, "tool": "run",
            "command": command_str, "status": status, "actor": actor,
            "params_json": json.dumps({"kind": "exec", "risk": tier, "risk_why": why,
                                       "timeout": timeout}),
            "priority": priority,
            "output": "", "summary": "", "started_at": db.now(), "finished_at": None})
        note = (f"⛔ HELD — {why}" if tier == "destructive" and not ready
                else "queued — needs approval" if not ready else f"queued (p{priority})")
        db.add_event(conn, src, "action", f"[run] {command_str} ({note})",
                     target_id=target_id,
                     meta={"tool_run": rid, "risk": tier}, engagement_id=engagement_id)
        conn.commit()
    finally:
        conn.close()
    pump()
    return {"id": rid, "rid": rid, "status": status, "command": command_str,
            "background": True, "risk": tier, "risk_reason": why,
            "needs_approval": status == "queued"}


def _execute_scanner(rid, engagement_id, target_id, ip, tool, spec, opts, actor):
    """Generic argv-based tool executor — the path most Kali tools take. build_argv
    -> run -> capture -> route the machine output to the spec's declared parser BY
    IDENTITY (we ran the tool, no output-sniffing) -> persist + finalize. A TOOL_SPEC
    of kind "scanner" declares its machine output:
        "output": {"dest": "stdout"|"file", "flag": [..], "suffix": ".json", "parser": <name>}
    New argv tools plug in with a spec + a PARSERS entry — no bespoke executor."""
    o = spec["output"]
    parse_fn = PARSERS[o["parser"]]
    # url-target tools (httpx/nuclei) want a full URL; render host:port -> scheme://host:port
    tgt = spec.get("target", {})
    target = ip
    if tgt.get("url") and "://" not in ip:
        thost, tport = _split_host_port(ip, spec.get("default_port"))
        target = f"{tgt.get('scheme', 'http')}://{thost}:{tport}" if tport else f"{tgt.get('scheme', 'http')}://{thost}"
    argv = build_argv(spec, opts, target)

    outfile = None
    if o.get("dest") == "file":
        fd, outfile = tempfile.mkstemp(prefix="redops-tool-", suffix=o.get("suffix", ".out"))
        os.close(fd)
        argv = argv[:-1] + list(o.get("flag", [])) + [outfile, argv[-1]]
    net = tool_net()
    if net and spec.get("bin"):
        argv = ["docker", "run", "--rm", "--network", net, spec["bin"]] + argv[1:]

    conn = db.connect()
    conn.execute("UPDATE tool_runs SET command=? WHERE id=?",
                 (" ".join(shlex.quote(a) for a in argv), rid))
    conn.commit(); conn.close()

    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=spec["timeout"])
        out = p.stdout + (("\n[stderr]\n" + p.stderr) if p.stderr.strip() else "")
        status = "done"
    except FileNotFoundError:
        out, status, p = f"{spec.get('bin')} not found on PATH", "error", None
    except subprocess.TimeoutExpired:
        out, status, p = f"{tool} timed out after {spec['timeout']}s", "error", None
    except Exception as e:  # noqa: BLE001
        out, status, p = f"error: {e!r}", "error", None

    machine = ""
    if status == "done":
        if outfile:
            try:
                with open(outfile) as f:
                    machine = f.read()
            except OSError:
                machine = ""
        else:
            machine = p.stdout
    if outfile:
        try:
            os.unlink(outfile)
        except OSError:
            pass

    # opts MUST be in the envelope: a parser can only stamp trust honestly if it
    # can see how the tool was invoked. Without it every ldapsearch run looked
    # anonymous and every SMB run looked like a null session, fabricating
    # "Anonymous LDAP bind" / "SMB null session" findings into the report.
    envelope = {"tool": tool, "argv": argv, "status": status, "output": machine,
                "stdout": out, "params": {"ip": ip, "has_target": bool(target_id),
                                          "opts": opts or {},
                                          "port": spec.get("default_port")}}
    result = parse_fn(envelope)

    conn = db.connect()
    try:
        parsers.persist(conn, engagement_id, target_id, ip, result,
                        stage="observed", source="wire-auto")
        _finalize_run(conn, engagement_id, target_id, ip, tool, rid, actor,
                      result.summary, out, status)
    finally:
        conn.close()
    return result.summary


def _execute_nmap(rid, engagement_id, target_id, ip, tool, spec, opts, actor):
    """Execute an nmap run against the pre-created row `rid`, capturing XML to a
    temp file for deterministic parsing while keeping the human output for the
    operator, then persist the structured result."""
    argv = build_argv(spec, opts, ip)
    # -oX <tmpfile>: machine-readable XML for parsing; normal text still on stdout
    # for the operator (copy/paste-replicable in the report). Inserted before the
    # trailing ip arg.
    xmldir = tempfile.mkdtemp(prefix="redops-nmap-")
    xmlpath = os.path.join(xmldir, "scan.xml")
    # macOS testing: the host can't route to docker container IPs. If REDOPS_TOOL_NET
    # is set, run the scanner INSIDE that docker network so real container IPs
    # are reachable — no localhost port-forwards needed.
    net = tool_net()
    if net and spec["bin"] == "nmap":
        # -oX has to name a path that exists *in the container*. Passing the host
        # tempfile path (as this did) made nmap fail to open its XML, which
        # _parse_nmap_xml reports as None and _persist_results renders as
        # "no open ports" — a silent false negative on every docker-network scan,
        # which is the worst possible failure for a recon tool. Bind-mount the
        # directory and write to a fixed in-container path instead.
        argv = argv[:-1] + ["-oX", "/out/scan.xml", argv[-1]]
        argv = ["docker", "run", "--rm", "--network", net,
                "-v", f"{xmldir}:/out", "instrumentisto/nmap"] + argv[1:]
    else:
        argv = argv[:-1] + ["-oX", xmlpath, argv[-1]]
    conn = db.connect()
    conn.execute("UPDATE tool_runs SET command=? WHERE id=?",
                 (" ".join(shlex.quote(a) for a in argv), rid))
    conn.commit(); conn.close()

    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=spec["timeout"])
        out = p.stdout + (("\n[stderr]\n" + p.stderr) if p.stderr.strip() else "")
        status = "done"
    except FileNotFoundError:
        out, status = f"{spec['bin']} not found on PATH", "error"
    except subprocess.TimeoutExpired:
        out, status = f"{tool} timed out after {spec['timeout']}s", "error"
    except Exception as e:  # noqa: BLE001
        out, status = f"error: {e!r}", "error"

    parsed = _parse_nmap_xml(xmlpath) if status == "done" else None
    if status == "done" and parsed is None:
        # The scan ran but produced no readable XML. Reporting that as an empty
        # result is indistinguishable from "the host has nothing open", so an
        # operator reads a broken scanner as a clean host. Fail loudly instead.
        status = "error"
        out += ("\n[redops] nmap produced no readable XML at "
                f"{xmlpath} — results NOT parsed. This is a tool failure, "
                "not an empty host.")
    shutil.rmtree(xmldir, ignore_errors=True)

    conn = db.connect()
    try:
        summary, _ = _persist_results(conn, engagement_id, target_id, ip, parsed, out,
                                      status, rid, actor, tool)
    finally:
        conn.close()
    return {"id": rid, "status": status, "summary": summary}


# ---------------------------------------------------------------------------
# shared, queued, prioritised tool runner
#
# Operator and agent enqueue into ONE queue. Agent runs are ready by default;
# an operator can opt into approval for queued runs.
# A parallel pool (cap _CONCURRENCY) drains `ready` runs highest-priority first.
# When the optional scope guard is on, every run is checked before execution;
# the in-process scanner never passed through the Bash hook.

_CONCURRENCY = max(1, int(os.environ.get("REDOPS_TOOL_CONCURRENCY", "4")))
_pump_lock = threading.Lock()
# operator-side ranges never blocked by the runner's scope check (loopback +
# configured callback ranges); mirrors hooks/scope_guard.NEVER_BLOCK.
_NEVER_BLOCK = [ipaddress.ip_network("127.0.0.0/8")]


def _auto_approve_tools() -> bool:
    conn = db.connect()
    try:
        raw = db.setting(conn, "tool_auto_approve", "REDOPS_TOOL_AUTOAPPROVE", "1")
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    finally:
        conn.close()


def _scope_lists(conn, eng):
    def _load(key):
        raw = db.get_state(conn, f"{key}:{eng}", "")
        try:
            return json.loads(raw) if raw else []
        except (ValueError, TypeError):
            return []
    return _load("scope_in"), _load("scope_out")


def _scope_ok(conn, eng, ip):
    """(ok, reason). Enforce the engagement scope on the runner itself so a
    queued scan can't hit an out-of-scope box. Hostnames pass (no literal to
    judge); loopback/VPN ranges are never blocked."""
    if not _scope_guard_enabled(conn):
        return True, ""
    try:
        addr = ipaddress.ip_address((ip or "").split(":")[0])
    except ValueError:
        return True, ""
    if any(addr in n for n in _NEVER_BLOCK):
        return True, ""

    def _nets(lst):
        nets = []
        for x in lst:
            try:
                nets.append(ipaddress.ip_network(x, strict=False))
            except ValueError:
                pass
        return nets

    sin, sout = _scope_lists(conn, eng)
    for net in _nets(sout):
        if addr in net:
            return False, f"{ip} is out of scope ({net})"
    innets = _nets(sin)
    if innets and not any(addr in n for n in innets):
        return False, f"{ip} is outside the allowed scope"
    return True, ""


def enqueue(engagement_id, target_id, ip, tool, actor="operator", preset=None,
            opts=None, priority=None, port=None):
    """Queue a tool run. Agent runs auto-start by default; an operator may
    require approval. Returns {id, status} or {error}. Kicks the pump."""
    sid, spec, preset = _resolve_tool(tool, preset)
    if not spec:
        return {"error": f"unknown tool {tool!r}; have {sorted(tool_names())}"}
    if not ip:
        return {"error": "ip (or target_id) required"}
    if is_loopback((ip or "").split(":")[0]) and not loopback_allowed():
        return {"error": f"{ip} is loopback (the operator's own box) — excluded. "
                         f"Set REDOPS_ALLOW_LOOPBACK=1 to run it deliberately."}
    try:
        resolved = resolve_opts(spec, preset, opts)
        validate_opts(spec, resolved)
    except ValueError as e:
        return {"error": str(e)}
    if priority is None:
        priority = spec.get("default_priority", 5)
    src = "agent" if actor == "agent" else "user"
    conn = db.connect()
    try:
        # a typed tool aimed at a flagged asset is gated exactly like a raw
        # command aimed at it — same judgement, both paths.
        tier, why = asset_risk(conn, engagement_id, ip, port,
                               writes=spec.get("writes", spec["kind"] == "cve"))
        if tier == "destructive" and actor != "operator" and _scope_guard_enabled(conn):
            ready, status = False, "queued"
        else:
            ready = actor == "operator" or _auto_approve_tools()
            status = "ready" if ready else "queued"
        rid = db.insert(conn, "tool_runs", {
            "engagement_id": engagement_id, "target_id": target_id, "tool": sid,
            "command": "", "status": status, "actor": actor,
            "params_json": json.dumps({"kind": spec["kind"], "preset": preset, "opts": resolved,
                                       "ip": ip, "port": port}),
            "priority": priority, "output": "", "summary": "",
            "started_at": db.now(), "finished_at": None})
        note = "queued — needs approval" if status == "queued" else f"queued (p{priority})"
        db.add_event(conn, src, "action", f"[tool] {sid} → {ip} ({note})",
                     target_id=target_id, meta={"tool_run": rid}, engagement_id=engagement_id)
    finally:
        conn.close()
    pump()
    return {"id": rid, "status": status, "tool": sid, "ip": ip}


def approve_run(rid) -> dict | None:
    conn = db.connect()
    try:
        r = db.row(conn, "SELECT * FROM tool_runs WHERE id=?", (rid,))
        if not r or r["status"] != "queued":
            return r
        conn.execute("UPDATE tool_runs SET status='ready' WHERE id=?", (rid,))
        conn.commit()
        db.add_event(conn, "user", "note", f"[tool] approved run #{rid} ({r['tool']})",
                     target_id=r["target_id"], engagement_id=r["engagement_id"])
    finally:
        conn.close()
    pump()
    conn = db.connect()
    try:
        return db.row(conn, "SELECT * FROM tool_runs WHERE id=?", (rid,))
    finally:
        conn.close()


def cancel_run(rid) -> dict | None:
    conn = db.connect()
    try:
        r = db.row(conn, "SELECT * FROM tool_runs WHERE id=?", (rid,))
        if not r or r["status"] not in ("queued", "ready"):
            return r
        conn.execute("UPDATE tool_runs SET status='cancelled', finished_at=? WHERE id=?",
                     (db.now(), rid))
        conn.commit()
        return db.row(conn, "SELECT * FROM tool_runs WHERE id=?", (rid,))
    finally:
        conn.close()


def reset_orphans():
    """On startup, any run still 'running' is an orphan from a prior process — its
    worker thread died with the restart, so nothing will ever finish it. Mark it
    interrupted so it stops animating forever and frees its concurrency slot.
    (A fresh process has nothing legitimately running yet, so this is safe.)"""
    conn = db.connect()
    try:
        n = conn.execute(
            "UPDATE tool_runs SET status='error', finished_at=?, "
            "summary=CASE WHEN summary='' THEN 'interrupted by server restart' ELSE summary END "
            "WHERE status='running'", (db.now(),)).rowcount
        conn.commit()
        return n
    finally:
        conn.close()


def pump():
    """Launch ready runs (priority desc, oldest first) until the pool is full.
    Called on every enqueue/approve/finish, plus periodically by the API."""
    if not _pump_lock.acquire(blocking=False):
        return
    try:
        while True:
            conn = db.connect()
            try:
                # count only runs THIS pool scheduled — a synchronous run_command
                # row is also 'running' but nobody here is waiting on it, so
                # counting it would let one blocking curl shrink the pool.
                running = conn.execute(
                    "SELECT count(*) FROM tool_runs WHERE status='running' "
                    "AND pooled=1").fetchone()[0]
                if running >= _CONCURRENCY:
                    return
                row = db.row(conn, "SELECT * FROM tool_runs WHERE status='ready' "
                                   "ORDER BY priority DESC, id ASC LIMIT 1")
                if not row:
                    return
                # claim atomically so two pumps can't grab the same row
                cur = conn.execute("UPDATE tool_runs SET status='running', pooled=1, "
                                   "started_at=? WHERE id=? AND status='ready'",
                                   (db.now(), row["id"]))
                conn.commit()
                if cur.rowcount == 0:
                    continue
            finally:
                conn.close()
            threading.Thread(target=_worker, args=(row["id"],), daemon=True,
                             name=f"tool-{row['tool']}-{row['id']}").start()
    finally:
        _pump_lock.release()


def _worker(rid):
    """Scope-check then execute one claimed (running) run, then re-pump."""
    try:
        conn = db.connect()
        run = db.row(conn, "SELECT * FROM tool_runs WHERE id=?", (rid,))
        conn.close()
        if not run:
            return
        params = json.loads(run["params_json"] or "{}")
        eng, tid, tool = run["engagement_id"], run["target_id"], run["tool"]
        ip, port, kind = params.get("ip"), params.get("port"), params.get("kind")
        actor = run["actor"]
        spec = TOOL_SPECS.get(tool)

        if kind == "exec":
            # free-form command: scope is checked on the command STRING (there's no
            # single ip to check), the same chokepoint the sync path uses.
            src = "agent" if actor == "agent" else "user"
            parsed = _parse_command(run["command"])
            conn = db.connect()
            ok, reason = _command_scope_ok(conn, eng, parsed["command_str"])
            if not ok:
                conn.execute("UPDATE tool_runs SET status='blocked', output=?, summary=?, "
                             "finished_at=? WHERE id=?",
                             (f"SCOPE BLOCK: {reason}", reason, db.now(), rid))
                conn.commit()
                db.add_event(conn, src, "error", f"[run] BLOCKED: {reason}",
                             target_id=tid, meta={"tool_run": rid}, engagement_id=eng)
                conn.close()
                return
            conn.close()
            _exec_command(rid, eng, parsed["command_str"], parsed["argv"],
                          parsed["use_shell"], tid, src,
                          timeout=params.get("timeout", 1800))
            return

        conn = db.connect()
        ok, reason = _scope_ok(conn, eng, ip)
        if not ok:
            conn.execute("UPDATE tool_runs SET status='blocked', output=?, summary=?, "
                         "finished_at=? WHERE id=?",
                         (f"SCOPE BLOCK: {reason}", reason, db.now(), rid))
            conn.commit()
            db.add_event(conn, "user", "error", f"[tool] {tool} → {ip} BLOCKED: {reason}",
                         target_id=tid, meta={"tool_run": rid}, engagement_id=eng)
            conn.close()
            return
        conn.close()

        if kind == "http":
            _execute_http(rid, eng, tid, ip, port, tool, spec, actor)
        elif kind == "chat":
            _execute_chat(rid, eng, tid, ip, port, tool, spec, params.get("opts", {}), actor)
        elif kind == "cve":
            _execute_cve(rid, eng, tid, ip, tool, spec, params.get("opts", {}), actor)
        elif kind == "scanner":
            _execute_scanner(rid, eng, tid, ip, tool, spec, params.get("opts", {}), actor)
        else:
            _execute_nmap(rid, eng, tid, ip, tool, spec, params.get("opts", {}), actor)
    except Exception as e:
        conn = db.connect()
        conn.execute("UPDATE tool_runs SET status='error', summary=?, finished_at=? WHERE id=?",
                     (f"runner error: {e!r}", db.now(), rid))
        conn.commit(); conn.close()
    finally:
        pump()


def queue(conn, engagement_id=None):
    """Pending + running runs (the live queue), highest priority first."""
    sql = ("SELECT * FROM tool_runs WHERE status IN ('queued','ready','running')")
    p = []
    if engagement_id is not None:
        sql += " AND engagement_id=?"; p.append(engagement_id)
    sql += " ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END, priority DESC, id ASC"
    return db.rows(conn, sql, p)


# back-compat shim: old callers used run_async(...). Now it enqueues.
def run_async(engagement_id, target_id, ip, tool, actor="operator", port=None):
    return enqueue(engagement_id, target_id, ip, tool, actor=actor, port=port)
