"""nmap parser (D1) — pure, no DB. Drives ``-oX`` and parses the stable XML, never
the human text (nmap's XML schema is complete, so no regex fragility, no lost ports).

``to_result`` reproduces the full richness of the old ``_persist_results``: the
complete structured services list, the curated graph (interesting services as nodes,
the ephemeral RPC range rolled up, unfingerprinted ports rolled up honestly), the
host role/OS/AD-domain coalescing, the status advance, and the summary line. The
contract carries all of it — nmap is not sanded down to a common shape.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from . import ExtractResult, Fact, Service

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
_DOMAIN_RE = re.compile(r"Domain:\s*([A-Za-z0-9][A-Za-z0-9.\-]{1,60})")


def _root_to_parsed(root) -> dict:
    host = root.find("host")
    if host is None:
        return {"state": "down", "ports": []}
    st = host.find("status")
    ports = []
    for p in host.findall("./ports/port"):
        state = p.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = p.find("service")
        g = (lambda k: svc.get(k, "") if svc is not None else "")
        cpe = svc.find("cpe").text if (svc is not None and svc.find("cpe") is not None) else ""
        ports.append({"port": int(p.get("portid")), "proto": p.get("protocol", "tcp"),
                      "name": g("name"), "product": g("product"), "version": g("version"),
                      "extra": g("extrainfo"), "cpe": cpe or ""})
    return {"state": st.get("state") if st is not None else "unknown", "ports": ports}


def parse_path(path: str) -> dict | None:
    """Parse an nmap XML *file* -> {state, ports:[…]} (only OPEN ports). For the runner."""
    try:
        return _root_to_parsed(ET.parse(path).getroot())
    except (ET.ParseError, FileNotFoundError, OSError):
        return None


def parse_string(xml: str | bytes) -> dict | None:
    """Parse nmap XML *content* -> {state, ports}. For fixtures/tests."""
    try:
        return _root_to_parsed(ET.fromstring(xml))
    except ET.ParseError:
        return None


def _is_dynamic_rpc(s: dict) -> bool:
    """CONFIRMED dynamic RPC — nmap named it msrpc/ncacn_http in the ephemeral
    range. We only claim 'RPC' when nmap actually said so."""
    return s["port"] >= 49152 and (
        "rpc" in (s["name"] or "").lower() or (s["name"] or "").lower() == "ncacn_http")


def _is_interesting(s: dict) -> bool:
    if s["port"] in _HIGH_VALUE_PORTS:
        return True
    return bool(_INTERESTING_NAME.search((s["name"] or "") + " " + (s["product"] or "")))


def infer_role(ports: set[int]) -> str:
    """Deterministic host-role guess from the open-port signature."""
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


def host_os(ports) -> str:
    """Coalesce the OS from the structured service fields."""
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


def host_domain(ports) -> str:
    """The AD domain, straight out of the LDAP/Kerberos extrainfo field."""
    for s in ports:
        m = _DOMAIN_RE.search(s.get("extra") or "")
        if m:
            return m.group(1).rstrip(".,")
    return ""


def to_result(parsed: dict | None, ip: str, *, has_target: bool = True,
              status: str = "done") -> ExtractResult:
    """Map a parsed nmap scan into an ExtractResult, byte-faithful to the old
    _persist_results curation. `has_target` mirrors the old `target_id` guard on the
    role fact; `status` produces the honest no-ports / interrupted summary."""
    ports = (parsed.get("ports") or []) if parsed else []
    r = ExtractResult(status=("ok" if ports else ("empty" if status == "done" else "partial")))

    # (1) services table — every open port, structured
    for s in ports:
        r.services.append(Service(
            port=s["port"], proto=s["proto"], state="open", name=s["name"],
            product=s.get("product", ""), version=s.get("version", ""),
            extrainfo=s.get("extra", ""), cpe=s.get("cpe", "")))

    if not ports:
        r.summary = "no open ports" if status == "done" else status
        return r

    # (2) graph — three honest buckets
    r.entities.append({"type": "host", "name": ip})
    interesting = [s for s in ports if _is_interesting(s) and not _is_dynamic_rpc(s)]
    dyn = [s for s in ports if _is_dynamic_rpc(s)]
    classified = {s["port"] for s in interesting} | {s["port"] for s in dyn}
    unknown = [s for s in ports if s["port"] not in classified]
    for s in interesting:
        r.entities.append({"type": "service", "name": f"{ip}:{s['port']}", "label": s["name"] or ""})
        r.facts.append(Fact(subject=f"{ip}:{s['port']}", subject_type="service",
                            predicate="on-host", object=ip, object_type="host"))
    if dyn:
        r.facts.append(Fact(subject=ip, subject_type="host", predicate="exposes",
                            object_text=(f"dynamic RPC ({len(dyn)} ephemeral ports "
                                         f"{dyn[0]['port']}–{dyn[-1]['port']})")))
    if unknown:
        plist = ", ".join(str(s["port"]) for s in unknown[:25])
        r.facts.append(Fact(subject=ip, subject_type="host", predicate="exposes",
                            object_text=(f"{len(unknown)} open port(s) not fingerprinted: {plist} "
                                         f"— run a service scan (-sV) to identify")))

    # (3) role — target update always; the FACT only with a target (old guard)
    role = infer_role({s["port"] for s in ports})
    if role:
        r.target_updates["role"] = role
        if has_target:
            r.facts.append(Fact(subject=ip, subject_type="host", predicate="role", object_text=role))

    # (4) OS + AD domain identity
    os_guess = host_os(ports)
    if os_guess:
        r.target_updates["os"] = os_guess
    domain = host_domain(ports)
    if domain:
        r.entities.append({"type": "network", "name": domain})
        r.facts.append(Fact(subject=ip, subject_type="host", predicate="in-domain",
                            object=domain, object_type="network"))

    r.target_updates["status_advance"] = True

    parts = ", ".join(f"{s['port']} {s['name']}".strip() for s in interesting[:10])
    tails = ([f"+{len(dyn)} dyn-rpc"] if dyn else []) + \
            ([f"+{len(unknown)} unfingerprinted"] if unknown else [])
    tail = f" ({', '.join(tails)})" if tails else ""
    r.summary = (f"{len(ports)} open" + (f" [{role}]" if role else "")
                 + (f": {parts}{tail}" if (interesting or tails) else ""))
    return r


def parse(envelope: dict) -> ExtractResult:
    """Contract entry: envelope carries the machine output (-oX content) + params. Pure."""
    xml = (envelope.get("output") or envelope.get("xml")
           or (envelope.get("output_files") or {}).get("nmap.xml"))
    parsed = parse_string(xml) if xml else None
    p = envelope.get("params") or {}
    return to_result(parsed, p.get("ip", ""), has_target=p.get("has_target", True),
                     status=envelope.get("status", "done"))
