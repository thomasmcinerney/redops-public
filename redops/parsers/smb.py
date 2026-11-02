"""SMB share parser (D1) — pure, no DB. Handles the three tools that answer the
same question in three formats: `smbclient -L`, `smbmap -H`, and `nxc smb --shares`.

The question is "what can I reach, and can I reach it without credentials", so the
parser's real output is not a share list — it is:
  * a `file`-typed node per share, with a `shares` fact from the host
  * READ/WRITE access recorded as facts, because a writable share is a
    write-primitive and that is what the correlation engine scores
  * a Finding when a null/guest session enumerated anything, which is the
    vulnerability the share list is only evidence of

stage=observed throughout — argv-bound parse of output we asked for.
See claudedocs/tools/smb.md.
"""
from __future__ import annotations

import re

from . import ExtractResult, Fact, Finding, Service

# smbclient -L:   "  ShareName      Disk      Comment"
_SMBCLIENT_RE = re.compile(r"^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)$", re.I)
# smbmap: "  ShareName    READ, WRITE    Comment" — name FIRST, then permission
_SMBMAP_RE = re.compile(
    r"^\s*(\S+)\s{2,}(NO ACCESS|READ ONLY|READ,\s*WRITE|READ,\s*ONLY|WRITE ONLY|READ|WRITE)"
    r"\s*(.*)$", re.I)
# nxc:            "SMB  10.0.0.1  445  DC01  ShareName  READ,WRITE  Comment"
_NXC_SHARE_RE = re.compile(r"^SMB\s+\S+\s+\d+\s+\S+\s+(\S+)\s+(READ[,\s]*WRITE|READ|WRITE)?\s*(.*)$", re.I)
_NXC_HOST_RE = re.compile(r"^SMB\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\*\]\s*(.*)$", re.I)

_SKIP = {"ipc$", "print$"}


def _access(raw: str) -> tuple[bool, bool]:
    r = (raw or "").upper()
    return ("READ" in r), ("WRITE" in r)


def to_result(text: str, host_hint: str = "", *, authenticated: bool = False) -> ExtractResult:
    r = ExtractResult()
    lines = (text or "").splitlines()
    shares: dict[str, tuple[str, bool, bool]] = {}       # name -> (comment, read, write)
    os_str = domain = hostname = ""

    for ln in lines:
        m = _NXC_HOST_RE.match(ln)
        if m:
            hostname = hostname or m.group(3)
            banner = m.group(4)
            mo = re.search(r"\(name:([^)]*)\)", banner)
            md = re.search(r"\(domain:([^)]*)\)", banner)
            if md:
                domain = domain or md.group(1).strip()
            if mo:
                hostname = mo.group(1).strip() or hostname
            # banner is already the text AFTER "[*]": the OS is everything up to
            # the first "(name:...)" group.
            mos = re.match(r"\s*([^(]+)", banner)
            if mos:
                os_str = os_str or mos.group(1).strip()
            continue
        m = _SMBMAP_RE.match(ln)
        if m and m.group(1).lower() not in ("disk", "----"):
            name, perm, comment = m.group(1), m.group(2), m.group(3).strip()
            if perm.upper().startswith("NO ACCESS"):
                shares.setdefault(name, (comment, False, False))
            else:
                rd, wr = _access(perm)
                shares[name] = (comment, rd, wr)
            continue
        m = _NXC_SHARE_RE.match(ln)
        # nxc status lines ([+] auth ok, [-] failure, [*] banner) sit in the same
        # column as the share name — without this a line literally became a share
        # called "[+]", which the shipped test's own "3 shares" output showed and
        # its presence-only assertions never caught.
        if m and m.group(1).lower() not in ("share", "-----", "disk") \
                and not m.group(1).startswith(("[", "-")):
            name, perm, comment = m.group(1), m.group(2) or "", m.group(3).strip()
            rd, wr = _access(perm)
            shares[name] = (comment, rd, wr)
            continue
        m = _SMBCLIENT_RE.match(ln)
        if m:
            name, _kind, comment = m.group(1), m.group(2), m.group(3).strip()
            # smbclient -L lists what is VISIBLE; it does not prove readability
            shares.setdefault(name, (comment, False, False))

    if not shares and not hostname:
        r.status = "unrecognized"
        r.summary = "no SMB shares or host banner recognised"
        r.notes.append("smb output not understood (access denied, or an unsupported format)")
        return r

    if host_hint:
        r.services.append(Service(port=445, proto="tcp", name="microsoft-ds",
                                  product=os_str, extrainfo=(f"domain: {domain}" if domain else "")))
    if hostname and host_hint:
        r.facts.append(Fact(subject=host_hint, subject_type="host",
                            predicate="has-hostname", object_text=hostname))
    if domain:
        r.entities.append({"type": "network", "name": domain, "label": "AD domain"})
        if host_hint:
            r.facts.append(Fact(subject=host_hint, subject_type="host", predicate="joined-to",
                                object=domain, object_type="network"))
    if os_str:
        r.target_updates["os"] = "Windows" if "windows" in os_str.lower() else os_str

    writable, readable = [], []
    for name, (comment, rd, wr) in sorted(shares.items()):
        if name.lower() in _SKIP and not (rd or wr):
            continue
        node = f"//{host_hint}/{name}" if host_hint else name
        r.entities.append({"type": "file", "name": node, "label": comment or "SMB share"})
        if host_hint:
            r.facts.append(Fact(subject=host_hint, subject_type="host", predicate="shares",
                                object=node, object_type="file"))
        if wr:
            writable.append(name)
            # a writable share is a write-primitive — the thing the engine scores
            r.facts.append(Fact(subject=node, subject_type="file",
                                predicate="writable-by", object_text="anonymous"
                                if not authenticated else "authenticated session"))
        elif rd:
            readable.append(name)
            r.facts.append(Fact(subject=node, subject_type="file",
                                predicate="readable-by", object_text="anonymous"
                                if not authenticated else "authenticated session"))

    if not authenticated and (readable or writable):
        r.findings.append(Finding(
            title="SMB null session exposes shares",
            severity="critical" if writable else "high",
            matched_at=f"//{host_hint}" if host_hint else "smb",
            description=("An unauthenticated session enumerated shares: "
                         + (f"WRITABLE {', '.join(writable)}. " if writable else "")
                         + (f"readable {', '.join(readable)}." if readable else ""))))

    listed = [s for s in shares if s.lower() not in _SKIP]
    r.summary = (f"smb: {len(listed)} shares"
                 + (f", {len(writable)} writable" if writable else "")
                 + (f", {len(readable)} readable" if readable else "")
                 + (f" ({domain})" if domain else ""))
    if not listed:
        r.status = "empty"
        r.summary = "smb: host answered, no shares listed"
    return r


def parse(envelope: dict) -> ExtractResult:
    p = envelope.get("params") or {}
    opts = p.get("opts") or {}
    authed = bool(opts.get("user") or opts.get("username"))
    return to_result(envelope.get("output") or "", host_hint=p.get("ip", ""),
                     authenticated=authed)
