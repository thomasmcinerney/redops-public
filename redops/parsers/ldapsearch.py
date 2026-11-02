"""ldapsearch parser (D1) — pure, no DB. Parses LDIF from `ldapsearch -x`.

Two shapes, both common on an AD engagement:

  RootDSE  (`-s base`)   an anonymous bind that answers at all: namingContexts,
                         dnsHostName, domain functional level. Proves the bind
                         succeeded and names the domain.
  Subtree  (`-b <DN>`)   directory objects: users, groups, computers.

What it yields:
  * the domain as a `network` node, with the DC bound to it
  * every user as a PRINCIPAL (via persist_extra -> the real principals store,
    not the legacy credentials table) with the domain as its realm — this is
    what feeds the spray matrix
  * groups and computers as nodes with membership facts
  * a Finding when an anonymous bind returns directory objects, which is the
    actual vulnerability, not just an observation

Everything lands at stage=observed: an argv-bound deterministic parse of output
we asked for. See claudedocs/tools/ldapsearch.md.
"""
from __future__ import annotations

import re

from . import ExtractResult, Fact, Finding

# LDIF: "attr: value", or "attr:: <base64>" which we decode where it is text.
_ATTR_RE = re.compile(r"^([A-Za-z0-9;-]+)(::?)\s*(.*)$")


def _dn_to_domain(dn: str) -> str:
    """CN=x,OU=y,DC=examplelab,DC=ai -> examplelab.ai"""
    parts = re.findall(r"DC=([^,]+)", dn or "", re.I)
    return ".".join(p.strip() for p in parts if p.strip())


def _decode(marker: str, value: str) -> str:
    if marker != "::":
        return value
    import base64
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except Exception:                                    # noqa: BLE001 - not text
        return ""


def _entries(text: str) -> list[dict]:
    """Split LDIF into entries. Continuation lines start with a single space."""
    entries, cur = [], {}
    lines, i = (text or "").splitlines(), 0
    while i < len(lines):
        raw = lines[i]
        # unfold RFC2849 continuation lines before parsing
        while i + 1 < len(lines) and lines[i + 1].startswith(" "):
            raw += lines[i + 1][1:]
            i += 1
        i += 1
        line = raw.rstrip()
        if not line.strip():
            if cur:
                entries.append(cur)
                cur = {}
            continue
        if line.startswith("#"):
            continue
        m = _ATTR_RE.match(line)
        if not m:
            continue
        attr, marker, value = m.group(1).lower(), m.group(2), m.group(3).strip()
        value = _decode(marker, value)
        if not value:
            continue
        cur.setdefault(attr, []).append(value)
    if cur:
        entries.append(cur)
    return entries


def _is_user(objectclasses: list[str]) -> bool:
    """A real AD computer object carries objectClass: top, person,
    organizationalPerson, user, computer — so "user in oc" matches MACHINE
    accounts too. Checking computer/group FIRST keeps DC01$ out of the spray
    pool and lets it become a host node instead."""
    oc = {o.lower() for o in objectclasses}
    if oc & {"computer", "group", "msds-groupmanagedserviceaccount"}:
        return False
    return bool(oc & {"user", "person", "organizationalperson", "inetorgperson"})


def _is_computer(objectclasses: list[str]) -> bool:
    return "computer" in {o.lower() for o in objectclasses}


def _is_group(objectclasses: list[str]) -> bool:
    oc = {o.lower() for o in objectclasses}
    return "group" in oc and "computer" not in oc


def to_result(text: str, host_hint: str = "", *, anonymous: bool = True) -> ExtractResult:
    r = ExtractResult()
    entries = _entries(text)
    if not entries:
        r.status = "unrecognized"
        r.summary = "no LDIF entries"
        r.notes.append("ldapsearch returned no parseable LDIF (bind refused, or empty result)")
        return r

    domain = ""
    users: list[tuple[str, str]] = []          # (sam, upn)
    groups, computers, n_obj = [], [], 0

    for e in entries:
        dn = (e.get("dn") or [""])[0]
        oc = e.get("objectclass") or []
        # RootDSE: no dn, but namingContexts names the domain
        for nc in e.get("namingcontexts", []):
            domain = domain or _dn_to_domain(nc)
        for dh in e.get("dnshostname", []):
            r.entities.append({"type": "host", "name": dh, "label": "dc"})
            if host_hint:
                r.facts.append(Fact(subject=host_hint, subject_type="host",
                                    predicate="has-hostname", object_text=dh))
        if not dn:
            continue
        n_obj += 1
        domain = domain or _dn_to_domain(dn)
        sam = (e.get("samaccountname") or [""])[0]
        # computer/group tested BEFORE user: AD machine objects are also users.
        if _is_computer(oc):
            name = (sam or (e.get("cn") or [""])[0]).rstrip("$")
            if name:
                computers.append(name)
        elif _is_group(oc):
            name = sam or (e.get("cn") or [""])[0]
            if name:
                groups.append(name)
        elif _is_user(oc):
            upn = (e.get("userprincipalname") or [""])[0]
            name = sam or (e.get("cn") or [""])[0]
            if name:
                users.append((name, upn))

    if domain:
        r.entities.append({"type": "network", "name": domain, "label": "AD domain"})
        if host_hint:
            r.facts.append(Fact(subject=host_hint, subject_type="host",
                                predicate="serves-domain", object=domain,
                                object_type="network"))

    for g in sorted(set(groups)):
        r.entities.append({"type": "privilege", "name": g, "label": "AD group"})
    for c in sorted(set(computers)):
        r.entities.append({"type": "host", "name": c, "label": "domain-joined"})
        if domain:
            r.facts.append(Fact(subject=c, subject_type="host", predicate="joined-to",
                                object=domain, object_type="network"))

    # An anonymous bind that returns directory objects is the FINDING — the
    # usernames are the loot, the unauthenticated read is the vulnerability.
    if anonymous and (users or n_obj):
        r.findings.append(Finding(
            title="Anonymous LDAP bind exposes directory objects",
            severity="high" if users else "medium",
            matched_at=f"ldap://{host_hint}" if host_hint else "ldap",
            description=(f"An unauthenticated bind returned {n_obj} directory object(s)"
                         + (f", including {len(users)} user account(s)" if users else "")
                         + ". Harvested identities feed credential spraying.")))

    uniq = sorted({u for u, _ in users})
    if uniq:
        def _persist(conn, engagement_id, target_id, ip, name2id):
            """Users go to the PRINCIPALS store (the real one), not the legacy
            credentials table — a username with no secret is exactly what the
            principal/secret/binding split exists to represent."""
            from .. import db
            for u, upn in users:
                db.add_principal(conn, engagement_id, u, kind="username",
                                 realm=domain, target_id=target_id,
                                 source="ldapsearch", origin="observed")
                if upn and upn != u:
                    db.add_principal(conn, engagement_id, upn, kind="email",
                                     realm=domain, target_id=target_id,
                                     source="ldapsearch", origin="observed")
        r.persist_extra = _persist
        for u in uniq:
            r.entities.append({"type": "principal", "name": u, "label": domain or "AD user"})

    bits = []
    if uniq:
        bits.append(f"{len(uniq)} users")
    if groups:
        bits.append(f"{len(set(groups))} groups")
    if computers:
        bits.append(f"{len(set(computers))} computers")
    if domain:
        bits.append(domain)
    r.summary = "ldap: " + (", ".join(bits) if bits else f"{n_obj} objects")
    if not n_obj and not domain:
        r.status = "empty"
        r.summary = "ldap: bind answered, no objects returned"
    return r


def parse(envelope: dict) -> ExtractResult:
    p = envelope.get("params") or {}
    opts = p.get("opts") or {}
    # -x with no -D is an anonymous bind: that's what makes a hit a finding
    anon = not bool(opts.get("binddn"))
    return to_result(envelope.get("output") or "", host_hint=p.get("ip", ""),
                     anonymous=anon)
