"""nuclei parser (D1) — pure, no DB. Parses nuclei `-json`/`-jsonl` output (one
finding per line) into structured `findings` (title/severity/cve/matched_at), plus a
`vuln` entity + `affects` fact per finding so the graph shows what's hittable. All
observed. See claudedocs/tools/nuclei.md.
"""
from __future__ import annotations

import json

from . import ExtractResult, Fact, Finding

_SEV = {"critical", "high", "medium", "low", "info", "unknown"}


def _cve_of(template_id: str, tags) -> str:
    if template_id.upper().startswith("CVE-"):
        return template_id.upper()
    for t in (tags or []):
        if str(t).upper().startswith("CVE-"):
            return str(t).upper()
    return ""


def to_result(text: str, host_hint: str = "", *, has_target: bool = True) -> ExtractResult:
    r = ExtractResult()
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            if isinstance(d, dict):
                rows.append(d)
        except json.JSONDecodeError:
            continue

    if not rows:
        r.status = "empty"
        r.summary = "no nuclei findings"
        return r

    host = host_hint
    for d in rows:
        info = d.get("info") or {}
        tid = str(d.get("template-id") or d.get("templateID") or "")
        sev = str(info.get("severity") or "info").lower()
        if sev not in _SEV:
            sev = "info"
        cve = _cve_of(tid, info.get("tags"))
        matched = str(d.get("matched-at") or d.get("matched_at") or "")
        title = str(info.get("name") or tid or "nuclei finding")
        r.findings.append(Finding(title=title, severity=sev, cve=cve, matched_at=matched,
                                  description=str(info.get("description") or "")))
        host = str(d.get("host") or host).split("://")[-1].split("/")[0] or host
        # a vuln node the correlation engine can hang chains off of
        vname = cve or tid or title
        if vname and host:
            r.entities.append({"type": "vuln", "name": vname})
            r.entities.append({"type": "host", "name": host.split(":")[0]})
            r.facts.append(Fact(subject=vname, subject_type="vuln", predicate="affects",
                                object=host.split(":")[0], object_type="host"))

    if has_target:
        r.target_updates["status_advance"] = True
    sev_counts = {}
    for f in r.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    r.status = "ok"
    r.summary = f"{len(r.findings)} finding(s): " + ", ".join(
        f"{sev_counts[s]} {s}" for s in order if sev_counts.get(s))
    return r


def parse(envelope: dict) -> ExtractResult:
    p = envelope.get("params") or {}
    return to_result(envelope.get("output") or "", host_hint=p.get("ip", ""),
                     has_target=p.get("has_target", True))
