"""httpx parser (D1) — pure, no DB. Parses httpx `-json` output (JSONL, one object
per probed URL) into: an endpoint node (titled), the web server, and the detected
tech stack as `framework` nodes with `backed-by` facts. All at stage=observed — we
fingerprinted it — so a tech the /about page only CLAIMED gets promoted to observed
by add_fact's dedup. See claudedocs/tools/httpx.md.
"""
from __future__ import annotations

import json

from . import ExtractResult, Fact


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
        r.status = "unrecognized"
        r.summary = "no httpx json output"
        r.notes.append("httpx produced no parseable -json lines")
        return r

    n_tech = 0
    for d in rows:
        host = str(d.get("host") or host_hint or "")
        port = str(d.get("port") or "")
        endpoint = f"{host}:{port}" if (host and port) else (host or str(d.get("url") or ""))
        if not endpoint:
            continue
        title = str(d.get("title") or "")
        r.entities.append({"type": "endpoint", "name": endpoint, "label": title})
        if host:
            r.entities.append({"type": "host", "name": host})
            r.facts.append(Fact(subject=endpoint, subject_type="endpoint", predicate="on-host",
                                object=host, object_type="host"))
        server = str(d.get("webserver") or "")
        if server:
            r.facts.append(Fact(subject=endpoint, subject_type="endpoint",
                                predicate="http-server", object_text=server))
        for tech in (d.get("tech") or []):
            tech = str(tech)
            if not tech:
                continue
            n_tech += 1
            r.entities.append({"type": "framework", "name": tech})
            r.facts.append(Fact(subject=endpoint, subject_type="endpoint", predicate="backed-by",
                                object=tech, object_type="framework"))
        sc = d.get("status_code")
        if sc in (401, 403):
            r.notes.append(f"{endpoint} returns {sc} — auth-gated")

    if has_target:
        r.target_updates["status_advance"] = True
    r.status = "ok"
    r.summary = f"{len(rows)} url(s), {n_tech} tech"
    return r


def parse(envelope: dict) -> ExtractResult:
    p = envelope.get("params") or {}
    return to_result(envelope.get("output") or "", host_hint=p.get("ip", ""),
                     has_target=p.get("has_target", True))
