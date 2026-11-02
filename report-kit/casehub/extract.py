"""Propose inventory entries from evidence already saved by report.py.

The adapters deliberately make proposals, not observations or claims.  The
source event and span remain available for a person to inspect before review.
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import re
import sys
from collections.abc import Callable, Iterator, Sequence
from urllib.parse import urlsplit

from .ledger import CaseHub, CaseHubError


IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w.])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?![\w.])")
HOSTNAME = re.compile(
    r"(?<![\w@/\\.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}(?![\w.(-])"
)
HOST_TLDS = frozenset(
    "com net org io edu gov mil int info biz dev app me co uk de fr nl at ch eu ca au us "
    "ru cn jp in local lan htb thm corp internal".split()
)
FILE_EXTENSIONS = frozenset(
    "txt php png jpg zip log sh c py html js css json xml md pdf conf cfg ini bak gz tar 7z exe dll so".split()
)
LISTING_LINE = re.compile(
    r"(?i)^\s*(?:[-dlcbps][rwxst-]{9}\s|\d{2}[-/]\d{2}[-/]\d{4}\s+"
    r"\d{1,2}:\d{2}|[d-][a-z-]{4}\s+\d{4}[-/]\d{2}[-/]\d{2})"
)
SCAN_HOST = re.compile(r"(?im)^Nmap scan report for\s+([^\r\n]+)")
PORT = re.compile(
    r"(?im)^[ \t]*(?P<port>\d{1,5})/(?P<proto>tcp|udp)[ \t]+"
    r"(?P<state>open\|filtered|closed\|filtered|open|closed|filtered)[ \t]+"
    r"(?P<service>[^\s\r\n]+)(?:[ \t]+(?P<version>[^\r\n]+))?"
)
URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
SHELL_PROMPT = re.compile(
    r"(?m)^[ \t]*(?P<user>[A-Za-z_][A-Za-z0-9_.-]*)@"
    r"(?P<host>[A-Za-z0-9_.-]+)(?::[^\r\n$#]*)?[$#](?=[ \t]|$)"
)
LOCAL_USER_AT_HOST = re.compile(
    r"(?<![\w@])(?P<user>[A-Za-z_][A-Za-z0-9_.-]*)@"
    r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)(?![\w.-])"
)
DOMAIN_USER = re.compile(r"(?<![\w\\])(?P<realm>[A-Za-z][\w.-]*)\\"
                         r"(?!(?:[nrt]\d|\d))(?P<user>[A-Za-z_][\w.-]*)(?!\w)")
UID_USER = re.compile(r"\buid=\d+\((?P<user>[A-Za-z_][\w.-]*)\)")
HOME_USER = re.compile(r"(?<!\w)/home/(?P<user>[A-Za-z_][\w.-]*)(?=/)")
LOGIN_AS = re.compile(r"(?i)\blogin as:?[ \t]+(?P<user>[A-Za-z_][\w.-]*)\b")
SU_USER = re.compile(r"(?<![\w-])su[ \t]+(?:-[ \t]+)?(?P<user>[A-Za-z_][\w.-]*)\b")
FLAG_USER = re.compile(r"(?<!\w)-u[ \t]+(?P<user>[A-Za-z_][\w.-]*)\b(?!://)")
ENDPOINT = re.compile(
    r"(?<![\w@/\\.-])(?P<host>\[[0-9A-Fa-f:.]+\]|"
    r"(?:\d{1,3}\.){3}\d{1,3}|"
    r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}):(?P<port>\d{1,5})(?!\w)"
)
SCAN_PORT_LIST = re.compile(r"(?im)^Host:[ \t]*(?P<host>\S+)(?:[ \t]+\([^\r\n)]*\))?"
                            r"[ \t]+Ports?:[ \t]*(?P<ports>[^\r\n]+)")
LIST_PORT = re.compile(r"(?P<port>\d{1,5})(?:/(?P<state>open\|filtered|closed\|filtered|open|closed|filtered)"
                       r"/(?P<proto>tcp|udp)(?://(?P<service>[^/,]*)(?:/[^,]*)?)?)?",
                       re.IGNORECASE)
UNIX_FILE = re.compile(r"(?<![\w:/])/(?:etc|var|home|usr|opt|tmp|root|srv|proc|sys)/"
                       r"[^\s<>\"'`]+")
WINDOWS_FILE = re.compile(r"(?<![\w])(?:[A-Za-z]:\\)(?:[^\\\s<>\"'`]+\\)*"
                          r"[^\\\s<>\"'`]+")
TITLE = re.compile(r"(?is)<title(?:\s[^>]*)?>(.*?)</title>")
TITLE_LINE = re.compile(r"(?im)^[ \t]*Title:[ \t]*(.+?)\s*$")
SERVER = re.compile(r"(?im)^[ \t]*Server:[ \t]*(.+?)\s*$")
HTTP_HOST = re.compile(r"(?im)^[ \t]*Host:[ \t]*([^\s\r\n]+)")
HOST_FIELD = re.compile(r"(?im)^[ \t]*(?:Host|Hostname):[ \t]*([^\s\r\n]+)")
IDENTITY_NOISE = frozenset(
    "through without usage authentication again exit id bak created at".split()
)

Adapter = Callable[[CaseHub, dict, str], list[dict]]


def _span(body: str, start: int, end: int) -> dict[str, int]:
    return {"start": start, "end": end, "line": body.count("\n", 0, start) + 1}


def _proposal(event: dict, body: str, *, type: str, key: str, label: str,
              attrs: dict, start: int, end: int, extractor: str,
              confidence: float, statement: str) -> dict:
    return {"type": type, "key": key.strip(), "label": label.strip(), "attrs": attrs,
            "source_events": [event["id"]], "source_span": _span(body, start, end),
            "extractor": extractor, "confidence": confidence,
            "level": "proposed", "statement": statement, "target": event.get("target")}


def _target_host(hub: CaseHub, event: dict) -> str | None:
    target = (hub.case().get("targets") or {}).get(event.get("target")) or {}
    return _valid_host(target.get("ip") or "")


def _valid_host(raw: str) -> str | None:
    value = raw.strip().strip("[]").lower()
    try:
        address = ipaddress.ip_address(value)
        return None if address.is_unspecified else str(address)
    except ValueError:
        pass
    labels = value.split(".")
    if (len(labels) < 2 or labels[-1] not in HOST_TLDS):
        return None
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
           for part in labels):
        return None
    return value


def _listing_filename(body: str, start: int, end: int) -> bool:
    line_start = body.rfind("\n", 0, start) + 1
    line_end = body.find("\n", end)
    line = body[line_start:line_end if line_end >= 0 else len(body)]
    if LISTING_LINE.match(line) and not line[end - line_start:].strip():
        return True
    return "Index of /" in body and bool(re.search(r"(?i)<a\s+href=", line))


def _code_attribute(body: str, start: int, end: int) -> bool:
    """Reject a hostname-shaped field when its line shows attribute syntax."""
    line_start = body.rfind("\n", 0, start) + 1
    line_end = body.find("\n", end)
    before = body[line_start:start]
    after = body[end:line_end if line_end >= 0 else len(body)]
    if re.match(r"[ \t]*=", after):
        return True
    first_label = body[start:end].split(".", 1)[0]
    return (len(first_label) == 1 and bool(re.match(r"[ \t]*,", after))
            and bool(re.search(rf"\b{re.escape(first_label)}\.[A-Za-z_]\w*\s*,", before)))


def _scan_host_value(text: str) -> str | None:
    # Nmap may print "name.example (192.0.2.1)".  Use the address as the
    # service key because it identifies the scanned endpoint most precisely.
    address = IPV4.search(text) or IPV6.search(text)
    if address and (valid := _valid_host(address.group())):
        return valid
    name = text.strip().split()[0] if text.strip() else ""
    return _valid_host(name)


def addresses(hub: CaseHub, event: dict, body: str) -> list[dict]:
    out: list[dict] = []
    for pattern in (IPV4, IPV6, HOSTNAME):
        for match in pattern.finditer(body):
            value = _valid_host(match.group())
            if not value or (pattern is HOSTNAME and (
                    _listing_filename(body, match.start(), match.end())
                    or _code_attribute(body, match.start(), match.end()))):
                continue
            out.append(_proposal(event, body, type="host", key=value, label=value,
                                 attrs={"address": value}, start=match.start(), end=match.end(),
                                 extractor="addresses@1", confidence=0.91,
                                 statement="Address or hostname appears in saved evidence"))
    # Scanner headers and prompts provide explicit context for host tokens.
    for match in SCAN_HOST.finditer(body):
        value = _scan_host_value(match.group(1))
        if value:
            out.append(_proposal(event, body, type="host", key=value, label=value,
                                 attrs={"address": value}, start=match.start(1), end=match.end(1),
                                 extractor="addresses@1", confidence=0.94,
                                 statement="Host named by scanner output"))
    for match in SHELL_PROMPT.finditer(body):
        host = _valid_host(match.group("host"))
        if not host:
            continue
        out.append(_proposal(event, body, type="host", key=host, label=host,
                             attrs={"address": host}, start=match.start("host"), end=match.end("host"),
                             extractor="addresses@1", confidence=0.85,
                             statement="Host named in user@host text"))
    for match in HOST_FIELD.finditer(body):
        raw = match.group(1)
        # HTTP Host headers may include a port; square brackets distinguish
        # IPv6 from that host:port form.
        if raw.count(":") == 1 and not raw.startswith("["):
            raw = raw.split(":", 1)[0]
        if host := _valid_host(raw):
            out.append(_proposal(event, body, type="host", key=host, label=host,
                                 attrs={"address": host}, start=match.start(1), end=match.end(1),
                                 extractor="addresses@1", confidence=0.87,
                                 statement="Host named by a Host or Hostname field"))
    return out


def scanner(hub: CaseHub, event: dict, body: str) -> list[dict]:
    out: list[dict] = []
    headers = list(SCAN_HOST.finditer(body))
    fallback = _target_host(hub, event)
    for match in PORT.finditer(body):
        port = int(match.group("port"))
        if not 1 <= port <= 65535:
            continue
        preceding = next((h for h in reversed(headers) if h.start() < match.start()), None)
        host = _scan_host_value(preceding.group(1)) if preceding else fallback
        if not host:
            continue
        host = host.lower()
        version_text = (match.group("version") or "").strip()
        product, _, version = version_text.partition(" ")
        attrs = {"host": host, "proto": match.group("proto").lower(), "port": port,
                 "state": match.group("state").lower(), "service": match.group("service"),
                 "product": product or match.group("service"), "version": version.strip()}
        key = f"{host}|{attrs['proto']}|{port}"
        out.append(_proposal(event, body, type="service", key=key,
                             label=f"{host}:{port}/{attrs['proto']} {attrs['service']}",
                             attrs=attrs, start=match.start(), end=match.end(),
                             extractor="scanner@1", confidence=0.96,
                             statement="Scanner port row in saved transcript"))
        # A service edge needs an entity at each endpoint.  This also handles
        # a transcript with a port table but no explicit scan-report header.
        host_start = preceding.start(1) if preceding else match.start()
        host_end = preceding.end(1) if preceding else match.end()
        out.append(_proposal(event, body, type="host", key=host, label=host,
                             attrs={"address": host}, start=host_start, end=host_end,
                             extractor="scanner@1", confidence=0.89,
                             statement="Host associated with scanner port row"))
    for match in SCAN_PORT_LIST.finditer(body):
        host = _valid_host(match.group("host"))
        if not host:
            continue
        out.append(_proposal(event, body, type="host", key=host, label=host,
                             attrs={"address": host}, start=match.start("host"),
                             end=match.end("host"), extractor="scanner@1", confidence=0.94,
                             statement="Host named by scanner port list"))
        for item in re.finditer(r"[^,]+", match.group("ports")):
            raw = item.group().strip()
            port_match = LIST_PORT.fullmatch(raw)
            if not port_match:
                continue
            port = int(port_match.group("port"))
            if not 1 <= port <= 65535:
                continue
            proto = (port_match.group("proto") or "tcp").lower()
            state = (port_match.group("state") or "unknown").lower()
            service = port_match.group("service") or ""
            attrs = {"host": host, "proto": proto, "port": port,
                     "state": state, "service": service}
            start = match.start("ports") + item.start()
            end = match.start("ports") + item.end()
            out.append(_proposal(event, body, type="service", key=f"{host}|{proto}|{port}",
                                 label=f"{host}:{port}/{proto} {service}".strip(),
                                 attrs=attrs, start=start, end=end,
                                 extractor="scanner@1", confidence=0.94 if service else 0.72,
                                 statement="Scanner port list in saved transcript"))
    return out


def endpoints(hub: CaseHub, event: dict, body: str) -> list[dict]:
    out: list[dict] = []
    for match in ENDPOINT.finditer(body):
        host = _valid_host(match.group("host"))
        port = int(match.group("port"))
        if not host or not 1 <= port <= 65535:
            continue
        out.append(_proposal(event, body, type="host", key=host, label=host,
                             attrs={"address": host}, start=match.start("host"),
                             end=match.end("host"), extractor="endpoint@1", confidence=0.83,
                             statement="Host in an IP or hostname and port token"))
        out.append(_proposal(event, body, type="service", key=f"{host}|tcp|{port}",
                             label=f"{host}:{port}/tcp", attrs={"host": host, "proto": "tcp",
                                                                   "port": port},
                             start=match.start(), end=match.end(), extractor="endpoint@1",
                             confidence=0.72, statement="Port in a host and port token"))
    return out


def _urls(body: str) -> Iterator[tuple[re.Match[str], str, str, str]]:
    for match in URL.finditer(body):
        raw = match.group().rstrip(".,;)]}")
        try:
            parsed = urlsplit(raw)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            continue
        host = _valid_host(host or "")
        if not host:
            continue
        authority = f"[{host}]" if ":" in host else host
        if port is not None:
            authority += f":{port}"
        origin = f"{parsed.scheme.lower()}://{authority}"
        yield match, raw, origin, parsed.path or ""


def urls(hub: CaseHub, event: dict, body: str) -> list[dict]:
    out: list[dict] = []
    for match, raw, origin, path in _urls(body):
        parsed = urlsplit(raw)
        end = match.start() + len(raw)
        host = parsed.hostname.lower()
        out.append(_proposal(event, body, type="host", key=host, label=host,
                             attrs={"address": host}, start=match.start(), end=end,
                             extractor="url@1", confidence=0.91,
                             statement="Host named by URL in saved evidence"))
        out.append(_proposal(event, body, type="application", key=origin, label=origin,
                             attrs={"origin": origin, "scheme": parsed.scheme.lower(),
                                    "host": host},
                             start=match.start(), end=end, extractor="url@1", confidence=0.96,
                             statement="URL origin in saved evidence"))
        if parsed.port is not None and 1 <= parsed.port <= 65535:
            out.append(_proposal(event, body, type="service", key=f"{host}|tcp|{parsed.port}",
                                 label=f"{host}:{parsed.port}/tcp",
                                 attrs={"host": host, "proto": "tcp", "port": parsed.port},
                                 start=match.start(), end=end, extractor="url@1", confidence=0.74,
                                 statement="Port named by URL in saved evidence"))
        if path and path != "/":
            out.append(_proposal(event, body, type="file", key=origin + path, label=path,
                                 attrs={"origin": origin, "path": path},
                                 start=match.start(), end=end, extractor="url@1", confidence=0.82,
                                 statement="URL path in saved evidence"))
    return out


def identities(hub: CaseHub, event: dict, body: str) -> list[dict]:
    out: list[dict] = []
    # Keep offsets unchanged so proposals still point into the original evidence.
    match_body = re.sub(r"\\[nrt]", "  ", body)
    patterns = ((SHELL_PROMPT, "host", 0.93), (LOCAL_USER_AT_HOST, "host", 0.85),
                (DOMAIN_USER, "realm", 0.88),
                (UID_USER, None, 0.96), (HOME_USER, None, 0.76),
                (LOGIN_AS, None, 0.85), (SU_USER, None, 0.65),
                (FLAG_USER, None, 0.65))
    for pattern, realm_group, confidence in patterns:
        for match in pattern.finditer(match_body):
            user = match.group("user")
            if pattern is DOMAIN_USER:
                domain = match.group("realm")
                if not (any(c.isupper() for c in domain) or _valid_host(domain)):
                    continue
            if (pattern not in (UID_USER, SHELL_PROMPT, LOCAL_USER_AT_HOST)
                    and user.lower() in IDENTITY_NOISE):
                continue
            realm = match.group(realm_group) if realm_group else "local"
            realm = realm.lower()
            out.append(_proposal(event, body, type="identity", key=f"{realm}\\{user.lower()}",
                                 label=f"{realm}\\{user}", attrs={"realm": realm, "name": user},
                                 start=match.start(), end=match.end(), extractor="identity@1",
                                 confidence=confidence,
                                 statement="Username appears in saved evidence"))
    return out


def paths(hub: CaseHub, event: dict, body: str) -> list[dict]:
    out: list[dict] = []
    for pattern in (UNIX_FILE, WINDOWS_FILE):
        for match in pattern.finditer(body):
            path = match.group().strip().rstrip(".,;)]}")
            if pattern is UNIX_FILE:
                path = re.sub(r"(?:\\[nrt])+$", "", path)
            if not path:
                continue
            out.append(_proposal(event, body, type="file", key=path, label=path,
                                 attrs={"path": path}, start=match.start(),
                                 end=match.start() + len(path), extractor="path@1",
                                 confidence=0.86, statement="File path in saved evidence"))
    return out


def http_metadata(hub: CaseHub, event: dict, body: str) -> list[dict]:
    title = TITLE.search(body) or TITLE_LINE.search(body)
    server = SERVER.search(body)
    if not title and not server:
        return []
    origins = [origin for _, _, origin, _ in _urls(body)]
    if not origins:
        header = HTTP_HOST.search(body)
        if header:
            raw_host = header.group(1)
            raw_host = raw_host.split("]", 1)[0] + "]" if raw_host.startswith("[") else raw_host.split(":", 1)[0]
            host = _valid_host(raw_host)
        else:
            host = _target_host(hub, event)
        if host:
            origins = [f"http://{host.lower()}"]
    if not origins:
        return []
    attrs: dict[str, str] = {}
    if title:
        attrs["title"] = " ".join(html.unescape(re.sub(r"<[^>]*>", "", title.group(1))).split())
    if server:
        attrs["server"] = server.group(1).strip()
    match = title or server
    assert match is not None
    return [_proposal(event, body, type="application", key=origin, label=origin,
                      attrs=attrs, start=match.start(), end=match.end(),
                      extractor="http_meta@1", confidence=0.9,
                      statement="HTTP title or Server header in saved evidence")
            for origin in dict.fromkeys(origins)]


ADAPTERS: list[Adapter] = [addresses, scanner, endpoints, urls, identities, paths, http_metadata]


def extract_event(hub: CaseHub, event: dict, body: str) -> list[dict]:
    """Return deduplicated entity proposals for one saved evidence event."""
    proposals: dict[tuple[str, str], dict] = {}
    for adapter in ADAPTERS:
        for candidate in adapter(hub, event, body):
            candidate["key"] = candidate["key"].strip()
            candidate["label"] = candidate["label"].strip()
            if (not any(char.isalnum() for char in candidate["key"])
                    or not any(char.isalnum() for char in candidate["label"])):
                continue
            if (candidate["type"] in {"host", "identity"}
                    and (re.search(r"\s", candidate["key"])
                         or re.search(r"\s", candidate["label"]))):
                continue
            key = (candidate["type"], candidate["key"].lower())
            prior = proposals.get(key)
            if prior is None:
                proposals[key] = candidate
            else:
                prior["attrs"].update({k: v for k, v in candidate["attrs"].items()
                                       if v not in ("", None)})
                if candidate["confidence"] > prior["confidence"]:
                    prior["confidence"] = candidate["confidence"]
                    prior["source_span"] = candidate["source_span"]
                    prior["extractor"] = candidate["extractor"]
                    prior["statement"] = candidate["statement"]
    return list(proposals.values())


def _edge_proposals(proposals: list[dict]) -> list[dict]:
    hosts = {p["key"].lower() for p in proposals if p["type"] == "host"}
    return [{"src_type": "service", "src_key": p["key"], "dst_type": "host",
             "dst_key": p["attrs"]["host"], "relation": "runs_on", "status": "inferred",
             "source_events": p["source_events"]}
            for p in proposals if p["type"] == "service" and p["attrs"]["host"] in hosts]


def _existing_extract_keys(hub: CaseHub) -> dict[str, str | None]:
    """Find prior extraction writes through the public ledger API."""
    keys: dict[str, str | None] = {}
    since_seq = 0
    while True:
        page = hub.records(kind="entity", since_seq=since_seq, limit=500)
        if not page:
            return keys
        keys.update({r["idempotency_key"]: r["epoch_id"] for r in page
                     if r.get("idempotency_key")})
        since_seq = page[-1]["seq"]


def extract_events(hub: CaseHub, event_ids: list[str], *, target: str | None = None,
                   dry_run: bool = False, min_confidence: float = 0.5) -> tuple[int, int]:
    """Run all extraction adapters over the specified synced evidence events."""
    try:
        min_confidence = float(min_confidence)
    except (TypeError, ValueError) as exc:
        raise CaseHubError("--min-confidence must be between 0 and 1") from exc
    if not 0 <= min_confidence <= 1:
        raise CaseHubError("--min-confidence must be between 0 and 1")
    selected = list(dict.fromkeys(event_ids))
    unknown = [event_id for event_id in selected if hub.evidence(event_id) is None]
    if unknown:
        raise CaseHubError(f"Unknown evidence event ID(s): {', '.join(unknown)}")
    prior_keys = {} if dry_run else _existing_extract_keys(hub)
    epoch_id = (hub.current_epoch() or {}).get("id")
    current_entities = {(e["type"], e["key"]): e["id"]
                        for e in hub.entities(epoch_id=epoch_id, limit=1_000_000)}
    entity_count = edge_count = 0
    for event_id in selected:
        event = hub.evidence(event_id, with_body=True)
        assert event is not None
        if target and event.get("target") != target:
            continue
        proposals = [p for p in extract_event(hub, event, event.get("body") or "")
                     if p["confidence"] >= min_confidence]
        edges = _edge_proposals(proposals)
        if dry_run:
            for proposal in proposals:
                print(json.dumps({"event_id": event_id, "entity": proposal}, ensure_ascii=False))
            for edge in edges:
                print(json.dumps({"event_id": event_id, "edge": edge}, ensure_ascii=False))
        else:
            ids: dict[tuple[str, str], str] = {}
            for proposal in proposals:
                extractor = proposal["extractor"]
                kind, key = proposal["type"], proposal["key"]
                normalized = (kind, key.lower())
                idempotency_key = f"extract:{extractor}:{event_id}:{kind}:{key}"
                if idempotency_key in prior_keys:
                    if prior_keys[idempotency_key] == epoch_id and normalized in current_entities:
                        ids[normalized] = current_entities[normalized]
                    continue
                entity_id = hub.record_entity(**proposal, idempotency_key=idempotency_key)
                ids[normalized] = entity_id
                current_entities[normalized] = entity_id
                prior_keys[idempotency_key] = epoch_id
            for edge in edges:
                src = ids.get((edge["src_type"], edge["src_key"].lower()))
                dst = ids.get((edge["dst_type"], edge["dst_key"].lower()))
                if not src or not dst:
                    continue
                existing = next((item for item in hub.neighbors(src)
                                 if item["src"] == src and item["dst"] == dst
                                 and item["relation"] == edge["relation"]), None)
                old_events = existing["source_events"] if existing else []
                if event_id not in old_events:
                    hub.add_edge(src, dst, edge["relation"], status="inferred",
                                 source_events=old_events + [event_id],
                                 explanation="Proposed from scanner port row")
        entity_count += len(proposals)
        edge_count += len(edges)
    return entity_count, edge_count


def main(hub: CaseHub, args: argparse.Namespace) -> int:
    hub.sync_evidence()
    selected = list(dict.fromkeys(getattr(args, "event", []) or []))
    if not selected:
        selected = [e["id"] for e in hub.case()["events"]]
    dry_run = bool(getattr(args, "dry_run", False))
    entity_count, edge_count = extract_events(
        hub, selected, target=getattr(args, "target", None), dry_run=dry_run,
        min_confidence=getattr(args, "min_confidence", 0.5))
    print(f"{'Proposed' if dry_run else 'Recorded'} {entity_count} entit{'y' if entity_count == 1 else 'ies'} "
          f"and {edge_count} edge{'s' if edge_count != 1 else ''} from saved evidence",
          file=sys.stderr if dry_run else sys.stdout)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m casehub.extract", description=__doc__)
    parser.add_argument("case", help="report.py case directory")
    parser.add_argument("--actor", help="actor for ledger writes (defaults to REPORT_ACTOR)")
    parser.add_argument("--event", action="append", default=[], metavar="ID")
    parser.add_argument("--target", metavar="T")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--min-confidence", type=float, default=0.5, metavar="N")
    return parser


if __name__ == "__main__":
    options = _parser().parse_args()
    try:
        with CaseHub(options.case, actor=options.actor) as casehub:
            raise SystemExit(main(casehub, options))
    except CaseHubError as exc:
        print(f"casehub: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
