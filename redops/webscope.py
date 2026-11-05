"""Exact web-chat scope for browser actions and direct API replay.

This is separate from the command-text IP/hostname guard. A permitted page does
not make arbitrary URLs on its host permitted API targets.
"""
from __future__ import annotations

from urllib.parse import unquote, urlsplit, urlunsplit
import ipaddress


def canonical_url(value: str, *, allow_query: bool = False) -> str:
    value = str(value).strip()
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("web scope requires an absolute http(s) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("web scope URL may not contain credentials or a fragment")
    host = parsed.hostname.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if parsed.scheme != "https" and (ip is None or not ip.is_loopback):
        raise ValueError("web scope requires HTTPS except for loopback tests")
    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("invalid web scope port")
    authority = host if ":" not in host else f"[{host}]"
    if port and not ((parsed.scheme == "https" and port == 443) or
                     (parsed.scheme == "http" and port == 80)):
        authority += f":{port}"
    path = parsed.path or "/"
    decoded = unquote(unquote(path))
    if "\\" in decoded or any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ValueError("web scope path may not traverse directories")
    if not allow_query and parsed.query:
        raise ValueError("web scope URL may not contain a query")
    return urlunsplit((parsed.scheme, authority, path, parsed.query if allow_query else "", ""))


def normalize_scope(pages: list[str], api_prefixes: list[str]) -> dict:
    if not isinstance(pages, list) or not isinstance(api_prefixes, list):
        raise ValueError("pages and api_prefixes must be lists")
    result = {
        "pages": sorted({canonical_url(x) for x in pages}),
        "api_prefixes": sorted({canonical_url(x) for x in api_prefixes}),
    }
    if not result["pages"]:
        raise ValueError("web scope needs at least one exact page URL")
    return result


def page_allowed(url: str, scope: dict) -> bool:
    try:
        parsed = canonical_url(url, allow_query=True)
    except ValueError:
        return False
    return parsed.split("?", 1)[0] in scope.get("pages", [])


def api_allowed(url: str, scope: dict) -> bool:
    try:
        parsed = canonical_url(url, allow_query=True).split("?", 1)[0]
    except ValueError:
        return False
    for prefix in scope.get("api_prefixes", []):
        root = prefix.rstrip("/")
        if parsed == root or parsed.startswith(root + "/"):
            return True
    return False
