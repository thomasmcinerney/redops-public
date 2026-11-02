"""Shared thin HTTP client for the RedOps API (stdlib urllib only).

Used by both the CLI (cli.py) and the MCP server (mcp_server.py).
Base URL: env REDOPS_URL, default http://127.0.0.1:9100
"""

import json
import os
import re
import urllib.error
import urllib.request
import uuid

BASE = os.environ.get("REDOPS_URL", "http://127.0.0.1:9100")

START_HINT = ("start the server: cd ~/redops && "
              "setsid nohup ./venv/bin/python -m redops.api > data/server.log 2>&1 &")


REQ_TIMEOUT = int(os.environ.get("REDOPS_HTTP_TIMEOUT", "15"))


class ApiError(Exception):
    pass


def _operator_headers() -> dict:
    """Attach the operator token ONLY when the caller opted in (the CLI sets
    REDOPS_OPERATOR=1). The MCP server shares this module and must never send it —
    the agent is not the operator, and the destructive gate depends on that."""
    if os.environ.get("REDOPS_OPERATOR") != "1":
        return {}
    try:
        from . import db
        return {"X-Redops-Operator": (db.DATA_DIR / "operator.token").read_text().strip()}
    except Exception:
        return {}


def req(method: str, path: str, body: dict | None = None, timeout: int | None = None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Content-Type": "application/json",
                                        **_operator_headers()})
    try:
        with urllib.request.urlopen(r, timeout=timeout if timeout is not None else REQ_TIMEOUT) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            if "json" in ctype:
                return json.loads(raw)
            return raw
    except urllib.error.HTTPError as e:
        raise ApiError(f"{method} {path} -> {e.code}: {e.read().decode(errors='replace')[:300]}")
    except urllib.error.URLError as e:
        raise ApiError(f"cannot reach RedOps API at {BASE}: {e.reason}. {START_HINT}")


def post_multipart(path: str, fields: dict, file_field: str, file_path: str):
    boundary = "----redops" + uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        if v is None:
            continue
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    with open(file_path, "rb") as f:
        payload = f.read()
    fname = os.path.basename(file_path)
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; "
                 f"filename=\"{fname}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
                 + payload + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    r = urllib.request.Request(BASE + path, data=body, method="POST",
                               headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ApiError(f"POST {path} -> {e.code}: {e.read().decode(errors='replace')[:300]}")
    except urllib.error.URLError as e:
        raise ApiError(f"cannot reach RedOps API at {BASE}: {e.reason}. {START_HINT}")


# Which engagement THIS process writes to. The CLI is the operator's hand and
# follows the active engagement; the MCP server installs a resolver that returns
# its ACP session's pin instead. Without this hook find_target resolved against
# the global active engagement, so ~a dozen target-bound MCP writes (svc_add,
# cred_add, finding_add, principal_add, evidence_add, tool_run…) followed the
# operator while the agent's facts followed the pin — half-pinned is not pinned.
_ENGAGEMENT_RESOLVER = None


def set_engagement_resolver(fn) -> None:
    global _ENGAGEMENT_RESOLVER
    _ENGAGEMENT_RESOLVER = fn


def current_engagement() -> int:
    return _ENGAGEMENT_RESOLVER() if _ENGAGEMENT_RESOLVER else default_engagement()


def find_target(ip: str) -> dict:
    # Scope to THIS caller's engagement. Lab IPs get reused across engagements, so
    # a global first-match resolved to a stale engagement's target and filed
    # scans/creds under the wrong engagement (engagement desync).
    eng = current_engagement()
    for t in req("GET", f"/api/targets?engagement_id={eng}"):
        if t["ip"] == ip:
            return t
    raise ApiError(f"target {ip} not found in the active engagement "
                   f"(add it first: redops target add {ip})")


def default_engagement() -> int:
    try:
        active = req("GET", "/api/active_engagement").get("id")
        if active:
            return active
    except ApiError:
        pass
    engs = req("GET", "/api/engagements")
    if not engs:
        raise ApiError("no engagements yet (add one: redops engage add NAME)")
    return engs[0]["id"]  # API returns newest first


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HOSTPORT_RE = re.compile(r"^[\w.-]+:\d{1,5}$")


def guess_type(value: str) -> str:
    if _IP_RE.match(value):
        return "host"
    if value.startswith(("http://", "https://")):
        return "endpoint"
    if value.startswith("/") or ("/" in value and not value.startswith("\\\\")):
        return "file"
    if _HOSTPORT_RE.match(value):
        return "service"
    return "other"
