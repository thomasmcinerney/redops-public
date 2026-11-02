"""ai-chat parser (D1) — pure, no DB. Turns a chat endpoint's response into
structured intel: the endpoint node, the model fingerprint, RAG retrieval provenance
(collections + a rag-backed fact), and the session-id PATTERN (the reusable
session-enum loot). Interpretive signals (refusal classification, candidate internal
hosts) go to `notes`, never facts. Fail-clean on shapes we don't recognize: zero
facts, status=unrecognized. See claudedocs/tools/ai-chat.md for the surface analysis.
"""
from __future__ import annotations

import json
import re

from . import ExtractResult, Fact

_ANSWER_KEYS = ("answer", "reply", "response", "text", "output", "content", "completion", "result")
_SOURCE_KEYS = ("sources", "rag_sources", "citations", "context", "documents", "retrieved")
_SESSION_KEYS = ("session_id", "conversation_id", "thread_id", "sid", "session")
_COLLECTION_KEYS = ("collection", "index", "store", "namespace", "kb")
_REFUSALS = ("i can't", "i cannot", "i'm not able", "i am not able", "cannot help",
             "unable to", "i won't", "i will not", "not allowed", "can't help",
             "against my", "as an ai", "i'm sorry, but i can", "i must decline")


def _reply_text(doc) -> str:
    if not isinstance(doc, dict):
        return ""
    ch = doc.get("choices")
    if isinstance(ch, list) and ch and isinstance(ch[0], dict):
        msg = ch[0].get("message") or {}
        if isinstance(msg, dict) and msg.get("content"):
            return str(msg["content"])
        if ch[0].get("text"):
            return str(ch[0]["text"])
    msg = doc.get("message")
    if isinstance(msg, dict) and msg.get("content"):
        return str(msg["content"])
    for k in _ANSWER_KEYS:
        v = doc.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _model(doc) -> str:
    if not isinstance(doc, dict):
        return ""
    if doc.get("model"):
        return str(doc["model"])
    ch = doc.get("choices")
    if isinstance(ch, list) and ch and isinstance(ch[0], dict):
        m = (ch[0].get("model") or (ch[0].get("message") or {}).get("model"))
        if m:
            return str(m)
    meta = doc.get("metadata")
    if isinstance(meta, dict) and meta.get("model"):
        return str(meta["model"])
    return ""


def _sources(doc):
    if not isinstance(doc, dict):
        return []
    for k in _SOURCE_KEYS:
        v = doc.get(k)
        if isinstance(v, list) and v:
            return v
    return []


def _session(doc) -> str:
    if not isinstance(doc, dict):
        return ""
    for k in _SESSION_KEYS:
        v = doc.get(k)
        if isinstance(v, (str, int)) and str(v):
            return str(v)
    return ""


def session_pattern(sid: str) -> str:
    """Generalize an observed session id to a shape token: an 8-digit run -> YYYYMMDD,
    other digit runs -> N*len, letters kept literally. MC-20260723-0042 -> MC-YYYYMMDD-NNNN."""
    return re.sub(r"\d+", lambda m: "YYYYMMDD" if len(m.group(0)) == 8 else "N" * len(m.group(0)), sid)


def _looks_internal(s: str) -> bool:
    s = (s or "").lower()
    return bool(re.search(r"\b(internal|intranet|corp|\.local|\.internal|localhost|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", s))


def _is_refusal(text: str) -> bool:
    t = (text or "").lower()
    return any(p in t for p in _REFUSALS)


def to_result(body: str, host: str, port, path: str, *, has_target: bool = True,
              status_code: int | None = None) -> ExtractResult:
    r = ExtractResult()
    endpoint = f"{host}:{port}{path}"

    if status_code in (401, 403):
        r.status = "unrecognized"
        r.summary = f"{endpoint}: auth required ({status_code})"
        r.notes.append(f"chat endpoint requires auth ({status_code}) — needs a credential/session")
        return r

    doc = None
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        doc = None

    reply = _reply_text(doc) if isinstance(doc, dict) else (body if isinstance(body, str) else "")
    model = _model(doc)
    sources = _sources(doc)
    sid = _session(doc)

    # fail-clean: no chat signal at all (empty, error page, or a non-chat JSON like a
    # health blob) => unrecognized, ZERO facts. A wrong `observed` fact is worse.
    if not (reply and reply.strip()) and not model and not sources and not sid:
        r.status = "unrecognized"
        r.summary = f"{endpoint}: unrecognized response"
        r.notes.append("response carried no chat signal (no reply/model/sources/session)")
        return r

    # the endpoint is real attack surface
    r.entities.append({"type": "endpoint", "name": endpoint, "meta": {"host": host, "port": port}})

    if model:
        r.entities.append({"type": "model", "name": model})
        r.facts.append(Fact(subject=endpoint, subject_type="endpoint",
                            predicate="runs-model", object=model, object_type="model"))

    if sources:
        r.facts.append(Fact(subject=endpoint, subject_type="endpoint", predicate="rag-backed",
                            object_text=f"{len(sources)} retrieved source(s) cited in the response"))
        seen_coll = set()
        for s in sources:
            if not isinstance(s, dict):
                continue
            coll = next((str(s[k]) for k in _COLLECTION_KEYS if s.get(k)), "")
            if coll and coll not in seen_coll:
                seen_coll.add(coll)
                r.entities.append({"type": "collection", "name": coll})
                r.facts.append(Fact(subject=endpoint, subject_type="endpoint",
                                    predicate="retrieves-from", object=coll, object_type="collection"))
            origin = str(s.get("source") or s.get("url") or s.get("title") or "")
            if origin and _looks_internal(origin):
                r.notes.append(f"citation leaks a possible internal source: {origin}")

    invoked = doc.get("tools_invoked") if isinstance(doc, dict) else None
    invoked = [str(name) for name in invoked if isinstance(name, str) and name] if isinstance(invoked, list) else []
    for name in dict.fromkeys(invoked):
        r.facts.append(Fact(subject=endpoint, subject_type="endpoint",
                            predicate="invoked-tool", object_text=name))

    sid = _session(doc)
    if sid:
        pat = session_pattern(sid)
        r.facts.append(Fact(subject=endpoint, subject_type="endpoint",
                            predicate="session-format", object_text=pat))

    if reply and _is_refusal(reply):
        r.notes.append("model refused (guardrail fired on this prompt) — try evasion/reframing")

    if has_target:
        r.target_updates["status_advance"] = True

    bits = []
    if model:
        bits.append(f"model {model}")
    if sources:
        bits.append(f"{len(sources)} rag source(s)")
    if sid:
        bits.append(f"session {session_pattern(sid)}")
    if invoked:
        bits.append("invoked " + ", ".join(dict.fromkeys(invoked)))
    r.status = "ok"
    r.summary = f"{endpoint}: " + (", ".join(bits) if bits else "responded")
    return r


def parse(envelope: dict) -> ExtractResult:
    """Contract entry: envelope carries the response body + request context."""
    p = envelope.get("params") or {}
    return to_result(envelope.get("output") or "", p.get("host", ""), p.get("port", ""),
                     p.get("path", "/chat"), has_target=p.get("has_target", True),
                     status_code=p.get("status_code"))
