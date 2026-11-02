"""agent-card / A2A / OpenAPI parser (D1) — pure, no DB. Turns fetched JSON
(`/.well-known/agent.json`, `/health`, `/openapi.json`) into agent/model/endpoint
entities + facts. Deterministic, no LLM. Faithful to the old _persist_http_results,
including the agent node's host/port meta (carried through the contract, not lost).

Input `results` is {path: (status_code, text)} exactly as the http runner captures.
"""
from __future__ import annotations

import json

from . import ExtractResult, Fact


def _docs(results: dict):
    """Pull the card / health / openapi JSON docs out of the fetched responses."""
    card = health = openapi = None
    for path, (code, text) in results.items():
        if code == 200 and text.strip().startswith(("{", "[")):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                continue
            if "agent.json" in path:
                card = doc
            elif "openapi" in path:
                openapi = doc
            elif "health" in path:
                health = doc
    return card, health, openapi


def raw_output(results: dict) -> str:
    """The concatenated GET dump kept for the operator (report-replicable)."""
    return "\n".join(f"# GET {path}  ->  {code}\n{text}\n" for path, (code, text) in results.items())


def to_result(results: dict, host: str, port, *, has_target: bool = True) -> ExtractResult:
    card, health, openapi = _docs(results)
    r = ExtractResult()

    agent_name = ""
    if isinstance(card, dict):
        agent_name = card.get("name") or (health or {}).get("agent") or f"{host}:{port}"
    elif isinstance(health, dict):
        agent_name = health.get("agent") or f"{host}:{port}"

    if not agent_name:
        r.status = "empty"
        r.summary = "no agent card found"
        return r

    # agent node carries host/port meta (superset contract preserves it)
    r.entities.append({"type": "agent", "name": agent_name, "meta": {"host": host, "port": port}})
    r.entities.append({"type": "host", "name": host})
    r.facts.append(Fact(subject=agent_name, subject_type="agent", predicate="on-host",
                        object=host, object_type="host"))

    model = None
    if isinstance(card, dict):
        model = (card.get("metadata") or {}).get("model") or card.get("model")
    if model:
        r.entities.append({"type": "model", "name": str(model)})
        r.facts.append(Fact(subject=agent_name, subject_type="agent", predicate="runs-model",
                            object=str(model), object_type="model", stage="claimed"))

    skills = (card or {}).get("skills") or []
    for sk in (skills if isinstance(skills, list) else []):
        name = (sk.get("name") or sk.get("id")) if isinstance(sk, dict) else str(sk)
        if name:
            r.facts.append(Fact(subject=agent_name, subject_type="agent",
                                predicate="has-skill", object_text=str(name), stage="claimed"))
            r.facts.append(Fact(subject=agent_name, subject_type="agent",
                                predicate="has-tool", object_text=str(name), stage="claimed"))

    eps = list((openapi or {}).get("paths", {}).keys()) if isinstance(openapi, dict) else []
    for ep in eps[:40]:
        r.facts.append(Fact(subject=agent_name, subject_type="agent",
                            predicate="exposes", object_text=ep, stage="claimed"))

    rag = health.get("rag") if isinstance(health, dict) else None
    if not rag and isinstance(card, dict):
        rag = (card.get("metadata") or {}).get("rag")
    if rag:
        rag_name, _, rag_loc = str(rag).partition("@")
        rag_name = rag_name.strip() or str(rag)
        r.entities.append({"type": "rag-store", "name": rag_name,
                           "meta": {"endpoint": rag_loc or ""}})
        r.facts.append(Fact(subject=rag_name, subject_type="rag-store",
                            predicate="is-read-by", object=agent_name, object_type="agent",
                            stage="claimed"))
        rag_host, _, _ = rag_loc.partition(":")
        rag_host = rag_host.strip()
        if rag_host and rag_host != host:
            r.entities.append({"type": "host", "name": rag_host})
            r.facts.append(Fact(subject=rag_name, subject_type="rag-store",
                                predicate="on-host", object=rag_host, object_type="host",
                                stage="claimed"))

    if has_target:
        r.target_updates["status_advance"] = True

    facts_made = len(r.facts)
    r.summary = (f"agent '{agent_name}'"
                 + (f" · model {model}" if model else "")
                 + f" · {facts_made} facts")
    r.status = "ok"
    return r
