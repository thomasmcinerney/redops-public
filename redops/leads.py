"""Leads + worklist: categories, scoring, and the ranked worklist VIEW.

The worklist (spec §0) is a scored view, not a store: the ranked union of
open opportunities, open leads, and un-joined facts whose predicate is in the
interesting set. Facts derive category from predicate; leads carry it
explicitly; scoring keys off it uniformly.
"""

import json
import re
from datetime import datetime

from . import db

# 13 closed categories (8 classic + 5 AI)
CATEGORIES = {
    "write-primitive", "priv-context", "restart-trigger", "auth-gap",
    "reachability-pivot", "secret-exposure", "read-exfil", "anomaly",
    "llm-read-sink", "action-tool", "trust-edge", "detection-tripwire",
    "guardrail-blindspot",
}

PREDICATE_CATEGORY = {
    "writable-by": "write-primitive",
    "runs-as": "priv-context",
    "crashes": "restart-trigger",
    "respawns": "restart-trigger",
    "restart-trigger": "restart-trigger",
    "no-auth": "auth-gap",
    "valid-on": "secret-exposure",
    "has-cred": "secret-exposure",
    "is-read-by": "llm-read-sink",
    "has-tool": "action-tool",
    "trusts": "trust-edge",
    "logs-to": "detection-tripwire",
    "evades": "guardrail-blindspot",
    "readable-by": "read-exfil",
}

RULE_CATEGORY = {
    "R1": "auth-gap", "R2": "priv-context", "R3": "secret-exposure",
    "R4": "read-exfil", "R5": "trust-edge", "R6": "llm-read-sink",
    "R7": "reachability-pivot", "R10": "action-tool", "R11": "detection-tripwire",
    # R13/R14/R15 were unmapped and fell through to "anomaly" (weight 1) — which
    # buried the inbound callback, the single highest-signal vector we have,
    # at the BOTTOM of the worklist.
    "R13": "callback",              # ground truth off the wire, not a claim
    "R14": "confirm-claim",         # a claimed component asking to be verified
    "R15": "detection-tripwire",    # canary secret — a warning, not an avenue
}

BASE_WEIGHTS = {
    # a callback is OBSERVED off the wire — the target reached out to us. That's
    # out-of-band confirmation, not an assertion, so it outranks everything.
    "callback": 4,
    "write-primitive": 3, "priv-context": 3, "secret-exposure": 3,
    "llm-read-sink": 3, "action-tool": 3, "restart-trigger": 2,
    "auth-gap": 2, "reachability-pivot": 2, "read-exfil": 2, "trust-edge": 2,
    "detection-tripwire": 2, "guardrail-blindspot": 2,
    "confirm-claim": 2, "anomaly": 1,
}

PRIV_WORDS = {"root", "admin", "administrator", "system", "nt authority\\system"}
DECAY_FREE_HOURS = 48      # no decay within the engagement's first 48h
DECAY_PER_DAY = 0.5
MIN_PROXIMITY_WORD = 5

_WORD_RE = re.compile(r"[a-z0-9_.:/-]+", re.I)


def category_of_fact(f: dict) -> str:
    return PREDICATE_CATEGORY.get(f["predicate"], "anomaly")


def _fact_text(f: dict) -> str:
    return f"{f['subject_name']} {f['predicate']} {f['object_name'] or f['object_text'] or ''}"


def _is_priv(facts: list[dict]) -> bool:
    for f in facts:
        if f["predicate"] == "runs-as":
            obj = (f["object_name"] or f["object_text"] or "").lower()
            if obj in PRIV_WORDS:
                return True
    return False


def _objective_proximity(sitrep_text: str, item_text: str) -> int:
    if not sitrep_text:
        return 0
    for w in set(_WORD_RE.findall(item_text.lower())):
        if len(w) >= MIN_PROXIMITY_WORD and w in sitrep_text:
            return 1
    return 0


def _decay(eng_created: str, item_updated: str) -> float:
    try:
        eng_ts = datetime.fromisoformat(eng_created)
        item_ts = datetime.fromisoformat(item_updated)
    except (TypeError, ValueError):
        return 0.0
    now = datetime.now().astimezone()
    if (now - eng_ts).total_seconds() < DECAY_FREE_HOURS * 3600:
        return 0.0
    idle_days = max(0.0, (now - item_ts).total_seconds() / 86400.0)
    return DECAY_PER_DAY * idle_days


def _ctx_data(conn, engagement_id):
    sitrep = db.row(conn, "SELECT activity, next_steps FROM sitrep WHERE engagement_id=?",
                    (engagement_id,)) or {}
    sitrep_text = ((sitrep.get("activity") or "") + " " + (sitrep.get("next_steps") or "")).lower()
    eng = db.row(conn, "SELECT created_at FROM engagements WHERE id=?", (engagement_id,)) or {}
    joined = {r["fact_id"] for r in db.rows(conn, "SELECT fact_id FROM opportunity_facts")}
    return sitrep_text, eng.get("created_at", ""), joined


def score_item(category: str, facts: list[dict], text: str, updated_at: str,
               rules_touching: int, eng_created: str, sitrep_text: str,
               extra_attached: int = 0) -> float:
    """Spec §4 formula (constants module-level; do not over-tune)."""
    return (BASE_WEIGHTS.get(category, 1)
            + 0.5 * rules_touching
            + 0.5 * extra_attached          # proven-cred boost for expansion leads
            + (1 if _is_priv(facts) else 0)
            + _objective_proximity(sitrep_text, text)
            - _decay(eng_created, updated_at))


def recompute_scores(conn, engagement_id: int) -> None:
    """Recompute and persist lead scores. Frozen on promote (skipped)."""
    sitrep_text, eng_created, _ = _ctx_data(conn, engagement_id)
    opp_facts = db.rows(conn, "SELECT opportunity_id, fact_id FROM opportunity_facts")
    rules_by_fact: dict[int, int] = {}
    for r in opp_facts:
        rules_by_fact[r["fact_id"]] = rules_by_fact.get(r["fact_id"], 0) + 1
    for lead in db.rows(conn, "SELECT * FROM leads WHERE engagement_id=? AND status != 'promoted'",
                        (engagement_id,)):
        fids = json.loads(lead["fact_ids"] or "[]")
        facts = [db.row(conn, db.FACT_SQL + " WHERE f.id=?", (fid,)) for fid in fids]
        facts = [f for f in facts if f]
        rules_touching = sum(rules_by_fact.get(fid, 0) for fid in fids)
        lead["score"] = score_item(
            lead["category"], facts, lead["observation"] + " " + (lead["candidate_vector"] or ""),
            lead["updated_at"], rules_touching, eng_created, sitrep_text,
            extra_attached=max(0, len(fids) - 1))
        conn.execute("UPDATE leads SET score=?, last_scored_at=? WHERE id=?",
                     (round(lead["score"], 2), db.now(), lead["id"]))
    conn.commit()


def worklist(conn, engagement_id: int) -> list[dict]:
    """The ranked view: open opportunities + open leads + un-joined interesting facts."""
    sitrep_text, eng_created, joined = _ctx_data(conn, engagement_id)
    all_facts = {f["id"]: f for f in db.rows(conn, db.FACT_SQL +
                                             " WHERE f.engagement_id=? AND f.status='active'",
                                             (engagement_id,))}
    rules_by_fact: dict[int, list[int]] = {}
    for r in db.rows(conn, "SELECT opportunity_id, fact_id FROM opportunity_facts"):
        rules_by_fact.setdefault(r["fact_id"], []).append(r["opportunity_id"])

    items = []

    for o in db.rows(conn, "SELECT * FROM opportunities WHERE engagement_id=? "
                           "AND status IN ('open','pinned')", (engagement_id,)):
        fids = [r["fact_id"] for r in db.rows(
            conn, "SELECT fact_id FROM opportunity_facts WHERE opportunity_id=?", (o["id"],))]
        facts = [all_facts[fid] for fid in fids if fid in all_facts]
        cat = RULE_CATEGORY.get(o["rule"], "anomaly")
        score = score_item(cat, facts, o["title"] + " " + o["rationale"], o["updated_at"],
                           len(fids), eng_created, sitrep_text)
        items.append({"kind": "opportunity", "id": o["id"], "title": o["title"],
                      "rationale": o["rationale"], "category": cat, "rule": o["rule"],
                      "status": o["status"], "detected": o["detected"],
                      "fact_ids": fids, "score": round(score, 2)})

    for lead in db.rows(conn, "SELECT * FROM leads WHERE engagement_id=? AND status='open'",
                        (engagement_id,)):
        fids = json.loads(lead["fact_ids"] or "[]")
        items.append({"kind": "lead", "id": lead["id"], "title": lead["observation"],
                      "rationale": lead["candidate_vector"], "category": lead["category"],
                      "rule": lead["source"], "status": lead["status"], "detected": 0,
                      "fact_ids": fids, "score": lead["score"]})

    for f in all_facts.values():
        if f["id"] in joined:
            continue
        cat = category_of_fact(f)
        if f["predicate"] not in PREDICATE_CATEGORY:
            continue
        score = score_item(cat, [f], _fact_text(f), f["ts"], 0, eng_created, sitrep_text)
        items.append({"kind": "fact", "id": f["id"], "title": _fact_text(f),
                      "rationale": "", "category": cat, "rule": "", "status": f["status"],
                      "detected": 0, "fact_ids": [f["id"]], "score": round(score, 2)})

    items.sort(key=lambda x: (-x["score"], -x["id"]))
    return items
