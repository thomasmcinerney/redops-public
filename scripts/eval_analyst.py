"""Measure what a model actually extracts. Run:

    uv run python scripts/eval_analyst.py                      # all configured models
    uv run python scripts/eval_analyst.py --model qwen/qwen3.6-27b --url http://127.0.0.1:1234/v1

The analyst has shipped with "PRECISION IS UNMEASURED" in its docstring since it
was written, because measuring it needs labelled windows and there were none.
This is that labelled set.

It scores the real code path — `analyst._chat`, with its schema ladder and its
predicate enum — so a model is judged on what RedOps would actually get from it,
not on a friendlier prompt written for the benchmark.

Four numbers per model:

  recall     of the facts a window genuinely supports, how many appeared
  spurious   facts emitted that the window does not support (per case)
  vocab      fraction of predicates inside correlate.CORRELATED_PREDICATES —
             anything outside it is inert, so this is "how much of the output
             could reach a rule at all"
  fires      whether the model's own output, loaded into a scratch graph and
             run through the real correlate.py, raises the rule the window is
             about. This is the number that matters. R2 and R10 need two or
             three facts that join, and a model that gets every fact
             individually right while naming the subject differently each time
             scores full recall and produces nothing. Rather than approximate
             that with a hand-rolled proxy, this inserts the facts and asks the
             engine.

`no_facts` is the precision control — a window about nothing, where the correct
answer is an empty list and any output is invention.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("REDOPS_DATA", "/tmp/redops-eval-data")

from redops import analyst, correlate, db  # noqa: E402

db.init_db()

# --------------------------------------------------------------- the labels
#
# `expect` is (subject-substring, exact-predicate, object-substring); matching is
# deliberately loose on the names and exact on the predicate, because a rule
# joins on the predicate string but a human reading the Intel tab can live with
# "qdrant" vs "qdrant service".
#
# `chain` names the facts that have to share a subject for the rule to fire.

CASES = [
    {
        "name": "nmap",
        "window": "[t1] (user/output) [tool] nmap 10.10.10.5: Nmap scan report for 10.10.10.5\n"
                  "22/tcp open ssh OpenSSH 9.6\n443/tcp open https nginx 1.24",
        "expect": [("10.10.10.5", "listens-on", "22")],
    },
    {
        "name": "agent-card",
        "window": '[t1] (user/output) [tool] agent-probe 10.99.7.10:8000\n'
                  '{"name":"support-assistant","metadata":{"model":"qwen2.5-7b-instruct"},'
                  '"skills":[{"name":"exec_sql"},{"name":"fs_read"}]}',
        "expect": [("support-assistant", "runs-model", "qwen2.5-7b"),
                   ("support-assistant", "has-tool", "exec_sql")],
    },
    {
        "name": "r2-privesc",
        "window": "[t1] (agent/reasoning) the qdrant service on db01 runs as root, and "
                  "/etc/qdrant/config.yaml is writable by our user www-data",
        "expect": [("qdrant", "runs-as", "root"),
                   ("config", "writable-by", "www-data")],
        "rule": "R2",
    },
    {
        "name": "r10-injection",
        "window": "[t1] (agent/reasoning) POST /kb/upload with no credentials returned stored "
                  "true, so kb-store accepts unauthenticated writes. A later POST /chat "
                  "replied with the planted document in its context and reported "
                  "tools_invoked [exec_sql], so kb-store is read by support-assistant and "
                  "instructions inside it reach its tools.",
        "expect": [("kb-store", "accepts", ""),
                   ("kb-store", "is-read-by", "support-assistant"),
                   ("support-assistant", "has-tool", "exec_sql")],
        "rule": "R10",
    },
    {
        "name": "creds",
        "window": "[t1] (agent/output) cat /opt/app/config.toml\n"
                  "db_user = svc_backup\ndb_password = Hunter2!Winter",
        "expect": [("config.toml", "has-cred", "Hunter2")],
    },
    {
        "name": "ssrf-imds",
        "window": "[t1] (agent/output) POST /tools/http_fetch {\"url\":"
                  "\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"} "
                  "returned 200 with an AccessKeyId and SecretAccessKey",
        "expect": [("http_fetch", "has-primitive", "")],
    },
    {
        "name": "detection",
        "window": "[t1] (user/note) ELK rule 'AIM3: Prompt Injection Keywords' fired on our "
                  "char-spacing payload at 14:02",
        "expect": [("", "fired", ""), ("", "flagged", ""), ("", "detected-by", "")],
        "any_of": True,      # any one of the three detection predicates is right
    },
    {
        "name": "no_facts",
        "window": "[t1] (user/note) operator opened the dashboard and reviewed the worklist\n"
                  "[t2] (user/note) took a break, no scans run",
        "expect": [],
        "must_be_empty": True,
    },
]

REFUSAL_MARKERS = ("i cannot", "i can't", "i won't", "unable to assist", "as an ai",
                   "not appropriate", "i'm sorry", "cannot help", "against my")


def _norm(s):
    return "".join(c for c in str(s or "").lower() if c.isalnum())


def _matches(fact, want):
    ws, wp, wo = want
    if fact.get("predicate") != wp:
        return False
    if ws and _norm(ws) not in _norm(fact.get("subject")):
        return False
    if wo and _norm(wo) not in _norm(fact.get("object")):
        return False
    return True


_EVAL_ENG = [0]


def _fires(facts, rule):
    """Load `facts` into a throwaway engagement and ask correlate.py whether
    `rule` raises. The engine is the authority on whether output is inert, so
    nothing here re-implements a join condition."""
    conn = db.connect()
    try:
        _EVAL_ENG[0] += 1
        eng = db.insert(conn, "engagements",
                        {"name": f"eval-{_EVAL_ENG[0]}", "scope": "", "notes": "",
                         "created_at": db.now()})
        for f in facts:
            subj = str(f.get("subject") or "").strip()
            obj = str(f.get("object") or "").strip()
            pred = str(f.get("predicate") or "").strip()
            if not (subj and pred):
                continue
            sid = db.upsert_entity(conn, eng, _guess(subj), subj)
            oid = db.upsert_entity(conn, eng, _guess(obj), obj) if obj and " " not in obj else None
            db.add_fact(conn, eng, sid, pred, oid, "" if oid else obj,
                        "confirmed", "analyst")
        conn.commit()
        correlate.run(conn, eng)
        conn.commit()
        hit = db.rows(conn, "SELECT rule FROM opportunities WHERE engagement_id=?", (eng,))
        return any(r["rule"] == rule for r in hit)
    finally:
        conn.close()


# Types recon would already have established before the analyst ever runs. R1
# and R2 gate on subject type, and `_guess_type` calls a bare service name
# `other` — so on a COLD graph R2 cannot fire no matter what the model emits.
# That is a real property of production too (the analyst's facts chain only when
# the entity already exists correctly typed, which is what nmap/agent-probe
# provide), but measuring only the cold case blames the model for the graph.
# --warm seeds the types the way a scanned engagement would.
WARM_TYPES = {"qdrant": "service", "/etc/qdrant/config.yaml": "config",
              "db01": "host", "support-assistant": "agent", "kb-store": "rag-store"}
WARM = [False]


def _guess(name):
    from redops.api import _guess_type
    if WARM[0]:
        # longest key first: "qdrant" is a substring of
        # "/etc/qdrant/config.yaml", and typing the config file as a service
        # silently re-breaks the R2 gate this mode exists to open.
        for k in sorted(WARM_TYPES, key=len, reverse=True):
            if k.lower() in str(name).lower():
                return WARM_TYPES[k]
    return _guess_type(name)


def score_case(case, facts):
    """(hits, expected, spurious, chain_ok)."""
    exp = case["expect"]
    if case.get("must_be_empty"):
        return 0, 0, len(facts), None
    if case.get("any_of"):
        hit = any(any(_matches(f, w) for f in facts) for w in exp)
        return (1 if hit else 0), 1, 0, None

    matched_idx = set()
    for i, w in enumerate(exp):
        if any(_matches(f, w) for f in facts):
            matched_idx.add(i)
    hits = len(matched_idx)
    # spurious = emitted facts that match no expectation
    spurious = sum(1 for f in facts if not any(_matches(f, w) for w in exp))

    chain_ok = _fires(facts, case["rule"]) if case.get("rule") else None
    return hits, len(exp), spurious, chain_ok


def run_model(label, url, model, cases=CASES, verbose=False):
    analyst.ANALYST_URL, analyst.ANALYST_MODEL = url, model
    tot_hits = tot_exp = tot_spur = 0
    preds, chains, errors, refusals, elapsed = [], [], 0, 0, 0.0
    per_case = {}

    for c in cases:
        t0 = time.time()
        try:
            out = analyst._chat(c["window"])
            facts = out.get("facts") or []
        except Exception as e:                                   # noqa: BLE001
            errors += 1
            per_case[c["name"]] = f"ERR {type(e).__name__}"
            blob = str(e).lower()
            if any(m in blob for m in REFUSAL_MARKERS):
                refusals += 1
            continue
        finally:
            elapsed += time.time() - t0

        facts = [f for f in facts if isinstance(f, dict)]
        blob = json.dumps(facts).lower()
        if any(m in blob for m in REFUSAL_MARKERS):
            refusals += 1
        preds += [f.get("predicate") for f in facts]

        h, e_, s, ch = score_case(c, facts)
        tot_hits += h
        tot_exp += e_
        tot_spur += s
        if ch is not None:
            chains.append(ch)
        per_case[c["name"]] = (f"{h}/{e_}" if e_ else f"{s} spurious") + \
            ("" if ch is None else (" FIRES" if ch else " inert"))
        if verbose:
            print(f"    {c['name']}: {per_case[c['name']]}")
            for f in facts:
                print(f"       {f.get('subject')} -{f.get('predicate')}-> {f.get('object')}")

    vocab = (sum(1 for p in preds if p in correlate.CORRELATED_PREDICATES) / len(preds)
             if preds else 0.0)
    return {
        "label": label, "model": model,
        "recall": tot_hits / tot_exp if tot_exp else 0.0,
        "spurious": tot_spur,
        "vocab": vocab,
        "fires": f"{sum(chains)}/{len(chains)}" if chains else "-",
        "errors": errors, "refusals": refusals,
        "secs": elapsed, "per_case": per_case, "n_facts": len(preds),
    }


MODELS = [
    ("qwen3.6-35b-a3b", "http://127.0.0.1:1234/v1", "qwen/qwen3.6-35b-a3b"),
    ("qwen3.6-27b", "http://127.0.0.1:1234/v1", "qwen/qwen3.6-27b"),
    ("gemma-4-31b", "http://127.0.0.1:1234/v1", "google/gemma-4-31b"),
    ("bonsai-27b-2bit", "http://127.0.0.1:1234/v1", "prism-ml/bonsai-27b"),
    ("aletheia-3b", "http://127.0.0.1:11434/v1", "aletheia-3b:latest"),
    ("deephat-7b", "http://127.0.0.1:11434/v1",
     "hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M"),
]

# NOTE ON WHAT THIS MEASURES. `_chat` is called with no `known` list, so the
# model gets no existing-entity anchor. That is deliberately harder than
# production, where `tick` passes the graph and the analyst can be pulled onto
# names that already exist — the difference is exactly what entity anchoring
# buys, and conflating the two would hide it. Read `fires` here as raw
# extraction, not as what RedOps gets on a warm engagement.


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model")
    ap.add_argument("--url", default="http://127.0.0.1:1234/v1")
    ap.add_argument("--label")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--warm", action="store_true",
                    help="type entities the way a scanned engagement already would")
    ns = ap.parse_args()
    WARM[0] = ns.warm

    targets = ([(ns.label or ns.model, ns.url, ns.model)] if ns.model else MODELS)
    rows = []
    for label, url, model in targets:
        print(f"\n== {label} ({model})", flush=True)
        try:
            rows.append(run_model(label, url, model, verbose=ns.verbose))
        except Exception as e:                                   # noqa: BLE001
            print(f"   unavailable: {type(e).__name__}: {str(e)[:80]}")

    print(f"\n{'model':<20}{'recall':>8}{'vocab':>8}{'fires':>8}{'spur':>6}"
          f"{'err':>5}{'ref':>5}{'secs':>7}")
    print("-" * 67)
    for r in rows:
        print(f"{r['label']:<20}{r['recall']:>7.0%}{r['vocab']:>8.0%}{r['fires']:>8}"
              f"{r['spurious']:>6}{r['errors']:>5}{r['refusals']:>5}{r['secs']:>7.0f}")
    print("\nrecall = labelled facts found · vocab = predicates a rule can read")
    print("fires  = model's own facts, run through correlate.py, raised the rule")
    print("spur   = facts emitted that the window does not support")


if __name__ == "__main__":
    main()
