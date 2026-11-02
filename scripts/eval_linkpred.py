"""Measure the link predictor. Run:

    uv run python scripts/make_graph_corpus.py --n 150 --out data/graphs.json
    uv run python scripts/eval_linkpred.py --corpus data/graphs.json

Two questions, and the second is the one that decides whether this ships.

RANKING -- can it find true-but-unobserved edges?
Reported as precision/recall at k over the whole per-graph candidate ranking,
because that is the shape an operator meets it in: the worklist shows twenty
rows and you go check them. MRR is included for comparability with the KG
literature, not because anyone reads a worklist that way.

Against three baselines, all of which must be beaten for the model to have
earned anything:
  random      the floor
  popularity  rank by how many edges the object already has. This recovers a
              great deal of any knowledge graph and is the baseline most link
              prediction papers omit.
  type-prior  P(predicate | subject type, object type) alone -- one of the
              model's own features, run by itself. The deterministic ablation
              that models/README.md exists because nobody ran.

UTILITY -- does a recovered edge change what the operator sees?
A predicted edge is only worth anything if it completes a chain. So every new
opportunity correlate.py raises after the predictions are loaded is classified:

  supported     every predicted fact it rests on is true in the ground truth.
                The rules could not raise this before and it is real.
  manufactured  at least one predicted fact is false. The chain is fiction.

`manufactured` is the number to watch. It is the same failure as the withdrawn
analyst LoRA -- a fact that does not merely add noise but invents an attack path
an operator would act on -- measured in the same units, on a model whose output
space cannot contain a fabricated entity. Constraining the vocabulary removes
one failure mode; it does not remove this one.

The ceiling row is what correlate.py would raise with perfect knowledge, i.e.
how much is hidden behind unobserved facts at all.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("REDOPS_DATA", "/tmp/redops-linkpred-eval")

from redops import correlate, db  # noqa: E402
from linkpred import GraphView, LinkPredictor, load, split  # noqa: E402

db.init_db()
_ENG = [0]


# ------------------------------------------------------------------ ranking

def ranking_scores(ranked, truth, ks=(5, 10, 20, 50)):
    """ranked: [(score, triple)] descending. truth: set of triples."""
    hits = [1 if t in truth else 0 for _, t in ranked]
    out = {}
    for k in ks:
        h = sum(hits[:k])
        out[f"p@{k}"] = h / k
        out[f"r@{k}"] = h / len(truth) if truth else 0.0
    rr = 0.0
    for i, h in enumerate(hits, 1):
        if h:
            rr = 1.0 / i
            break
    out["mrr"] = rr
    return out


def baseline_random(g, cands, rng):
    order = list(cands)
    rng.shuffle(order)
    return [(0.0, c) for c in order]


def baseline_popularity(g, cands):
    return sorted(((float(g.degree(o)), (s, p, o)) for s, p, o in cands), key=lambda t: -t[0])


def baseline_type_prior(m, g, cands):
    return sorted(((m.type_prior.get((g.t(s), p, g.t(o)), 0.0), (s, p, o))
                   for s, p, o in cands), key=lambda t: -t[0])


# ------------------------------------------------------------------ utility

def _load_graph(conn, rec, edges, literals, tag):
    _ENG[0] += 1
    eng = db.insert(conn, "engagements",
                    {"name": f"{tag}-{_ENG[0]}", "scope": "", "notes": "",
                     "created_at": db.now()})
    ids = {}
    for name, etype in rec["entities"].items():
        ids[name] = db.upsert_entity(conn, eng, etype, name)
    fact_of = {}
    for s, p, o in edges:
        if s not in ids or o not in ids:
            continue
        fid = db.add_fact(conn, eng, ids[s], p, ids[o], "", "confirmed", "linkpred")
        fact_of[fid] = (s, p, o)
    for s, p, text in literals:
        if s not in ids:
            continue
        db.add_fact(conn, eng, ids[s], p, None, text, "confirmed", "linkpred")
    conn.commit()
    correlate.run(conn, eng)
    conn.commit()
    opps = db.rows(conn, "SELECT id, rule, sig FROM opportunities WHERE engagement_id=?", (eng,))
    links = db.rows(conn,
                    "SELECT of.opportunity_id, of.fact_id FROM opportunity_facts of "
                    "JOIN opportunities o ON o.id=of.opportunity_id WHERE o.engagement_id=?",
                    (eng,))
    by_opp = {}
    for r in links:
        by_opp.setdefault(r["opportunity_id"], []).append(r["fact_id"])
    return opps, by_opp, fact_of


def _key(opp, by_opp, fact_of):
    """Identity of an opportunity that survives being re-created in a second
    engagement: the rule plus the triples it joined. correlate.py's own sig is
    built from row ids, which differ between the two loads."""
    trips = sorted(str(fact_of.get(f, f)) for f in by_opp.get(opp["id"], []))
    return (opp["rule"], tuple(trips))


def utility(rec, pred_sets, truth):
    """pred_sets: {label: [triple, ...]}. obs/full loads are shared across
    labels, so a threshold sweep costs one correlate run per threshold."""
    conn = db.connect()
    try:
        obs = [tuple(e) for e in rec["observed"]]
        lits = [tuple(t) for t in rec["literals"]]
        held = [tuple(e) for e in rec["heldout"]]

        o_obs, l_obs, f_obs = _load_graph(conn, rec, obs, lits, "obs")
        base = {_key(o, l_obs, f_obs) for o in o_obs}

        o_full, l_full, f_full = _load_graph(conn, rec, obs + held, lits, "full")
        ceiling = {_key(o, l_full, f_full) for o in o_full} - base

        out = {}
        for label, preds in pred_sets.items():
            o_pred, l_pred, f_pred = _load_graph(conn, rec, obs + preds, lits, "pred")
            predset = set(preds)
            supported = manufactured = 0
            for o in o_pred:
                if _key(o, l_pred, f_pred) in base:
                    continue
                used = [f_pred[f] for f in l_pred.get(o["id"], []) if f in f_pred]
                used_pred = [t for t in used if t in predset]
                if not used_pred:
                    continue          # rules already had it; not attributable
                if all(t in truth for t in used_pred):
                    supported += 1
                else:
                    manufactured += 1
            n_true = sum(1 for t in preds if t in truth)
            out[label] = {"supported": supported, "manufactured": manufactured,
                          "injected": len(preds), "edges_true": n_true}
        return {"base": len(base), "ceiling": len(ceiling), "per": out}
    finally:
        conn.close()


# ------------------------------------------------------------------ driver

def main():
    import random
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="data/graphs.json")
    ap.add_argument("--k", type=int, default=20, help="predictions injected for the utility run")
    ap.add_argument("--seed", type=int, default=3)
    a = ap.parse_args()

    corpus = load(a.corpus)
    tr, te = split(corpus)
    views_tr = [GraphView(r) for r in tr]

    m = LinkPredictor()
    m.fit_structure(views_tr)
    m.mine_rules(views_tr)
    info = m.fit_combiner(list(zip(tr, views_tr)))
    print(f"train {len(tr)} graphs / test {len(te)} graphs   "
          f"({info['train_rows']} rows, {info['positives']} positives)")
    print(f"mined {sum(len(v) for v in m.path_rules.values())} path + "
          f"{sum(len(v) for v in m.sib_rules.values())} sibling + "
          f"{sum(len(v) for v in m.pair_rules.values())} pair rules\n")

    rng = random.Random(a.seed)
    agg = {name: [] for name in ("linkpred", "type-prior", "popularity", "random")}
    THRESH = [0.0, 0.50, 0.80, 0.90, 0.95, 0.99]
    util = {"base": 0, "ceiling": 0}
    per = {t: {"supported": 0, "manufactured": 0, "injected": 0, "edges_true": 0}
           for t in THRESH}

    for rec in te:
        g = GraphView(rec)
        truth = set(map(tuple, rec["heldout"]))
        cands = m.candidates(g)
        if not truth or not cands:
            continue
        ranked = m.score(g, cands)
        agg["linkpred"].append(ranking_scores(ranked, truth))
        agg["type-prior"].append(ranking_scores(baseline_type_prior(m, g, cands), truth))
        agg["popularity"].append(ranking_scores(baseline_popularity(g, cands), truth))
        agg["random"].append(ranking_scores(baseline_random(g, cands, rng), truth))

        sets = {t: [c for pr, c in ranked[:a.k] if pr >= t] for t in THRESH}
        u = utility(rec, sets, truth)
        util["base"] += u["base"]
        util["ceiling"] += u["ceiling"]
        for t in THRESH:
            for key in per[t]:
                per[t][key] += u["per"][t][key]

    cols = ("p@5", "p@10", "p@20", "r@20", "r@50", "mrr")
    print("RANKING  (mean over test graphs; candidate sets are thousands wide)\n")
    print(f"  {'model':<12}" + "".join(f"{c:>8}" for c in cols))
    for name in ("linkpred", "type-prior", "popularity", "random"):
        rows = agg[name]
        means = [sum(r[c] for r in rows) / len(rows) for c in cols]
        print(f"  {name:<12}" + "".join(f"{v:8.3f}" for v in means))

    n = len(agg["linkpred"])
    print(f"\nUTILITY  (top {a.k} by score, filtered by threshold, correlate.py re-run; "
          f"{n} graphs)")
    print(f"  correlate.py already raises {util['base']} opportunities from the observed graph.")
    print(f"  {util['ceiling']} more are hidden behind unobserved facts -- the ceiling.\n")
    print(f"  {'thresh':>7}{'edges':>7}{'edge P':>8}{'supported':>11}{'manufac':>9}"
          f"{'chain P':>9}{'ceiling':>9}")
    for t in THRESH:
        d = per[t]
        inj, sup, man = d["injected"], d["supported"], d["manufactured"]
        edge_p = d["edges_true"] / inj if inj else 0.0
        chain_p = sup / (sup + man) if (sup + man) else 0.0
        cov = sup / util["ceiling"] if util["ceiling"] else 0.0
        print(f"  {t:>7.2f}{inj:>7}{edge_p:>8.2f}{sup:>11}{man:>9}{chain_p:>9.2f}{cov:>9.1%}")
    print("\n  edge P   = fraction of injected edges that are true")
    print("  chain P  = fraction of newly-raised opportunities whose predicted facts are all true")
    print("  ceiling  = share of the hidden opportunities recovered")


if __name__ == "__main__":
    main()
