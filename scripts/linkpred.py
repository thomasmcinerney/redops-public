"""Link prediction over the fact graph: rank edges that are probably true but
have not been observed yet.

    uv run python scripts/linkpred.py --corpus data/graphs.json --rules   # show mined rules
    uv run python scripts/linkpred.py --corpus data/graphs.json --graph 3 # top hypotheses

WHAT THIS IS FOR

correlate.py joins facts that are already in the store. It cannot say anything
about a fact nobody recorded, and 43% of a simulated engagement's ground truth
is never recorded (make_graph_corpus.py). This ranks the missing edges, so the
worklist can carry "go check whether nginx-04's config is writable" next to
"here is a chain you already have".

WHY NOT AN LLM

The output space is (existing entity, known predicate, existing entity). A wrong
answer is a wasted probe. It is not possible for this to emit a tool that does
not exist, which is the failure that killed the analyst LoRA (models/README.md)
-- not because the model here is better, but because it cannot name anything the
graph does not already contain.

THREE CHANNELS, NO EMBEDDINGS

At 60-graph / 4k-edge scale a translational embedding (RotatE et al.) has
nothing to fit. What works at this scale is structure:

  prior    P(predicate | subject type, object type). Kills most of the
           candidate space for free and is learnable from a handful of graphs.
  rules    mined Horn clauses, over the relation set closed under inverses.
           Two families: paths (X p1 Y) & (Y p2 Z) => (X p3 Z), and siblings
           (X p1 H) & (Y p1 H) & (Y p3 Z) => (X p3 Z). The sibling family is
           the one that earns its keep -- "the other services on this host run
           as root" is a three-atom body and a path miner cannot say it.
  analogy  entities with similar typed neighbourhoods have similar edges, scored
           against the specific object rather than its type.

A popularity baseline (rank by how many edges the object already has) recovers a
surprising amount of any knowledge graph, so eval_linkpred.py runs it explicitly.
Anything this model claims is claimed over that, not over random.

A logistic combiner is fitted over those features on a train split. It is fitted,
not tuned by hand, so the weights are a result rather than a preference.
"""

import argparse
import json
import math
import random
from collections import Counter, defaultdict

INV = "^"          # marks an inverted relation in a mined rule body


# ---------------------------------------------------------------- graph views

class GraphView:
    """One engagement, as the predictor sees it: entities + observed edges."""

    def __init__(self, rec, edges=None):
        self.id = rec["id"]
        self.types = dict(rec["entities"])
        self.edges = set(map(tuple, edges if edges is not None else rec["observed"]))
        self.out = defaultdict(set)     # s -> {(p, o)}
        self.inc = defaultdict(set)     # o -> {(p, s)}
        for s, p, o in self.edges:
            self.out[s].add((p, o))
            self.inc[o].add((p, s))

    def t(self, e):
        return self.types.get(e, "other")

    def adj(self, e):
        """(relation, neighbour) with inverses marked, so paths can run backwards."""
        return [(p, o) for p, o in self.out[e]] + [(INV + p, s) for p, s in self.inc[e]]

    def degree(self, e):
        return len(self.out[e]) + len(self.inc[e])

    def groups(self):
        """(relation, neighbour) -> entities attached to it. Two entities in the
        same group are siblings: same host, same model, same skill."""
        gs = defaultdict(set)
        for e in self.types:
            for r, nb in self.adj(e):
                gs[(r, nb)].add(e)
        return gs

    def signature(self, e):
        """Typed neighbourhood: what this entity looks like, independent of names."""
        sig = Counter()
        for p, o in self.out[e]:
            sig[("out", p, self.t(o))] += 1
        for p, s in self.inc[e]:
            sig[("in", p, self.t(s))] += 1
        return sig


def cosine(a, b):
    if not a or not b:
        return 0.0
    common = a.keys() & b.keys()
    if not common:
        return 0.0
    dot = sum(a[k] * b[k] for k in common)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


# ---------------------------------------------------------------- the model

class LinkPredictor:
    def __init__(self, min_support=4, min_conf=0.10, max_rules_per_head=12):
        self.min_support = min_support
        self.min_conf = min_conf
        self.max_rules_per_head = max_rules_per_head
        self.type_prior = {}        # (ts, p, to) -> prob
        self.pred_freq = {}
        self.preds = []
        self.sig_pairs = defaultdict(set)   # (ts, to) -> {p}
        self.path_rules = defaultdict(list)  # head p3 -> [((p1, p2), conf, pca, support)]
        self.pair_rules = defaultdict(list)  # head p3 -> [(p1, conf, support)]
        self.sib_rules = defaultdict(list)   # head p3 -> [(p1, conf, support)]
        self.w = None
        self.mu = None
        self.sd = None

    # --- statistics -------------------------------------------------------

    def fit_structure(self, graphs):
        sig_count = Counter()
        type_count = Counter()
        pred_count = Counter()
        for g in graphs:
            for s, p, o in g.edges:
                sig_count[(g.t(s), p, g.t(o))] += 1
                type_count[(g.t(s), g.t(o))] += 1
                pred_count[p] += 1
                self.sig_pairs[(g.t(s), g.t(o))].add(p)

        self.preds = sorted(pred_count)
        total = sum(pred_count.values()) or 1
        self.pred_freq = {p: c / total for p, c in pred_count.items()}
        n_p = len(self.preds) or 1
        for (ts, to), tc in type_count.items():
            for p in self.preds:
                c = sig_count[(ts, p, to)]
                # Laplace, so an unseen predicate on a seen type pair is small
                # rather than impossible -- the corpus is not the world.
                self.type_prior[(ts, p, to)] = (c + 0.5) / (tc + 0.5 * n_p)

    def mine_rules(self, graphs):
        """AMIE-lite. Bodies of one or two atoms, head is a single relation
        between the endpoints. Confidence is support / body groundings, which
        is the closed-world reading; open-world PCA confidence is reported
        alongside so a rule about a rarely-observed head is not thrown away for
        being rarely observed."""
        path_body = Counter()
        path_supp = Counter()
        path_pca = Counter()      # body groundings where X has SOME p3 edge
        pair_body = Counter()
        pair_supp = Counter()
        sib_body = Counter()
        sib_supp = Counter()

        for g in graphs:
            # sibling family: (X r H) & (Y r H) & (Y p3 Z) => (X p3 Z)
            for (r, h), members in g.groups().items():
                if len(members) < 2:
                    continue
                for x in members:
                    for y in members:
                        if x == y:
                            continue
                        for p3, z in g.out[y]:
                            # z == h makes the head true by group membership
                            # alone: every X in a group keyed on (r, h) already
                            # has that edge. Counting it mines conf 1.0
                            # tautologies that crowd out the real rules.
                            if z == x or z == h:
                                continue
                            sib_body[(r, p3)] += 1
                            if (x, p3, z) in g.edges:
                                sib_supp[(r, p3)] += 1

        for g in graphs:
            has_head = defaultdict(set)     # (X, p) -> seen at all
            for s, p, o in g.edges:
                has_head[s].add(p)

            for x in g.types:
                a1 = g.adj(x)
                if not a1:
                    continue
                # length-1 bodies: same endpoint pair, different relation
                for p1, y in a1:
                    if p1.startswith(INV):
                        continue
                    pair_body[p1] += 1
                    for p3, y2 in g.out[x]:
                        if y2 == y and p3 != p1:
                            pair_supp[(p1, p3)] += 1
                # length-2 bodies
                for p1, y in a1:
                    for p2, z in g.adj(y):
                        if z == x:
                            continue
                        path_body[(p1, p2)] += 1
                        heads = {p for p, o in g.out[x] if o == z}
                        for p3 in heads:
                            path_supp[(p1, p2, p3)] += 1
                        for p3 in has_head[x]:
                            path_pca[(p1, p2, p3)] += 1

        for (p1, p2, p3), sup in path_supp.items():
            body = path_body[(p1, p2)]
            if sup < self.min_support or not body:
                continue
            conf = sup / body
            pca = sup / max(path_pca[(p1, p2, p3)], 1)
            if max(conf, pca) < self.min_conf:
                continue
            self.path_rules[p3].append(((p1, p2), conf, pca, sup))

        for (p1, p3), sup in pair_supp.items():
            body = pair_body[p1]
            if sup < self.min_support or not body:
                continue
            conf = sup / body
            if conf < self.min_conf:
                continue
            self.pair_rules[p3].append((p1, conf, sup))

        for (r, p3), sup in sib_supp.items():
            body = sib_body[(r, p3)]
            if sup < self.min_support or not body:
                continue
            conf = sup / body
            if conf < self.min_conf:
                continue
            self.sib_rules[p3].append((r, conf, sup))

        for d in (self.path_rules, self.pair_rules, self.sib_rules):
            for k in d:
                d[k].sort(key=lambda r: -r[1])
                del d[k][self.max_rules_per_head:]

    # --- candidates -------------------------------------------------------

    def candidates(self, g, cap=40000):
        """(s, p, o) not observed, whose type signature was seen in training."""
        ents = list(g.types)
        out = []
        for s in ents:
            ts = g.t(s)
            for o in ents:
                if s == o:
                    continue
                allowed = self.sig_pairs.get((ts, g.t(o)))
                if not allowed:
                    continue
                for p in allowed:
                    if (s, p, o) not in g.edges:
                        out.append((s, p, o))
                        if len(out) >= cap:
                            return out
        return out

    # --- features ---------------------------------------------------------

    def _rule_features(self, g, s, p, o):
        best_conf = best_pca = 0.0
        fired = 0
        adj_s = g.adj(s)
        for (p1, p2), conf, pca, _sup in self.path_rules.get(p, ()):
            hit = False
            for r1, y in adj_s:
                if r1 != p1:
                    continue
                for r2, z in g.adj(y):
                    if r2 == p2 and z == o:
                        hit = True
                        break
                if hit:
                    break
            if hit:
                fired += 1
                best_conf = max(best_conf, conf)
                best_pca = max(best_pca, pca)
        pair_best = 0.0
        existing = {r for r, y in g.out[s] if y == o}
        for p1, conf, _sup in self.pair_rules.get(p, ()):
            if p1 in existing:
                pair_best = max(pair_best, conf)
        return best_conf, best_pca, math.log1p(fired), pair_best

    def _sibling(self, g, s, p, o, idx):
        """Do s's siblings -- entities sharing one of its neighbours -- already
        hold this exact edge? Scored two ways: by the mined rule's corpus-wide
        confidence, and by the empirical fraction inside this graph."""
        holders = idx["holders"].get((p, o), ())
        if not holders:
            return 0.0, 0.0
        sib_by_rel = idx["sib_by_rel"].get(s, {})
        best = 0.0
        for r, conf, _sup in self.sib_rules.get(p, ()):
            peers = sib_by_rel.get(r)
            if peers and any(h in peers for h in holders):
                best = max(best, conf)
        allsibs = idx["allsibs"].get(s, set())
        frac = (sum(1 for h in holders if h in allsibs) / len(allsibs)) if allsibs else 0.0
        return best, frac

    def _analogy(self, g, s, p, o, idx):
        """Does s look like the entities that already point at this exact o?"""
        holders = idx["holders"].get((p, o), ())
        sigs = idx["sigs"]
        subj = max((cosine(sigs[s], sigs[h]) for h in holders if h != s), default=0.0)
        recv = idx["receivers"].get(p, ())
        obj = max((cosine(sigs[o], sigs[r]) for r in recv if r != o), default=0.0)
        return subj, obj

    def _index(self, g):
        sigs = {e: g.signature(e) for e in g.types}
        holders = defaultdict(set)      # (p, o) -> subjects that already assert it
        receivers = defaultdict(set)    # p -> objects that already receive it
        for s, p, o in g.edges:
            holders[(p, o)].add(s)
            receivers[p].add(o)
        sib_by_rel = defaultdict(lambda: defaultdict(set))
        allsibs = defaultdict(set)
        for (r, _nb), members in g.groups().items():
            if len(members) < 2:
                continue
            for x in members:
                peers = members - {x}
                sib_by_rel[x][r] |= peers
                allsibs[x] |= peers
        return {"sigs": sigs, "holders": holders, "receivers": receivers,
                "sib_by_rel": sib_by_rel, "allsibs": allsibs}

    FEATURES = ("type_prior", "rule_conf", "rule_pca", "rules_fired", "pair_rule",
                "sib_rule", "sib_frac", "analogy_s", "analogy_o",
                "deg_s", "deg_o", "obj_indeg_p", "pred_freq",
                "pred_in_graph", "subj_has_pred")

    def featurize(self, g, cands):
        idx = self._index(g)
        preds_here = {p for _, p, _ in g.edges}
        subj_pred = {(s, p) for s, p, _ in g.edges}
        rows = []
        for s, p, o in cands:
            prior = self.type_prior.get((g.t(s), p, g.t(o)), 1e-4)
            rc, rp, rf, pr = self._rule_features(g, s, p, o)
            sib, sfrac = self._sibling(g, s, p, o, idx)
            asc, aoc = self._analogy(g, s, p, o, idx)
            rows.append([
                math.log(prior), rc, rp, rf, pr, sib, sfrac, asc, aoc,
                math.log1p(g.degree(s)), math.log1p(g.degree(o)),
                math.log1p(len(idx["holders"].get((p, o), ()))),
                math.log(self.pred_freq.get(p, 1e-4)),
                1.0 if p in preds_here else 0.0,
                1.0 if (s, p) in subj_pred else 0.0,
            ])
        return rows

    # --- combiner ---------------------------------------------------------

    def fit_combiner(self, graphs, neg_per_pos=20, epochs=220, lr=0.35, l2=1e-3, seed=1):
        rng = random.Random(seed)
        X, y = [], []
        for rec, g in graphs:
            truth = set(map(tuple, rec["heldout"]))
            cands = self.candidates(g)
            pos = [c for c in cands if c in truth]
            neg = [c for c in cands if c not in truth]
            if not pos:
                continue
            rng.shuffle(neg)
            sample = pos + neg[:len(pos) * neg_per_pos]
            feats = self.featurize(g, sample)
            X.extend(feats)
            y.extend([1.0] * len(pos) + [0.0] * (len(sample) - len(pos)))

        n, d = len(X), len(X[0])
        self.mu = [sum(r[j] for r in X) / n for j in range(d)]
        self.sd = [max(math.sqrt(sum((r[j] - self.mu[j]) ** 2 for r in X) / n), 1e-6)
                   for j in range(d)]
        Z = [[(r[j] - self.mu[j]) / self.sd[j] for j in range(d)] for r in X]

        w = [0.0] * (d + 1)
        pos_rate = sum(y) / n
        w[d] = math.log(pos_rate / (1 - pos_rate))
        for _ in range(epochs):
            gr = [0.0] * (d + 1)
            for zi, yi in zip(Z, y):
                z = sum(w[j] * zi[j] for j in range(d)) + w[d]
                pi = 1 / (1 + math.exp(-max(-30, min(30, z))))
                e = pi - yi
                for j in range(d):
                    gr[j] += e * zi[j]
                gr[d] += e
            for j in range(d):
                w[j] -= lr * (gr[j] / n + l2 * w[j])
            w[d] -= lr * (gr[d] / n)
        self.w = w
        return {"train_rows": n, "positives": int(sum(y))}

    def score(self, g, cands):
        d = len(self.w) - 1
        out = []
        for c, r in zip(cands, self.featurize(g, cands)):
            z = sum(self.w[j] * ((r[j] - self.mu[j]) / self.sd[j]) for j in range(d)) + self.w[d]
            out.append((1 / (1 + math.exp(-max(-30, min(30, z)))), c))
        out.sort(key=lambda t: -t[0])
        return out

    def predict(self, g, k=20):
        return self.score(g, self.candidates(g))[:k]

    # --- readability ------------------------------------------------------

    def describe_rules(self, top=25):
        rows = []
        for head, rs in self.path_rules.items():
            for (p1, p2), conf, pca, sup in rs:
                rows.append((conf, pca, sup, f"(X {p1} Y) & (Y {p2} Z)  =>  (X {head} Z)"))
        for head, rs in self.pair_rules.items():
            for p1, conf, sup in rs:
                rows.append((conf, conf, sup, f"(X {p1} Y)  =>  (X {head} Y)"))
        for head, rs in self.sib_rules.items():
            for r, conf, sup in rs:
                rows.append((conf, conf, sup,
                             f"(X {r} H) & (Y {r} H) & (Y {head} Z)  =>  (X {head} Z)"))
        rows.sort(key=lambda r: (-r[0], -r[2]))
        return rows[:top]

    def weights(self):
        return sorted(zip(self.FEATURES, self.w), key=lambda t: -abs(t[1]))


# ---------------------------------------------------------------- plumbing

def load(path):
    with open(path) as fh:
        return json.load(fh)


def split(corpus, frac=0.7):
    cut = int(len(corpus) * frac)
    return corpus[:cut], corpus[cut:]


def train(corpus, **kw):
    tr, _ = split(corpus)
    views = [GraphView(r) for r in tr]
    m = LinkPredictor(**kw)
    m.fit_structure(views)
    m.mine_rules(views)
    m.fit_combiner(list(zip(tr, views)))
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="data/graphs.json")
    ap.add_argument("--rules", action="store_true", help="print the mined rules and stop")
    ap.add_argument("--graph", type=int, help="print top hypotheses for one held-out graph")
    ap.add_argument("--k", type=int, default=20)
    a = ap.parse_args()

    corpus = load(a.corpus)
    m = train(corpus)

    if a.rules:
        print("mined rules (conf = support/body, pca = open-world corrected)\n")
        print(f"  {'conf':>5} {'pca':>5} {'sup':>5}  rule")
        for conf, pca, sup, txt in m.describe_rules(30):
            print(f"  {conf:5.2f} {pca:5.2f} {sup:5d}  {txt}")
        print("\nfitted feature weights (standardised)\n")
        for name, w in m.weights():
            print(f"  {w:+7.3f}  {name}")
        return

    _, te = split(corpus)
    rec = te[a.graph if a.graph is not None else 0]
    g = GraphView(rec)
    truth = set(map(tuple, rec["heldout"]))
    print(f"graph {rec['id']}: {len(g.types)} entities, {len(g.edges)} observed edges, "
          f"{len(truth)} true-but-unseen\n")
    print(f"  {'p':>5}  {'':1}  hypothesis")
    for prob, (s, p, o) in m.predict(g, a.k):
        mark = "*" if (s, p, o) in truth else " "
        print(f"  {prob:5.2f}  {mark}  {s} --{p}--> {o}")
    print("\n  * = actually true in the simulated ground truth")


if __name__ == "__main__":
    main()
