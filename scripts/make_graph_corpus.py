"""Generate a corpus of engagement graphs: ground truth + partial observation.

    uv run python scripts/make_graph_corpus.py --n 60 --out data/graphs.json

WHY THIS IS NOT GENERATED FROM THE RULES

scripts/make_analyst_dataset.py generates windows from correlate.py's scenarios,
which is correct for that task (the label *is* the rule's shape) and admits the
contamination in its own docstring. This generator must not do that, because the
thing being measured is whether a learned model can propose edges the rules were
never written for. If the environment is drawn from R1-R13, a predictor that
recovers R1-R13 scores perfectly and has discovered nothing.

So this simulates an *environment* instead. Hosts run services, services are
managed by an init system, an init system implies a unit file and a respawn
primitive, containers on a host share a runtime principal, an agent that holds a
retrieval skill has a store to retrieve from. Those regularities come from how
infrastructure is actually built. correlate.py never appears in this file.

The rules are only used downstream, in eval_linkpred.py, to ask a different
question: of the edges a model recovered, how many complete a chain a human
would act on -- and how many complete a chain that isn't there.

WHAT AN "OBSERVATION" IS

A real engagement graph is not a subgraph sampled uniformly. Some facts are
almost free (a port scan gives you listens-on and on-host); some cost a shell
(runs-as, writable-by); some cost a shell plus curiosity (respawns). VISIBILITY
encodes that. The held-out set is therefore "true, and you have not paid for it
yet" -- which is exactly the set a worklist wants ranked.

Nothing here is a claim about a real network. It is a testbed with a known
answer key, which is the only way to get Hits@k at all. Every number it
produces is in-distribution to these assumptions; treat a result as a reason to
run the thing against data/redops.db, not as a result.
"""

import argparse
import json
import os
import random

# --- the environment vocabulary ---------------------------------------------

INIT_SYSTEMS = ["systemd", "supervisor", "docker", "k8s"]

SERVICE_CATALOG = [
    # (name stem, port, typical principal, config path stem, family)
    ("nginx",        80,   "www-data", "/etc/nginx/nginx.conf",         "web"),
    ("apache",       80,   "www-data", "/etc/apache2/apache2.conf",     "web"),
    ("gitea",        3000, "git",      "/etc/gitea/app.ini",            "web"),
    ("grafana",      3000, "grafana",  "/etc/grafana/grafana.ini",      "web"),
    ("postgres",     5432, "postgres", "/etc/postgresql/postgresql.conf", "db"),
    ("mysql",        3306, "mysql",    "/etc/mysql/my.cnf",             "db"),
    ("redis",        6379, "redis",    "/etc/redis/redis.conf",         "db"),
    ("mongo",        27017, "mongodb", "/etc/mongod.conf",              "db"),
    ("qdrant",       6333, "root",     "/opt/qdrant/config.yaml",       "vector"),
    ("milvus",       19530, "root",    "/srv/milvus/milvus.yaml",       "vector"),
    ("weaviate",     8080, "root",     "/etc/weaviate/config.yaml",     "vector"),
    ("vault-agent",  8200, "root",     "/opt/vault/agent.hcl",          "secrets"),
    ("consul-agent", 8500, "consul",   "/etc/consul.d/agent.json",      "secrets"),
    ("minio",        9000, "minio",    "/opt/minio/policy.json",        "storage"),
    ("rabbit",       5672, "rabbitmq", "/etc/rabbitmq/rabbitmq.conf",   "queue"),
    ("elastic",      9200, "elastic",  "/etc/elasticsearch/es.yml",     "search"),
    ("sshd",         22,   "root",     "/etc/ssh/sshd_config",          "admin"),
    ("winrm",        5985, "system",   "",                              "admin"),
    ("smb",          445,  "system",   "",                              "admin"),
]

MODELS = ["qwen3.6-35b-a3b", "llama-4-17b", "gpt-oss-20b", "gemma-4-31b",
          "mistral-3-24b", "phi-5-mini", "qwen2.5-7b-instruct", "deepseek-v4-lite"]

# tool families an agent draws from; the skill it advertises predicts the pool
SKILL_TOOLS = {
    "retrieval":  ["kb_search", "doc_lookup", "index_query", "corpus_fetch"],
    "ops":        ["shell_run", "svc_restart", "host_exec", "job_submit"],
    "data":       ["sql_query", "table_read", "report_build", "export_rows"],
    "comms":      ["mail_send", "chat_post", "ticket_open", "reply_user"],
    "web":        ["url_fetch", "page_render", "api_call", "webhook_post"],
}
USER_FACING_SKILLS = {"comms"}

OUR_PRINCIPALS = ["us", "www-data"]
PRIV = {"root", "system", "administrator", "admin"}


def _name(rng, stem, taken):
    """Per-graph unique instance name. Never a fixed pool -- a model that
    memorises entity strings must not be able to score here (the v1 LoRA
    lesson, models/README.md)."""
    for _ in range(200):
        n = f"{stem}-{rng.randint(1, 99):02d}"
        if n not in taken:
            taken.add(n)
            return n
    raise RuntimeError("name space exhausted")


class Graph:
    def __init__(self):
        self.ents = {}          # name -> type
        self.edges = set()      # (subject, predicate, object)
        self.literals = []      # (subject, predicate, object_text)

    def ent(self, name, etype):
        self.ents[name] = etype
        return name

    def edge(self, s, p, o):
        self.edges.add((s, p, o))

    def lit(self, s, p, text):
        self.literals.append((s, p, text))


# --- the simulator -----------------------------------------------------------

def build_environment(rng):
    """One engagement's ground truth. Regularities here are infrastructural."""
    g = Graph()
    taken = set()

    subnet = rng.choice(["10.10.10", "198.51.100", "172.20.4"])
    n_hosts = rng.randint(3, 7)
    hosts = []
    for i in range(n_hosts):
        ip = f"{subnet}.{rng.randint(2, 250)}"
        h = g.ent(ip, "host")
        hosts.append(h)
        if rng.random() < 0.7:
            hn = _name(rng, rng.choice(["web", "db", "app", "ops", "ai"]), taken)
            g.ent(hn, "host")
            g.edge(hn, "resolves-to", h)

    # A fleet has a house style: one init system dominates, and that decides
    # whether unit files and respawn primitives exist at all.
    house_init = rng.choice(INIT_SYSTEMS)
    containerised = house_init in ("docker", "k8s")

    for h in hosts:
        init = house_init if rng.random() < 0.85 else rng.choice(INIT_SYSTEMS)
        # a containerised host runs everything as one runtime principal
        host_principal = "root" if init in ("docker", "k8s") else None

        for _, (stem, port, principal, cfgpath, family) in enumerate(
                rng.sample(SERVICE_CATALOG, rng.randint(2, 5))):
            svc = g.ent(_name(rng, stem, taken), "service")
            g.edge(svc, "on-host", h)
            g.lit(svc, "listens-on", str(port))

            who = host_principal or principal
            # drift: a fraction of services are misconfigured to run privileged
            if rng.random() < 0.18:
                who = "root"
            g.ent(who, "user")
            g.edge(svc, "runs-as", who)

            # an init-managed service has a unit file and a restart primitive.
            # this is the regularity: respawns is *implied by* the init system,
            # never asserted independently.
            if init in ("systemd", "supervisor", "docker", "k8s"):
                g.edge(svc, "respawns", init)
                g.ent(init, "other")
                if rng.random() < 0.6:
                    g.edge(svc, "restart-trigger", init)

            if cfgpath:
                cfg = g.ent(f"{svc}{cfgpath}", "config")
                g.edge(cfg, "on-host", h)
                # writability follows ownership, not chance: a config owned by
                # a non-root service principal on a containerised host is very
                # often group-writable by the web user.
                p_write = 0.55 if (containerised and who not in PRIV) else 0.15
                if rng.random() < p_write:
                    w = rng.choice(OUR_PRINCIPALS)
                    g.ent(w, "user")
                    g.edge(cfg, "writable-by", w)

            # auth surface
            if family in ("db", "admin", "secrets"):
                g.edge(svc, "auth-accepts", who)
            # vector stores and internal queues ship unauthenticated far too often
            if family in ("vector", "queue", "search") and rng.random() < 0.65:
                g.lit(svc, "no-auth", "default config, no auth configured")

    # credentials: a valid cred on one host is reused across the fleet, which is
    # the whole reason spraying works. modelled as an environment property.
    n_creds = rng.randint(1, 3)
    for _ in range(n_creds):
        c = g.ent(_name(rng, rng.choice(["svc_backup", "deploy", "adm", "jenkins"]), taken),
                  "credential")
        home = rng.choice(hosts)
        g.edge(c, "valid-on", home)
        reuse_rate = 0.5 if rng.random() < 0.4 else 0.08   # fleets are bimodal
        for h in hosts:
            if h != home and rng.random() < reuse_rate:
                g.edge(c, "valid-on", h)

    # --- the AI stack -------------------------------------------------------
    for _ in range(rng.randint(1, 3)):
        h = rng.choice(hosts)
        ag = g.ent(_name(rng, rng.choice(["assistant", "copilot", "triage-bot", "helpdesk"]),
                         taken), "agent")
        g.edge(ag, "on-host", h)
        m = g.ent(rng.choice(MODELS), "model")
        g.edge(ag, "runs-model", m)

        skills = rng.sample(list(SKILL_TOOLS), rng.randint(1, 3))
        for sk in skills:
            g.edge(ag, "has-skill", sk)
            g.ent(sk, "other")
            # the tools an agent holds are drawn from the pool its skill implies.
            # this is the regularity a predictor should find: skill -> toolset.
            for t in rng.sample(SKILL_TOOLS[sk], rng.randint(1, len(SKILL_TOOLS[sk]))):
                g.ent(t, "other")
                g.edge(ag, "has-tool", t)
            if sk in USER_FACING_SKILLS:
                g.ent("reply to user", "other")
                g.edge(ag, "has-tool", "reply to user")

        # a retrieval agent has something to retrieve from, and that store has
        # an ingest path. the ingest path is what makes it poisonable.
        if "retrieval" in skills:
            store = g.ent(_name(rng, rng.choice(["kb-store", "docs-index", "ticket-kb"]), taken),
                          "rag-store")
            g.edge(store, "on-host", h)
            g.edge(store, "is-read-by", ag)
            if rng.random() < 0.75:
                ep = g.ent(f"/{rng.choice(['kb', 'docs', 'ingest'])}/upload", "endpoint")
                g.edge(ep, "on-host", h)
                g.edge(ep, "ingests", store)
                if rng.random() < 0.55:
                    g.lit(ep, "no-auth", "no auth on upload path")
                g.edge(store, "accepts", ep)

    return g


# --- observation -------------------------------------------------------------
#
# Probability the engagement actually recorded a true edge. Roughly: what did it
# cost to learn? A scan gives you the top block for free; the bottom block needs
# a shell and a reason to look.

VISIBILITY = {
    "on-host":        0.95,
    "listens-on":     0.95,
    "resolves-to":    0.85,
    "no-auth":        0.80,
    "runs-model":     0.70,
    "has-skill":      0.70,
    "ingests":        0.60,
    "accepts":        0.55,
    "is-read-by":     0.55,
    "has-tool":       0.50,
    "auth-accepts":   0.50,
    "runs-as":        0.40,
    "valid-on":       0.35,
    "writable-by":    0.30,
    "restart-trigger": 0.25,
    "respawns":       0.25,
}
DEFAULT_VIS = 0.5


def observe(g, rng):
    """Split ground truth into (observed, held-out)."""
    obs, held = [], []
    for (s, p, o) in sorted(g.edges):
        (obs if rng.random() < VISIBILITY.get(p, DEFAULT_VIS) else held).append([s, p, o])
    lits = [[s, p, t] for (s, p, t) in g.literals
            if rng.random() < VISIBILITY.get(p, DEFAULT_VIS)]
    return obs, held, lits


def make(n, seed):
    rng = random.Random(seed)
    out = []
    for i in range(n):
        g = build_environment(rng)
        obs, held, lits = observe(g, rng)
        out.append({
            "id": i,
            "entities": g.ents,
            "observed": obs,
            "heldout": held,
            "literals": lits,
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="data/graphs.json")
    a = ap.parse_args()

    corpus = make(a.n, a.seed)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as fh:
        json.dump(corpus, fh)

    ents = sum(len(g["entities"]) for g in corpus)
    obs = sum(len(g["observed"]) for g in corpus)
    held = sum(len(g["heldout"]) for g in corpus)
    print(f"{len(corpus)} graphs -> {a.out}")
    print(f"  entities   {ents:5d}  ({ents/len(corpus):.1f} per graph)")
    print(f"  observed   {obs:5d}  ({obs/len(corpus):.1f} per graph)")
    print(f"  held out   {held:5d}  ({held/len(corpus):.1f} per graph)"
          f"  = {held/(obs+held):.0%} of ground truth unseen")


if __name__ == "__main__":
    main()
