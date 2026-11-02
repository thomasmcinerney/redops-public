"""Generate LoRA training data for the analyst task.

    uv run python scripts/make_analyst_dataset.py --out data/ft --n 900

WHAT THIS TRAINS FOR, AND WHY IT IS NOT "VALUES"

The obvious fine-tune for a red-team tool is an uncensored one. The measurement
does not support it: across six local models on scripts/eval_refusal.py, the
mainstream models refused nothing, and the only refusal came from the
*uncensored* 3B — which declined to write a detection rule. Refusal is not what
this workload is losing to.

What it is losing to is `fires` in scripts/eval_analyst.py. Every model tested
reads 82-91% of the facts a window supports and keeps 100% of its predicates
inside the rules' vocabulary (the schema enum guarantees that), and still fails
to raise the rule on at least one of the two windows that describe a complete
chain. The reason is mundane: a model writes `is-read-by` against `kb-store` and
`accepts` against `/kb/upload`, or hangs `has-tool` off the sink instead of the
agent. Each fact is individually defensible. Together they join nothing, and a
relation that does not join is inert.

So every example here is generated with its entity names chosen ONCE and reused
across every fact in the window, and with the subject of each predicate fixed by
the rule that consumes it. The label is not "what is true about this text" but
"what shape does this text have in the graph".

CONTAMINATION. The scenario templates overlap the eval's by construction — both
are derived from the same correlation rules, and a training set that avoided
R2 and R10 would not teach the thing being measured. Entity names, ports,
paths, phrasings and distractors are drawn from pools disjoint from the eval
cases, so a model cannot pass eval_analyst.py by memorising a string. It can
still pass by learning the shape, which is the point. Read the eval as
in-distribution, and hold anything it claims to a live lab run before believing
it.
"""

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("REDOPS_DATA", "/tmp/redops-ds")

from redops import analyst, correlate  # noqa: E402

# Pools deliberately disjoint from scripts/eval_analyst.py, which uses
# qdrant / kb-store / support-assistant / config.toml / 10.10.10.5.
SERVICES = ["redis-cache", "vault-agent", "milvus", "weaviate", "elastic-ingest",
            "gitea", "minio", "rabbit-broker", "consul-agent", "grafana"]
CONFIGS = ["/etc/redis/redis.conf", "/opt/vault/agent.hcl", "/srv/milvus/milvus.yaml",
           "/etc/gitea/app.ini", "/opt/minio/policy.json", "/etc/consul.d/agent.json"]
# Tool and agent names are GENERATED per example, not drawn from a fixed list.
# v1 used a six-item pool and the model memorised it: against a real 5,400-char
# window it emitted `shell_exec`, `run_query`, `fetch_url` and `send_invoice` —
# every trial — none of which existed on the target. Fabricated capabilities in
# a store the correlation engine reasons over are worse than no analyst, so the
# vocabulary must be impossible to learn.
_VERB = ["run", "exec", "fetch", "send", "create", "update", "list", "purge",
         "sync", "emit", "scan", "resolve", "archive", "drain"]
_NOUN = ["query", "record", "invoice", "ticket", "blob", "index", "job", "report",
         "session", "token", "digest", "batch", "entry", "policy"]


def _tool(rnd):
    return f"{rnd.choice(_VERB)}_{rnd.choice(_NOUN)}{rnd.choice(['', '', '_v2', str(rnd.randint(2, 99))])}"


def _agentname(rnd):
    return (f"{rnd.choice(['helpdesk', 'sre', 'billing', 'triage', 'intake', 'ops'])}-"
            f"{rnd.choice(['bot', 'agent', 'assistant', 'copilot'])}-{rnd.randint(2, 89)}")


def _storename(rnd):
    return (f"{rnd.choice(['ticket', 'runbook', 'policy', 'invoice', 'faq', 'wiki'])}-"
            f"{rnd.choice(['index', 'corpus', 'store', 'collection'])}-{rnd.randint(2, 89)}")
MODELS = ["llama-3.3-8b", "mistral-small-3", "phi-4-mini", "gemma-3-12b",
          "granite-3-8b"]
HOSTS = ["172.20.4.9", "192.168.88.14", "10.55.2.7", "172.31.9.21", "10.66.4.3"]
USERS = ["www-data", "app", "svc_runner", "nobody", "deploy"]
PRIVS = ["root", "administrator", "system"]
UPLOADS = ["/ingest/doc", "/corpus/add", "/docs/submit", "/import/file"]
SECRETS = ["Wint3r!Storm", "Br0nze-Anchor-9", "tR0ut!Salmon", "Qu4rtz#Lantern"]
FILES = ["/srv/app/settings.ini", "/opt/svc/env.conf", "/etc/app/secrets.yaml"]
RULES_NAMED = ["SOC-114: Anomalous Tool Chain", "AIM7: Retrieval Poisoning",
               "DET-22: Unauthenticated Corpus Write"]
PAYLOADS = ["zero-width split", "homoglyph swap", "base64 wrapper", "acrostic carrier"]

# Distractor sentences that support no fact. Their job is to teach that prose is
# not evidence — the `no_facts` control in the eval exists because a model with
# nothing to extract will happily invent something.
NOISE = [
    "The operator refilled their coffee and re-read the worklist.",
    "Scan queue was idle for eleven minutes.",
    "Reminder: the engagement window closes Friday.",
    "The dashboard was reloaded twice.",
    "Nothing new appeared in the feed.",
    "A note was added to the sitrep and then removed.",
]


def _fact(s, p, o, c="confirmed"):
    return {"subject": s, "predicate": p, "object": o, "confidence": c}


def case_r2(rnd):
    svc, cfg, host = rnd.choice(SERVICES), rnd.choice(CONFIGS), rnd.choice(HOSTS)
    priv, user = rnd.choice(PRIVS), rnd.choice(USERS)
    window = rnd.choice([
        f"the {svc} service on {host} runs as {priv}, and {cfg} is writable by our user {user}",
        f"confirmed {cfg} is writable by {user}; the {svc} unit that loads it runs as {priv} on {host}",
        f"{svc} (host {host}) executes as {priv}. Its config {cfg} has group-write for {user}.",
    ])
    # Both facts carry a host so ctx.same_host() can join them — the join is the
    # product here, not the two facts in isolation.
    return window, [_fact(svc, "runs-as", priv), _fact(svc, "on-host", host),
                    _fact(cfg, "writable-by", user), _fact(cfg, "on-host", host)]


def case_r10(rnd):
    agent, store, tool = _agentname(rnd), _storename(rnd), _tool(rnd)
    ep = rnd.choice(UPLOADS)
    window = rnd.choice([
        f"POST {ep} with no credentials returned 201, so {store} accepts unauthenticated "
        f"writes. A later chat call returned the planted document in context and reported "
        f"tools_invoked [{tool}], so {store} is read by {agent} and instructions inside it "
        f"reach its tools.",
        f"{ep} takes anonymous uploads straight into {store}. {agent} retrieves from {store} "
        f"on every turn and holds {tool}; a planted line caused {tool} to run.",
    ])
    # `accepts` and `is-read-by` MUST share the store subject, and `has-tool`
    # MUST hang off the agent. This is the exact alignment models get wrong.
    return window, [_fact(store, "accepts", "unauthenticated writes"),
                    _fact(store, "is-read-by", agent),
                    _fact(agent, "has-tool", tool)]


def case_card(rnd):
    """A full agent-probe dump, at the length the tool runner actually emits.

    v1 taught this on a 120-char one-liner. Real `tool_run` output is thousands
    of characters of pretty-printed JSON plus /health and /openapi.json, and a
    model trained only on the short form falls back on memorised vocabulary when
    it meets the long one. Length is part of the distribution."""
    agent, model = _agentname(rnd), rnd.choice(MODELS)
    tools = [_tool(rnd) for _ in range(rnd.randint(3, 6))]
    host, port = rnd.choice(HOSTS), rnd.choice([8000, 8080, 9000, 8001])
    skills = ",\n    ".join(
        '{"id": "%s", "name": "%s", "description": "%s the %s"}'
        % (t, t, rnd.choice(["run", "read", "update", "emit"]), rnd.choice(_NOUN))
        for t in tools)
    paths = ",\n    ".join('"/%s": {"post": {}}' % t for t in tools)
    window = (
        '[tool] agent-probe %s:%d\n'
        '# GET /.well-known/agent.json  ->  200\n'
        '{\n  "name": "%s",\n  "description": "Internal assistant with retrieval",\n'
        '  "version": "%d.%d.%d",\n  "url": "http://%s:%d",\n'
        '  "metadata": {"model": "%s", "provider": "self-hosted"},\n'
        '  "capabilities": {"streaming": true, "pushNotifications": false},\n'
        '  "skills": [\n    %s\n  ]\n}\n'
        '# GET /health  ->  200\n{"agent": "%s", "status": "ok", "uptime_s": %d}\n'
        '# GET /openapi.json  ->  200\n{"openapi": "3.0.0", "paths": {\n    %s\n}}'
        % (host, port, agent, rnd.randint(1, 4), rnd.randint(0, 9), rnd.randint(0, 9),
           host, port, model, skills, agent, rnd.randint(100, 99999), paths))
    facts = [_fact(agent, "runs-model", model), _fact(agent, "on-host", host)]
    facts += [_fact(agent, "has-tool", t) for t in tools]
    return window, facts


def case_nmap(rnd):
    host = rnd.choice(HOSTS)
    ports = rnd.sample([(22, "ssh"), (443, "https"), (6379, "redis"), (5432, "postgresql"),
                        (9200, "elasticsearch"), (3306, "mysql")], 2)
    body = "\n".join(f"{p}/tcp open {n}" for p, n in ports)
    window = f"[tool] nmap {host}: Nmap scan report for {host}\n{body}"
    return window, [_fact(host, "listens-on", f"{p}/tcp {n}") for p, n in ports]


def case_cred(rnd):
    f, sec, user = rnd.choice(FILES), rnd.choice(SECRETS), rnd.choice(USERS)
    window = f"cat {f}\nusername = {user}\npassword = {sec}"
    return window, [_fact(f, "has-cred", sec)]


def case_ssrf(rnd):
    tool, host = _tool(rnd), rnd.choice(HOSTS)
    window = (f"POST /tools/{tool} with url=http://169.254.169.254/latest/meta-data/"
              f"iam/security-credentials/ returned 200 with an AccessKeyId and "
              f"SecretAccessKey, from {host}")
    return window, [_fact(tool, "has-primitive", "SSRF to cloud metadata"),
                    _fact(tool, "on-host", host)]


def case_detection(rnd):
    rule, pay = rnd.choice(RULES_NAMED), rnd.choice(PAYLOADS)
    window = f"detection: rule '{rule}' fired on our {pay} payload at 09:41"
    return window, [_fact(rule, "fired", pay)]


def case_noauth(rnd):
    svc, host = rnd.choice(SERVICES), rnd.choice(HOSTS)
    window = f"{svc} on {host}:6379 answered PING without authentication"
    return window, [_fact(svc, "no-auth", "responds without credentials"),
                    _fact(svc, "on-host", host)]


def case_empty(rnd):
    return "\n".join(rnd.sample(NOISE, rnd.randint(2, 3))), []


GENERATORS = [case_r2, case_r10, case_card, case_nmap, case_cred, case_ssrf,
              case_detection, case_noauth, case_empty]
# R2/R10 over-weighted: they are the cases the eval shows failing, and they are
# the only ones where getting each fact right is not enough.
WEIGHTS = [3, 3, 2, 2, 1, 1, 1, 1, 2]


def build(n, seed=7):
    rnd = random.Random(seed)
    rows, seen = [], set()
    guard = 0
    while len(rows) < n and guard < n * 40:
        guard += 1
        gen = rnd.choices(GENERATORS, weights=WEIGHTS, k=1)[0]
        body, facts = gen(rnd)
        if rnd.random() < 0.35:                      # interleave irrelevant prose
            body = body + "\n" + rnd.choice(NOISE)
        window = f"[t{rnd.randint(1, 99)}] (agent/reasoning) {body}"
        if window in seen:
            continue
        seen.add(window)
        prompt = analyst.PROMPT.format(
            categories=analyst.CATEGORIES, window=window,
            predicates=", ".join(correlate.CORRELATED_PREDICATES),
            entities="(none yet)")
        rows.append({"messages": [
            {"role": "user", "content": prompt},
            {"role": "assistant",
             "content": json.dumps({"facts": facts, "leads": []}, separators=(",", ":"))},
        ]})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/ft")
    ap.add_argument("--n", type=int, default=900)
    ap.add_argument("--seed", type=int, default=7)
    ns = ap.parse_args()

    rows = build(ns.n, ns.seed)
    random.Random(ns.seed).shuffle(rows)
    n_val = max(20, len(rows) // 10)
    splits = {"train": rows[: -2 * n_val], "valid": rows[-2 * n_val: -n_val],
              "test": rows[-n_val:]}
    os.makedirs(ns.out, exist_ok=True)
    for name, part in splits.items():
        with open(os.path.join(ns.out, f"{name}.jsonl"), "w") as fh:
            for r in part:
                fh.write(json.dumps(r) + "\n")
        print(f"{name:<6} {len(part):>5}")
    print(f"\nwrote {ns.out}/  (train/valid/test)")


if __name__ == "__main__":
    main()
