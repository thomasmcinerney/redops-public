"""Can a model read prose the deterministic path refuses to? Run:

    uv run python scripts/eval_prose.py

This is the only open question about putting a model in this pipeline.

Everything measured so far fed the analyst STRUCTURED input — agent cards, nmap
XML, JSON tool output — and on that ground a parser wins outright: with
`agent-probe` emitting `has-tool`, the deterministic path produced 5 R10
opportunities where the analyst-in-the-loop run produced 3. That result says
nothing about a model's worth, because parsing parseable data is not a model's
job.

The case that remains is free prose in the agent's own reasoning, where nothing
declares anything and there is no schema to parse.

There is NO deterministic incumbent on that ground, and that was a decision, not
an oversight. `wiretail.py` still defines WRITABLE_RE, NOAUTH_RE, HAS_TOOL_RE,
READ_BY_RE, INGESTS_RE and friends — and `extract_facts()` calls none of them.
Its comment records why: "Regex-extracting facts from the agent's natural
language produces garbage subjects ('requires no-auth unauthenticated' —
'requires' is not an entity)". Prose scraping was tried, produced junk, and was
cut. The only text extractor kept is an /etc/hosts parser, which is a file
format rather than prose. The same comment names what should cover the gap
instead: "the analyst pass".

So this is not model vs regex. It is model vs nothing, on the one input class
the deterministic path has explicitly declined. The regex row below is scored
anyway, to show what the retained-but-unused patterns would contribute if they
were re-enabled — which is the experiment their removal already ran.

Sentences below are phrased the way an operator writes at 2am — hedged, indirect,
sometimes stating the finding only by implication. None of them are phrased to
suit either contender.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("REDOPS_DATA", "/tmp/redops-prose")

from redops import analyst, wiretail  # noqa: E402

# (prose, [(subject-substring, predicate, object-substring)])
CASES = [
    ("the qdrant config came back group-writable for www-data, and the unit file "
     "says it starts as root",
     [("config", "writable-by", "www-data"), ("qdrant", "runs-as", "root")]),

    ("no credentials anywhere on that upload endpoint — it just took the document",
     [("", "no-auth", "")]),

    ("killed the char-server and it was answering again within four seconds, so "
     "something is bringing it back",
     [("char-server", "respawns", "")]),

    ("whatever we drop in the ticket corpus ends up quoted back at us by the "
     "assistant, word for word",
     [("", "is-read-by", "")]),

    ("the assistant happily ran a database query for me when the document asked "
     "it to",
     [("assistant", "has-tool", "")]),

    ("that reset link doesn't check who you are at all, you just need the token",
     [("", "no-auth", "")]),

    ("its /fetch helper will pull any URL you hand it, including link-local",
     [("fetch", "has-primitive", "")]),

    ("the SOC rule for prompt injection lit up the moment we sent the payload",
     [("", "fired", "")]),

    ("spent an hour on the login flow, nothing interesting, moving on to the API",
     []),

    ("reviewed the worklist, took a break, no scans run",
     []),
]


def _n(s):
    return "".join(c for c in str(s or "").lower() if c.isalnum())


def _hit(facts, want):
    ws, wp, wo = want
    for f in facts:
        if f.get("predicate") != wp:
            continue
        if ws and _n(ws) not in _n(f.get("subject")):
            continue
        if wo and _n(wo) not in _n(f.get("object")):
            continue
        return True
    return False


def score(get_facts, label):
    hits = exp = spur = 0
    per = []
    for prose, want in CASES:
        try:
            facts = get_facts(prose)
        except Exception as e:                                    # noqa: BLE001
            per.append(f"ERR {type(e).__name__}")
            continue
        facts = [f for f in facts if isinstance(f, dict)]
        if not want:
            spur += len(facts)
            per.append(f"{len(facts)} spurious" if facts else "clean")
            continue
        got = sum(1 for w in want if _hit(facts, w))
        hits += got
        exp += len(want)
        spur += sum(1 for f in facts
                    if not any(_hit([f], w) for w in want))
        per.append(f"{got}/{len(want)}")
    print(f"  {label:<14} recall {hits}/{exp} ({hits / exp:.0%})  spurious {spur}")
    return hits, exp, spur, per


def regex_facts(prose):
    """What `extract_facts` yields today: nothing, for prose. Kept in the table
    so the zero is visible rather than assumed."""
    out = []
    for f in wiretail.extract_facts(prose):
        out.append({"subject": f.get("subject") or f.get("subject_name") or "",
                    "predicate": f.get("predicate") or "",
                    "object": f.get("object_text") or f.get("object") or ""})
    return out


def model_facts_via(url, model):
    def _f(prose):
        analyst.ANALYST_URL, analyst.ANALYST_MODEL = url, model
        return analyst._chat(f"[t1] (agent/reasoning) {prose}").get("facts") or []
    return _f


MODELS = [
    ("qwen3.6-35b", "http://127.0.0.1:1234/v1", "qwen/qwen3.6-35b-a3b"),
    ("qwen3-4b", "http://127.0.0.1:8099/v1", "mlx-community/Qwen3-4B-Instruct-2507-4bit"),
]


def main():
    print(f"{len(CASES)} prose windows "
          f"({sum(1 for _, w in CASES if not w)} of them supporting nothing)\n")
    rows = [("regex (wiretail)", *score(regex_facts, "regex")[:3])]
    for label, url, model in MODELS:
        try:
            rows.append((label, *score(model_facts_via(url, model), label)[:3]))
        except Exception as e:                                    # noqa: BLE001
            print(f"  {label:<14} unavailable: {type(e).__name__}")
    print("\nregex 0/9 is not a failure — extract_facts declines prose on purpose.")
    print("It is the size of the gap the analyst was introduced to cover, and the")
    print("only input class where a model here is doing work nothing else does.")


if __name__ == "__main__":
    main()
