"""Correlation engine: joins facts into opportunities.

Runs after every fact insert and once at API startup. Rules are plain
functions over the active-fact set; each returns candidate opportunities as
(rule, title, rationale, fact_ids). Dedup via sig = rule + sorted fact ids.
The engine suggests, never declares.
"""

import json
import os
import re

from . import db

PRIV_PRINCIPALS = {"root", "admin", "administrator", "system", "nt authority\\system"}
OUR_PRINCIPALS = {"us", "we", "our user", "our-user", "current user", "www-data"}
ATTACKER_NETS = tuple(prefix.strip() for prefix in os.environ.get("REDOPS_ATTACKER_NETS", "").split(",") if prefix.strip())
AUTH_PORTS = {21, 22, 23, 445, 3389, 5985, 5986, 5432, 3306, 6379, 1433, 27017}
SENSITIVE_RE = re.compile(r"(etc/passwd|etc/shadow|/shadow$|\.env$|id_rsa|config)", re.I)
INGEST_RE = re.compile(r"(ingest|upload|import|collect)", re.I)


class Ctx:
    def __init__(self, conn, engagement_id):
        self.conn = conn
        self.eng = engagement_id
        # polarity='affirm' only. An absent fact records that something was
        # checked and is NOT there; joining one would manufacture a chain out of
        # its own negation (an absent `writable-by` completing R1/R2 is the
        # worst thing this engine could do). Absence is read by precedent, which
        # compares engagements, never by a rule that asserts a path.
        self.facts = db.rows(conn, db.FACT_SQL + " WHERE f.engagement_id=? AND f.status='active'"
                                                 " AND f.polarity='affirm'",
                             (engagement_id,))
        self.entities = {e["id"]: e for e in db.rows(
            conn, "SELECT * FROM entities WHERE engagement_id=?", (engagement_id,))}
        self.targets = db.rows(conn, "SELECT * FROM targets WHERE engagement_id=?", (engagement_id,))
        # decomposed credential material (v12): independent pools the spray
        # matrix cross-joins, plus the bindings already asserted (so we never
        # re-suggest a pairing that's been recorded/tried).
        self.principals = db.rows(
            conn, "SELECT * FROM principals WHERE engagement_id=? AND status='active'", (engagement_id,))
        self.secrets = db.rows(
            conn, "SELECT * FROM secrets WHERE engagement_id=? AND status='active'", (engagement_id,))
        self.bindings = db.rows(
            conn, "SELECT * FROM cred_bindings WHERE engagement_id=?", (engagement_id,))

    def meta(self, ent_id):
        try:
            return json.loads(self.entities[ent_id]["meta_json"] or "{}")
        except (KeyError, json.JSONDecodeError):
            return {}

    # --- helpers rules share -------------------------------------------------

    def hosts_of(self, ent_id):
        """Host entity ids linked to ent_id via on-host/listens-on/resolves-to facts."""
        hosts = set()
        for f in self.facts:
            if f["subject_id"] == ent_id and f["predicate"] in ("on-host", "resolves-to") and f["object_id"]:
                if self.entities.get(f["object_id"], {}).get("type") == "host":
                    hosts.add(f["object_id"])
            if f["object_id"] == ent_id and f["predicate"] == "on-host":
                if self.entities.get(f["subject_id"], {}).get("type") == "host":
                    hosts.add(f["subject_id"])
        return hosts

    def same_host(self, a_id, b_id):
        ha, hb = self.hosts_of(a_id), self.hosts_of(b_id)
        if ha and hb:
            return bool(ha & hb)
        # fallback: shared name stem ("qdrant" / "qdrant config")
        na, nb = self.entities[a_id]["name"].lower(), self.entities[b_id]["name"].lower()
        return na.startswith(nb) or nb.startswith(na)

    def is_no_auth(self, f):
        return f["predicate"] == "no-auth" or (
            f["predicate"] == "listens-on" and "no-auth" in (f["object_text"] or "").lower())


def _principal(f, ctx):
    if f["object_id"] and f["object_id"] in ctx.entities:
        return ctx.entities[f["object_id"]]["name"].lower()
    return (f["object_text"] or "").lower()


def writable_us(ctx, f):
    return f["predicate"] == "writable-by" and _principal(f, ctx) in OUR_PRINCIPALS


# --- rules -------------------------------------------------------------------

def r1_unauth_privileged_write(ctx):
    out = []
    noauth = [f for f in ctx.facts if ctx.is_no_auth(f)
              and ctx.entities.get(f["subject_id"], {}).get("type") in ("service", "endpoint")]
    writ = [f for f in ctx.facts if writable_us(ctx, f)
            and ctx.entities.get(f["subject_id"], {}).get("type") in ("config", "file")]
    for a in noauth:
        for w in writ:
            if a["subject_id"] != w["subject_id"] and ctx.same_host(a["subject_id"], w["subject_id"]):
                out.append(("R1", "Unauthenticated control path",
                            f"{a['subject_name']} is reachable without authentication and "
                            f"{w['subject_name']} on the same host is writable by us - "
                            f"config change may be applied without creds.",
                            [a["id"], w["id"]]))
    return out


def _restart_facts_on_host(ctx, subject_ids):
    """crash/respawn/restart-trigger facts co-located (host link or name stem)."""
    out = []
    for f in ctx.facts:
        if f["predicate"] in ("crashes", "respawns", "restart-trigger"):
            if any(ctx.same_host(f["subject_id"], sid) for sid in subject_ids):
                out.append(f)
    return out


def r2_privesc_config_hijack(ctx):
    out = []
    runsas = [f for f in ctx.facts if f["predicate"] == "runs-as"
              and _principal(f, ctx) in PRIV_PRINCIPALS
              and ctx.entities.get(f["subject_id"], {}).get("type") == "service"]
    writ = [f for f in ctx.facts if writable_us(ctx, f)
            and ctx.entities.get(f["subject_id"], {}).get("type") in ("config", "file")]
    for r in runsas:
        for w in writ:
            if ctx.same_host(r["subject_id"], w["subject_id"]):
                restarts = _restart_facts_on_host(ctx, [r["subject_id"], w["subject_id"]])
                if restarts:
                    extra = (" HIGH CONFIDENCE: a restart primitive on the same host is "
                             "available (" + "; ".join(f"{x['subject_name']} {x['predicate']}"
                                                      for x in restarts) +
                             ") - poison, then force the reload.")
                else:
                    extra = " Find a restart/reload trigger to complete the chain."
                out.append(("R2", "Privesc via config/binary hijack",
                            f"{r['subject_name']} runs as {_principal(r, ctx)} and "
                            f"{w['subject_name']} is writable by us - replace/poison it and "
                            f"wait for the service to load it.{extra}",
                            [r["id"], w["id"]] + [x["id"] for x in restarts],
                            [r["id"], w["id"]]))  # stable key: the core pair, not the restart facts
    return out


def r3_cred_reuse(ctx):
    out = []
    valid_on = [f for f in ctx.facts if f["predicate"] in ("valid-on", "works-on") and f["object_id"]
                and ctx.entities.get(f["subject_id"], {}).get("type") == "credential"]
    auth_svcs = [f for f in ctx.facts if f["predicate"] == "auth-accepts" or (
        f["predicate"] == "listens-on" and ctx.entities.get(f["subject_id"], {}).get("type") == "service"
        and _port(f["object_text"]) in AUTH_PORTS)]
    for c in valid_on:
        home = ctx.hosts_of(c["object_id"]) or {c["object_id"]}
        for s in auth_svcs:
            if s["id"] == c["id"] or s["subject_id"] == c["object_id"]:
                continue
            shosts = ctx.hosts_of(s["subject_id"])
            if shosts and not (shosts & home):
                out.append(("R3", "Password reuse candidate",
                            f"Credential {c['subject_name']} works on {c['object_name']} - "
                            f"{s['subject_name']} on a different host accepts authentication; "
                            f"try the same credential there.",
                            [c["id"], s["id"]]))
    return out


def _port(text):
    m = re.search(r"\d+", text or "")
    return int(m.group()) if m else None


def r4_exfil_path(ctx):
    out = []
    readable = [f for f in ctx.facts if f["predicate"] == "readable-by"
                and _principal(f, ctx) in OUR_PRINCIPALS
                and SENSITIVE_RE.search(ctx.entities.get(f["subject_id"], {}).get("name") or "")]
    sinks = [f for f in ctx.facts if f["predicate"] == "exposes"
             and INGEST_RE.search((f["object_text"] or "") + " " + (f["object_name"] or ""))]
    for r in readable:
        for s in sinks:
            out.append(("R4", "Exfiltration path",
                        f"Sensitive file {r['subject_name']} is readable by us and "
                        f"{s['subject_name']} exposes {s['object_text'] or s['object_name']} - "
                        f"possible exfil channel.",
                        [r["id"], s["id"]]))
    return out


def _is_attacker_ip(ctx, f):
    text = f["object_text"] or ""
    if f["object_id"] and f["object_id"] in ctx.entities:
        ent = ctx.entities[f["object_id"]]
        text = text or ent["name"]
        if ctx.meta(f["object_id"]).get("attacker"):
            return True
    return any(text.startswith(net) for net in ATTACKER_NETS)


def r5_resolution_control(ctx):
    out = []
    for f in ctx.facts:
        if f["predicate"] == "resolves-to" and _is_attacker_ip(ctx, f):
            out.append(("R5", "Intercept/spoof active",
                        f"{f['subject_name']} resolves to {f['object_text'] or f['object_name']} "
                        f"(attacker-controlled) - traffic to this name can be intercepted/spoofed.",
                        [f["id"]]))
    return out


def r6_poisoning_surface(ctx):
    out = []
    for f in ctx.facts:
        if ctx.is_no_auth(f) and ctx.entities.get(f["subject_id"], {}).get("type") == "endpoint":
            name = ctx.entities[f["subject_id"]]["name"]
            if INGEST_RE.search(name + " " + (f["object_text"] or "")):
                out.append(("R6", "Data poisoning surface",
                            f"Ingest endpoint {name} accepts unauthenticated input - "
                            f"poisoned data may reach downstream consumers.",
                            [f["id"]]))
    return out


LOOPBACK_RE = re.compile(r"^(127\.|localhost|::1|\[::1\])", re.I)
USER_FACING_RE = re.compile(r"(user-facing|response channel|user output|chat|to user)", re.I)


def r7_localhost_pivot(ctx):
    """Service on loopback (or an unreachable subnet) + a foothold that can reach it."""
    out = []
    footholds = [t for t in ctx.targets if t["status"] in ("foothold", "rooted")]
    if not footholds:
        return out
    for f in ctx.facts:
        if f["predicate"] != "listens-on":
            continue
        where = (f["object_text"] or "") + " " + (f["object_name"] or "") + " " + \
                ctx.entities.get(f["subject_id"], {}).get("name", "")
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", where)
        ip = m.group(1) if m else ""
        loopback = bool(LOOPBACK_RE.search(where)) or ip.startswith("127.")
        if not (loopback or ip):
            continue
        for t in footholds:
            same_box = ip and ip == t["ip"]
            same_subnet = ip and not loopback and \
                ".".join(ip.split(".")[:3]) == ".".join(t["ip"].split(".")[:3])
            on_same_host = any(ctx.same_host(f["subject_id"], e["id"]) for e in
                               ctx.entities.values() if e["name"] == t["ip"])
            if loopback and (same_box or on_same_host):
                out.append(("R7", "Pivot via foothold (loopback service)",
                            f"{f['subject_name']} listens on loopback of {t['ip']} - "
                            f"unreachable from our VPN but the foothold there can reach it. "
                            f"Forward a port (ssh -L / chisel) and attack it through the foothold.",
                            [f["id"]]))
            elif not loopback and ip and not ip.startswith(ATTACKER_NETS) and same_subnet \
                    and not same_box:
                out.append(("R7", "Pivot via foothold (cross-subnet service)",
                            f"{f['subject_name']} listens on {ip}, outside our VPN range; "
                            f"foothold {t['ip']} shares its subnet and can reach it - "
                            f"route through the foothold.",
                            [f["id"]]))
    return out


INFLUENCE_PREDS = ("no-auth", "writable-by", "accepts", "ingests")

# The closed vocabulary R1-R13 actually join on.
#
# Rules match predicates by exact string, so a fact written with any other
# predicate is inert — it renders in the Intel tab and contributes to nothing.
# That is invisible when facts are authored by hand against these rules, and
# very visible the moment something generates them: pointed at a lab agent
# holding exec_sql behind an unauthenticated document sink, the analyst emitted
# `exposes-tool`, `uses-model`, `is-exposed` and `runs`, all plausible, none of
# them joinable, and R10 stayed silent on a textbook R10.
#
# Exported so a generator can be *constrained* to it rather than trusted to
# guess it. Extend this when a rule learns a new predicate — not to accommodate
# a generator's preference, since a predicate no rule reads is by construction
# a predicate that does nothing.
CORRELATED_PREDICATES = (
    "accepts", "auth-accepts", "crashes", "detected-by", "exposes", "fired",
    "flagged", "has-cred", "has-primitive", "has-skill", "has-tool", "ingests",
    "is-read-by", "listens-on", "logs-to", "no-auth", "on-host", "readable-by",
    "resolves-to", "respawns", "restart-trigger", "runs-as", "runs-model",
    "valid-on", "works-on", "writable-by",
)


def _sink_influenceable(ctx, sink_id):
    for f in ctx.facts:
        if f["subject_id"] == sink_id and (f["predicate"] in INFLUENCE_PREDS or ctx.is_no_auth(f)):
            return f
    return None


def r10_sink_tool(ctx):
    """Attacker-influenceable llm-read-sink x an action-tool the reading agent holds
    (including the degenerate user-facing response channel)."""
    out = []
    reads = [f for f in ctx.facts if f["predicate"] == "is-read-by"]
    tools = [f for f in ctx.facts if f["predicate"] == "has-tool"]
    for rd in reads:
        agent_id = rd["object_id"]
        agent_name = rd["object_name"] or rd["object_text"] or ""
        influence = _sink_influenceable(ctx, rd["subject_id"])
        if not influence:
            continue
        for tool in tools:
            same_agent = (agent_id and tool["subject_id"] == agent_id) or \
                (agent_name and tool["subject_name"].lower() == agent_name.lower())
            if not same_agent:
                continue
            tool_desc = tool["object_name"] or tool["object_text"] or "?"
            if USER_FACING_RE.search(tool_desc):
                out.append(("R10", "Poison-to-user channel (indirect phishing)",
                            f"{rd['subject_name']} is attacker-influenceable and read by "
                            f"{agent_name or tool['subject_name']}, whose output goes straight to the "
                            f"user - planted content becomes trusted advice/phishing (lab34 arm).",
                            [rd["id"], tool["id"], influence["id"]]))
            else:
                out.append(("R10", "Indirect injection to action",
                            f"{rd['subject_name']} is attacker-influenceable and read by "
                            f"{agent_name or tool['subject_name']}, which holds tool {tool_desc} - "
                            f"planted instructions ride the sink into a side effect.",
                            [rd["id"], tool["id"], influence["id"]]))
    return out


FIRED_PREDS = ("flagged", "fired", "detected-by")


def r11_cover_tracks(ctx):
    """Detection-tripwire fired + access to its log sink -> cover-tracks opportunity."""
    out = []
    fired = [f for f in ctx.facts if f["predicate"] in FIRED_PREDS]
    logs = [f for f in ctx.facts if f["predicate"] == "logs-to"]
    access = [f for f in ctx.facts if f["predicate"] in ("valid-on", "readable-by", "writable-by")]
    for fd in fired:
        for lg in logs:
            sink_name = lg["object_name"] or lg["object_text"] or ""
            sink_tokens = [t for t in re.split(r"\s+", sink_name) if len(t) >= 4]
            for ac in access:
                where = " ".join([ac["subject_name"] or "", ac["object_name"] or "",
                                  ac["object_text"] or ""])
                if not ((lg["object_id"] and ac["object_id"] == lg["object_id"]) or
                        any(t in where for t in sink_tokens)):
                    continue
                out.append(("R11", "Cover tracks: tripwire fired, sink reachable",
                            f"Detection fired ({fd['subject_name']} {fd['predicate']} "
                            f"{fd['object_text'] or fd['object_name'] or ''}) and the log sink "
                            f"{sink_name} is reachable via {ac['subject_name']} - "
                            f"assess tampering with the record before it is reviewed.",
                            [fd["id"], lg["id"], ac["id"]]))
    return out


def update_detected(conn, engagement_id: int) -> int:
    """Flip opportunities.detected=1 when a fired tripwire shares entities with
    the opportunity's supporting facts (were you seen?). Two fired signals:
    tripwire FACTS (predicate in FIRED_PREDS), and the detection-rule CATALOG
    (detection_rules.fired=1) matched by name against an opportunity rationale."""
    ctx_facts = db.rows(conn, db.FACT_SQL + " WHERE f.engagement_id=? AND f.status='active'",
                        (engagement_id,))
    fired = [f for f in ctx_facts if f["predicate"] in FIRED_PREDS]
    fired_rules = db.rows(conn, "SELECT name FROM detection_rules "
                          "WHERE engagement_id=? AND fired=1", (engagement_id,))
    if not fired and not fired_rules:
        return 0
    flipped = 0
    for o in db.rows(conn, "SELECT * FROM opportunities WHERE engagement_id=? AND detected=0",
                     (engagement_id,)):
        sup = db.rows(conn, db.FACT_SQL +
                      " JOIN opportunity_facts x ON x.fact_id=f.id WHERE x.opportunity_id=?",
                      (o["id"],))
        rationale = (o["rationale"] or "").lower()
        hit = False
        for fd in fired:
            ent_ids = {x for x in (fd["subject_id"], fd["object_id"]) if x}
            if any(sf["subject_id"] in ent_ids or sf["object_id"] in ent_ids for sf in sup):
                hit = True
                break
            if (fd["subject_name"] or "").lower() and (fd["subject_name"] or "").lower() in rationale:
                hit = True
                break
        # catalog: a recorded rule that fired, named in this opportunity's rationale
        if not hit:
            hit = any((r["name"] or "").lower() and (r["name"] or "").lower() in rationale
                      for r in fired_rules)
        if hit:
            conn.execute("UPDATE opportunities SET detected=1, updated_at=? WHERE id=?",
                         (db.now(), o["id"]))
            flipped += 1
    conn.commit()
    return flipped


# --- expansion rules: emit LEADS (source=rule), not opportunities ------------

def r8_spray_matrix(ctx):
    """Every harvested credential x every reachable auth-service it was not tried on."""
    out = []
    creds: dict[int, list] = {}
    for f in ctx.facts:
        if f["predicate"] in ("valid-on", "works-on") and f["object_id"] \
                and ctx.entities.get(f["subject_id"], {}).get("type") == "credential":
            creds.setdefault(f["subject_id"], []).append(f)
    auth_svcs = [f for f in ctx.facts if f["predicate"] == "auth-accepts" or (
        f["predicate"] == "listens-on" and ctx.entities.get(f["subject_id"], {}).get("type") == "service"
        and _port(f["object_text"]) in AUTH_PORTS)]
    for cid, cfacts in creds.items():
        cname = cfacts[0]["subject_name"]
        worked = {f["object_id"] for f in cfacts}
        for f in cfacts:
            worked |= ctx.hosts_of(f["object_id"])
        for s in auth_svcs:
            shosts = ctx.hosts_of(s["subject_id"]) or {s["subject_id"]}
            if shosts & worked:
                continue
            n = len(cfacts)
            out.append({"category": "secret-exposure",
                        "observation": f"spray {cname} against {s['subject_name']} (untried)",
                        "candidate_vector": f"credential already valid on {n} host(s); "
                                            f"{s['subject_name']} accepts auth and was never tried",
                        "fact_ids": [f["id"] for f in cfacts] + [s["id"]]})
    return out


PRIMITIVE_TARGETS = {
    "ssrf": ("reachability-pivot",
             "re-aim SSRF at 169.254.169.254 (IMDS) for cloud credentials"),
    "arbitrary-read": ("read-exfil",
                       "re-aim arbitrary-read at /etc/shadow, cloud creds, app config, SSH keys"),
    "arbitrary-write": ("write-primitive",
                        "re-aim arbitrary-write at startup folders, web.config, service binaries"),
}


def r9_primitive_generalization(ctx):
    out = []
    for f in ctx.facts:
        text = ((f["predicate"] + " " + (f["object_text"] or "") + " " +
                 (f["object_name"] or "") + " " + (f["subject_name"] or "")).lower())
        for key, (cat, obs) in PRIMITIVE_TARGETS.items():
            if key in text and (f["predicate"] == "has-primitive" or key in
                                (f["object_text"] or "").lower()):
                out.append({"category": cat,
                            "observation": f"{obs} (primitive confirmed on {f['subject_name']})",
                            "candidate_vector": "general primitive - fan out to the full target set",
                            "fact_ids": [f["id"]]})
    return out


def r12_spray_matrix_parts(ctx):
    """The password-spray matrix over the decomposed pools: every harvested
    principal × every candidate secret it is not already bound to, grouped by
    realm. One vector per realm (the actionable spray), not N×M noise rows.

    realm '' is a wildcard — a global candidate password sprays every realm,
    a global username is tried with every candidate secret. This is the vector
    R8 can't produce: R8 sprays an *already-valid* credential laterally; this
    proposes the *initial* user×password guessing that discovers one."""
    out = []
    if not ctx.principals or not ctx.secrets:
        return out
    # pairings already recorded (any status) — don't re-propose them
    bound = {(b["principal_id"], b["secret_id"]) for b in ctx.bindings}

    realms = {(p.get("realm") or "") for p in ctx.principals} | \
             {(s.get("realm") or "") for s in ctx.secrets}
    realms.discard("")  # handled per-realm via the wildcard include below

    def _in(realm, items):
        return [x for x in items if (x.get("realm") or "") in ("", realm)]

    groups = list(realms) or [""]
    for realm in groups:
        princ = _in(realm, ctx.principals)
        # canary/honeypot secrets are WITHHELD from the spray matrix (r15 warns).
        secs = [s for s in _in(realm, ctx.secrets) if not is_canary_secret(s)]
        if not princ or not secs:
            continue
        untried = sum(1 for p in princ for s in secs
                      if (p["id"], s["id"]) not in bound)
        if not untried:
            continue
        skinds = sorted({s["kind"] for s in secs})
        where = f" in realm {realm}" if realm else ""
        names = ", ".join(p["name"] for p in princ[:6]) + ("…" if len(princ) > 6 else "")
        # STABLE observation (dedup key) — no mutable counts, or the lead would
        # re-fork every time a principal/secret lands. Live numbers ride in the
        # candidate_vector, which _emit_lead refreshes in place.
        out.append({
            "category": "secret-exposure",
            "observation": f"password-spray matrix{where}",
            "candidate_vector": f"{len(princ)} principals × {len(secs)} candidate "
                                f"{'/'.join(skinds)}(s) = {untried} untried logins{where}: "
                                f"principals [{names}] — spray low-and-slow, record each hit "
                                f"as a valid binding.",
            "fact_ids": [],
        })
    return out


def r13_unexpected_callback(ctx):
    """An inbound connection the target opened to US that we never solicited — a
    callback. Ground truth off the wire (an observed packet, not an agent claim),
    so it's high-confidence: reverse shell, C2 beacon, or a blind-command side
    effect calling home. This is the out-of-band confirmation the AI-lab
    methodology depends on, surfaced automatically as a vector."""
    out = []
    rows = db.rows(ctx.conn,
        "SELECT * FROM flows WHERE engagement_id=? AND direction='in' "
        "AND opened=1 AND target_id IS NOT NULL AND state!='closed' "
        "ORDER BY last_seen DESC", (ctx.eng,))
    for f in rows:
        port = f":{f['dport']}" if f["dport"] is not None else ""
        title = f"Unexpected callback from {f['src']}"
        rationale = (
            f"{f['src']} opened an inbound {f['proto']} connection to you{port} "
            f"(state {f['state']}, {f['packets']} pkt) that you did not initiate — "
            f"likely a reverse shell, C2 beacon, or a blind-command side effect "
            f"calling home. Observed on the wire, not claimed by the agent. "
            f"Confirm the local listener/process and attribute the source.")
        # stable synthetic key (no backing facts): dedup per source+port+proto
        key = [f"cb:{f['src']}:{f['dport']}:{f['proto']}"]
        out.append(("R13", title, rationale, [], key))
    return out


CONFIRM_HINT = {
    "rag-store": "hit its API (Qdrant :6333/:6334, Chroma :8000, Weaviate :8080) and list collections",
    "service": "connect to its port (Mongo :27017, Postgres :5432, Redis :6379, Elasticsearch :9200) and check auth",
    "model": "probe the app for the model behind it — name/version, guardrails, extractable system prompt",
    "collection": "enumerate and read the collection through the store's API",
    "framework": "fingerprint it (headers, debug/error pages) and check the version against known CVEs",
    "endpoint": "request it and observe the response",
}


def r14_confirm_claimed_stack(ctx):
    """A tech component the target only CLAIMED — read off an /about page, a banner,
    a config comment — that we have never observed. Surfaces it as a vector: go touch
    it and turn the claim into ground truth. This is the point of the confirmation
    lifecycle — a claimed node generates its own next action, and it stops being a
    vector the moment fact_confirm advances it to observed."""
    out = []
    for f in ctx.facts:
        if f["predicate"] != "backed-by" or f.get("stage") != "claimed":
            continue
        if f["object_id"] and f["object_id"] in ctx.entities:
            ent = ctx.entities[f["object_id"]]
            name, ctype = ent["name"], ent["type"]
        else:
            name, ctype = (f["object_text"] or "component"), "component"
        subj = ctx.entities.get(f["subject_id"], {}).get("name", "the app")
        hint = CONFIRM_HINT.get(ctype, "probe it directly to confirm it exists")
        title = f"Confirm claimed {ctype}: {name}"
        rationale = (
            f"{subj} is CLAIMED to be backed by {name} ({ctype}) — disclosed by the "
            f"target, not observed by us. We've never touched it. Confirm it: {hint}. "
            f"On success, fact_confirm the backed-by fact so the board shows it as real.")
        out.append(("R14", title, rationale, [f["id"]]))
    return out


# canary / honeypot markers — a secret carrying one is a tripwire, not loot.
_CANARY_MARKERS = re.compile(r"honeypot|canary|tripwire|decoy|do[\s_-]?not[\s_-]?use", re.I)
_DECOY_PW = re.compile(r"[A-Za-z]{3,}20\d\d!")          # CompanyName2024!-style decoy
_UPPER_MARKER = re.compile(r"\b(TEST|HONEYPOT|DECOY|CANARY)\b")   # explicit uppercase marker


def is_canary_secret(secret) -> bool:
    """A recovered secret that looks like a planted tripwire (HONEYPOT/canary/decoy
    markers, or the CompanyName20NN! decoy-password shape). Detection is a heuristic
    fail-SAFE: it only WITHHOLDS (visibly, overridably), never deletes — a false
    positive costs a click, a false negative costs the engagement."""
    blob = (secret.get("value") or "") + " " + (secret.get("notes") or "")
    return bool(_CANARY_MARKERS.search(blob) or _DECOY_PW.search(blob) or _UPPER_MARKER.search(blob))


def r15_canary_quarantine(ctx):
    """A recovered secret with canary/honeypot markers — WITHHELD from the spray
    matrix (r12 skips it) and surfaced as a warning so the operator doesn't burn the
    op tripping a tripwire. Non-destructive: flagged, not deleted; clear the marker
    to override if it's genuinely a real credential."""
    out = []
    for s in ctx.secrets:
        if not is_canary_secret(s):
            continue
        val = s.get("value") or "(no value)"
        title = "⚠ Suspected canary — withheld from spray"
        rationale = (
            f"The {s.get('kind', 'secret')} '{val}' carries a canary/honeypot marker. "
            f"Spraying it likely trips a tripwire and burns the engagement, so it has been "
            f"WITHHELD from the spray matrix. Confirm it is a real credential before use; if "
            f"it is, clear the marker to override.")
        out.append(("R15", title, rationale, [], [f"canary:{s['id']}"]))
    return out


RULES = [r1_unauth_privileged_write, r2_privesc_config_hijack, r3_cred_reuse,
         r4_exfil_path, r5_resolution_control, r6_poisoning_surface,
         r7_localhost_pivot, r10_sink_tool, r11_cover_tracks,
         r13_unexpected_callback, r14_confirm_claimed_stack, r15_canary_quarantine]

EXPANSION_RULES = [r8_spray_matrix, r9_primitive_generalization, r12_spray_matrix_parts]


def _emit_lead(conn, eng, item: dict) -> dict | None:
    existing = db.row(conn, "SELECT id, candidate_vector FROM leads WHERE engagement_id=? "
                            "AND observation=? AND status='open'", (eng, item["observation"]))
    if existing:
        # same lead (stable observation) — refresh the live vector text (e.g. the
        # spray matrix counts) rather than fork a near-duplicate.
        cv = item.get("candidate_vector", "")
        if cv and cv != existing["candidate_vector"]:
            conn.execute("UPDATE leads SET candidate_vector=?, updated_at=? WHERE id=?",
                         (cv, db.now(), existing["id"]))
            conn.commit()
        return None
    lid = db.insert(conn, "leads", {
        "engagement_id": eng, "observation": item["observation"],
        "category": item["category"], "candidate_vector": item.get("candidate_vector", ""),
        "source": "rule", "fact_ids": json.dumps(item.get("fact_ids", [])),
        "status": "open", "created_at": db.now(), "updated_at": db.now()})
    return db.row(conn, "SELECT * FROM leads WHERE id=?", (lid,))


def _auto_promote(conn, eng: int, created: list[dict]) -> None:
    """An opportunity whose supporting facts cover a lead's fact_ids promotes it.

    Only genuine hunches (analyst/agent-authored) are auto-promoted this way.
    Rule-generated expansion leads (spray matrix, primitive fan-out) are standing
    *suggestions* to act, not hypotheses awaiting confirmation — an opportunity
    that merely shares their facts (e.g. an R3 reuse opp over the same cred+host)
    doesn't mean the spray was tried, so promoting them just hides open work."""
    for lead in db.rows(conn, "SELECT * FROM leads WHERE engagement_id=? AND status='open' "
                              "AND source != 'rule'", (eng,)):
        fids = set(json.loads(lead["fact_ids"] or "[]"))
        if not fids:
            continue
        for o in db.rows(conn, "SELECT id FROM opportunities WHERE engagement_id=?", (eng,)):
            sup = {r["fact_id"] for r in db.rows(
                conn, "SELECT fact_id FROM opportunity_facts WHERE opportunity_id=?", (o["id"],))}
            if fids <= sup:
                conn.execute("UPDATE leads SET status='promoted', "
                             "candidate_vector = candidate_vector || ?, updated_at=? WHERE id=?",
                             (f" [auto-promoted by opp #{o['id']}]", db.now(), lead["id"]))
                break
    conn.commit()


def run(conn, engagement_id=None) -> list[dict]:
    """Run all rules; insert new opportunities (dedup by sig). Returns new rows."""
    if engagement_id is None:
        eng_ids = [r["id"] for r in db.rows(conn, "SELECT id FROM engagements")]
    else:
        eng_ids = [engagement_id]
    created = []
    for eng in eng_ids:
        ctx = Ctx(conn, eng)
        produced = set()   # sigs emitted this pass, for reaping self-resolving vectors
        for rule in RULES:
            for entry in rule(ctx):
                # rules may return (name, title, rationale, fact_ids) or, when
                # strengthening facts can arrive after the core match, a 5th
                # key_ids: the STABLE identity subset the signature dedups on.
                # Without it the sig would change as facts accrue and the same
                # vector would surface twice (e.g. R2 when the restart primitive
                # is found last).
                if len(entry) == 5:
                    rule_name, title, rationale, fact_ids, key_ids = entry
                else:
                    rule_name, title, rationale, fact_ids = entry
                    key_ids = fact_ids
                sig = rule_name + ":" + ",".join(str(i) for i in sorted(key_ids))
                produced.add(sig)
                existing = db.row(conn, "SELECT * FROM opportunities WHERE sig=?", (sig,))
                if existing:
                    # same vector: upgrade in place (refresh rationale, attach
                    # any newly-arrived strengthening facts) rather than dup.
                    linked = {r["fact_id"] for r in db.rows(
                        conn, "SELECT fact_id FROM opportunity_facts WHERE opportunity_id=?",
                        (existing["id"],))}
                    new_fids = [fid for fid in fact_ids if fid not in linked]
                    if new_fids or existing["rationale"] != rationale or existing["status"] == "resolved":
                        for fid in new_fids:
                            conn.execute("INSERT INTO opportunity_facts (opportunity_id, fact_id) "
                                         "VALUES (?,?)", (existing["id"], fid))
                        new_status = "open" if existing["status"] == "resolved" else existing["status"]
                        conn.execute("UPDATE opportunities SET rationale=?, status=?, updated_at=? WHERE id=?",
                                     (rationale, new_status, db.now(), existing["id"]))
                        conn.commit()
                    continue
                oid = db.insert(conn, "opportunities", {
                    "engagement_id": eng, "title": title, "rationale": rationale,
                    "rule": rule_name, "sig": sig, "status": "open",
                    "created_at": db.now(), "updated_at": db.now()})
                for fid in fact_ids:
                    conn.execute("INSERT INTO opportunity_facts (opportunity_id, fact_id) VALUES (?,?)",
                                 (oid, fid))
                conn.commit()
                created.append(db.row(conn, "SELECT * FROM opportunities WHERE id=?", (oid,)))
        # R14 resolves when a claim is confirmed; R13 when a flow no longer
        # qualifies as a callback; R10 when a sink/tool path is ruled out.
        stale = db.rows(conn, "SELECT id, sig FROM opportunities WHERE engagement_id=? AND "
                              "rule IN ('R10','R13','R14') AND status IN ('open','pinned')", (eng,))
        for o in stale:
            if o["sig"] not in produced:
                conn.execute("UPDATE opportunities SET status='resolved', updated_at=? WHERE id=?",
                             (db.now(), o["id"]))
        conn.commit()
        for xrule in EXPANSION_RULES:
            for item in xrule(ctx):
                _emit_lead(conn, eng, item)
        update_detected(conn, eng)
        _auto_promote(conn, eng, created)
    return created
