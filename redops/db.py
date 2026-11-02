"""SQLite storage for RedOps. Idempotent init via PRAGMA user_version."""

import hashlib
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

DATA_DIR = Path(os.environ.get("REDOPS_DATA", Path(__file__).resolve().parent.parent / "data"))
DB_PATH = DATA_DIR / "redops.db"
EVIDENCE_DIR = DATA_DIR / "evidence"
TRANSCRIPT_DIR = DATA_DIR / "transcript"

SCHEMA_VERSION = 24

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    scope TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    ip TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    os TEXT DEFAULT '',
    role TEXT DEFAULT '',
    status TEXT DEFAULT 'unidentified',
    meta_json TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT DEFAULT 'tcp',
    state TEXT DEFAULT 'open',
    name TEXT DEFAULT '',
    product TEXT DEFAULT '',
    version TEXT DEFAULT '',
    extrainfo TEXT DEFAULT '',
    cpe TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    username TEXT NOT NULL,
    secret TEXT NOT NULL,
    kind TEXT DEFAULT 'password',
    source TEXT DEFAULT '',
    valid INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    description TEXT DEFAULT '',
    cve TEXT DEFAULT '',
    matched_at TEXT DEFAULT '',
    status TEXT DEFAULT 'open',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    target_id INTEGER,
    text TEXT NOT NULL,
    meta_json TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    target_id INTEGER,
    kind TEXT DEFAULT 'file',
    path TEXT NOT NULL,
    caption TEXT DEFAULT '',
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS objectives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    text TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    value TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT DEFAULT 'user',
    text TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT NOT NULL,
    done_at TEXT
);
CREATE TABLE IF NOT EXISTS wiretail_state (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_target ON events(target_id);
CREATE INDEX IF NOT EXISTS idx_targets_eng ON targets(engagement_id);
"""

# v2: intel layer (additive)
SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    type TEXT NOT NULL DEFAULT 'other',
    name TEXT NOT NULL,
    label TEXT DEFAULT '',
    meta_json TEXT DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(engagement_id, type, name)
);
CREATE TABLE IF NOT EXISTS facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    subject_id INTEGER NOT NULL,
    predicate TEXT NOT NULL,
    object_id INTEGER,
    object_text TEXT DEFAULT '',
    stage TEXT DEFAULT 'claimed',
    source TEXT DEFAULT 'agent',
    source_event_id INTEGER,
    status TEXT DEFAULT 'active',
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS opportunities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    title TEXT NOT NULL,
    rationale TEXT DEFAULT '',
    rule TEXT DEFAULT '',
    sig TEXT UNIQUE,
    status TEXT DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS opportunity_facts (
    opportunity_id INTEGER NOT NULL,
    fact_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sitrep (
    engagement_id INTEGER PRIMARY KEY,
    activity TEXT DEFAULT '',
    hypothesis TEXT DEFAULT '',
    next_steps TEXT DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_facts_eng ON facts(engagement_id);
CREATE INDEX IF NOT EXISTS idx_facts_subject ON facts(subject_id);
CREATE INDEX IF NOT EXISTS idx_oppfacts_fact ON opportunity_facts(fact_id);
"""

# v4: leads + stealth flag (additive)
SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    observation TEXT NOT NULL,
    category TEXT NOT NULL,
    candidate_vector TEXT DEFAULT '',
    source TEXT DEFAULT 'agent',
    source_event_id INTEGER,
    fact_ids TEXT DEFAULT '[]',
    score REAL DEFAULT 0,
    status TEXT DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_scored_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_leads_eng ON leads(engagement_id);
CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);
"""

# v10: dedicated AI-artifact stores — the three things you author during the
# engagement and reuse/track: an injection-payload library, the detection-rule catalog
# ("read the rule, evade by mechanism"), and planted-poison provenance + cleanup.
SCHEMA_V10 = """
CREATE TABLE IF NOT EXISTS payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    technique TEXT NOT NULL,
    target_model TEXT DEFAULT '',
    target_ref TEXT DEFAULT '',
    guardrail_defeated TEXT DEFAULT '',
    body TEXT DEFAULT '',
    outcome TEXT DEFAULT 'untried',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    name TEXT NOT NULL,
    source_system TEXT DEFAULT '',
    match_mechanism TEXT DEFAULT '',
    blind_spot TEXT DEFAULT '',
    evasion TEXT DEFAULT '',
    fired INTEGER DEFAULT 0,
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS poison (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    store_type TEXT DEFAULT 'other',
    location TEXT DEFAULT '',
    payload_id INTEGER,
    planted_at TEXT NOT NULL,
    live INTEGER DEFAULT 1,
    verify_method TEXT DEFAULT '',
    cleanup_done INTEGER DEFAULT 0,
    notes TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_payloads_eng ON payloads(engagement_id);
CREATE INDEX IF NOT EXISTS idx_detrules_eng ON detection_rules(engagement_id);
CREATE INDEX IF NOT EXISTS idx_poison_eng ON poison(engagement_id);
"""


# v12: decompose credential material into independent, recombinable parts —
# principals (who you auth AS), secrets (what you auth WITH) and bindings
# (a principal ⊕ secret pairing = one usable credential). A pool entry can
# exist with no binding: harvested usernames and candidate passwords are the
# raw feed the spray-matrix rule cross-joins. A single welded credentials row
# could never express "6 usernames × 5 passwords, pairings unknown".
SCHEMA_V12 = """
CREATE TABLE IF NOT EXISTS principals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    kind TEXT DEFAULT 'username',
    name TEXT NOT NULL,
    realm TEXT DEFAULT '',
    target_id INTEGER,
    source TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    UNIQUE(engagement_id, kind, name, realm)
);
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    kind TEXT DEFAULT 'password',
    value TEXT NOT NULL,
    realm TEXT DEFAULT '',
    target_id INTEGER,
    source TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    UNIQUE(engagement_id, kind, value, realm)
);
CREATE TABLE IF NOT EXISTS cred_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    principal_id INTEGER,
    secret_id INTEGER,
    target_id INTEGER,
    status TEXT DEFAULT 'candidate',
    source TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_principals_eng ON principals(engagement_id);
CREATE INDEX IF NOT EXISTS idx_secrets_eng ON secrets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_bindings_eng ON cred_bindings(engagement_id);
"""

# Vocabularies for the decomposed credential model.
PRINCIPAL_KINDS = {"username", "account", "email", "service-account", "key-id"}
SECRET_KINDS = {"password", "hash", "ntlm", "ticket", "private-key", "api-key", "token"}

FACT_POLARITIES = {"affirm", "absent"}

# The transferable join key. A CVE id joins to one product version; a mechanism
# joins across the corpus. Derived from 64 solved boxes — every entry below is a
# class that occurred at least once, and the pairs that motivated it are noted.
MECHANISMS = {
    # access
    "default-creds",            # ChurchCRM admin:changeme, ClipBucket, phpMyAdmin root/blank
    "weak-creds",               # AuthBy ftp admin:admin, PayDay
    "cred-reuse",               # Codo root=FatPanda123, bullyBox
    "setup-wizard-exposed",     # BarracudaDrive AND FuguHub — same bug, different product
    "auth-bypass",              # Next.js middleware, Camel header filter
    "self-signup-privileged",   # registration that lands you in an admin role
    # read / write primitives
    "path-traversal-read",      # Vendure, YesWiki, Vite, Argus DVR
    "path-traversal-write",     # Camaleon CMS
    "arbitrary-file-upload",    # FlatPress, docassemble, AquilaCMS module upload
    "source-disclosure",        # exposed .git (bullyBox), AdminPanel source leak
    "unauth-write",             # Redis root write (Wombo)
    # code execution
    "template-injection",       # Yeti Jinja2, changedetection.io, docassemble
    "code-eval",                # DocsGPT eval(), pdfmake, FUXA runscript, Langflow
    "command-injection",        # Interface /api/backup, clone-voice, find-exec, FOG
    "deserialization",          # BentoML pickle, rpcpy, SmarterMail .NET, TorrentPier
    "sql-injection",            # PMPro, ZoneMinder stacked + second-order
    "mass-assignment",          # Infilo deepMerge
    "config-pollution",         # Squirrelly
    "sandbox-escape",           # pyLoad js2py
    "unsafe-model-load",        # InvokeAI torch.load
    "unauth-api",               # Ray Jobs API, exposed admin API needing no auth
    "protocol-rce",             # MS17-010, CVE-2009-3103, OpenSMTPD, SaltStack
    "db-exec-primitive",        # Appsmith COPY FROM PROGRAM
    "memory-corruption",        # Precision format string + BOF
    "ssrf",
    "open-proxy",               # Squid pivot to internal WampServer
    # local privilege escalation
    "suid-binary",              # Astronaut SUID php7.4
    "sudo-misconfig",           # Cockpit tar wildcard, Pelican gcore, PayDay
    "capability-abuse",         # Levram python3.10 cap_setuid
    "kernel-lpe",               # PwnKit, Copy Fail, RDS
    "writable-service-path",    # Slort scheduled-task binary
    "scheduled-job-abuse",      # Exfiltrated root cron + ExifTool
    "token-privilege-abuse",    # SeImpersonate (Jacko), SeManageVolume (Access)
    "installer-elevation",      # AlwaysInstallElevated (Shenzi)
    "directory-secret-read",    # LAPS readable by low-priv user (Hutch)
    "ad-acl-abuse",             # RBCD / GenericAll on a DC computer object (Resourced)
    "privileged-group",         # 'disk' group -> debugfs full FS read (Extplorer)
    "library-path-hijack",      # sudo python module hijack via writable dir (Walla)
    "secret-in-memory",         # gcore of a password store
    "webshell-localhost",       # Nickel ws80.ps1 on 127.0.0.1
}

ENGAGEMENT_OUTCOMES = {"open", "solved", "parked", "abandoned"}
BINDING_STATUSES = {"candidate", "untested", "valid", "invalid"}
# how a piece of credential material entered the graph — drives confidence + how
# the board renders it. candidate = a guess (spray/wordlist); observed = seen in
# the wild (a username in a leak); recovered = pulled from a real source (config,
# dump, memory); operator = the human typed it in by hand.
CRED_ORIGINS = {"candidate", "observed", "recovered", "operator"}


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def use_data_dir(path) -> None:
    """Repoint storage at `path`.

    Tests need this because setting REDOPS_DATA inside a test is TOO LATE:
    running `python -m redops.parsers.fixtures.X` imports the redops package
    chain first (redops.parsers does `from .. import db`), which binds DATA_DIR
    at import time. Every fixture believed it was on a scratch database and was
    in fact writing to the operator's live one — 73 stray engagements before this
    was caught. connect() reads these globals per call, so rebinding is enough.
    """
    global DATA_DIR, DB_PATH, EVIDENCE_DIR, TRANSCRIPT_DIR
    DATA_DIR = Path(path)
    DB_PATH = DATA_DIR / "redops.db"
    EVIDENCE_DIR = DATA_DIR / "evidence"
    TRANSCRIPT_DIR = DATA_DIR / "transcript"
    os.environ["REDOPS_DATA"] = str(DATA_DIR)


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    TRANSCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    conn = connect()
    try:
        # WAL persists in the database header. Configure it once here rather
        # than reapplying a journal-mode pragma on every concurrent connection.
        conn.execute("PRAGMA journal_mode=WAL")
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        if ver < 1:
            conn.executescript(SCHEMA)
        if ver < 2:
            conn.executescript(SCHEMA_V2)
        if ver < 3:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(sitrep)").fetchall()]
            if "commander_intent" not in cols:
                conn.execute("ALTER TABLE sitrep ADD COLUMN commander_intent TEXT DEFAULT ''")
        if ver < 4:
            conn.executescript(SCHEMA_V4)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(opportunities)").fetchall()]
            if "detected" not in cols:
                conn.execute("ALTER TABLE opportunities ADD COLUMN detected INTEGER DEFAULT 0")
        if ver < 5:
            # engagement-scope evidence/tasks/findings so a fresh engagement
            # isolates cleanly and the report never leaks cross-engagement data.
            for tbl in ("evidence", "tasks", "findings"):
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({tbl})").fetchall()]
                if "engagement_id" not in cols:
                    conn.execute(f"ALTER TABLE {tbl} ADD COLUMN engagement_id INTEGER")
            # backfill via target -> engagement (and evidence via finding -> target)
            conn.execute("UPDATE findings SET engagement_id=("
                         "SELECT engagement_id FROM targets WHERE targets.id=findings.target_id) "
                         "WHERE engagement_id IS NULL AND target_id IS NOT NULL")
            conn.execute("UPDATE evidence SET engagement_id=("
                         "SELECT engagement_id FROM targets WHERE targets.id=evidence.target_id) "
                         "WHERE engagement_id IS NULL AND target_id IS NOT NULL")
            conn.execute("UPDATE evidence SET engagement_id=("
                         "SELECT t.engagement_id FROM findings f JOIN targets t ON t.id=f.target_id "
                         "WHERE f.id=evidence.finding_id) "
                         "WHERE engagement_id IS NULL AND finding_id IS NOT NULL")
            conn.commit()
        if ver < 6:
            # tool-capture: deterministic tools (nmap, …) run directly and dump
            # here; both operator and agent trigger runs and read results.
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS tool_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER, target_id INTEGER,
                tool TEXT NOT NULL, command TEXT NOT NULL,
                status TEXT DEFAULT 'running',
                output TEXT DEFAULT '', summary TEXT DEFAULT '',
                actor TEXT DEFAULT 'operator',
                started_at TEXT NOT NULL, finished_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_toolruns_tgt ON tool_runs(target_id);
            CREATE INDEX IF NOT EXISTS idx_toolruns_eng ON tool_runs(engagement_id);
            """)
            conn.commit()
        if ver < 7:
            # engagement-scope the live feed so a new engagement starts clean.
            cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
            if "engagement_id" not in cols:
                conn.execute("ALTER TABLE events ADD COLUMN engagement_id INTEGER")
            # backfill existing events via their target's engagement; the rest
            # collapse onto the newest engagement so history isn't orphaned.
            conn.execute("UPDATE events SET engagement_id=("
                         "SELECT engagement_id FROM targets WHERE targets.id=events.target_id) "
                         "WHERE engagement_id IS NULL AND target_id IS NOT NULL")
            newest = conn.execute("SELECT id FROM engagements ORDER BY id DESC LIMIT 1").fetchone()
            if newest:
                conn.execute("UPDATE events SET engagement_id=? WHERE engagement_id IS NULL",
                             (newest[0],))
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_eng ON events(engagement_id)")
            conn.commit()
        if ver < 8:
            # engagement lifecycle: archive (hide without deleting) vs delete.
            cols = [r[1] for r in conn.execute("PRAGMA table_info(engagements)").fetchall()]
            if "archived_at" not in cols:
                conn.execute("ALTER TABLE engagements ADD COLUMN archived_at TEXT")
            conn.commit()
        if ver < 9:
            # credentials become first-class: scope them to an engagement (so
            # target-less creds — bare tokens/API keys — stop leaking across
            # engagements and appear in the scoped report), and give them a
            # verification lifecycle (untested->valid|invalid, partial for
            # username-only/secret-only). base username/secret stay NOT NULL;
            # the absent half is stored '' and status carries the meaning.
            cols = [r[1] for r in conn.execute("PRAGMA table_info(credentials)").fetchall()]
            if "engagement_id" not in cols:
                conn.execute("ALTER TABLE credentials ADD COLUMN engagement_id INTEGER")
            if "status" not in cols:
                conn.execute("ALTER TABLE credentials ADD COLUMN status TEXT DEFAULT 'untested'")
            # backfill engagement via the credential's target
            conn.execute("UPDATE credentials SET engagement_id=("
                         "SELECT engagement_id FROM targets WHERE targets.id=credentials.target_id) "
                         "WHERE engagement_id IS NULL AND target_id IS NOT NULL")
            conn.commit()
        if ver < 10:
            conn.executescript(SCHEMA_V10)
            conn.commit()
        if ver < 11:
            # link an objective/flag to the proof that satisfied it: the target
            # it was captured on and/or an evidence item.
            cols = [r[1] for r in conn.execute("PRAGMA table_info(objectives)").fetchall()]
            if "target_id" not in cols:
                conn.execute("ALTER TABLE objectives ADD COLUMN target_id INTEGER")
            if "evidence_id" not in cols:
                conn.execute("ALTER TABLE objectives ADD COLUMN evidence_id INTEGER")
            conn.commit()
        if ver < 12:
            conn.executescript(SCHEMA_V12)
            # fold each welded credentials row into principal + secret + binding
            # so nothing already recorded is lost when the model splits.
            for c in conn.execute("SELECT * FROM credentials").fetchall():
                eng = c["engagement_id"]
                old_kind = (c["kind"] if "kind" in c.keys() else "password") or "password"
                pid = sid = None
                if (c["username"] or "").strip():
                    pkind = "service-account" if old_kind == "principal" else "username"
                    pid = add_principal(conn, eng, c["username"].strip(), kind=pkind,
                                        target_id=c["target_id"], source=c["source"] or "")
                if (c["secret"] or "").strip():
                    skind = old_kind if old_kind in SECRET_KINDS else "password"
                    sid = add_secret(conn, eng, c["secret"], kind=skind,
                                     target_id=c["target_id"], source=c["source"] or "")
                if pid or sid:
                    st = c["status"] if "status" in c.keys() and c["status"] else "untested"
                    st = "valid" if st == "valid" else ("invalid" if st == "invalid"
                                                        else ("untested" if (pid and sid) else "candidate"))
                    add_binding(conn, eng, principal_id=pid, secret_id=sid,
                                target_id=c["target_id"], status=st, source=c["source"] or "")
            conn.commit()
        if ver < 13:
            # tool runs become a shared, queued, prioritised work list: params
            # (typed options), a priority, and statuses that include queued
            # (agent, awaiting approval) / ready (approved or operator) / blocked
            # (failed the runner's scope check). Operator + agent enqueue into one
            # queue drained by a parallel worker pool.
            cols = [r[1] for r in conn.execute("PRAGMA table_info(tool_runs)").fetchall()]
            if "params_json" not in cols:
                conn.execute("ALTER TABLE tool_runs ADD COLUMN params_json TEXT DEFAULT '{}'")
            if "priority" not in cols:
                conn.execute("ALTER TABLE tool_runs ADD COLUMN priority INTEGER DEFAULT 5")
            # any run left mid-flight by the old code is terminal now
            conn.execute("UPDATE tool_runs SET status='done' WHERE status='running'")
            conn.commit()
        if ver < 14:
            # provenance + confidence on credential material: `origin` (how it
            # entered — a guess vs recovered loot) and the event that produced it,
            # so the board can answer "says who, from what?" and never render a
            # spray guess with the same weight as a recovered secret.
            for tbl in ("principals", "secrets"):
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({tbl})").fetchall()]
                if "origin" not in cols:
                    conn.execute(f"ALTER TABLE {tbl} ADD COLUMN origin TEXT DEFAULT 'observed'")
                if "source_event_id" not in cols:
                    conn.execute(f"ALTER TABLE {tbl} ADD COLUMN source_event_id INTEGER")
            # backfill origin from the free-text source: spray/wordlist => candidate
            # (a guess), config/dump/file/memory => recovered (real loot).
            conn.execute("UPDATE secrets SET origin='candidate' WHERE origin='observed' AND ("
                         "lower(source) LIKE '%spray%' OR lower(source) LIKE '%wordlist%' OR "
                         "lower(source) LIKE '%guess%' OR lower(source) LIKE '% list%')")
            conn.execute("UPDATE secrets SET origin='recovered' WHERE lower(source) LIKE '%config%' "
                         "OR lower(source) LIKE '%dump%' OR lower(source) LIKE '%memory%' "
                         "OR lower(source) LIKE '%disassembl%' OR lower(source) LIKE '%.txt%'")
            conn.commit()
        if ver < 15:
            # services stored nmap's structured output as ONE mashed `banner` blob,
            # discarding product/version/extrainfo/cpe as separate, queryable data.
            # Store what nmap already gives us, structured. (The dead `banner`
            # column is left behind on an already-migrated DB; the code no longer
            # touches it, and a fresh DB never has it.)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(services)").fetchall()]
            for col in ("state", "product", "version", "extrainfo", "cpe"):
                if col not in cols:
                    conn.execute(f"ALTER TABLE services ADD COLUMN {col} TEXT DEFAULT ''")
            conn.commit()
        if ver < 16:
            # observed connectivity: the net sensor (tcpdump) upserts one row per
            # (src,dst,dport,proto) flow it sees on the wire. Unlike heat/attribution
            # beams, these are ground truth. direction is relative to the operator
            # box: 'out' (you->target), 'in' (a callback — target->you, the
            # high-signal reverse-shell/exfil/side-effect case), or 'transit'.
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                src TEXT NOT NULL, sport INTEGER,
                dst TEXT NOT NULL, dport INTEGER,
                proto TEXT NOT NULL,
                direction TEXT DEFAULT 'transit',
                state TEXT DEFAULT 'active',
                target_id INTEGER,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                packets INTEGER DEFAULT 1, bytes INTEGER DEFAULT 0
            );
            -- Flow identity is the 3-tuple (src, dst, dport) + proto, NOT the
            -- full 5-tuple: `sport` (the ephemeral source port) is deliberately
            -- excluded so the scope map shows ONE edge per (host -> service),
            -- not 50 rows for 50 ephemeral connections to the same port. Accepted
            -- tradeoff: two CONCURRENT callbacks to the same local port from the
            -- same host share one row, so you cannot separately cite the second.
            -- This does not weaken the trust feature — one witnessed, citable
            -- callback per (target, local-port) already proves the effect fired;
            -- proving it fired *twice* is not the claim. Adding sport would fix the
            -- attribution edge at the cost of board clarity, a bad trade here.
            CREATE UNIQUE INDEX IF NOT EXISTS idx_flows_key
                ON flows(engagement_id, src, dst, dport, proto);
            CREATE INDEX IF NOT EXISTS idx_flows_eng ON flows(engagement_id);
            """)
            conn.commit()
        if ver < 23:
            # facts carried a binary `confidence` (low|confirmed) that conflated two
            # different things: "a source CLAIMED it" and "we CONFIRMED it". Replace
            # it with a real confirmation lifecycle — claimed (a source asserts it,
            # unverified) -> observed (we saw it ourselves: a scan, the wire, a probe
            # response) -> confirmed (verified or exploited). New facts start
            # `claimed`: guilty until proven. Migrate the old values: low => observed
            # (almost all `low` facts came from our own scans/wire), confirmed stays.
            cols = [r[1] for r in conn.execute("PRAGMA table_info(facts)").fetchall()]
            if "stage" not in cols:
                conn.execute("ALTER TABLE facts RENAME COLUMN confidence TO stage")
            conn.execute("UPDATE facts SET stage='observed' WHERE stage='low'")
            conn.commit()
        if ver < 23:
            # findings carried CVE + matched-location inside the description blob;
            # store them structured (nuclei et al. produce them as separate fields).
            cols = [r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
            for col in ("cve", "matched_at"):
                if col not in cols:
                    conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT DEFAULT ''")
            conn.commit()
        if ver < 23:
            # pump() capped concurrency by counting every 'running' row — but a
            # synchronous run_command row is 'running' too and nobody in the pool
            # is waiting on it, so one blocking curl shrank the pool. Mark the rows
            # the pool actually scheduled.
            cols = [r[1] for r in conn.execute("PRAGMA table_info(tool_runs)").fetchall()]
            if "pooled" not in cols:
                conn.execute("ALTER TABLE tool_runs ADD COLUMN pooled INTEGER DEFAULT 0")
            conn.commit()
        if ver < 23:
            # asset-level risk. You can't reliably classify an arbitrary shell
            # command, but you CAN classify an asset once ("exploiting Qdrant
            # :6333 crashes it"). Gating on the asset can't be dodged by
            # reaching for a different tool.  '' | 'fragile' | 'gated'
            cols = [r[1] for r in conn.execute("PRAGMA table_info(services)").fetchall()]
            if "risk" not in cols:
                conn.execute("ALTER TABLE services ADD COLUMN risk TEXT DEFAULT ''")
            conn.commit()
            # a port is ONE service. `POST /api/services` blind-inserted, so an
            # agent that registered a port on discovery and again after -sV left
            # two rows for the same port — one bare, one with product/version.
            # Collapse them (later non-empty values win) and make it impossible.
            dups = conn.execute(
                "SELECT target_id, port, proto FROM services "
                "GROUP BY target_id, port, proto HAVING COUNT(*) > 1").fetchall()
            for d in dups:
                key = (d["target_id"], d["port"], d["proto"])
                rs = conn.execute("SELECT * FROM services WHERE target_id=? AND port=? "
                                  "AND proto=? ORDER BY id", key).fetchall()
                merged = {}
                for r in rs:
                    for c in ("state", "name", "product", "version", "extrainfo", "cpe"):
                        if r[c]:
                            merged[c] = r[c]
                keep = rs[0]["id"]
                if merged:
                    conn.execute("UPDATE services SET " + ", ".join(f"{k}=?" for k in merged)
                                 + " WHERE id=?", (*merged.values(), keep))
                conn.execute("DELETE FROM services WHERE target_id=? AND port=? AND proto=? "
                             "AND id<>?", (*key, keep))
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_services_key "
                         "ON services(target_id, port, proto)")
            conn.commit()
        if ver < 23:
            # Verification events (v18). A finding's trust is DERIVED from these,
            # never typed: the same discipline redteam-db arrived at after a
            # source-only "LIVE shell" claim rode as an engagement's headline RCE
            # for days. The live-network analogue of a lab's RestartCount is the
            # observed callback — ground truth off the wire that an effect fired —
            # so `method='callback'` cites the flow row that proves it.
            #
            # `fingerprint` is the target's service banner set at verification
            # time. A re-scan that changes a banner invalidates proof taken
            # against the old one, which is what gives staleness an input signal
            # on a target you do not control.
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                finding_id INTEGER NOT NULL,
                result TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT 'manual',
                fingerprint TEXT DEFAULT '',
                flow_id INTEGER,
                event_id INTEGER,
                note TEXT DEFAULT '',
                agent TEXT DEFAULT 'user',
                stale INTEGER DEFAULT 0,
                ts TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_verif_finding ON verifications(finding_id);
            CREATE INDEX IF NOT EXISTS idx_verif_eng ON verifications(engagement_id);
            -- One flow proves ONE finding: 'which claim does this packet prove?'
            -- has a single answer. A flow_id already cited anywhere cannot be
            -- reused, so a single reverse shell can't be spread across N findings
            -- to manufacture N live-verifieds.
            CREATE UNIQUE INDEX IF NOT EXISTS idx_verif_flow
                ON verifications(flow_id) WHERE flow_id IS NOT NULL;
            """)
            for col, decl in (("confidence", "TEXT DEFAULT 'claimed'"),
                              ("stale", "INTEGER DEFAULT 0")):
                cols = [r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
                if col not in cols:
                    conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")
            # `opened` = we witnessed this inbound flow OPEN (saw the remote's SYN),
            # not joined it mid-stream. Only a witnessed open is trustworthy
            # callback proof: a capture that starts mid-connection sees our own
            # outbound traffic's return leg as an established 'inbound' flow (the
            # R6 false-callback), and that must not be citable as ground truth.
            fcols = [r[1] for r in conn.execute("PRAGMA table_info(flows)").fetchall()]
            if "opened" not in fcols:
                conn.execute("ALTER TABLE flows ADD COLUMN opened INTEGER DEFAULT 0")
            conn.commit()
        if ver < 23:
            # Background exec tasks: /api/exec?background=true spawns detached,
            # records pid + output file here, and the task is polled/stopped via
            # /api/exec_tasks/<id>. Long-running work (exploit loops, nc -lvp
            # listeners) survives past the foreground 600s cap.
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS exec_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER, target_id INTEGER,
                command TEXT NOT NULL, why TEXT DEFAULT '',
                pid INTEGER, status TEXT DEFAULT 'running',
                output_file TEXT DEFAULT '',
                exit_code INTEGER,
                started_at TEXT NOT NULL, finished_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_exectasks_eng ON exec_tasks(engagement_id);
            """)
            conn.commit()
        if ver < 24:
            # v24: three columns that make cross-engagement correlation possible.
            #
            # facts.polarity — absence as evidence. 92 real engagements produced
            # exactly ONE ruled-out fact out of 986, because the schema could
            # only say what is true. On a timeboxed box most of the discriminating
            # information is eliminative (version current, no default creds,
            # 403 not 500), and none of it was representable.
            #
            # findings.mechanism — the join key that transfers. `affects` points
            # at CVE ids, which join to exactly one product version. Two boxes in
            # the same corpus (BarracudaDrive, FuguHub) were the same bug — an
            # unauthenticated setup wizard — and nothing could see it.
            #
            # engagements.outcome — precedent needs to know how it ended.
            cols = [r[1] for r in conn.execute("PRAGMA table_info(facts)").fetchall()]
            if "polarity" not in cols:
                conn.execute("ALTER TABLE facts ADD COLUMN polarity TEXT DEFAULT 'affirm'")
                conn.execute("UPDATE facts SET polarity='affirm' WHERE polarity IS NULL")
            cols = [r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
            if "mechanism" not in cols:
                conn.execute("ALTER TABLE findings ADD COLUMN mechanism TEXT DEFAULT ''")
            cols = [r[1] for r in conn.execute("PRAGMA table_info(engagements)").fetchall()]
            for col, default in (("outcome", "'open'"), ("outcome_note", "''"),
                                 ("lab_time", "''")):
                if col not in cols:
                    conn.execute(f"ALTER TABLE engagements ADD COLUMN {col} TEXT DEFAULT {default}")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_polarity ON facts(polarity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_mech ON findings(mechanism)")
            conn.commit()
        if ver < SCHEMA_VERSION:
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            conn.commit()
    finally:
        conn.close()


def rows(conn: sqlite3.Connection, sql: str, params=()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def row(conn: sqlite3.Connection, sql: str, params=()) -> dict | None:
    r = conn.execute(sql, params).fetchone()
    return dict(r) if r else None


def insert(conn: sqlite3.Connection, table: str, data: dict) -> int:
    cols = ", ".join(data.keys())
    ph = ", ".join("?" for _ in data)
    cur = conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({ph})", tuple(data.values()))
    conn.commit()
    return cur.lastrowid


_SVC_FIELDS = ("state", "name", "product", "version", "extrainfo", "cpe")


def upsert_service(conn: sqlite3.Connection, target_id: int, port: int, proto: str,
                   fields: dict) -> int:
    """A port is ONE service row. Re-registering it (bare on discovery, then with
    product/version after -sV) REFRESHES that row instead of adding a second one.
    Empty values never overwrite what's already known — a later quick scan can't
    wipe the version a service scan established."""
    proto = proto or "tcp"
    r = row(conn, "SELECT id FROM services WHERE target_id=? AND port=? AND proto=?",
            (target_id, int(port), proto))
    upd = {k: v for k in _SVC_FIELDS if (v := fields.get(k, "")) not in ("", None)}
    if not r:
        return insert(conn, "services", {"target_id": target_id, "port": int(port),
                                         "proto": proto, "state": "open", **upd})
    if upd:
        conn.execute("UPDATE services SET " + ", ".join(f"{k}=?" for k in upd) + " WHERE id=?",
                     (*upd.values(), r["id"]))
        conn.commit()
    return r["id"]


def add_event(conn: sqlite3.Connection, source: str, kind: str, text: str,
              target_id=None, meta: dict | None = None, engagement_id=None) -> int:
    # Tag every event with an engagement so the live feed scopes to it. Callers
    # that know the engagement pass it; the rest fall back to the active one
    # (then newest), so a fresh engagement starts with an empty feed.
    if engagement_id is None and target_id is not None:
        r = conn.execute("SELECT engagement_id FROM targets WHERE id=?", (target_id,)).fetchone()
        if r:
            engagement_id = r["engagement_id"]
    if engagement_id is None:
        engagement_id = _active_engagement_id(conn)
    return insert(conn, "events", {
        "ts": now(), "source": source, "kind": kind, "target_id": target_id,
        "text": text, "meta_json": json.dumps(meta or {}), "engagement_id": engagement_id,
    })


def _active_engagement_id(conn: sqlite3.Connection):
    v = get_state(conn, "active_engagement", "")
    if v.isdigit() and conn.execute("SELECT 1 FROM engagements WHERE id=?", (int(v),)).fetchone():
        return int(v)
    r = conn.execute("SELECT id FROM engagements ORDER BY id DESC LIMIT 1").fetchone()
    return r["id"] if r else None


ENTITY_TYPES = {"host", "service", "user", "credential", "file", "privilege",
                "config", "endpoint", "network", "vuln",
                # decomposed credential material (v12): a principal is an
                # identity, a secret is auth material, a credential is a binding
                "principal", "secret",
                # AI-native targets (Modules 3-5: agents, models, RAG stores)
                "agent", "model", "rag-store", "collection", "token", "prompt",
                # application stack components (from stack_add)
                "framework",
                "other"}


def upsert_entity(conn: sqlite3.Connection, engagement_id, etype: str, name: str,
                  label: str = "", meta: dict | None = None) -> int:
    """Insert or refresh an entity; returns its id."""
    etype = etype if etype in ENTITY_TYPES else "other"
    r = conn.execute(
        "SELECT id, label, meta_json FROM entities WHERE engagement_id IS ? AND type=? AND name=?",
        (engagement_id, etype, name)).fetchone()
    if r:
        conn.execute("UPDATE entities SET last_seen=?, label=CASE WHEN ?='' THEN label ELSE ? END, "
                     "meta_json=CASE WHEN ?='{}' THEN meta_json ELSE ? END WHERE id=?",
                     (now(), label, label, json.dumps(meta or {}), json.dumps(meta or {}), r["id"]))
        conn.commit()
        return r["id"]
    return insert(conn, "entities", {
        "engagement_id": engagement_id, "type": etype, "name": name, "label": label,
        "meta_json": json.dumps(meta or {}), "first_seen": now(), "last_seen": now()})


FACT_SQL = """
SELECT f.*, s.name AS subject_name, s.type AS subject_type,
       o.name AS object_name, o.type AS object_type
FROM facts f
JOIN entities s ON s.id = f.subject_id
LEFT JOIN entities o ON o.id = f.object_id
"""


# the confirmation lifecycle: a fact only moves forward, never back.
STAGE_RANK = {"claimed": 0, "observed": 1, "confirmed": 2}


def add_fact(conn: sqlite3.Connection, engagement_id, subject_id: int, predicate: str,
             object_id=None, object_text: str = "", stage: str = "claimed",
             source: str = "agent", source_event_id=None, dedup: bool = True,
             polarity: str = "affirm") -> int:
    """Record an affirmative or checked-absent fact with a monotonic stage."""
    if polarity not in FACT_POLARITIES:
        raise ValueError(f"polarity must be one of {sorted(FACT_POLARITIES)}")
    if stage not in STAGE_RANK:
        raise ValueError(f"stage must be one of {sorted(STAGE_RANK)}")
    if dedup:
        r = conn.execute(
            "SELECT id, stage FROM facts WHERE engagement_id IS ? AND subject_id=? AND predicate=? "
            "AND object_id IS ? AND object_text=? AND status='active' AND polarity=?",
            (engagement_id, subject_id, predicate, object_id, object_text, polarity)).fetchone()
        if r:
            # re-asserting a known fact PROMOTES it: if this sighting is stronger
            # (a claim we've now observed, an observation we've now confirmed), the
            # fact advances. It never regresses.
            if STAGE_RANK.get(stage, 0) > STAGE_RANK.get(r["stage"], 0):
                conn.execute("UPDATE facts SET stage=?, source_event_id=COALESCE(?, source_event_id) "
                             "WHERE id=?", (stage, source_event_id, r["id"]))
                conn.commit()
            return r["id"]
    if polarity == "affirm":
        # we looked again and it IS there — retire the earlier absence
        conn.execute(
            "UPDATE facts SET status='ruled-out' WHERE engagement_id IS ? AND subject_id=? "
            "AND predicate=? AND object_id IS ? AND object_text=? AND polarity='absent' "
            "AND status='active'",
            (engagement_id, subject_id, predicate, object_id, object_text))
    return insert(conn, "facts", {
        "engagement_id": engagement_id, "subject_id": subject_id, "predicate": predicate,
        "object_id": object_id, "object_text": object_text, "stage": stage,
        "source": source, "source_event_id": source_event_id, "status": "active",
        "polarity": polarity, "ts": now()})


# --- decomposed credential material (v12) ---------------------------------
# principals (identities) and secrets (auth material) are independent pools;
# a binding pairs one of each (either side nullable). add_* dedupe so recording
# the same username/password twice is a no-op, and lists stay clean.

def add_principal(conn: sqlite3.Connection, engagement_id, name: str, kind: str = "username",
                  realm: str = "", target_id=None, source: str = "", notes: str = "",
                  origin: str = "observed", source_event_id=None) -> int:
    kind = kind if kind in PRINCIPAL_KINDS else "username"
    origin = origin if origin in CRED_ORIGINS else "observed"
    name = name.strip()
    conn.execute(
        "INSERT OR IGNORE INTO principals "
        "(engagement_id,kind,name,realm,target_id,source,notes,status,origin,source_event_id,created_at) "
        "VALUES (?,?,?,?,?,?,?, 'active', ?,?,?)",
        (engagement_id, kind, name, realm, target_id, source, notes, origin, source_event_id, now()))
    # backfill a home host/source if this row was first seen bare
    conn.execute("UPDATE principals SET target_id=COALESCE(target_id,?), "
                 "source=CASE WHEN source='' THEN ? ELSE source END, "
                 "source_event_id=COALESCE(source_event_id,?) "
                 "WHERE engagement_id IS ? AND kind=? AND name=? AND realm=?",
                 (target_id, source, source_event_id, engagement_id, kind, name, realm))
    conn.commit()
    r = conn.execute("SELECT id FROM principals WHERE engagement_id IS ? AND kind=? AND name=? "
                     "AND realm=?", (engagement_id, kind, name, realm)).fetchone()
    return r["id"]


def add_secret(conn: sqlite3.Connection, engagement_id, value: str, kind: str = "password",
               realm: str = "", target_id=None, source: str = "", notes: str = "",
               origin: str = "observed", source_event_id=None) -> int:
    kind = kind if kind in SECRET_KINDS else "password"
    origin = origin if origin in CRED_ORIGINS else "observed"
    conn.execute(
        "INSERT OR IGNORE INTO secrets "
        "(engagement_id,kind,value,realm,target_id,source,notes,status,origin,source_event_id,created_at) "
        "VALUES (?,?,?,?,?,?,?, 'active', ?,?,?)",
        (engagement_id, kind, value, realm, target_id, source, notes, origin, source_event_id, now()))
    conn.execute("UPDATE secrets SET target_id=COALESCE(target_id,?), "
                 "source=CASE WHEN source='' THEN ? ELSE source END, "
                 "source_event_id=COALESCE(source_event_id,?) "
                 "WHERE engagement_id IS ? AND kind=? AND value=? AND realm=?",
                 (target_id, source, source_event_id, engagement_id, kind, value, realm))
    conn.commit()
    r = conn.execute("SELECT id FROM secrets WHERE engagement_id IS ? AND kind=? AND value=? "
                     "AND realm=?", (engagement_id, kind, value, realm)).fetchone()
    return r["id"]


def add_binding(conn: sqlite3.Connection, engagement_id, principal_id=None, secret_id=None,
                target_id=None, status: str = "candidate", source: str = "") -> int:
    status = status if status in BINDING_STATUSES else "candidate"
    r = conn.execute(
        "SELECT id, status FROM cred_bindings WHERE engagement_id IS ? AND principal_id IS ? "
        "AND secret_id IS ? AND target_id IS ?",
        (engagement_id, principal_id, secret_id, target_id)).fetchone()
    if r:
        # advance status toward confirmation; never downgrade a valid binding
        rank = {"candidate": 0, "untested": 1, "invalid": 2, "valid": 3}
        if rank.get(status, 0) > rank.get(r["status"], 0):
            conn.execute("UPDATE cred_bindings SET status=? WHERE id=?", (status, r["id"]))
            conn.commit()
        return r["id"]
    return insert(conn, "cred_bindings", {
        "engagement_id": engagement_id, "principal_id": principal_id, "secret_id": secret_id,
        "target_id": target_id, "status": status, "source": source, "created_at": now()})


# compat + display shape: bindings joined to their principal/secret, rendered in
# the old {username, secret, kind, status, valid} columns so existing readers
# (board inspector, report, CLI) keep working over the decomposed store.
BINDING_VIEW_SQL = """
SELECT b.id, b.engagement_id, b.target_id, b.status, b.source,
       b.principal_id, b.secret_id,
       p.name AS username, p.kind AS principal_kind,
       s.value AS secret, s.kind AS secret_kind
FROM cred_bindings b
LEFT JOIN principals p ON p.id = b.principal_id
LEFT JOIN secrets s ON s.id = b.secret_id
"""


def binding_view(conn: sqlite3.Connection, where: str = "", params=()) -> list[dict]:
    out = []
    for r in rows(conn, BINDING_VIEW_SQL + where, params):
        r["username"] = r.get("username") or ""
        r["secret"] = r.get("secret") or ""
        # kind reflects the secret when present, else the principal kind
        r["kind"] = r.get("secret_kind") or r.get("principal_kind") or "principal"
        r["valid"] = 0 if r.get("status") == "invalid" else 1
        out.append(r)
    return out


def get_state(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    r = conn.execute("SELECT value FROM wiretail_state WHERE key=?", (key,)).fetchone()
    return r[0] if r else default


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO wiretail_state (key,value) VALUES (?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    conn.commit()


# --- runtime settings: DB override wins, else env, else default ------------
# Keeps toggles in the UI truthfully live (read here, not just at launch).
def setting(conn: sqlite3.Connection, key: str, env: str = "", default: str = "") -> str:
    r = conn.execute("SELECT value FROM wiretail_state WHERE key=?", (f"set:{key}",)).fetchone()
    if r is not None:
        return r[0]
    import os
    if env and os.environ.get(env) is not None:
        return os.environ.get(env, default)
    return default


def setting_bool(conn: sqlite3.Connection, key: str, env: str = "") -> bool:
    return setting(conn, key, env, "0").strip().lower() in ("1", "true", "yes", "on")


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    set_state(conn, f"set:{key}", value)


# --- verification: trust derived from evidence, not typed ------------------
#
# A finding's `confidence` is COMPUTED from its verification events and must
# never be written by hand. The failure this prevents is specific: a claim
# inherited from an earlier session reads as proven, nobody can see which
# evidence backed it, and it rides as the headline finding until someone
# re-tests it.
#
# `status` is deliberately NOT derived. Recording that a callback fired is an
# observation; deciding the finding is therefore refuted is a judgement, and
# folding the two together is how a validated state machine gets bypassed by
# its own evidence path. A finding whose status disagrees with its evidence is
# surfaced as contested rather than silently flipped.

VERIFICATION_RESULTS = ("reproduced", "not-reproduced", "partial", "errored")
VERIFICATION_METHODS = ("callback", "tool", "manual")
FINDING_CONFIDENCE = ("claimed", "observed", "live-verified")

# Finding lifecycle status. Deliberately small. `status` is the OPERATOR'S
# assessment; `confidence` is the DERIVED evidence grade — kept separate so the
# report can flag disagreement (a status that asserts more than the evidence
# backs) instead of letting a typed word read as proven.
FINDING_STATUSES = ("open", "confirmed", "exploited", "remediated",
                    "false-positive", "closed")
# Statuses whose word CLAIMS the effect worked. If one of these is set but
# `confidence` is not live-verified, the report marks the finding as asserting
# more than its evidence supports — closing the free-text escape hatch.
STATUS_ASSERTS_PROOF = ("confirmed", "exploited")
# A callback is trustworthy proof only if a handshake actually completed. A lone
# inbound SYN is backscatter or someone scanning us; a refused/closed flow is a
# probe that bounced. Only 'established' is "the effect reached back and talked".
CALLBACK_PROOF_STATES = ("established",)


def _fingerprint_map(conn: sqlite3.Connection, target_id) -> dict:
    """The target's observable service surface as {`port/proto`: [state, name,
    product, version]}. A structured map, not a single hash, so staleness can ask
    the right question — 'did a service I relied on change or vanish?' — instead
    of 'did anything about this host change?' (which additive port discovery
    trips). `state` is included so an open->closed transition counts as drift."""
    if target_id is None:
        return {}
    rs = conn.execute(
        "SELECT port, proto, state, name, product, version FROM services "
        "WHERE target_id=? ORDER BY port, proto", (target_id,)).fetchall()
    return {f"{r['port']}/{r['proto']}": [r["state"] or "", r["name"] or "",
            r["product"] or "", r["version"] or ""] for r in rs}


def target_fingerprint(conn: sqlite3.Connection, target_id) -> str:
    """The service surface as a canonical JSON string, stored on each
    verification. This is the live-network stand-in for a lab build fingerprint:
    we cannot enumerate a target we do not own, but we can record what it was
    answering with when the proof was taken."""
    m = _fingerprint_map(conn, target_id)
    return json.dumps(m, sort_keys=True) if m else ""


def _fingerprint_drifted(old_fp: str, current: dict) -> bool:
    """Did a service the proof relied on change or disappear? Compared at two
    levels, both 'only what we knew then':

    - keys: only ports present in the OLD fingerprint are checked, so discovering
      a NEW port is not drift (that is better coverage, B4).
    - fields: within a port, only fields that were NON-EMPTY at proof time are
      checked, so a later `-sV` LEARNING a banner we didn't have is not drift
      (bare register -> verify -> version scan is the normal workflow, N1). A
      field that had a value and changed, or a port now gone, is drift.
    """
    # Empty stored fingerprint = no service surface was known when the proof was
    # taken (e.g. a callback-verified finding on a target with no registered
    # services). There is nothing to drift against, so it never goes stale — the
    # callback flow, not the banner, was the proof. Known follow-up: a finding
    # verified manual/tool against a bare target likewise can't stale; that rests
    # on operator attestation, same as any manual result.
    if not old_fp:
        return False
    try:
        old = json.loads(old_fp)
    except (json.JSONDecodeError, TypeError):
        return False
    for port, ovals in old.items():
        cvals = current.get(port)
        if cvals is None:
            return True                      # a port we relied on is gone
        # element-wise: an old field that was known ("") -> different now is drift;
        # an old field that was blank is something we simply hadn't learned yet.
        for i, ov in enumerate(ovals):
            if ov != "" and (i >= len(cvals) or cvals[i] != ov):
                return True
    return False


def recompute_finding_trust(conn: sqlite3.Connection, finding_id: int) -> dict:
    """Derive trust from this finding's verification events. LATEST meaningful
    event wins — a claim whose effect stopped working must not keep the grade an
    earlier success gave it (that was the order-insensitivity bug).

    live-verified — the most recent real test reproduced, on the current surface.
    observed      — evidence exists but the latest is stale, partial, or negative.
    claimed       — no real evidence, whatever anyone typed.

    `contested` — the latest real result is `not-reproduced`: the claim was fired
    and did not fire. Surfaced, never silently applied to status, because
    'the effect failed' is an observation and 'the finding is wrong' is a
    judgement for the operator.
    """
    f = row(conn, "SELECT target_id FROM findings WHERE id=?", (finding_id,))
    current = _fingerprint_map(conn, f["target_id"]) if f else {}
    vs = rows(conn, "SELECT * FROM verifications WHERE finding_id=? ORDER BY ts DESC, id DESC",
              (finding_id,))
    # Staleness is derived LIVE against the current surface, not read from a flag
    # frozen at drift time — so a service that comes back (a filtered/flaky scan,
    # then a clean one) HEALS instead of being permanently demoted. Refresh each
    # reproduced row's stored flag for display consistency (report/UI read it).
    for v in vs:
        if v["result"] == "reproduced":
            s = 1 if _fingerprint_drifted(v["fingerprint"], current) else 0
            if s != v["stale"]:
                conn.execute("UPDATE verifications SET stale=? WHERE id=?", (s, v["id"]))
                v["stale"] = s
    # 'errored' is a test that did not run — not evidence for or against.
    meaningful = [v for v in vs if v["result"] != "errored"]
    contested = False
    if not meaningful:
        conf, stale = "claimed", 0
    else:
        latest = meaningful[0]
        if latest["result"] == "reproduced":
            conf, stale = ("observed", 1) if latest["stale"] else ("live-verified", 0)
        else:                                   # not-reproduced or partial is the last word
            conf, stale = "observed", 0
            contested = latest["result"] == "not-reproduced"
    conn.execute("UPDATE findings SET confidence=?, stale=? WHERE id=?", (conf, stale, finding_id))
    conn.commit()
    return {"confidence": conf, "stale": bool(stale), "contested": contested,
            "verifications": len(vs)}


def add_verification(conn: sqlite3.Connection, finding_id: int, result: str,
                     method: str = "manual", note: str = "", agent: str = "user",
                     flow_id=None, event_id=None, engagement_id=None) -> dict:
    """Record one verification event against a finding and re-derive its trust.

    A `callback` cites an observed inbound flow as out-of-band proof, so it MUST
    carry a `flow_id`, that flow must belong to the finding's target, and it must
    have completed a handshake. Those checks are what stop 'callback' from being a
    magic word that grants live-verified with no packet behind it."""
    if result not in VERIFICATION_RESULTS:
        raise ValueError(f"result must be one of {', '.join(VERIFICATION_RESULTS)}")
    if method not in VERIFICATION_METHODS:
        raise ValueError(f"method must be one of {', '.join(VERIFICATION_METHODS)}")
    f = row(conn, "SELECT * FROM findings WHERE id=?", (finding_id,))
    if not f:
        raise ValueError(f"finding {finding_id} not found")
    if engagement_id is None:
        engagement_id = f["engagement_id"]
    if method == "callback":
        if flow_id is None:
            raise ValueError("method 'callback' must cite a flow_id — the observed "
                             "inbound connection that is the proof")
        fl = row(conn, "SELECT * FROM flows WHERE id=?", (flow_id,))
        if not fl:
            raise ValueError(f"flow {flow_id} not found")
        if fl["direction"] != "in":
            raise ValueError(f"flow {flow_id} is direction={fl['direction']}, not an "
                             "inbound callback — only a connection the target opened to "
                             "you is out-of-band proof")
        if fl["state"] not in CALLBACK_PROOF_STATES:
            raise ValueError(f"flow {flow_id} is state={fl['state']} — only an established "
                             "callback proves the effect fired (a lone SYN or a refused/"
                             "closed probe does not)")
        if not fl["opened"]:
            raise ValueError(f"flow {flow_id}'s open was not witnessed (capture likely "
                             "started mid-connection), so it may be the return leg of your "
                             "own outbound traffic, not a callback. Confirm it yourself and "
                             "record method='manual' with evidence, rather than citing the "
                             "wire as ground truth.")
        if f["target_id"] is None or fl["target_id"] != f["target_id"]:
            raise ValueError(f"flow {flow_id} is attributed to a different host than finding "
                             f"{finding_id} — a callback from one box does not prove a claim "
                             "on another")
        if fl["engagement_id"] != engagement_id:
            raise ValueError(f"flow {flow_id} belongs to a different engagement")
    if event_id is not None:
        ev = row(conn, "SELECT id, target_id FROM events WHERE id=?", (event_id,))
        if not ev:
            raise ValueError(f"event {event_id} not found")
        if f["target_id"] is not None and ev["target_id"] not in (None, f["target_id"]):
            raise ValueError(f"event {event_id} is attributed to a different host than "
                             f"finding {finding_id}")
    vid = insert(conn, "verifications", {
        "engagement_id": engagement_id, "finding_id": finding_id, "result": result,
        "method": method, "fingerprint": target_fingerprint(conn, f["target_id"]),
        "flow_id": flow_id, "event_id": event_id, "note": note, "agent": agent,
        "stale": 0, "ts": now()})
    # Concurrency (R7): the fingerprint read above and this recompute are not one
    # transaction, but they need not be — recompute derives staleness LIVE against
    # the current surface, so a scan that lands mid-verify simply produces the
    # CORRECT result (born stale if the surface it was proven against is already
    # gone) and heals if it returns. And every surface mutation (scanner and API
    # both) re-runs staleness, so no finding is left stuck against a changed
    # surface. Concurrent recomputes converge — they read the same rows + surface.
    trust = recompute_finding_trust(conn, finding_id)
    return {"id": vid, "finding_id": finding_id, "result": result, "method": method,
            "flow_id": flow_id, **trust}


def refresh_target_staleness(conn: sqlite3.Connection, target_id) -> list[int]:
    """A target's service surface changed — expire proof that relied on a service
    which has since changed or vanished, and re-derive the affected findings.
    Returns the finding ids whose grade actually moved, so callers log the
    demotion rather than have a claim quietly change grade under the operator.

    Compares per-service (see `_fingerprint_drifted`): additive discovery of a new
    port does NOT stale existing proof, but a changed banner or a dead service
    does. This runs on EVERY path that persists a service — the API and the nmap
    tool runner both — so drift is caught wherever the re-scan came from."""
    if target_id is None:
        return []
    if not _fingerprint_map(conn, target_id):
        return []      # nothing observed now; no basis to judge drift
    # recompute derives staleness live against the current surface (and heals it
    # when a service returns), so this just re-derives every finding on the target
    # and reports which ones actually changed grade — for the demotion feed.
    moved = []
    for r in rows(conn, "SELECT id, confidence FROM findings WHERE target_id=?", (target_id,)):
        after = recompute_finding_trust(conn, r["id"])
        if r["confidence"] != after["confidence"]:
            moved.append(r["id"])
    return moved


def pending_callbacks(conn: sqlite3.Connection, engagement_id) -> list[dict]:
    """Observed inbound flows not yet cited as proof of anything. This is a
    QUEUE, not an inference: which claim a packet proves is a judgement, and
    guessing it is the overclaim that `refuted` exists to catch. Where exactly
    one open finding sits on the same target it is offered as a suggestion."""
    flows = rows(conn,
        "SELECT f.*, t.ip AS target_ip, t.hostname FROM flows f "
        "LEFT JOIN targets t ON t.id=f.target_id "
        "WHERE f.engagement_id=? AND f.direction='in' AND f.opened=1 "
        "AND f.target_id IS NOT NULL "
        "AND f.id NOT IN (SELECT flow_id FROM verifications WHERE flow_id IS NOT NULL) "
        "ORDER BY f.last_seen DESC LIMIT 100", (engagement_id,))
    out = []
    for fl in flows:
        cands = rows(conn, "SELECT id, title, status, confidence FROM findings "
                     "WHERE target_id=? AND status NOT IN ('closed','refuted') ORDER BY id",
                     (fl["target_id"],)) if fl["target_id"] else []
        out.append({**fl, "candidates": cands,
                    "suggested_finding_id": cands[0]["id"] if len(cands) == 1 else None})
    return out


# --- engagement lifecycle: archive / reset / delete ------------------------
# Every table scoped to an engagement, and how it hangs off the engagement.
_ENG_DIRECT = ("targets", "findings", "evidence", "objectives", "tasks",
               "entities", "facts", "opportunities", "sitrep", "leads",
               "tool_runs", "events", "payloads", "detection_rules", "poison",
               "principals", "secrets", "cred_bindings",
               # `flows` escaped this list when it was added in v16, so reset and
               # delete reported success while leaving every captured flow —
               # operator IPs, target IPs, callback records — behind with
               # dangling target_ids. `test_purge_completeness` now enumerates
               # sqlite_master and fails if a scoped table is missing here, so a
               # new table cannot repeat it.
               # `exec_tasks` (v19) repeated the same miss: reset left every
               # command the agent ran, with dangling target_ids. The output
               # files it points at live under the per-engagement work dir and
               # are the caller's to clean — the rows are ours.
               "flows", "verifications", "exec_tasks")


def _purge_engagement_data(conn: sqlite3.Connection, eid: int) -> None:
    """Delete everything scoped to an engagement, keeping the row itself.
    Children (via target/finding/opportunity) go first, then direct tables."""
    # services & credentials hang off targets
    conn.execute("DELETE FROM services WHERE target_id IN "
                 "(SELECT id FROM targets WHERE engagement_id=?)", (eid,))
    conn.execute("DELETE FROM credentials WHERE target_id IN "
                 "(SELECT id FROM targets WHERE engagement_id=?)", (eid,))
    # target-less creds (bare tokens) are scoped only by engagement_id
    conn.execute("DELETE FROM credentials WHERE engagement_id=?", (eid,))
    # opportunity_facts hangs off opportunities
    conn.execute("DELETE FROM opportunity_facts WHERE opportunity_id IN "
                 "(SELECT id FROM opportunities WHERE engagement_id=?)", (eid,))
    # evidence may predate engagement scoping — also sweep via finding/target
    conn.execute("DELETE FROM evidence WHERE finding_id IN "
                 "(SELECT id FROM findings WHERE engagement_id=?)", (eid,))
    conn.execute("DELETE FROM evidence WHERE target_id IN "
                 "(SELECT id FROM targets WHERE engagement_id=?)", (eid,))
    for tbl in _ENG_DIRECT:
        conn.execute(f"DELETE FROM {tbl} WHERE engagement_id=?", (eid,))
    conn.commit()


def reset_engagement(conn: sqlite3.Connection, eid: int) -> None:
    """Wipe an engagement's data but keep the (renamed/scoped) engagement."""
    _purge_engagement_data(conn, eid)


def delete_engagement(conn: sqlite3.Connection, eid: int) -> None:
    """Purge the engagement's data and remove the engagement row."""
    _purge_engagement_data(conn, eid)
    conn.execute("DELETE FROM engagements WHERE id=?", (eid,))
    conn.commit()


def set_archived(conn: sqlite3.Connection, eid: int, archived: bool) -> None:
    conn.execute("UPDATE engagements SET archived_at=? WHERE id=?",
                 (now() if archived else None, eid))
    conn.commit()


def engagement_counts(conn: sqlite3.Connection, eid: int) -> dict:
    q = lambda sql: conn.execute(sql, (eid,)).fetchone()[0]
    return {
        "targets": q("SELECT count(*) FROM targets WHERE engagement_id=?"),
        "facts":   q("SELECT count(*) FROM facts WHERE engagement_id=?"),
        "events":  q("SELECT count(*) FROM events WHERE engagement_id=?"),
        "findings": q("SELECT count(*) FROM findings WHERE engagement_id=?"),
        "tool_runs": q("SELECT count(*) FROM tool_runs WHERE engagement_id=?"),
    }


# --- precedent: the cross-engagement join ----------------------------------
#
# Every rule in correlate.py is scoped to one engagement. On a corpus of
# timeboxed single-box runs there is nothing to join inside one — median 5 facts,
# one bug, one request. The structure is BETWEEN engagements: same agent, same
# prompt, same budget, same toolchain, 92 targets, known outcomes. That is a
# controlled experiment, and precedent is the only thing that reads it.
#
# Deterministic set overlap with IDF weighting. No model, no embedding: a
# precedent that cannot be explained is one an operator cannot argue with, and
# the whole design suggests rather than declares.

_COMMON_PORTS = {22, 80, 443}


def _idf(doc_freq: dict, n_docs: int) -> dict:
    """Rarer signals discriminate. Port 80 is on every box and means nothing."""
    import math
    return {k: math.log((n_docs + 1) / (v + 0.5)) for k, v in doc_freq.items()}


def engagement_signature(conn: sqlite3.Connection, eid: int) -> dict:
    """What this engagement looks like, in terms that can match another one."""
    mech = {r["mechanism"] for r in rows(
        conn, "SELECT DISTINCT mechanism FROM findings WHERE engagement_id=? "
              "AND mechanism<>''", (eid,))}
    svc = rows(conn, "SELECT s.port, s.name, s.product FROM services s "
                     "JOIN targets t ON t.id=s.target_id WHERE t.engagement_id=?", (eid,))
    ports = {r["port"] for r in svc}
    products = set()
    for r in svc:
        for tok in (r["product"] or "").lower().split():
            tok = tok.strip("(),/")
            if len(tok) > 2 and not tok.replace(".", "").isdigit():
                products.add(tok)
        if (r["name"] or "").strip():
            products.add(r["name"].strip().lower())
    absent = {f"{r['predicate']}:{(r['object_text'] or '')[:40]}" for r in rows(
        conn, "SELECT predicate, object_text FROM facts WHERE engagement_id=? "
              "AND polarity='absent' AND status='active'", (eid,))}
    return {"mechanisms": mech, "ports": ports, "products": products, "absent": absent}


# mechanism is the key that transfers, so it outweighs everything else; an
# absence match is weak alone but distinctive in combination.
_FIELD_WEIGHT = {"mechanisms": 6.0, "products": 3.0, "absent": 2.0, "ports": 1.0}


def precedent(conn: sqlite3.Connection, eid: int, limit: int = 5,
              include_open: bool = False, sig: dict | None = None) -> list[dict]:
    """Past engagements that look like this one, most similar first.

    Returns the matched terms alongside the score so the ranking is auditable —
    an unexplained precedent is worse than none, because it anchors the agent
    the way a recalled writeup anchored the OpenSMTPD run onto a patched CVE."""
    # `sig` lets a caller substitute a partial view — eval_precedent.py passes
    # the minute-three signature (ports/products only) to ask what this would
    # have said before the box was solved.
    me = sig if sig is not None else engagement_signature(conn, eid)
    if not any(me.values()):
        return []

    others = [r for r in rows(
        conn, "SELECT id, name, outcome, outcome_note, lab_time FROM engagements "
              "WHERE id<>? AND archived_at IS NULL", (eid,))]
    if not include_open:
        others = [r for r in others if (r["outcome"] or "open") != "open"] or others

    sigs = {r["id"]: engagement_signature(conn, r["id"]) for r in others}
    n = len(sigs) or 1
    idf = {}
    for field in _FIELD_WEIGHT:
        df: dict = {}
        for s in sigs.values():
            for term in s[field]:
                df[term] = df.get(term, 0) + 1
        idf[field] = _idf(df, n)

    out = []
    for r in others:
        s = sigs[r["id"]]
        score, matched = 0.0, {}
        for field, w in _FIELD_WEIGHT.items():
            shared = me[field] & s[field]
            if field == "ports":
                shared = {p for p in shared if p not in _COMMON_PORTS}
            if not shared:
                continue
            matched[field] = sorted(shared, key=str)
            score += w * sum(idf[field].get(t, 1.0) for t in shared)
        if score <= 0:
            continue
        finds = rows(conn, "SELECT title, mechanism, severity FROM findings "
                           "WHERE engagement_id=? AND mechanism<>'' ORDER BY id", (r["id"],))
        out.append({
            "engagement_id": r["id"], "name": r["name"],
            "outcome": r["outcome"] or "open", "outcome_note": r["outcome_note"] or "",
            "lab_time": r["lab_time"] or "", "score": round(score, 2),
            "matched": matched,
            "findings": [f for f in finds if f["mechanism"] in matched.get("mechanisms", [])]
                        or finds[:3],
        })
    out.sort(key=lambda d: -d["score"])
    return out[:limit]
