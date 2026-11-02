"""RedOps CLI - thin client over the REST API (stdlib urllib only).

Base URL: env REDOPS_URL, default http://127.0.0.1:9100
Shared HTTP helpers live in redops/client.py.
"""

import os
import argparse
import json
import sys

from .client import (ApiError, default_engagement, find_target, guess_type,
                     post_multipart, req)


def show(row) -> None:
    print(json.dumps(row, indent=None, ensure_ascii=False))


def main(argv=None) -> int:
    # the CLI is the operator's own hand — the agent drives RedOps through MCP,
    # never through this entrypoint.
    os.environ.setdefault("REDOPS_OPERATOR", "1")
    p = argparse.ArgumentParser(prog="redops", description="RedOps CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("log", help="log an agent event")
    sp.add_argument("text")
    sp.add_argument("--kind", default="note", choices=["reasoning", "action", "note", "objective", "error"])
    sp.add_argument("--target", help="target IP to link")

    sp = sub.add_parser("target", help="manage targets")
    tsub = sp.add_subparsers(dest="sub", required=True)
    ta = tsub.add_parser("add")
    ta.add_argument("ip")
    ta.add_argument("--hostname", default="")
    ta.add_argument("--os", default="")
    ta.add_argument("--role", default="")
    ta.add_argument("--status", default="unidentified",
                    choices=["unidentified", "identified", "foothold", "rooted", "flagged"])
    ta.add_argument("--engagement", type=int, default=None)
    tsub.add_parser("list")

    sp = sub.add_parser("svc", help="manage services")
    ssub = sp.add_subparsers(dest="sub", required=True)
    sa = ssub.add_parser("add")
    sa.add_argument("ip")
    sa.add_argument("port", type=int)
    sa.add_argument("proto", default="tcp")
    sa.add_argument("--name", default="")
    sa.add_argument("--product", default="")
    sa.add_argument("--version", default="")
    sa.add_argument("--info", default="", help="extrainfo (e.g. 'protocol 2.0')")

    _CRED_KINDS = ["password", "hash", "ticket", "key", "token", "api-key", "principal"]
    _CRED_STATUSES = ["untested", "valid", "invalid", "partial"]
    sp = sub.add_parser("cred", help="manage credentials")
    csub = sp.add_subparsers(dest="sub", required=True)
    ca = csub.add_parser("add", help="record a credential (partial ok: give username OR secret)")
    ca.add_argument("username", nargs="?", default="",
                    help="username (omit for a bare token/key: cred add '' <secret> --kind token)")
    ca.add_argument("secret", nargs="?", default="", help="secret/hash/token (omit if unknown yet)")
    ca.add_argument("--target", help="target IP")
    ca.add_argument("--kind", default="password", choices=_CRED_KINDS)
    ca.add_argument("--status", default=None, choices=_CRED_STATUSES,
                    help="verification state (default: untested, or partial if half-known)")
    ca.add_argument("--source", default="")
    cl = csub.add_parser("list", help="list credentials")
    cl.add_argument("--target", help="target IP")
    cl.add_argument("--engagement", type=int)
    cst = csub.add_parser("set", help="update a credential by id")
    cst.add_argument("id", type=int)
    cst.add_argument("--username")
    cst.add_argument("--secret")
    cst.add_argument("--kind", choices=_CRED_KINDS)
    cst.add_argument("--status", choices=_CRED_STATUSES)
    cst.add_argument("--source")
    cst.add_argument("--valid", type=int, choices=[0, 1])

    # decomposed credential material: pools you feed independently, cross-joined
    # by the spray-matrix rule. `cred add` is still the one-shot sugar.
    _P_KINDS = ["username", "account", "email", "service-account", "key-id"]
    _S_KINDS = ["password", "hash", "ntlm", "ticket", "private-key", "api-key", "token"]
    pp = sub.add_parser("principal", help="identities (usernames/accounts) — no secret yet")
    ppsub = pp.add_subparsers(dest="sub", required=True)
    pa = ppsub.add_parser("add", help="record an identity (harvested username, account, key-id)")
    pa.add_argument("name")
    pa.add_argument("--kind", default="username", choices=_P_KINDS)
    pa.add_argument("--realm", default="", help="AD domain / app scope (groups the spray matrix)")
    pa.add_argument("--target", help="host it was found on")
    pa.add_argument("--source", default="")
    pl = ppsub.add_parser("list", help="list identities")
    pl.add_argument("--engagement", type=int)

    xp = sub.add_parser("secret", help="auth material (passwords/hashes/keys/tokens) — no owner yet")
    xpsub = xp.add_subparsers(dest="sub", required=True)
    xa = xpsub.add_parser("add", help="record auth material (candidate password, hash, key, token)")
    xa.add_argument("value")
    xa.add_argument("--kind", default="password", choices=_S_KINDS)
    xa.add_argument("--realm", default="", help="scope (groups the spray matrix)")
    xa.add_argument("--target", help="host it was found on")
    xa.add_argument("--source", default="")
    xl = xpsub.add_parser("list", help="list auth material")
    xl.add_argument("--engagement", type=int)

    bp = sub.add_parser("binding", help="pair a principal with a secret (a usable credential)")
    bpsub = bp.add_subparsers(dest="sub", required=True)
    ba = bpsub.add_parser("add", help="assert a principal×secret pairing (e.g. a confirmed spray hit)")
    ba.add_argument("--principal", type=int, help="principal id")
    ba.add_argument("--secret", type=int, help="secret id")
    ba.add_argument("--target", help="host the pairing is valid on")
    ba.add_argument("--status", default="untested",
                    choices=["candidate", "untested", "valid", "invalid"])
    ba.add_argument("--source", default="")
    bl = bpsub.add_parser("list", help="list bindings (usable credentials)")
    bl.add_argument("--engagement", type=int)

    sp = sub.add_parser("payload", help="injection-payload library")
    psub = sp.add_subparsers(dest="sub", required=True)
    pa = psub.add_parser("add")
    pa.add_argument("technique")
    pa.add_argument("--body", default="")
    pa.add_argument("--model", default="", help="target model")
    pa.add_argument("--guardrail", default="", help="guardrail defeated")
    pa.add_argument("--outcome", default="untried",
                    choices=["untried", "worked", "failed", "blocked"])
    pa.add_argument("--target-ref", default="")
    psub.add_parser("list")

    sp = sub.add_parser("rule", help="detection-rule catalog")
    rsub = sp.add_subparsers(dest="sub", required=True)
    ra = rsub.add_parser("add")
    ra.add_argument("name")
    ra.add_argument("--source", default="", help="elk|phoenix|...")
    ra.add_argument("--match", default="", help="match mechanism")
    ra.add_argument("--blind", default="", help="blind spot")
    ra.add_argument("--evade", default="", help="evasion")
    ra.add_argument("--fired", action="store_true")
    rsub.add_parser("list")

    sp = sub.add_parser("poison", help="planted-poison provenance + cleanup")
    posub = sp.add_subparsers(dest="sub", required=True)
    poa = posub.add_parser("add")
    poa.add_argument("location")
    poa.add_argument("--store", default="other",
                     choices=["kb-db", "rag", "minio", "agent-card", "registry", "file", "other"])
    poa.add_argument("--verify", default="", help="how to verify it's live")
    poa.add_argument("--payload", type=int, help="linked payload id")
    pos = posub.add_parser("set")
    pos.add_argument("id", type=int)
    pos.add_argument("--cleanup", type=int, choices=[0, 1])
    pos.add_argument("--live", type=int, choices=[0, 1])
    posub.add_parser("list")

    sp = sub.add_parser("objective", help="objectives / flags (with proof links)")
    obsub = sp.add_subparsers(dest="sub", required=True)
    oba = obsub.add_parser("add")
    oba.add_argument("text")
    oba.add_argument("--value", default="", help="flag/answer value")
    oba.add_argument("--target", help="target IP the proof lives on")
    oba.add_argument("--engagement", type=int)
    obsub.add_parser("list")
    obd = obsub.add_parser("done")
    obd.add_argument("id", type=int)
    obd.add_argument("--value", help="set the captured value too")
    obl = obsub.add_parser("link")
    obl.add_argument("id", type=int)
    obl.add_argument("--target", help="target IP")
    obl.add_argument("--evidence", type=int, help="evidence id")
    obl.add_argument("--value")

    sp = sub.add_parser("finding", help="manage findings")
    fsub = sp.add_subparsers(dest="sub", required=True)
    fa = fsub.add_parser("add")
    fa.add_argument("--target", help="target IP")
    fa.add_argument("--title", required=True)
    fa.add_argument("--sev", default="info", choices=["info", "low", "medium", "high", "critical"])
    fa.add_argument("--desc", default="")

    sp = sub.add_parser("evidence", help="manage evidence")
    esub = sp.add_subparsers(dest="sub", required=True)
    ea = esub.add_parser("add")
    ea.add_argument("finding_id", type=int)
    ea.add_argument("file")
    ea.add_argument("--caption", default="")

    sp = sub.add_parser("tasks", help="list tasks")
    sp.add_argument("--pending", action="store_true")

    sp = sub.add_parser("task", help="task ops")
    ksub = sp.add_subparsers(dest="sub", required=True)
    kd = ksub.add_parser("done")
    kd.add_argument("id", type=int)

    sp = sub.add_parser("engage", help="manage engagements")
    gsub = sp.add_subparsers(dest="sub", required=True)
    ga = gsub.add_parser("add")
    ga.add_argument("name")
    ga.add_argument("--scope", default="")
    ga.add_argument("--notes", default="")
    gsub.add_parser("list")

    sp = sub.add_parser("export", help="export engagement report to stdout")
    sp.add_argument("engagement_id", type=int)
    sp.add_argument("--fmt", default="md", choices=["md", "html"])

    sp = sub.add_parser("fact", help="manage intel facts")
    fcsub = sp.add_subparsers(dest="sub", required=True)
    fa2 = fcsub.add_parser("add", help="add a fact (entities auto-upserted)")
    fa2.add_argument("subject")
    fa2.add_argument("predicate")
    fa2.add_argument("object")
    fa2.add_argument("--stype", default=None, help="subject entity type")
    fa2.add_argument("--otype", default=None, help="object entity type")
    fa2.add_argument("--stage", default="claimed", choices=["claimed", "observed", "confirmed"])
    fa2.add_argument("--engagement", type=int, default=None)
    fab = fcsub.add_parser("absent", help="record that something was CHECKED and is NOT there")
    fab.add_argument("subject")
    fab.add_argument("predicate")
    fab.add_argument("object")
    fab.add_argument("--stype", default=None, help="subject entity type")
    fab.add_argument("--otype", default=None, help="object entity type")
    fab.add_argument("--engagement", type=int, default=None)
    fl = fcsub.add_parser("list")
    fl.add_argument("--status", default=None, choices=["active", "ruled-out"])
    fl.add_argument("--polarity", default=None, choices=["affirm", "absent"])
    fl.add_argument("--engagement", type=int, default=None)
    fo = fcsub.add_parser("out", help="rule out a fact (dead end)")
    fo.add_argument("id", type=int)

    sp = sub.add_parser("mech", help="mechanism vocabulary (the cross-box join key)")
    msub = sp.add_subparsers(dest="sub", required=True)
    msub.add_parser("list", help="show the controlled vocabulary and its usage")
    ms = msub.add_parser("set", help="label a finding with its mechanism")
    ms.add_argument("finding_id", type=int)
    ms.add_argument("mechanism")

    sp = sub.add_parser("precedent", help="past engagements that look like this one")
    sp.add_argument("--engagement", type=int, default=None)
    sp.add_argument("--limit", type=int, default=5)
    sp.add_argument("--include-open", action="store_true",
                    help="also match engagements with no recorded outcome")

    sp = sub.add_parser("outcome", help="record how an engagement ended")
    sp.add_argument("engagement", type=int)
    sp.add_argument("outcome", choices=["open", "solved", "parked", "abandoned"])
    sp.add_argument("--note", default=None, help="how it was solved, or why it was parked")
    sp.add_argument("--time", dest="lab_time", default=None, help="e.g. 5m32")

    sp = sub.add_parser("opp", help="manage opportunities")
    osub = sp.add_subparsers(dest="sub", required=True)
    ol = osub.add_parser("list")
    ol.add_argument("--status", default=None, choices=["open", "pinned", "dismissed", "converted"])
    ol.add_argument("--engagement", type=int, default=None)
    for name in ("pin", "dismiss", "convert"):
        op = osub.add_parser(name)
        op.add_argument("id", type=int)

    sp = sub.add_parser("prune", help="bounded growth: drop wire noise (DRY RUN by default)")
    sp.add_argument("--wire-days", type=float, default=2,
                    help="age of flow/flowclose events to drop (default 2)")
    sp.add_argument("--flow-days", type=float, default=2,
                    help="age of CLOSED flow rows to drop (default 2)")
    sp.add_argument("--opp-days", type=float, default=14,
                    help="age of DISMISSED opportunities to drop (default 14)")
    sp.add_argument("--engagement", type=int, default=None)
    sp.add_argument("--apply", action="store_true",
                    help="actually delete (without this it only reports)")

    sp = sub.add_parser("sitrep", help="situation report")
    ssub = sp.add_subparsers(dest="sub", required=True)
    ss = ssub.add_parser("set")
    ss.add_argument("--activity", default=None)
    ss.add_argument("--hypothesis", default=None)
    ss.add_argument("--next", dest="next_steps", default=None)
    ss.add_argument("--engagement", type=int, default=None)
    sh = ssub.add_parser("show")
    sh.add_argument("--engagement", type=int, default=None)

    sp = sub.add_parser("focus", help="set/show the current-target pointer (output attribution)")
    sp.add_argument("target", nargs="?", default=None, help="target ip, or 'none' to clear")

    sp = sub.add_parser("scope", help="show/set scope lists for the engagement")
    sp.add_argument("--in", dest="scope_in", default=None,
                    help="allowlist: comma-separated CIDRs/IPs (empty string clears)")
    sp.add_argument("--out", default=None,
                    help="blocklist: comma-separated CIDRs/IPs (empty string clears)")
    sp.add_argument("--guard", default=None, choices=["on", "off"],
                    help="turn scope enforcement on/off (default on); off = no command is scope-checked")
    sp.add_argument("--engagement", type=int, default=None)

    sp = sub.add_parser("transcript", help="register a flat text file to tail into the feed")
    sp.add_argument("path")

    sp = sub.add_parser("lead", help="manage leads (hunches / expansion items)")
    lsub = sp.add_subparsers(dest="sub", required=True)
    la = lsub.add_parser("add")
    la.add_argument("observation")
    la.add_argument("--category", default="anomaly")
    la.add_argument("--vector", default="", help="candidate vector")
    la.add_argument("--engagement", type=int, default=None)
    ll = lsub.add_parser("list")
    ll.add_argument("--status", default="open")
    ll.add_argument("--engagement", type=int, default=None)
    for name in ("promote", "dismiss", "rule-out"):
        lp = lsub.add_parser(name)
        lp.add_argument("id", type=int)

    sp = sub.add_parser("worklist", help="ranked worklist view (opportunities + leads + lone facts)")
    sp.add_argument("--engagement", type=int, default=None)

    args = p.parse_args(argv)

    try:
        if args.cmd == "log":
            body = {"source": "agent", "kind": args.kind, "text": args.text}
            if args.target:
                body["target_id"] = find_target(args.target)["id"]
            show(req("POST", "/api/events", body))

        elif args.cmd == "target":
            if args.sub == "add":
                show(req("POST", "/api/targets", {
                    "ip": args.ip, "hostname": args.hostname, "os": args.os,
                    "role": args.role, "status": args.status,
                    "engagement_id": args.engagement}))
            else:
                for t in req("GET", "/api/targets"):
                    print(f"#{t['id']} {t['ip']} [{t['status']}] {t.get('hostname') or ''} "
                          f"{t.get('os') or ''} eng={t.get('engagement_id')}")

        elif args.cmd == "svc":
            t = find_target(args.ip)
            show(req("POST", "/api/services", {
                "target_id": t["id"], "port": args.port, "proto": args.proto,
                "name": args.name, "product": args.product, "version": args.version,
                "extrainfo": args.info}))

        elif args.cmd == "cred" and args.sub == "add":
            body = {"username": args.username, "secret": args.secret,
                    "kind": args.kind, "source": args.source}
            if args.status:
                body["status"] = args.status
            if args.target:
                body["target_id"] = find_target(args.target)["id"]
            show(req("POST", "/api/credentials", body))

        elif args.cmd == "cred" and args.sub == "list":
            if args.target:
                show(req("GET", f"/api/credentials?target_id={find_target(args.target)['id']}"))
            else:
                eng = args.engagement or default_engagement()
                show(req("GET", f"/api/credentials?engagement_id={eng}"))

        elif args.cmd == "cred" and args.sub == "set":
            body = {k: v for k, v in {
                "username": args.username, "secret": args.secret, "kind": args.kind,
                "status": args.status, "source": args.source, "valid": args.valid,
            }.items() if v is not None}
            if not body:
                raise ApiError("pass at least one field to update")
            show(req("PATCH", f"/api/credentials/{args.id}", body))

        elif args.cmd == "principal" and args.sub == "add":
            body = {"name": args.name, "kind": args.kind, "realm": args.realm,
                    "source": args.source}
            if args.target:
                body["target_id"] = find_target(args.target)["id"]
            show(req("POST", "/api/principals", body))

        elif args.cmd == "principal" and args.sub == "list":
            eng = args.engagement or default_engagement()
            show(req("GET", f"/api/principals?engagement_id={eng}"))

        elif args.cmd == "secret" and args.sub == "add":
            body = {"value": args.value, "kind": args.kind, "realm": args.realm,
                    "source": args.source}
            if args.target:
                body["target_id"] = find_target(args.target)["id"]
            show(req("POST", "/api/secrets", body))

        elif args.cmd == "secret" and args.sub == "list":
            eng = args.engagement or default_engagement()
            show(req("GET", f"/api/secrets?engagement_id={eng}"))

        elif args.cmd == "binding" and args.sub == "add":
            body = {"principal_id": args.principal, "secret_id": args.secret,
                    "status": args.status, "source": args.source}
            if args.target:
                body["target_id"] = find_target(args.target)["id"]
            show(req("POST", "/api/bindings", body))

        elif args.cmd == "binding" and args.sub == "list":
            eng = args.engagement or default_engagement()
            show(req("GET", f"/api/bindings?engagement_id={eng}"))

        elif args.cmd == "payload" and args.sub == "add":
            show(req("POST", "/api/payloads", {
                "technique": args.technique, "body": args.body, "target_model": args.model,
                "guardrail_defeated": args.guardrail, "outcome": args.outcome,
                "target_ref": args.target_ref}))
        elif args.cmd == "payload" and args.sub == "list":
            show(req("GET", f"/api/payloads?engagement_id={default_engagement()}"))

        elif args.cmd == "rule" and args.sub == "add":
            show(req("POST", "/api/detection_rules", {
                "name": args.name, "source_system": args.source, "match_mechanism": args.match,
                "blind_spot": args.blind, "evasion": args.evade, "fired": args.fired}))
        elif args.cmd == "rule" and args.sub == "list":
            show(req("GET", f"/api/detection_rules?engagement_id={default_engagement()}"))

        elif args.cmd == "poison" and args.sub == "add":
            body = {"location": args.location, "store_type": args.store, "verify_method": args.verify}
            if args.payload is not None:
                body["payload_id"] = args.payload
            show(req("POST", "/api/poison", body))
        elif args.cmd == "poison" and args.sub == "set":
            body = {k: v for k, v in {"cleanup_done": args.cleanup, "live": args.live}.items()
                    if v is not None}
            if not body:
                raise ApiError("pass --cleanup and/or --live")
            show(req("PATCH", f"/api/poison/{args.id}", body))
        elif args.cmd == "poison" and args.sub == "list":
            show(req("GET", f"/api/poison?engagement_id={default_engagement()}"))

        elif args.cmd == "objective" and args.sub == "add":
            body = {"text": args.text, "value": args.value,
                    "engagement_id": args.engagement or default_engagement()}
            if args.target:
                body["target_id"] = find_target(args.target)["id"]
            show(req("POST", "/api/objectives", body))
        elif args.cmd == "objective" and args.sub == "list":
            show(req("GET", f"/api/objectives?engagement_id={default_engagement()}"))
        elif args.cmd == "objective" and args.sub == "done":
            body = {"status": "done"}
            if args.value is not None:
                body["value"] = args.value
            show(req("PATCH", f"/api/objectives/{args.id}", body))
        elif args.cmd == "objective" and args.sub == "link":
            body = {}
            if args.target:
                body["target_id"] = find_target(args.target)["id"]
            if args.evidence is not None:
                body["evidence_id"] = args.evidence
            if args.value is not None:
                body["value"] = args.value
            if not body:
                raise ApiError("pass --target, --evidence and/or --value")
            show(req("PATCH", f"/api/objectives/{args.id}", body))

        elif args.cmd == "finding":
            body = {"title": args.title, "severity": args.sev, "description": args.desc}
            if args.target:
                body["target_id"] = find_target(args.target)["id"]
            show(req("POST", "/api/findings", body))

        elif args.cmd == "evidence":
            show(post_multipart("/api/evidence",
                                {"finding_id": str(args.finding_id), "caption": args.caption},
                                "file", args.file))

        elif args.cmd == "tasks":
            path = "/api/tasks?status=pending" if args.pending else "/api/tasks"
            for t in req("GET", path):
                print(f"#{t['id']} [{t['status']}] {t['text']} (by {t['author']})")

        elif args.cmd == "task":
            show(req("POST", f"/api/tasks/{args.id}/done"))

        elif args.cmd == "engage":
            if args.sub == "add":
                show(req("POST", "/api/engagements",
                         {"name": args.name, "scope": args.scope, "notes": args.notes}))
            else:
                for e in req("GET", "/api/engagements"):
                    print(f"#{e['id']} {e['name']} scope={e.get('scope') or '-'} created={e['created_at']}")

        elif args.cmd == "export":
            raw = req("GET", f"/api/export/{args.engagement_id}?fmt={args.fmt}")
            sys.stdout.write(raw.decode() if isinstance(raw, bytes) else str(raw))

        elif args.cmd == "fact":
            if args.sub == "add":
                body = {
                    "engagement_id": args.engagement,
                    "subject_name": args.subject,
                    "subject_type": args.stype or guess_type(args.subject),
                    "predicate": args.predicate,
                    "stage": args.stage,
                    "source": "agent",
                }
                # object: entity if a type was forced or it's not free text with spaces
                if args.otype or " " not in args.object:
                    body["object_name"] = args.object
                    body["object_type"] = args.otype or guess_type(args.object)
                else:
                    body["object_text"] = args.object
                show(req("POST", "/api/facts", body))
            elif args.sub == "list":
                eng = args.engagement or default_engagement()
                path = f"/api/facts?engagement_id={eng}"
                if args.status:
                    path += f"&status={args.status}"
                if args.polarity:
                    path += f"&polarity={args.polarity}"
                for f in req("GET", path):
                    obj = f.get("object_name") or f.get("object_text") or "?"
                    neg = "NOT " if f.get("polarity") == "absent" else ""
                    print(f"#{f['id']} [{f['status']}/{f['stage']}] "
                          f"{f['subject_name']} -{neg}{f['predicate']}-> {obj} ({f['source']})")
            elif args.sub == "absent":
                body = {
                    "engagement_id": args.engagement,
                    "subject_name": args.subject,
                    "subject_type": args.stype or guess_type(args.subject),
                    "predicate": args.predicate,
                    "polarity": "absent",
                    "stage": "confirmed",
                    "source": "agent",
                }
                if args.otype or " " not in args.object:
                    body["object_name"] = args.object
                    body["object_type"] = args.otype or guess_type(args.object)
                else:
                    body["object_text"] = args.object
                show(req("POST", "/api/facts", body))
            else:  # out
                show(req("PATCH", f"/api/facts/{args.id}", {"status": "ruled-out"}))

        elif args.cmd == "mech":
            if args.sub == "list":
                for m in req("GET", "/api/mechanisms"):
                    mark = f"{m['findings']:>4}" if m["findings"] else "   ."
                    print(f"{mark}  {m['mechanism']}")
            else:
                show(req("PATCH", f"/api/findings/{args.finding_id}",
                         {"mechanism": args.mechanism}))

        elif args.cmd == "precedent":
            eng = args.engagement or default_engagement()
            path = f"/api/precedent?engagement_id={eng}&limit={args.limit}"
            if args.include_open:
                path += "&include_open=true"
            r = req("GET", path)
            sig = r["signature"]
            print(f"engagement {r['engagement_id']}  "
                  f"mech={len(sig['mechanisms'])} products={len(sig['products'])} "
                  f"ports={len(sig['ports'])} absent={len(sig['absent'])}")
            if not r["precedents"]:
                print("  no precedent — label findings with `redops mech set` to build the corpus")
            for p in r["precedents"]:
                t = f" [{p['lab_time']}]" if p["lab_time"] else ""
                print(f"\n  {p['score']:>6.1f}  #{p['engagement_id']} {p['name']} "
                      f"({p['outcome']}){t}")
                if p["outcome_note"]:
                    print(f"          {p['outcome_note']}")
                for field, terms in p["matched"].items():
                    print(f"          {field}: {', '.join(str(t) for t in terms[:6])}")
                for f in p["findings"][:3]:
                    print(f"          - [{f['mechanism']}] {f['title'][:70]}")

        elif args.cmd == "outcome":
            body = {"outcome": args.outcome}
            if args.note is not None:
                body["outcome_note"] = args.note
            if args.lab_time is not None:
                body["lab_time"] = args.lab_time
            show(req("PATCH", f"/api/engagements/{args.engagement}", body))

        elif args.cmd == "opp":
            if args.sub == "list":
                eng = args.engagement or default_engagement()
                path = f"/api/opportunities?engagement_id={eng}"
                if args.status:
                    path += f"&status={args.status}"
                for o in req("GET", path):
                    print(f"#{o['id']} [{o['status']}] ({o['rule']}) {o['title']}")
                    print(f"    {o['rationale']}")
            else:
                show(req("POST", f"/api/opportunities/{args.id}/{args.sub}"))

        elif args.cmd == "prune":
            r = req("POST", "/api/maintenance/prune",
                    {"wire_days": args.wire_days, "flow_days": args.flow_days,
                     "opp_days": args.opp_days, "engagement_id": args.engagement,
                     "apply": args.apply})
            verb = "removed" if r.get("applied") else "would remove"
            print(f"{verb}: {r['wire_events']:,} wire events "
                  f"({r['wire_bytes'] / 1e6:.2f} MB), "
                  f"{r['closed_flows']:,} closed flows, "
                  f"{r['dismissed_opportunities']:,} dismissed opportunities")
            if not r.get("applied"):
                print("dry run — re-run with --apply to delete. "
                      "facts/findings/evidence/creds/tool runs are never touched.")

        elif args.cmd == "sitrep":
            eng = args.engagement or default_engagement()
            if args.sub == "set":
                body = {k: v for k, v in {"activity": args.activity, "hypothesis": args.hypothesis,
                                          "next_steps": args.next_steps}.items() if v is not None}
                if not body:
                    raise ApiError("nothing to set (use --activity/--hypothesis/--next)")
                show(req("PUT", f"/api/sitrep/{eng}", body))
            else:
                s = req("GET", f"/api/sitrep/{eng}")
                print(f"intent:     {s.get('commander_intent') or '-'}")
                print(f"activity:   {s.get('activity') or '-'}")
                print(f"hypothesis: {s.get('hypothesis') or '-'}")
                print(f"next steps: {s.get('next_steps') or '-'}")
                print(f"updated:    {s.get('updated_at') or 'never'}")

        elif args.cmd == "focus":
            if args.target is None:
                show(req("GET", "/api/current_target"))
            elif args.target.lower() == "none":
                show(req("PUT", "/api/current_target", {"target_id": None}))
            else:
                t = find_target(args.target)
                show(req("PUT", "/api/current_target", {"target_id": t["id"]}))

        elif args.cmd == "scope":
            eng = args.engagement or default_engagement()
            if args.guard is not None:
                show(req("PUT", "/api/settings", {"scope_guard": args.guard == "on"}))
            body = {}
            if args.scope_in is not None:
                body["in"] = [x.strip() for x in args.scope_in.split(",") if x.strip()]
            if args.out is not None:
                body["out"] = [x.strip() for x in args.out.split(",") if x.strip()]
            if body:
                show(req("PUT", f"/api/scope/{eng}", body))
            else:
                s = req("GET", f"/api/scope/{eng}")
                g = req("GET", "/api/settings").get("scope_guard", {})
                print("scope guard:     " + ("ON" if g.get("value") else "OFF (no command is scope-checked)"))
                print("allowlist (in):  " + (", ".join(s["in"]) if s["in"] else "(none - allowlist off)"))
                print("blocklist (out): " + (", ".join(s["out"]) if s["out"] else "(none)"))

        elif args.cmd == "transcript":
            show(req("POST", "/api/transcript/sources", {"path": args.path}))

        elif args.cmd == "lead":
            if args.sub == "add":
                show(req("POST", "/api/leads", {
                    "observation": args.observation, "category": args.category,
                    "candidate_vector": args.vector, "engagement_id": args.engagement}))
            elif args.sub == "list":
                eng = args.engagement or default_engagement()
                for l in req("GET", f"/api/leads?engagement_id={eng}&status={args.status}"):
                    print(f"#{l['id']} [{l['status']}/{l['category']}] ({l['score']}) {l['observation']}")
            else:
                show(req("POST", f"/api/leads/{args.id}/{args.sub}"))

        elif args.cmd == "worklist":
            eng = args.engagement or default_engagement()
            for it in req("GET", f"/api/worklist?engagement_id={eng}"):
                det = " [DETECTED]" if it.get("detected") else ""
                print(f"{it['score']:6.2f} {it['kind']:<11} #{it['id']} [{it['category']}]{det} {it['title'][:90]}")
        return 0
    except ApiError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
