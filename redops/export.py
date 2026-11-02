"""Engagement report export (markdown / html, dependency-free).

Images are embedded as base64 data URIs so a single exported file is
self-contained. PDF is intentionally out of scope (use pandoc/weasyprint
manually - see README).
"""

import base64
import html as html_mod
import json
import mimetypes
import os
import re
from datetime import datetime

from . import db

SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATUSES = ["unidentified", "identified", "foothold", "rooted", "flagged"]


def _data_uri(path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    return f"data:{mime};base64,{base64.b64encode(raw).decode()}"


def _img_ref(ev: dict) -> str:
    uri = _data_uri(db.EVIDENCE_DIR / ev["path"])
    cap = ev.get("caption") or ev["path"]
    if uri and (ev["path"].lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"))):
        return f"![{cap}]({uri})"
    return f"[{cap}]({ev['path']})"


def _ev_meta(e: dict) -> dict:
    try:
        return json.loads(e.get("meta_json") or "{}")
    except json.JSONDecodeError:
        return {}


# A report is a DOCUMENT, not a data dump. Full ground truth stays in the DB and
# under data/transcript/ — the report carries a readable excerpt and says exactly
# where the rest lives. Without this a single engagement rendered 2.6 MB, 2 MB of
# it one host's raw scan output.
OUTPUT_LIMIT = int(os.environ.get("REDOPS_REPORT_OUTPUT_LIMIT", "4000"))
# Per-narrative budget for captured OUTPUT only. Commands and reasoning are the
# story and are always kept in full; raw output is the bulk (3,253 narrative
# events on one engagement) and is what gets bounded. Set 0 for no budget.
SECTION_BUDGET = int(os.environ.get("REDOPS_REPORT_SECTION_BUDGET", "80000"))


def _ev_full_text(e: dict, limit: int | None = None) -> str:
    """Event text with overflow resolution. `limit` caps it for rendering and
    points at the stored capture; None returns the untruncated ground truth."""
    ov = _ev_meta(e).get("overflow")
    text = e["text"]
    if ov:
        # meta_json is attacker-influenced: POST /api/events takes arbitrary meta,
        # so an overflow of "../operator.token" (or an absolute path) would read
        # that file straight into the report. Resolve and require containment.
        try:
            p = (db.TRANSCRIPT_DIR / str(ov)).resolve()
            root = db.TRANSCRIPT_DIR.resolve()
            if p.is_file() and (p == root or root in p.parents):
                text = p.read_text(errors="replace")
        except (OSError, ValueError):
            pass
    if limit and len(text) > limit:
        rid = _ev_meta(e).get("tool_run")
        where = (f"tool run #{rid}" if rid else
                 f"data/transcript/{ov}" if ov else f"event #{e.get('id')}")
        text = (text[:limit].rstrip()
                + f"\n\n[… {len(text) - limit:,} more bytes truncated — "
                  f"full capture: {where}]")
    return text


def _safe_fence(body: str) -> str:
    """A fence longer than any backtick run inside the body. Captured output
    containing ``` used to CLOSE the block early, after which the rest of the
    capture was parsed as markdown — which is how a git-status capture became an
    83 KB top-level section of an unrelated engagement's report."""
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    return "`" * max(3, longest + 1)


def _oneline(s: str, cap: int = 300) -> str:
    """Flatten to a single line for list-item rendering: a newline followed by
    '## ' would otherwise break out of the bullet and forge a report section."""
    s = " ".join((s or "").split())
    return s if len(s) <= cap else s[:cap].rstrip() + " […]"


def _cred_table(L: list[str], creds: list[dict]) -> None:
    """Render a credentials table, tolerant of partial creds (empty username or
    secret) and the verification status. Secret-only tokens show '—' for user."""
    L.append("| Username | Secret | Kind | Status | Source | Valid |")
    L.append("|---|---|---|---|---|---|")
    for c in creds:
        user = c.get("username") or "—"
        secret = f"`{c['secret']}`" if c.get("secret") else "—"
        status = c.get("status") or "untested"
        L.append(f"| {user} | {secret} | {c['kind']} | {status} | {c.get('source') or ''} | "
                 f"{'yes' if c['valid'] else 'no'} |")
    L.append("")


def _render_narrative(L: list[str], events: list[dict], limit: int | None = None) -> None:
    """Chronological call+output transcript: `$ command` then output, fenced as
    code blocks so the section is copy/paste-replicable.

    Block content is BUFFERED so the fence can be sized to the content — captured
    output is untrusted text and must never be able to close its own block and
    have the remainder parsed as markdown."""
    limit = OUTPUT_LIMIT if limit is None else limit
    buf: list[str] = []
    spent, omitted, omitted_bytes = 0, 0, 0

    def close():
        if buf:
            body = "\n".join(buf)
            fence = _safe_fence(body)
            L.append(fence)
            L.append(body)
            L.append(fence)
            L.append("")
            buf.clear()

    for e in events:
        m = _ev_meta(e)
        is_tool_call = e["kind"] == "action" and str(m.get("uuid", "")).startswith("tool_")
        if e["kind"] == "reasoning":
            close()
            L.append(f"- `{e['ts']}` [{e['source']}] _{_oneline(e['text'])}_")
        elif is_tool_call:
            close()
            buf.append(f"$ {_oneline(e['text'], 500)}")
        elif e["kind"] == "output":
            body = _ev_full_text(e, limit)
            if SECTION_BUDGET and spent >= SECTION_BUDGET:
                # budget spent: keep the command narrative, drop the dump. Say so
                # explicitly — a silently shortened report is worse than a long one.
                omitted += 1
                omitted_bytes += len(body)
                continue
            if not buf:
                buf.append("$ (captured output)")
            buf.append(body)
            spent += len(body)
        else:
            close()
            L.append(f"- `{e['ts']}` [{e['source']}] {_oneline(e['text'])}")
    close()
    if omitted:
        L.append(f"> _{omitted:,} further captured outputs ({omitted_bytes:,} bytes) "
                 f"omitted from this narrative to keep the report readable. They are "
                 f"stored in full — see the tool runs and `data/transcript/`._")
        L.append("")


def _finding_trust(conn, f) -> list[str]:
    """The trust line under a finding: its DERIVED confidence, staleness, and the
    verification events behind it — so the deliverable shows what actually backs a
    claim, not just its typed status. A finding whose typed status asserts more
    than its evidence supports is flagged, because a report that renders a
    never-tested finding as 'verified' is exactly the stale conclusion this
    database exists to stop."""
    conf = f.get("confidence") or "claimed"
    stale = f.get("stale")
    vs = db.rows(conn, "SELECT * FROM verifications WHERE finding_id=? ORDER BY ts DESC, id DESC",
                 (f["id"],))
    meaningful = [v for v in vs if v["result"] != "errored"]
    label = {"live-verified": "LIVE-VERIFIED", "observed": "OBSERVED",
             "claimed": "CLAIMED (source only — no test)"}.get(conf, conf.upper())
    if stale:
        label += " · STALE (target surface changed since proof)"
    contested = meaningful and meaningful[0]["result"] == "not-reproduced"
    if contested:
        label += " · CONTESTED (fired and did not reproduce)"
    # the typed-status escape hatch: if the words claim proof the evidence doesn't
    # carry, say so in the report rather than letting it read as settled. Uses the
    # canonical STATUS_ASSERTS_PROOF set, not a loose wordlist.
    if (f.get("status") or "") in db.STATUS_ASSERTS_PROOF and conf != "live-verified":
        label += f" · ⚠ status '{f['status']}' is not backed by a live verification"
    out = [f"- **Trust:** {label}"]
    for v in vs:
        cite = f", callback flow #{v['flow_id']}" if v["flow_id"] else ""
        sflag = " [stale]" if v["stale"] else ""
        note = f" — {v['note']}" if v["note"] else ""
        out.append(f"  - `{v['ts']}` {v['result']} via {v['method']}{cite}{sflag} "
                   f"(by {v['agent']}){note}")
    return out


def build_markdown(engagement_id: int) -> str:
    conn = db.connect()
    try:
        eng = db.row(conn, "SELECT * FROM engagements WHERE id=?", (engagement_id,))
        if not eng:
            raise ValueError(f"engagement {engagement_id} not found")
        targets = db.rows(conn, "SELECT * FROM targets WHERE engagement_id=? ORDER BY ip", (engagement_id,))
        objectives = db.rows(conn, "SELECT * FROM objectives WHERE engagement_id=?", (engagement_id,))
        # engagement-scoped so the report never leaks another engagement's
        # findings or evidence (schema v5).
        findings = db.rows(conn, "SELECT * FROM findings WHERE engagement_id=? ORDER BY id",
                           (engagement_id,))
        evidence = db.rows(conn, "SELECT * FROM evidence WHERE engagement_id=? ORDER BY id",
                           (engagement_id,))

        L: list[str] = []
        L.append(f"# Engagement Report: {eng['name']}")
        L.append("")
        L.append(f"- **Scope:** {eng.get('scope') or 'n/a'}")
        L.append(f"- **Date:** {datetime.now().astimezone().isoformat(timespec='seconds')}")
        L.append(f"- **Engagement started:** {eng['created_at']}")
        if eng.get("notes"):
            L.append(f"- **Notes:** {eng['notes']}")
        L.append("")

        # Summary
        L.append("## Summary")
        L.append("")
        by_status = {s: 0 for s in STATUSES}
        for t in targets:
            by_status[t["status"]] = by_status.get(t["status"], 0) + 1
        by_sev = {s: 0 for s in SEVERITIES}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        L.append(f"- **Targets:** {len(targets)} (" +
                 ", ".join(f"{k}: {v}" for k, v in by_status.items() if v) + ")")
        L.append(f"- **Findings:** {len(findings)} (" +
                 ", ".join(f"{k}: {v}" for k, v in by_sev.items() if v) + ")")
        L.append(f"- **Evidence items:** {len(evidence)}")
        L.append("")

        if objectives:
            L.append("## Objectives")
            L.append("")
            tgt_ip = {t["id"]: t["ip"] for t in targets}
            for o in objectives:
                mark = "x" if o["status"] == "done" else " "
                val = f" -> `{o['value']}`" if o.get("value") else ""
                proof = []
                if o.get("target_id") and o["target_id"] in tgt_ip:
                    proof.append(f"on {tgt_ip[o['target_id']]}")
                if o.get("evidence_id"):
                    proof.append(f"evidence #{o['evidence_id']}")
                pf = f"  *(proof: {', '.join(proof)})*" if proof else ""
                L.append(f"- [{mark}] {o['text']}{val}{pf}")
            L.append("")

        # Per-target sections
        for t in targets:
            L.append(f"## Target: {t['ip']}" + (f" ({t['hostname']})" if t.get("hostname") else ""))
            L.append("")
            L.append(f"- **Status:** {t['status']}")
            if t.get("os"):
                L.append(f"- **OS:** {t['os']}")
            if t.get("role"):
                L.append(f"- **Role:** {t['role']}")
            L.append("")

            svcs = db.rows(conn, "SELECT * FROM services WHERE target_id=? ORDER BY port", (t["id"],))
            if svcs:
                L.append("### Services")
                L.append("")
                L.append("| Port | Proto | Service | Product | Version | Info |")
                L.append("|---|---|---|---|---|---|")
                for s in svcs:
                    L.append(f"| {s['port']} | {s['proto']} | {s['name']} | {s.get('product','')} "
                             f"| {s.get('version','')} | {s.get('extrainfo','')} |")
                L.append("")

            creds = db.binding_view(conn, "WHERE b.target_id=? ORDER BY b.id", (t["id"],))
            if creds:
                L.append("### Credentials")
                L.append("")
                _cred_table(L, creds)

            tfind = [f for f in findings if f["target_id"] == t["id"]]
            if tfind:
                L.append("### Findings")
                L.append("")
                for f in tfind:
                    L.append(f"#### [{f['severity'].upper()}] {f['title']} ({f['status']})")
                    L.append("")
                    L.extend(_finding_trust(conn, f))
                    L.append("")
                    if f.get("description"):
                        L.append(f["description"])
                        L.append("")
                    fev = [e for e in evidence if e["finding_id"] == f["id"]]
                    for e in fev:
                        L.append(_img_ref(e))
                        if e.get("caption"):
                            L.append(f"*{e['caption']}*")
                        L.append("")

            # Attack narrative: wire/agent/transcript events tied to this target,
            # with full command+output code blocks (overflow files resolved).
            narrative = db.rows(
                conn, "SELECT * FROM events WHERE target_id=? AND kind IN ('action','reasoning','output') "
                      "ORDER BY id", (t["id"],))
            if narrative:
                L.append("### Attack narrative")
                L.append("")
                _render_narrative(L, narrative)

        # Global findings (no target)
        gfind = [f for f in findings if f["target_id"] is None]
        if gfind:
            L.append("## Global findings")
            L.append("")
            for f in gfind:
                L.append(f"#### [{f['severity'].upper()}] {f['title']} ({f['status']})")
                L.append("")
                L.extend(_finding_trust(conn, f))
                L.append("")
                if f.get("description"):
                    L.append(f["description"])
                    L.append("")

        # Global credentials (bare tokens/keys with no host) — scoped by engagement
        # so they don't vanish from the report just because target_id is null.
        gcreds = db.binding_view(conn, "WHERE b.engagement_id=? AND b.target_id IS NULL "
                                       "ORDER BY b.id", (engagement_id,))
        if gcreds:
            L.append("## Credentials (no host)")
            L.append("")
            _cred_table(L, gcreds)

        # Credential material pools: harvested identities and auth material not yet
        # bound into a confirmed credential — the raw feed for the spray matrix.
        princ = db.rows(conn, "SELECT * FROM principals WHERE engagement_id=? AND status='active' "
                              "ORDER BY id", (engagement_id,))
        secs = db.rows(conn, "SELECT * FROM secrets WHERE engagement_id=? AND status='active' "
                             "ORDER BY id", (engagement_id,))
        if princ or secs:
            L.append("## Credential material")
            L.append("")
            if princ:
                L.append("**Principals (identities):**")
                L.append("")
                L.append("| Name | Kind | Realm | Source |")
                L.append("|---|---|---|---|")
                for p in princ:
                    L.append(f"| {p['name']} | {p['kind']} | {p.get('realm') or ''} "
                             f"| {p.get('source') or ''} |")
                L.append("")
            if secs:
                L.append("**Secrets (auth material):**")
                L.append("")
                L.append("| Value | Kind | Realm | Source |")
                L.append("|---|---|---|---|")
                for s in secs:
                    L.append(f"| `{s['value']}` | {s['kind']} | {s.get('realm') or ''} "
                             f"| {s.get('source') or ''} |")
                L.append("")

        # Intelligence summary + opportunities
        eng_facts = db.rows(conn, db.FACT_SQL +
                            " WHERE f.engagement_id=? ORDER BY f.id", (engagement_id,))
        if eng_facts:
            L.append("## Intelligence summary")
            L.append("")
            by_type: dict[str, list] = {}
            for f in eng_facts:
                by_type.setdefault(f["subject_type"] or "other", []).append(f)
            for t, fl in sorted(by_type.items()):
                L.append(f"### Facts about {t}s ({len(fl)})")
                L.append("")
                for f in fl:
                    obj = f["object_name"] or f["object_text"] or "?"
                    flag = "" if f["status"] == "active" else " (RULED OUT)"
                    stage = "" if f["stage"] == "confirmed" else f" [{f['stage']}]"
                    L.append(f"- **{f['subject_name']}** -{f['predicate']}-> {obj}{stage}{flag}")
                L.append("")

        opps = db.rows(conn, "SELECT * FROM opportunities WHERE engagement_id=? "
                             "ORDER BY id", (engagement_id,))
        if opps:
            L.append("## Opportunities identified")
            L.append("")
            for o in opps:
                L.append(f"### [{o['status'].upper()}] {o['title']} (rule {o['rule']})")
                L.append("")
                L.append(o["rationale"])
                L.append("")
                for of in db.rows(conn, db.FACT_SQL +
                                  " JOIN opportunity_facts x ON x.fact_id=f.id WHERE x.opportunity_id=?",
                                  (o["id"],)):
                    obj = of["object_name"] or of["object_text"] or "?"
                    L.append(f"- supporting fact: **{of['subject_name']}** -{of['predicate']}-> {obj}")
                L.append("")

        # AI-artifact appendices: payload library, detection rules, planted poison
        payloads = db.rows(conn, "SELECT * FROM payloads WHERE engagement_id=? ORDER BY id",
                           (engagement_id,))
        if payloads:
            L.append("## Payload library")
            L.append("")
            L.append("| Technique | Model | Guardrail defeated | Outcome | Target |")
            L.append("|---|---|---|---|---|")
            for p in payloads:
                L.append(f"| {p['technique']} | {p.get('target_model') or ''} | "
                         f"{p.get('guardrail_defeated') or ''} | {p.get('outcome') or ''} | "
                         f"{p.get('target_ref') or ''} |")
            L.append("")
            for p in payloads:
                if p.get("body"):
                    L.append(f"**{p['technique']}**"
                             + (f" — {p['target_ref']}" if p.get("target_ref") else ""))
                    L.append("")
                    # an injection payload is by definition hostile text — fence
                    # it past its own content like every other capture
                    fence = _safe_fence(p["body"])
                    L.append(fence)
                    L.append(p["body"])
                    L.append(fence)
                    L.append("")

        drules = db.rows(conn, "SELECT * FROM detection_rules WHERE engagement_id=? ORDER BY id",
                         (engagement_id,))
        if drules:
            L.append("## Detection rules encountered")
            L.append("")
            L.append("| Rule | Source | Match mechanism | Blind spot | Evasion | Fired |")
            L.append("|---|---|---|---|---|---|")
            for r in drules:
                L.append(f"| {r['name']} | {r.get('source_system') or ''} | "
                         f"{r.get('match_mechanism') or ''} | {r.get('blind_spot') or ''} | "
                         f"{r.get('evasion') or ''} | {'yes' if r['fired'] else 'no'} |")
            L.append("")

        poison = db.rows(conn, "SELECT * FROM poison WHERE engagement_id=? ORDER BY id",
                         (engagement_id,))
        if poison:
            L.append("## Planted artifacts (cleanup checklist)")
            L.append("")
            for p in poison:
                mark = "x" if p["cleanup_done"] else " "
                live = "live" if p["live"] else "removed"
                L.append(f"- [{mark}] **{p['store_type']}** @ `{p['location']}` ({live})"
                         + (f" — verify: {p['verify_method']}" if p.get("verify_method") else ""))
            L.append("")

        # Unattributed transcript appendix: captured call/output events with no
        # target attribution - nothing is silently dropped.
        # engagement_id was missing here: every OTHER engagement's unattributed
        # captures rendered into this report — a cross-engagement leak in the one
        # artifact that leaves the building.
        unattributed = db.rows(
            conn, "SELECT * FROM events WHERE target_id IS NULL AND engagement_id=? "
                  "AND kind IN ('action','output') "
                  "AND source IN ('wire','transcript') ORDER BY id", (engagement_id,))
        if unattributed:
            L.append("## Unattributed transcript")
            L.append("")
            L.append("Captured command/output events with no target attribution "
                     "(set focus with `redops focus <ip>` to attribute future output).")
            L.append("")
            _render_narrative(L, unattributed)

        # Evidence appendix
        if evidence:
            L.append("## Evidence appendix")
            L.append("")
            for e in evidence:
                L.append(f"### Evidence #{e['id']}: {e.get('caption') or e['path']}")
                L.append("")
                L.append(f"- **Kind:** {e['kind']}  **Captured:** {e['ts']}"
                         + (f"  **Finding:** #{e['finding_id']}" if e["finding_id"] else "")
                         + (f"  **Target:** #{e['target_id']}" if e["target_id"] else ""))
                L.append("")
                L.append(_img_ref(e))
                L.append("")

        return "\n".join(L)
    finally:
        conn.close()


# --- tiny md -> html for the subset build_markdown emits --------------------

def _attr(s: str) -> str:
    """Escape for an ATTRIBUTE value. _inline escaped with quote=False and then
    interpolated into alt="" / src="" / href="", so an evidence caption of
    `" onerror="alert(1)` became a live handler in a report the operator opens in
    a browser. Captions and paths are attacker-influenced text."""
    return html_mod.escape(s or "", quote=True)


def _safe_url(u: str) -> str:
    """Only allow URL schemes that cannot execute. javascript:/vbscript:/data:
    (other than images) in an href is script execution on open."""
    u = (u or "").strip()
    low = u.lower().replace("\t", "").replace("\n", "")
    if low.startswith(("javascript:", "vbscript:", "file:")):
        return "#"
    if low.startswith("data:") and not low.startswith("data:image/"):
        return "#"
    return u


def _inline(s: str) -> str:
    s = html_mod.escape(s, quote=False)
    # images (already data URIs or paths) - escape() leaves ()/:;,.- intact
    s = re.sub(r"!\[([^]]*)\]\(([^)]*)\)",
               lambda m: f'<img alt="{_attr(m.group(1))}" src="{_attr(_safe_url(m.group(2)))}"'
                         f' style="max-width:100%">', s)
    s = re.sub(r"\[([^]]*)\]\(([^)]*)\)",
               lambda m: f'<a href="{_attr(_safe_url(m.group(2)))}">{m.group(1)}</a>', s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![\w*])_([^_]+)_(?![\w*])", r"<em>\1</em>", s)
    return s


def md_to_html(md: str) -> str:
    lines = md.split("\n")
    out: list[str] = []
    i = 0
    in_list = False
    in_code = False
    fence = ""          # the exact run that opened the block
    while i < len(lines):
        ln = lines[i]
        # Fences are VARIABLE length: a block whose content contains ``` is opened
        # with ```` (or longer) and may only be closed by a run at least as long.
        # Matching any ``` let untrusted captured output close its own block, after
        # which the remainder was parsed as markdown — that is how a capture forged
        # an <h2> in the report.
        m = re.match(r"^\s*(`{3,})", ln)
        if m and (not in_code or len(m.group(1)) >= len(fence)):
            if in_code:
                out.append("</code></pre>")
                in_code = False
                fence = ""
            else:
                if in_list:
                    out.append("</ul>"); in_list = False
                out.append("<pre><code>")
                in_code = True
                fence = m.group(1)
            i += 1
            continue
        if in_code:
            out.append(html_mod.escape(ln))
            i += 1
            continue
        if ln.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1]):
            if in_list:
                out.append("</ul>"); in_list = False
            header = [c.strip() for c in ln.strip("|").split("|")]
            out.append("<table><thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in header) + "</tr></thead><tbody>")
            i += 2
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip("|").split("|")]
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
                i += 1
            out.append("</tbody></table>")
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", ln)
        if m:
            if in_list:
                out.append("</ul>"); in_list = False
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{_inline(m.group(2))}</h{lvl}>")
        elif ln.startswith("- ["):
            if not in_list:
                out.append("<ul>"); in_list = True
            checked = " checked" if ln[3] == "x" else ""
            out.append(f'<li><input type="checkbox" disabled{checked}> {_inline(ln[6:])}</li>')
        elif ln.startswith("- "):
            if not in_list:
                out.append("<ul>"); in_list = True
            out.append(f"<li>{_inline(ln[2:])}</li>")
        elif not ln.strip():
            if in_list:
                out.append("</ul>"); in_list = False
        else:
            if in_list:
                out.append("</ul>"); in_list = False
            out.append(f"<p>{_inline(ln)}</p>")
        i += 1
    if in_list:
        out.append("</ul>")
    body = "\n".join(out)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>RedOps Report</title>
<style>
body {{ font-family: system-ui, sans-serif; background:#111418; color:#d7dce2; max-width:960px; margin:2rem auto; padding:0 1rem; line-height:1.5; }}
h1,h2,h3,h4 {{ color:#7fd0ff; border-bottom:1px solid #2a3138; padding-bottom:.2em; }}
table {{ border-collapse:collapse; width:100%; margin:1em 0; }}
th,td {{ border:1px solid #2a3138; padding:6px 10px; text-align:left; }}
th {{ background:#1a1f26; }}
code {{ background:#1a1f26; padding:1px 5px; border-radius:3px; }}
pre {{ background:#1a1f26; padding:10px; border-radius:4px; overflow-x:auto; border:1px solid #2a3138; }}
pre code {{ background:none; padding:0; }}
img {{ border:1px solid #2a3138; border-radius:4px; margin:.5em 0; }}
a {{ color:#7fd0ff; }}
</style></head><body>
{body}
</body></html>"""


def export(engagement_id: int, fmt: str) -> tuple[str, str]:
    """Return (content, media_type)."""
    md = build_markdown(engagement_id)
    if fmt == "html":
        return md_to_html(md), "text/html"
    return md, "text/markdown"
