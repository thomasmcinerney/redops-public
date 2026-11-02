"""Read-only, loopback CaseHub dashboard for one report.py case."""

from __future__ import annotations

import os
import argparse
import hashlib
import json
import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from .ledger import CaseHub, CaseHubError

# report.py is the report gate authority and lives beside the casehub package.
_KIT = Path(__file__).resolve().parent.parent
if str(_KIT) not in sys.path:
    sys.path.insert(0, str(_KIT))
from report import report_stem, validate  # noqa: E402


def _safe_entity(entity: dict | None) -> dict | None:
    if entity is None:
        return None
    if entity.get("type") != "secret_ref":
        return entity
    fingerprint = (entity.get("attrs") or {}).get("fingerprint", "")
    # Neither the key nor observation attrs belong in a dashboard response.
    safe = {k: v for k, v in entity.items()
            if k not in ("key", "attrs", "observations", "edges", "claims")}
    safe["fingerprint_prefix"] = fingerprint[:12]
    if "observations" in entity:
        safe["observations"] = []
        safe["edges"] = [_safe_edge(edge) for edge in entity.get("edges", [])]
        safe["claims"] = entity.get("claims", [])
    return safe


def _safe_edge(edge: dict) -> dict:
    safe = dict(edge)
    for name in ("src_entity", "dst_entity"):
        if safe.get(name):
            safe[name] = _safe_entity(safe[name])
    return safe


def _report(hub: CaseHub) -> dict:
    data = hub.case()
    root = hub.root
    errors = validate(root, data)
    stem = report_stem(data)
    pdf = root / "build" / f"{stem}.pdf"
    archive = root / "build" / f"{stem}.7z"
    receipt_file = root / "build" / "package-receipt.json"
    review = data.get("review")
    pdf_digest = hashlib.sha256(pdf.read_bytes()).hexdigest() if pdf.is_file() else None
    reviewed = bool(pdf_digest and review and review.get("pdf_sha256") == pdf_digest)
    receipt = None
    if receipt_file.is_file():
        try:
            receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    archive_md5 = hashlib.md5(archive.read_bytes()).hexdigest() if archive.is_file() else None
    packaged = bool(
        reviewed and receipt and archive_md5
        and receipt.get("archive") == archive.name
        and receipt.get("md5") == archive_md5
        and receipt.get("pdf_sha256") == pdf_digest
        and receipt.get("bytes") == archive.stat().st_size
    )
    upload_gate = next((e for e in reversed(data["events"])
                        if e.get("kind") == "gate" and e.get("gate") == "verify_upload"), None)
    uploaded = bool(packaged and upload_gate
                    and upload_gate.get("result") == "verified"
                    and upload_gate.get("archive") == archive.name
                    and upload_gate.get("local_md5", "").lower() == archive_md5
                    and upload_gate.get("portal_md5", "").lower() == archive_md5)
    targets = hub.context()["targets"]
    return {
        "valid": not errors,
        "errors": errors,
        "gates": {tid: {"stages_missing": t["stages_missing"],
                        "proof_recorded": t["proof_recorded"],
                        "ready_submit": t["ready_submit"],
                        "accepted_capture": t["accepted_capture"],
                        "direct_roles": t["direct_roles"]} for tid, t in targets.items()},
        "build": {"state": "built" if pdf_digest else "missing", "file": pdf.name if pdf_digest else None},
        "review": {"state": "reviewed" if reviewed else "missing", "at": review.get("at") if reviewed else None},
        "package": {"state": "packaged" if packaged else "missing",
                    "file": archive.name if packaged else None,
                    "bytes": archive.stat().st_size if packaged else None},
        "upload": {"state": "verified" if uploaded else "missing",
                   "at": upload_gate.get("at") if uploaded else None},
    }


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CaseHub</title><style>
:root{color-scheme:dark;font:15px/1.45 system-ui,sans-serif;background:#101821;color:#e7edf2}
*{box-sizing:border-box}body{margin:0}header{padding:1rem 1.5rem;background:#172431;border-bottom:1px solid #304253;position:sticky;top:0;z-index:2}
h1{font-size:1.25rem;margin:0}h2{font-size:1.1rem;margin:0 0 .7rem}h3{font-size:1rem;margin:.3rem 0}p{margin:.35rem 0 .8rem}
.muted{color:#aab8c5}.bar{display:flex;gap:1rem;flex-wrap:wrap;align-items:center}.scope{max-width:70rem;white-space:pre-wrap}
nav{display:flex;gap:.4rem;padding:.8rem 1.5rem;border-bottom:1px solid #304253;flex-wrap:wrap}
button,select,input{font:inherit;background:#233444;color:#edf3f6;border:1px solid #52677a;border-radius:.35rem;padding:.4rem .7rem}
button{cursor:pointer}button[aria-selected="true"]{background:#376b78;border-color:#81c5cc}button:hover{border-color:#9bd5dc}
main{padding:1.3rem 1.5rem;max-width:92rem;margin:auto}.panel{background:#172431;border:1px solid #304253;border-radius:.5rem;padding:1rem;margin:.7rem 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(18rem,1fr));gap:.7rem}.grid .panel{margin:0}
.badge{display:inline-block;padding:.1rem .45rem;margin:.1rem;border-radius:.3rem;border:1px solid #586b78;background:#263847}
.good{color:#abedc5;border-color:#459866}.warn{color:#ffe0a3;border-color:#b78636}.bad{color:#ffb9b5;border-color:#af5654}
.filters{display:flex;gap:.5rem;flex-wrap:wrap;margin:.7rem 0}.filters input{min-width:14rem}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.5rem;border-bottom:1px solid #304253;vertical-align:top}tr[data-id]{cursor:pointer}tr[data-id]:hover{background:#243849}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0d151d;padding:.8rem;border-radius:.3rem;max-height:35rem;overflow:auto}
.list{padding-left:1.2rem}.list li{margin:.4rem 0}.detail{margin-top:1rem}img{max-width:100%;max-height:25rem;object-fit:contain;border:1px solid #52677a}
[hidden]{display:none!important}a{color:#a3dce5}
</style></head><body>
<header><div class="bar"><h1>CaseHub</h1><span id="case-title" class="muted">Loading case…</span><span id="epoch" class="badge">Epoch unknown</span><span id="updated" class="muted"></span></div><div id="scope" class="scope muted"></div></header>
<nav aria-label="Views"><button data-tab="mission" aria-selected="true">Mission</button><button data-tab="inventory" aria-selected="false">Inventory</button><button data-tab="evidence" aria-selected="false">Evidence</button><button data-tab="report" aria-selected="false">Report</button></nav>
<main>
<section id="mission"><div id="mission-body"></div></section>
<section id="inventory" hidden><h2>Inventory</h2><div class="filters"><input id="entity-query" placeholder="Filter labels" aria-label="Filter inventory"><select id="entity-type" aria-label="Entity type"><option value="">All types</option></select><select id="entity-target" aria-label="Entity target"><option value="">All targets</option></select><select id="entity-level" aria-label="Evidence level"><option value="">All levels</option><option>captured</option><option>proposed</option><option>observed</option><option>verified</option><option>ruled_out</option></select><select id="entity-applicability" aria-label="Applicability"><option value="">All applicability</option><option>current</option><option>stale</option><option>revoked</option><option>unknown</option></select></div><div class="panel"><table><thead><tr><th>Type</th><th>Label</th><th>Target</th><th>Level</th><th>Applicability</th></tr></thead><tbody id="entity-rows"></tbody></table></div><div id="entity-detail" class="detail"></div></section>
<section id="evidence" hidden><h2>Evidence</h2><div class="filters"><select id="event-target" aria-label="Evidence target"><option value="">All targets</option></select><input id="event-stage" placeholder="Stage" aria-label="Stage"><input id="event-kind" placeholder="Kind" aria-label="Kind"><input id="event-limit" type="number" min="1" max="500" value="100" aria-label="Limit"><button id="event-refresh">Refresh</button></div><div class="panel"><table><thead><tr><th>Time</th><th>ID</th><th>Actor</th><th>Target / stage</th><th>Action / result</th></tr></thead><tbody id="event-rows"></tbody></table></div><div id="event-detail" class="detail"></div></section>
<section id="report" hidden><h2>Report</h2><div id="report-body"></div></section>
</main><script>
'use strict';
const $=id=>document.getElementById(id);
const node=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n};
const add=(parent,...children)=>{for(const child of children)parent.append(child);return parent};
const clear=n=>n.replaceChildren();
const badge=(label,ok)=>node('span',label,'badge '+(ok===true?'good':ok===false?'bad':'warn'));
const list=(items,render)=>{const ul=node('ul',undefined,'list');if(!items.length)add(ul,node('li','None','muted'));else items.forEach(x=>add(ul,render(x)));return ul};
const panel=(title)=>add(node('div',undefined,'panel'),node('h3',title));
const age=at=>{if(!at)return 'unknown';const seconds=Math.max(0,Math.floor((Date.now()-Date.parse(at))/1000));return seconds<60?seconds+' s ago':seconds<3600?Math.floor(seconds/60)+' min ago':Math.floor(seconds/3600)+' h ago'};
async function api(path){const r=await fetch(path,{cache:'no-store'});const body=await r.json();if(!r.ok)throw Error(body.error||r.statusText);return body}
function showError(parent,error){clear(parent);add(parent,node('div',error.message||String(error),'panel bad'))}
function fillTargets(ctx){for(const id of ['entity-target','event-target']){const sel=$(id),previous=sel.value;while(sel.options.length>1)sel.remove(1);for(const tid of Object.keys(ctx.targets)){const o=node('option',tid);o.value=tid;sel.add(o)}sel.value=previous}}
function mission(ctx){$('case-title').textContent=ctx.case.title+' · '+ctx.case.report_id;$('scope').textContent='Authorized scope: '+ctx.case.scope;$('epoch').textContent='Epoch: '+(ctx.epoch?.label||'unknown');$('updated').textContent='Updated '+new Date().toLocaleTimeString();fillTargets(ctx);const root=$('mission-body');clear(root);add(root,node('h2','Mission'));const grid=node('div',undefined,'grid');for(const [id,t] of Object.entries(ctx.targets)){const p=panel(t.name||id);add(p,node('p',[id,t.ip,t.role].filter(Boolean).join(' · '),'muted'),node('p',t.objective||''),node('p','Stages done: '+(t.stages_done.join(', ')||'none')),node('p','Stages missing: '+(t.stages_missing.join(', ')||'none')));add(p,badge('Proof '+(t.proof_recorded?'recorded':'missing'),t.proof_recorded),badge('Ready-submit '+(t.ready_submit?'ready':'missing'),t.ready_submit),badge('Accepted '+(t.accepted_capture?'captured':'missing'),t.accepted_capture));add(p,node('p','Running commands: '+(t.running_commands.join(', ')||'none')+' · Unresolved interrupted: '+(t.unresolved_interrupted.join(', ')||'none'),'muted'));add(grid,p)}if(!grid.children.length)add(grid,panel('No targets'));add(root,grid);
const sections=[['Actors',ctx.actors,a=>node('li',a.actor+' · heartbeat '+age(a.at)+' · '+(a.note||''))],['Live tasks',ctx.tasks.filter(t=>!['done','cancelled'].includes(t.state)),t=>node('li',t.state+' · '+(t.owner||'unassigned')+' · '+t.objective)],['Leases',ctx.leases,l=>node('li',l.resource+' · '+l.owner+' · '+(l.expired?'expired':'until '+l.expires_at))],['Open decisions',ctx.open_decisions,d=>node('li',d.question)],['Pending handoffs',ctx.pending_handoffs,h=>node('li',h.from_actor+' → '+(h.to_actor||'anyone')+' · '+(h.packet?.objective||''))],['Conflicting claims',ctx.conflicting_claims,c=>node('li',c.statement+' · conflicts with '+c.conflicts_with.join(', '))]];for(const [title,items,render] of sections){const p=panel(title);add(p,list(items,render));add(root,p)}}
async function inventory(){try{const params=new URLSearchParams();for(const [field,key] of [['entity-type','type'],['entity-target','target'],['entity-level','level'],['entity-applicability','applicability']])if($(field).value)params.set(key,$(field).value);const entities=await api('/api/entities?'+params);const types=new Set(entities.map(e=>e.type));const select=$('entity-type'),before=select.value;for(const type of types){if(![...select.options].some(o=>o.value===type)){const o=node('option',type);o.value=type;select.add(o)}}select.value=before;const q=$('entity-query').value.toLowerCase(),rows=$('entity-rows');clear(rows);for(const e of entities.filter(e=>(e.label||'').toLowerCase().includes(q))){const tr=node('tr');tr.dataset.id=e.id;for(const value of [e.type,e.label,e.target||'',e.level,e.applicability])add(tr,node('td',value));tr.addEventListener('click',()=>entityDetail(e.id));add(rows,tr)}}catch(e){showError($('entity-detail'),e)}}
async function entityDetail(id){const root=$('entity-detail');try{const e=await api('/api/entity/'+encodeURIComponent(id));clear(root);const p=panel(e.type+' · '+e.label);add(p,node('p','Level: '+e.level+' · Applicability: '+e.applicability+' · Target: '+(e.target||'none')));if(e.type==='secret_ref')add(p,node('p','Fingerprint: '+(e.fingerprint_prefix||'unknown')));else add(p,node('pre',JSON.stringify(e.attrs||{},null,2)));add(p,node('h3','Observations'),list(e.observations||[],o=>node('li',(o.statement||'Observation')+' · '+(o.source_events||[]).join(', '))));add(p,node('h3','Neighbors'),list(e.edges||[],edge=>node('li',(edge.src_entity?.label||edge.src)+' — '+edge.relation+' → '+(edge.dst_entity?.label||edge.dst))));add(p,node('h3','Claims'),list(e.claims||[],c=>node('li',c.state+' · '+c.statement)));add(root,p)}catch(e){showError(root,e)}}
async function timeline(){const root=$('event-rows');try{const params=new URLSearchParams();for(const [field,key] of [['event-target','target'],['event-stage','stage'],['event-kind','kind'],['event-limit','limit']])if($(field).value)params.set(key,$(field).value);const events=await api('/api/timeline?'+params);clear(root);for(const e of events){const tr=node('tr');tr.dataset.id=e.id;for(const value of [e.at,e.id,e.actor||'unknown',(e.target||'case')+' / '+(e.stage||'—'),e.kind+' · '+e.summary])add(tr,node('td',value));tr.addEventListener('click',()=>evidenceDetail(e.id));add(root,tr)}}catch(e){showError($('event-detail'),e)}}
async function evidenceDetail(id){const root=$('event-detail');try{const e=await api('/api/evidence/'+encodeURIComponent(id));clear(root);const p=panel(e.kind+' · '+e.id);add(p,node('p',e.at+' · '+(e.actor||'unknown')+' · '+(e.target||'case')+' / '+(e.stage||'—')),node('pre',e.body||e.summary));if(e.kind==='screenshot'){const img=node('img');img.src='/evidence-file/'+encodeURIComponent(e.id);img.alt=e.summary;add(p,img)}add(root,p)}catch(e){showError(root,e)}}
async function report(){const root=$('report-body');try{const r=await api('/api/report');clear(root);const p=panel('Validation');add(p,badge(r.valid?'Pass':'Blocked',r.valid),list(r.errors,e=>node('li',e)));add(root,p);const gates=panel('Target gates');for(const [tid,g] of Object.entries(r.gates)){const line=node('p',tid+' · missing stages: '+(g.stages_missing.join(', ')||'none')+' ');add(line,badge('Proof '+(g.proof_recorded?'recorded':'missing'),g.proof_recorded),badge('Ready '+(g.ready_submit?'ready':'missing'),g.ready_submit),badge('Accepted '+(g.accepted_capture?'captured':'missing'),g.accepted_capture));add(gates,line)}add(root,gates);const states=panel('Build, review, package, upload');for(const name of ['build','review','package','upload'])add(states,node('p',name[0].toUpperCase()+name.slice(1)+': '),badge(r[name].state,r[name].state!=='missing'));add(root,states)}catch(e){showError(root,e)}}
const loaders={mission:async()=>mission(await api('/api/context')),inventory,timeline,report};
async function select(tab){for(const button of document.querySelectorAll('nav button'))button.setAttribute('aria-selected',button.dataset.tab===tab?'true':'false');for(const section of document.querySelectorAll('main section'))section.hidden=section.id!==tab;try{if(tab==='evidence')await timeline();else await loaders[tab]()}catch(e){showError($(tab==='mission'?'mission-body':tab==='report'?'report-body':tab==='inventory'?'entity-detail':'event-detail'),e)}}
document.querySelectorAll('nav button').forEach(button=>button.addEventListener('click',()=>select(button.dataset.tab)));
for(const id of ['entity-query','entity-type','entity-target','entity-level','entity-applicability'])$(id).addEventListener(id==='entity-query'?'input':'change',inventory);
$('event-refresh').addEventListener('click',timeline);
select('mission');setInterval(async()=>{try{const ctx=await api('/api/context');mission(ctx)}catch(e){showError($('mission-body'),e)}},5000);
</script></body></html>'''


def create_server(root: Path | str, actor: str | None = None,
                  host: str = "127.0.0.1", port: int = 8765,
                  auto_extract: bool = True) -> ThreadingHTTPServer:
    """Create a loopback server; callers may start it in a thread for tests."""
    if host != "127.0.0.1":
        raise ValueError("Dashboard must bind to 127.0.0.1")
    root = Path(root).resolve()
    # Fail before starting a listener if the case does not exist.
    with CaseHub(root, actor=actor):
        pass
    return ThreadingHTTPServer((host, port), _handler(root, actor, auto_extract))


def _pending_evidence_ids(hub: CaseHub) -> list[str]:
    pending = []
    for event in hub.case()["events"]:
        evidence = hub.evidence(event["id"])
        if (evidence is None or evidence.get("sha256") != event.get("sha256")
                or evidence.get("payload") != event):
            pending.append(event["id"])
    return pending


def _sync_evidence(hub: CaseHub, auto_extract: bool) -> int:
    pending = _pending_evidence_ids(hub)
    synced = hub.sync_evidence()
    if synced > 0 and auto_extract:
        try:
            from .extract import extract_events
            with CaseHub(hub.root, actor="extractor") as extractor:
                extract_events(extractor, pending)
        except Exception as exc:
            print(f"casehub dashboard: automatic extraction failed: {exc}", file=sys.stderr)
    return synced


def _handler(root: Path, actor: str | None,
             auto_extract: bool = True) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            path = unquote(parsed.path)
            query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
            if path == "/":
                self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            try:
                with CaseHub(root, actor=actor) as hub:
                    _sync_evidence(hub, auto_extract)
                    if path == "/api/context":
                        result = hub.context()
                    elif path == "/api/entities":
                        result = [_safe_entity(e) for e in hub.entities(
                            type=query.get("type"), target=query.get("target"),
                            level=query.get("level"), applicability=query.get("applicability"))]
                    elif path.startswith("/api/entity/"):
                        result = _safe_entity(hub.entity(path.removeprefix("/api/entity/")))
                    elif path == "/api/timeline":
                        result = hub.timeline(target=query.get("target"), stage=query.get("stage"),
                                              kind=query.get("kind"), limit=self._limit(query))
                    elif path.startswith("/api/evidence/"):
                        result = hub.evidence(path.removeprefix("/api/evidence/"), with_body=True)
                    elif path == "/api/search":
                        result = hub.search(query.get("q", ""))
                        result["entities"] = [_safe_entity(e) for e in result["entities"]]
                    elif path == "/api/claims":
                        result = hub.claims()
                    elif path == "/api/tasks":
                        result = hub.tasks()
                    elif path == "/api/report":
                        result = _report(hub)
                    elif path.startswith("/evidence-file/"):
                        self._evidence_file(hub, path.removeprefix("/evidence-file/"))
                        return
                    else:
                        self._json(404, {"error": "Not found"})
                        return
                    if result is None:
                        self._json(404, {"error": "Not found"})
                    else:
                        self._json(200, result)
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
            except (CaseHubError, OSError, KeyError) as exc:
                self._json(500, {"error": str(exc)})

        def _limit(self, query: dict) -> int:
            value = int(query.get("limit", "100"))
            if not 1 <= value <= 500:
                raise ValueError("limit must be from 1 to 500")
            return value

        def _evidence_file(self, hub: CaseHub, event_id: str) -> None:
            evidence = hub.evidence(event_id)
            if not evidence or evidence["kind"] != "screenshot":
                self._json(404, {"error": "Screenshot not found"})
                return
            relative = evidence["payload"].get("file")
            if not relative:
                self._json(404, {"error": "Screenshot file not found"})
                return
            file = (root / relative).resolve()
            if not file.is_relative_to(root) or not file.is_file():
                self._json(404, {"error": "Screenshot file not found"})
                return
            mime = mimetypes.guess_type(file.name)[0]
            if mime not in ("image/png", "image/jpeg", "image/webp", "image/gif"):
                self._json(404, {"error": "Unsupported screenshot format"})
                return
            self._send(200, file.read_bytes(), mime)

        def _json(self, status: int, value: object) -> None:
            self._send(status, json.dumps(value, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            # Keep the server quiet during normal polling.
            return

    return Handler


def main(hub: CaseHub, args: argparse.Namespace) -> int:
    server = create_server(hub.root, actor=hub.actor, host=args.host, port=args.port,
                           auto_extract=not args.no_auto_extract)
    print(f"CaseHub dashboard: http://127.0.0.1:{server.server_port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", nargs="?", default=os.environ.get("REPORT_CASE"), help="report.py case directory (default: $REPORT_CASE)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-auto-extract", action="store_true",
                        help="sync new evidence without running extraction adapters")
    options = parser.parse_args()
    with CaseHub(options.case) as casehub:
        raise SystemExit(main(casehub, options))
