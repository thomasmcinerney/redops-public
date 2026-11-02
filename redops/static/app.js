(function(){const _f=window.fetch;window.fetch=function(u,o){o=o||{};
  const t=window.REDOPS_OPERATOR_TOKEN;
  if(t&&(typeof u==="string")&&(u.startsWith("/")||u.startsWith(location.origin))){
    o.headers=Object.assign({},o.headers,{"X-Redops-Operator":t});}
  return _f(u,o);};})();
/* RedOps frontend - vanilla JS, SSE live feed, no external assets. */
"use strict";

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// confirmation lifecycle: claimed (unverified assertion) -> observed (we saw it) ->
// confirmed (verified/exploited). A claimed fact reads dim; a confirmed one gets a ✓.
const STAGE_DOT = {
  claimed: '<span title="claimed — a source asserts it, unverified" style="color:var(--dim)">◍</span>',
  observed: '<span title="observed — we saw it ourselves" style="color:var(--steel,#6f8fb8)">◉</span>',
  confirmed: '<span title="confirmed — verified or exploited" style="color:var(--teal,#3fd0ee)">✓</span>',
};
const stageDot = (st) => STAGE_DOT[st] || STAGE_DOT.claimed;
const stageCls = (st) => (st === "claimed" ? "low" : "");   // claimed reads dim, like the old low

async function api(path, opts = {}) {
  if (opts.json !== undefined) {
    opts.method = opts.method || "POST";
    opts.headers = { "Content-Type": "application/json" };
    opts.body = JSON.stringify(opts.json);
    delete opts.json;
  }
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${path}: ${r.status} ${await r.text()}`);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
}

/* ---------------- tabs ---------------- */
document.querySelectorAll("nav button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $("#tab-" + b.dataset.tab).classList.add("active");
    history.replaceState(null, "", "#" + b.dataset.tab);
    refreshTab(b.dataset.tab);
  });
});
// deep-link: /#intel (etc.) — opened in init(), AFTER the engagement loads
function openHashTab() {
  const h = (location.hash || "").slice(1);
  if (h) { const b = document.querySelector(`nav button[data-tab="${h}"]`); if (b) { b.click(); return true; } }
  return false;
}

function refreshTab(name) {
  if (name === "targets") loadTargets();
  else if (name === "objtasks") { loadObjectives(); loadTasks(); }
  else if (name === "evidence") loadEvidence();
  else if (name === "sitrep") loadSitrepAll();
  else if (name === "map") loadMap();
  else if (name === "intel") loadIntel();
  else if (name === "leads") loadWorklist();
  else if (name === "arsenal") loadArsenal();
  else if (name === "manage") loadManage();
}

/* ---------------- engagement selector ---------------- */
async function loadEngagements() {
  const sel = $("#engsel");
  const [list, active] = await Promise.all([
    api("/api/engagements"), api("/api/active_engagement")]);
  sel.innerHTML = list.length
    ? list.map((e) => `<option value="${e.id}">#${e.id} ${esc(e.name)}</option>`).join("")
    : `<option value="">no engagements</option>`;
  if (list.length) {
    const valid = (id) => list.some((e) => e.id === Number(id));
    sel.value = valid(active.id) ? active.id : list[0].id;
    if (String(sel.value) !== String(active.id)) {
      await api("/api/active_engagement", { method: "PUT", json: { id: Number(sel.value) } });
    }
  } else if (!loadEngagements._prompted) {
    // fresh install / everything deleted: get the operator straight into creating one
    loadEngagements._prompted = true;
    newEngagementModal(async ({ name, scope, notes, copy_scope_from }) => {
      const e = await api("/api/engagements", { json: { name, scope, notes, copy_scope_from } });
      await loadEngagements();
      $("#engsel").value = e.id;
      $("#engsel").dispatchEvent(new Event("change"));
    });
  }
}
$("#engsel").addEventListener("change", async () => {
  await api("/api/active_engagement", { method: "PUT", json: { id: Number($("#engsel").value) } });
  loadTargets(); loadObjectives(); loadSitrepAll(); loadIntel(); loadMap(); loadFeed();
});
$("#eng-new").addEventListener("click", () => {
  newEngagementModal(async ({ name, scope, notes, copy_scope_from }) => {
    const e = await api("/api/engagements", { json: { name, scope, notes, copy_scope_from } });
    await loadEngagements();
    $("#engsel").value = e.id;
    $("#engsel").dispatchEvent(new Event("change"));
  });
});
const currentEngagement = () => $("#engsel").value || null;

/* ---------------- feed ---------------- */
let feedEvents = [];   // newest first
let ipById = {};

function feedFilters() {
  return { source: $("#f-source").value, kind: $("#f-kind").value, target: $("#f-target").value.trim() };
}
function feedMatch(e) {
  const f = feedFilters();
  if (f.source && e.source !== f.source) return false;
  if (f.kind && e.kind !== f.kind) return false;
  if (f.target) {
    const ip = e.target_id ? (ipById[e.target_id] || "") : "";
    if (!ip.includes(f.target)) return false;
  }
  return true;
}
function eventHtml(e) {
  const ip = e.target_id && ipById[e.target_id] ? ` <span class="badge kind">${esc(ipById[e.target_id])}</span>` : "";
  if (e.kind === "output") {
    let meta = {};
    try { meta = JSON.parse(e.meta_json || "{}"); } catch { }
    const cls = meta.isError ? "output error" : "output";
    const link = meta.overflow
      ? `<a class="overflow-link" href="/api/transcript/${encodeURIComponent(meta.overflow)}" target="_blank">full output (${meta.full_len || "?"} bytes)</a>`
      : "";
    return `<div class="event ${cls}">
      <span class="ts">${esc((e.ts || "").replace("T", " ").slice(0, 19))}</span>
      <span class="badge ${esc(e.source)}">${esc(e.source)}</span>
      <span class="badge kind">output</span>${ip}${link}
      <pre class="txt" title="click to expand/collapse">${esc(e.text)}</pre></div>`;
  }
  return `<div class="event ${esc(e.kind)}">
    <span class="ts">${esc((e.ts || "").replace("T", " ").slice(0, 19))}</span>
    <span class="badge ${esc(e.source)}">${esc(e.source)}</span>
    <span class="badge kind">${esc(e.kind)}</span>${ip}
    <span class="txt">${esc(e.text)}</span></div>`;
}
/* expand/collapse for output blocks (event delegation) */
$("#feedlist").addEventListener("click", (ev) => {
  const pre = ev.target.closest(".event.output pre.txt");
  if (pre) pre.classList.toggle("open");
});

/* capture health banner */
async function pollHealth() {
  try {
    const h = await api("/api/health");
    // read the ACTIVE capture mechanism (acp | wire), not just wire \u2014 otherwise
    // an ACP-live server false-alarms "no wire file".
    const cap = h.capture || { mechanism: "wire", status: (h.wire || {}).status };
    const b = $("#healthbanner");
    const BAD = ["stalled", "errors", "stale-read", "parse-errors", "auth"];
    if (BAD.includes(cap.status)) {
      b.textContent = `\u26A0 capture (${cap.mechanism || "wire"}): ${cap.status}`;
      b.style.display = "block";
    } else {
      b.style.display = "none";   // live / ok / off / disabled / no-file are fine
    }
  } catch { /* server unreachable - leave banner as-is */ }
}
setInterval(pollHealth, 15000);
pollHealth();
function renderFeed() {
  if (feedMode === "grouped") { renderTurns(); return; }
  const el = $("#feedlist");
  el.innerHTML = feedEvents.filter(feedMatch).map(eventHtml).join("") ||
    `<div class="event"><span class="txt" style="color:var(--dim)">no events yet</span></div>`;
  if ($("#f-scroll").checked) el.scrollTop = 0;
}
["#f-source", "#f-kind"].forEach((s) => $(s).addEventListener("change", renderFeed));
$("#f-target").addEventListener("input", renderFeed);

async function loadFeed() {
  const eng = currentEngagement();
  feedEvents = await api(`/api/events?limit=300&feed=1${eng ? `&engagement_id=${eng}` : ""}`);
  renderFeed();
}

/* ---- grouped (turn) mode ---- */
let feedMode = localStorage.getItem("redops.feedmode") || "grouped";
let turnsCache = [];
let turnOpenState = {};   // turn_id -> bool (user overrides; latest defaults open)
let lastTurnFetch = 0;

function setFeedMode(mode) {
  feedMode = mode;
  localStorage.setItem("redops.feedmode", mode);
  $("#mode-grouped").classList.toggle("active", mode === "grouped");
  $("#mode-raw").classList.toggle("active", mode === "raw");
  if (mode === "grouped") loadTurns(); else renderFeed();
}
$("#mode-grouped").addEventListener("click", () => setFeedMode("grouped"));
$("#mode-raw").addEventListener("click", () => setFeedMode("raw"));

async function loadTurns() {
  const d = await api("/api/turns?limit=15");
  turnsCache = d.turns || [];
  if (feedMode === "grouped") renderTurns();
}

function outBlock(e) {
  const meta = e.meta || {};
  const link = meta.overflow
    ? ` <a class="overflow-link" href="/api/transcript/${encodeURIComponent(meta.overflow)}" target="_blank">full output (${meta.full_len || "?"} bytes)</a>` : "";
  return `<details><summary>output${meta.isError ? " (error)" : ""}${link}</summary>
    <pre class="out-block ${meta.isError ? "err" : ""}">${esc(e.text)}</pre></details>`;
}

function turnCard(t, idx, total) {
  const reasoning = [], actions = [], texts = [], notes = [];
  const outputsByCall = {};
  const orphans = [];
  for (const e of t.events) {
    const meta = e.meta || {};
    if (e.kind === "reasoning") reasoning.push(e);
    else if (e.kind === "output") {
      if (meta.tool_call_id) outputsByCall[meta.tool_call_id] = e;
      else orphans.push(e);
    } else if (e.kind === "action" && String(meta.uuid || "").startsWith("tool_")) actions.push(e);
    else if (e.kind === "action") texts.push(e);
    else notes.push(e);
  }
  const paired = new Set(Object.keys(outputsByCall));
  const errors = t.events.filter((e) => (e.meta || {}).isError).length;
  const summary = `${reasoning.length} reasoning · ${actions.length} actions` +
    (errors ? ` · ${errors} errors` : "");
  const prompt = t.user_text || (t.turn_id === "ungrouped" ? "ungrouped events" : "agent work");
  const newest = total ? idx === total - 1 : idx === 0;
  const open = turnOpenState[t.turn_id] !== undefined ? turnOpenState[t.turn_id] : newest;
  // target filter: dim non-matching turns
  const tf = feedFilters().target;
  const dim = tf && !t.events.some((e) => (ipById[e.target_id] || "").includes(tf)) ? " dim" : "";

  const actionsHtml = actions.map((a) => {
    const out = outputsByCall[(a.meta || {}).uuid];
    if (out) paired.delete((a.meta || {}).uuid);
    return `<div class="turn-action"><div class="cmd">${esc(a.text)}</div>${out ? outBlock(out) : ""}</div>`;
  }).join("");
  const orphanList = orphans.concat([...paired].map((k) => outputsByCall[k]));
  const orphanHtml = orphanList
    .map((o) => `<div class="orphan-out ${((o.meta || {}).isError) ? "err" : ""}">${outBlock(o)}</div>`).join("");

  return `<div class="turn-card${open ? " open" : ""}${dim}" data-turn="${esc(t.turn_id)}">
    <div class="turn-head"><span class="prompt">${esc(prompt.slice(0, 120))}</span>
      <span class="summary">${summary}</span></div>
    <div class="turn-body">
      ${reasoning.length ? `<details><summary>reasoning (${reasoning.length})</summary>
        ${reasoning.map((r) => `<div class="rsn-block">${esc(r.text)}</div>`).join("")}</details>` : ""}
      ${actionsHtml}
      ${orphanHtml}
      ${texts.map((x) => `<div class="turn-reply">${esc(x.text)}</div>`).join("")}
      ${notes.map((n) => `<div class="turn-note">[${esc(n.source)} note] ${esc(n.text)}</div>`).join("")}
    </div></div>`;
}

function renderTurns() {
  const el = $("#feedlist");
  // chronological: oldest turn at top, newest at the bottom (terminal/report order).
  const ordered = [...turnsCache].reverse();
  el.innerHTML = ordered.map((t, i) => turnCard(t, i, ordered.length)).join("") ||
    `<div class="event"><span class="txt" style="color:var(--dim)">no turns yet</span></div>`;
  if ($("#f-scroll").checked) el.scrollTop = el.scrollHeight;  // follow the newest turn
}
$("#feedlist").addEventListener("click", (ev) => {
  const head = ev.target.closest(".turn-head");
  if (head) {
    const card = head.parentElement;
    card.classList.toggle("open");
    turnOpenState[card.dataset.turn] = card.classList.contains("open");
  }
});

/* throttled turn refresh for SSE */
function scheduleTurnRefresh() {
  if (feedMode !== "grouped") return;
  const now = Date.now();
  if (now - lastTurnFetch < 1500) {
    clearTimeout(scheduleTurnRefresh._t);
    scheduleTurnRefresh._t = setTimeout(loadTurns, 1600);
    return;
  }
  lastTurnFetch = now;
  loadTurns();
}

$("#note-send").addEventListener("click", async () => {
  const t = $("#note-text").value.trim();
  if (!t) return;
  await api("/api/events", { json: { source: "user", kind: "note", text: t } });
  $("#note-text").value = "";
});
$("#note-text").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#note-send").click(); });

$("#task-send").addEventListener("click", async () => {
  const t = $("#task-text").value.trim();
  if (!t) return;
  await api("/api/tasks", { json: { text: t, engagement_id: currentEngagement() } });
  $("#task-text").value = "";
});
$("#task-text").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#task-send").click(); });

/* ---------------- SSE ---------------- */
function connectStream() {
  const es = new EventSource("/api/stream");
  const live = $("#live");
  es.onopen = () => { live.textContent = "\u25CF feed live"; live.classList.add("on"); };
  es.onerror = () => { live.textContent = "\u25CF reconnecting"; live.classList.remove("on"); };
  es.onmessage = (m) => {
    let d;
    try { d = JSON.parse(m.data); } catch { return; }
    if (d.type === "event") {
      feedEvents.unshift(d.event);
      if (feedEvents.length > 600) feedEvents.pop();
      if (feedMode === "grouped") scheduleTurnRefresh(); else renderFeed();
    } else if (d.type === "change") {
      if ($("#tab-objtasks").classList.contains("active")) { loadObjectives(); loadTasks(); }
      if ($("#tab-sitrep").classList.contains("active")) loadSitrepAll();
      if ($("#tab-intel").classList.contains("active")) loadIntel();
      if ($("#tab-map").classList.contains("active")) loadMap();
      if ($("#tab-leads").classList.contains("active")) loadWorklist();
    }
  };
}

/* ---------------- targets ---------------- */
const TARGET_STATUSES = ["unidentified", "identified", "foothold", "rooted", "flagged"];

async function loadTargets() {
  ipById = {};
  const eng = currentEngagement();
  const targets = await api("/api/targets" + (eng ? `?engagement_id=${eng}` : ""));
  targets.forEach((t) => { ipById[t.id] = t.ip; });
  const el = $("#targetlist");
  if (!targets.length) { el.innerHTML = `<div class="panel">No targets for this engagement.</div>`; return; }
  el.innerHTML = targets.map((t) => `
    <div class="target-card" data-id="${t.id}">
      <div class="target-head">
        <span class="ip">${esc(t.ip)}</span>
        <span>${esc(t.hostname || "")}</span>
        <span style="color:var(--dim)">${esc(t.os || "")} ${esc(t.role || "")}</span>
        <span class="grow"></span>
        <select class="st-status st-${esc(t.status)}" data-id="${t.id}">
          ${TARGET_STATUSES.map((s) => `<option ${s === t.status ? "selected" : ""}>${s}</option>`).join("")}
        </select>
      </div>
      <div class="target-body">loading...</div>
    </div>`).join("");

  el.querySelectorAll(".target-head").forEach((h) => {
    h.addEventListener("click", async (e) => {
      if (e.target.tagName === "SELECT") return;
      const card = h.parentElement;
      card.classList.toggle("open");
      if (card.classList.contains("open")) await fillTargetDetail(card);
    });
  });
  el.querySelectorAll(".st-status").forEach((s) => {
    s.addEventListener("change", async () => {
      await api(`/api/targets/${s.dataset.id}`, { method: "PATCH", json: { status: s.value } });
      s.className = `st-status st-${s.value}`;
    });
  });
}

async function fillTargetDetail(card) {
  const id = card.dataset.id;
  const body = card.querySelector(".target-body");
  const [svcs, creds, finds, facts] = await Promise.all([
    api(`/api/services?target_id=${id}`),
    api(`/api/credentials?target_id=${id}`),
    api(`/api/findings?target_id=${id}`),
    api(`/api/facts${currentEngagement() ? `?engagement_id=${currentEngagement()}` : ""}`),
  ]);
  const t = await api(`/api/targets`);
  const me = t.find((x) => String(x.id) === String(id)) || {};
  const names = [me.ip, me.hostname].filter(Boolean).map((s) => s.toLowerCase());
  const relFacts = facts.filter((f) =>
    names.some((n) => (f.subject_name || "").toLowerCase().includes(n) ||
                      (f.object_name || "").toLowerCase().includes(n) ||
                      (f.object_text || "").toLowerCase() === n));
  body.innerHTML = `
    <h4>Services</h4>
    ${svcs.length ? `<table><tr><th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th><th>Info</th></tr>` +
      svcs.map((s) => `<tr><td>${s.port}</td><td>${esc(s.proto)}</td><td>${esc(s.name)}</td><td>${esc(s.product||"")}</td><td>${esc(s.version||"")}</td><td>${esc(s.extrainfo||"")}</td></tr>`).join("") +
      `</table>` : `<div style="color:var(--dim)">none</div>`}
    <h4>Credentials (click to unmask)</h4>
    ${creds.length ? `<table><tr><th>User</th><th>Secret</th><th>Kind</th><th>Status</th><th>Source</th><th>Valid</th></tr>` +
      creds.map((c) => `<tr><td>${c.username ? esc(c.username) : "&mdash;"}</td>
        <td>${c.secret ? `<span class="secret" data-secret="${esc(c.secret)}">&#9679;&#9679;&#9679;&#9679;&#9679;&#9679;</span>` : "&mdash;"}</td>
        <td>${esc(c.kind)}</td><td>${esc(c.status || "untested")}</td><td>${esc(c.source)}</td><td>${c.valid ? "yes" : "no"}</td></tr>`).join("") +
      `</table>` : `<div style="color:var(--dim)">none</div>`}
    <h4>Findings</h4>
    ${finds.length ? `<table><tr><th>#</th><th>Severity</th><th>Title</th><th>Status</th></tr>` +
      finds.map((f) => `<tr><td>${f.id}</td><td class="sev-${esc(f.severity)}">${esc(f.severity)}</td>
        <td title="${esc(f.description)}">${esc(f.title)}</td><td>${esc(f.status)}</td></tr>`).join("") +
      `</table>` : `<div style="color:var(--dim)">none</div>`}
    <h4>Facts</h4>
    ${relFacts.length ? relFacts.map((f) => {
      const obj = f.object_name || f.object_text || "?";
      return `<div class="fact-line ${stageCls(f.stage)} ${f.status === "ruled-out" ? "ruled" : ""}">
        ${stageDot(f.stage)} <b>${esc(f.subject_name)}</b> <span class="pred">-${esc(f.predicate)}-&gt;</span> ${esc(obj)}</div>`;
    }).join("") : `<div style="color:var(--dim)">none</div>`}`;
  body.querySelectorAll(".secret").forEach((td) => {
    td.addEventListener("click", () => {
      td.textContent = td.textContent.includes("\u25CF") ? td.dataset.secret : "\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF";
    });
  });
}

$("#nt-add").addEventListener("click", async () => {
  const ip = $("#nt-ip").value.trim();
  if (!ip) return;
  // operator-added = a host you KNOW exists, so it lands identified (visible +
  // interactable), not fogged as an unknown "?" you can't click.
  await api("/api/targets", { json: {
    ip, hostname: $("#nt-host").value.trim(), os: $("#nt-os").value.trim(),
    role: $("#nt-role").value.trim(), status: "identified",
    engagement_id: Number(currentEngagement()) || null } });
  ["#nt-ip", "#nt-host", "#nt-os", "#nt-role"].forEach((s) => { $(s).value = ""; });
  loadTargets();
});

/* ---------------- objectives & tasks ---------------- */
async function loadObjectives() {
  const eng = currentEngagement();
  const objs = await api("/api/objectives" + (eng ? `?engagement_id=${eng}` : ""));
  $("#objtable").innerHTML = objs.length
    ? `<tr><th>#</th><th>Objective</th><th>Value</th><th>Status</th><th></th></tr>` + objs.map((o) =>
      `<tr class="${o.status === "done" ? "obj-done" : ""}"><td>${o.id}</td><td>${esc(o.text)}</td>
       <td>${esc(o.value || "")}</td><td>${esc(o.status)}</td>
       <td>${o.status !== "done" ? `<button class="act obj-done-btn" data-id="${o.id}">complete</button>` : ""}</td></tr>`).join("")
    : `<tr><td style="color:var(--dim)">no objectives</td></tr>`;
  document.querySelectorAll(".obj-done-btn").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/objectives/${b.dataset.id}`, { method: "PATCH", json: { status: "done" } });
    loadObjectives();
  }));
}
$("#obj-add").addEventListener("click", async () => {
  const t = $("#obj-text").value.trim();
  if (!t) return;
  await api("/api/objectives", { json: {
    text: t, value: $("#obj-value").value.trim(),
    engagement_id: Number(currentEngagement()) || null } });
  $("#obj-text").value = ""; $("#obj-value").value = "";
  loadObjectives();
});

async function loadTasks() {
  const eng = currentEngagement();
  const tasks = await api(`/api/tasks${eng ? `?engagement_id=${eng}` : ""}`);
  $("#tasktable").innerHTML = tasks.length
    ? `<tr><th>#</th><th>Task</th><th>Author</th><th>Status</th><th></th></tr>` + tasks.map((t) =>
      `<tr class="${t.status === "done" ? "task-done" : ""}"><td>${t.id}</td><td>${esc(t.text)}</td>
       <td>${esc(t.author)}</td><td>${esc(t.status)}</td>
       <td>${t.status === "pending" ? `<button class="act task-done-btn" data-id="${t.id}">mark done</button>` : esc(t.done_at || "")}</td></tr>`).join("")
    : `<tr><td style="color:var(--dim)">no tasks</td></tr>`;
  document.querySelectorAll(".task-done-btn").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/tasks/${b.dataset.id}/done`, { method: "POST" });
    loadTasks();
  }));
}

/* ---------------- evidence ---------------- */
const IMG_RE = /\.(png|jpe?g|gif|webp|bmp)$/i;
async function loadEvidence() {
  const eng = currentEngagement();
  const ev = await api(`/api/evidence${eng ? `?engagement_id=${eng}` : ""}`);
  $("#evgrid").innerHTML = ev.length ? ev.map((e) => `
    <div class="ev-card">
      ${IMG_RE.test(e.path)
        ? `<a href="/api/evidence/${e.id}/file" target="_blank"><img src="/api/evidence/${e.id}/file" loading="lazy"></a>`
        : `<a href="/api/evidence/${e.id}/file" target="_blank"><div class="fileicon">&#128196;</div></a>`}
      <div class="meta">#${e.id} ${esc(e.caption || e.path)}<br>
        ${e.finding_id ? `finding #${e.finding_id} ` : ""}${e.target_id ? `target #${e.target_id}` : ""}</div>
    </div>`).join("") : `<div class="panel">No evidence yet.</div>`;
}
$("#ev-upload").addEventListener("click", async () => {
  const f = $("#ev-file").files[0];
  if (!f) return;
  const fd = new FormData();
  fd.append("file", f);
  if ($("#ev-finding").value.trim()) fd.append("finding_id", $("#ev-finding").value.trim());
  if ($("#ev-target").value.trim()) fd.append("target_id", $("#ev-target").value.trim());
  fd.append("caption", $("#ev-caption").value.trim());
  const r = await fetch("/api/evidence", { method: "POST", body: fd });
  if (!r.ok) { alert("upload failed: " + await r.text()); return; }
  $("#ev-file").value = ""; $("#ev-caption").value = "";
  loadEvidence();
});

/* ---------------- report ---------------- */
async function download(fmt) {
  const eng = currentEngagement();
  if (!eng) return;
  const text = await api(`/api/export/${eng}?fmt=${fmt}`);
  const blob = new Blob([text], { type: fmt === "html" ? "text/html" : "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `redops-engagement-${eng}.${fmt === "html" ? "html" : "md"}`;
  a.click();
  URL.revokeObjectURL(a.href);
}
$("#rep-dl-md").addEventListener("click", () => download("md"));
$("#rep-dl-html").addEventListener("click", () => download("html"));
$("#rep-gen").addEventListener("click", async () => {
  const eng = currentEngagement();
  if (!eng) { $("#reportview").innerHTML = `<pre>No engagement selected.</pre>`; return; }
  const html = await api(`/api/export/${eng}?fmt=html`);
  const blob = new Blob([html], { type: "text/html" });
  $("#reportview").innerHTML = `<iframe src="${URL.createObjectURL(blob)}"></iframe>`;
});

/* ---------------- sitrep ---------------- */
async function loadSitrepAll() {
  const eng = currentEngagement();
  if (!eng) return;
  const [sr, opps, facts, tasks, scope] = await Promise.all([
    api(`/api/sitrep/${eng}`),
    api(`/api/opportunities?engagement_id=${eng}`),
    api(`/api/facts?engagement_id=${eng}`),
    api(`/api/tasks?status=pending&engagement_id=${eng}`),
    api(`/api/scope/${eng}`),
  ]);
  if (document.activeElement !== $("#sr-intent")) $("#sr-intent").value = sr.commander_intent || "";
  if (document.activeElement !== $("#scope-in")) $("#scope-in").value = (scope.in || []).join(", ");
  if (document.activeElement !== $("#scope-out")) $("#scope-out").value = (scope.out || []).join(", ");
  if (document.activeElement !== $("#sr-activity")) $("#sr-activity").value = sr.activity || "";
  if (document.activeElement !== $("#sr-hypothesis")) $("#sr-hypothesis").value = sr.hypothesis || "";
  if (document.activeElement !== $("#sr-next")) $("#sr-next").value = sr.next_steps || "";
  $("#sr-updated").textContent = sr.updated_at ? `updated ${sr.updated_at}` : "";

  const visible = opps.filter((o) => o.status === "open" || o.status === "pinned");
  $("#opp-list").innerHTML = visible.length ? visible.map((o) => `
    <div class="opp-card ${o.status}">
      <span class="opp-title">${esc(o.title)}</span><span class="opp-rule">${esc(o.rule)}</span>
      <div class="opp-rationale">${esc(o.rationale)}</div>
      <div>
        ${o.status !== "pinned" ? `<button class="act opp-act" data-id="${o.id}" data-act="pin">pin</button>` : ""}
        <button class="act opp-act" data-id="${o.id}" data-act="convert">convert to task</button>
        <button class="act opp-act" data-id="${o.id}" data-act="dismiss">dismiss</button>
      </div>
    </div>`).join("") : `<div style="color:var(--dim)">no open opportunities</div>`;
  document.querySelectorAll(".opp-act").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/opportunities/${b.dataset.id}/${b.dataset.act}`, { method: "POST" });
    loadSitrepAll();
  }));

  const factLine = (f) => {
    const obj = f.object_name || f.object_text || "?";
    return `<div class="fact-line ${stageCls(f.stage)}">
      ${stageDot(f.stage)} <b>${esc(f.subject_name)}</b> <span class="pred">-${esc(f.predicate)}-&gt;</span> ${esc(obj)}
      <span style="color:var(--dim);font-size:11px"> #${f.id} ${esc(f.source)}</span></div>`;
  };
  const active = facts.filter((f) => f.status === "active");
  const rank = { confirmed: 0, observed: 1, claimed: 2 };
  const recent = [...active].sort((a, b) => (rank[a.stage] ?? 3) - (rank[b.stage] ?? 3)).slice(0, 15);
  $("#recent-facts").innerHTML = recent.map(factLine).join("") ||
    `<div style="color:var(--dim)">no facts yet</div>`;
  const ruled = facts.filter((f) => f.status === "ruled-out").slice(0, 15);
  $("#ruledout-facts").innerHTML = ruled.map((f) =>
    factLine(f).replace('class="fact-line', 'class="fact-line ruled')).join("") ||
    `<div style="color:var(--dim)">none</div>`;
  $("#pending-tasks").innerHTML = tasks.length
    ? tasks.map((t) => `<div class="fact-line">#${t.id} ${esc(t.text)}</div>`).join("")
    : `<div style="color:var(--dim)">no pending tasks</div>`;
}

$("#sr-save").addEventListener("click", async () => {
  const eng = currentEngagement();
  if (!eng) return;
  await api(`/api/sitrep/${eng}`, { method: "PUT", json: {
    activity: $("#sr-activity").value, hypothesis: $("#sr-hypothesis").value,
    next_steps: $("#sr-next").value } });
  loadSitrepAll();
});

$("#sr-intent-save").addEventListener("click", async () => {
  const eng = currentEngagement();
  if (!eng) return;
  await api(`/api/sitrep/${eng}/intent`, { method: "PUT", json: { text: $("#sr-intent").value } });
  loadSitrepAll();
});

$("#scope-save").addEventListener("click", async () => {
  const eng = currentEngagement();
  if (!eng) return;
  const parse = (v) => v.split(",").map((s) => s.trim()).filter(Boolean);
  await api(`/api/scope/${eng}`, { method: "PUT", json: {
    in: parse($("#scope-in").value), out: parse($("#scope-out").value) } });
  loadSitrepAll();
});

/* ---------------- intel ---------------- */
let intelFacts = [];

async function loadIntel() {
  const eng = currentEngagement();
  intelFacts = eng ? await api(`/api/facts?engagement_id=${eng}`) : [];
  renderIntel();
}

function renderIntel() {
  const text = $("#ff-text").value.trim().toLowerCase();
  const pred = $("#ff-pred").value.trim().toLowerCase();
  const conf = $("#ff-conf").value;
  const status = $("#ff-status").value;
  const rows = intelFacts.filter((f) => {
    const obj = (f.object_name || f.object_text || "").toLowerCase();
    if (text && !(f.subject_name.toLowerCase().includes(text) || obj.includes(text))) return false;
    if (pred && !f.predicate.toLowerCase().includes(pred)) return false;
    if (conf && f.stage !== conf) return false;
    if (status && f.status !== status) return false;
    return true;
  });
  const active = intelFacts.filter((f) => f.status === "active");
  const byStage = (s) => active.filter((f) => f.stage === s).length;
  const ruled = intelFacts.filter((f) => f.status === "ruled-out").length;
  $("#intel-summary").innerHTML =
    `${active.length} active fact${active.length === 1 ? "" : "s"} ` +
    `&middot; ${byStage("claimed")} claimed &middot; ${byStage("observed")} observed ` +
    `&middot; ${byStage("confirmed")} confirmed &middot; ${ruled} ruled out ` +
    `&nbsp;&mdash;&nbsp; showing ${rows.length}`;
  $("#facttable").innerHTML = rows.length
    ? `<tr><th>#</th><th>Subject</th><th>Type</th><th>Predicate</th><th>Object</th>
       <th>Stage</th><th>Source</th><th>Status</th><th></th></tr>` + rows.map((f) =>
      `<tr class="${stageCls(f.stage) ? "fact-line low" : ""}"><td>${f.id}</td>
       <td>${esc(f.subject_name)}</td><td>${esc(f.subject_type)}</td>
       <td class="editable" data-id="${f.id}" data-field="predicate" title="click to edit">${esc(f.predicate)}</td>
       <td class="editable" data-id="${f.id}" data-field="object_text" title="click to edit">${esc(f.object_name || f.object_text || "")}</td>
       <td>${stageDot(f.stage)} ${esc(f.stage)}</td>
       <td>${esc(f.source)}</td><td>${esc(f.status)}</td>
       <td>${f.status === "active" ? `<button class="act rule-out" data-id="${f.id}">rule out</button>` : ""}</td></tr>`).join("")
    : `<tr><td style="color:var(--dim)">no facts match</td></tr>`;
  document.querySelectorAll(".rule-out").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/facts/${b.dataset.id}`, { method: "PATCH", json: { status: "ruled-out" } });
    loadIntel();
  }));
  document.querySelectorAll("td.editable").forEach((td) => td.addEventListener("click", () => {
    if (td.querySelector("input")) return;
    const old = td.textContent;
    const input = document.createElement("input");
    input.value = old;
    td.textContent = "";
    td.appendChild(input);
    input.focus();
    input.select();
    const save = async () => {
      const val = input.value.trim();
      if (val && val !== old) {
        await api(`/api/facts/${td.dataset.id}`, { method: "PATCH", json: { [td.dataset.field]: val } });
      }
      loadIntel();
    };
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") input.blur(); if (e.key === "Escape") loadIntel(); });
    input.addEventListener("blur", save);
  }));
}
["#ff-text", "#ff-pred"].forEach((s) => $(s).addEventListener("input", renderIntel));
["#ff-conf", "#ff-status"].forEach((s) => $(s).addEventListener("change", renderIntel));

$("#fa-add").addEventListener("click", async () => {
  const subject = $("#fa-subject").value.trim();
  const predicate = $("#fa-predicate").value.trim();
  const object = $("#fa-object").value.trim();
  if (!subject || !predicate || !object) return;
  const body = { engagement_id: Number(currentEngagement()) || null,
    subject_name: subject, predicate, stage: $("#fa-stage").value, source: "user" };
  if ($("#fa-stype").value) body.subject_type = $("#fa-stype").value;
  if (object.includes(" ")) body.object_text = object;
  else { body.object_name = object; }
  await api("/api/facts", { json: body });
  $("#fa-subject").value = ""; $("#fa-object").value = "";
  loadIntel();
});

/* ---------------- map ---------------- */
const MAP_COLS = [["network"], ["host"], ["agent", "model"], ["service", "endpoint"],
                  ["rag-store", "collection", "prompt"], ["file", "config"],
                  ["user", "credential", "token"], ["privilege"]];
let mapView = { x: 0, y: 0, w: 1000, h: 600 };

function mapNodeFacts(id) {
  const eng = currentEngagement();
  return api(`/api/facts?engagement_id=${eng}`).then((facts) => {
    const rel = facts.filter((f) => f.subject_id === id || f.object_id === id);
    $("#map-detail-body").innerHTML = rel.length ? rel.map((f) => {
      const obj = f.object_name || f.object_text || "?";
      return `<div class="fact-line ${f.status === "ruled-out" ? "ruled" : ""} ${stageCls(f.stage)}">
        ${stageDot(f.stage)} <b>${esc(f.subject_name)}</b> <span class="pred">-${esc(f.predicate)}-&gt;</span> ${esc(obj)}</div>`;
    }).join("") : `<span style="color:var(--dim)">no facts for this node</span>`;
  });
}

async function loadMap() {
  const eng = currentEngagement();
  const svg = $("#mapsvg");
  if (!eng) { svg.innerHTML = ""; return; }
  // reset pan/zoom so the graph is always framed on load
  mapView = { x: 0, y: 0, w: 1000, h: 600 };
  svg.setAttribute("viewBox", "0 0 1000 600");
  const g = await api(`/api/graph?engagement_id=${eng}`);
  const byId = Object.fromEntries(g.nodes.map((n) => [n.id, n]));
  // layout: column per type-group, nodes stacked
  const colW = 1000 / MAP_COLS.length;
  const pos = {};
  const NS = "http://www.w3.org/2000/svg";
  svg.innerHTML = "";
  const root = document.createElementNS(NS, "g");
  svg.appendChild(root);

  MAP_COLS.forEach((types, ci) => {
    const label = document.createElementNS(NS, "text");
    label.setAttribute("class", "col-label");
    label.setAttribute("x", ci * colW + 8); label.setAttribute("y", 18);
    label.textContent = types.join(" / ");
    root.appendChild(label);
    const colNodes = g.nodes.filter((n) => types.includes(n.type));
    colNodes.forEach((n, i) => {
      pos[n.id] = { x: ci * colW + 10, y: 34 + i * 46, w: colW - 30, h: 34 };
    });
    // nodes of unmapped types go in last column
    if (ci === MAP_COLS.length - 1) {
      g.nodes.filter((n) => !MAP_COLS.flat().includes(n.type)).forEach((n, i) => {
        pos[n.id] = { x: 5 * colW + 10, y: 34 + (colNodes.length + i) * 46, w: colW - 30, h: 34 };
      });
    }
  });

  // edges first (under nodes)
  g.edges.forEach((e) => {
    const a = pos[e.from], b = e.to ? pos[e.to] : null;
    if (!a) return;
    const line = document.createElementNS(NS, "path");
    const x1 = a.x + a.w, y1 = a.y + a.h / 2;
    let x2, y2, labelX, labelY;
    if (b) {
      x2 = b.x; y2 = b.y + b.h / 2;
    } else {
      // text-only object: short stub edge to the right
      x2 = Math.min(a.x + a.w + 40, 990); y2 = y1;
    }
    labelX = (x1 + x2) / 2; labelY = (y1 + y2) / 2 - 3;
    line.setAttribute("d", `M ${x1} ${y1} C ${x1 + 30} ${y1}, ${x2 - 30} ${y2}, ${x2} ${y2}`);
    line.setAttribute("class", "edge" + (e.in_opportunity ? " opp" : "") + (e.status === "ruled-out" ? " ruled" : ""));
    root.appendChild(line);
    const t = document.createElementNS(NS, "text");
    t.setAttribute("class", "edge-label");
    t.setAttribute("x", labelX); t.setAttribute("y", labelY);
    t.setAttribute("text-anchor", "middle");
    t.textContent = e.predicate + (!b && e.to_text ? `: ${e.to_text.slice(0, 20)}` : "");
    root.appendChild(t);
  });

  g.nodes.forEach((n) => {
    const p = pos[n.id];
    if (!p) return;
    const gEl = document.createElementNS(NS, "g");
    gEl.setAttribute("class", "node");
    const rect = document.createElementNS(NS, "rect");
    rect.setAttribute("x", p.x); rect.setAttribute("y", p.y);
    rect.setAttribute("width", p.w); rect.setAttribute("height", p.h);
    const t = document.createElementNS(NS, "text");
    t.setAttribute("x", p.x + 6); t.setAttribute("y", p.y + 14);
    t.textContent = n.name.length > 22 ? n.name.slice(0, 21) + "…" : n.name;
    const t2 = document.createElementNS(NS, "text");
    t2.setAttribute("x", p.x + 6); t2.setAttribute("y", p.y + 27);
    t2.setAttribute("class", "col-label");
    t2.textContent = n.label || n.type;
    gEl.appendChild(rect); gEl.appendChild(t); gEl.appendChild(t2);
    gEl.addEventListener("click", () => {
      $("#map-detail-body").innerHTML = `<b>${esc(n.name)}</b> <span class="col-label">${esc(n.type)}</span><hr style="border-color:var(--border)">`;
      mapNodeFacts(n.id);
    });
    root.appendChild(gEl);
  });
}

/* pan/zoom on the map svg */
(() => {
  const svg = $("#mapsvg");
  let drag = null;
  const apply = () => svg.setAttribute("viewBox", `${mapView.x} ${mapView.y} ${mapView.w} ${mapView.h}`);
  svg.addEventListener("mousedown", (e) => { drag = { x: e.clientX, y: e.clientY, vx: mapView.x, vy: mapView.y }; });
  window.addEventListener("mousemove", (e) => {
    if (!drag) return;
    mapView.x = drag.vx - (e.clientX - drag.x) * mapView.w / svg.clientWidth;
    mapView.y = drag.vy - (e.clientY - drag.y) * mapView.h / svg.clientHeight;
    apply();
  });
  window.addEventListener("mouseup", () => { drag = null; });
  svg.addEventListener("wheel", (e) => {
    e.preventDefault();
    const k = e.deltaY > 0 ? 1.15 : 1 / 1.15;
    mapView.w = Math.min(4000, Math.max(200, mapView.w * k));
    mapView.h = mapView.w * 0.6;
    apply();
  }, { passive: false });
})();

/* ---------------- leads / worklist ---------------- */
async function loadWorklist() {
  const eng = currentEngagement();
  if (!eng) return;
  const items = await api(`/api/worklist?engagement_id=${eng}`);
  $("#worklist-table").innerHTML = items.length
    ? `<tr><th>Score</th><th>Kind</th><th>Category</th><th>Item</th><th></th></tr>` +
      items.map((it) => `<tr>
        <td><b>${it.score.toFixed(1)}</b></td>
        <td>${esc(it.kind)}${it.rule ? ` <span style="color:var(--dim)">${esc(it.rule)}</span>` : ""}</td>
        <td><span class="badge kind">${esc(it.category)}</span>
            ${it.detected ? `<span title="detection tripwire fired" style="color:var(--err)">&#9762;</span>` : ""}</td>
        <td>${esc(it.title)}${it.rationale ? `<div style="color:var(--dim);font-size:12px">${esc(it.rationale)}</div>` : ""}</td>
        <td>${it.kind === "lead" ? `
          <button class="act lead-act" data-id="${it.id}" data-act="promote">promote</button>
          <button class="act lead-act" data-id="${it.id}" data-act="dismiss">dismiss</button>
          <button class="act lead-act" data-id="${it.id}" data-act="rule-out">rule out</button>` : ""}</td>
      </tr>`).join("")
    : `<tr><td style="color:var(--dim)">worklist empty</td></tr>`;
  document.querySelectorAll(".lead-act").forEach((b) => b.addEventListener("click", async () => {
    const body = b.dataset.act === "promote" ? { facts: [] } : undefined;
    await api(`/api/leads/${b.dataset.id}/${b.dataset.act}`,
              body ? { json: body } : { method: "POST" });
    loadWorklist();
  }));
}

$("#la-add").addEventListener("click", async () => {
  const obs = $("#la-obs").value.trim();
  if (!obs) return;
  await api("/api/leads", { json: {
    observation: obs, category: $("#la-cat").value, candidate_vector: $("#la-vec").value.trim(),
    engagement_id: Number(currentEngagement()) || null } });
  $("#la-obs").value = ""; $("#la-vec").value = "";
  loadWorklist();
});

/* ---------------- arsenal: payloads / rules / poison ---------------- */
const OUTCOME_COL = { worked: "var(--ok,#45d6a0)", failed: "var(--dim)", blocked: "var(--err)", untried: "var(--dim)" };

async function loadArsenal() {
  const eng = currentEngagement();
  if (!eng) return;
  const [pl, ru, po] = await Promise.all([
    api(`/api/payloads?engagement_id=${eng}`),
    api(`/api/detection_rules?engagement_id=${eng}`),
    api(`/api/poison?engagement_id=${eng}`),
  ]);
  $("#payloads-table").innerHTML = pl.length
    ? `<tr><th>Technique</th><th>Model</th><th>Guardrail</th><th>Outcome</th><th>Body</th></tr>` +
      pl.map((p) => `<tr><td>${esc(p.technique)}</td><td>${esc(p.target_model)}</td>
        <td>${esc(p.guardrail_defeated)}</td>
        <td style="color:${OUTCOME_COL[p.outcome] || "var(--dim)"}">${esc(p.outcome)}</td>
        <td style="color:var(--dim);font-size:12px">${esc((p.body || "").slice(0, 80))}</td></tr>`).join("")
    : `<tr><td style="color:var(--dim)">no payloads saved</td></tr>`;
  $("#rules-table").innerHTML = ru.length
    ? `<tr><th>Rule</th><th>Source</th><th>Mechanism</th><th>Blind spot</th><th>Evasion</th><th>Fired</th></tr>` +
      ru.map((r) => `<tr><td>${esc(r.name)}</td><td>${esc(r.source_system)}</td>
        <td>${esc(r.match_mechanism)}</td><td>${esc(r.blind_spot)}</td><td>${esc(r.evasion)}</td>
        <td>${r.fired ? `<span style="color:var(--err)">yes</span>` : "no"}</td></tr>`).join("")
    : `<tr><td style="color:var(--dim)">no rules catalogued</td></tr>`;
  $("#poison-table").innerHTML = po.length
    ? `<tr><th>Store</th><th>Location</th><th>State</th><th>Verify</th><th>Cleaned</th></tr>` +
      po.map((p) => `<tr><td>${esc(p.store_type)}</td><td>${esc(p.location)}</td>
        <td>${p.live ? `<span style="color:var(--err)">live</span>` : "removed"}</td>
        <td style="color:var(--dim);font-size:12px">${esc(p.verify_method)}</td>
        <td><input type="checkbox" class="poison-clean" data-id="${p.id}" ${p.cleanup_done ? "checked" : ""}></td></tr>`).join("")
    : `<tr><td style="color:var(--dim)">nothing planted</td></tr>`;
  document.querySelectorAll(".poison-clean").forEach((cb) => cb.addEventListener("change", async () => {
    await api(`/api/poison/${cb.dataset.id}`, { method: "PATCH", json: { cleanup_done: cb.checked, live: !cb.checked } });
    loadArsenal();
  }));
}

$("#pa-add").addEventListener("click", async () => {
  const technique = $("#pa-tech").value.trim();
  if (!technique) return;
  await api("/api/payloads", { json: {
    technique, target_model: $("#pa-model").value.trim(), guardrail_defeated: $("#pa-guard").value.trim(),
    outcome: $("#pa-outcome").value, body: $("#pa-body").value.trim(),
    engagement_id: Number(currentEngagement()) || null } });
  $("#pa-tech").value = ""; $("#pa-model").value = ""; $("#pa-guard").value = ""; $("#pa-body").value = "";
  loadArsenal();
});

$("#ra-add").addEventListener("click", async () => {
  const name = $("#ra-name").value.trim();
  if (!name) return;
  await api("/api/detection_rules", { json: {
    name, source_system: $("#ra-src").value.trim(), match_mechanism: $("#ra-match").value.trim(),
    blind_spot: $("#ra-blind").value.trim(), evasion: $("#ra-evade").value.trim(),
    fired: $("#ra-fired").checked, engagement_id: Number(currentEngagement()) || null } });
  $("#ra-name").value = ""; $("#ra-match").value = ""; $("#ra-blind").value = ""; $("#ra-evade").value = ""; $("#ra-fired").checked = false;
  loadArsenal();
});

$("#poa-add").addEventListener("click", async () => {
  const location = $("#poa-loc").value.trim();
  if (!location) return;
  await api("/api/poison", { json: {
    location, store_type: $("#poa-store").value, verify_method: $("#poa-verify").value.trim(),
    engagement_id: Number(currentEngagement()) || null } });
  $("#poa-loc").value = ""; $("#poa-verify").value = "";
  loadArsenal();
});

/* ---------------- manage ---------------- */
let mngShowArchived = false;

async function loadManage() {
  await Promise.all([loadManageEngagements(), loadManageSettings(), loadManageStatus()]);
}

function fmtBytes(n) {
  if (n == null) return "—";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

async function loadManageEngagements() {
  const [list, active] = await Promise.all([
    api(`/api/engagements?include_archived=1&with_counts=1`), api("/api/active_engagement")]);
  const rows = list.filter((e) => mngShowArchived || !e.archived_at);
  const el = $("#mng-englist");
  if (!rows.length) { el.innerHTML = `<p class="muted">No engagements.</p>`; return; }
  el.innerHTML = `<table><thead><tr>
      <th></th><th>Name</th><th>Scope</th><th>Hosts</th><th>Facts</th><th>Events</th>
      <th>Findings</th><th>Created</th><th></th></tr></thead><tbody>${
    rows.map((e) => {
      const isActive = active.id === e.id;
      const c = e.counts || {};
      const created = (e.created_at || "").slice(0, 10);
      return `<tr class="engrow ${isActive ? "active-row" : ""} ${e.archived_at ? "archived" : ""}" data-id="${e.id}">
        <td>${isActive ? '<span class="dot-active" title="Active">●</span>' : ""}</td>
        <td class="editable eng-name" data-field="name" title="click to rename">${esc(e.name)}
          ${e.archived_at ? '<span class="tag arch">archived</span>' : (isActive ? '<span class="tag on">active</span>' : "")}</td>
        <td class="editable" data-field="scope" title="click to edit">${esc(e.scope || "—")}</td>
        <td class="cnt">${c.targets ?? 0}</td>
        <td class="cnt">${c.facts ?? 0}</td>
        <td class="cnt">${c.events ?? 0}</td>
        <td class="cnt">${c.findings ?? 0}</td>
        <td class="muted">${created}</td>
        <td><div class="eng-actions">
          ${isActive ? "" : `<button class="act" data-act="activate">Set active</button>`}
          ${e.archived_at
            ? `<button class="act" data-act="unarchive">Unarchive</button>`
            : `<button class="act" data-act="archive">Archive</button>`}
          <button class="act warn" data-act="reset">Reset</button>
          <button class="act warn" data-act="delete">Delete</button>
        </div></td></tr>`;
    }).join("")}</tbody></table>`;

  el.querySelectorAll(".engrow").forEach((tr) => {
    const id = Number(tr.dataset.id);
    const name = list.find((e) => e.id === id)?.name || `#${id}`;
    const counts = list.find((e) => e.id === id)?.counts || {};
    tr.querySelectorAll("button[data-act]").forEach((b) =>
      b.addEventListener("click", () => engAction(b.dataset.act, id, name, counts)));
    tr.querySelectorAll("td.editable").forEach((td) =>
      td.addEventListener("click", () => editEngField(td, id)));
  });
}

function editEngField(td, id) {
  if (td.querySelector("input")) return;
  const field = td.dataset.field;
  const cur = field === "scope" ? (td.textContent.trim() === "—" ? "" : td.textContent.trim())
                                : td.childNodes[0].textContent.trim();
  const inp = document.createElement("input");
  inp.value = cur; inp.size = 18;
  td.textContent = ""; td.appendChild(inp); inp.focus();
  const commit = async () => {
    const val = inp.value.trim();
    if (val !== cur && (field !== "name" || val)) {
      await api(`/api/engagements/${id}`, { method: "PATCH", json: { [field]: val } });
      await loadEngagements();
    }
    loadManageEngagements();
  };
  inp.addEventListener("blur", commit);
  inp.addEventListener("keydown", (e) => { if (e.key === "Enter") inp.blur();
    else if (e.key === "Escape") { inp.value = cur; inp.blur(); } });
}

async function engAction(act, id, name, counts) {
  if (act === "activate") {
    await api("/api/active_engagement", { method: "PUT", json: { id } });
  } else if (act === "archive") {
    await api(`/api/engagements/${id}/archive`, { method: "POST" });
  } else if (act === "unarchive") {
    await api(`/api/engagements/${id}/unarchive`, { method: "POST" });
  } else if (act === "reset") {
    confirmModal({
      title: `Reset “${name}”?`, danger: "Reset",
      body: `Wipes all data — ${counts.targets ?? 0} targets, ${counts.facts ?? 0} facts, ${counts.events ?? 0} events, ${counts.findings ?? 0} findings — but keeps the engagement.`,
      confirmName: name,
      onConfirm: async () => { await api(`/api/engagements/${id}/reset`, { method: "POST" });
        await refreshAfterEngChange(); },
    });
    return;
  } else if (act === "delete") {
    confirmModal({
      title: `Delete “${name}”?`, danger: "Delete",
      body: `Permanently removes this engagement and all its data — ${counts.targets ?? 0} targets, ${counts.facts ?? 0} facts, ${counts.events ?? 0} events, ${counts.findings ?? 0} findings.`,
      confirmName: name,
      onConfirm: async () => { await api(`/api/engagements/${id}`, { method: "DELETE" });
        await refreshAfterEngChange(); },
    });
    return;
  }
  await refreshAfterEngChange();
}

async function refreshAfterEngChange() {
  await loadEngagements();          // resync the header selector + active
  loadManage();
}

/* type-to-confirm modal */
function confirmModal({ title, body, confirmName, danger, onConfirm }) {
  const wrap = $("#modal");
  wrap.innerHTML = `<div class="modal">
    <h3>${esc(title)}</h3>
    <p>${esc(body)}</p>
    ${confirmName ? `<p class="muted">Type <b>${esc(confirmName)}</b> to confirm:</p>
      <input class="confirm" id="m-confirm" autocomplete="off" placeholder="${esc(confirmName)}">` : ""}
    <div class="row">
      <button class="act" id="m-cancel">Cancel</button>
      <button class="act warn" id="m-ok" ${confirmName ? "disabled" : ""}>${esc(danger || "Confirm")}</button>
    </div></div>`;
  wrap.style.display = "flex";
  const close = () => { wrap.style.display = "none"; wrap.innerHTML = ""; };
  $("#m-cancel").addEventListener("click", close);
  wrap.addEventListener("click", (e) => { if (e.target === wrap) close(); });
  const ok = $("#m-ok");
  if (confirmName) {
    const inp = $("#m-confirm");
    inp.addEventListener("input", () => { ok.disabled = inp.value.trim() !== confirmName; });
    inp.addEventListener("keydown", (e) => { if (e.key === "Enter" && !ok.disabled) ok.click();
      else if (e.key === "Escape") close(); });
    inp.focus();
  }
  ok.addEventListener("click", async () => { ok.disabled = true; try { await onConfirm(); } finally { close(); } });
}

// Proper new-engagement dialog (replaces the blocking prompt() chain): name +
// scope + notes, inline validation, Enter to submit / Esc to cancel.
function newEngagementModal(onCreate) {
  const wrap = $("#modal");
  wrap.innerHTML = `<div class="modal create">
    <h3 class="ok">New engagement</h3>
    <p class="muted" style="margin:-4px 0 10px">Scope everything for a fresh target set — the board, facts, and report attach to it.</p>
    <label class="mlbl">Name</label>
    <input class="confirm" id="m-name" autocomplete="off" placeholder="e.g. CLIENT-LAB">
    <label class="mlbl">Clone from <span class="muted">— optional: copies the scope + the host list (not recon)</span></label>
    <select class="confirm" id="m-copyscope"><option value="">— none, type it below</option></select>
    <label class="mlbl">Scope <span class="muted">— CIDR(s)/IPs, space or comma separated</span></label>
    <input class="confirm" id="m-scope" autocomplete="off" placeholder="192.0.2.0/24">
    <label class="mlbl">Notes <span class="muted">— optional</span></label>
    <input class="confirm" id="m-notes" autocomplete="off" placeholder="what this engagement is">
    <div class="merr" id="m-err"></div>
    <div class="row">
      <button class="act" id="m-cancel">Cancel</button>
      <button class="act go" id="m-ok" disabled>Create</button>
    </div></div>`;
  wrap.style.display = "flex";
  const close = () => { wrap.style.display = "none"; wrap.innerHTML = ""; };
  $("#m-cancel").addEventListener("click", close);
  wrap.addEventListener("click", (e) => { if (e.target === wrap) close(); });
  const name = $("#m-name"), scope = $("#m-scope"), notes = $("#m-notes"),
        copy = $("#m-copyscope"), ok = $("#m-ok"), err = $("#m-err");
  const validate = () => { ok.disabled = name.value.trim() === ""; };
  name.addEventListener("input", validate);
  // populate the "copy scope from" list; picking one mirrors its scope text so the
  // operator can see what's being carried (the structured in/out lists copy too).
  api("/api/engagements").then((list) => {
    for (const e of (list || [])) {
      const o = document.createElement("option");
      o.value = e.id; o.textContent = `#${e.id} ${e.name}`; o.dataset.scope = e.scope || "";
      copy.appendChild(o);
    }
  }).catch(() => { });
  copy.addEventListener("change", () => {
    const opt = copy.selectedOptions[0];
    if (copy.value) { scope.value = opt.dataset.scope || ""; scope.placeholder = "copied from " + opt.textContent; }
  });
  [name, scope, notes].forEach((i) => i.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !ok.disabled) ok.click();
    else if (e.key === "Escape") close();
  }));
  name.focus();
  ok.addEventListener("click", async () => {
    ok.disabled = true; err.textContent = "";
    try {
      await onCreate({ name: name.value.trim(), scope: scope.value.trim(),
        notes: notes.value.trim(), copy_scope_from: copy.value ? Number(copy.value) : null });
      close();
    }
    catch (e) { err.textContent = String(e && e.message || e); ok.disabled = false; }
  });
}

/* settings */
async function loadManageSettings() {
  const s = await api("/api/settings");
  const ns = await api("/api/netsensor").catch(() => ({}));
  const el = $("#mng-settings");
  const wireState = ns.running ? "live" : (ns.error ? "blocked" : "off");
  const wireColor = ns.running ? "#7fd88f" : (ns.error ? "#e89a9a" : "#c9a24a");
  const wireHint = ns.running
    ? `capturing on ${ns.iface || "?"} · ${ns.bpf || ""}`
    : (ns.error || "tcpdump packet capture — needs cap_net_raw (setcap) or root");
  const wireRow = `
    <div class="setrow">
      <button class="act" id="mng-wire-toggle">${ns.running ? "Stop" : "Start"}</button>
      <div class="lbl"><b>Wire sensor (packet capture) — <span style="color:${wireColor}">${wireState}</span></b>
        <span class="src">${esc(wireHint)}</span></div>
    </div>`;
  const toggle = (key, label, hint) => `
    <div class="setrow">
      <label class="switch"><input type="checkbox" data-set="${key}" ${s[key].value ? "checked" : ""}><span class="sl"></span></label>
      <div class="lbl"><b>${label}</b><span class="src">${hint} · source: ${s[key].source} (${s[key].env})</span></div>
    </div>`;
  el.innerHTML =
    toggle("allow_loopback", "Include loopback targets",
           "off = 127.0.0.1 excluded from scans/targets") +
    `<div class="setrow">
      <input type="text" data-set="tool_net" value="${esc(s.tool_net.value)}" placeholder="(none)" size="18">
      <div class="lbl"><b>Docker tool-network</b><span class="src">run scanners inside this docker net (macOS real IPs) · source: ${s.tool_net.source} (${s.tool_net.env})</span></div>
    </div>` +
    toggle("acp_autoapprove", "ACP auto-approve permissions",
           "auto-allow + log agent permission prompts") +
    toggle("tool_auto_approve", "Auto-approve agent tool runs",
           "off = agent-queued scans wait for your approval; scope guard is a separate setting") +
    toggle("brief_on_prompt", "Inject [RedOps] briefing into the agent",
           "off = agent isn't fed the engagement/worklist on every prompt (no steering)") +
    toggle("scope_guard", "Scope guard (block out-of-scope commands)",
           "off = assigned scope remains visible, with no RedOps command scope denial") +
    wireRow;

  const wt = el.querySelector("#mng-wire-toggle");
  if (wt) wt.addEventListener("click", async () => {
    wt.disabled = true;
    try { await api(ns.running ? "/api/netsensor/stop" : "/api/netsensor/start", { method: "POST" }); }
    catch (e) { /* status refresh will show the reason */ }
    setTimeout(loadManageSettings, 800);
  });

  el.querySelectorAll('input[type="checkbox"][data-set]').forEach((c) =>
    c.addEventListener("change", async () => {
      await api("/api/settings", { method: "PUT", json: { [c.dataset.set]: c.checked } });
      loadManageSettings();
    }));
  const net = el.querySelector('input[data-set="tool_net"]');
  const saveNet = async () => { await api("/api/settings", { method: "PUT", json: { tool_net: net.value.trim() } });
    loadManageSettings(); };
  net.addEventListener("blur", saveNet);
  net.addEventListener("keydown", (e) => { if (e.key === "Enter") net.blur(); });
}

/* read-only status */
async function loadManageStatus() {
  const st = await api("/api/status");
  const cap = st.capture || {};
  const cell = (k, v, ok) => `<div class="cell"><div class="k">${k}</div><div class="v ${ok ? "ok" : ""}">${esc(v)}</div></div>`;
  $("#mng-status").innerHTML =
    cell("Capture", `${(cap.mechanism || "—").toUpperCase()} · ${cap.status || "—"}`, cap.status === "live") +
    cell("Schema version", "v" + st.schema_version) +
    cell("Build", st.commit || "—") +
    cell("Database size", fmtBytes(st.db_size)) +
    cell("Data dir", st.data_dir) +
    cell("Server", `${st.host}:${st.port}`) +
    cell("Engagements", st.counts.engagements) +
    cell("Targets", st.counts.targets) +
    cell("Facts", st.counts.facts) +
    cell("Events", st.counts.events) +
    cell("Tool runs", st.counts.tool_runs);
}

$("#mng-new").addEventListener("click", () => {
  newEngagementModal(async ({ name, scope, notes, copy_scope_from }) => {
    await api("/api/engagements", { json: { name, scope, notes, copy_scope_from } });
    await refreshAfterEngChange();
  });
});
$("#mng-showarch").addEventListener("change", (e) => { mngShowArchived = e.target.checked; loadManageEngagements(); });

/* ---------------- init ---------------- */
(async () => {
  await loadEngagements();
  const jumped = openHashTab();   // e.g. arriving from the board via /#intel
  await loadFeed();
  await loadTargets();   // also fills ipById for feed badges
  $("#mode-grouped").classList.toggle("active", feedMode === "grouped");
  $("#mode-raw").classList.toggle("active", feedMode === "raw");
  if (feedMode === "grouped") await loadTurns(); else renderFeed();
  if (!jumped) loadSitrepAll();   // sitrep is the default home tab
  connectStream();
})();
