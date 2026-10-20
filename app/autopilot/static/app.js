// F5 Agentic AI Autopilot — SE-operated UI (v2).
// Renders ONLY what the API returns: no topology, names, addresses or counts are defined here.
// Workflow: Discover → Assess → Recommend → Approve → Deploy → Validate → Observe. Long actions run as server-side
// operations whose progress is persisted (refresh-safe). Buttons are enabled from the backend's lifecycle/role rules.
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (x) => String(x ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const { patch, inBackground, jv, jvLines } = window.UICore;
// Server-generated reports download through plain same-origin links (session cookie, Content-Disposition: attachment).
// The previous fetch → blob: URL → revoke approach produced .crdownload / ERR_BLOCKED_BY_CLIENT in Chrome profiles whose
// extensions cancel blob downloads; a direct link has no object URL lifetime and degrades to "open inline" if blocked.
const dlLink = (href, filename, label, cls = "") => `<a class="dl ${cls}" href="${esc(href)}" download="${esc(filename)}" data-filename="${esc(filename)}">${label}</a>`;
const ts = (t) => (t ? new Date(t * 1000).toLocaleTimeString() : "");
const utcFull = (t) => (t ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "—");
// Same rule as validation_evidence.effective(): a check refused because no live window was open did not run (doc 38).
const effResult = (x) => (x.result === "fail" && (JSON.stringify(x.observed || {}) || "").includes("live execution is locked") ? "not_run" : x.result);
const CLIENT_DEFECT = "cannot be combined with `cert=...`";
const utc = (t) => (t ? new Date(t * 1000).toISOString().slice(11, 16) + " UTC" : "");
const dur = (s) => (s == null ? "" : s < 60 ? `${Math.round(s)} s` : `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`);
const badge = (v, cls) => `<span class="badge b-${esc(cls || String(v).split(/[ —(-]/)[0])}">${esc(String(v).replace(/_/g, " "))}</span>`;
const ROLES = { viewer: 1, operator: 2, approver: 3, owner: 4 };
const can = (role) => ME && ROLES[ME.role] >= ROLES[role];
const STAGES = [["discover", "Discover"], ["assess", "Assess"], ["recommend", "Recommend"], ["approve", "Approve"], ["deploy", "Deploy"], ["validate", "Validate"], ["observe", "Observe"]];
const PAGES = ["demo", "fraud", "control", "aiops", "discover", "assess", "recommend", "approve", "deploy", "validate", "observe", "audit"];
let ME = null, STATE = null, PKGS = [], WIN = null, VALS = [], PAGE = PAGES.includes(location.hash.slice(1)) ? location.hash.slice(1) : localStorage.getItem("ap.page") || "demo";
let VIEW = localStorage.getItem("ap.view") || "exec";
const DISMISSED = new Set();
let cy = null, gsig = "", HIDDEN = new Set(JSON.parse(localStorage.getItem("ap.hidden") || "[]")), lastOps = {}, ANALYSIS = null;

// ------------------------------------------------------------------ api / auth
const csrf = () => (document.cookie.split("; ").find((c) => c.startsWith("ap_csrf=")) || "").slice(8);
let AUTH_EPOCH = 0;   // bumped on sign-in: a 401 from a request issued before it is stale and must not reopen the dialog
async function api(path, opts = {}) {
  const epoch = AUTH_EPOCH;
  const r = await fetch(path, { headers: { "content-type": "application/json", "X-CSRF-Token": csrf() }, credentials: "same-origin", ...opts });
  const ct = r.headers.get("content-type") || "";
  const body = ct.includes("json") ? await r.json().catch(() => ({})) : await r.text();
  if (r.status === 401 && !path.endsWith("/login")) { if (epoch === AUTH_EPOCH) showLogin(); throw new Error("sign-in required"); }
  if (r.status === 403 && body && String(body.detail || "").includes("CSRF")) { showLogin("Your session security token is missing — please sign in again."); throw new Error(body.detail); }
  if (!r.ok) throw new Error((body && body.detail) || r.statusText || `HTTP ${r.status}`);   // never an empty message
  return body;
}
const post = (p, b) => api(p, { method: "POST", body: JSON.stringify(b || {}) });
function showLogin(msg = "") {
  // Background polls also land here on 401: never steal focus from (or clear) a dialog the user is already typing in.
  const open = !$("#login").classList.contains("hidden");
  $("#login").classList.remove("hidden");
  if (msg || !open) $("#lerr").textContent = msg;
  if (!open && !$("#login").contains(document.activeElement)) setTimeout(() => { if (!$("#login").contains(document.activeElement)) $("#lu").focus(); }, 50);
}
$("#lb").onclick = async () => {
  try { ME = await post("/api/login", { username: $("#lu").value.trim(), password: $("#lp").value }); AUTH_EPOCH++;
    $("#lp").value = ""; $("#login").classList.add("hidden"); applyRole(); await refresh(true); toast(`Signed in as ${ME.username} (${ME.role})`, "ok");
  } catch (e) { $("#lerr").textContent = e.message; }
};
$("#lp").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#lb").click(); });
$("#acct").onclick = (e) => { e.stopPropagation(); $("#acct-menu").classList.toggle("hidden"); };
document.addEventListener("click", () => $("#acct-menu").classList.add("hidden"));
async function signOut(switching) {
  await post("/api/logout").catch(() => {}); ME = null; applyRole();
  $("#lu").value = switching ? "" : $("#lu").value; showLogin(switching ? "Sign in with another account." : "Signed out.");
}
$("#m-logout").onclick = () => signOut(false);
$("#m-switch").onclick = () => signOut(true);
$("#m-audit").onclick = () => go("audit");
function applyRole() {
  const name = ME ? ME.username : "not signed in";
  $("#acct-name").textContent = ME ? `${ME.username} · ${ME.role}` : name;
  $("#avatar").textContent = ME ? ME.username[0].toUpperCase() : "?";
  $("#m-user").textContent = name;
  $("#m-role").textContent = ME ? { viewer: "Viewer — read only", operator: "SE operator — discover, assess, recommend, preflight, validate",
    approver: "Approver — everything an operator can do, plus approve, deploy, roll back, Reset Demo, close a live window",
    owner: "Lab owner — approver rights plus authorising live infrastructure changes (opening a supervised live window)" }[ME.role] : "";
  $$("[data-need]").forEach((b) => { const ok = can(b.dataset.need); b.disabled = !ok || b.dataset.busy === "1";
    b.title = ok ? (b.dataset.title || b.title) : `requires the ${b.dataset.need} role`; });
}

// ------------------------------------------------------------------ helpers: toast, modal, ask
function toast(msg, kind = "") { const d = document.createElement("div"); d.className = `toast ${kind}`; d.innerHTML = msg; $("#toast").appendChild(d); setTimeout(() => d.remove(), 7000); }
function modal(html) { $("#modal-c").innerHTML = html; $("#modal").classList.remove("hidden"); }
$("#modal-x").onclick = () => $("#modal").classList.add("hidden");
function ask(title, text, { placeholder = "", confirm = "Confirm", must = null, cls = "primary" } = {}) {
  return new Promise((res) => {
    modal(`<h2>${esc(title)}</h2><p class="small">${text}</p><textarea id="ask-v" placeholder="${esc(placeholder)}" style="height:70px"></textarea>
      <p><button class="${cls}" id="ask-ok">${esc(confirm)}</button> <button id="ask-no">Cancel</button> <span class="small muted" id="ask-err"></span></p>`);
    $("#ask-ok").onclick = () => { const v = $("#ask-v").value.trim(); if (must && v !== must) { $("#ask-err").textContent = `type exactly: ${must}`; return; }
      $("#modal").classList.add("hidden"); res(v); };
    $("#ask-no").onclick = () => { $("#modal").classList.add("hidden"); res(null); };
    setTimeout(() => $("#ask-v").focus(), 30);
  });
}
async function showEvidence(id, assetId) {
  const e = await api(`/api/evidence/${id}${assetId ? `?asset=${encodeURIComponent(assetId)}` : ""}`);
  const sc = e.scoped;
  modal(`<h2>Evidence <code>${esc(id)}</code> ${trustChip(e.trust)}</h2>
    <p class="small">${esc(e.summary)}</p>
    <div class="kv"><div>source / method</div><div>${esc(e.source)} · ${esc(e.method)}</div><div>what this proves</div><div class="small">${esc(e.trust.meaning)}</div>
    <div>collected</div><div>${new Date(e.collected_at * 1000).toISOString()}</div><div>SHA-256</div><div><code>${esc(e.digest)}</code></div>
    <div>size</div><div>${(e.raw_size / 1024).toFixed(1)} KB raw${sc ? ` · ${(sc.size / 1024).toFixed(1)} KB about this service` : ""}</div></div>
    ${sc ? `<h3>Only the parts about this service</h3><p class="small muted">Matched on ${esc(sc.matched_on.join(", "))}. The full document is below.</p>
      ${jv(sc.content, { id: `ev-sc:${id}:${assetId}`, title: "Service-specific evidence", filename: `evidence-${id}-${assetId}.json`, height: 320 })}` : ""}
    <details ${sc ? "" : "open"}><summary>Full evidence document (raw JSON)</summary>${jv(e.raw, { id: `ev:${id}`, title: `Evidence ${id} (raw)`, filename: `evidence-${id}.json`, height: 420 })}</details>`);
}
window.showEvidence = showEvidence;
const evLinks = (ids, assetId) => (ids || []).map((e) => `<a class="ev" data-ev="${esc(e)}" ${assetId ? `data-asset="${esc(assetId)}"` : ""}>${esc(e.slice(0, 8))}</a>`).join(" · ");
const trustChip = (t) => t ? `<span class="trust ${t.verified ? "v" : t.level === "customer_assertion" || t.level === "hypothesis" ? "u" : "i"}" title="${esc(t.meaning)}">${esc(t.label)}</span>` : "";
document.addEventListener("click", (e) => { const a = e.target.closest("a.ev[data-ev]"); if (a) { e.preventDefault(); showEvidence(a.dataset.ev, a.dataset.asset); } });

// ------------------------------------------------------------------ navigation (single, workflow-driven)
function stageDone() {
  const c = STATE ? STATE.counters : {}, st = (s) => PKGS.some((p) => p.lifecycle && s.includes(p.lifecycle.state));
  const deployed = PKGS.some((p) => p.deployments.some((d) => d.status === "succeeded"));
  return { discover: c.evidence > 0, assess: c.findings > 0, recommend: PKGS.length > 0,
    approve: st(["approved", "deploying", "deployed"]) || deployed, deploy: deployed,
    validate: VALS.some((v) => v.label !== "before" && v.results.every((r) => r.result === "pass")),
    observe: !!(OVR && !OVR.error && OVR.observe_completion && OVR.observe_completion.complete) };   // server criteria (overview.observe_completion); never set by opening the page
}
function renderStages() {
  const done = stageDone(); const cur = STAGES.find(([k]) => !done[k]);
  patch($("#stages"), STAGES.map(([k, n], i) => `${i ? '<span class="stage-arrow">›</span>' : ""}<div class="stage ${done[k] ? "done" : cur && cur[0] === k ? "current" : ""} ${PAGE === k ? "active" : ""}" data-stage="${k}"${k === "observe" && !done[k] && OVR && OVR.observe_completion ? ` title="Observe completes when every criterion holds. Next: ${esc(OVR.observe_completion.next || "")}"` : ""}>
    <span class="n">${done[k] ? "✓" : i + 1}</span>${n}</div>`).join(""));
  $$(".stage").forEach((s) => (s.onclick = () => go(s.dataset.stage)));
}
function go(page) {
  PAGE = page; localStorage.setItem("ap.page", page); history.replaceState(null, "", "#" + page);
  $$(".page").forEach((p) => p.classList.toggle("active", p.id === `p-${page}`));
  $$(".toplinks a").forEach((a) => a.classList.toggle("on", a.dataset.go === page));
  renderStages(); renderPage(true);
}
function renderPage(full) {
  ({ demo: renderDemo, fraud: () => (full ? renderFraud(true) : renderFraudRuns()), control: () => renderControl(full),
     discover: () => { if (cy) cy.resize(); renderDiscover(); }, assess: renderAssess, recommend: () => { renderRecommend(); renderAdvisory(full); }, approve: renderApprove,
     deploy: renderDeploy, validate: renderValidate, observe: () => full && renderObserve(), audit: () => full && renderAudit(),
     aiops: () => window.renderAIOps && window.renderAIOps(full) }[PAGE] || (() => {}))();
}

// ------------------------------------------------------------------ operations / progress (persisted server-side)
async function startOp(path, body, label) {
  try { const o = await post(path, body); lastOps[o.id] = o; renderProgress([o]); toast(`${esc(label || o.title)} started`); poll(); return o; }
  catch (e) { toast(`${esc(label || path)}: ${esc(e.message)}`, "bad"); return null; }
}
async function renderProgressFromServer() {
  const ops = await api("/api/ops").catch(() => []);
  const now = Date.now() / 1000;
  const running = ops.filter((o) => o.status === "running");
  const latest = ops.find((o) => o.status !== "running" && o.finished && now - o.finished < 30 && !DISMISSED.has(o.id));
  const show = running.concat(latest ? [latest] : []);
  for (const o of ops) { const prev = lastOps[o.id];
    if (prev && prev.status === "running" && o.status !== "running") onOpFinished(o);
    lastOps[o.id] = o; }
  renderProgress(show);
  return show.some((o) => o.status === "running");
}
function renderProgress(ops) {
  patch($("#progress"), ops.map((o) => {
    const run = o.status === "running";
    if (!run) return `<div class="op ${o.status === "partial" ? "failed" : o.status}"><div class="row"><span class="title">${o.status === "succeeded" ? "✓" : "⚠"} ${esc(o.title)}
      — ${o.status === "succeeded" ? "completed" : o.status === "partial" ? "completed with errors" : "failed"}</span><span class="meta">by ${esc(o.actor)} · took ${dur(o.elapsed_s)}</span>
      <span class="spacer"></span><button onclick="DISMISSED.add('${o.id}');this.closest('.op').remove()">Dismiss</button></div>
      ${o.error ? `<div class="small" style="margin-top:6px">${esc(o.error)}</div>` : ""}</div>`;
    return `<div class="op"><div class="row"><span class="title"><span class="spin"></span>${esc(o.title)}</span>
      <span class="meta">by ${esc(o.actor)} · ${run ? "elapsed" : "took"} ${dur(o.elapsed_s)}${run && o.eta_s ? ` · ETA ~${dur(o.eta_s)} (${esc(o.eta_basis)})` : ""}</span>
      <span class="spacer"></span><span class="meta">${run ? esc(o.current || "") : esc(o.status)}</span></div>
      ${run ? '<div class="bar"><i></i></div>' : ""}
      <ul class="steps">${(o.steps || []).map((s) => `<li>${s.status === "running" ? '<span class="spin"></span>' : s.status === "ok" ? "✓" : "✗"} ${esc(s.name)}
        <span class="muted small">${s.finished ? dur(s.finished - s.started) : ""} ${s.detail && s.detail.completed ? `· ${s.detail.completed} tests done${s.detail.failed.length ? `, failing: ${esc(s.detail.failed.join(", "))}` : ""}` : ""}
        ${s.status === "failed" && s.detail && s.detail.error ? `· ${esc(s.detail.error)}` : ""}</span></li>`).join("")}</ul>
      ${o.error ? `<div class="small" style="margin-top:6px">${esc(o.error)}</div>` : ""}</div>`; }).join(""));
}
function onOpFinished(o) {
  const ok = o.status === "succeeded" || o.status === "partial";
  const nxt = { discover: "Next: review findings in Assess.", describe: "See the AI interpretation in the Discover panel.", recommend: "Next: open Recommend.",
    validate: "Results are in Validate.", deploy: ok ? "Next: Validate, then rediscover and compare in Observe." : "Open Deploy for the failure diagnosis and next actions.",
    rollback: "Rollback finished.", reset_demo: ok ? "Lab restored to the unprotected baseline." : "Reset verification failed — see Deploy." }[o.kind] || "";
  toast(`${ok ? "✓" : "✗"} ${esc(o.title)} ${ok ? "completed" : "failed"}. ${esc(nxt)}${o.error ? `<br><span class="small">${esc(o.error)}</span>` : ""}`, ok ? "ok" : "bad");
  if (o.kind === "describe") ANALYSIS = null;
  if (o.kind === "investigate" && o.result && o.result.fraud_run) { FR.run = null; loadRun(o.result.fraud_run); }
  refresh(true);
}

// ------------------------------------------------------------------ refresh / polling (reads only)
let polling = null;
async function refresh(full) {
  try { STATE = await api("/api/state"); } catch (e) { return; }
  ME = STATE.user; applyRole();
  PKGS = await api("/api/packages").catch(() => PKGS);
  VALS = await api("/api/validations").catch(() => VALS);
  if (full || Date.now() - OVR_AT > 30000) { OVR_AT = Date.now(); api("/api/overview").then((o) => { OVR = o; renderStages(); }).catch(() => {}); }
  const a = STATE.assessment;
  $("#ctx").textContent = `Assessment “${a.name}” · ${a.id} · started ${ts(a.created)}`;
  $("#llm").textContent = STATE.llm.provider === "none" ? "AI: deterministic fallback (no LLM)" : `AI: ${STATE.llm.model}`;
  renderStages(); renderPage(full); markRefreshed();
}
async function refreshWindow() {
  WIN = await api("/api/window").catch(() => null);
  const w = (WIN && WIN.window) || {}, el = $("#win");
  el.className = "pill " + (w.phase === "live" ? "live" : w.phase === "cleanup" ? "cleanup" : "");
  el.textContent = w.phase === "live" ? `LIVE deployment until ${utc(w.not_after)} (${Math.round(w.remaining_s / 60)} min)` :
    w.phase === "cleanup" ? `cleanup grace until ${utc(w.cleanup_until)}` : "live deployment locked";
}
async function poll() {
  clearTimeout(polling);
  const running = await inBackground(() => renderProgressFromServer());
  if (running && ["deploy", "validate"].includes(PAGE)) await inBackground(() => refresh(false));
  polling = setTimeout(poll, running ? 1500 : 4000);
}
let LAST_REFRESH = 0;
function markRefreshed() { LAST_REFRESH = Date.now(); const el = $("#refresh-state"); if (el) el.textContent = `updated ${new Date().toLocaleTimeString()}`; }

// ------------------------------------------------------------------ DISCOVER
const ICON = {
  agent: '<rect x="5" y="8" width="14" height="11" rx="3"/><circle cx="9.5" cy="13" r="1.4" fill="#fff"/><circle cx="14.5" cy="13" r="1.4" fill="#fff"/><path d="M12 8V4.5"/><circle cx="12" cy="4" r="1"/>',
  tool: '<path d="M14.5 5.5a4 4 0 0 0-5 5L4 16l4 4 5.5-5.5a4 4 0 0 0 5-5l-2.5 2.5-2.5-.5-.5-2.5z"/>',
  stack: '<path d="M12 4l8 4-8 4-8-4z"/><path d="M4 12l8 4 8-4"/><path d="M4 16l8 4 8-4"/>',
  db: '<ellipse cx="12" cy="6" rx="7" ry="2.6"/><path d="M5 6v12c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6V6"/><path d="M5 12c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6"/>',
  bucket: '<path d="M4 7h16l-2 13H6z"/><ellipse cx="12" cy="7" rx="8" ry="2"/>',
  spark: '<path d="M12 3l2 7 7 2-7 2-2 7-2-7-7-2 7-2z"/>',
  f5: '<circle cx="12" cy="12" r="10" fill="#e4002b" stroke="none"/><text x="12" y="16" font-size="10" text-anchor="middle" fill="#fff" stroke="none" font-family="Arial,sans-serif" font-weight="800">f5</text>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  grid: '<rect x="4" y="4" width="7" height="7"/><rect x="13" y="4" width="7" height="7"/><rect x="4" y="13" width="7" height="7"/><rect x="13" y="13" width="7" height="7"/>',
  chart: '<path d="M5 20V10M10 20V5M15 20v-7M20 20V8"/>',
  laptop: '<rect x="5" y="5" width="14" height="10" rx="1"/><path d="M3 19h18"/>',
  radar: '<circle cx="12" cy="12" r="2"/><path d="M7 7a7 7 0 0 0 0 10M17 7a7 7 0 0 1 0 10M4.5 4.5a10.5 10.5 0 0 0 0 15M19.5 4.5a10.5 10.5 0 0 1 0 15"/>',
  globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c3 3 3 14 0 17M12 3.5c-3 3-3 14 0 17"/>',
  box: '<path d="M4 8l8-4 8 4v8l-8 4-8-4z"/><path d="M4 8l8 4 8-4M12 12v8"/>',
  bubble: '<path d="M4 5h16v10H9l-5 4z"/>', door: '<rect x="6" y="3" width="12" height="18" rx="1"/><circle cx="15" cy="12" r="1"/>',
};
const KIND = {  // kind -> [icon, color, category, label]
  a2a_agent: ["agent", "#8957e5", "Agents", "A2A agent"], ai_agent: ["agent", "#8957e5", "Agents", "AI agent"], a2a_endpoint: ["door", "#6e40c9", "Agents", "advertised A2A URL"],
  mcp_server: ["tool", "#1f6feb", "MCP", "MCP server"], mcp_service: ["stack", "#0b4fb3", "MCP", "MCP service (replicas)"],
  vector_db: ["db", "#238636", "Data", "vector DB"], object_store: ["bucket", "#2ea043", "Data", "object store"], llm_endpoint: ["spark", "#d4761c", "Models", "LLM"],
  adc: ["shield", "#e4002b", "BIG-IP", "BIG-IP"], bigip_virtual: ["shield", "#c2183c", "BIG-IP", "virtual server"], bigip_vip: ["door", "#c2183c", "BIG-IP", "VIP"],
  bigip_pool: ["grid", "#a3172f", "BIG-IP", "pool"], analytics: ["chart", "#8250df", "Infrastructure", "analytics"], otel_collector: ["radar", "#57606a", "Infrastructure", "OTel"],
  dns_server: ["globe", "#57606a", "Infrastructure", "DNS"], client: ["laptop", "#6e7781", "Clients", "client"], client_app: ["laptop", "#6e7781", "Clients", "client"],
  workload: ["box", "#6e7781", "Clients", "workload"], asserted_component: ["bubble", "#9a6700", "Described", "described"], unknown: ["box", "#484f58", "Other", "unknown"],
};
const iconURI = (k) => "data:image/svg+xml;utf8," + encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${ICON[(KIND[k] || KIND.unknown)[0]]}</svg>`);
const CONFIG_EDGES = new Set(["hosts_config", "load_balances", "implemented_by", "forwards_to", "has_replica", "advertises", "same_instance", "possibly_same"]);
function groupOf(n) {
  const k = n.key;
  if (k.startsWith("described:")) return ["grp:described", "Described by customer — unverified"];
  if (k.startsWith("bigip") || ["adc", "bigip_virtual", "bigip_pool", "bigip_vip"].includes(n.kind)) return ["grp:bigip", "BIG-IP"];
  if (k.startsWith("otel:")) return ["grp:workloads", "Instrumented workloads (no listener)"];
  const m = k.match(/(\d+\.\d+\.\d+)\.\d+/);
  if (m) return [`grp:${m[1]}`, `Network ${m[1]}.0/24`];
  if (k.startsWith("mcpsvc:")) return ["grp:logical", "Logical services"];
  return ["grp:other", "Other"];
}
const PROTO_COLOR = { a2a: "#a371f7", mcp: "#2f81f7", llm: "#f0883e", vector_db: "#3fb950", s3: "#56d364", http: "#8b949e" };
const PATH_COLOR = { via_bigip: "#e4002b", direct: "#d29922" };
let EDGE_MODE = localStorage.getItem("ap.edgemode") || "path";
const edgeProto = (kind) => (kind.startsWith("calls_") ? kind.slice(6) : null);
const edgeColor = (e) => (e.data("status") === "conflicted" ? "#f85149" : e.data("config") ? "#3b4757"
  : EDGE_MODE === "protocol" ? PROTO_COLOR[e.data("proto")] || "#8b949e" : PATH_COLOR[e.data("path")] || "#5c6b7d");
function legendHTML() {
  return (EDGE_MODE === "protocol"
    ? "edges: " + Object.entries(PROTO_COLOR).map(([k, c]) => `<span style="color:${c}">━ ${k.replace("_", " ")}</span>`).join(" · ")
    : "edges: <span style='color:#d29922'>━ direct</span> · <span style='color:#e4002b'>━ via BIG-IP</span> · <span style='color:#5c6b7d'>━ path unknown</span>") +
    " · <span style='color:#f85149'>━ conflicted</span> · ┄ asserted · ··· configuration · node border: <span style='color:#3fb950'>corroborated</span> / <span style='color:#d29922'>asserted</span>";
}
function initGraph() {
  cy = cytoscape({ container: $("#graph"), elements: [], wheelSensitivity: 0.25, minZoom: 0.15, maxZoom: 3,
    style: [
      { selector: "node[?isGroup]", style: { "background-color": "#0e141b", "background-opacity": 0.6, "border-color": "#2a3441", "border-width": 1,
          shape: "round-rectangle", label: "data(label)", "text-valign": "top", "text-halign": "center", color: "#c9d4e0", "font-size": 13, "font-weight": 600, padding: 26 } },
      { selector: "node[!isGroup]", style: { shape: "round-rectangle", width: 40, height: 40, "background-color": "data(color)", "background-image": "data(icon)",
          "background-fit": "contain", "background-clip": "none", "background-width": "72%", "background-height": "72%", "background-position-x": "50%", "background-position-y": "50%",
          label: "data(label)", color: "#e8eef5", "font-size": 11, "text-valign": "bottom", "text-margin-y": 5, "text-wrap": "wrap", "text-max-width": 128,
          "text-background-color": "#0b0f14", "text-background-opacity": 0.75, "text-background-padding": 2, "border-width": 2,
          "border-color": (n) => ({ asserted: "#d29922", conflicted: "#f85149", corroborated: "#3fb950" }[n.data("status")] || "#2a3441"),
          "border-style": (n) => (n.data("status") === "asserted" ? "dashed" : "solid") } },
      { selector: "node.hit", style: { "border-color": "#ffd33d", "border-width": 4 } },
      { selector: "node:selected, node.sel", style: { "border-color": "#ffffff", "border-width": 4, "overlay-color": "#58a6ff", "overlay-opacity": 0.18, "overlay-padding": 6 } },
      { selector: "edge", style: { width: 1.8, "curve-style": "bezier", "target-arrow-shape": "triangle", "arrow-scale": 0.9, "font-size": 9, color: "#c9d4e0",
          label: "data(label)", "text-rotation": "autorotate", "text-background-color": "#0b0f14", "text-background-opacity": 0.85, "text-background-padding": 2,
          "line-color": edgeColor, "target-arrow-color": edgeColor,
          "line-style": (e) => (e.data("status") === "asserted" ? "dashed" : e.data("config") ? "dotted" : "solid") } },
      { selector: "edge[?config]", style: { label: "", width: 1, "target-arrow-shape": "none" } },
      { selector: "edge:selected, edge.sel", style: { width: 4, "z-index": 9 } },
      { selector: ".dim", style: { opacity: 0.15 } } ] });
  cy.on("tap", "node[!isGroup]", (e) => selectAsset(e.target.id(), { center: false }));
  cy.on("tap", "edge", (e) => selectEdge(e.target.id()));
  cy.on("tap", (e) => { if (e.target === cy) closePanel(); });
  const tip = $("#g-tip");
  cy.on("mouseover", "node[!isGroup], edge", (e) => {
    const d = e.target.data(), p = e.renderedPosition || e.target.renderedMidpoint?.() || e.target.renderedPosition();
    tip.innerHTML = e.target.isNode()
      ? `<b>${esc(d.full)}</b>${esc(d.kindLabel)}${d.address ? ` · <code>${esc(d.address)}</code>` : ""}<br>${d.fd || d.fs ? `findings: <span class="dom-delivery">${d.fd} delivery</span> · <span class="dom-security">${d.fs} security</span>` : "no findings"}<br><span class="muted">click for details</span>`
      : `<b>${esc(d.fromName)} → ${esc(d.toName)}</b>${esc(d.label)} · path ${esc(d.path || "unknown")}${d.config ? " (configuration)" : ""}<br><span class="muted">click for evidence</span>`;
    tip.style.left = `${Math.min(p.x + 16, $("#graph").clientWidth - 300)}px`; tip.style.top = `${p.y + 16}px`; tip.classList.remove("hidden");
  });
  cy.on("mouseout", "node, edge", () => tip.classList.add("hidden"));
  cy.on("pan zoom", () => tip.classList.add("hidden"));
  patch($("#g-legend"), legendHTML());
  $("#g-fit").onclick = () => cy.fit(undefined, 40); $("#g-in").onclick = () => cy.zoom({ level: cy.zoom() * 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  $("#g-out").onclick = () => cy.zoom({ level: cy.zoom() / 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  $("#g-relayout").onclick = () => layout();
  $("#g-filter").onclick = () => $("#g-filters").classList.toggle("hidden");
  $("#g-full").onclick = () => toggleGraphFull();
  const setMode = (m) => { EDGE_MODE = m; localStorage.setItem("ap.edgemode", m); $("#g-color-path").classList.toggle("on", m === "path"); $("#g-color-proto").classList.toggle("on", m === "protocol");
    cy.style().update(); patch($("#g-legend"), legendHTML()); };
  $("#g-color-path").onclick = () => setMode("path"); $("#g-color-proto").onclick = () => setMode("protocol"); setMode(EDGE_MODE);
  $("#g-search").oninput = (e) => { const q = e.target.value.trim().toLowerCase(); cy.nodes().removeClass("hit");
    if (!q) return; const hits = cy.nodes("[!isGroup]").filter((n) => (n.data("search") || "").includes(q)); hits.addClass("hit"); if (hits.length) cy.animate({ fit: { eles: hits, padding: 80 } }, { duration: 300 }); };
  const cats = [...new Set(Object.values(KIND).map((k) => k[2]))];
  const protos = ["a2a", "mcp", "llm", "vector_db", "s3", "http"];
  patch($("#g-filters"), `<b class="small">Service types</b>${cats.map((c) => `<label><input type="checkbox" data-cat="${c}" ${HIDDEN.has(c) ? "" : "checked"}> ${c}</label>`).join("")}
    <b class="small">Communication</b>${protos.map((c) => `<label><input type="checkbox" data-cat="proto:${c}" ${HIDDEN.has("proto:" + c) ? "" : "checked"}> <span style="color:${PROTO_COLOR[c]}">━</span> ${c.replace("_", " ")}</label>`).join("")}
    <label><input type="checkbox" data-cat="Configuration edges" ${HIDDEN.has("Configuration edges") ? "" : "checked"}> ··· configuration edges</label>`);
  $$("#g-filters input").forEach((i) => (i.onchange = () => { i.checked ? HIDDEN.delete(i.dataset.cat) : HIDDEN.add(i.dataset.cat);
    localStorage.setItem("ap.hidden", JSON.stringify([...HIDDEN])); gsig = ""; renderGraph(STATE.graph); }));
}
function toggleGraphFull(force) {
  const w = $(".graph-wrap"), on = force ?? !w.classList.contains("full");
  w.classList.toggle("full", on); $("#g-full").textContent = on ? "✕ Exit full screen" : "⤢ Full screen";
  setTimeout(() => { cy.resize(); cy.fit(undefined, 40); }, 60);
}
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && $(".graph-wrap.full") && !$(".jv.full")) toggleGraphFull(false); });
/** Columns per group. Small inventories (<= 30 nodes) keep the original plan (1-3 columns, 5 per column). Larger ones pick
 *  the rows-per-column that makes the whole layout's aspect ratio closest to the canvas, so "fit" stays readable (W1-11). */
function gridPlan(sizes, aspect, { DX = 160, DY = 118, GAP = 90 } = {}) {
  const legacy = sizes.map((n) => Math.max(1, Math.min(3, Math.ceil(n / 5))));
  if (sizes.reduce((a, b) => a + b, 0) <= 30 || !(aspect > 0)) return legacy;
  let best = legacy, score = Infinity;
  for (let rows = 3; rows <= 40; rows++) {
    const cols = sizes.map((n) => Math.max(1, Math.ceil(n / rows)));
    const w = cols.reduce((a, c) => a + c * DX, 0) + GAP * (sizes.length - 1), h = Math.min(rows, Math.max(...sizes)) * DY;
    const sc = Math.abs(Math.log((w / h) / aspect));
    if (sc < score - 1e-9) { score = sc; best = cols; }
  }
  return best;
}
window.gridPlan = gridPlan;
function layout() {
  cy.resize();                                    // the container may have been hidden (0×0) when elements changed
  if (!cy.width() || !cy.height()) { gsig = ""; return; }   // re-layout when the Discover page becomes visible
  // Deterministic grouped layout: one column per group, ordered along the traffic direction; grid inside each group.
  const groups = cy.nodes("[?isGroup]").map((g) => ({ id: g.id(), kids: g.children().sort((a, b) => (a.data("kind") + a.data("label")).localeCompare(b.data("kind") + b.data("label"))) }));
  const has = (g, kinds) => g.kids.some((n) => kinds.includes(n.data("kind")));
  const rank = (g) => g.id === "grp:workloads" ? 0 : g.id === "grp:described" ? 9 : has(g, ["client", "workload"]) && !has(g, ["a2a_agent", "mcp_server"]) ? 1
    : has(g, ["a2a_agent", "ai_agent"]) ? 2 : g.id === "grp:bigip" ? 3 : has(g, ["mcp_server", "mcp_service", "vector_db", "object_store", "llm_endpoint"]) ? 4
    : g.id.startsWith("grp:192.") ? 6 : 5;
  groups.sort((a, b) => rank(a) - rank(b) || a.id.localeCompare(b.id));
  const pos = {}, DX = 160, DY = 118, GAP = 90;
  const colsOf = gridPlan(groups.map((g) => g.kids.length), cy.width() / cy.height(), { DX, DY, GAP });
  let x = 0;
  groups.forEach((g, gi) => {
    const cols = colsOf[gi];
    g.kids.forEach((k, i) => { pos[k.id()] = { x: x + (i % cols) * DX, y: Math.floor(i / cols) * DY }; });
    x += cols * DX + GAP;
  });
  cy.layout({ name: "preset", positions: (n) => pos[n.id()], fit: true, padding: 50 }).run();
}
function renderGraph(g) {
  const nodes = g.nodes.filter((n) => !HIDDEN.has((KIND[n.kind] || KIND.unknown)[2]) && !(n.status === "asserted" && HIDDEN.has("Described")));
  const keep = new Set(nodes.map((n) => n.id));
  const edges = g.edges.concat(identityEdges(keep)).filter((e) => keep.has(e.source) && keep.has(e.target) && !(CONFIG_EDGES.has(e.kind) && HIDDEN.has("Configuration edges"))
    && !(edgeProto(e.kind) && HIDDEN.has("proto:" + edgeProto(e.kind))));
  const s = JSON.stringify([nodes.map((n) => [n.id, n.status, n.kind, n.name, n.findings]), edges.map((e) => [e.id, e.status, e.observed_path])]);
  $("#g-empty").style.display = g.nodes.length ? "none" : "flex";
  if (s === gsig) return;
  gsig = s;
  const groups = {};
  nodes.forEach((n) => { const [id, label] = groupOf(n); groups[id] = label; n._parent = id; });
  for (const e of edges.filter((e) => e.kind === "has_replica")) {     // a logical MCP service is drawn inside the group of its replicas
    const svc = nodes.find((n) => n.id === e.source), rep = nodes.find((n) => n.id === e.target);
    if (svc && rep && svc._parent === "grp:logical") svc._parent = rep._parent;
  }
  for (const id of Object.keys(groups)) if (!nodes.some((n) => n._parent === id)) delete groups[id];
  const byId = Object.fromEntries(g.nodes.map((n) => [n.id, n]));
  cy.elements().remove();
  cy.add(Object.entries(groups).map(([id, label]) => ({ group: "nodes", data: { id, label, isGroup: true } })));
  cy.add(nodes.map((n) => ({ group: "nodes", data: { id: n.id, parent: n._parent, label: n.name.length > 40 ? n.name.slice(0, 38) + "…" : n.name, full: n.name,
    kind: n.kind, kindLabel: (KIND[n.kind] || KIND.unknown)[3], address: n.address, status: n.status, fd: (n.findings || {}).delivery || 0, fs: (n.findings || {}).security || 0,
    color: (KIND[n.kind] || KIND.unknown)[1], icon: iconURI(n.kind), search: [n.name, n.key, n.address, ...(n.aliases || [])].join(" ").toLowerCase() } })));
  cy.add(edges.map((e) => ({ group: "edges", data: { id: e.id, source: e.source, target: e.target, status: e.status, path: e.observed_path, proto: edgeProto(e.kind),
    fromName: (byId[e.source] || {}).name, toName: (byId[e.target] || {}).name,
    config: CONFIG_EDGES.has(e.kind), label: e.kind.startsWith("calls_") ? e.kind.slice(6) : e.kind.replace(/_/g, " ") } })));
  layout();
  if (SEL && cy.getElementById(SEL.id).length) cy.getElementById(SEL.id).addClass("sel");
}

// ------------------------------------------------------------------ asset / edge explorer panel
let SEL = null;   // {type: "asset"|"edge", id, tab}
function closePanel() { SEL = null; $("#g-panel").classList.add("hidden"); cy.elements().removeClass("sel"); }
async function selectAsset(id, { center = true, tab } = {}) {
  SEL = { type: "asset", id, tab: tab || (SEL && SEL.type === "asset" && SEL.id === id ? SEL.tab : "overview") };
  cy.elements().removeClass("sel");
  const el = cy.getElementById(id);
  if (el.length) { el.addClass("sel"); if (center) cy.animate({ center: { eles: el }, zoom: Math.max(cy.zoom(), 0.9) }, { duration: 350 }); }
  $("#g-panel").classList.remove("hidden");
  patch($("#g-panel"), `<div class="pbody"><span class="spin"></span>loading…</div>`);
  try { SEL.data = await api(`/api/assets/${id}`); } catch (e) { patch($("#g-panel"), `<div class="pbody">${esc(e.message)}</div>`); return; }
  renderPanel();
}
window.selectAsset = selectAsset;
async function selectEdge(id) {
  SEL = { type: "edge", id, tab: "overview" };
  cy.elements().removeClass("sel"); cy.getElementById(id).addClass("sel");
  $("#g-panel").classList.remove("hidden");
  try { SEL.data = await api(`/api/relationships/${id}`); } catch (e) { patch($("#g-panel"), `<div class="pbody">${esc(e.message)}</div>`); return; }
  renderPanel();
}
const traceLink = (t) => STATE && STATE.scope.jaeger_ui ? `<a href="${esc(STATE.scope.jaeger_ui)}/trace/${esc(t)}" target="_blank" rel="noopener"><code>${esc(t.slice(0, 16))}…</code></a>` : `<code>${esc(t)}</code>`;
const latTxt = (l) => (l ? `p50 ${l.p50} · p95 ${l.p95} · max ${l.max} ms <span class="muted">(n=${l.n ?? "?"}${l.n != null && !l.p95_reliable ? ", too few samples for a meaningful p95" : ""})</span>` : "—");
const assetLink = (x) => (x && x.id ? `<a class="linkish" data-sel-asset="${esc(x.id)}">${esc(x.name || x.key)}</a>` : esc((x && (x.name || x.key)) || "?"));
function panelTabs(tabs) {
  return `<div class="tabs" role="tablist">${tabs.map(([k, n]) => `<button role="tab" data-ptab="${k}" class="${SEL.tab === k ? "on" : ""}">${n}</button>`).join("")}</div>`;
}
function renderPanel() {
  if (!SEL || !SEL.data) return;
  const d = SEL.data;
  if (SEL.type === "edge") return renderEdgePanel(d);
  const i = d.identity, tools = (d.mcp && d.mcp.tools) || [];
  const tabs = [["overview", "Overview"], ...(d.mcp ? [["tools", `Tools (${tools.length})`]] : []), ["comms", `Communications (${d.communications.length})`],
    ["findings", `Findings (${d.findings.length})`], ["evidence", `Evidence (${d.claims.length})`], ["recs", `Recommendations (${d.recommendations.length})`], ["raw", "Raw"]];
  if (!tabs.some(([k]) => k === SEL.tab)) SEL.tab = "overview";
  let body = "";
  if (SEL.tab === "overview") {
    const c = d.agent_card;
    var canon = canonicalBlock(d.canonical);
    body = `<div class="kv"><div>type</div><div>${esc(i.kind_label)} ${badge(d.status)}</div><div>protocol</div><div>${esc(i.protocol)}</div>
      <div>address</div><div>${i.address ? `<code>${esc(i.address)}</code>` : "—"}</div><div>IP / port</div><div>${esc(i.ip || "—")} / ${esc(i.port || "—")}</div>
      <div>hostname / FQDN</div><div>${i.dns_names.length ? i.dns_names.map((n) => `<code>${esc(n)}</code>`).join(" ") : '<span class="muted">no DNS name in the approved zone</span>'}</div>
      ${i.otel_service ? `<div>telemetry identity</div><div><code>${esc(i.otel_service)}</code></div>` : ""}
      ${i.described_as.length ? `<div>customer called it</div><div>${esc(i.described_as.join(", "))}</div>` : ""}
      ${i.same_host_as.length ? `<div>same host as</div><div>${esc(i.same_host_as.join(", "))}</div>` : ""}
      <div>discovery sources</div><div>${esc(d.sources.join(", "))} · confidence ${d.confidence}</div>
      <div>evidence trust</div><div>${d.claims.map((x) => x.trust).filter((t, k, a) => a.findIndex((y) => y.level === t.level) === k).map(trustChip).join("")}
        ${d.verified ? "" : '<br><b class="small" style="color:#d29922">Not independently verified — only asserted / inferred evidence.</b>'}</div>
      ${d.service_of.length ? `<div>replica of</div><div>${d.service_of.map(assetLink).join(", ")}</div>` : ""}
      ${d.replicas.length ? `<div>replicas</div><div>${d.replicas.map(assetLink).join(", ")}</div>` : ""}</div>
      ${c ? `<h3>A2A Agent Card</h3><div class="kv"><div>name</div><div>${esc(c.name || "—")}</div>${c.description ? `<div>description</div><div>${esc(c.description)}</div>` : ""}
        <div>skills</div><div>${(c.skills || []).map((x) => `<span class="badge">${esc(typeof x === "string" ? x : x.name || x.id)}</span>`).join(" ") || "—"}</div>
        <div>advertised URL(s)</div><div>${(c.advertised_urls || []).map((u) => `<code>${esc(u)}</code>`).join("<br>") || "—"}</div>
        <div>security schemes</div><div>${(c.security_schemes || []).length ? esc(JSON.stringify(c.security_schemes)) : '<b class="priv">none declared</b> — any client can submit tasks'}</div>
        <div>streaming</div><div>${c.streaming ? "yes (SSE)" : "no / not declared"}</div></div>` : ""}
      ${d.mcp ? `<h3>MCP server</h3><div class="kv"><div>server</div><div>${esc(d.mcp.server_name)} ${esc(d.mcp.server_version || "")}</div><div>protocol</div><div>${esc(d.mcp.protocol_version || "—")}</div>
        <div>authentication</div><div>${d.mcp.authenticated ? "required" : '<b class="priv">none</b> — initialize + tools/list succeeded without credentials'}</div>
        <div>tools</div><div>${tools.length} (${tools.filter((t) => t.privileged).length} privileged) — see the Tools tab</div></div>` : ""}`;
    body += canon;
  } else if (SEL.tab === "tools") {
    body = `<p class="small muted">Tool inventory returned by <code>tools/list</code> during the protocol fingerprint. Annotations are self-declared by the server.</p>
      <table class="t toolstbl"><tr><th>tool</th><th>annotations</th></tr>${tools.map((t) => `<tr><td><code>${esc(t.name)}</code>${t.privileged ? ' <span class="priv">privileged</span>' : ""}</td>
      <td class="small">${Object.entries(t.annotations).map(([k, v]) => `${esc(k)}=${esc(v)}`).join(", ") || '<span class="muted">none</span>'}</td></tr>`).join("")}</table>`;
  } else if (SEL.tab === "comms") {
    body = d.communications.length ? `<table class="t"><tr><th></th><th>peer</th><th>protocol</th><th>path</th><th>calls</th><th>evidence</th></tr>${d.communications.map((c) =>
      `<tr><td>${c.direction === "outbound" ? "→" : "←"}</td><td>${assetLink(c.peer)}</td><td><a class="linkish" data-sel-edge="${esc(c.id)}">${esc(c.kind.replace(/^calls_/, ""))}</a></td>
       <td>${c.path ? badge(c.path, c.path === "via_bigip" ? "ok" : "warn") : '<span class="muted">—</span>'}</td><td>${c.calls ?? ""}</td>
       <td class="small">${c.trust.map((t) => esc(t.replace(/_/g, " "))).join(", ")} ${evLinks(c.evidence_ids, d.id)}${c.trace_ids.length ? "<br>traces: " + c.trace_ids.slice(0, 3).map(traceLink).join(" ") : ""}</td></tr>`).join("")}</table>
      <p class="small muted">Click a protocol to open that connection's evidence, latency and traces.</p>` : `<p class="muted">No communication observed or configured for this service.</p>`;
  } else if (SEL.tab === "findings") {
    body = d.findings.length ? d.findings.map((f) => `<div class="card" style="padding:9px"><span class="tag-dom ${f.domain}">AI ${f.domain === "security" ? "Security" : "Delivery"}</span>
      ${badge(f.class_label || "", f.class)} ${badge(f.severity)} <b>${esc(f.rule_id)}</b> ${esc(f.issue || f.title)}<div class="small">${esc(f.title)}</div>
      <div class="small">${f.package ? `addressed by the AI ${esc(f.package)} package` : "<b>not addressed by a package in this iteration</b>"} · evidence ${evLinks(f.evidence_ids, d.id)}
      · <a class="linkish" data-goto-finding="${esc(f.rule_id)}">open in Assess</a></div></div>`).join("") : `<p class="muted">No findings reference this service.</p>`;
  } else if (SEL.tab === "evidence") {
    body = `<table class="t"><tr><th>source</th><th>trust</th><th>conf.</th><th>when</th><th>evidence</th></tr>${d.claims.map((c) =>
      `<tr><td>${esc(c.source)} <span class="muted small">${esc(c.method || "")}</span></td><td>${trustChip(c.trust)}</td><td>${c.confidence}</td><td>${ts(c.ts)}</td><td>${evLinks([c.evidence_id], d.id)}</td></tr>`).join("")}</table>
      <p class="small muted">Evidence opens filtered to this service; the full raw document stays one click away.</p>`;
  } else if (SEL.tab === "recs") {
    body = d.recommendations.length ? d.recommendations.map((p) => `<div class="card" style="padding:9px"><span class="tag-dom ${p.kind === "security" ? "security" : "delivery"}">AI ${esc(p.kind)}</span>
      <b>${esc(p.title)}</b><div class="small">${esc(p.why.join("; "))}</div><a class="linkish small" data-goto-pkg="${esc(p.id)}">open in Recommend</a></div>`).join("")
      : `<p class="muted">${PKGS.length ? "No generated package references this service." : "No recommendations generated yet."}</p>`;
  } else body = jv(d.attrs, { id: `asset-attrs:${d.id}`, title: `${d.name} — discovered attributes`, filename: `asset-${d.id}.json`, height: 520 });
  patch($("#g-panel"), `<header><div class="t"><b>${esc(d.name)}</b><br><span class="small muted">${esc(i.kind_label)} · <code>${esc(d.key)}</code></span></div>
    <button data-panel-wide title="Widen panel">⇔</button><button data-panel-close title="Close">✕</button></header>${panelTabs(tabs)}<div class="pbody">${body}</div>`);
}
function renderEdgePanel(d) {
  const o = d.observed || {};
  const tabs = [["overview", "Overview"], ["evidence", `Evidence (${d.claims.length})`], ["raw", "Raw"]];
  let body = "";
  if (SEL.tab === "overview") {
    body = `<div class="kv"><div>from</div><div>${assetLink(d.from)}</div><div>to</div><div>${assetLink(d.to)}</div><div>protocol</div><div>${esc(d.protocol)}</div>
      <div>observed path</div><div>${d.observed_path ? badge(d.observed_path, d.observed_path === "via_bigip" ? "ok" : "warn") : '<span class="muted">not established</span>'}</div>
      ${d.asserted_paths.length ? `<div>customer asserted</div><div>${esc(d.asserted_paths.join(", "))} ${d.assertion_contradicted ? badge("contradicted by telemetry", "fail") : ""}</div>` : ""}
      <div>status</div><div>${badge(d.status)} · confidence ${d.confidence}</div>
      ${o.calls != null ? `<div>calls observed</div><div>${o.calls}${o.errors ? ` · ${o.errors} errors` : ""}${o.trace_count ? ` in ${o.trace_count} traces` : ""}</div>` : ""}
      ${o.latency_ms ? `<div>latency</div><div>${latTxt(o.latency_ms)}<br><span class="small muted">${esc(o.latency_source || "")}${o.mixed_operations ? " — mixes operation types; see per-operation rows" : ""}</span></div>` : ""}
      ${o.tools && Object.keys(o.tools).length ? `<div>MCP tools</div><div>${Object.entries(o.tools).map(([k, v]) => `<code>${esc(k)}</code>×${v}`).join(" ")}</div>` : ""}
      ${o.replicas && o.replicas.length ? `<div>replicas</div><div>${esc(o.replicas.join(", "))}</div>` : ""}
      ${o.peer_addresses && o.peer_addresses.length ? `<div>peer addresses</div><div>${o.peer_addresses.map((x) => `<code>${esc(x)}</code>`).join(" ")}</div>` : ""}</div>
      ${o.latency_by_operation && Object.keys(o.latency_by_operation).length > 1 ? `<h3>Latency by operation</h3><table class="t">${Object.entries(o.latency_by_operation).map(([k, l]) =>
        `<tr><td><code>${esc(k)}</code></td><td class="small">${latTxt(l)}</td></tr>`).join("")}</table>` : ""}
      ${d.trace_ids.length ? `<h3>Trace evidence</h3><div class="small">${d.trace_ids.map(traceLink).join(" ")}</div>` : ""}`;
  } else if (SEL.tab === "evidence") {
    body = `<table class="t"><tr><th>source</th><th>trust</th><th>path</th><th>conf.</th><th>when</th><th>evidence</th></tr>${d.claims.map((c) =>
      `<tr><td>${esc(c.source)}</td><td>${trustChip(c.trust)}</td><td>${esc(c.path)}</td><td>${c.confidence}</td><td>${ts(c.ts)}</td><td>${evLinks([c.evidence_id], d.from && d.from.id)}</td></tr>`).join("")}</table>`;
  } else body = jv(d.claims.map((c) => ({ source: c.source, path: c.path, attrs: c.attrs })), { id: `edge-claims:${d.id}`, title: "Observed attributes per claim", filename: `edge-${d.id}.json`, height: 520 });
  patch($("#g-panel"), `<header><div class="t"><b>${esc(d.from.name)} → ${esc(d.to.name)}</b><br><span class="small muted">${esc(d.kind)}</span></div>
    <button data-panel-wide title="Widen panel">⇔</button><button data-panel-close title="Close">✕</button></header>${panelTabs(tabs)}<div class="pbody">${body}</div>`);
}
document.addEventListener("click", (e) => {
  const t = e.target.closest("[data-ptab],[data-panel-close],[data-panel-wide],[data-sel-asset],[data-sel-edge],[data-goto-finding],[data-goto-pkg],[data-asset-link]");
  if (!t) return;
  if (t.dataset.ptab) { SEL.tab = t.dataset.ptab; renderPanel(); }
  else if (t.hasAttribute("data-panel-close")) closePanel();
  else if (t.hasAttribute("data-panel-wide")) $("#g-panel").classList.toggle("wide");
  else if (t.dataset.selAsset || t.dataset.assetLink) { const id = t.dataset.selAsset || t.dataset.assetLink; $("#modal").classList.add("hidden"); if (PAGE !== "discover") go("discover"); setTimeout(() => selectAsset(id), PAGE === "discover" ? 0 : 250); }
  else if (t.dataset.selEdge) selectEdge(t.dataset.selEdge);
  else if (t.dataset.gotoFinding) { go("assess"); setTimeout(() => flashKey(`fg-${t.dataset.gotoFinding}`), 150); }
  else if (t.dataset.gotoPkg) { go("recommend"); setTimeout(() => flashKey(`pkg-${t.dataset.gotoPkg}`), 150); }
});
function flashKey(k) { const el = document.querySelector(`[data-key="${CSS.escape(k)}"]`); if (!el) return; el.scrollIntoView({ block: "start", behavior: "smooth" }); el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash"); }
async function renderDiscover() {
  if (!STATE) return;
  await loadServices();
  if (DVIEW === "topology") renderGraph(STATE.graph);
  if (DVIEW === "changes" && !UICore.UI.background) loadChanges();
  const S = STATE.sources;
  patch($("#d-sources"), [["observe", "Observe", "BIG-IP config (read-only)"], ["describe", "Describe", "SE description (AI)"], ["enumerate", "Enumerate", "approved-scope probes"],
    ["ingest", "Ingest", "OpenTelemetry traces"]].map(([k, n, d]) => `<div class="src"><b>${S[k].evidence}</b>${n} <span class="muted">· ${d}</span><br>
    <span class="muted">${S[k].last_run ? "last " + ts(S[k].last_run) : "not run"}</span></div>`).join(""));
  const sc = STATE.scope;
  patch($("#d-scope"), `${esc(sc.statement)}<div class="kv" style="margin-top:6px"><div>CIDRs</div><div>${esc(sc.cidrs.join(", "))}</div>
    <div>approved hosts</div><div>${esc(sc.approved_hosts.join(", ") || "—")}</div><div>ports</div><div>${esc((sc.ports || []).join(", "))}</div>
    <div>DNS zone</div><div>${esc(sc.dns_zone)} @ ${esc(sc.dns_server)}</div><div>inventory</div><div>${esc(sc.inventory.join(", "))}</div></div>`);
  patch($("#d-gaps"), STATE.gaps.length ? STATE.gaps.map((g) => `<li>${esc(g.gap)} <span class="muted">→ ${esc(g.close_with)}</span></li>`).join("")
    : `<li class="muted">${STATE.counters.evidence ? "No open coverage gaps" : "Nothing discovered yet"}</li>`);
  if (STATE.sources.describe.evidence && !ANALYSIS) ANALYSIS = await api("/api/describe/analysis").catch(() => null);
  renderAI();
}
function renderAI() {
  const A = ANALYSIS;
  if (!A || !A.descriptions.length) { patch($("#d-ai"), ""); return; }
  const d = A.descriptions[A.descriptions.length - 1];
  const cnt = (s) => d.claims.filter((c) => c.status === s).length;
  patch($("#d-ai"), `<div class="card ai" style="margin-top:8px"><h4>AI interpretation ${d.llm ? badge("LLM", "observed") : badge("deterministic parser — not an LLM", "warn")}</h4>
    <div class="small muted">${esc(d.generated_by)} · by ${esc(d.author)} · ${ts(d.collected_at)}${d.fallback_reason ? ` · fallback: ${esc(d.fallback_reason)}` : ""}</div>
    ${A.contradictions.map((c) => `<div class="contradiction" style="margin-top:8px"><b>⚠ Contradicted by telemetry (S-007):</b> “${esc(c.text || c.subject)}”<br>
      <span class="small">${esc(c.explanation)} Evidence: ${evLinks(c.evidence)}</span></div>`).join("")}
    <h3>Components extracted (${d.components.length})</h3><ul class="clean small">${d.components.map((c) => `<li><b>${esc(c.name)}</b> <span class="muted">${esc(c.kind)}</span>
      ${c.matched_to ? `→ matched <b>${esc(c.matched_to.name)}</b> <code>${esc(c.matched_to.key)}</code> (score ${c.matched_to.score})` : badge(c.status, "unverified")}</li>`).join("")}</ul>
    ${d.relationships.length ? `<h3>Relationships</h3><ul class="clean small">${d.relationships.map((r) => `<li>${esc(r.from)} → ${esc(r.to)} <span class="muted">${esc(r.protocol)} · asserted ${esc(r.path)}</span></li>`).join("")}</ul>` : ""}
    <h3>Claims: ${cnt("confirmed")} confirmed · ${cnt("contradicted")} contradicted · ${cnt("unverified")} unverified</h3>
    <ul class="clean small">${d.claims.map((c) => `<li>${badge(c.status)} <b>${esc(c.claim)}</b> — “${esc((c.text || c.subject || "").slice(0, 120))}”<br>
      <span class="muted">${esc(c.explanation)}</span>${c.evidence.length ? ` <span class="muted">evidence:</span> ${evLinks(c.evidence)}` : ""}</li>`).join("") || "<li class='muted'>no control claims stated</li>"}</ul>
    ${A.follow_up_questions.length ? `<h3>Suggested follow-up questions for the customer</h3><ul class="clean small">${A.follow_up_questions.map((q) => `<li>${esc(q)}</li>`).join("")}</ul>` : ""}
    <div class="small muted">${esc(A.note)}</div></div>`);
}
$$("[data-method]").forEach((b) => (b.onclick = () => startOp("/api/ops/discover", { methods: [b.dataset.method] })));
$("#d-all").onclick = () => startOp("/api/ops/discover", { methods: ["observe", "enumerate", "ingest"] });
$("#d-describe").onclick = async () => { const t = $("#d-text").value.trim(); if (t.length < 10) return toast("Write a description first (≥ 10 characters).", "bad");
  if (await startOp("/api/ops/describe", { text: t })) { $("#d-text").value = ""; ANALYSIS = null; } };
$("#d-new").onclick = async () => { const n = await ask("New assessment", "Starts an empty assessment (the previous one is kept for before/after comparison).", { placeholder: "Customer AI environment — after", confirm: "Create" });
  if (n === null) return; await post("/api/assessment/new", { name: n || "Assessment" }); gsig = ""; ANALYSIS = null; refresh(true); };
$("#d-reset").onclick = async () => { const ok = await ask("Reset assessment", "Clears ONLY this discovery workspace. BIG-IP, applications, DNS, firewall rules, telemetry and the audit log are not touched. Type RESET to confirm.", { must: "RESET", confirm: "Reset assessment", cls: "danger" });
  if (ok === null) return; await post("/api/assessment/reset"); gsig = ""; ANALYSIS = null; $("#d-detail").textContent = ""; refresh(true); };

// ------------------------------------------------------------------ Wave 2A: canonical services, changes, schedule (evidence-only)
let SVCS = null, DVIEW = localStorage.getItem("ap.dview") || "topology", CHG = { snaps: [], sel: null, data: null, sched: null, type: "" };
const gchip = (g, label) => `<span class="gchip ${esc(g)}" title="${esc({ corroborated: "telemetry corroborates this grouping", inferred: "grouped by protocol metadata only — not independently verified",
  single: "one endpoint, no grouping needed", "unresolved-candidate": "an identical Agent Card exists elsewhere, but nothing proves it is the same agent",
  resolved: "instance identity observed in telemetry", provisional: "instance identity not observed — one provisional instance per endpoint" }[g] || "")}">${esc(label || String(g).replace(/-/g, " "))}</span>`;
function setDView(v) {
  DVIEW = v; localStorage.setItem("ap.dview", v);
  $$(".dviews [data-dview]").forEach((b) => b.classList.toggle("on", b.dataset.dview === v));
  $("#d-services").classList.toggle("hidden", v !== "services"); $("#d-changes").classList.toggle("hidden", v !== "changes");
  $(".graph-wrap").classList.toggle("hidden", v !== "topology");
  if (v === "topology") setTimeout(() => { cy.resize(); if (!gsig && STATE) renderGraph(STATE.graph); }, 30);
  if (v === "services") renderServices(); if (v === "changes") loadChanges();
}
document.addEventListener("click", (e) => { const b = e.target.closest("[data-dview]"); if (b) setDView(b.dataset.dview); });
async function loadServices() {
  SVCS = await api("/api/services").catch(() => SVCS);
  if (!SVCS) return;
  const sm = SVCS.summary;
  $("#dv-svc").textContent = sm.services;
  $("#dv-hint").textContent = `${sm.services} services · ${sm.instances} instances · ${sm.endpoints} endpoints${sm.unresolved ? ` · ${sm.unresolved} unresolved` : ""}`;
  const snaps = await api("/api/inventory/snapshots").catch(() => []);
  CHG.snaps = snaps; $("#dv-chg").textContent = snaps[0] && snaps[0].unacknowledged ? snaps[0].unacknowledged : "";
  if (DVIEW === "services") renderServices();
}
function renderServices() {
  if (!SVCS) return patch($("#d-services"), `<p class="muted"><span class="spin"></span>loading canonical services…</p>`);
  const V = SVCS, sm = V.summary;
  patch($("#d-services"), `<div class="small muted" style="margin-bottom:8px">Canonical identity is derived from stored evidence only. Endpoint records are never merged or deleted;
      a relationship the evidence does not settle is shown as <b>unresolved</b>. Telemetry evidence: ${sm.telemetry_evidence ? "present" : "<b>none</b> — run Ingest to resolve instances"}${sm.telemetry_evidence && !sm.instance_evidence ? " (older format: single-instance fallback only)" : ""}.</div>
    ${V.unresolved.map((u) => `<div class="unres" data-key="unres-${esc(u.type)}-${esc((u.endpoints || []).join(","))}"><b>${u.type === "possibly_same_service" ? "Possibly the same service — unresolved" : "Instance relationship unknown"}</b>
      <span class="small">${esc((u.endpoints || []).join(", "))}</span><div class="small">${esc((u.basis || []).join("; "))}${(u.basis || []).length ? " — " : ""}${esc(u.why_unresolved)}</div></div>`).join("")}
    ${V.notes.map((n) => `<div class="small muted" data-key="note-${esc(n.type)}">ⓘ ${esc(n.detail)} ${n.name ? `(${esc(n.name)})` : ""}</div>`).join("")}
    ${V.services.map((s) => `<div class="svc" data-key="svc-${esc(s.id)}"><h4>${esc(s.name)} <span class="badge">${esc(s.classification)}</span> ${gchip(s.grouping)}
        <span class="small muted">confidence ${s.confidence}</span>${s.replicas ? ` <span class="badge">${s.replicas} replicas ${gchip(s.replica_status)}</span>` : ""}
        ${s.verified ? "" : '<span class="trust u" title="no independent technical corroboration">not independently verified</span>'}</h4>
      <div class="small muted">${esc(s.basis.join("; "))}</div>
      ${s.instances.map((i) => `<div class="inst"><div class="small">instance <b>${esc(i.label)}</b> ${i.status === "provisional" && s.instances.length === 1 && i.endpoints.length === 1 ? '<span class="gchip single" title="only one endpoint was observed; no instance identity in the evidence">one endpoint · instance identity not observed</span>' : gchip(i.status)} <span class="muted">${esc(i.basis)}</span></div>
        ${s.endpoints.filter((e) => e.instance_id === i.id).map((e) => `<div class="small">↳ <a class="linkish" data-asset-link="${esc(e.asset_id)}">${esc(e.address)}</a> · ${esc(e.role)}
          ${e.membership && e.membership !== "single" ? gchip(e.membership, "membership " + e.membership) : ""} <span class="muted">last seen ${ts(e.last_seen)}</span></div>`).join("") ||
          '<div class="small muted">↳ no listening endpoint (instrumented client)</div>'}</div>`).join("")}
      <div class="small" style="margin-top:4px">${s.capabilities.skills.length ? `skills: ${esc(s.capabilities.skills.join(", "))} · ` : ""}${s.capabilities.tools.length ? `tools: ${s.capabilities.tools.length}${s.capabilities.privileged_tools.length ? ` (<span class="priv">${esc(s.capabilities.privileged_tools.join(", "))}</span>)` : ""} · ` : ""}
        ${s.auth.security_schemes ? `auth: ${s.auth.security_schemes.length ? esc(s.auth.security_schemes.join(", ")) : '<span class="priv">none declared</span>'} · ` : ""}${s.auth.mcp_authenticated === false ? '<span class="priv">MCP unauthenticated</span> · ' : ""}
        sources ${esc(s.sources.join(", "))} · first seen ${ts(s.first_seen)} · last seen ${ts(s.last_seen)}</div></div>`).join("") || '<p class="muted">No services discovered in this assessment.</p>'}`);
}
async function loadChanges() {
  const [snaps, sched] = await Promise.all([api("/api/inventory/snapshots").catch(() => []), api("/api/discovery/schedule").catch(() => null)]);
  CHG.snaps = snaps; CHG.sched = sched;
  if (!CHG.sel || !snaps.some((s) => s.id === CHG.sel)) CHG.sel = snaps[0] && snaps[0].id;
  CHG.data = CHG.sel ? await api(`/api/inventory/snapshots/${CHG.sel}`).catch(() => null) : null;
  renderChanges();
}
const CHG_TEXT = {
  new: (d) => `newly discovered at ${esc((d.endpoints || []).join(", ") || "—")} (${esc(d.classification || "")}, ${esc(d.grouping || "")})`,
  address_changed: (d) => `address changed ${esc((d.from || []).join(", "))} → ${esc((d.to || []).join(", "))}`,
  changed: (d) => `endpoints ${d.endpoints_added && d.endpoints_added.length ? "added " + esc(d.endpoints_added.join(", ")) : ""} ${Object.entries(d.endpoints_missing || {}).map(([a, st]) => `${esc(a)} ${esc(st)}`).join(", ")}`,
  replica_added: (d) => `instances ${d.instances_before} → ${d.instances_now}`, replica_removed: (d) => `instances ${d.instances_before} → ${d.instances_now} — ${esc(d.note || "")}`,
  capabilities_changed: (d) => `skills +[${esc((d.skills_added || []).join(", "))}] −[${esc((d.skills_removed || []).join(", "))}]`,
  tools_changed: (d) => `tools +[${esc((d.tools_added || []).join(", "))}] −[${esc((d.tools_removed || []).join(", "))}]${(d.privileged_added || []).length ? ` · <span class="priv">new privileged: ${esc(d.privileged_added.join(", "))}</span>` : ""}`,
  auth_changed: (d) => `authentication ${esc(JSON.stringify(d.from))} → ${esc(JSON.stringify(d.to))}`, version_changed: (d) => `version ${esc((d.from || []).join(","))} → ${esc((d.to || []).join(","))}`,
  relationship_added: (d) => `new ${esc(d.protocol)} relationship → ${esc(d.to)}`, relationship_removed: (d) => `${esc(d.protocol)} relationship → ${esc(d.to)} not observed — ${esc(d.note || "")}`,
  unreachable: (d) => `<b>unreachable</b>: ${esc(d.reason)} · last seen ${ts(d.last_seen)} · kept in inventory`, unobserved: (d) => `<b>unobserved</b>: ${esc(d.reason)} · last seen ${ts(d.last_seen)} · kept in inventory`,
  reappeared: (d) => `reappeared (was ${esc(d.previous_status)}) at ${esc((d.endpoints || []).join(", "))}`,
};
function renderChanges() {
  const S = CHG.sched || {}, D = CHG.data, cur = CHG.snaps.find((s) => s.id === CHG.sel);
  const types = D ? [...new Set(D.changes.map((c) => c.change_type))] : [];
  const list = D ? D.changes.filter((c) => !CHG.type || c.change_type === CHG.type) : [];
  patch($("#d-changes"), `<div class="toolbar"><button class="primary" id="ch-snap" data-need="operator" ${can("operator") ? "" : "disabled"} title="Builds a snapshot from the evidence already stored in the current assessment — no network access">Record inventory snapshot</button>
      ${cur && cur.unacknowledged ? `<button id="ch-ack" data-need="operator" ${can("operator") ? "" : "disabled"}>Acknowledge ${cur.unacknowledged} change(s)</button>` : ""}
      <span class="small muted">Snapshots compare canonical services between discovery runs. Absence is classified, never deleted.</span></div>
    <div class="grid2"><div><h3>Snapshots</h3><table class="t">${CHG.snaps.map((s) => `<tr class="snaprow ${s.id === CHG.sel ? "sel" : ""}" data-snap="${esc(s.id)}" data-key="snap-${esc(s.id)}"><td>${new Date(s.created * 1000).toLocaleString()}</td>
        <td>${badge(s.trigger, s.trigger === "scheduled" ? "low" : "observed")}${s.reconstructed ? ' <span class="trust i" title="reconstructed from historical stored evidence">reconstructed</span>' : ""}</td>
        <td class="small">${esc(s.assessment_name || s.source_assessment)}</td><td>${s.changes} changes${s.unacknowledged ? ` <b>(${s.unacknowledged} new)</b>` : ""}</td></tr>`).join("") || "<tr><td class='muted'>No snapshots yet — record one, or backfill from history below.</td></tr>"}</table></div>
      <div><h3>Scheduled discovery</h3><div class="card" style="padding:9px"><div>${S.enabled ? badge("enabled", "ok") : badge("disabled", "warn")} ${S.permitted ? "" : badge("not permitted in this environment", "low")}
        <span class="small muted">cadence ${esc(S.cadence_min)} min · jobs ${esc((S.jobs || []).join(", "))} · last run ${S.last_run ? ts(S.last_run) + " " + esc(S.last_status || "") : "never"}</span></div>
        <p class="small muted">${esc(S.note || "")}</p>
        <p><button id="sch-enable" ${ME && ME.role === "owner" && S.permitted && !S.enabled ? "" : "disabled"}>Enable</button> <button id="sch-disable" ${ME && ME.role === "owner" && S.enabled ? "" : "disabled"}>Disable</button>
          <span class="why">${ME && ME.role === "owner" ? (S.permitted ? "" : "the environment configuration does not permit scheduling") : "lab owner only"}</span></p></div>
        <h3>Migration</h3><p class="small">Reconstruct snapshots from historical assessments' stored evidence (approver; marked <i>reconstructed</i>; original records untouched).</p>
        <p><button id="ch-backfill" ${can("approver") ? "" : "disabled"}>Preview backfill…</button></p></div></div>
    ${D ? `<h3>Changes in snapshot ${new Date(D.created * 1000).toLocaleString()} <select id="ch-type" style="margin-left:8px"><option value="">all types</option>${types.map((t) => `<option ${t === CHG.type ? "selected" : ""}>${esc(t)}</option>`).join("")}</select></h3>
      <div class="small muted">Coverage: ${Object.keys(D.coverage.sources || {}).map(esc).join(", ") || "no sources"}${D.coverage.scan ? ` · scan ${ts(D.coverage.scan.at)} (${esc((D.coverage.scan.scope_cidrs || []).join(", "))}; ports ${esc((D.coverage.scan.ports || []).join(","))})` : " · no scan"}${D.coverage.telemetry ? ` · telemetry ${ts(D.coverage.telemetry.at)}` : ""}</div>
      ${list.map((c) => `<div class="chg ${esc(c.change_type)}" data-key="chg-${esc(c.id)}"><span class="t">${esc(c.change_type.replace(/_/g, " "))}</span><span>${esc(c.service_name)}</span>
        <span>${(CHG_TEXT[c.change_type] || ((d) => esc(JSON.stringify(d))))(c.detail)} ${(c.evidence_ids || []).length ? "· evidence " + evLinks(c.evidence_ids) : ""}${c.acknowledged_by ? ` <span class="muted">· ack ${esc(c.acknowledged_by)}</span>` : ""}</span></div>`).join("") || '<p class="muted">No changes in this snapshot.</p>'}` : ""}`);
  const b = (id, fn) => { const el = $(id); if (el) el.onclick = fn; };
  b("#ch-snap", async () => { try { const r = await post("/api/inventory/snapshot", {}); toast(`Snapshot recorded: ${r.services} services, ${r.changes} changes`, "ok"); CHG.sel = r.snapshot_id; loadChanges(); loadServices(); } catch (e) { toast(esc(e.message), "bad"); } });
  b("#ch-ack", async () => { await post("/api/inventory/changes/ack", { snapshot_id: CHG.sel }).catch((e) => toast(esc(e.message), "bad")); loadChanges(); loadServices(); });
  b("#sch-enable", async () => { try { await api("/api/discovery/schedule", { method: "PUT", body: JSON.stringify({ enabled: true }) }); } catch (e) { toast(esc(e.message), "bad"); } loadChanges(); });
  b("#sch-disable", async () => { try { await api("/api/discovery/schedule", { method: "PUT", body: JSON.stringify({ enabled: false }) }); } catch (e) { toast(esc(e.message), "bad"); } loadChanges(); });
  b("#ch-backfill", async () => { const p = await post("/api/inventory/backfill", { dry_run: true }).catch((e) => ({ error: e.message }));
    if (p.error) return toast(esc(p.error), "bad");
    modal(`<h2>Backfill inventory history (preview)</h2><p class="small">Builds snapshots from stored evidence of these assessments, oldest first. Existing records are not modified.</p>
      <table class="t">${p.plan.map((x) => `<tr><td>${esc(x.name)}</td><td>${x.at ? new Date(x.at * 1000).toLocaleString() : "—"}</td><td>${x.technical_evidence} evidence</td><td>${esc(x.action)}</td></tr>`).join("")}</table>
      <p><button class="primary" id="bf-go">Reconstruct ${p.plan.filter((x) => x.action === "reconstruct").length} snapshot(s)</button></p>`);
    $("#bf-go").onclick = async () => { try { const r = await post("/api/inventory/backfill", { dry_run: false }); toast(`${r.created.length} snapshots reconstructed`, "ok"); } catch (e) { toast(esc(e.message), "bad"); }
      $("#modal").classList.add("hidden"); loadChanges(); }; });
  const sel = $("#ch-type"); if (sel) sel.onchange = () => { CHG.type = sel.value; renderChanges(); };
}
document.addEventListener("click", (e) => { const r = e.target.closest("[data-snap]"); if (r) { CHG.sel = r.dataset.snap; CHG.type = ""; loadChanges(); } });
function identityEdges(keep) {
  const out = [];
  for (const s of (SVCS && SVCS.services) || []) for (const i of s.instances) {
    const eps = i.endpoints.filter((x) => keep.has(x));
    for (let k = 1; k < eps.length; k++) out.push({ id: `same-${eps[0]}-${eps[k]}`, source: eps[0], target: eps[k], kind: "same_instance", status: "inferred", observed_path: null });
  }
  for (const u of (SVCS && SVCS.unresolved) || []) { const ids = (u.asset_ids || []).filter((x) => keep.has(x));
    for (let k = 1; k < ids.length; k++) out.push({ id: `maybe-${ids[0]}-${ids[k]}`, source: ids[0], target: ids[k], kind: "possibly_same", status: "asserted", observed_path: null }); }
  return out;
}
function canonicalBlock(c) {
  if (!c) return "";
  const s = c.service, inst = c.instances.find((i) => i.id === c.instance_id) || {};
  const role = c.instances.length > 1 ? `one of ${c.instances.length} instances (replicas${s.replica_status === "resolved" ? "" : ", provisional"})` : "the only instance";
  return `<h3>Canonical identity</h3><div class="kv"><div>logical service</div><div><b>${esc(s.name)}</b> ${gchip(s.grouping)} <span class="muted small">confidence ${s.confidence}</span></div>
    <div>this endpoint</div><div>${esc(c.role)} of instance <b>${esc(inst.label || "?")}</b> ${gchip(inst.status || "provisional")} — ${esc(role)}</div>
    <div>membership</div><div>${gchip(c.membership || "single", c.membership || "single")}</div>
    <div>basis</div><div class="small">${esc(s.basis.join("; "))}</div>
    <div>all endpoints</div><div>${c.endpoints.map((e) => `<a class="linkish" data-sel-asset="${esc(e.asset_id)}">${esc(e.address)}</a> <span class="muted small">(${esc(e.role)})</span>`).join("<br>")}</div>
    ${c.unresolved.length ? `<div>unresolved</div><div class="small">${c.unresolved.map((u) => esc(u.why_unresolved)).join("<br>")}</div>` : ""}</div>`;
}

// ------------------------------------------------------------------ ASSESS
let OVR = null, OVR_AT = 0;
const PROT_CLS = { yes: "ok", no: "fail", unknown: "unverified", "n/a": "skipped" };
function renderOverview(where) {
  const el = $(where === "assess" ? "#a-overview" : "#o-overview"); if (!el) return;
  api("/api/overview").then((o) => { OVR = o; OVR_AT = Date.now(); paint(); renderStages(); }).catch((e) => { OVR = OVR && !OVR.error ? OVR : { error: e.message || "request failed" }; paint(); });
  function paint() {
    if (!OVR) return patch(el, `<div class="card ovr"><p class="muted"><span class="spin"></span>loading ${where === "assess" ? "risk dashboard" : "overview"}…</p></div>`);
    if (OVR.error) return patch(el, `<div class="card ovr"><h3 style="margin-top:0">${where === "assess" ? "Risk dashboard" : "Overview"}</h3><p class="small">unavailable: ${esc(OVR.error)} — retried on the next refresh</p></div>`);
    const Q = OVR.questions, sev = Q.at_risk.findings_by_severity;
    const tiles = where === "assess"
      ? [["services discovered", Q.operating.value, Q.operating.source], ["high-severity findings", sev.high, Q.at_risk.source],
         ["services with findings", Q.at_risk.services_with_findings, Q.at_risk.source], ["unverified services", OVR.risk.unverified_services.length, "identity grouping not corroborated"],
         ["protected / unprotected / unknown / client n/a", `${Q.protected.yes} / ${Q.protected.no} / ${Q.protected.unknown} / ${Q.protected.not_applicable ?? 0}`, Q.protected.source]]
      : [["AI services operating", Q.operating.value, Q.operating.source], [`protected${Q.protected.not_applicable ? ` (${Q.protected.not_applicable} client n/a)` : ""}`, `${Q.protected.yes} of ${Q.protected.applicable ?? Q.operating.value} applicable`, Q.protected.source],
         ["with findings", Q.at_risk.services_with_findings, Q.at_risk.source], ["delivering BIG-IP", Q.delivering.devices.join(", ") || "none observed", Q.delivering.source],
         ["BIG-IP health", Q.healthy.devices.map((d) => `${d.device.replace("bigip:", "")} ${d.result}${d.warnings.length ? " (" + d.warnings.length + " warning)" : ""}`).join(" · ") || "no evidence", Q.healthy.source],
         ["last deployment", Q.changed.last_deployment ? `${Q.changed.last_deployment.kind || ""} ${Q.changed.last_deployment.status}` : "none", Q.changed.source]];
    patch(el, `<div class="card ovr" data-key="ovr-${where}"><h3 style="margin-top:0">${where === "assess" ? "Risk dashboard" : "Overview"} <span class="small muted">${esc(OVR.statement)}</span></h3>
      <div class="tiles">${tiles.map(([n, v, src]) => `<div class="tile" title="source: ${esc(src)}"><b>${esc(v)}</b><span>${esc(n)}</span></div>`).join("")}</div>
      <table class="t small"><tr><th>Service</th><th>Kind</th><th>Protected</th><th>Delivered by</th><th>Findings H/M/L</th><th>Identity</th></tr>
      ${OVR.services.map((s) => `<tr data-key="ovs-${esc(s.id)}"><td>${esc(s.name)}</td><td>${esc(s.classification)}</td><td title="${esc(s.protected_basis)}">${badge(s.protected, PROT_CLS[s.protected])}${s.protection_note ? ` <span class="small muted">${esc(s.protection_note)}</span>` : ""}</td>
        <td>${esc(s.delivered_by.join(", ") || "—")}</td><td>${s.findings.high} / ${s.findings.medium} / ${s.findings.low}</td><td>${s.verified ? gchip(s.grouping) : '<span class="trust u">not independently verified</span>'}</td></tr>`).join("")}</table>
      ${where === "assess" && OVR.history.length > 1 ? `<details data-key="ovr-hist"><summary class="small">Findings over time (${OVR.history.length} assessments with findings)</summary>
        <table class="t small"><tr><th>Assessment</th><th>Date</th><th>High</th><th>Medium</th><th>Low</th></tr>${OVR.history.map((h) => `<tr data-key="ovh-${esc(h.assessment_id)}"><td>${esc(h.name)}${h.current ? " <b>(current)</b>" : ""}</td>
          <td>${ts(h.created)}</td><td>${h.findings.high}</td><td>${h.findings.medium}</td><td>${h.findings.low}</td></tr>`).join("")}</table></details>` : ""}
      ${where === "observe" ? `<h3>AI interactions (observed)</h3><div class="small muted">${esc(OVR.interactions.source)}</div>
        ${OVR.interactions.edges.length ? `<table class="t small"><tr><th>From</th><th>To</th><th>Protocol</th><th>Path</th><th>Calls</th><th>Errors</th><th>p50 / p95 ms</th><th>Replicas</th></tr>
        ${OVR.interactions.edges.map((e, i) => `<tr data-key="ovi-${i}"><td>${esc(e.from)}</td><td>${esc(e.to)}</td><td>${esc(e.protocol)}</td><td>${esc(e.path)}</td><td>${e.calls ?? "—"}</td><td>${e.errors ?? "—"}</td>
          <td>${e.p50_ms ?? "—"} / ${e.p95_ms ?? "—"}${e.n != null ? ` <span class="muted">(n=${e.n}${e.p95_reliable === false ? ", p95 unreliable" : ""})</span>` : ""}</td><td>${esc((e.replicas || []).join(", ") || "—")}</td></tr>`).join("")}</table>`
          : '<p class="small muted">No traced interactions in this assessment (run Ingest).</p>'}
        <div class="small muted">Not available without more instrumentation: ${OVR.interactions.not_available.map(esc).join(" · ")}</div>` : ""}
      ${where === "observe" && Q.changed.recent_changes.length ? `<div class="small muted">recent inventory changes: ${Q.changed.recent_changes.slice(0, 8).map((c) => `${esc(c.service)} ${esc(c.type)}`).join(" · ")}</div>` : ""}</div>`);
  }
  paint();
}
function renderAssess() {
  renderOverview("assess");
  if (!STATE) return;
  const G = STATE.findings_grouped, cls = $("#a-class").value, cat = $("#a-cat").value;
  const count = (c) => G.filter((g) => g.class === c).reduce((n, g) => n + g.count, 0);
  patch($("#a-tiles"), [["contradicted_claim", "contradicted claims"], ["confirmed_vulnerability", "confirmed vulnerabilities"], ["architectural_gap", "architectural gaps"],
    ["inferred_risk", "inferred risks"]].map(([c, n]) => `<div class="tile"><b>${count(c)}</b><span>${n}</span></div>`).join("") +
    `<div class="tile"><b>${STATE.findings.length}</b><span>findings in ${G.length} issue types</span></div>`);
  const list = G.filter((g) => (!cls || g.class === cls) && (!cat || g.category === cat));
  patch($("#a-list"), list.length ? list.map((g) => `<div class="card ${g.class === "contradicted_claim" ? "alert" : ""}" data-key="fg-${esc(g.rule_id)}">
    <h4><span class="tag-dom ${g.rule_id.startsWith("S-") ? "security" : "delivery"}">AI ${g.rule_id.startsWith("S-") ? "Security" : "Delivery"}</span> ${badge(g.class_label, g.class)} ${badge(g.severity)} <span class="muted">${esc(g.rule_id)}</span> ${esc(g.issue)} <span class="muted">× ${g.count}</span></h4>
    <div class="small">${esc(g.items[0].detail)}</div>
    <div class="kv" style="margin-top:8px"><div>evidence basis</div><div>${esc(g.basis)}</div>
      <div>affected</div><div>${g.affected.map((a) => `<a class="badge linkish" data-asset-link="${esc(a.id)}" title="Open this service in the Discover topology">${esc(a.name)} <span class="muted">${esc(a.endpoint)}</span></a>`).join(" ")}</div>
      <div>addressed by</div><div>${g.package === "per finding" ? "depends on the contradicted claim — see each finding below"
        : g.package ? `AI ${esc(g.package[0].toUpperCase() + g.package.slice(1))} package · proven by ${esc((g.tests || []).join(", "))}` : `<b>not addressed in this iteration</b> — ${esc(g.not_addressed || "")}`}</div>
      <div>evidence</div><div>${evLinks(g.evidence_ids, g.affected.length === 1 ? g.affected[0].id : null)}</div>
      ${g.guidance ? `<div>business impact</div><div>${esc(g.guidance.impact || "—")}</div>
      <div>mitigation</div><div>${esc(g.guidance.mitigation || "—")}</div>
      <div>BIG-IP control</div><div>${g.guidance.control ? esc(g.guidance.control) : `<span class="muted">${esc(g.guidance.control_status)}</span>`}</div>
      <div>confidence</div><div>${badge(g.guidance.confidence, g.guidance.confidence === "high" ? "observed" : "inferred")} <span class="small muted">${esc(g.guidance.confidence_basis)}</span></div>
      <div>limitations</div><div class="small">${esc(g.guidance.limitations || "")}</div>` : ""}</div>
    ${g.count > 1 ? `<details data-key="fgd-${esc(g.rule_id)}"><summary>${g.count} individual findings</summary><ul class="clean small">${g.items.map((i) => `<li><b>${esc(i.title)}</b> — ${esc(i.detail)}
      ${(i.asset_ids || []).length ? ` <a class="linkish" data-asset-link="${esc(i.asset_ids[0])}">service</a> · evidence ${evLinks(i.evidence_ids, i.asset_ids[0])}` : ""}${g.package === "per finding" ? ` <span class="muted">(${i.package ? `AI ${esc(i.package)} · proven by ${esc((i.tests || []).join(", "))}` : "not machine-verifiable"})</span>` : ""}</li>`).join("")}</ul></details>` : ""}</div>`).join("")
    : `<p class="muted">${STATE.findings.length ? "No findings match the filter." : "No findings yet. Findings are produced only from discovered evidence — run discovery first."}</p>`);
}
$("#a-class").onchange = renderAssess; $("#a-cat").onchange = renderAssess;
$("#a-run").onclick = () => startOp("/api/ops/assess", {});

// ------------------------------------------------------------------ RECOMMEND
const REVIEWS = {};
function actBtn(p, action, label, cls, handler) {
  const a = p.lifecycle.actions[action];
  return `<button class="${cls}" ${a.allowed ? "" : "disabled"} title="${esc(a.reason || "")}" onclick="${handler}">${label}</button>${a.allowed ? "" : `<span class="why">${esc(a.reason)}</span>`}`;
}
function changeTable(rows) {
  return `<table class="t"><tr><th>action</th><th>object</th><th>name</th><th>detail</th></tr>${rows.map((c) => `<tr><td>${badge(c.action === "host" ? "host step" : c.action, c.action === "host" ? "warn" : "observed")}</td>
    <td>${esc(c.object)}</td><td><code>${esc(c.name)}</code></td><td class="small">${esc(c.detail)}</td></tr>`).join("")}</table>`;
}
function renderRecommend() {
  patch($("#r-list"), PKGS.length ? PKGS.map((p) => { const b = p.body, x = b.explanation || {}, v = p.validation || {}, lc = p.lifecycle;
    return `<div class="card" data-key="pkg-${esc(p.id)}"><h4><span class="tag-dom ${p.kind === "security" ? "security" : "delivery"}">AI ${p.kind === "security" ? "Security" : "Delivery"}</span> ${esc(p.title)} ${badge(lc.state)}</h4><div class="small muted">${esc(x.summary || "")} · target <code>${esc(p.target)}</code> · hash <code>${esc(p.hash.slice(0, 16))}…</code>
      · AS3 schema ${v.valid ? badge("valid", "ok") : badge("invalid", "fail")}</div>
      ${lc.blocked ? `<p class="small">🔒 ${esc(lc.blocked)}</p>` : ""}
      <p style="margin:10px 0">${actBtn(p, "review", "▶ Preview, Diff &amp; Preflight on device", "hero", `review('${p.id}')`)}
        <span class="small muted">&nbsp;Reads the live device state, diffs it against this package and runs every preflight check — required before approval.</span></p>
      <div id="rv-${p.id}">${REVIEWS[p.id] ? reviewHTML(REVIEWS[p.id]) : ""}</div>
      <div class="grid2" style="margin-top:8px"><div><h3>Business value</h3><ul class="clean small">${(x.business_value || []).map((t) => `<li>${esc(t)}</li>`).join("")}</ul>
        <h3>Findings addressed</h3><table class="t">${(x.findings_addressed || []).map((f) => `<tr><td>${esc(f.rule)}</td><td>${esc(f.issue)} <span class="muted">× ${f.count}</span></td>
          <td class="small muted">proven by ${esc(f.proven_by.join(", "))}</td></tr>`).join("")}</table>
        ${(x.addressed_later || []).length ? `<p class="small muted">Next stage: ${x.addressed_later.map((f) => esc(`${f.rule} ${f.issue}`)).join("; ")}</p>` : ""}
        ${(x.not_addressed || []).length ? `<h3>Not addressed by this package</h3><ul class="clean small">${x.not_addressed.map((f) => `<li><b>${esc(f.rule)}</b> ${esc(f.issue)} — <span class="muted">${esc(f.reason)}</span></li>`).join("")}</ul>` : ""}</div>
      <div><h3>Affected services</h3><div class="small">${(x.affected_services || []).map((s) => `<span class="badge">${esc(s)}</span>`).join(" ")}</div>
        <h3>Deployment dependencies</h3><ul class="clean small">${(x.deployment_dependencies || []).map((d) => `<li>${esc(d)}</li>`).join("")}</ul>
        <h3>Host steps (executed only after approval)</h3><ol class="small">${b.dependencies.map((d) => `<li><code>${esc(d.host)}</code> ${esc(d.command)} — ${esc(d.effect)}</li>`).join("")}</ol>
        ${b.tool_allow_list ? `<h3>Tool authorisation (from observed usage)</h3><ul class="clean small">${Object.entries(b.tool_allow_list).map(([k, t]) => `<li><b>${esc(k)}</b>: ${esc(t.join(", "))}</li>`).join("")}</ul>
          <div class="small muted">rate limit ${b.rate_limit_per_min}/min per identity; every other identity and tool is denied</div>` : ""}
        <h3>Rollback</h3><div class="small">${esc(b.rollback)}</div></div></div>
      <h3>What will change</h3>${changeTable(x.change_summary || [])}
      <details data-key="as3-${esc(p.id)}"><summary>Advanced: full AS3 declaration (JSON)</summary>${jv(b.as3, { id: `as3:${p.id}`, title: `AS3 declaration — ${p.title}`, filename: `as3-${p.kind}-${p.hash.slice(0, 12)}.json`, height: 460 })}</details></div>`; }).join("")
    : `<p class="muted">No recommendations yet. Run discovery, review findings, then Generate recommendations.</p>`);
}
const CHECK_TEXT = {
  "sequence.requires": "AI Security cannot proceed until AI Delivery has been successfully deployed and validated.",
  "template.bigip_version": "The BIG-IP version must be one the pattern library was validated on.",
  "template.as3_version": "AS3 on the BIG-IP must be recent enough for this package.",
  "prereq.self_ips": "The BIG-IP must have the expected self IPs (network prerequisites).",
  "prereq.certificates": "The lab certificates the package references must exist on the BIG-IP.",
  "prereq.clock": "The BIG-IP clock must agree with Autopilot (certificate and log correctness).",
  "resource.control_plane_memory": "The BIG-IP control plane must have enough memory and swap headroom.",
  "resource.rest_latency": "The BIG-IP management API must respond quickly enough for a safe change.",
  "policy.as3_scope": "The package may only touch the approved tenant and pattern-library objects.",
};
const checkText = (id) => CHECK_TEXT[id] || (id.startsWith("policy.dependency.") ? `The host step on ${id.slice(18)} must be on the allow-list.` : "");
function reviewHTML(r) {
  if (r.error) return `<p class="small">${esc(r.error)}</p>`;
  const caps = r.device.capabilities, ok = r.preflight.every((c) => c.ok);
  return `<div class="card ${ok ? "" : "alert"}" style="margin-top:8px"><h4>Preflight ${ok ? badge("passed", "ok") : badge("failed", "fail")} <span class="small muted">recorded ${ts(r.review.created)} by ${esc(r.review.reviewer)} · valid 30 min for approval</span></h4>
    <div class="small muted">Verified on device: BIG-IP ${esc(caps.bigip_version)} · AS3 ${esc(caps.as3_version)} · self IPs ${esc(caps.self_ips.join(", "))} · clock skew ${(+caps.clock_skew_s).toFixed(1)} s · host profiles ${esc(Object.values(r.device.hosts).join("/"))}</div>
    <ul class="clean small">${r.preflight.map((c) => `<li>${badge(c.level || (c.ok ? "pass" : "fail"), c.level === "warn" ? "warn" : c.ok ? "pass" : "fail")} ${checkText(c.check) ? `<b>${esc(checkText(c.check))}</b> ` : ""}<code>${esc(c.check)}</code> <span class="muted">${esc(typeof c.detail === "string" ? c.detail : JSON.stringify(c.detail))}</span></li>`).join("")}</ul>
    <details data-key="diff-${esc(r.review.id || r.review.created)}"><summary>Advanced: configuration diff (device AP_AI → proposed)</summary>${jvLines(r.diff, { id: `diff:${r.review.id || r.review.created}`, title: "Configuration diff — device AP_AI → proposed", filename: "as3-diff.txt", height: 420 })}</details></div>`;
}
window.review = async (id) => {
  $$(`[id="rv-${id}"]`).forEach((el) => patch(el, `<p class="small"><span class="spin"></span>reading device state, running preflight checks on BIG-IP_C…</p>`));
  try { REVIEWS[id] = await api(`/api/packages/${id}/review`); } catch (e) { REVIEWS[id] = { error: e.message }; }
  await refresh(false); if (PAGE === "approve") renderApprove();
};
$("#r-gen").onclick = () => startOp("/api/ops/recommend", {});

// ------------------------------------------------------------------ Wave 3: placement advisory (read-only; GET only)
let ADV = null, ADV_BUSY = false;
async function loadAdvisory() {
  if (ADV_BUSY) return; ADV_BUSY = true;
  try { ADV = await api("/api/recommendations/advisory"); } catch (e) { ADV = { error: e.message }; }
  ADV_BUSY = false; if (PAGE === "recommend") renderAdvisory(false); else if (PAGE === "approve") renderApprove();
}
const PST = { observed: "read from stored evidence", inferred: "derived by a stated rule from observed facts", configured: "from configuration or a preference — shown, never proof",
  unknown: "not present in the evidence", unverified: "on a target device the evidence does not verify" };
const EVS = { missing: "not collected", stale: "older than the health freshness limit", unsupported: "not supported by this device (HTTP 400/404/501)",
  permission_denied: "the collector's account may not read it (HTTP 401/403)", malformed: "response not in the expected shape", failed: "collection failed (timeout, TLS, connection or HTTP 5xx)" };
const ago = (t) => t ? `${Math.max(0, Math.round((Date.now() / 1000 - t) / 60))} min ago` : "time unknown";
function advExplain(x, selected, sid) {
  if (!x) return "";
  return `<details class="advexp" data-key="advexp-${esc(sid)}" open><summary><b>${selected ? "Why this device" : "Why no device was selected"}</b></summary>
    ${selected ? `<ul class="clean small">${x.why_selected.map((w) => `<li>✓ ${esc(w)}</li>`).join("")}</ul>
      <div class="small"><b>Supporting evidence</b></div><ul class="clean small">${x.supporting_evidence.map((e) => `<li><code>${esc(e.evidence_id)}</code> ${esc(e.what)}${e.collected_at ? ` · collected ${esc(ago(e.collected_at))}` : ""}</li>`).join("")}</ul>`
      : `<p class="small">${esc(x.why_not_selected || "")}</p>${(x.missing_evidence || []).length ? `<div class="small"><b>Missing or unusable evidence</b></div><ul class="clean small">${x.missing_evidence.map((m) => `<li><code>${esc(m.device)}</code> ${esc(m.check)} — <span class="evs ${esc(m.evidence_state)}">${esc(String(m.evidence_state).replace(/_/g, " "))}</span> ${esc(m.detail)}</li>`).join("")}</ul>` : ""}
      ${(x.rejections || []).length ? `<div class="small"><b>Rejected</b></div><ul class="clean small">${x.rejections.map((r) => `<li><code>${esc(r.device)}</code> ${esc(r.reasons.join("; "))}</li>`).join("")}</ul>` : ""}`}
    ${(x.unverified_assumptions || []).length ? `<div class="small"><b>Unverified assumptions</b></div><ul class="clean small assume">${x.unverified_assumptions.map((a) => `<li>⚠ ${esc(a)}</li>`).join("")}</ul>` : ""}
    <div class="small muted">${esc(x.deployment_readiness || "")}</div></details>`;
}
const pst = (s) => `<span class="pst ${esc(s)}" title="${esc(PST[s] || "")}">${esc(s)}</span>`;
const RES_CLS = { pass: "ok", fail: "fail", unknown: "warn" }, DEC_CLS = { selected: "ok", abstain: "warn", no_eligible_device: "fail", not_placed: "skipped" };
const advVal = (v) => v === null || v === undefined ? '<span class="muted">—</span>' : esc(Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : v);
function advChecks(cs) {
  return `<table class="t advchk">${cs.map((c) => `<tr><td>${badge(c.result, RES_CLS[c.result])}</td><td><code>${esc(c.check)}</code></td><td>${pst(c.status)}</td>
    <td class="small">${c.evidence_state && c.evidence_state !== "observed" ? `<span class="evs ${esc(c.evidence_state)}" title="${esc(EVS[c.evidence_state] || "")}">${esc(c.evidence_state.replace(/_/g, " "))}</span> ` : ""}${esc(c.detail)}${(c.warnings || []).length ? ` <span class="muted">· warnings: ${esc(c.warnings.join(", "))}</span>` : ""}</td></tr>`).join("")}</table>`;
}
function advDevice(e, verdict, sid) {
  const extra = verdict === "eligible" && e.rank_key ? `<span class="small muted">rank: ${esc(Object.entries(e.rank_key).filter(([k]) => k !== "device_id").map(([k, v]) => `${k.replace(/_/g, " ")} ${v}`).join(" · "))}</span>`
    : verdict === "rejected" ? `<span class="small">${esc((e.reasons || []).join("; "))}</span>` : "";
  return `<details class="advdev" data-key="advdev-${esc(sid)}-${esc(e.device)}"><summary>${badge(verdict, verdict === "eligible" ? "ok" : verdict === "rejected" ? "fail" : "unverified")} <b>${esc(e.device)}</b> ${extra}</summary>
    ${advChecks(e.checks)}${(e.assumptions || []).map((a) => `<div class="small assume">⚠ ${esc(a)} — <i>not ranked, not used for selection</i></div>`).join("")}</details>`;
}
function advProposal(p) {
  const A = ADV, rec = A.placement.services.find((r) => r.service.id === p.service.id) || {}, map = A.mappings.find((m) => m.service.id === p.service.id), pr = p.proposal;
  const vip = pr && pr.vip;
  return `<div class="card advsvc" data-key="advsvc-${esc(p.service.id)}"><h4>${esc(p.service.name)} <span class="badge">${esc(p.service.kind === "a2a_agent" ? "A2A agent" : "MCP server")}</span>
      ${gchip(p.service.grouping)} ${badge(p.eligibility.replace(/_/g, " "), p.eligibility === "eligible" ? "observed" : "skipped")} ${badge(p.decision.replace(/_/g, " "), DEC_CLS[p.decision])}</h4>
    ${p.reasons.length ? `<div class="small">${p.reasons.map(esc).join("<br>")}</div>` : ""}${p.uncertainty.map((u) => `<div class="small assume">uncertainty: ${esc(u)}</div>`).join("")}
    ${advExplain(rec.selected ? rec.selected.explanation : rec.explanation, !!rec.selected, p.service.id)}
    <div class="grid2"><div><h3>Identity → endpoints → proposed BIG-IP service</h3>
      ${map.instances.map((i) => `<div class="inst"><div class="small">instance <b>${esc(i.label)}</b> ${gchip(i.status)}</div>${i.endpoints.map((e) => `<div class="small">↳ ${esc(e.address)} · ${esc(e.role)} ${e.proposed_member ? '<span class="badge b-proposed">proposed pool member</span>' : ""}</div>`).join("")}</div>`).join("")}
      <div class="small advmap">→ ${map.proposed.virtual_server ? `<b>${esc(map.proposed.application)}</b> ${esc(map.proposed.virtual_server)} on <code>${esc(map.proposed.device)}</code> ${badge(map.proposed.status, map.proposed.status === "selected" ? "ok" : "unverified")}` : esc(map.proposed.status.replace(/_/g, " "))}</div>
      <h3>BIG-IP candidates</h3>${(rec.eligible || []).map((e) => advDevice(e, "eligible", p.service.id)).join("")}${(rec.unverified || []).map((e) => advDevice(e, "unverified", p.service.id)).join("")}${(rec.rejected || []).map((e) => advDevice(e, "rejected", p.service.id)).join("") || ""}
      ${!(rec.eligible || []).length && !(rec.unverified || []).length && !(rec.rejected || []).length ? '<p class="small muted">not evaluated (not placeable)</p>' : ""}</div>
    <div>${pr ? `<h3>Proposed VIP</h3><div class="advvip">${vip.address ? `<b>${esc(vip.address)}:${esc(vip.port)}</b>` : "<b>none</b>"} <span class="badge b-unverified">${esc(vip.reservation)}</span> <span class="badge b-${vip.verification === "ipam-confirmed-available" ? "ok" : "unverified"}">${esc(vip.verification)}</span>
        <div class="small">${esc(vip.label)} · ${esc(vip.source || vip.reason || "")}</div>${vip.checks ? advChecks(vip.checks) : ""}
        ${vip.skipped.length ? `<div class="small muted">skipped: ${vip.skipped.map((s) => `${esc(s.address)} (${esc(s.reasons.join("; "))})`).join(" · ")}</div>` : ""}
        <div class="small muted">not checked: ${esc(vip.not_checked.join("; "))}</div></div>
      <div class="small advdeploy">${pr.deployment_engine.supported ? '<span class="badge b-ok">deployment engine: supported target</span>' : '<span class="badge b-skipped">deployment engine: not supported — advisory only</span>'} <span class="muted">${esc(pr.deployment_engine.detail)}</span></div>
      <h3>Provenance ${pr.status === "selected" ? "" : '<span class="badge b-unverified">provisional — target unverified</span>'}</h3>
      <table class="t advprov">${pr.provenance.map((x) => `<tr><td><code>${esc(x.object)}</code></td><td>${advVal(x.value)}</td><td>${pst(x.status)}</td><td class="small">${esc(x.source)}${x.rule ? `<div class="muted">${esc(x.rule)}</div>` : ""}</td></tr>`).join("")}</table>
      ${p.alternatives.length ? `<div class="small muted">${p.alternatives.length} other unverified candidate device(s) — see the full advisory JSON</div>` : ""}`
      : p.coverage.length ? `<h3>Existing coverage (observed)</h3><ul class="clean small">${p.coverage.map((c) => `<li>${esc(c.virtual)} ${esc(c.destination)} on <code>${esc(c.device)}</code>: ${esc(c.members.join(", "))}</li>`).join("")}</ul>` : '<p class="small muted">No proposal.</p>'}</div></div></div>`;
}
function renderAdvisory(full) {
  const el = $("#r-advisory"); if (!el) return;
  if (full || (!ADV && !ADV_BUSY)) loadAdvisory();
  if (!ADV) return patch(el, `<div class="card"><p class="muted"><span class="spin"></span>evaluating BIG-IP placement from stored evidence…</p></div>`);
  if (ADV.error) return patch(el, `<div class="card"><h3>Placement advisory</h3><p class="small">${esc(ADV.error)}</p></div>`);
  const A = ADV, sm = A.summary, C = A.comparison;
  patch(el, `<div class="card note advhead" data-key="adv-head"><h3 style="margin-top:0">Placement advisory <span class="badge b-unverified">read-only · not a package · never deployed</span> ${badge(A.status.replace(/_/g, " "), A.status === "decided" ? "ok" : A.status === "abstained" ? "warn" : "proposed")}
      <button id="adv-reload" title="Re-reads stored evidence; no network access">↻ Re-evaluate</button></h3>
    <div class="small">${sm.eligible} eligible · ${sm.selected} placed · ${sm.abstained} abstained · ${sm.no_eligible_device} without an eligible device · ${sm.already_covered} already covered · ${sm.ineligible} ineligible · ${sm.out_of_scope} out of scope · ${sm.devices} BIG-IP device(s)</div>
    <div class="small">Health policy <code>${esc(A.health_policy.version)}</code> <span class="muted">${esc(A.health_policy.status)}</span> · IPAM: ${A.ipam.authoritative ? esc(A.ipam.provider) : `<b>none</b> — ${esc(A.ipam.statement)}`}</div>
    <ul class="clean small muted">${A.notices.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>
    <div class="small"><b>${esc(A.deployment_readiness)}</b></div>
    <div class="small">Status legend: ${Object.keys(PST).map(pst).join(" ")} · evidence: ${Object.keys(EVS).map((k) => `<span class="evs ${k}" title="${esc(EVS[k])}">${k.replace(/_/g, " ")}</span>`).join(" ")}</div></div>
    <div class="card advdevs" data-key="adv-devs"><h3 style="margin-top:0">BIG-IP evidence used</h3>${A.placement.devices.length ? `<table class="t"><tr><th>Device</th><th>Origin</th><th>Collected</th><th>Subnets</th><th>Routes</th><th>HA</th><th>Health</th><th>Deployment engine</th></tr>
      ${A.placement.devices.map((d) => { const sub = d.self_ips.every((x) => x.network.status === "observed") && d.self_ips.length ? "observed" : "unknown";
        const cell = (f) => f.status === "observed" ? '<span class="evs observed">observed</span>' : `<span class="evs ${esc(f.evidence_state || "missing")}">${esc(String(f.evidence_state || "missing").replace(/_/g, " "))}</span>`;
        const hc = (d.checks.find((c) => c.check === "health") || {});
        return `<tr><td><code>${esc(d.id)}</code><div class="small muted">${esc(d.hostname.value || "")} · mgmt ${pst(d.mgmt.status)}</div></td><td class="small">${esc(d.origin)}</td>
          <td class="small">${esc(ago(d.collected_at))}</td><td><span class="evs ${sub}">${sub}</span></td><td>${cell(d.routes)}</td><td>${cell(d.ha)}</td>
          <td>${hc.evidence_state === "stale" ? '<span class="evs stale">stale</span>' : cell(d.health)}</td>
          <td>${(A.deployment_engine.devices[d.id] || {}).supported ? '<span class="badge b-ok" title="still requires approval, preview, diff and on-device preflight">supported target</span>' : '<span class="badge b-skipped">not supported — advisory only</span>'}</td></tr>`; }).join("")}</table>
      <div class="small"><b>${esc(A.deployment_engine.statement)}</b> Deployment engine target(s): ${A.deployment_engine.targets.map((x) => `<code>${esc(x)}</code>`).join(", ") || "none"}.</div>`
      : '<p class="small muted">No BIG-IP Observe evidence in this assessment.</p>'}
      <div class="small muted">Health freshness limit: ${A.health_policy.max_sample_age_s ? `${Math.round(A.health_policy.max_sample_age_s / 60)} min` : "none"} (${esc(A.health_policy.version)}).</div></div>
    ${A.proposals.map(advProposal).join("") || '<div class="card"><p class="muted">No A2A agents or MCP servers in this assessment.</p></div>'}
    <div class="card advcmp" data-key="adv-cmp"><h3 style="margin-top:0">Advisory vs configured packages <span class="small muted">${C.agreements} matching value(s) · ${C.disagreements.length} disagreement(s) · ${esc(C.note)}</span></h3>
      ${C.disagreements.length ? `<table class="t"><tr><th>Package</th><th>Application</th><th>Service</th><th>Field</th><th>Package</th><th>Advisory</th><th>Kind</th></tr>${C.disagreements.map((d) => `<tr><td>${esc(d.package)}</td><td>${esc(d.application || "—")}</td><td>${esc(d.service || "—")}</td><td><code>${esc(d.field)}</code></td>
        <td class="small">${advVal(d.package_value)}</td><td class="small">${advVal(d.advisory_value)}</td><td>${badge(d.kind.replace(/_/g, " "), d.kind === "difference" || d.kind === "missing_from_package" ? "warn" : d.kind === "naming" ? "skipped" : "unverified")}<div class="small muted">${esc(d.explanation)}</div></td></tr>`).join("")}</table>`
        : `<p class="small">${C.packages_compared.length ? "No disagreements." : "No configured package in this assessment yet."}</p>`}</div>
    <details data-key="adv-raw"><summary>Advanced: full placement advisory (JSON)</summary>${jv(A, { id: "adv:raw", title: "Placement advisory (read-only)", filename: `placement-advisory-${A.digest.slice(0, 12)}.json`, height: 440 })}</details>`);
}
document.addEventListener("click", (e) => { if (e.target.closest("#adv-reload")) loadAdvisory(); });
document.addEventListener("click", async (e) => {
  if (!e.target.closest("#d-obs-snap")) return;
  try { const r = await post("/api/discover/observe/snapshots", {}); toast(`Observe from snapshots: ${r.devices.map((d) => esc(d.device)).join(", ")}`); ADV = null; refresh(true); }
  catch (err) { toast(`Observe from snapshots: ${esc(err.message)}`, "bad"); }
});

// ------------------------------------------------------------------ APPROVE
/** Placement advisory context for the approver: selected device, VIP status, health warnings, open assumptions and the
 *  package/advisory disagreements. Read-only; the advisory never authorises anything. */
function approveAdvisory(p) {
  if (!ADV && !ADV_BUSY) loadAdvisory();
  if (!ADV || ADV.error) return `<div class="card note small apadv" data-key="apadv-${esc(p.id)}">${ADV && ADV.error ? `Placement advisory unavailable: ${esc(ADV.error)}` : '<span class="spin"></span>loading placement advisory…'}</div>`;
  const apps = new Set((p.body.architecture || []).map((a) => a.application));
  const props = ADV.proposals.filter((x) => x.proposal && apps.has(x.proposal.application));
  const dis = ADV.comparison.disagreements.filter((d) => d.package === p.kind || d.package === "all");
  const warn = [...new Set(ADV.placement.services.flatMap((s) => s.selected ? s.selected.explanation.unverified_assumptions.filter((a) => /warning/i.test(a)) : []))];
  return `<div class="card note apadv" data-key="apadv-${esc(p.id)}"><h3 style="margin-top:0">Placement advisory for this package <span class="badge b-unverified">advisory — not an authorisation</span> ${badge(ADV.status.replace(/_/g, " "), ADV.status === "decided" ? "ok" : "warn")}</h3>
    ${props.length ? `<table class="t small"><tr><th>Application</th><th>Advised BIG-IP</th><th>VIP (status)</th><th>Pool members</th><th>Deployment engine</th></tr>${props.map((x) => { const pr = x.proposal;
      return `<tr><td><code>${esc(pr.application)}</code></td><td>${esc(pr.device)} ${badge(pr.status, pr.status === "selected" ? "ok" : "unverified")}</td><td>${esc(pr.virtual_server || "—")} <span class="muted">${esc(pr.vip.reservation)}, ${esc(pr.vip.verification)}</span></td>
        <td>${esc(pr.pool_members.filter(Boolean).join(", "))}</td><td>${pr.deployment_engine.supported ? badge("supported target", "ok") : badge("not supported", "skipped")}</td></tr>`; }).join("")}</table>`
      : '<p class="small muted">No advisory proposal maps to this package (see Recommend → Placement advisory).</p>'}
    ${warn.length ? `<div class="small assume">${warn.map((w) => `⚠ ${esc(w)}`).join("<br>")}</div>` : ""}
    <div class="small">${dis.length ? `<b>${dis.length} difference(s)</b> between this package and the advisory: ${dis.slice(0, 6).map((d) => `${esc(d.application || d.service || "")} ${esc(d.field)} (${esc(d.kind.replace(/_/g, " "))})`).join("; ")}` : "The advisory agrees with this package on target, VIPs, members, monitors, persistence and TLS."}</div>
    <div class="small muted">${esc(ADV.deployment_readiness)}</div></div>`;
}
function renderApprove() {
  patch($("#ap-list"), PKGS.length ? PKGS.map((p) => { const lc = p.lifecycle, rv = lc.review, x = p.body.explanation || {};
    return `<div class="card" data-key="apk-${esc(p.id)}"><h4><span class="tag-dom ${p.kind === "security" ? "security" : "delivery"}">AI ${p.kind === "security" ? "Security" : "Delivery"}</span> ${esc(p.title)} ${badge(lc.state)}</h4><p class="small">${esc(lc.next_step || "")}</p>
      <div class="kv"><div>package hash</div><div><code>${esc(p.hash)}</code></div>
        <div>preflight</div><div>${rv ? `${rv.ok ? badge("passed", "ok") : badge("failed", "fail")} ${rv.fresh ? "" : badge("stale — re-run", "warn")} by ${esc(rv.reviewer)} at ${ts(rv.created)}
          ${rv.failed_checks.length ? `· failing: ${esc(rv.failed_checks.join(", "))}` : ""}` : badge("not run", "warn")}</div>
        <div>active approval</div><div>${lc.active_approval ? `${esc(lc.active_approval.approver)} at ${ts(lc.active_approval.created)} · expires ${ts(lc.active_approval.expires)} · bound to device <code>${esc(lc.active_approval.device_fingerprint.slice(0, 12))}…</code>` : "none"}</div>
        <div>findings addressed</div><div>${esc((x.findings_addressed || []).map((f) => f.rule).join(", "))}</div></div>
      ${x.targets ? `<div class="grid2"><div><h3>Exact targets</h3><div class="kv small"><div>device</div><div>${esc(x.targets.device)}</div><div>tenant</div><div>${esc(x.targets.tenant)}</div>
        <div>hosts</div><div>${x.targets.hosts.map((h) => `${esc(h.host)}: <code>${esc(h.command)}</code>`).join("<br>")}</div><div>never touched</div><div>${esc(x.targets.not_touched)}</div></div></div>
        <div><h3>External changes this requires</h3><table class="t">${(x.external_changes.dns || []).map((d) => `<tr><td>DNS</td><td><code>${esc(d.name)}</code></td><td>${esc(d.from)} → <b>${esc(d.to)}</b></td></tr>`).join("")}
        ${(x.external_changes.agent_configuration || []).map((d) => `<tr><td>agent</td><td>${esc(d.service)} <code>${esc(d.setting)}</code></td><td class="small">${esc(d.from)} → <b>${esc(d.to)}</b></td></tr>`).join("")}
        ${(x.external_changes.firewall || []).map((f) => `<tr><td>firewall</td><td colspan="2" class="small">${esc(f)}</td></tr>`).join("")}</table></div></div>
        <details class="tech-only"><summary>BIG-IP objects to be created (${x.targets.objects.length})</summary><div class="small">${x.targets.objects.map((o) => `<code>${esc(o)}</code>`).join(" ")}</div></details>` : ""}
      ${approveAdvisory(p)}
      <h3>Change summary (what the approver is authorising)</h3>${changeTable(x.change_summary || [])}
      <p style="margin-top:10px">${actBtn(p, "review", "▶ Preview, Diff &amp; Preflight", "hero", `review('${p.id}')`)}
        ${actBtn(p, "approve", "Approve", "go", `decide('${p.id}','approved')`)} ${actBtn(p, "reject", "Request changes", "", `decide('${p.id}','changes_requested')`)}
        ${actBtn(p, "reject", "Reject", "danger", `decide('${p.id}','rejected')`)} ${lc.active_approval ? actBtn(p, "revoke", "Revoke approval", "danger", `revokeA('${lc.active_approval.id}')`) : ""}</p>
      <div id="rv-${p.id}">${REVIEWS[p.id] ? reviewHTML(REVIEWS[p.id]) : ""}</div>
      <details data-key="hist-${esc(p.id)}"><summary>Decision history (${p.approvals.length})</summary><table class="t">${p.approvals.map((a) => `<tr><td>${ts(a.created)}</td><td>${badge(a.decision)}</td><td>${esc(a.approver)}</td>
        <td class="small">${esc(a.comment)}</td><td class="small">${a.consumed_by ? "used by " + esc(a.consumed_by) : ""}</td></tr>`).join("")}</table></details></div>`; }).join("")
    : `<p class="muted">Nothing to approve yet — generate recommendations first.</p>`);
}
window.decide = async (id, d) => {
  const verb = { approved: "Approve", rejected: "Reject", changes_requested: "Request changes" }[d];
  const c = await ask(`${verb} package`, `Your decision is recorded with your identity, the package hash and the device fingerprint${d === "approved" ? "; it is valid for 2 hours and can be used for exactly one deployment" : ""}.`,
    { placeholder: "comment (recorded in the audit log)", confirm: verb, cls: d === "approved" ? "go" : d === "rejected" ? "danger" : "primary" });
  if (c === null) return;
  try { await post(`/api/packages/${id}/decision`, { decision: d, comment: c }); toast(`${verb}: recorded`, "ok"); } catch (e) { toast(esc(e.message), "bad"); }
  refresh(true);
};
window.revokeA = async (aid) => { const r = await ask("Revoke approval", "The approval can no longer be used. History is preserved.", { placeholder: "reason", confirm: "Revoke", cls: "danger" });
  if (r === null) return; try { await post(`/api/approvals/${aid}/revoke`, { reason: r }); toast("Approval revoked", "ok"); } catch (e) { toast(esc(e.message), "bad"); } refresh(true); };

// ------------------------------------------------------------------ DEPLOY
function journal(d) {
  const dg = d.diagnosis;
  return `<div class="card ${d.status === "succeeded" ? "" : d.status === "running" ? "note" : "alert"}" data-key="dep-${esc(d.id)}"><h4>${badge(d.status)} deployment <code>${esc(d.id)}</code></h4>
    <div class="small muted">${esc(d.mode)} · by ${esc(d.requested_by)} · ${ts(d.started)}${d.finished ? ` · ${dur(d.finished - d.started)}` : ""} · approved hash <code>${esc(d.package_hash.slice(0, 12))}…</code></div>
    ${dg ? `<div class="card" style="margin-top:8px;background:#1b1116"><b>What happened:</b> ${esc(dg.explanation)}<br><b>Rollback:</b> ${esc(dg.rollback)}
      <br><b>Next actions:</b><ol class="small">${dg.next_actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ol></div>` : ""}
    <ol class="small">${d.steps.map((s) => `<li>${s.status === "running" ? '<span class="spin"></span>' : badge(s.status)} ${esc(s.step)} <span class="muted">${s.finished ? dur(s.finished - s.started) : ""}</span>
      ${stepDetail(s)}</li>`).join("")}</ol>
    ${d.status === "succeeded" ? `<button class="danger" ${can("approver") ? "" : "disabled"} onclick="rollback('${d.id}')">Roll back</button>` : ""}</div>`;
}
function stepDetail(s) {
  const rep = s.report || (s.detail && s.detail.checks ? s.detail : null);
  if (rep && rep.checks) return `<details><summary>convergence: ${Object.values(rep.checks).filter((c) => c.ok).length}/${Object.keys(rep.checks).length} checks · ${rep.elapsed_s} s</summary>
    <table class="t">${Object.entries(rep.checks).map(([k, c]) => `<tr><td>${badge(c.ok ? "ok" : "fail")}</td><td>${esc(k)}</td><td class="small">${esc(typeof c.observed === "string" ? c.observed : JSON.stringify(c.observed))}</td>
    <td class="small muted">${c.converged_after_s != null ? `after ${c.converged_after_s} s` : ""}</td></tr>`).join("")}</table></details>`;
  const res = (s.report && s.report.results) || (s.detail && s.detail.results);
  if (res) return `<details data-key="gate-${esc(s.step)}-${s.started}"><summary>validation: ${res.filter((r) => r.result === "pass").length}/${res.length} pass</summary>${testsTable(res, "gate" + s.started)}</details>`;
  if (s.status === "failed") return typeof s.detail === "string" ? `<div class="small">${esc(s.detail)}</div>` : jv(s.detail, { id: `step:${s.step}:${s.started}`, title: `Failed step — ${s.step}`, filename: "step-detail.json", height: 240 });
  if (s.detail && typeof s.detail === "object" && Object.keys(s.detail).length) return `<details data-key="sd-${esc(s.step)}-${s.started}"><summary class="small muted">step evidence</summary>${jv(s.detail, { id: `step:${s.step}:${s.started}`, title: `Step evidence — ${s.step}`, filename: "step-detail.json", height: 260 })}</details>`;
  return "";
}
async function renderDeploy() {
  const w = (WIN && WIN.window) || {};
  const live = w.phase === "live";
  patch($("#dp-env"), `<h4>Live deployment window ${badge(w.phase || "unknown", w.phase === "live" ? "ok" : "warn")}</h4>
    <div class="small">${live ? `Open until <b>${utc(w.not_after)}</b> (${Math.round(w.remaining_s / 60)} min left), cleanup grace until ${utc(w.cleanup_until)}. Opened by ${esc(w.authorized_by)}.`
      : w.phase === "cleanup" ? `Expired at ${utc(w.not_after)} — until ${utc(w.cleanup_until)} only rollback to a verified state and Reset Demo are possible.`
      : `Locked: ${esc(w.reason || "no live window authorised")}. Approvals can be recorded; execution is refused by the deployment service. The lab owner opens a supervised window.`}</div>
    <p style="margin-top:10px"><button class="danger" id="dp-reset" ${ME && ME.role === "approver" && (live || w.phase === "cleanup") ? "" : "disabled"} title="${ME && ME.role === "owner" ? "Reset is performed by an approver account (the owner opens the live window)" : ""}">Reset Demo Environment</button>
    <span class="why">${!can("approver") ? "approver role required" : !(live || w.phase === "cleanup") ? "requires the live window or its cleanup grace" : "restores the deliberately unprotected baseline (tenant AP_AI + three project hosts only)"}</span></p>`);
  $("#dp-reset").onclick = async () => { const c = await ask("Reset Demo Environment", "Deletes AS3 tenant <b>AP_AI</b> on BIG-IP_C, sets the three project hosts to their <b>baseline</b> profile, waits for convergence and verifies the 'before' profile. History is kept. Type RESET DEMO ENVIRONMENT to confirm.", { must: "RESET DEMO ENVIRONMENT", confirm: "Reset demo", cls: "danger" });
    if (c !== null) startOp("/api/ops/reset-demo", { confirmation: c }); };
  patch($("#dp-list"), PKGS.length ? PKGS.map((p) => { const lc = p.lifecycle, a = lc.actions.deploy;
    const allowed = a.allowed && live, why = !a.allowed ? a.reason : !live ? "live deployment window is not open" : "";
    return `<div class="card" data-key="dpk-${esc(p.id)}"><h4>${esc(p.title)} ${badge(lc.state)}</h4><p class="small">${esc(lc.next_step || "")}</p>
      <p><button class="go" ${allowed ? "" : "disabled"} title="${esc(why)}" onclick="deployP('${p.id}')">Deploy approved package</button>${allowed ? "" : `<span class="why">${esc(why)}</span>`}</p>
      ${p.deployments.map(journal).join("")}</div>`; }).join("") : `<p class="muted">No packages.</p>`);
}
window.deployP = async (id) => { const p = PKGS.find((x) => x.id === id);
  const c = await ask("Deploy approved package", `Executes <b>${esc(p.title)}</b> on BIG-IP_C and the project hosts: preflight → AS3 dry-run → AS3 deploy → host steps → convergence → validation gate. Any failure rolls back automatically. Type DEPLOY to continue.`, { must: "DEPLOY", confirm: "Deploy", cls: "go" });
  if (c !== null) startOp(`/api/ops/deploy/${id}`, {}); };
window.rollback = async (id) => { const c = await ask("Roll back deployment", "Restores the state captured before this deployment and waits for convergence. Type ROLLBACK to continue.", { must: "ROLLBACK", confirm: "Roll back", cls: "danger" });
  if (c !== null) startOp(`/api/ops/rollback/${id}`, {}); };

// ------------------------------------------------------------------ VALIDATE
function testsTable(res, key = "t") {
  return `<table class="t"><tr><th>test</th><th>result</th><th>expected</th><th>observed</th></tr>${res.map((x) => { const o = JSON.stringify(x.observed) || "";
    return `<tr><td>${esc(x.test)}</td><td>${effResult(x) === "not_run" ? badge("not run — live window required", "skipped") : badge(x.result)}</td><td class="small">${esc(x.expected)}</td><td class="small">${o.length <= 140 ? `<code>${esc(o)}</code>`
      : `<details data-key="obs-${esc(key)}-${esc(x.test)}"><summary><code>${esc(o.slice(0, 120))}…</code></summary>${jv(x.observed, { id: `obs:${key}:${x.test}`, title: `Observed — ${x.test}`, filename: `observed-${x.test}.json`, height: 260 })}</details>`}</td></tr>`; }).join("")}</table>`;
}
let VERIF = null;
const VR_CLS = { passed: "ok", failed: "fail", not_run: "skipped", inconclusive: "warn" };
function renderVerification() {
  const el = $("#v-levels"); if (!el) return;
  api("/api/verification").then((v) => { VERIF = v; paint(); }).catch((e) => { VERIF = VERIF && !VERIF.error ? VERIF : { error: e.message || "request failed" }; paint(); });
  function paint() {
    if (!VERIF) return patch(el, `<div class="card"><p class="muted"><span class="spin"></span>loading verification levels…</p></div>`);
    if (VERIF.error) return patch(el, `<div class="card"><h3 style="margin-top:0">Verification levels</h3><p class="small">unavailable: ${esc(VERIF.error)} — retried on the next refresh</p></div>`);
    const cs = VERIF.current_state || {}, id8 = (x) => esc((x || "").slice(0, 8));
    const now = { none: "no deployment has changed the infrastructure yet",
      active: `deployment ${id8(cs.active_deployment)} is in place`,
      baseline: `no deployed configuration is in place — the last change (deployment ${id8(cs.last_change)}) was ${cs.reset_at ? "reset by Reset Demo" : "rolled back"}`,
      restored: `a rollback restored the configuration of deployment ${id8(cs.restored_to)}; it has not been re-verified since`,
      unverified: `the infrastructure state after deployment ${id8(cs.last_change)} is not verified` }[cs.kind];
    const pr = VERIF.protection, prot = pr ? (pr.security ? "AI Delivery + AI Security" : pr.delivery ? "AI Delivery only — no AI Security controls" : "none")
      + (pr.state === "restored" ? " (restored by rollback, not re-verified)" : "") : "";
    const expo = (x) => x && x.length ? `<div class="muted">${badge("exposure — not protection", "warn")} ${x.map((e) => `${esc(e.check)}: ${esc(e.result)}`).join(" · ")}</div>` : "";
    const hist = (h) => h ? `<div class="muted">${badge("historical — not current", "unverified")} deployment ${id8(h.deployment)} (${esc(h.status)}): ${esc(h.result)}${h.at ? ` at ${ts(h.at)}` : ""}${h.checks.length ? " — " + h.checks.map((c) => `${esc(c.check)}: ${esc(c.result)}`).join(" · ") : ""}</div>` : "";
    patch(el, `<div class="card" data-key="vlv"><h3 style="margin-top:0">Verification levels</h3>${now ? `<div class="small" id="v-current"><b>Current state:</b> ${now}</div>` : ""}${prot ? `<div class="small" id="v-protection"><b>Protection in place:</b> ${esc(prot)}</div>` : ""}<div class="small muted">${esc(VERIF.statement)}</div>
      <table class="t">${VERIF.levels.map((l) => `<tr data-key="vl-${l.level}"><td><b>${l.level}</b></td><td><b>${esc(l.title)}</b><div class="small muted">${esc(l.meaning)}</div></td>
        <td>${badge(l.result.replace("_", " "), VR_CLS[l.result])}</td><td class="small">${esc(l.detail)}${l.checks.length ? `<div class="muted">${l.checks.map((c) => `${esc(c.check)}: ${esc(c.result)}`).join(" · ")}</div>` : ""}${hist(l.history)}${expo(l.exposure)}</td></tr>`).join("")}</table></div>`);
  }
  paint();
}
function renderValidate() {
  renderVerification();
  const sec = PKGS.find((p) => p.kind === "security"), del = PKGS.find((p) => p.kind === "delivery");
  const rec = sec && sec.lifecycle.state === "deployed" ? "after-security" : del && del.lifecycle.state === "deployed" ? "after-delivery" : "before";
  if (!$("#v-profile").dataset.touched) $("#v-profile").value = rec;
  $("#v-hint").textContent = `Recommended for the current deployment state: ${rec}.`;
  patch($("#v-list"), VALS.map((r, i) => { const p = r.results.filter((x) => x.result === "pass").length, f = r.results.filter((x) => effResult(x) === "fail"),
    nr = r.results.filter((x) => effResult(x) === "not_run"), newer = VALS.slice(0, i).find((x) => x.label === r.label),
    bad = r.results.some((x) => (JSON.stringify(x.observed || {}) || "").includes(CLIENT_DEFECT));
    return `<div class="card ${f.length && !newer ? "alert" : ""}" data-key="val-${esc(r.id)}"><h4>${esc(r.label)} · ${utcFull(r.started)} · ${p}/${r.results.length - nr.length} pass ${f.length ? badge(`${f.length} failed`, "fail") : badge("all passed", "ok")}
      ${nr.length ? badge(`${nr.length} not run — live window required`, "skipped") : ""} ${newer ? badge(`superseded by ${utcFull(newer.started)}`, "skipped") : badge("current", "ok")}</h4>
      ${bad ? `<p class="small">Invalid run — the validator could not present its mTLS client certificate (web validator defect fixed by release 75d1739f70e6); not evidence about the deployment.</p>` : ""}
      ${f.length ? `<p class="small">Failing: ${esc(f.map((x) => x.test).join(", "))}</p>` : ""}<details data-key="vald-${esc(r.id)}" ${f.length ? "open" : ""}><summary>all tests</summary>${testsTable(r.results, r.id)}</details></div>`; }).join("")
    || `<p class="muted">No validation runs in this assessment yet.</p>`);
}
$("#v-profile").onchange = (e) => (e.target.dataset.touched = "1");
$("#v-run").onclick = () => startOp("/api/ops/validate", { profile: $("#v-profile").value });

// ------------------------------------------------------------------ OBSERVE
let ASSESS = [], SUGG = [];
const aLabel = (a) => `${a.name} · ${new Date(a.created * 1000).toLocaleString()} · discovery ${a.discovery} · ${a.infra_state} · ${a.counts.findings} findings${a.current ? " · current" : ""}`;
function fillAssessmentSelects() {
  const q = ($("#o-q").value || "").toLowerCase(), only = $("#o-complete").checked;
  const from = $("#o-from") && $("#o-from").value ? new Date($("#o-from").value + "T00:00:00").getTime() / 1000 : null;
  const to = $("#o-to") && $("#o-to").value ? new Date($("#o-to").value + "T23:59:59").getTime() / 1000 : null;
  const list = ASSESS.filter((a) => (!q || aLabel(a).toLowerCase().includes(q) || a.id.includes(q)) && (!only || a.discovery === "complete")
    && (from === null || a.created >= from) && (to === null || a.created <= to));
  for (const sel of ["#o-before", "#o-after"]) {
    const el = $(sel), cur = el.value;
    patch(el, list.map((a) => `<option value="${a.id}" data-key="${a.id}">${esc(aLabel(a))}</option>`).join("") || `<option value="">no assessment matches</option>`);
    if (list.some((a) => a.id === cur)) el.value = cur;
  }
}
async function renderObserve() {
  renderOverview("observe");
  [ASSESS, SUGG] = await Promise.all([api("/api/assessments"), api("/api/assessments/suggestions").then((r) => r.pairs).catch(() => [])]);
  const firstTime = !$("#o-before").options.length;
  fillAssessmentSelects();
  if (firstTime) {                                  // default: the best suggestion, else current vs the previous complete one
    const s = SUGG[0], full = ASSESS.filter((a) => a.discovery === "complete");
    $("#o-before").value = s ? s.before : (full[1] || ASSESS[1] || ASSESS[0] || {}).id || "";
    $("#o-after").value = s ? s.after : (full[0] || ASSESS[0] || {}).id || "";
  }
  renderObserveExtra();                             // report links need the selected assessments
  patch($("#o-sugg"), SUGG.length ? `<span class="small muted">Suggested comparisons:</span> ${SUGG.map((s) => {
    const b = ASSESS.find((a) => a.id === s.before), a = ASSESS.find((x) => x.id === s.after);
    return `<button class="small" data-pair="${s.before}|${s.after}" title="${esc(s.label)}">${esc(b ? b.name : s.before)} → ${esc(a ? a.name : s.after)} ${badge(s.status, s.status === "verified" ? "ok" : "warn")}</button>`; }).join(" ")}`
    : `<span class="small muted">No meaningful pair yet: a verified before/after needs two complete discoveries with a successful, linked F5 deployment between them.</span>`);
  const an = await api("/api/analytics");
  patch($("#o-paths"), an.paths.length ? `<table class="t"><tr><th>from</th><th>to</th><th>protocol</th><th>path</th><th>calls</th><th>errors</th><th>latency (server/client span)</th><th>tools</th><th>replicas</th></tr>${an.paths.map((p) =>
    `<tr><td>${esc(p.from)}</td><td>${esc(p.to)}</td><td>${esc(p.protocol)}</td><td>${badge(p.path || "unknown", p.path === "via_bigip" ? "ok" : "warn")}</td><td>${p.calls ?? ""}</td><td>${p.errors ?? ""}</td>
     <td class="small">${latTxt(p.latency_ms)}${p.mixed_operations ? '<br><span class="muted">mixes operation types (e.g. card fetch + task) — open the edge in Discover for per-operation latency</span>' : ""}</td>
     <td class="small">${esc(Object.entries(p.tools || {}).map(([k, v]) => `${k}×${v}`).join(", "))}</td><td class="small">${esc((p.replicas || []).join(", "))}</td></tr>`).join("")}</table>`
    : `<p class="muted">No telemetry ingested in this assessment.</p>`);
}
document.addEventListener("click", (e) => { const b = e.target.closest("[data-pair]"); if (!b) return; const [x, y] = b.dataset.pair.split("|");
  $("#o-q").value = ""; $("#o-complete").checked = false; $("#o-from").value = ""; $("#o-to").value = ""; fillAssessmentSelects(); $("#o-before").value = x; $("#o-after").value = y; $("#o-cmp").click(); });
$("#o-q").oninput = () => fillAssessmentSelects(); $("#o-complete").onchange = () => fillAssessmentSelects();
$("#o-from").onchange = () => fillAssessmentSelects(); $("#o-to").onchange = () => fillAssessmentSelects();
$("#o-before").onchange = $("#o-after").onchange = () => renderObserveExtra();
$("#o-cmp").onclick = async () => {
  const before = $("#o-before").value, after = $("#o-after").value;
  if (!before || !after) return toast("Select two assessments first.", "bad");
  const c = await api(`/api/compare?before=${before}&after=${after}`);
  const cb = c.coverage.before, ca = c.coverage.after, cp = c.comparability || {}, ok = cp.claims_allowed;
  const B = cp.before || {}, A = cp.after || {};
  patch($("#o-cmpout"), `<div class="cmpbanner ${esc(cp.status)}"><b>${esc(cp.label)}</b><ul class="small">${(cp.reasons || []).map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
      ${ok ? "" : "<b class='small'>No F5 benefit is claimed. Findings that appear only in “after” reflect discovery coverage or new conditions — not security deterioration.</b>"}</div>
    <table class="t"><tr><th></th><th>before — ${esc(B.name || "")}</th><th>after — ${esc(A.name || "")}</th></tr>
      <tr><td>created</td><td>${B.created ? new Date(B.created * 1000).toLocaleString() : ""}</td><td>${A.created ? new Date(A.created * 1000).toLocaleString() : ""}</td></tr>
      <tr><td>discovery coverage</td><td>${esc(B.discovery)} (${esc((B.technical_sources || []).join(", ") || "none")})</td><td>${esc(A.discovery)} (${esc((A.technical_sources || []).join(", ") || "none")})</td></tr>
      <tr><td>BIG-IP state (Observe)</td><td>${esc(B.infra_state)}</td><td>${esc(A.infra_state)}</td></tr>
      <tr><td>assets / evidence</td><td>${c.counts.before.assets} / ${(B.counts || {}).evidence ?? ""}</td><td>${c.counts.after.assets} / ${(A.counts || {}).evidence ?? ""}</td></tr>
      <tr><td>findings observed</td><td>${c.counts.before.findings}</td><td>${c.counts.after.findings}${c.new_in_after.length ? ` <span class="small muted">(${c.new_in_after.length} newly observed)</span>` : ""}</td></tr></table>
    <div class="tiles">${ok ? `<div class="tile"><b>${c.summary.resolved}</b><span>resolved (validated)</span></div>
      <div class="tile"><b>${c.summary.awaiting_rediscovery}</b><span>enforcement validated — awaiting rediscovery</span></div>
      <div class="tile"><b>${c.summary.remaining}</b><span>remaining (${c.summary.not_addressed} not addressed by any package)</span></div>
      <div class="tile" title="${esc(c.coverage.definitions.endpoints)}"><b>${ca.ai_endpoints_behind_bigip}/${ca.ai_endpoints}</b><span>A2A/MCP endpoints fronted by BIG-IP (${cb.percent}% → ${ca.percent}%)</span></div>
      <div class="tile" title="${esc(c.coverage.definitions.services)}"><b>${ca.services.fronted}/${ca.services.total}</b><span>AI services fronted (Overview)</span></div>`
      : `<div class="tile"><b>${c.summary.remaining}</b><span>findings present in both</span></div><div class="tile"><b>${c.summary.unverified}</b><span>not raised again — not claimed as fixed</span></div>
         <div class="tile"><b>${c.new_in_after.length}</b><span>newly observed (coverage)</span></div><div class="tile"><b>${cb.virtual_servers} → ${ca.virtual_servers}</b><span>virtual servers (Observe)</span></div>`}</div>
    <p class="small muted">Counts are findings (one rule on one affected service); baseline: ${c.summary.findings_before} findings across ${c.summary.risk_types_before} risk types.
      ${esc(c.coverage.definitions.scope)} Unfronted endpoints after: ${esc(ca.endpoints.filter((x) => !x.fronted).map((x) => x.address).join(", ") || "none")}.</p>
    <div class="card"><h4>Linked deployments</h4>${c.deployments.length ? `<table class="t">${c.deployments.map((d) => `<tr><td><code>${esc(d.id)}</code></td><td>${esc(d.title || "")}</td><td>${badge(d.status)} ${badge(d.now || "", d.in_place ? "ok" : "skipped")}</td>
      <td class="small">${esc(d.requested_by)} · ${utcFull(d.started)}</td><td class="small">gate: ${esc((d.gate || {}).status || "—")}</td></tr>`).join("")}</table>` : "<p class='small muted'>None — no remediation is claimed.</p>"}</div>
    <div class="card"><h4>Findings before → after</h4><table class="t">${c.findings.map((f) => `<tr><td>${esc(f.rule_id)}</td><td>${esc(f.title)}</td><td>${badge(f.class_label || "", f.class)}</td>
      <td>${badge(f.outcome, f.outcome.startsWith("resolved") ? "ok" : f.outcome.startsWith("remaining") ? "fail" : "warn")}</td><td class="small muted">${esc(((f.evidence || {}).tests || []).map((t) => `${t.test} ${t.result}${t.at ? " " + utcFull(t.at) : ""}`).join("; ") || (f.proven_by || []).join(", "))}</td></tr>`).join("") || "<tr><td class='muted'>no findings in “before”</td></tr>"}</table>
      ${c.new_in_after.length ? `<details data-key="cmp-new"><summary>${c.new_in_after.length} finding(s) only in “after” — newly observed, not deterioration</summary><ul class="small">${c.new_in_after.map((f) => `<li>${esc(f.rule_id)} ${esc(f.title)}</li>`).join("")}</ul></details>` : ""}</div>
    <div class="card"><h4>Topology changes</h4><table class="t"><tr><th>from</th><th>to</th><th>protocol</th><th>before</th><th>after</th></tr>${c.topology.map((t) => `<tr><td>${esc(t.from)}</td><td>${esc(t.to)}</td><td>${esc(t.protocol)}</td>
      <td>${esc(t.before || "—")} <span class="muted small">${esc(t.before_target || "")}</span></td><td>${esc(t.after || "—")} <span class="muted small">${esc(t.after_target || "")}</span></td></tr>`).join("")}</table></div>
    ${c.performance.length ? `<div class="card"><h4>Latency (OpenTelemetry span durations, ms)</h4>${ok ? "" : "<p class='small muted'>Exploratory: differences are not attributable to F5.</p>"}
      <p class="small muted">Trace windows: ${Object.entries(c.ingest_windows || {}).map(([k, w]) => `${k} ${w ? `${utcFull(w.start)} → ${utcFull(w.end)}${w.note ? " — " + esc(w.note) : ""}` : "none"}`).join("; ")}</p><table class="t"><tr><th>path</th><th>p50</th><th>p95</th></tr>${c.performance.map((p) => `<tr><td>${esc(p.from)} → ${esc(p.to)} (${esc(p.protocol)})</td>
      <td>${p.p50_before ?? "—"} → ${p.p50_after ?? "—"}</td><td>${p.p95_before ?? "—"} → ${p.p95_after ?? "—"}</td></tr>`).join("")}</table></div>` : ""}
    <div class="card" data-key="cmp-vperf"><h4>Equivalent validator workload (this comparison)</h4><table class="t"><tr><th>state</th><th>measured</th><th>MCP p50</th><th>MCP p95</th><th>A2A task</th></tr>
      ${c.validation_performance.rows.map((p) => `<tr><td>${esc(p.profile)}</td><td class="small">${p.measured_at ? utcFull(p.measured_at) : "no run"}</td><td>${p.mcp_p50_ms ?? "not measured"}</td><td>${p.mcp_p95_ms ?? "not measured"}</td><td>${p.a2a_task_s ?? "not measured"}</td></tr>`).join("")}</table>
      <p class="small muted">${esc(c.validation_performance.statement)}</p></div>
    <div class="card" data-key="cmp-fraud"><h4>Fraud application runs since ${esc(c.fraud_runs.since_utc || "—")}</h4>${c.fraud_runs.runs.length ? `<table class="t"><tr><th>time</th><th>scenario</th><th>infrastructure</th><th>decision</th><th>s</th></tr>
      ${c.fraud_runs.runs.slice(0, 12).map((r) => `<tr><td class="small">${esc(r.created_utc)}</td><td>${esc(r.scenario)}</td><td>${badge(r.infra_state, r.infra_state === "baseline" ? "warn" : "ok")}</td><td>${esc(r.decision || r.state)}</td><td>${r.seconds ?? ""}</td></tr>`).join("")}</table>` : "<p class='small muted'>No fraud scenario ran in this comparison window.</p>"}
      ${c.fraud_runs.note ? `<p class="small">${esc(c.fraud_runs.note)}</p>` : ""}</div>`);
  renderObserveExtra();
};
$("#o-rep").onclick = () => window.open(`/api/report/${$("#o-after").value}?before=${$("#o-before").value}`, "_blank");
window.viewEvidenceBundle = async () => {
  const a = $("#o-after").value, b = $("#o-before").value;
  modal(`<h2>Technical evidence bundle</h2><p class="small"><span class="spin"></span>building…</p>`);
  const data = await api(`/api/report/${a}/evidence?before=${b}`).catch((e) => ({ error: e.message }));
  modal(`<h2>Technical evidence bundle</h2><p class="small muted">Same content as the downloadable JSON: evidence digests, approvals, preflight reviews, deployment journals, validation runs, fraud runs and window events.</p>
    ${jv(data, { id: `bundle:${a}:${b}`, title: "Technical evidence", filename: `autopilot-technical-evidence-${a}.json`, height: 560 })}`);
};
async function renderObserveExtra() {
  const [pf, fc] = await Promise.all([api("/api/perf").catch(() => ({ validation: [] })), api("/api/fraud/compare").catch(() => ({ comparisons: [] }))]);
  const el = document.getElementById("o-extra") || (() => { const d = document.createElement("div"); d.id = "o-extra"; $("#o-cmpout").after(d); return d; })();
  const a = $("#o-after").value, b = $("#o-before").value, q = b ? `before=${encodeURIComponent(b)}` : "";
  patch(el, `<div class="card"><h4>Reports for customers</h4><p>
      <button class="primary" onclick="window.open('/api/report/'+$('#o-after').value+'/executive?before='+$('#o-before').value,'_blank')">Executive summary (open)</button>
      ${a ? dlLink(`/api/report/${a}/executive?download=1&${q}`, `autopilot-executive-summary-${a}.html`, "Download executive summary", "btnlike") : ""}
      <button onclick="viewEvidenceBundle()">View technical evidence</button>
      ${a ? dlLink(`/api/report/${a}/evidence?${q}`, `autopilot-technical-evidence-${a}.json`, "Download technical evidence (JSON)", "btnlike") : ""}</p>
      <p class="small muted">Select the assessments above first. Reports carry the same comparability verdict as this page. If a browser extension blocks a download,
      open the report and use Print / Save as — the inline report is complete.</p></div>
    <div class="grid2"><div class="card"><h4>Performance — equivalent validation workload</h4>${pf.validation.length ? `<table class="t"><tr><th>state</th><th>MCP tool p50</th><th>MCP tool p95</th><th>A2A investigation (task)</th><th>tests</th></tr>${pf.validation.map((p) =>
      `<tr><td>${esc(p.profile)} <span class="small muted">${utcFull(p.measured_at)}</span></td><td>${p.mcp_p50_ms != null ? p.mcp_p50_ms + " ms" : "not measured"}</td><td>${p.mcp_p95_ms != null ? p.mcp_p95_ms + " ms" : "not measured"}</td><td>${p.a2a_task_s != null ? p.a2a_task_s + " s" : "not measured"}</td><td>${p.passed}/${p.total}</td></tr>`).join("")}</table>
      <p class="small muted">MCP latency: 10 sequential tools/call round trips measured by the validator (n=10, nearest-rank percentiles). A2A: one complete investigation task, LLM-bound.</p>` : "<p class='small muted'>Run Validate in each state (before, after Delivery, after Security) to compare.</p>"}</div>
    <div class="card"><h4>Fraud application — same scenario before vs after</h4>${fc.comparisons.length ? fc.comparisons.map((c) => `<p><b>${esc(c.scenario_id)}</b> ${esc(c.title)}</p><table class="t">${Object.entries(c.states).map(([st, x]) =>
      `<tr><td>${badge(st, st === "baseline" ? "warn" : "ok")}</td><td class="small">${utcFull(x.created)}</td><td>${esc(x.decision || "")}</td><td>${x.seconds} s</td><td class="small">${esc(JSON.stringify(x.paths || {}))}</td></tr>`).join("")}</table>`).join("")
      : "<p class='small muted'>Investigate the same scenario before and after F5 in the Fraud application to compare.</p>"}<p class="small muted">${esc(fc.note || "")}</p></div></div>`);
}

// ------------------------------------------------------------------ AUDIT
async function renderAudit() {
  const q = new URLSearchParams({ category: $("#au-cat").value, actor: $("#au-actor").value, q: $("#au-q").value, limit: 500 });
  const a = await api(`/api/audit?${q}`);
  if ($("#au-cat").options.length === 1) $("#au-cat").innerHTML += a.categories.map((c) => `<option>${esc(c)}</option>`).join("");
  if ($("#au-actor").options.length === 1) $("#au-actor").innerHTML += a.actors.map((c) => `<option>${esc(c)}</option>`).join("");
  patch($("#au-list"), `<table class="t"><tr><th>#</th><th>time</th><th>category</th><th>actor</th><th>action</th><th>detail</th></tr>${a.rows.map((x) =>
    `<tr><td>${x.seq}</td><td>${new Date(x.ts * 1000).toLocaleString()}</td><td>${badge(x.category, "low")}</td><td>${esc(x.actor)}</td><td>${esc(x.action)}</td><td class="small"><code>${esc(x.detail).slice(0, 300)}</code></td></tr>`).join("")}</table>`);
}
$("#au-go").onclick = renderAudit;

// ------------------------------------------------------------------ DEMO GUIDE (Phase 2)
let DEMO = null;
async function renderDemo() {
  if (!DEMO) DEMO = await api("/api/demo/content").catch(() => ({ hero: { exec: "", tech: "" }, experiences: [], value: { exec: [], tech: [] } }));
  const EXPS = DEMO.experiences;
  $("#demo-lead").textContent = DEMO.hero[VIEW];
  const runs = await api("/api/fraud/runs?limit=5").catch(() => []);
  const del = PKGS.find((p) => p.kind === "delivery"), sec = PKGS.find((p) => p.kind === "security"), w = (WIN && WIN.window) || {};
  const lastV = VALS[0], fs = STATE ? STATE.findings_grouped : [];
  const status = {
    1: runs[0] ? `last run: ${runs[0].scenario_id} → ${runs[0].decision || runs[0].state} (${runs[0].infra_state}, ${runs[0].seconds} s)` : "not run yet",
    2: STATE && STATE.counters.evidence ? `${STATE.counters.assets} assets · ${STATE.findings.length} findings · ${fs.filter((g) => g.class === "contradicted_claim").length} contradicted claims` : "not discovered yet",
    3: del ? `AI Delivery: ${del.lifecycle.state.replace(/_/g, " ")}` : "no recommendation yet",
    4: sec ? `AI Security: ${sec.lifecycle.state.replace(/_/g, " ")}${sec.lifecycle.blocked ? " (waits for Delivery)" : ""}` : "no recommendation yet",
    5: lastV ? `last validation: ${lastV.label} ${lastV.results.filter((r) => r.result === "pass").length}/${lastV.results.length}` : "not validated yet",
    6: "compare assessments and download reports",
  };
  patch($("#demo-exp"), EXPS.map((x) => `<div class="exp"><div><span class="num">${x.n}</span></div><h4>${esc(x.title)}</h4>
    <div class="small">${esc(VIEW === "exec" ? x.exec : x.tech)}</div><div class="spacer"></div><div class="status">${esc(status[x.n])}</div>
    <div><button class="${x.n === 1 ? "primary" : ""}" data-go="${x.page}">Open experience ${x.n} →</button></div></div>`).join(""));
  patch($("#demo-state"), `<b>Current state</b><div class="kv" style="margin-top:6px"><div>signed in</div><div>${esc(ME ? `${ME.username} (${ME.role})` : "—")}</div>
    <div>assessment</div><div>${esc(STATE ? STATE.assessment.name : "—")}</div><div>live window</div><div>${badge(w.phase || "unknown", w.phase === "live" ? "ok" : "warn")}</div>
    <div>BIG-IP state</div><div>${esc(runs[0] ? runs[0].infra_state : (del && del.lifecycle.state === "deployed" ? "delivery" : "baseline (unprotected)"))}</div></div>
    <p class="small muted">Normal operation needs no terminal: the lab owner opens the live window in the Control center.</p>`);
  patch($("#demo-value"), DEMO.value[VIEW].map((t) => `<li>${esc(t)}</li>`).join(""));
}
$("#demo-new").onclick = async () => { const n = await ask("Start a new demo assessment", "Creates an empty assessment for a fresh walkthrough. Infrastructure is not touched; earlier assessments stay available for comparison.", { placeholder: "Customer AI environment — demo", confirm: "Create" });
  if (n === null) return; await post("/api/assessment/new", { name: n || "Demo" }); gsig = ""; ANALYSIS = null; refresh(true); toast("New assessment created", "ok"); };

// ------------------------------------------------------------------ FRAUD APPLICATION (Phase 1)
const FR = { data: null, sel: null, run: null, health: null, customTitle: "Custom test transaction", custom: [{ amount: 9400, mcc: "4829", country: "NG", channel: "wire", timestamp: "2026-10-01T12:00:00Z", direction: "outbound", merchant_id: "CUSTOM-MERCHANT-01", merchant_name: "Synthetic custom merchant 1", beneficiary_id: "CUSTOM-BENEFICIARY-01", device_id: "CUSTOM-DEVICE-01" }] };
const CAT = { a2a: "A2A (agent-to-agent, application level)", mcp: "MCP tool execution", llm: "LLM inference", vector_db: "Vector DB (network/API)",
  s3: "Object storage S3 (network/API)", http: "Other HTTP (network/API)", agent: "Agent internal work" };
const money = (v) => "$" + Number(v).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
async function renderFraud(full) {
  if (full || !FR.data) FR.data = await api("/api/fraud/scenarios").catch((e) => ({ error: e.message }));
  if (FR.data.error) { patch($("#fr-scen"), `<p class="small">${esc(FR.data.error)}</p>`); return; }
  const ag = FR.data.agent, caps = ag.capabilities || [];
  const group = (k, t) => `<h3>${t}</h3>` + FR.data.scenarios.filter((s) => s.kind === k).map((s) => { const ok = caps.includes(s.requires);
    return `<div class="scn ${FR.sel && FR.sel.id === s.id ? "sel" : ""} ${ok ? "" : "dis"}" data-scn="${s.id}" title="${ok ? "" : esc(ag.note || "not supported by the running agents")}">
      <b>${esc(s.id)}</b> ${esc(s.title)}<br><span class="small muted">${esc(s.account.holder)} · ${s.transactions.length} txn · ${money(s.transactions.reduce((a, t) => a + t.amount, 0))}</span></div>`; }).join("");
  patch($("#fr-scen"), `<div class="small">${ag.reachable ? `${badge("Agent A reachable", "ok")} <span class="muted">Agent B URL: <code>${esc(ag.agent_b_url)}</code></span>` : badge("Agent A unreachable", "fail") + " " + esc(ag.error || "")}</div>
    ${ag.note ? `<p class="small muted">${esc(ag.note)}</p>` : ""}${group("suspicious", "Suspicious — rules-engine alerts")}${group("normal", "Normal activity")}
    <h3>Compose a test transaction</h3><div class="scn ${FR.sel && FR.sel.kind === "custom" ? "sel" : ""} ${caps.includes("scenarios") ? "" : "dis"}" data-scn="CUSTOM">Custom scenario builder</div>
    <p class="small muted">${esc(FR.data.dataset.note)} Seed ${FR.data.dataset.seed}.</p>`);
  renderFraudDetail();
  if (full || !FR.health) fraudHealth();
  renderFraudRuns();
  if (FR.run) renderRun(); else { patch($("#fr-result"), `<p class="muted small">No investigation selected. Results appear here as <span class="chip c-live">live measured</span> data.</p>`);
    patch($("#fr-timeline"), ""); patch($("#fr-story"), ""); }
}
function renderFraudDetail() {
  const s = FR.sel, d = FR.data;
  if (!s) { patch($("#fr-detail"), `<p class="muted">Select a scenario on the left. Suspicious alerts come from the bank's rules engine; normal activity and custom
    transactions let you check that the agents do not over-react.</p>`); return; }
  const runBtn = `<button class="go" data-need="operator" id="fr-go" ${can("operator") ? "" : "disabled"}>▶ Investigate with the AI agents (live)</button>
    ${can("operator") ? "" : '<span class="why">operator role required</span>'}`;
  if (s.kind === "custom") {
    const opt = (o, v) => Object.entries(o).map(([k, t]) => `<option value="${esc(k)}" ${k === v ? "selected" : ""}>${esc(t)}</option>`).join("");
    patch($("#fr-detail"), `<h4>Custom test transaction <span class="chip c-input">scenario input</span></h4>
      <p class="small">Account <select id="fc-acct">${d.accounts.map((a) => `<option value="${a.account_id}">${esc(a.account_id)} — ${esc(a.holder)} (${esc(a.home_country)}, KYC ${esc(a.kyc_risk)})</option>`).join("")}</select>
      Title <input id="fc-title" style="width:240px;display:inline-block" value="${esc(FR.customTitle)}"></p>
      <p class="small muted">Each row preserves timestamp, direction, merchant identity, geography, beneficiary/sender, device, and temporal relationship through Agent A → A2A → Agent B → MCP.</p>
      <table class="t"><tr><th>timestamp</th><th>amount (USD)</th><th>merchant</th><th>category</th><th>country</th><th>direction</th><th>channel</th><th></th></tr>${FR.custom.map((t, i) => `<tr>
        <td><input data-i="${i}" data-f="timestamp" type="datetime-local" value="${String(t.timestamp || "").replace("Z", "").slice(0, 16)}" style="width:175px"></td>
        <td><input data-i="${i}" data-f="amount" type="number" min="0.01" max="50000" step="0.01" value="${t.amount}" style="width:120px"></td>
        <td><input data-i="${i}" data-f="merchant_name" value="${esc(t.merchant_name || "Synthetic merchant")}" style="width:150px"><input data-i="${i}" data-f="merchant_id" value="${esc(t.merchant_id || "CUSTOM-MERCHANT-01")}" style="width:130px"></td>
        <td><select data-i="${i}" data-f="mcc">${opt(d.mcc, t.mcc)}</select></td>
        <td><select data-i="${i}" data-f="country">${opt(Object.fromEntries(d.countries.map((c) => [c, c])), t.country)}</select></td>
        <td><select data-i="${i}" data-f="direction">${opt({ outbound: "outbound", inbound: "inbound", debit: "debit", credit: "credit" }, t.direction || "outbound")}</select></td>
        <td><select data-i="${i}" data-f="channel">${opt(Object.fromEntries(d.channels.map((c) => [c, c])), t.channel)}</select></td>
        <td><button data-del="${i}">✕</button></td></tr>`).join("")}</table>
      <p><button id="fc-add" ${FR.custom.length >= 6 ? "disabled" : ""}>+ transaction</button> ${runBtn}</p>`);
    $$("#fr-detail [data-f]").forEach((el) => (el.onchange = () => { FR.custom[+el.dataset.i][el.dataset.f] = el.dataset.f === "amount" ? +el.value : el.value; }));
    $("#fc-title").onchange = () => { FR.customTitle = $("#fc-title").value; };
    $$("#fr-detail [data-del]").forEach((el) => (el.onclick = () => { FR.custom.splice(+el.dataset.del, 1); if (!FR.custom.length) FR.custom.push({ amount: 50, mcc: "5411", country: "US", channel: "card_present" }); renderFraudDetail(); }));
    $("#fc-add").onclick = () => { const i = FR.custom.length; FR.custom.push({ amount: 120, mcc: "5812", country: "US", channel: "card_present", timestamp: `2026-10-01T12:${String(i * 5).padStart(2, "0")}:00Z`, direction: "outbound", merchant_id: `CUSTOM-MERCHANT-${String(i + 1).padStart(2, "0")}`, merchant_name: `Synthetic custom merchant ${i + 1}`, beneficiary_id: `CUSTOM-BENEFICIARY-${String(i + 1).padStart(2, "0")}`, device_id: "CUSTOM-DEVICE-01" }); renderFraudDetail(); };
  } else {
    const a = s.account;
    patch($("#fr-detail"), `<h4>${esc(s.id)} · ${esc(s.title)} ${badge(s.kind, s.kind === "suspicious" ? "fail" : "ok")} <span class="chip c-input">scenario input</span></h4>
      <div class="kv small"><div>customer</div><div>${esc(a.holder)} · <code>${esc(a.account_id)}</code></div><div>profile</div><div>${esc(a.segment)} · home ${esc(a.home_country)} · KYC ${esc(a.kyc_risk)} · avg monthly spend ${money(a.avg_monthly_spend)}</div>
        <div>trigger</div><div>${esc(s.trigger)}</div><div class="tech-only">scenario label</div><div class="tech-only">${esc(s.scenario_label)}</div></div>
      <table class="t" style="margin-top:8px"><tr><th>transaction</th><th>amount</th><th>category</th><th>country</th><th>channel</th><th class="tech-only">time</th></tr>${s.transactions.map((t) =>
        `<tr><td><code>${esc(t.transaction_id)}</code></td><td>${money(t.amount)}</td><td>${esc(t.category || d.mcc[t.mcc] || t.mcc)}</td><td>${esc(t.country)}</td><td>${esc(t.channel)}</td><td class="tech-only small">${esc((t.timestamp || "").slice(0, 16))}</td></tr>`).join("")}</table>
      <p style="margin-top:10px">${runBtn}</p>`);
  }
  const go_ = $("#fr-go"); if (go_) go_.onclick = async () => {
    const body = s.kind === "custom" ? { custom: { account_id: $("#fc-acct").value, title: $("#fc-title").value, transactions: FR.custom } } : { scenario_id: s.id };
    const o = await startOp("/api/ops/investigate", body, `Investigation ${s.id}`);
    if (o) patch($("#fr-result"), `<p><span class="spin"></span>Agent A is delegating to Agent B over A2A; Agent B is calling MCP tools and the LLM… (typically 20–120 s, LLM-bound)</p>`); };
}
async function fraudHealth() {
  patch($("#fr-topo"), `<p class="small"><span class="spin"></span>checking reachability…</p>`);
  [FR.health, FR.protection] = await Promise.all([api("/api/fraud/health").catch((e) => ({ checks: [], error: e.message })),
    api("/api/verification").then((v) => v.protection || null).catch(() => null)]);
  renderTopo();
}
$("#fr-health").onclick = () => fraudHealth();
function renderTopo() {
  const H = FR.health || { checks: [] }, edges = FR.run && FR.run.summary ? FR.run.summary.edges || [] : [];
  const cols = { agent: 0, mcp: 1, model: 2, data: 2, observability: 2 }, rows = {}, pos = {};
  H.checks.forEach((c) => { const col = cols[c.role] ?? 2; rows[col] = (rows[col] || 0) + 1; pos[c.id] = { x: 4 + col * 120, y: 10 + (rows[col] - 1) * 60, c }; });
  const svcMap = Object.fromEntries(H.checks.filter((c) => c.otel).map((c) => [c.otel, c.id]));
  const hostMap = Object.fromEntries(H.checks.map((c) => { try { return [new URL(c.url).host, c.id]; } catch (e) { return ["", c.id]; } }));
  const tgt = (t) => svcMap[t] || hostMap[t] || null;
  const color = { a2a: "#8957e5", mcp: "#1f6feb", llm: "#d4761c", vector_db: "#8b949e", s3: "#8b949e", http: "#8b949e" };
  const lines = edges.map((e) => { const a = pos[tgt(e.from)], b = pos[tgt(e.to)]; if (!a || !b) return "";
    const via = (e.paths || []).includes("via_bigip");
    return `<line x1="${a.x + 56}" y1="${a.y + 23}" x2="${b.x + 56}" y2="${b.y + 23}" stroke="${color[e.category] || "#8b949e"}" stroke-width="${via ? 3 : 2}" ${via ? "" : 'stroke-dasharray="5 3"'}><title>${esc(e.category)} ×${e.count} ${esc((e.paths || []).join(","))}</title></line>`; }).join("");
  // AI Security lockdown drops direct connections to the MCP backends (only BIG-IP may connect): with Security verified in place,
  // a connection-level failure of a direct MCP probe is the expected protection, not an outage. HTTP errors stay red.
  const pr = FR.protection, protectedBlocked = (c) => c.role === "mcp" && !c.reachable && c.status == null && /^Connect(Timeout|Error)$/.test(c.error || "")
    && !!(pr && pr.security && pr.verified);
  const nodes = Object.entries(pos).map(([id, p]) => { const c = p.c, ok = c.reachable, pb = protectedBlocked(c), col = ok ? "#2ea043" : pb ? "#d29922" : "#f85149";
    return `<g data-key="topo-${esc(c.id)}" data-state="${ok ? "up" : pb ? "protected" : "down"}"><rect x="${p.x}" y="${p.y}" width="112" height="46" rx="8" fill="#18202b" stroke="${col}" stroke-width="2"/>
      <text x="${p.x + 56}" y="${p.y + 19}" fill="#e8eef5" font-size="12" font-weight="600" text-anchor="middle">${esc(c.id)}</text>
      <text x="${p.x + 56}" y="${p.y + 36}" fill="${ok ? "#3fb950" : pb ? "#d29922" : "#f85149"}" font-size="10" text-anchor="middle">${ok ? `up · ${c.ms} ms` : pb ? "protected · direct blocked" : `unreachable${c.error ? " · " + esc(c.error) : ""}`}</text>
      <title>${esc(c.name)} — ${esc(c.url)}${pb ? " — Protected — direct access blocked (expected): AI Security lockdown accepts only BIG-IP; traffic uses the BIG-IP front door" : ""}</title></g>`; }).join("");
  const anyProtected = H.checks.some(protectedBlocked);
  const h = 14 + Math.max(...Object.values(rows), 1) * 60;
  patch($("#fr-topo"), `<div class="topo"><svg viewBox="0 0 360 ${h}" role="img" aria-label="application topology">${lines}${nodes}</svg></div>
    <div class="small muted">Boxes: live reachability from AP-AUTOPILOT-01 (${H.checked_at ? ts(H.checked_at) : "—"}). Lines: calls seen in the selected run's trace —
    solid = through BIG-IP, dashed = direct. ${edges.length ? "" : "No run selected: no observed calls shown."}</div>
    ${anyProtected ? `<div class="small" id="fr-protected">${badge("Protected — direct access blocked (expected)", "warn")} MCP backends accept connections only from BIG-IP (AI Security lockdown); verify the service path with Validate or a fraud run.</div>` : ""}`);
}
async function renderFraudRuns() {
  const [runs, cmp] = await Promise.all([api("/api/fraud/runs?limit=12").catch(() => []), api("/api/fraud/compare").catch(() => ({ comparisons: [] }))]);
  patch($("#fr-runs"), runs.length ? `<table class="t">${runs.map((r) => `<tr data-run="${r.id}" style="cursor:pointer"><td>${esc(r.scenario_id)}</td>
    <td>${r.decision ? `<span class="decision d-${esc(r.decision)}" style="font-size:10px;padding:1px 6px">${esc(r.decision)}</span>` : badge(r.state || "?", "warn")}</td>
    <td>${badge(r.infra_state, r.infra_state === "baseline" ? "warn" : "ok")}</td><td>${r.seconds}s</td></tr>`).join("")}</table>` : `<p class="muted">none yet</p>`);
  patch($("#fr-cmp"), cmp.comparisons.length ? cmp.comparisons.map((c) => `<b>${esc(c.scenario_id)}</b><table class="t">${Object.entries(c.states).map(([st, x]) =>
    `<tr><td>${esc(st)}</td><td>${esc(x.decision || "")}</td><td>${x.seconds}s</td><td>${esc(Object.values(x.paths || {}).flat().join("/"))}</td></tr>`).join("")}</table>`).join("")
    : `<p class="muted">Run the same scenario before and after F5 to compare.</p>`);
}
function bindFraudInteractions() {
  $("#fr-scen").addEventListener("click", (e) => {
    const el = e.target.closest("[data-scn]");
    if (!el || !$("#fr-scen").contains(el)) return;
    if (el.classList.contains("dis")) return toast(esc(el.title || "not supported by the running agents"), "bad");
    const id = el.dataset.scn;
    FR.sel = id === "CUSTOM" ? { id: "CUSTOM", kind: "custom", title: "Custom test transaction" } : FR.data.scenarios.find((s) => s.id === id);
    renderFraud(false);
  });
  $("#fr-runs").addEventListener("click", (e) => {
    const row = e.target.closest("[data-run]");
    if (row && $("#fr-runs").contains(row)) loadRun(row.dataset.run);
  });
}
async function loadRun(id) { FR.run = await api(`/api/fraud/runs/${id}`).catch(() => null); if (PAGE === "fraud") { renderRun(); renderTopo(); } }
function renderRun() {
  const r = FR.run, resp = r.response || {}, res = resp.result || {}, a = res.assessment || {}, s = r.summary || {};
  const viaBig = Object.values(s.paths || {}).flat().includes("via_bigip");
  const coh = res.classification_coherence;
  const hy = res.classification;
  const classificationLabel = a.classification_status === "classified" ? "Suspicious pattern identified" : (res.classification && res.classification.normality_score >= .72) ? "No suspicious pattern identified" : "Insufficient evidence — abstention";
  const operationalLabel = a.decision === "close" ? "Operational decision: close / no immediate action" : a.decision === "monitor" ? "Operational decision: monitor for additional activity" : a.decision === "escalate" ? "Operational decision: escalate for investigation" : "Operational decision: unavailable";
  patch($("#fr-result"), `<h4>Investigation result <span class="chip c-live">live measured</span> <span class="small muted">${esc(r.scenario_id)} · ${ts(r.created)} · by ${esc(r.actor)}</span></h4>
    <div class="small muted fr-provenance">Data provenance: transactions are <b>synthetic</b> (seeded generator; the agents are not told the injected pattern). Timings and agent/tool calls are <b>measured</b> from this run's traces. Risk scores come from the lab's MCP scoring tool — a <b>transparent logistic model</b> for demonstration, <b>not a validated fraud model</b>.</div>
    ${r.state !== "completed" ? `<div class="card alert"><b>Investigation ${esc(r.state || "failed")}</b><br><span class="small">${esc(r.error || resp.error || "no result returned")}</span></div>` : ""}
    ${a.decision ? `<p><span class="decision d-${esc(a.decision)}">${esc(a.decision)}</span> &nbsp;risk <b>${esc(a.risk_level)}</b> · confidence ${esc(a.confidence)}
      · ${esc(a.generated_by || "")} ${String(a.generated_by || "").startsWith("deterministic") ? badge("fallback — not an LLM", "warn") : ""}</p>
      <p><b>Fraud classification:</b> ${esc(classificationLabel)}<br><b>${esc(operationalLabel)}</b></p><p>${esc(a.rationale || "")}</p>${(a.recommended_actions || []).length ? `<p class="small"><b>Recommended actions:</b> ${esc(a.recommended_actions.join("; "))}</p>` : ""}` : ""}
    ${coh ? `<div class="card ${coh.status === "disagreement" ? "alert" : ""}"><b>Independent classification check:</b> ${badge(coh.status, coh.status === "coherent" ? "ok" : coh.status === "disagreement" ? "fail" : "low")}<br><span class="small">${esc(coh.reason)}${coh.expected_pattern_id ? ` Expected ${esc(coh.expected_pattern_id)}; observed ${(coh.observed_pattern_ids || []).map(esc).join(", ") || "none"}.` : ""}</span></div>` : ""}
    ${hy ? `<div class="card ${hy.status === "abstain" ? "alert" : ""}"><b>Hybrid evidence classifier:</b> ${badge(hy.status, hy.status === "classified" ? "ok" : "warn")}<br>
      <span class="small">${hy.dominant_pattern ? `Dominant pattern <code>${esc(hy.dominant_pattern.pattern_id)}</code> ${esc(hy.dominant_pattern.name)} · classifier confidence ${esc(hy.confidence)} · margin ${esc(hy.margin)}` : "No dominant pattern meets the evidence threshold; analyst review/abstention applies."}<br>
      Normality score ${esc(hy.normality_score)} · data completeness ${esc(hy.data_completeness)} · ${esc(hy.reason || "")}</span>
      ${(hy.candidate_patterns || []).length ? `<details><summary>Candidate evidence</summary><ul>${hy.candidate_patterns.slice(0, 5).map(p => `<li><code>${esc(p.pattern_id)}</code> ${esc(p.name)} (${esc(p.score)}): ${esc((p.evidence || []).join("; "))}</li>`).join("")}</ul></details>` : ""}</div>` : ""}
    <p class="small">${dlLink(`/api/fraud/runs/${encodeURIComponent(r.id)}/executive?download=1`, `fraud-executive-${r.id}.html`, "Download executive report")} ·
      <a href="/api/fraud/runs/${encodeURIComponent(r.id)}/executive" target="_blank" rel="noopener">open inline</a> ·
      ${dlLink(`/api/fraud/runs/${encodeURIComponent(r.id)}/evidence`, `fraud-evidence-${r.id}.json`, "Download technical evidence JSON")}
      <span class="muted">· if a browser extension blocks the download, use “open inline” and Save As</span></p>
    <div class="kv small"><div>end-to-end</div><div>${r.seconds} s measured by Autopilot · trace ${s.duration_ms != null ? s.duration_ms + " ms" : '<span class="chip c-na">unavailable</span>'}</div>
      <div>path</div><div>${viaBig ? badge("through BIG-IP", "ok") : badge("direct — no ADC in the path", "warn")} <code>${esc(r.agent_b_url || "")}</code></div>
      <div>correlation</div><div>trace <code>${esc(r.trace_id || "—")}</code>${(s.a2a_tasks || []).length ? ` · A2A task <code>${esc(s.a2a_tasks.join(", "))}</code>` : ""}</div>
      <div>errors</div><div>${s.errors != null ? (s.errors ? badge(`${s.errors} error span(s)`, "fail") : badge("none", "ok")) : '<span class="chip c-na">unavailable</span>'}</div>
      <div>MCP tools</div><div>${Object.entries(s.mcp_tools || {}).map(([k, v]) => `<code>${esc(k)}</code>×${v}`).join(" ") || '<span class="chip c-na">not in trace</span>'}</div>
      <div>risk replicas</div><div>${esc((res.replicas_used || s.risk_replicas || []).join(", ") || "—")}</div></div>
    ${(res.model_scores || []).length ? `<h3>Model scores (MCP scoring tool — transparent logistic model over synthetic data; illustrative)</h3><table class="t">${res.model_scores.map((m) => `<tr><td><code>${esc(m.transaction_id)}</code></td>
      <td style="width:40%"><div class="scorebar"><i style="width:${Math.round(m.score * 100)}%;background:${m.score >= 0.7 ? "#f85149" : m.score >= 0.4 ? "#d29922" : "#3fb950"}"></i></div></td>
      <td>${esc(m.score)} ${esc(m.band || "")}</td><td class="small muted">${esc(m.replica || "")}</td></tr>`).join("")}</table>` : ""}
    ${(s.error_spans || []).length ? `<h3>Trace errors</h3><table class="t">${s.error_spans.map((e) => `<tr><td><code>${esc(e.service || "?")}</code></td><td>${esc(e.name || "?")}</td><td>${e.http_status || "—"}</td><td>${esc(e.error_detail || "unspecified error")}</td></tr>`).join("")}</table>` : ""}
    ${(s.recoverable_spans || []).length ? `<p class="small"><b>Recoverable trace conditions:</b> ${s.recoverable_spans.map((e) => `${esc(e.service || "?")} / ${esc(e.name || "?")}`).join("; ")} — recorded separately from genuine failures.</p>` : ""}
    ${(res.rag_patterns || []).length ? `<p class="small"><b>Similar fraud patterns (RAG):</b> ${res.rag_patterns.map((p) => `${esc(p.pattern_id)} ${esc(p.name)} (${(+p.score).toFixed(2)})`).join("; ")}
      ${res.case_file ? ` · closest case file (S3): <code>${esc(res.case_file)}</code>` : ""}</p>` : ""}
    <details class="tech-only" data-key="a2a-updates-${esc(r.id)}"><summary>A2A task status updates (${(resp.updates || []).length}, as streamed to Agent A)</summary>${jv(resp.updates || [], { id: `a2a:${r.id}`, title: "A2A status updates", filename: `a2a-updates-${r.id}.json`, height: 300 })}</details>`);
  renderTimeline(); renderStory();
}
function renderTimeline() {
  const ev = FR.run.events || [];
  if (!ev.length) { patch($("#fr-timeline"), `<h4>Interaction timeline</h4><p><span class="chip c-na">unavailable</span> Jaeger returned no spans for trace
    <code>${esc(FR.run.trace_id || "—")}</code> — nothing is drawn rather than guessed.</p>`); return; }
  const total = Math.max(...ev.map((e) => e.start_ms + e.duration_ms), 1), lanes = [];
  ev.forEach((e) => { const k = e.service + (e.instance && e.service.startsWith("mcp-risk") ? ` (${e.instance})` : ""); if (!lanes.includes(k)) lanes.push(k); });
  patch($("#fr-timeline"), `<h4>Interaction timeline <span class="chip c-live">live measured (OpenTelemetry)</span> <span class="small muted">${ev.length} spans · ${Math.round(total)} ms</span></h4>
    <div class="legend2">${Object.entries(CAT).map(([k, t]) => `<span><i class="k-${k}"></i>${esc(t)}</span>`).join("")}</div>
    ${lanes.map((l) => { const items = ev.filter((e) => (e.service + (e.instance && e.service.startsWith("mcp-risk") ? ` (${e.instance})` : "")) === l)
        .sort((x, y) => x.start_ms - y.start_ms), ends = [];
      items.forEach((e) => { let r = ends.findIndex((end) => end <= e.start_ms); if (r < 0) { r = ends.length; ends.push(0); } ends[r] = e.start_ms + e.duration_ms; e._row = r; });
      return `<div class="lane"><div class="lbl" title="${esc(l)}">${esc(l)}</div><div class="track" style="height:${Math.max(1, ends.length) * 19 + 4}px">${items.map((e) =>
      `<div class="bar k-${e.category} ${e.status === "error" ? "err" : ""}" data-ev="${e.id}" style="top:${3 + e._row * 19}px;left:${(100 * e.start_ms / total).toFixed(2)}%;width:${Math.max(0.3, 100 * e.duration_ms / total).toFixed(2)}%"
        title="${esc(e.name)} · ${e.duration_ms} ms"></div>`).join("")}</div></div>`; }).join("")}
    <div id="fr-ev" class="small" style="margin-top:8px"><span class="muted">Click a bar for its details (safe attributes only — no payloads or credentials are recorded).</span></div>`);
  $$("#fr-timeline [data-ev]").forEach((b) => (b.onclick = () => { const e = ev.find((x) => x.id === b.dataset.ev);
    patch($("#fr-ev"), `<b>${esc(e.name)}</b> ${badge(CAT[e.category] || e.category, e.category === "a2a" ? "observed" : "low")} ${badge(e.status, e.status === "ok" ? "ok" : "fail")}
      <div class="kv"><div>service</div><div>${esc(e.service)} ${e.instance ? `(${esc(e.instance)})` : ""} · ${esc(e.kind || "")}</div><div>start / duration</div><div>+${e.start_ms} ms / ${e.duration_ms} ms</div>
      ${e.target ? `<div>target</div><div><code>${esc(e.target)}</code></div>` : ""}${e.peer ? `<div>peer address</div><div><code>${esc(e.peer)}</code> ${e.path ? badge(e.path, e.path === "via_bigip" ? "ok" : "warn") : ""}</div>` : ""}
      <div>span id</div><div><code>${esc(e.id)}</code>${e.parent ? ` ← parent <code>${esc(e.parent)}</code>` : ""}</div></div>
      ${jv(e.attrs || {}, { id: `span:${e.id}`, title: "Span attributes", filename: `span-${e.id}.json`, height: 260 })}`); }));
}
function renderStory() {
  const r = FR.run, s = r.summary || {}, res = (r.response || {}).result || {}, a = res.assessment || {};
  const tools = Object.values(s.mcp_tools || {}).reduce((x, y) => x + y, 0), via = Object.values(s.paths || {}).flat().includes("via_bigip");
  patch($("#fr-story"), `<h4>What just happened</h4><ol class="story">
    <li><b>The fraud agent</b> picked up ${esc(r.scenario.title.toLowerCase())} for ${esc(r.scenario.account.holder)} and asked the <b>risk agent</b> for an assessment over A2A.</li>
    <li>The risk agent used <b>${tools || "several"} AI tool call(s)</b> (MCP) — customer data, fraud knowledge base, case files and the risk model${(res.replicas_used || []).length ? ` (served by ${esc(res.replicas_used.join(", "))})` : ""}.</li>
    <li>A language model weighed the evidence and decided: <b>${esc(a.decision || r.state)}</b>${a.risk_level ? ` (${esc(a.risk_level)} risk)` : ""} in ${r.seconds} s.</li>
    <li>${via ? "Every agent and tool call went <b>through F5 BIG-IP</b> — balanced, health-checked and policy-controlled." :
      "All of this traffic went <b>directly</b> between services: no load balancing, no failover, no identity check and no single point of control — what F5 adds in experiences 3 and 4."}</li></ol>`);
}

// ------------------------------------------------------------------ CONTROL CENTER (Phase 3)
let CC = null;
async function renderControl(full) {
  if (!full && CC) return;
  CC = await api("/api/control/status").catch((e) => ({ error: e.message }));
  if (CC.error) { patch($("#cc-top"), `<div class="card alert">${esc(CC.error)}</div>`); return; }
  const w = CC.window || {}, d = CC.deployer, b = CC.broker;
  patch($("#cc-top"), `<div class="card"><h4>Deployment service ${badge(d.available ? "reachable" : "unavailable", d.available ? "ok" : "fail")}</h4>
      <div class="small">${d.available ? `status ${esc(d.status)} · live=${esc(d.live)}` : esc(d.error || "")}</div></div>
    <div class="card"><h4>Live window ${badge(w.phase || "unknown", w.phase === "live" ? "ok" : w.phase === "cleanup" ? "warn" : "low")}</h4><div class="small">
      ${w.phase === "live" ? `open until <b>${utc(w.not_after)}</b> (${Math.round(w.remaining_s / 60)} min left) · cleanup until ${utc(w.cleanup_until)}<br>authorised by <b>${esc(w.authorized_by)}</b>`
        : w.phase === "cleanup" ? `expired ${utc(w.not_after)} · cleanup grace until ${utc(w.cleanup_until)}` : esc(w.reason || "locked")}</div></div>
    <div class="card"><h4>Window controller ${badge(b.available && b.ok !== false ? "available" : "unavailable", b.available && b.ok !== false ? "ok" : "fail")}</h4>
      <div class="small">${b.available ? `ap-window-broker v${esc(b.version)} (root, Unix socket, HMAC)` : esc(b.error || "")}</div></div>`);
  const canOpen = CC.can_open && w.phase !== "live" && w.phase !== "cleanup" && b.available;
  patch($("#cc-window"), `<h4>Authorise live infrastructure changes</h4><p class="small">${esc(CC.separation)}</p>
    <h3>While the window is ${esc(w.phase || "locked")}, Autopilot may</h3><ul class="clean small">${CC.enables_now.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
    <details class="tech-only"><summary>All phases</summary>${Object.entries(CC.enables).map(([k, v]) => `<p class="small"><b>${esc(k)}</b>: ${esc(v.join(" · "))}</p>`).join("")}</details>
    <h3>Open a supervised window (lab owner)</h3>
    <div class="grid2 small"><label>Duration (minutes, max ${CC.limits.max_minutes})<input id="cw-min" type="number" min="1" max="${CC.limits.max_minutes}" value="120"></label>
      <label>Cleanup grace (minutes, max ${CC.limits.max_grace})<input id="cw-grace" type="number" min="1" max="${CC.limits.max_grace}" value="30"></label></div>
    <label class="small">Reason (recorded in the audit log)<input id="cw-reason" placeholder="e.g. Rehearsal 2 — supervised, demo for PM"></label>
    <label class="small">Re-enter your password<input id="cw-pw" type="password" autocomplete="current-password"></label>
    <label class="small">Type <b>AUTHORIZE LIVE CHANGES</b><input id="cw-phrase"></label>
    <p><button class="go" id="cw-open" ${canOpen ? "" : "disabled"}>Open live window</button> <span class="why">${!CC.can_open ? "lab owner role required" :
      w.phase === "live" || w.phase === "cleanup" ? "a window is already open" : !b.available ? "window controller unavailable" : "expires automatically; cannot be extended"}</span></p>
    <h3>Close the window now</h3><p class="small"><input id="cc-close-reason" placeholder="reason" style="width:60%;display:inline-block">
      <button class="danger" id="cw-close" ${CC.can_close && (w.phase === "live" || w.phase === "cleanup") ? "" : "disabled"}>Close window</button>
      <span class="why">${CC.can_close ? "" : "approver or owner role required"}</span></p>`);
  $("#cw-open").onclick = async () => {
    try { const r = await post("/api/control/window/open", { minutes: +$("#cw-min").value, grace: +$("#cw-grace").value, reason: $("#cw-reason").value,
      password: $("#cw-pw").value, confirmation: $("#cw-phrase").value });
      toast(`Live window opened until ${utc(r.window.not_after)}`, "ok"); } catch (e) { toast(esc(e.message), "bad"); }
    $("#cw-pw").value = ""; refreshWindow(); renderControl(true); };
  $("#cw-close").onclick = async () => { const c = await ask("Close live window", "Ends the window immediately (no cleanup grace). In-flight operations finish. Type CLOSE WINDOW.", { must: "CLOSE WINDOW", confirm: "Close", cls: "danger" });
    if (c === null) return; try { await post("/api/control/window/close", { reason: $("#cc-close-reason").value || "closed from control center", confirmation: c }); toast("Window closed", "ok"); }
    catch (e) { toast(esc(e.message), "bad"); } refreshWindow(); renderControl(true); };
  const sc = CC.scope;
  patch($("#cc-scope"), `<h4>Deployment scope</h4><div class="kv small"><div>device</div><div>${esc(sc.device)}</div><div>tenant</div><div>${esc(sc.tenant)}</div>
    <div>hosts</div><div>${esc(sc.hosts.join(", "))}</div><div>host actions</div><div>${esc(sc.host_actions)}</div><div>never</div><div>${esc(sc.never)}</div></div>
    <h3>Reset Demo Environment</h3><p class="small">Removes tenant ${esc(sc.tenant)} and returns the hosts to the unprotected baseline, then verifies. Needs approver + live window or cleanup grace.</p>
    <p><button class="danger" id="cc-reset" ${ME && ME.role === "approver" && (w.phase === "live" || w.phase === "cleanup") ? "" : "disabled"} title="${ME && ME.role === "owner" ? "Reset is performed by an approver account (the owner opens the live window)" : ""}">Reset Demo Environment</button></p>`);
  $("#cc-reset").onclick = async () => { const c = await ask("Reset Demo Environment", "Deletes tenant AP_AI and sets the three hosts to baseline, then verifies. Type RESET DEMO ENVIRONMENT.", { must: "RESET DEMO ENVIRONMENT", confirm: "Reset", cls: "danger" });
    if (c !== null) startOp("/api/ops/reset-demo", { confirmation: c }); };
  patch($("#cc-diag"), `<h4>Diagnostics (read-only)</h4><p><button id="dg-bigip">BIG-IP health</button></p><div id="dg-out" class="small"></div>`);
  $("#dg-bigip").onclick = async () => { patch($("#dg-out"), '<span class="spin"></span>reading BIG-IP…'); const r = await api("/api/diagnostics/bigip").catch((e) => ({ error: e.message }));
    const m = r.memory || {};
    patch($("#dg-out"), r.reachable ? `<div class="kv"><div>version</div><div>${esc(r.bigip_version)} · AS3 ${esc(r.as3_version)}</div><div>clock skew</div><div>${r.clock_skew_s != null ? (+r.clock_skew_s).toFixed(1) + " s" : "unreadable"}</div>
      <div>REST latency</div><div>${esc(r.rest_latency_s)} s</div><div>control plane</div><div>${esc(m.other_used_pct)}% used · swap ${esc(m.swap_used_pct)}% ${m.swap_used_pct >= 75 ? badge("high", "warn") : ""}</div>
      <div>virtual servers</div><div>${esc(r.virtual_servers)} · tenant AP_AI ${r.tenant_present ? "present" : "absent"}</div></div>` : `<span class="chip c-na">unavailable</span> ${esc(r.error || "")}`); };
  patch($("#cc-history"), `<h4>Window history (audit)</h4><table class="t">${CC.history.map((h) => `<tr><td class="small">${new Date(h.ts * 1000).toLocaleString()}</td><td>${esc(h.actor)}</td>
    <td>${esc(h.action.replace("live_window.", ""))}</td><td class="small tech-only"><code>${esc(h.detail).slice(0, 160)}</code></td></tr>`).join("") || "<tr><td class='muted'>no window events yet</td></tr>"}</table>`);
}

// ------------------------------------------------------------------ boot
function setView(v) { VIEW = v; localStorage.setItem("ap.view", v); document.body.classList.toggle("exec", v === "exec"); document.body.classList.toggle("tech", v === "tech");
  $$(".viewtoggle button").forEach((b) => b.classList.toggle("on", b.dataset.view === v)); renderPage(true); }
$$(".viewtoggle button").forEach((b) => (b.onclick = () => setView(b.dataset.view)));
document.addEventListener("click", (e) => { const a = e.target.closest("[data-go]"); if (a) { e.preventDefault(); go(a.dataset.go); } });
document.body.classList.add(VIEW); $$(".viewtoggle button").forEach((b) => b.classList.toggle("on", b.dataset.view === VIEW));
$$(".toplinks a").forEach((a) => a.classList.toggle("on", a.dataset.go === PAGE));
$$(".page").forEach((p) => p.classList.toggle("active", p.id === `p-${PAGE}`));
bindFraudInteractions();
window.addEventListener("hashchange", () => { const h = location.hash.slice(1); if (PAGES.includes(h) && h !== PAGE) go(h); });
initGraph();
setDView(DVIEW);
$$(".page").forEach((p) => p.classList.toggle("active", p.id === `p-${PAGE}`));
api("/api/me").then((u) => { ME = u; applyRole(); refresh(true); }).catch(() => {});
refreshWindow(); setInterval(refreshWindow, 15000);
poll(); setInterval(() => { if (!document.hidden && !document.body.classList.contains("jv-modal")) inBackground(() => refresh(false)); }, 5000);
$("#refresh-now").onclick = () => refresh(true);
