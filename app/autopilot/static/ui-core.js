// F5 Agentic AI Autopilot — UI core (Wave 1): state-preserving rendering + reusable JSON / diff viewer.
//
// Why: pages were re-rendered with innerHTML on every background poll, which destroyed <details> state, viewer scroll,
// text selection and inline viewers every 1.5–5 s. patch() morphs the existing DOM into the new markup instead:
// unchanged nodes are kept (so open/closed state, scroll and selection survive), and background updates are deferred
// while the user is selecting text or pressing the mouse inside the region being updated.
(() => {
"use strict";

// ------------------------------------------------------------------ morph / patch
const UI = { background: false, deferred: new Map(), pointerDown: false, last: new WeakMap() };
const _keyOf = (n) => (n.nodeType === 1 ? n.getAttribute("data-key") || n.id || null : null);

function _syncAttrs(from, to) {
  for (const { name } of [...from.attributes]) {
    if (to.hasAttribute(name)) continue;
    if (name === "open" && from.nodeName === "DETAILS") continue;          // user-controlled disclosure state
    if (name === "class" && from.hasAttribute("data-ui-classes")) continue;
    from.removeAttribute(name);
  }
  for (const { name, value } of [...to.attributes]) {
    if (name === "open" && from.nodeName === "DETAILS") continue;
    if (from.getAttribute(name) !== value) from.setAttribute(name, value);
  }
}

function _morphNode(from, to) {
  if (from.nodeType !== to.nodeType || from.nodeName !== to.nodeName) { from.replaceWith(to); return; }
  if (from.nodeType === 3 || from.nodeType === 8) { if (from.nodeValue !== to.nodeValue) from.nodeValue = to.nodeValue; return; }
  if (from.nodeType !== 1) return;
  // identical content signature (e.g. a JSON viewer for unchanged data): keep the live subtree untouched
  const sig = to.getAttribute("data-sig");
  if (sig && from.getAttribute("data-sig") === sig) return;
  _syncAttrs(from, to);
  if (from.hasAttribute("data-ui-owned")) return;                           // subtree managed client-side
  const tag = from.nodeName;
  if ((tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") && document.activeElement === from) return;
  if (tag === "TEXTAREA") return;                                           // never clobber typed text
  _morphChildren(from, to);
}

function _morphChildren(fromEl, toEl) {
  const keyed = new Map();
  for (const c of fromEl.childNodes) { const k = _keyOf(c); if (k) keyed.set(k, c); }
  let cur = fromEl.firstChild;
  for (const t of [...toEl.childNodes]) {
    const k = _keyOf(t);
    let match = null;
    if (k && keyed.has(k)) { match = keyed.get(k); keyed.delete(k); }
    else if (!k && cur && !_keyOf(cur) && cur.nodeType === t.nodeType && cur.nodeName === t.nodeName) match = cur;
    if (match) {
      if (match === cur) cur = cur.nextSibling; else fromEl.insertBefore(match, cur);
      _morphNode(match, t);
    } else fromEl.insertBefore(t, cur);
  }
  while (cur) { const n = cur.nextSibling; cur.remove(); cur = n; }
}

function _selectionInside(el) {
  const s = document.getSelection();
  return !!(s && !s.isCollapsed && s.rangeCount && el.contains(s.getRangeAt(0).commonAncestorContainer));
}

/** Render html into el without destroying user state. Background renders are deferred during selection/drag. */
function patch(el, html) {
  if (!el) return false;
  if (UI.background && el.childNodes.length && (_selectionInside(el) || (UI.pointerDown && el.contains(UI.pointerTarget)))) {
    UI.deferred.set(el, html);                                              // applied once the user is done
    return false;
  }
  UI.deferred.delete(el);
  const tpl = document.createElement("template");
  tpl.innerHTML = html;
  if (!el.childNodes.length) { el.replaceChildren(tpl.content); return true; }
  const box = document.createElement(el.nodeName === "TBODY" ? "tbody" : "div");
  box.appendChild(tpl.content);
  _morphChildren(el, box);
  return true;
}
function _flushDeferred() {
  if (UI.pointerDown) return;
  for (const [el, html] of [...UI.deferred]) {
    if (!el.isConnected) { UI.deferred.delete(el); continue; }
    if (_selectionInside(el)) continue;
    UI.deferred.delete(el);
    const bg = UI.background; UI.background = false; patch(el, html); UI.background = bg;
  }
}
document.addEventListener("pointerdown", (e) => { UI.pointerDown = true; UI.pointerTarget = e.target; }, true);
document.addEventListener("pointerup", () => { UI.pointerDown = false; setTimeout(_flushDeferred, 50); }, true);
document.addEventListener("selectionchange", () => { if (UI.deferred.size) setTimeout(_flushDeferred, 300); });
/** Run fn as a background (poll-driven) render: deferrable, never steals focus or selection. */
async function inBackground(fn) { const prev = UI.background; UI.background = true; try { return await fn(); } finally { UI.background = prev; } }

// ------------------------------------------------------------------ clipboard / files
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch (e) {                                                               // non-secure context / permission: legacy path
    const ta = document.createElement("textarea"); ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.left = "-9999px";
    document.body.appendChild(ta); ta.select(); let ok = false; try { ok = document.execCommand("copy"); } catch (e2) { ok = false; } ta.remove(); return ok;
  }
}
function saveText(text, filename, type = "application/json") {
  // client-side data the page already holds (viewer content); server reports use plain links instead (see app.js)
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a"); a.href = url; a.download = filename; a.rel = "noopener"; a.style.display = "none";
  document.body.appendChild(a); a.click(); setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 60000);
}
const _hash = (s) => { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0; return (h >>> 0).toString(36) + s.length.toString(36); };
const _esc = (x) => String(x ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ------------------------------------------------------------------ JSON viewer
// jv(data, {id, title, filename}) -> HTML. The data is registered client-side so copy/download/expand work without
// re-fetching. Line numbers are those of the fully pretty-printed document (2-space indent), like an editor.
const JV = new Map();          // id -> {data, title, filename, lines: Map(path -> line), total}
const JVS = new Map();         // id -> view state {mode, open:Set(path), q, hit}
const JV_MAX_TREE_LINES = 25000;

function _number(data) {       // path -> first line number in the pretty-printed document; total lines
  const lines = new Map(); let n = 0;
  const walk = (v, p) => {
    n++; lines.set(p, n);
    if (v && typeof v === "object") {
      const ks = Array.isArray(v) ? v.map((_, i) => i) : Object.keys(v);
      if (!ks.length) return;
      ks.forEach((k) => walk(v[k], p + "/" + String(k).replace(/~/g, "~0").replace(/\//g, "~1")));
      n++;                      // closing bracket line
    }
  };
  walk(data, ""); return { lines, total: n };
}
function _get(data, path) {
  if (!path) return data;
  return path.split("/").slice(1).reduce((v, k) => (v == null ? v : v[k.replace(/~1/g, "/").replace(/~0/g, "~")]), data);
}
function _prim(v) {
  if (v === null) return '<span class="j-null">null</span>';
  if (typeof v === "string") return `<span class="j-str">"${_esc(v)}"</span>`;
  if (typeof v === "number") return `<span class="j-num">${v}</span>`;
  if (typeof v === "boolean") return `<span class="j-bool">${v}</span>`;
  return _esc(String(v));
}
function _treeHTML(id, v, path, key, depth, last) {
  const st = JVS.get(id), meta = JV.get(id), ln = meta.lines.get(path) || "";
  const k = key === null ? "" : typeof key === "number" ? "" : `<span class="j-key">"${_esc(key)}"</span>: `;
  const comma = last ? "" : ",";
  const hit = st.hits && st.hits.has(path) ? " hit" : "";
  if (!v || typeof v !== "object") return `<div class="jl${hit}" data-p="${_esc(path)}"><span class="ln">${ln}</span><span class="ind">${"  ".repeat(depth)}</span>${k}${_prim(v)}${comma}</div>`;
  const arr = Array.isArray(v), ks = arr ? v.map((_, i) => i) : Object.keys(v);
  const [o, c] = arr ? ["[", "]"] : ["{", "}"];
  if (!ks.length) return `<div class="jl${hit}" data-p="${_esc(path)}"><span class="ln">${ln}</span><span class="ind">${"  ".repeat(depth)}</span>${k}${o}${c}${comma}</div>`;
  const open = st.open.has(path);
  const sum = `${ks.length} ${arr ? (ks.length === 1 ? "item" : "items") : ks.length === 1 ? "key" : "keys"}`;
  const head = `<div class="jl jo${hit}" data-p="${_esc(path)}"><span class="ln">${ln}</span><span class="ind">${"  ".repeat(depth)}</span>` +
    `<button class="tg" data-jv-act="toggle" data-jv="${id}" data-p="${_esc(path)}" aria-label="${open ? "collapse" : "expand"}">${open ? "▾" : "▸"}</button>${k}${o}` +
    (open ? "" : `<span class="j-sum">…${sum}…</span>${c}${comma}`) +
    `<button class="cp" data-jv-act="copy-node" data-jv="${id}" data-p="${_esc(path)}" title="Copy this ${arr ? "array" : "object"} as JSON">copy</button></div>`;
  if (!open) return head;
  const kids = ks.map((kk, i) => _treeHTML(id, v[kk], path + "/" + String(kk).replace(/~/g, "~0").replace(/\//g, "~1"), arr ? i : kk, depth + 1, i === ks.length - 1)).join("");
  const endLn = (meta.lines.get(path) || 0) + _span(v) - 1;
  return head + kids + `<div class="jl"><span class="ln">${endLn || ""}</span><span class="ind">${"  ".repeat(depth)}</span>${c}${comma}</div>`;
}
function _span(v) {            // number of pretty-printed lines a value occupies
  if (!v || typeof v !== "object") return 1;
  const ks = Array.isArray(v) ? v : Object.values(v);
  return ks.length ? 2 + ks.reduce((n, x) => n + _span(x), 0) : 1;
}
function _textHTML(id) {
  const st = JVS.get(id), q = (st.q || "").toLowerCase();
  const text = JSON.stringify(JV.get(id).data, null, 2) ?? "undefined";
  return text.split("\n").map((l, i) => {
    const m = l.match(/^(\s*)("(?:[^"\\]|\\.)*"\s*:\s*)?(.*)$/);
    const hl = (m[2] ? `<span class="j-key">${_esc(m[2])}</span>` : "") + _esc(m[3]).replace(/^("(?:[^"\\]|\\.)*")/, '<span class="j-str">$1</span>')
      .replace(/^(-?\d[\d.eE+-]*)/, '<span class="j-num">$1</span>').replace(/^(true|false|null)/, '<span class="j-bool">$1</span>');
    const hit = q && l.toLowerCase().includes(q) ? " hit" : "";
    return `<div class="jl${hit}"><span class="ln">${i + 1}</span>${_esc(m[1])}${hl}</div>`;
  }).join("");
}
function _defaultOpen(id) {    // expand the first two levels (bounded) so the structure is visible immediately
  const st = JVS.get(id), data = JV.get(id).data;
  let budget = 400;
  const walk = (v, p, d) => {
    if (!v || typeof v !== "object" || d > 2 || budget <= 0) return;
    st.open.add(p); budget -= Array.isArray(v) ? v.length : Object.keys(v).length;
    (Array.isArray(v) ? v.map((_, i) => i) : Object.keys(v)).forEach((k) => walk(v[k], p + "/" + String(k).replace(/~/g, "~0").replace(/\//g, "~1"), d + 1));
  };
  walk(data, "", 0);
}
function _bodyHTML(id) {
  const st = JVS.get(id), meta = JV.get(id);
  if (st.mode === "text" || meta.total > JV_MAX_TREE_LINES) return _textHTML(id);
  return _treeHTML(id, meta.data, "", null, 0, true);
}
function _barHTML(id, extra = "") {
  const st = JVS.get(id), meta = JV.get(id);
  const big = meta.total > JV_MAX_TREE_LINES;
  return `<div class="jv-bar"><b class="jv-title">${_esc(meta.title || "JSON")}</b><span class="muted small">${meta.total} lines${big ? " · large document: text view" : ""}${meta.redacted ? ` · <span class="jv-red" title="secret-named values and auth headers are masked on screen, in copies and downloads">${meta.redacted} value(s) redacted</span>` : ""}</span>
    <span class="spacer"></span>
    ${meta.kind === "json" && !big ? `<span class="seg"><button data-jv-act="mode" data-jv="${id}" data-mode="tree" class="${st.mode !== "text" ? "on" : ""}">Tree</button><button data-jv-act="mode" data-jv="${id}" data-mode="text" class="${st.mode === "text" ? "on" : ""}">Text</button></span>
    <button data-jv-act="expand" data-jv="${id}" title="Expand all">Expand all</button><button data-jv-act="collapse" data-jv="${id}" title="Collapse all">Collapse</button>` : ""}
    <input class="jv-q" data-jv="${id}" placeholder="Search…" value="${_esc(st.q || "")}" aria-label="Search in ${_esc(meta.title || "JSON")}"><span class="jv-hits small muted">${st.q ? `${st.nhits || 0} match${st.nhits === 1 ? "" : "es"}` : ""}</span>
    ${extra}<button data-jv-act="copy" data-jv="${id}">Copy</button><button data-jv-act="download" data-jv="${id}">Download</button>
    <button data-jv-act="full" data-jv="${id}" title="Full screen (Esc to exit)">⤢ Full screen</button></div>`;
}

/** Sensitive values never reach the screen, the clipboard or a download: secret-named STRING/NUMBER values and auth headers
 *  inside strings are replaced. Objects (e.g. AS3 {bigip: "/Common/x.key"} references) are walked, not masked. */
const _SECRET_KEY = /(pass(phrase|word)?|secret|token|psk|shared[-_]?key|private[-_]?key|authorization|cookie)$/i;
const _AUTH_IN_TEXT = /\b(authorization|proxy-authorization|cookie|x-f5-auth-token)\s*:\s*[^\\\r\n"]+/gi;
function _redact(v, n = { count: 0 }) {
  if (Array.isArray(v)) return v.map((x) => _redact(x, n));
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, x] of Object.entries(v)) {
      if (_SECRET_KEY.test(k) && (typeof x === "string" || typeof x === "number") && x !== "" && x !== "none") { o[k] = "[REDACTED]"; n.count++; }
      else o[k] = _redact(x, n);
    }
    return o;
  }
  if (typeof v === "string" && _AUTH_IN_TEXT.test(v)) { _AUTH_IN_TEXT.lastIndex = 0; n.count++; return v.replace(_AUTH_IN_TEXT, (m, h) => `${h}: [REDACTED]`); }
  return v;
}

/** Reusable JSON viewer. */
function jv(data, { id, title = "JSON", filename = "data.json", height = 380 } = {}) {
  id = String(id || "jv-" + _hash(title));
  const red = { count: 0 };
  data = _redact(data, red);
  const text = JSON.stringify(data) ?? "null";
  const prev = JV.get(id);
  const sig = _hash(text);
  if (!prev || prev.sig !== sig) { const nb = _number(data); JV.set(id, { data, title, filename, kind: "json", sig, redacted: red.count, ...nb }); }
  if (!JVS.has(id)) { JVS.set(id, { mode: "tree", open: new Set(), q: "" }); _defaultOpen(id); }
  return `<div class="jv" data-key="jv:${_esc(id)}" data-sig="${sig}" data-jv-root="${_esc(id)}" style="--jvh:${height}px">${_barHTML(id)}
    <div class="jv-body" tabindex="0" data-jv-body="${_esc(id)}" role="region" aria-label="${_esc(title)}">${_bodyHTML(id)}</div></div>`;
}

/** Line viewer for diffs / logs: lines starting with + or - are coloured; same toolbar as the JSON viewer. */
function jvLines(lines, { id, title = "Diff", filename = "diff.txt", height = 380 } = {}) {
  id = String(id || "jl-" + _hash(title));
  const text = lines.join("\n"), sig = _hash(text);
  JV.set(id, { data: text, title, filename, kind: "lines", sig, total: lines.length, lines: new Map() });
  if (!JVS.has(id)) JVS.set(id, { mode: "text", open: new Set(), q: "" });
  const st = JVS.get(id), q = (st.q || "").toLowerCase();
  const adds = lines.filter((l) => l.startsWith("+") && !l.startsWith("+++")).length, dels = lines.filter((l) => l.startsWith("-") && !l.startsWith("---")).length;
  const body = lines.map((l, i) => `<div class="jl ${l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : l.startsWith("@@") ? "hunk" : ""}${q && l.toLowerCase().includes(q) ? " hit" : ""}"><span class="ln">${i + 1}</span>${_esc(l) || " "}</div>`).join("");
  return `<div class="jv" data-key="jv:${_esc(id)}" data-sig="${sig}" data-jv-root="${_esc(id)}" style="--jvh:${height}px">${_barHTML(id, `<span class="small"><span class="d-add">+${adds}</span> <span class="d-del">−${dels}</span></span>`)}
    <div class="jv-body" tabindex="0" data-jv-body="${_esc(id)}" role="region" aria-label="${_esc(title)}">${body}</div></div>`;
}

function _rerender(id) {
  const root = document.querySelector(`[data-jv-root="${CSS.escape(id)}"]`);
  if (!root) return;
  const meta = JV.get(id), body = root.querySelector(".jv-body"), top = body.scrollTop;
  if (meta.kind === "lines") {
    const st = JVS.get(id), q = (st.q || "").toLowerCase();
    body.querySelectorAll(".jl").forEach((l) => l.classList.toggle("hit", !!q && l.textContent.toLowerCase().includes(q)));
    st.nhits = body.querySelectorAll(".jl.hit").length;
  } else body.innerHTML = _bodyHTML(id);
  const bar = root.querySelector(".jv-bar"), qEl = bar.querySelector(".jv-q"), focused = document.activeElement === qEl, pos = qEl.selectionStart;
  const fresh = document.createElement("div"); fresh.innerHTML = _barHTML(id); _morphNode(bar, fresh.firstElementChild);
  if (focused) { qEl.focus(); try { qEl.setSelectionRange(pos, pos); } catch (e) { /* ignore */ } }
  body.scrollTop = top;
}
function _search(id, q) {
  const st = JVS.get(id), meta = JV.get(id);
  st.q = q; st.hits = new Set(); st.cursor = -1;
  if (q && meta.kind === "json") {
    const ql = q.toLowerCase();
    const walk = (v, p, key) => {
      const self = (key != null && String(key).toLowerCase().includes(ql)) || (v !== null && typeof v !== "object" && String(v).toLowerCase().includes(ql));
      if (self) { st.hits.add(p); const parts = p.split("/"); for (let i = 1; i < parts.length; i++) st.open.add(parts.slice(0, i).join("/")); }
      if (v && typeof v === "object") (Array.isArray(v) ? v.map((_, i) => i) : Object.keys(v)).forEach((k) => walk(v[k], p + "/" + String(k).replace(/~/g, "~0").replace(/\//g, "~1"), k));
    };
    walk(meta.data, "", null);
    st.nhits = st.hits.size;
    if (st.mode === "text") st.nhits = JSON.stringify(meta.data, null, 2).split("\n").filter((l) => l.toLowerCase().includes(ql)).length;
  }
  _rerender(id);
}
function _nextHit(id, back) {
  const body = document.querySelector(`[data-jv-body="${CSS.escape(id)}"]`); if (!body) return;
  const hits = [...body.querySelectorAll(".jl.hit")]; if (!hits.length) return;
  const st = JVS.get(id); st.cursor = ((st.cursor ?? -1) + (back ? -1 : 1) + hits.length) % hits.length;
  hits.forEach((h) => h.classList.remove("cur")); const h = hits[st.cursor]; h.classList.add("cur");
  body.scrollTop = h.offsetTop - body.clientHeight / 3;
}
function _toast(msg, kind) { if (typeof toast === "function") toast(msg, kind); }

document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-jv-act]"); if (!b) return;
  const id = b.dataset.jv, act = b.dataset.jvAct, meta = JV.get(id), st = JVS.get(id); if (!meta) return;
  e.preventDefault();
  const asText = () => (meta.kind === "json" ? JSON.stringify(meta.data, null, 2) : meta.data);
  if (act === "toggle") { const p = b.dataset.p; st.open.has(p) ? st.open.delete(p) : st.open.add(p); _rerender(id); }
  else if (act === "copy-node") { const ok = await copyText(JSON.stringify(_get(meta.data, b.dataset.p), null, 2)); _toast(ok ? "Copied object to the clipboard" : "Copy failed — select the text and press ⌘C", ok ? "ok" : "bad"); }
  else if (act === "copy") { const ok = await copyText(asText()); _toast(ok ? `Copied ${_esc(meta.title)} (${meta.total} lines)` : "Copy failed — select the text and press ⌘C", ok ? "ok" : "bad"); }
  else if (act === "download") saveText(asText(), meta.filename, meta.kind === "json" ? "application/json" : "text/plain");
  else if (act === "mode") { st.mode = b.dataset.mode; if (st.q) _search(id, st.q); else _rerender(id); }
  else if (act === "expand") {
    const walk = (v, p) => { if (v && typeof v === "object") { st.open.add(p); (Array.isArray(v) ? v.map((_, i) => i) : Object.keys(v)).forEach((k) => walk(v[k], p + "/" + String(k).replace(/~/g, "~0").replace(/\//g, "~1"))); } };
    walk(meta.data, ""); _rerender(id);
  } else if (act === "collapse") { st.open = new Set([""]); _rerender(id); }
  else if (act === "full") { const root = b.closest(".jv"); const on = !root.classList.contains("full"); root.classList.toggle("full", on); document.body.classList.toggle("jv-modal", on); b.textContent = on ? "✕ Exit full screen" : "⤢ Full screen"; if (on) root.querySelector(".jv-body").focus(); }

});
let _qTimer = null;
document.addEventListener("input", (e) => {
  const q = e.target.closest(".jv-q"); if (!q) return;
  clearTimeout(_qTimer); _qTimer = setTimeout(() => _search(q.dataset.jv, q.value.trim()), 180);
});
document.addEventListener("keydown", (e) => {
  const q = e.target.closest && e.target.closest(".jv-q");
  if (q && e.key === "Enter") { e.preventDefault(); _nextHit(q.dataset.jv, e.shiftKey); return; }
  const body = e.target.closest && e.target.closest(".jv-body");
  if (body && (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "a") {   // select-all stays inside the viewer
    e.preventDefault(); const r = document.createRange(); r.selectNodeContents(body); const s = getSelection(); s.removeAllRanges(); s.addRange(r);
  }
  if (e.key === "Escape") { const f = document.querySelector(".jv.full"); if (f) { f.classList.remove("full"); document.body.classList.remove("jv-modal"); const fb = f.querySelector('[data-jv-act="full"]'); if (fb) fb.textContent = "⤢ Full screen"; } }
});
// Drag-selection that starts inside a viewer stays inside it (the rest of the page becomes unselectable meanwhile).
document.addEventListener("pointerdown", (e) => {
  const body = e.target.closest && e.target.closest(".jv-body");
  document.querySelectorAll(".jv-body.selecting").forEach((b) => b.classList.remove("selecting"));
  if (body && !e.target.closest("button")) { body.classList.add("selecting"); document.body.classList.add("jv-selecting"); }
}, true);
document.addEventListener("pointerup", () => document.body.classList.remove("jv-selecting"), true);

window.UICore = { patch, inBackground, jv, jvLines, copyText, saveText, JV, JVS, UI };
})();
