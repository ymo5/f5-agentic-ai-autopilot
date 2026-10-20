// F5 Agentic AI Autopilot — AI Operations dashboard v2 (read-only, plus Traffic Generator preset controls).
// Tabs: Overview · AI Data Delivery · AI Security · Fraud investigations · Traffic Generator (see autopilot/aiops.py).
// Every number is labelled with its kind: LIFETIME (cumulative counter), Δ (change between two server reads),
// DURATION (measured elapsed time).
// The browser only chooses a tab and an investigation id; it never sends a query, URL or destination.
// Polling: one request per visible tab every 60 s (10 s on the Traffic Generator tab while a run is active), paused while the
// browser tab is hidden or another Autopilot page is open.
// Traffic Generator controls: the browser sends only a preset id plus the typed confirmation; the server re-checks the role
// (operator+), conflicts and limits, audits, and the host broker owns every preset's fixed command line.
// Loaded before app.js; uses app.js helpers (api, patch, esc, badge, PAGE) only at call time.
"use strict";
const AIOPS = { range: localStorage.getItem("ap.aiops.range") || "1h", tab: localStorage.getItem("ap.aiops.tab") || "overview",
  timer: null, busy: false, data: {}, at: {}, path: null, pathKey: null, tg: null, tgBusy: false };
const AI_TABS = [["overview", "Overview"], ["delivery", "AI Data Delivery"], ["security", "AI Security"], ["investigations", "Fraud investigations"],
  ["trafficgen", "Traffic Generator"]];
const AI_RANGED = new Set();
if (!AI_TABS.some(([k]) => k === AIOPS.tab)) AIOPS.tab = "overview";
const AIOPS_STATE = { ok: ["ok", "ok"], stale: ["stale", "warn"], unavailable: ["unavailable", "fail"], auth_failed: ["auth failed", "fail"],
  not_configured: ["not configured", "low"], not_installed: ["not installed", "low"], error: ["error", "fail"], trace_expired: ["trace expired", "warn"],
  not_found: ["not found", "low"], unknown: ["not captured", "low"], pending: ["summary pending", "low"] };
const AI_COLORS = ["#2f81f7", "#a371f7", "#3fb950", "#d29922", "#f85149", "#39c5cf", "#e4002b", "#93a1b1"];

function aiState(s, detail) {
  const st = s && typeof s === "object" ? s.state : s;
  const [label, cls] = AIOPS_STATE[st] || [String(st || "unknown"), "low"];
  const d = detail ?? (s && typeof s === "object" ? s.detail : "");
  return `<span class="badge b-${cls}" data-state="${esc(st)}">${esc(label)}</span>${d ? ` <span class="small muted">${esc(d)}</span>` : ""}`;
}
const aiKind = (k) => `<span class="ai-kind ai-k-${esc(k)}" title="${esc({ lifetime: "Cumulative counter since the counter was last reset — not a time window", delta: "Change between the two most recent server-side reads", duration: "Measured elapsed time" }[k] || "")}">${esc({ lifetime: "LIFETIME", delta: "Δ", duration: "DURATION" }[k] || k)}</span>`;
const aiNum = (v, unit = "") => (v == null ? "—" : `${Number(v) >= 1e6 ? (v / 1e6).toFixed(1) + "M" : Number(v) >= 1e4 ? (v / 1e3).toFixed(1) + "k" : Math.round(v * 10) / 10}${unit}`);
const aiBytes = (v) => (v == null ? "—" : v >= 1 << 30 ? (v / (1 << 30)).toFixed(1) + " GiB" : v >= 1 << 20 ? (v / (1 << 20)).toFixed(1) + " MiB" : v >= 1024 ? (v / 1024).toFixed(1) + " KiB" : Math.round(v) + " B");
const aiMs = (v) => (v == null ? "—" : v >= 1000 ? (v / 1000).toFixed(v >= 10000 ? 1 : 2) + " s" : Math.round(v) + " ms");
const aiAge = (s) => (s == null ? "" : s < 90 ? `${Math.round(s)} s` : `${Math.round(s / 60)} min`);
const aiHref = (u) => (typeof u === "string" && /^https?:\/\/[^\s"<>]+$/.test(u) ? u : null);   // links: http(s) only
const aiTime = (t) => (t ? new Date(t * 1000).toLocaleString() : "—");
const aiClock = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const aiSum = (points) => (points || []).reduce((a, p) => a + (p[1] || 0), 0);
const aiLink = (u, label) => (aiHref(u) ? `<a href="${esc(aiHref(u))}" target="_blank" rel="noopener noreferrer">${label}</a>` : "");

// ------------------------------------------------------------------ dependency-free SVG charts
function aiSpark(points, { w = 140, h = 26, color = "var(--blue)" } = {}) {
  const v = (points || []).map((p) => p[1]);
  if (!v.length) return '<span class="small muted">no samples</span>';
  const max = Math.max(1, ...v.filter((x) => x != null)), step = v.length > 1 ? w / (v.length - 1) : w;
  let d = "", pen = false;
  v.forEach((x, i) => { if (x == null) { pen = false; return; } d += `${pen ? "L" : "M"}${(i * step).toFixed(1)},${(h - 2 - (x / max) * (h - 4)).toFixed(1)} `; pen = true; });
  return `<svg class="ai-spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="total ${aiSum(points)}"><path d="${d}" fill="none" stroke="${color}" stroke-width="1.5"/></svg>`;
}
// Stacked area: series = [{name, points:[[t,v],...]}] sharing timestamps.
function aiArea(series, { w = 760, h = 190, unit = "" } = {}) {
  const ss = (series || []).filter((s) => s.points && s.points.length);
  if (!ss.length) return '<p class="muted small">no samples in range</p>';
  const ts = [...new Set(ss.flatMap((s) => s.points.map((p) => p[0])))].sort((a, b) => a - b);
  const idx = new Map(ts.map((t, i) => [t, i]));
  const L = 44, B = 18, W = w - L - 6, H = h - B - 6;
  const acc = ts.map(() => 0), layers = ss.map((s) => { const v = ts.map(() => 0); s.points.forEach(([t, y]) => { v[idx.get(t)] = y || 0; }); return v; });
  const tops = layers.map((v) => v.map((y, i) => (acc[i] += y)));
  const max = Math.max(1, ...acc);
  const X = (i) => L + (ts.length > 1 ? (i / (ts.length - 1)) * W : W / 2), Y = (v) => 6 + H - (v / max) * H;
  let paths = "", prev = ts.map(() => 0);
  tops.forEach((top, k) => {
    const up = top.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(" L"), down = prev.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`).reverse().join(" L");
    paths += `<path d="M${up} L${down} Z" fill="${AI_COLORS[k % AI_COLORS.length]}" fill-opacity=".55" stroke="${AI_COLORS[k % AI_COLORS.length]}" stroke-width="1"><title>${esc(ss[k].name)}: ${aiNum(aiSum(ss[k].points))}${esc(unit)}</title></path>`;
    prev = top;
  });
  const ticks = [0, Math.floor((ts.length - 1) / 2), ts.length - 1].filter((v, i, a) => a.indexOf(v) === i);
  const axis = ticks.map((i) => `<text x="${X(i).toFixed(0)}" y="${h - 4}" class="ai-ax" text-anchor="middle">${esc(aiClock(ts[i]))}</text>`).join("")
    + `<text x="${L - 4}" y="12" class="ai-ax" text-anchor="end">${esc(aiNum(max))}</text><text x="${L - 4}" y="${6 + H}" class="ai-ax" text-anchor="end">0</text>`
    + `<line x1="${L}" y1="${6 + H}" x2="${L + W}" y2="${6 + H}" class="ai-grid"/>`;
  const legend = ss.map((s, k) => `<span class="ai-leg"><i style="background:${AI_COLORS[k % AI_COLORS.length]}"></i>${esc(s.name)} <b>${aiNum(aiSum(s.points))}${esc(unit)}</b></span>`).join("");
  return `<svg class="ai-area" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img">${axis}${paths}</svg><div class="ai-legend">${legend}</div>`;
}
// Horizontal bars: items = [{label, value, cls}]
function aiBars(items, { unit = "" } = {}) {
  const max = Math.max(1, ...items.map((i) => i.value || 0));
  return `<div class="ai-bars">${items.map((i) => `<div class="ai-bar-row"><span class="ai-bar-l">${esc(i.label)}</span><span class="ai-bar-t"><i class="${esc(i.cls || "")}" style="width:${(100 * (i.value || 0) / max).toFixed(1)}%"></i></span><span class="ai-bar-v">${aiNum(i.value)}${esc(unit)}</span></div>`).join("")}</div>`;
}
// Investigation execution path: one row per stage, bar from first span to first+busy (not to scale for overlapping spans).
function aiFlow(p) {
  if (!p || !p.stages) return "";
  const total = Math.max(1, p.total_ms || Math.max(...p.stages.filter((s) => s.observed).map((s) => (s.first_ms || 0) + (s.busy_ms || 0)), 1));
  const rows = p.stages.map((s, i) => {
    if (!s.observed) return `<div class="ai-flow-row muted"><span class="ai-flow-l">${esc(s.label)}</span><span class="ai-flow-t"></span><span class="ai-flow-v small">not observed in this trace</span></div>`;
    const left = Math.min(99, (100 * (s.first_ms || 0)) / total), width = Math.max(0.6, Math.min(100 - left, (100 * (s.busy_ms || 0)) / total));
    const ps = s.paths || [], via = (ps.includes("via_bigip") && ps.includes("direct") ? badge("mixed: via BIG-IP + direct", "warn") : ps.includes("via_bigip") ? badge("via BIG-IP", "ok") : ps.includes("direct") ? badge("direct (not via BIG-IP)", "warn") : ps.includes("unknown") ? badge("path unknown", "low") : "")
      + (ps.includes("unknown") && (ps.includes("via_bigip") || ps.includes("direct")) ? " " + badge("some spans unclassified", "low") : "");
    return `<div class="ai-flow-row"><span class="ai-flow-l">${esc(s.label)} ${via}</span><span class="ai-flow-t"><i style="left:${left.toFixed(1)}%;width:${width.toFixed(1)}%;background:${AI_COLORS[i % AI_COLORS.length]}"></i></span>
      <span class="ai-flow-v small">${aiMs(s.busy_ms)} busy · ${esc(s.calls)} call${s.calls === 1 ? "" : "s"} · slowest ${aiMs(s.max_call_ms)}${s.errors ? " · " + badge(s.errors + " error spans", "fail") : ""}</span></div>`;
  }).join("");
  return `<div class="ai-flow"><div class="small muted">${aiKind("duration")} end-to-end ${aiMs(p.total_ms)} · ${esc(p.spans)} spans · ${esc(p.errors)} error spans${p.tokens ? ` · LLM tokens reported by the agent: ${esc(p.tokens.input)} in / ${esc(p.tokens.output)} out` : ""}
    · busy = time with at least one span of the stage active (parallel calls are not double-counted)</div>${rows}</div>`;
}

// ------------------------------------------------------------------ tabs
function aiOverview(o) {
  if (!o) return "";
  const tiles = (o.vips || []).map((v) => `<div class="ai-tile" data-key="tile-${esc(v.app)}"><div class="ai-tile-h"><b>${esc(v.label)}</b>
      ${badge(v.source === "bigip" ? "BIG-IP statistics" : "no data", "low")}</div>
      <div class="ai-tile-n">${aiNum(v.lifetime && v.lifetime.requests)} <span class="small muted">requests</span> ${aiKind("lifetime")}</div>
    </div>`).join("");
  const gates = (o.security.gates || []).map((g) => `<div>${badge(`${g.gate} ${g.counts.pass || 0}/${g.total}`, (g.counts.fail || 0) ? "fail" : "ok")} <span class="small muted">deployment gate · ${esc(g.deployment)} · ${esc(aiTime(g.started))}</span></div>`).join("");
  const s3 = o.data.s3_lifetime || {}, d3 = o.data.s3_delta || {};
  const tg = o.trafficgen || {}, lr = tg.last_run, inv = o.investigation;
  return `<div class="ai-tiles">${tiles}</div>
    <div class="grid3">
      <div class="card"><h4>Security posture</h4>${gates || '<p class="muted small">no deployment gate validations</p>'}</div>
      <div class="card"><h4>AI data delivery · S3</h4><div class="small">${aiKind("lifetime")} GET objects ${aiNum(s3.s3_get_object)} · lists ${aiNum(s3.s3_list_bucket)} · bytes ${aiBytes(s3.s3_get_bytes)} · 2xx ${aiNum(s3.s3_resp_2xx)} · 4xx ${aiNum(s3.s3_resp_4xx)} · unsigned ${aiNum(s3.s3_unsigned)}</div>
        <div class="small">${aiKind("delta")} ${o.data.delta_seconds ? `over ${esc(Math.round(o.data.delta_seconds))} s: GET objects +${aiNum(d3.s3_get_object)} · requests +${aiNum(d3.s3_requests)}` : "available after the next refresh"}</div></div>
      <div class="card"><h4>Latest investigation</h4>${inv ? `<div>${esc(inv.alert)} ${inv.decision ? badge(inv.decision, inv.decision === "escalate" ? "fail" : inv.decision === "monitor" ? "warn" : "ok") : ""} risk ${esc(inv.risk || "—")}${inv.confidence != null ? ` · confidence ${esc(inv.confidence)}` : ""}</div>
        <div class="small">${aiKind("duration")} ${aiMs(inv.duration && inv.duration.seconds != null ? inv.duration.seconds * 1000 : null)} ${aiLink(inv.trace_url, "trace")}</div>` : '<p class="muted small">none</p>'}
        <h4>Traffic Generator</h4><div class="small">${esc(tg.status || tg.state)}${lr ? ` · last run ${esc(lr.run)}: ${aiNum(lr.totals.ok)}/${aiNum(lr.totals.runs)} ok, ${aiNum(lr.totals.requests)} requests, ${aiNum(lr.rate && lr.rate.requests_per_min)}/min` : ""}</div></div>
    </div>
    <p class="small muted">Sources: BIG-IP via deployer ${aiState(o.states.bigip, "")} · gates ${aiState(o.states.gates, "")} · Agent A ${aiState(o.states.agent_a, "")} · generator ${aiState(o.states.trafficgen, "")}</p>`;
}

function aiDelivery(d) {
  if (!d) return "";
  const bg = d.bigip || {};
  const s3 = (bg.lifetime || {}).s3_statistics || {}, dl = bg.delta || {}, dv = (bg.lifetime || {}).data_vips || {};
  const s3rows = Object.keys(s3).sort().map((k) => `<tr><td><code>${esc(k)}</code></td><td class="num">${aiNum(s3[k])}</td><td class="num">${dl.s3 && dl.s3[k] != null ? "+" + aiNum(dl.s3[k]) : "—"}</td></tr>`).join("");
  return `<div class="grid2"><div class="card"><h3>S3 statistics <span class="small muted">BIG-IP statistics profile stats_s3 via the Autopilot deployer (read-only)</span></h3><p>${aiState(bg)}</p>
      ${s3rows ? `<table class="t small"><tr><th>counter</th><th>${aiKind("lifetime")}</th><th>${aiKind("delta")} ${dl.seconds ? esc(Math.round(dl.seconds)) + " s" : ""}</th></tr>${s3rows}</table>${(dl.resets || []).length ? `<p class="small">${badge("counter reset detected", "warn")} ${(dl.resets || []).map(esc).join(", ")}</p>` : ""}` : '<p class="muted small">—</p>'}</div>
    <div class="card"><h3>Data VIP counters <span class="small muted">BIG-IP iControl (http_ai numberReqs)</span></h3>
      ${Object.keys(dv).length ? `<table class="t small"><tr><th></th><th>requests ${aiKind("lifetime")}</th><th>connections ${aiKind("lifetime")}</th><th>requests ${aiKind("delta")}</th></tr>${Object.entries(dv).map(([k, v]) => `<tr><td>${esc(k)}</td><td class="num">${aiNum(v["http.numberReqs"])}</td><td class="num">${aiNum(v["clientside.totConns"])}</td><td class="num">${dl.data_vips && dl.data_vips[k] && dl.data_vips[k]["http.numberReqs"] != null ? "+" + aiNum(dl.data_vips[k]["http.numberReqs"]) : "—"}</td></tr>`).join("")}</table>` : '<p class="muted small">—</p>'}
      <h4>Pool members (BIG-IP)</h4>${(bg.members || []).map((m) => `<span class="badge b-${m.availability === "available" ? "ok" : "fail"}">${esc(m.service)} ${esc(m.member)}:${esc(m.port)}</span>`).join(" ") || '<span class="muted small">—</span>'}</div></div>`;
}

function aiSecurity(d) {
  if (!d) return "";
  const g = d.gates || {}, ind = d.independent || {};
  const gateRow = (h) => `<tr><td>${badge(h.gate, "low")}</td><td><code>${esc(h.deployment)}</code> ${badge(h.deployment_status, h.deployment_status === "succeeded" ? "ok" : "warn")}<div class="small muted">${esc(h.package_title)}</div></td>
    <td class="small">${aiTime(h.started)}</td><td>${h.total != null ? Object.entries(h.counts).map(([k, n]) => badge(`${n} ${k}`, k === "pass" ? "ok" : k === "fail" ? "fail" : "low")).join(" ") : badge("gate failed", "fail") + ` <span class="small muted">${esc(h.error || "")}</span>`}</td>
    <td class="small">${(h.failed_tests || []).map((t) => `<code>${esc(t)}</code>`).join(" ") || "—"}</td></tr>`;
  const indRows = (ind.runs || []).map((r) => `<tr><td>${badge(r.label, "low")}</td><td class="small">${aiTime(r.started)}</td><td>${Object.entries(r.counts || {}).map(([k, n]) => badge(`${n} ${k}`, k === "pass" ? "ok" : k === "fail" ? "fail" : "low")).join(" ")}</td><td class="small">${(r.failed_tests || []).map((t) => `<code>${esc(t)}</code>`).join(" ") || "—"}</td></tr>`).join("");
  return `<div class="card"><h3>Proven enforcement <span class="small muted">Autopilot validation tests executed against the BIG-IP</span></h3>
      <h4>Deployment gate validations ${aiState(g, "")} <span class="small muted">run by the deployer as part of a deployment (deployment journal)</span></h4>
      ${(g.latest || []).length ? `<table class="t"><tr><th>Gate</th><th>Deployment</th><th>When</th><th>Result</th><th>Failed tests</th></tr>${g.latest.map(gateRow).join("")}</table>` : '<p class="muted small">none</p>'}
      <details><summary class="small">gate history (incl. failed and rolled-back deployments)</summary><table class="t small">${(g.history || []).map(gateRow).join("")}</table></details>
      <h4>Independent validation runs ${aiState(ind, "")} <span class="small muted">started from the Validate page, outside a deployment</span></h4>
      ${indRows ? `<table class="t small"><tr><th>Run</th><th>When</th><th>Result</th><th>Failed tests</th></tr>${indRows}</table>` : '<p class="muted small">none</p>'}</div>`;
}

function aiInvestigations(d) {
  if (!d) return "";
  const sel = AIOPS.pathKey;
  const row = (r) => {
    const key = `${r.source}/${r.id}`;
    const can = r.source === "autopilot" || !!r.trace_id;
    return `<tr class="${sel === key ? "ai-sel" : ""}"><td>${esc(r.alert || "")}${r.title ? `<div class="small muted">${esc(r.title)}</div>` : ""}</td><td class="small">${aiTime(r.started)}</td>
      <td>${badge(r.state || "?", r.state === "completed" ? "ok" : r.error ? "fail" : "low")}</td><td>${r.decision ? badge(r.decision, r.decision === "escalate" ? "fail" : r.decision === "monitor" ? "warn" : "ok") : "—"}</td>
      <td>${esc(r.risk || "—")}${r.confidence != null ? ` <span class="small muted">${esc(r.confidence)}</span>` : ""}</td><td class="num">${r.duration && r.duration.seconds != null ? esc(r.duration.seconds) + " s" : "—"}</td>
      <td class="small">${r.front_door ? `<code>${esc(r.front_door)}</code>` : ""}</td>
      <td>${can ? `<button class="small" data-aipath="${esc(key)}">path</button>` : ""} ${r.path_state ? aiState(r.path_state, "") : ""} ${aiLink(r.trace_url, `<code>${esc((r.trace_id || "").slice(0, 10))}…</code>`)}</td></tr>`;
  };
  const tbl = (s) => (s.runs && s.runs.length ? `<table class="t"><tr><th>Alert</th><th>Started</th><th>State</th><th>Decision</th><th>Risk · confidence</th><th>Duration ${aiKind("duration")}</th><th>Front door</th><th>Execution path</th></tr>${s.runs.map(row).join("")}</table>` : '<p class="muted small">none</p>');
  const p = AIOPS.path;
  return `${p ? `<div class="card" data-key="aiops-path"><h3>Execution path · ${esc(sel || "")}</h3><p>${aiState(p)} ${aiLink(p.trace_url, "open the full trace in Jaeger")}</p>${p.path ? aiFlow(p.path) : ""}</div>` : ""}
    <div class="card"><h3>Agent A investigations ${aiState(d.agent_a || {})}</h3>${tbl(d.agent_a || {})}
      <p class="small muted">Execution paths are summarised from Jaeger while the trace is retained (≈ 9–10 h in this lab) and kept as a sanitised summary (stages, timings, counts — no case content). Summary store: ${esc(d.summary_store)}.</p></div>
    <div class="card"><h3>Investigations started from Autopilot ${aiState(d.autopilot || {})}</h3>${tbl(d.autopilot || {})}</div>`;
}

function aiTrafficgen(d) {
  if (!d) return "";
  const wl = (w, lat) => Object.entries(w || {}).map(([n, x]) => `<tr><td><code>${esc(n)}</code></td><td class="num">${aiNum(x.runs)}</td><td class="num">${aiNum(x.ok)}</td>
    <td class="num">${aiNum((x.unexpected || 0) + (x.unavailable || 0) + (x.error || 0))}</td><td class="num">${aiNum(x.deferred)}</td><td class="num">${aiNum(x.requests)}</td>
    <td class="num">${aiBytes(x.bytes)}</td><td class="num">${lat && lat[n] ? `${aiMs(lat[n].p50)} / ${aiMs(lat[n].p95)}` : x.avg_ms != null ? aiMs(x.avg_ms) + " avg" : "—"}</td>
    <td class="small">${Object.values(x.targets || {}).map((t) => `<code>${esc(t.bigip_object || t.address)}</code>`).join(" ")}</td></tr>`).join("");
  const head = `<tr><th>Workload</th><th>runs</th><th>ok</th><th>failures</th><th>deferred</th><th>requests</th><th>bytes</th><th>latency p50 / p95 ${aiKind("duration")}</th><th>BIG-IP virtual server</th></tr>`;
  const cur = d.current, runs = d.runs || [];
  const rateBars = aiBars(runs.slice().reverse().map((r) => ({ label: r.run, value: r.rate && r.rate.requests_per_min, cls: r.exit_code === 0 ? "ok" : "bad" })), { unit: "/min" });
  const runRows = runs.map((r) => `<tr><td><code>${esc(r.run)}</code></td><td class="small">${esc(r.mode || "")}</td>
    <td>${badge(r.exit_code === 0 ? "exit 0" : `exit ${r.exit_code ?? "?"}`, r.exit_code === 0 ? "ok" : "fail")}${r.stopped_by_stop_file ? " " + badge("stopped", "low") : ""}</td>
    <td class="num">${r.duration && r.duration.seconds != null ? esc(Math.round(r.duration.seconds)) + " s" : "—"}</td><td class="num">${aiNum(r.totals.ok)}/${aiNum(r.totals.runs)}</td>
    <td class="num">${aiNum(r.totals.requests)}</td><td class="num">${aiNum(r.rate && r.rate.requests_per_min)}</td><td>${aiSpark((r.runs_per_minute || []).map(([t, v]) => [t, v]))}</td><td class="small">${esc(r.args || "")}</td></tr>`).join("");
  return `${aiTgControl(AIOPS.tg)}<div class="card"><h3>Traffic Generator <span class="small muted">ap-trafficgen on AP-AUTOPILOT-01 · run archive</span></h3><p>${aiState(d)} ${badge(d.status || "—", d.status === "running" ? "ok" : "low")}</p>
    ${cur ? `<h4>${cur.running ? "Running" : "Last unarchived"} run <span class="small muted">${esc(cur.mode)} · started ${esc(cur.started)} · updated ${esc(cur.updated)}</span></h4><table class="t small">${head}${wl(cur.workloads)}</table>` : ""}
    <h4>Request rate per run</h4>${runs.length ? rateBars : '<p class="muted small">no archived runs</p>'}
    <h4>Archived runs</h4>${runRows ? `<table class="t small"><tr><th>run</th><th>mode</th><th>result</th><th>duration ${aiKind("duration")}</th><th>ok</th><th>requests</th><th>req/min</th><th>activity</th><th>arguments</th></tr>${runRows}</table>` : ""}
    ${runs[0] ? `<h4>Latest run · per workload</h4><table class="t small">${head}${wl(runs[0].workloads, runs[0].latency_ms)}</table>` : ""}
    <p class="small muted">Latency is measured by the generator client (request to response). Controlled starts use the presets above; the owner can still use <code>sudo ap-trafficgen</code> on the host.</p></div>`;
}

// ------------------------------------------------------------------ Traffic Generator controls (server-defined presets)
const aiDur = (s) => (s == null ? "—" : s >= 60 ? `${Math.floor(s / 60)} min ${String(Math.round(s % 60)).padStart(2, "0")} s` : `${Math.round(s)} s`);
const AI_TG_LABEL = { "a2a-discovery-5m": "A2A discovery", "rag-retrieval-10m": "Qdrant retrieval (RAG)", "embeddings-10m": "Ollama embeddings",
  "ai-data-path-15m": "AI data path (A2A + Qdrant + embeddings)", "llm-chat-sample": "Small LLM chat sample (one pass)" };
function aiTgControl(c) {
  if (!c) return `<div class="card" id="tg-control"><h3>Traffic Generator control</h3><p><span class="spin"></span> loading…</p></div>`;
  if (!c.available) return `<div class="card" id="tg-control"><h3>Traffic Generator control ${badge("unavailable", "low")}</h3><p class="small muted">${esc(c.reason || "controller not installed")} — the run archive below stays readable.</p></div>`;
  const cur = c.current, run = c.running === true, tm = c.timing, busy = AIOPS.tgBusy;
  const why = !c.can_control ? `${esc(c.min_role || "operator")} role required — viewers have read-only access` : run ? "a run is active — stop it first" :
    c.start_blocked ? `start blocked: ${esc(c.start_blocked)}` : c.running == null ? "generator state unknown" : "";
  const startOk = c.can_control && c.running === false && !c.start_blocked && !busy;
  const pct = tm && cur && cur.duration_s ? Math.min(100, Math.round(100 * tm.elapsed_s / cur.duration_s)) : 0;
  const presets = Object.entries(c.presets || {}).map(([id, p]) => `<div class="card ai-tg-preset" data-preset="${esc(id)}"><h4>${esc(AI_TG_LABEL[id] || id)}</h4>
    <div class="small"><code>${esc(id)}</code></div><div class="kv small"><div>duration</div><div>${p.duration_s >= 120 && !/sample/.test(id) ? esc(aiDur(p.duration_s)) : "one pass (≤ " + esc(aiDur(p.duration_s)) + ")"}</div>
    <div>max rate</div><div>${esc(p.max_rpm)} req/min</div><div>workloads</div><div>${(p.workloads || []).map((w) => `<code>${esc(w)}</code>`).join(" ")}</div></div>
    <p><button class="go" data-tgstart="${esc(id)}" ${startOk ? "" : "disabled"}>Start</button></p></div>`).join("");
  const hist = (c.history || []).slice().reverse().map((h) => `<tr><td><code>${esc(h.preset)}</code></td><td>${esc(h.by || "")}</td><td class="small">${aiTime(h.requested_at)}</td>
    <td>${badge(h.outcome || "—", h.outcome === "stopped" || h.outcome === "started" ? "ok" : /fail/.test(h.outcome || "") ? "fail" : "low")}</td><td>${esc(h.stopped_by || "")}</td></tr>`).join("");
  const lim = c.limits || {};
  return `<div class="card" id="tg-control"><h3>Traffic Generator control ${badge(run ? "running" : c.running === false ? "idle" : "unknown", run ? "ok" : "low")}</h3>
    ${cur ? `<div class="kv small"><div>${run ? "current" : "last"} preset</div><div><code>${esc(cur.preset)}</code> · ${esc(cur.outcome || "")}${cur.ended ? " · ended" : ""}</div>
      <div>started by</div><div>${esc(cur.by || "")} · ${aiTime(cur.requested_at)}</div>
      <div>workloads</div><div>${(cur.workloads || []).map((w) => `<code>${esc(w)}</code>`).join(" ")} · max ${esc(cur.max_rpm)} req/min</div>
      ${tm ? `<div>elapsed / remaining ${aiKind("duration")}</div><div>${esc(aiDur(tm.elapsed_s))} / ${esc(aiDur(tm.remaining_s))} <progress max="100" value="${pct}"></progress></div>` : ""}</div>` : '<p class="small muted">No run started from Autopilot yet.</p>'}
    <p><button class="danger" id="tg-stop" ${c.can_control && run && !busy ? "" : "disabled"}>Stop run</button> <span class="why">${busy ? '<span class="spin"></span> request in progress…' : !c.can_control ? why : ""}</span></p>
    <h4>Presets <span class="small muted">fixed on the server · MCP and S3 workloads are not offered</span></h4>
    <p class="why small">${why}</p><div class="grid3">${presets}</div>
    <p class="small muted">Limits: one active run · at most ${esc(lim.starts_per_hour ?? "—")} starts per hour · ${esc(lim.mutations_per_10min ?? "—")} start/stop requests per 10 min · generator container 256 MiB / 0.5 CPU, read-only, maximum duration 15 min. Stop is graceful (stop file, then container stop) and archives the run. Every request is recorded in the audit log (category <code>trafficgen</code>).</p>
    ${hist ? `<h4>Recent controlled runs</h4><table class="t small"><tr><th>preset</th><th>started by</th><th>requested</th><th>outcome</th><th>stopped by</th></tr>${hist}</table>` : ""}</div>`;
}
async function aiTgLoad() {
  AIOPS.tg = await api("/api/aiops/trafficgen/control").catch((e) => ({ available: false, reason: e.message }));
}
async function aiTgAction(kind, preset) {
  if (AIOPS.tgBusy) return;                        // one dialog / request at a time from this page (the server enforces it too)
  AIOPS.tgBusy = true;
  const c = kind === "start"
    ? await ask(`Start Traffic Generator: ${AI_TG_LABEL[preset] || preset}`, `Runs the fixed server-side preset <code>${esc(preset)}</code> against the AI data path through BIG-IP_C. Type the preset id <b>${esc(preset)}</b> to confirm.`, { must: preset, confirm: "Start", cls: "go" })
    : await ask("Stop Traffic Generator", "Gracefully stops the active run and archives it. Type <b>STOP</b> to confirm.", { must: "STOP", confirm: "Stop", cls: "danger" });
  if (c === null) { AIOPS.tgBusy = false; return; }
  aiRender();
  try {
    const r = kind === "start" ? await post("/api/aiops/trafficgen/start", { preset, confirm: c }) : await post("/api/aiops/trafficgen/stop", { confirm: c });
    toast(kind === "start" ? `Traffic Generator started: ${esc(preset)}` : r.stopped ? `Traffic Generator stopped${r.seconds != null ? ` in ${esc(r.seconds)} s` : ""}` : "Traffic Generator was not running", "ok");
  } catch (e) { toast(esc(e.message), "bad"); }
  AIOPS.tgBusy = false;
  await aiTgLoad(); await aiLoad("trafficgen"); aiRender(); renderAIOps(false);
}

// ------------------------------------------------------------------ page
const AI_ENDPOINT = { overview: "overview", delivery: "delivery", security: "security", investigations: "investigations", trafficgen: "trafficgen" };
async function aiLoad(tab) {
  if (AIOPS.busy) return; AIOPS.busy = true;
  try {
    const q = AI_RANGED.has(tab) ? `?range=${encodeURIComponent(AIOPS.range)}` : "";
    AIOPS.data[tab] = await api(`/api/aiops/${AI_ENDPOINT[tab]}${q}`).catch((e) => ({ state: "error", detail: e.message }));
    if (tab === "trafficgen") await aiTgLoad();
    AIOPS.at[tab] = Date.now();
  } finally { AIOPS.busy = false; }
}
async function aiShowPath(key) {
  const [source, id] = key.split("/");
  if (!/^(autopilot|agent_a)$/.test(source) || !/^[0-9a-f-]{16,36}$/.test(id)) return;
  AIOPS.pathKey = key; AIOPS.path = { state: "unknown", detail: "loading…" }; aiRender();
  AIOPS.path = await api(`/api/aiops/investigations/${source}/${id}/path`).catch((e) => ({ state: "error", detail: e.message }));
  aiRender();
}
function aiRender() {
  const el = document.getElementById("aiops"); if (!el) return;
  const t = AIOPS.tab, d = AIOPS.data[t];
  const tabs = AI_TABS.map(([k, l]) => `<button data-aitab="${k}" class="${k === t ? "primary" : ""}">${esc(l)}</button>`).join("");
  const ranges = "";
  const body = { overview: aiOverview, delivery: aiDelivery, security: aiSecurity, investigations: aiInvestigations, trafficgen: aiTrafficgen }[t] || aiOverview;
  patch(el, `<div class="ai-head"><h2>AI Operations</h2><span class="small muted">${t === "trafficgen" ? "controls: operator+" : "read-only"} · ${AIOPS.at[t] ? "updated " + new Date(AIOPS.at[t]).toLocaleTimeString() : "loading…"}</span><span class="spacer"></span><span class="ai-ranges">${ranges}</span></div>
    <div class="ai-tabs">${tabs}</div>
    <p class="small muted ai-legend-kinds">${aiKind("lifetime")} cumulative counter · ${aiKind("delta")} change between two reads · ${aiKind("duration")} measured elapsed time</p>
    ${d ? (d.state === "error" ? `<div class="card alert">${aiState(d)}</div>` : body(d)) : '<p><span class="spin"></span> loading…</p>'}`);
  el.querySelectorAll("[data-aitab]").forEach((b) => (b.onclick = () => { AIOPS.tab = b.dataset.aitab; localStorage.setItem("ap.aiops.tab", AIOPS.tab); renderAIOps(false); }));
  el.querySelectorAll("[data-airange]").forEach((b) => (b.onclick = () => { AIOPS.range = b.dataset.airange; localStorage.setItem("ap.aiops.range", AIOPS.range); AIOPS.data = {}; AIOPS.at = {}; renderAIOps(true); }));
  el.querySelectorAll("[data-aipath]").forEach((b) => (b.onclick = () => aiShowPath(b.dataset.aipath)));
  el.querySelectorAll("[data-tgstart]").forEach((b) => (b.onclick = () => aiTgAction("start", b.dataset.tgstart)));
  el.querySelectorAll("#tg-stop").forEach((b) => (b.onclick = () => aiTgAction("stop")));
}
const aiVisible = () => (typeof PAGE === "undefined" || PAGE === "aiops") && !(typeof document !== "undefined" && document.hidden);
async function renderAIOps(full) {
  clearTimeout(AIOPS.timer);
  const t = AIOPS.tab;
  const fast = t === "trafficgen" && AIOPS.tg && AIOPS.tg.running === true;     // live elapsed / counters while a run is active
  if (full || !AIOPS.at[t] || Date.now() - AIOPS.at[t] > (fast ? 9000 : 55000)) { aiRender(); if (aiVisible()) await aiLoad(t); }
  aiRender();
  AIOPS.timer = setTimeout(() => { if (aiVisible()) renderAIOps(false); }, AIOPS.tg && AIOPS.tg.running === true && AIOPS.tab === "trafficgen" ? 10000 : 60000);
}
if (typeof document !== "undefined" && document.addEventListener) {
  document.addEventListener("visibilitychange", () => { if (!document.hidden && typeof PAGE !== "undefined" && PAGE === "aiops") renderAIOps(false); });
}
window.renderAIOps = renderAIOps;
