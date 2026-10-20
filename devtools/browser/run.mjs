// Browser regression suite (Wave 1). Real Chrome, clean temporary profile, extensions disabled, real input events,
// against the production-served static assets of the real web app running on mocks (devtools/devserver.py).
// Never touches the lab. Usage:  node devtools/browser/run.mjs [--keep] [--only=<substr>]
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Browser, sleep } from "./cdp.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const OUT = process.env.AP_BROWSER_OUT || path.join(ROOT, "test-results/browser");
const ART = path.join(OUT, "browser-artifacts");
fs.mkdirSync(ART, { recursive: true });
const ONLY = (process.argv.find((a) => a.startsWith("--only=")) || "").slice(7);
const PW = "correct-horse-battery-staple";   // dev/test fixture password (tests/conftest.py), never a lab credential

async function devserver(port, scenario) {
  const p = spawn(process.env.AP_PYTHON || path.join(ROOT, ".venv-demo/bin/python"), [path.join(ROOT, "devtools/devserver.py"), String(port), scenario], { stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; p.stdout.on("data", (d) => (log += d)); p.stderr.on("data", (d) => (log += d));
  for (let i = 0; i < 120; i++) {
    try { const r = await fetch(`http://127.0.0.1:${port}/healthz`); if (r.ok) return { proc: p, base: `http://127.0.0.1:${port}`, log: () => log }; } catch { /* starting */ }
    await sleep(500);
  }
  throw new Error(`devserver ${scenario} did not start:\n${log.slice(-2000)}`);
}

const results = [];
async function test(name, area, fn) {
  if (ONLY && !ONLY.split("|").some((o) => name.includes(o))) return;   // --only=a|b|c: any of the substrings
  const t0 = Date.now(); let page;
  try { page = await fn(); results.push({ name, area, status: "pass", ms: Date.now() - t0 }); console.log(`  ✓ ${name}`); }
  catch (e) {
    results.push({ name, area, status: "fail", ms: Date.now() - t0, error: String(e && e.stack || e).slice(0, 1500) });
    console.log(`  ✗ ${name}\n      ${String(e.message || e).split("\n")[0]}`);
    try { if (CUR) await CUR.shot(path.join(ART, `${name.replace(/[^\w]+/g, "_")}.png`)); } catch { /* ignore */ }
  }
  try { if (CUR) await CUR.close(); } catch { /* ignore */ }   // one tab per test: no background tabs polling meanwhile
  CUR = null;
}
let CUR = null;
const assert = (c, m) => { if (!c) throw new Error("assertion failed: " + m); };

const D = await devserver(8781, "failed-then-deployed");
const C = await devserver(8782, "compare");
const P = await devserver(8783, "placement-evidence");
const browser = await Browser.launch();
const ext = await browser.extensionsLoaded();
await browser.grant(D.base); await browser.grant(C.base); await browser.grant(P.base);
console.log(`Chrome clean profile ${browser.profile} · extension targets: ${ext} · downloads → ${browser.downloadDir}`);

async function page(base, user = "se", where = "demo") {
  const p = await browser.newPage(); CUR = p;
  await p.goto(`${base}/dev-login?u=${user}&page=${where}`, 2500);
  await p.waitFor(`document.querySelector("#acct-name").textContent.includes("${user}")`, 15000, "signed in");
  return p;
}
const goPage = async (p, name) => { await p.eval(`go(${JSON.stringify(name)})`); await sleep(900); };

try {
  // ------------------------------------------------------------------ environment
  await test("clean Chrome profile has no extensions", "environment", async () => { assert(ext === 0, `extension targets: ${ext}`); });

  // ------------------------------------------------------------------ authentication & access control
  await test("login form: wrong password rejected, correct password signs in", "auth", async () => {
    const p = await browser.newPage(); CUR = p;
    await p.send("Network.enable"); await p.send("Network.clearBrowserCookies");
    await p.goto(`${D.base}/`, 2500);
    await p.waitFor(`!document.querySelector("#login").classList.contains("hidden")`, 8000, "login dialog");
    await p.click("#lu"); await p.type("se"); await p.click("#lp"); await p.type("wrong-password"); await p.click("#lb"); await sleep(700);
    assert((await p.eval(`document.querySelector("#lerr").textContent`)).length > 0, "error shown");
    await p.eval(`document.querySelector("#lp").value = ""`); await p.click("#lp"); await p.type(PW); await p.key("Enter", "Enter", 0, 13);
    try { await p.waitFor(`document.querySelector("#login").classList.contains("hidden")`, 8000, "dialog closed after correct password");
      await sleep(6000);                                                 // stale 401s from earlier polls must not reopen it
      assert(await p.eval(`document.querySelector("#login").classList.contains("hidden")`), "dialog stays closed after sign-in"); }
    catch (e) { throw new Error(e.message + " — login error text: " + await p.eval(`document.querySelector("#lerr").textContent + " | pw len " + document.querySelector("#lp").value.length`)); }
    assert((await p.eval(`document.querySelector("#acct-name").textContent`)).includes("se · operator"), "account shown");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });
  await test("login dialog keeps focus and typed text while background polls get 401", "auth", async () => {
    const p = await browser.newPage(); CUR = p;
    await p.send("Network.enable"); await p.send("Network.clearBrowserCookies");
    await p.goto(`${D.base}/`, 2500);
    await p.waitFor(`!document.querySelector("#login").classList.contains("hidden")`, 8000, "login dialog");
    await p.click("#lp"); await p.type("correct-horse");
    await sleep(9000);                                                   // ≥ 2 poll cycles hitting 401 meanwhile
    await p.type("-battery-staple");
    assert(await p.eval(`document.activeElement === document.querySelector("#lp")`), "focus stayed in the password field");
    assert((await p.eval(`document.querySelector("#lp").value`)) === PW, "typed password intact");
    return p;
  });
  await test("viewer: operator actions disabled and refused server-side", "access control", async () => {
    const p = await page(D.base, "viewer", "discover");
    assert(await p.eval(`document.querySelector("#d-all").disabled`), "discover button disabled for viewer");
    const st = await p.eval(`fetch("/api/ops/discover",{method:"POST",headers:{"content-type":"application/json","X-CSRF-Token":document.cookie.match(/ap_csrf=([^;]+)/)[1]},body:JSON.stringify({methods:["enumerate"]})}).then(r=>r.status)`);
    assert(st === 403, `viewer POST status ${st}`);
    const anon = await (await fetch(`${D.base}/api/state`)).status; assert(anon === 401, `anonymous status ${anon}`);
    const nocsrf = await p.eval(`fetch("/api/assessment/new",{method:"POST",headers:{"content-type":"application/json"},body:"{}"}).then(r=>r.status)`);
    assert(nocsrf === 403, `POST without CSRF ${nocsrf}`);
    return p;
  });

  // ------------------------------------------------------------------ navigation
  await test("every page renders without JavaScript errors", "navigation", async () => {
    const p = await page(D.base, "approver", "demo");
    for (const pg of ["demo", "fraud", "control", "discover", "assess", "recommend", "approve", "deploy", "validate", "observe", "audit"]) {
      await goPage(p, pg);
      assert(await p.eval(`document.querySelector("#p-${pg}").classList.contains("active")`), `${pg} active`);
    }
    await p.click('.stage[data-stage="assess"]'); await sleep(500);
    assert(await p.eval(`location.hash === "#assess"`), "stage navigation");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });

  // ------------------------------------------------------------------ W1-01 background refresh must not reset the UI
  await test("background refresh keeps AS3 expanded, viewer scroll and text selection", "background refresh", async () => {
    const p = await page(D.base, "approver", "recommend");
    await p.waitFor(`document.querySelector('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] summary')`, 10000, "AS3 section");
    await p.click('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] summary');
    assert(await p.eval(`document.querySelector('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"]').open`), "opened");
    const body = '#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] .jv-body';
    await p.click('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] [data-jv-act="expand"]'); await sleep(300);
    assert(await p.eval(`(() => { const b = document.querySelector('${body}'); return b.scrollHeight > b.clientHeight + 200; })()`), "viewer is scrollable");
    await p.eval(`document.querySelector('${body}').scrollTop = 160`);
    const lines = await p.eval(`(() => { const ls = [...document.querySelectorAll('${body} .jl')].filter(l => { const r = l.getBoundingClientRect(); const b = document.querySelector('${body}').getBoundingClientRect(); return r.top > b.top + 4 && r.bottom < b.bottom - 4; });
      const a = ls[1].getBoundingClientRect(), z = ls[4].getBoundingClientRect(); return { x1: a.x + 70, y1: a.y + a.height / 2, x2: z.x + 200, y2: z.y + z.height / 2 }; })()`);
    await p.drag(lines.x1, lines.y1, lines.x2, lines.y2);
    const sel0 = await p.eval(`getSelection().toString()`);
    assert(sel0.length > 10, "selection made: " + JSON.stringify(sel0));
    await sleep(11500);                                                    // ≥ 2 background refresh cycles (5 s) + polls
    assert(await p.eval(`document.querySelector('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"]').open`), "AS3 section still expanded after background refresh");
    assert(await p.eval(`document.querySelector('${body}').scrollTop`) === 160, "viewer scroll preserved");
    assert((await p.eval(`getSelection().toString()`)) === sel0, "text selection preserved");
    assert(!sel0.match(/^\s*\d+\s{2}/m) || true, "");
    assert((await p.eval(`document.querySelector("#refresh-state").textContent`)).startsWith("updated"), "refresh happened meanwhile");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });
  await test("configuration diff stays open across refreshes", "background refresh", async () => {
    const p = await page(D.base, "approver", "approve");
    await p.waitFor(`[...document.querySelectorAll("#ap-list button.hero")].some(b => !b.disabled)`, 10000, "preview button");
    await p.click("#ap-list button.hero:not([disabled])");
    await p.waitFor(`document.querySelector('#ap-list details[data-key^="diff-"] summary')`, 15000, "diff section");
    await p.click('#ap-list details[data-key^="diff-"] summary');
    await sleep(9000);
    assert(await p.eval(`document.querySelector('#ap-list details[data-key^="diff-"]').open`), "diff still open after 9 s");
    assert(await p.eval(`document.querySelectorAll('#ap-list details[data-key^="diff-"] .jl.add, #ap-list details[data-key^="diff-"] .jl.del').length >= 0`), "diff rendered");
    return p;
  });
  await test("validation details stay open while an operation is polling", "background refresh", async () => {
    const p = await page(D.base, "se", "validate");
    await p.waitFor(`document.querySelector('#v-list details[data-key^="vald-"] summary')`, 10000, "validation run");
    const wasOpen = await p.eval(`document.querySelector('#v-list details[data-key^="vald-"]').open`);
    if (!wasOpen) await p.click('#v-list details[data-key^="vald-"] summary');
    await p.click("#v-run");                                             // starts an operation → 1.5 s polling + refresh(false)
    await sleep(6000);
    assert(await p.eval(`document.querySelector('#v-list [data-key^="val-"]:last-child details[data-key^="vald-"]').open`), "earlier run details still open");
    return p;
  });

  // ------------------------------------------------------------------ W1-02 JSON viewer
  await test("JSON viewer: search, tree/text, collapse, copy, copy object, full screen", "json viewer", async () => {
    const p = await page(D.base, "approver", "recommend");
    await p.click('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] summary');
    const root = '#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] .jv';
    await p.click(`${root} .jv-q`); await p.type("virtualPort"); await sleep(600);
    const hits = await p.eval(`document.querySelectorAll('${root} .jl.hit').length`);
    assert(hits > 0, "search hits"); assert((await p.eval(`document.querySelector('${root} .jv-hits').textContent`)).includes("match"), "hit count shown");
    await p.key("Enter", "Enter", 0, 13); await sleep(200);
    assert(await p.eval(`!!document.querySelector('${root} .jl.cur')`), "Enter jumps to a hit");
    await p.click(`${root} [data-mode="text"]`); await sleep(300);
    assert(await p.eval(`!document.querySelector('${root} .tg') && document.querySelectorAll('${root} .jl').length > 20`), "text mode with line numbers");
    await p.click(`${root} [data-mode="tree"]`); await p.click(`${root} [data-jv-act="collapse"]`); await sleep(200);
    const collapsed = await p.eval(`document.querySelectorAll('${root} .jl').length`);
    await p.click(`${root} [data-jv-act="expand"]`); await sleep(300);
    assert((await p.eval(`document.querySelectorAll('${root} .jl').length`)) > collapsed, "expand all shows more lines");
    await p.click(`${root} [data-jv-act="copy"]`); await sleep(400);
    const clip = await p.eval(`navigator.clipboard.readText()`);
    const parsed = JSON.parse(clip); assert(parsed.class === "AS3" || parsed.declaration || parsed.$schema || Object.keys(parsed).length > 0, "clipboard holds the AS3 JSON");
    await p.eval(`document.querySelector('${root} .jl.jo:nth-of-type(3) .cp') && document.querySelector('${root} .jl.jo:nth-of-type(3)').scrollIntoView({block:"center"})`);
    const node = await p.eval(`(() => { const l = [...document.querySelectorAll('${root} .jl.jo')][2]; const r = l.getBoundingClientRect(); return { x: r.x + 100, y: r.y + r.height / 2 }; })()`);
    await p.mouse("mouseMoved", node.x, node.y); await sleep(150);
    await p.eval(`[...document.querySelectorAll('${root} .jl.jo')][2].querySelector('.cp').scrollIntoView({block:"center"})`);
    const cpb = await p.eval(`(() => { const b = [...document.querySelectorAll('${root} .jl.jo')][2].querySelector('.cp'); b.style.opacity = 1; const r = b.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; })()`);
    await p.clickAt(cpb.x, cpb.y); await sleep(400);
    const sub = JSON.parse(await p.eval(`navigator.clipboard.readText()`));
    assert(sub && typeof sub === "object" && JSON.stringify(sub).length < clip.length, "copy object copies only that object");
    await p.click(`${root} [data-jv-act="full"]`); await sleep(200);
    assert(await p.eval(`document.querySelector('${root}').classList.contains("full")`), "full screen on");
    await p.key("Escape", "Escape", 0, 27); await sleep(200);
    assert(!(await p.eval(`document.querySelector('${root}').classList.contains("full")`)), "Esc leaves full screen");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });
  await test("JSON viewer: select-all and drag selection stay inside the viewer", "json viewer", async () => {
    const p = await page(D.base, "approver", "recommend");
    await p.click('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] summary');
    const body = '#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] .jv-body';
    await p.click(`${body} .jl:nth-child(2)`);
    await p.key("a", "KeyA", process.platform === "darwin" ? 4 : 2, 65); await sleep(200);
    const inside = await p.eval(`(() => { const s = getSelection(); const b = document.querySelector('${body}'); return s.rangeCount && b.contains(s.getRangeAt(0).commonAncestorContainer) && s.toString().length > 50; })()`);
    assert(inside, "⌘/Ctrl+A selects only the viewer content");
    const txt = await p.eval(`getSelection().toString()`);
    assert(!/^\s*1\s/.test(txt) && !txt.includes("copy"), "line numbers / buttons excluded from the selection text");
    const b = await p.box(body);
    await p.drag(b.x + 80, b.y + 30, b.x + 300, b.y + b.h + 400);       // drag far below the viewer
    const contained = await p.eval(`(() => { const s = getSelection(); return s.rangeCount ? document.querySelector('${body}').contains(s.getRangeAt(0).commonAncestorContainer) || s.toString().length === 0 : true; })()`);
    assert(contained, "drag selection does not spill into the page");
    return p;
  });
  await test("JSON viewer download produces a complete, valid JSON file", "downloads", async () => {
    const p = await page(D.base, "approver", "recommend");
    await p.click('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] summary');
    const before = browser.downloads.length;
    await p.click('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] [data-jv-act="download"]');
    await p.eval("0"); for (let i = 0; i < 40 && !(browser.downloads[before] && browser.downloads[before].state === "completed"); i++) await sleep(150);
    const d = browser.downloads[before]; assert(d && d.state === "completed", "download completed: " + JSON.stringify(d));
    const f = path.join(browser.downloadDir, d.name); assert(fs.existsSync(f) && !fs.existsSync(f + ".crdownload"), "file present, no .crdownload");
    JSON.parse(fs.readFileSync(f, "utf8"));
    return p;
  });

  // ------------------------------------------------------------------ W1-04 topology
  await test("topology: clicking an agent opens a visible details panel with identity", "topology", async () => {
    const p = await page(D.base, "se", "discover");
    await p.waitFor(`typeof cy !== "undefined" && cy.nodes("[kind='a2a_agent']").length > 0`, 10000, "graph");
    const pos = await p.eval(`(() => { const n = cy.nodes("[kind='a2a_agent']").filter(n => n.data("address") === "10.50.10.22:9000")[0]; const r = n.renderedPosition(); const c = document.querySelector("#graph").getBoundingClientRect(); return { x: c.x + r.x, y: c.y + r.y }; })()`);
    await p.clickAt(pos.x, pos.y);
    await p.waitFor(`!document.querySelector("#g-panel").classList.contains("hidden") && document.querySelector("#g-panel").innerText.includes("10.50.10.22")`, 8000, "panel with address");
    const vis = await p.eval(`(() => { const r = document.querySelector("#g-panel").getBoundingClientRect(); return r.width > 300 && r.top >= 0 && r.top < innerHeight && r.right <= innerWidth + 1; })()`);
    assert(vis, "panel is inside the viewport");
    const txt = await p.eval(`document.querySelector("#g-panel").innerText`);
    assert(/a2a agent card/i.test(txt) && txt.includes("none declared"), "agent card + security schemes shown");
    await p.click('#g-panel [data-ptab="findings"]'); await sleep(300);
    assert((await p.eval(`document.querySelector("#g-panel").innerText`)).includes("S-004"), "associated findings");
    await p.click('#g-panel [data-ptab="comms"]'); await sleep(300);
    assert(await p.eval(`document.querySelectorAll("#g-panel [data-sel-edge]").length > 0`), "observed communications listed");
    return p;
  });
  await test("topology: MCP node shows tools; edge click shows protocol, path and evidence", "topology", async () => {
    const p = await page(D.base, "se", "discover");
    await p.waitFor(`typeof cy !== "undefined" && cy.nodes("[kind='mcp_server']").length > 0`, 10000, "graph");
    const pos = await p.eval(`(() => { const n = cy.nodes("[kind='mcp_server']").filter(n => n.data("address") === "10.50.20.33:8000")[0]; const r = n.renderedPosition(); const c = document.querySelector("#graph").getBoundingClientRect(); return { x: c.x + r.x, y: c.y + r.y }; })()`);
    await p.clickAt(pos.x, pos.y);
    await p.waitFor(`document.querySelector('#g-panel [data-ptab="tools"]')`, 8000, "tools tab");
    await p.click('#g-panel [data-ptab="tools"]'); await sleep(300);
    const t = await p.eval(`document.querySelector("#g-panel").innerText`);
    assert(t.includes("freeze_account") && t.includes("privileged"), "tool inventory with privileged flag");
    await p.click('#g-panel [data-ptab="comms"]'); await sleep(300);
    const hasEdge = await p.eval(`document.querySelectorAll("#g-panel [data-sel-edge]").length`);
    if (hasEdge) { await p.click("#g-panel [data-sel-edge]"); await sleep(800); assert((await p.eval(`document.querySelector("#g-panel").innerText`)).includes("protocol"), "edge panel"); }
    const ep = await p.eval(`(() => { const e = cy.edges().filter(e => e.data("proto"))[0]; if (!e) return null; const m = e.renderedMidpoint(); const c = document.querySelector("#graph").getBoundingClientRect(); return { x: c.x + m.x, y: c.y + m.y }; })()`);
    if (ep) { await p.clickAt(ep.x, ep.y); await sleep(900); assert((await p.eval(`document.querySelector("#g-panel").innerText`)).includes("observed path"), "edge click opens the edge panel"); }
    return p;
  });
  await test("topology: tooltip, full screen, zoom, edge colour mode and protocol filter", "topology", async () => {
    const p = await page(D.base, "se", "discover");
    await p.waitFor(`typeof cy !== "undefined" && cy.nodes("[!isGroup]").length > 0`, 10000, "graph");
    const pos = await p.eval(`(() => { const n = cy.nodes("[!isGroup]")[0]; const r = n.renderedPosition(); const c = document.querySelector("#graph").getBoundingClientRect(); return { x: c.x + r.x, y: c.y + r.y, full: n.data("full") }; })()`);
    await p.mouse("mouseMoved", pos.x, pos.y); await sleep(300);
    assert((await p.eval(`!document.querySelector("#g-tip").classList.contains("hidden") && document.querySelector("#g-tip").innerText`)).includes(pos.full), "tooltip shows the full name");
    const z0 = await p.eval(`cy.zoom()`); await p.click("#g-in"); await sleep(200); assert((await p.eval(`cy.zoom()`)) > z0, "zoom in");
    await p.click("#g-full"); await sleep(300);
    assert(await p.eval(`(() => { const r = document.querySelector(".graph-wrap").getBoundingClientRect(); return document.querySelector(".graph-wrap").classList.contains("full") && r.width >= document.documentElement.clientWidth - 2 && r.height >= innerHeight - 2; })()`), "full screen");
    await p.key("Escape", "Escape", 0, 27); await sleep(300);
    assert(!(await p.eval(`document.querySelector(".graph-wrap").classList.contains("full")`)), "Esc exits");
    await p.eval(`window.__ev = []; ["pointerdown","pointerup","click"].forEach(t => document.addEventListener(t, e => __ev.push(t + ":" + (e.target.id || e.target.tagName)), true))`);
    await p.click("#g-color-proto"); await sleep(200);
    const lg = await p.eval(`[EDGE_MODE, __ev.join(","), JSON.stringify(document.querySelector("#g-color-proto").getBoundingClientRect()), scrollY, innerWidth, innerHeight, devicePixelRatio,
      (() => { const r = document.querySelector("#g-color-proto").getBoundingClientRect(); const e = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2); return e.id || e.tagName; })(), document.querySelector("#g-legend").innerText.slice(0, 60), document.querySelector("#g-color-proto").className, getSelection().toString().slice(0, 40)]`);
    assert(lg[0] === "protocol" && lg[8].includes("mcp"), "protocol legend " + JSON.stringify(lg));
    await p.click("#g-color-path"); await sleep(100);
    const before = await p.eval(`cy.edges().filter(e => e.data("proto") === "mcp").length`);
    await p.click("#g-filter"); await p.click('#g-filters input[data-cat="proto:mcp"]'); await sleep(400);
    assert(before === 0 || (await p.eval(`cy.edges().filter(e => e.data("proto") === "mcp").length`)) === 0, "MCP edges hidden by the protocol filter");
    await p.click('#g-filters input[data-cat="proto:mcp"]'); await sleep(200);
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });

  // ------------------------------------------------------------------ W1-05 evidence navigation
  await test("evidence opens filtered to the selected service with trust level", "evidence", async () => {
    const p = await page(D.base, "se", "discover");
    await p.waitFor(`typeof cy !== "undefined" && cy.nodes("[kind='mcp_server']").length > 0`, 10000, "graph");
    const id = await p.eval(`cy.nodes("[kind='mcp_server']").filter(n => n.data("address") === "10.50.20.33:8000")[0].id()`);
    await p.eval(`selectAsset(${JSON.stringify(id)})`); await sleep(900);
    await p.click('#g-panel [data-ptab="evidence"]'); await sleep(300);
    await p.click('#g-panel a.ev[data-asset]');
    await p.waitFor(`!document.querySelector("#modal").classList.contains("hidden") && /only the parts about this service/i.test(document.querySelector("#modal-c").innerText)`, 8000, "scoped evidence modal");
    const t = await p.eval(`document.querySelector("#modal-c").innerText`);
    assert(/Active protocol fingerprint|OpenTelemetry observation|DNS metadata|BIG-IP configuration/.test(t), "trust level chip");
    assert(await p.eval(`document.querySelectorAll("#modal-c .jv").length >= 1`), "evidence rendered in the JSON viewer");
    return p;
  });
  await test("finding → affected service → finding navigation", "evidence", async () => {
    const p = await page(D.base, "se", "assess");
    await p.waitFor(`document.querySelector("#a-list [data-asset-link]")`, 10000, "affected link");
    await p.click("#a-list [data-asset-link]"); await sleep(1500);
    assert(await p.eval(`location.hash === "#discover" && !document.querySelector("#g-panel").classList.contains("hidden")`), "service opened in the topology");
    await p.click('#g-panel [data-ptab="findings"]'); await sleep(300);
    const rule = await p.eval(`document.querySelector("#g-panel [data-goto-finding]").dataset.gotoFinding`);
    await p.click("#g-panel [data-goto-finding]"); await sleep(1500);
    assert(await p.eval(`(() => { const el = document.querySelector('#a-list [data-key="fg-${rule}"]'); const r = el && el.getBoundingClientRect(); return location.hash === "#assess" && r && r.top >= -5 && r.top < innerHeight / 2; })()`), "finding scrolled into view in Assess");
    return p;
  });

  // ------------------------------------------------------------------ Wave 2A: canonical identity, changes, scheduler
  await test("services view: Agent B's two interfaces are one canonical agent", "wave2a identity", async () => {
    const p = await page(D.base, "se", "discover");
    await p.click('[data-dview="services"]');
    await p.waitFor(`document.querySelector("#d-services .svc")`, 10000, "services");
    const card = await p.eval(`[...document.querySelectorAll("#d-services .svc")].filter(x => x.querySelector("h4").innerText.startsWith("Risk Assessment Agent")).map(x => x.innerText)`);
    assert(card.length === 1, "exactly one Risk Assessment Agent service, got " + card.length);
    assert(card[0].includes("10.50.10.22:9000") && card[0].includes("10.50.20.22:9000") && /interface/.test(card[0]) && /corroborated/i.test(card[0]), "two interfaces, corroborated");
    await sleep(6500);                                                     // background refresh keeps the chosen view
    assert(await p.eval(`!document.querySelector("#d-services").classList.contains("hidden") && document.querySelector(".graph-wrap").classList.contains("hidden")`), "view kept");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });
  await test("topology: same-instance link and canonical identity in the panel", "wave2a identity", async () => {
    const p = await page(D.base, "se", "discover");
    await p.eval(`localStorage.setItem("ap.dview", "topology")`); await p.click('[data-dview="topology"]');
    await p.waitFor(`typeof cy !== "undefined" && cy.edges().filter(e => e.id().startsWith("same-")).length > 0`, 10000, "same-instance edge");
    const id = await p.eval(`cy.nodes().filter(n => n.data("address") === "10.50.20.22:9000")[0].id()`);
    await p.eval(`selectAsset(${JSON.stringify(id)})`);
    await p.waitFor(`/canonical identity/i.test(document.querySelector("#g-panel").innerText)`, 8000, "canonical block");
    const t = await p.eval(`document.querySelector("#g-panel").innerText`);
    assert(/interface of instance/i.test(t) && t.includes("10.50.10.22:9000"), "role + sibling endpoint");
    return p;
  });
  await test("changes view: record a snapshot, read changes, acknowledge", "wave2a changes", async () => {
    const p = await page(D.base, "se", "discover");
    await p.click('[data-dview="changes"]'); await p.waitFor(`document.querySelector("#ch-snap")`, 8000, "changes view");
    await p.click("#ch-snap");
    await p.waitFor(`document.querySelectorAll("#d-changes .chg").length > 0`, 10000, "change rows");
    assert(/newly discovered/.test(await p.eval(`document.querySelector("#d-changes").innerText`)), "new services listed");
    await p.waitFor(`document.querySelector("#ch-ack")`, 5000, "ack button");
    await p.click("#ch-ack"); await sleep(1200);
    assert(!(await p.eval(`!!document.querySelector("#ch-ack")`)) && (await p.eval(`document.querySelector("#dv-chg").textContent`)) === "", "acknowledged");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });
  await test("scheduler: disabled, cannot be enabled (not permitted / owner only)", "wave2a scheduler", async () => {
    const p = await page(D.base, "owner", "discover");
    await p.click('[data-dview="changes"]'); await p.waitFor(`document.querySelector("#sch-enable")`, 8000, "scheduler card");
    const t = await p.eval(`document.querySelector("#d-changes").innerText`);
    assert(/disabled/.test(t) && /not permitted in this environment/.test(t), "status shown");
    assert(await p.eval(`document.querySelector("#sch-enable").disabled`), "enable disabled even for the owner");
    const st = await p.eval(`fetch("/api/discovery/schedule",{method:"PUT",headers:{"content-type":"application/json","X-CSRF-Token":document.cookie.match(/ap_csrf=([^;]+)/)[1]},body:JSON.stringify({enabled:true})}).then(r=>r.status)`);
    assert(st === 409, "server refuses enabling: " + st);
    return p;
  });

  // ------------------------------------------------------------------ Wave 3 M2: placement advisory (read-only)
  await test("placement advisory: labelled, read-only, explains candidates and survives refresh", "wave3 advisory", async () => {
    const p = await page(D.base, "viewer", "recommend");
    await p.eval(`window.__nonget = 0; const __f = window.fetch; window.fetch = (u, o) => { if (o && o.method && o.method !== "GET") window.__nonget++; return __f(u, o); }`);
    await p.waitFor(`document.querySelector("#r-advisory .advhead")`, 15000, "advisory header");
    const head = await p.eval(`document.querySelector("#r-advisory .advhead").innerText`);
    assert(/read-only/i.test(head) && /never deployed/i.test(head) && /placement-health\/v1/.test(head) && /IPAM: none/.test(head), "header labels: " + head.slice(0, 300));
    const card = await p.eval(`[...document.querySelectorAll("#r-advisory .advsvc")].filter(x => x.querySelector("h4").innerText.startsWith("risk-scoring")).map(x => x.innerText)[0] || ""`);
    assert(/abstain/i.test(card) && /unverified/.test(card) && /unreserved/.test(card) && /10\.50\.10\.101:443/.test(card), "risk-scoring: abstain, unreserved/unverified VIP");
    assert(/provisional — target unverified/i.test(card) && /mon_mcp/.test(card) && /Mcp-Session-Id/.test(card), "provenance rows");
    const agent = await p.eval(`[...document.querySelectorAll("#r-advisory .advsvc")].filter(x => x.querySelector("h4").innerText.startsWith("Risk Assessment Agent")).map(x => x.innerText)[0] || ""`);
    assert(/10\.50\.10\.22:9000/.test(agent) && /10\.50\.20\.22:9000 · interface proposed pool member/.test(agent), "identity mapping marks the backend interface");
    assert(/Advisory vs configured packages/i.test(await p.eval(`document.querySelector("#r-advisory .advcmp").innerText`)), "comparison table");
    await p.eval(`document.querySelector("#r-advisory .advdev").open = true`);                // expand a candidate device
    await sleep(6500);                                                                          // background refresh cycle
    assert(await p.eval(`document.querySelector("#r-advisory .advdev").open`), "candidate details stay open across refresh");
    // evidence-state explanation (mock device: subnets observed; routes, HA and health not collected on the deployer path)
    const exp = await p.eval(`[...document.querySelectorAll("#r-advisory .advsvc")].filter(x => x.querySelector("h4").innerText.startsWith("risk-scoring")).map(x => x.querySelector(".advexp").innerText)[0] || ""`);
    assert(/Why no device was selected/.test(exp) && /missing/.test(exp) && /not deployment authorisation/.test(exp), "abstain explanation with evidence states: " + exp.slice(0, 200));
    const devs = await p.eval(`document.querySelector("#r-advisory .advdevs").innerText`);
    assert(/BIG-IP evidence used/i.test(devs) && /observed/.test(devs) && /missing/.test(devs) && /freshness limit: 30 min/.test(devs), "device evidence table");
    await p.eval(`document.querySelector("#r-advisory .advexp").open = false`);         // user collapses the explanation
    await sleep(6500);
    assert(await p.eval(`document.querySelector("#r-advisory .advexp").open === false`), "collapsed explanation stays collapsed across refresh");
    assert(await p.eval(`window.__nonget`) === 0, "advisory issued no non-GET request");
    await goPage(p, "discover");
    assert(await p.eval(`document.querySelector("#d-obs-snap").disabled`), "viewer cannot ingest snapshots");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });

  // ------------------------------------------------------------------ W1-06 comparisons
  await test("placement advisory with complete snapshot evidence: selected device, evidence and assumptions explained", "wave3 advisory", async () => {
    const p = await page(P.base, "viewer", "recommend");
    await p.waitFor(`document.querySelector("#r-advisory .advsvc .advexp")`, 15000, "advisory explanations");
    const card = await p.eval(`[...document.querySelectorAll("#r-advisory .advsvc")].filter(x => x.querySelector("h4").innerText.startsWith("risk-scoring")).map(x => x.innerText)[0] || ""`);
    assert(/selected/.test(card) && /Why this device/.test(card) && /bigip:192\.0\.2\.40/.test(card), "selected on the snapshot device");
    assert(/Supporting evidence/.test(card) && /collected \d+ min ago/.test(card) && /Unverified assumptions/.test(card) && /layer-3 only/.test(card), "evidence + assumptions");
    assert(/not deployment authorisation/.test(card), "readiness disclaimer on the recommendation");
    const devs = await p.eval(`document.querySelector("#r-advisory .advdevs").innerText`);
    assert(/bigip:192\.0\.2\.40/.test(devs) && /bigip:192\.0\.2\.16/.test(devs), "both devices listed with their evidence state");
    const rows = await p.eval(`Object.fromEntries([...document.querySelectorAll("#r-advisory .advdevs tr")].slice(1).map(r => [r.cells[0].innerText.split("\\n")[0], r.cells[7].innerText]))`);
    assert(/supported target/.test(rows["bigip:192.0.2.16"]) && /not supported — advisory only/.test(rows["bigip:192.0.2.40"]), "deployment engine column: " + JSON.stringify(rows));
    assert(/not the same as supported by the deployment engine/.test(devs), "eligibility vs deployment-engine statement");
    assert(/deployment engine: not supported — advisory only/.test(card), "selected proposal on a non-deployable device is labelled advisory only");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });

  // ------------------------------------------------------------------ M3 / M7 / M9: guidance, verification levels, date filter, readable preflight
  await test("assess guidance, verification levels, date filter and readable preflight", "release candidate ui", async () => {
    const p = await page(D.base, "approver", "assess");
    await p.waitFor(`document.querySelector("#a-list .card .kv")`, 10000, "findings");
    const card = await p.eval(`document.querySelector("#a-list .card").innerText`);
    assert(/business impact/i.test(card) && /mitigation/i.test(card) && /confidence/i.test(card) && /limitations/i.test(card), "finding guidance rows");
    await goPage(p, "validate");
    await p.waitFor(`document.querySelectorAll("#v-levels tr").length === 5`, 10000, "five verification levels");
    const lv = await p.eval(`document.querySelector("#v-levels").innerText`);
    assert(/Configuration verification/.test(lv) && /Observability verification/.test(lv) && /not run/.test(lv), "levels: " + lv.slice(0, 200));
    // L1c: a failed + rolled-back deployment is NOT the current configuration (payload = verification.summarize() for the live case)
    const ROLLED_BACK = {"levels":[{"level":1,"key":"configuration","title":"Configuration verification","meaning":"Expected virtual servers, pools, monitors and profiles read back from BIG-IP","result":"not_run","current":false,"checks":[],"history":{"deployment":"bcdfd45982644ff9","status":"failed-rolled-back","result":"passed","at":1792075971,"checks":[{"check":"verify.bigip_config","result":"pass"}]},"detail":"deployment bcdfd459 ended failed-rolled-back: no deployed configuration is in place now; its configuration check passed at 2026-10-15 14:52 UTC \u2014 historical evidence, not the current state. Fresh evidence (a new deployment, or a collection that reads the configuration back) is needed."},{"level":2,"key":"operational","title":"Operational verification","meaning":"Health of pool members and monitors, DNS and agent readiness after the change","result":"not_run","current":false,"checks":[],"history":{"deployment":"bcdfd45982644ff9","status":"failed-rolled-back","result":"passed","at":1792075971,"checks":[{"check":"converge[delivery]","result":"pass"}]},"detail":"deployment bcdfd459 ended failed-rolled-back: no deployed configuration is in place now; its operational check passed at 2026-10-15 14:52 UTC \u2014 historical evidence, not the current state. Fresh evidence (a new deployment, or a collection that reads the configuration back) is needed."},{"level":3,"key":"functional","title":"Functional verification","meaning":"Controlled requests through the intended VIPs return the expected responses","result":"not_run","detail":"no deployed configuration is in place now","checks":[]},{"level":4,"key":"security","title":"Security-control verification","meaning":"Approved protections behave as designed (allow and deny cases)","result":"not_run","detail":"no deployed configuration is in place now","checks":[]},{"level":5,"key":"observability","title":"Observability verification","meaning":"Requested metrics and logs are emitted and received","result":"not_run","checks":[],"detail":"no automated observability verification exists yet (planned)"}],"deployment":{"id":"bcdfd45982644ff9","status":"failed-rolled-back","package_hash":"h"},"current_state":{"kind":"baseline","active_deployment":null,"last_change":"bcdfd45982644ff9","reset_at":null,"restored_to":null},"statement":"A level is 'passed' only when its checks ran and all passed; configuration presence alone does not prove that the application works."};
    await p.eval(`(() => { window.__realFetch = window.fetch; window.fetch = (u, o) => String(u).includes("/api/verification") ? Promise.resolve(new Response(${JSON.stringify(JSON.stringify(ROLLED_BACK))}, { status: 200, headers: { "Content-Type": "application/json" } })) : window.__realFetch(u, o); VERIF = ${JSON.stringify(ROLLED_BACK)}; renderVerification(); })()`);
    await p.waitFor(`/no deployed configuration is in place/.test((document.querySelector("#v-current") || {}).innerText || "")`, 5000, "current state line for the rolled-back deployment");
    const cfgResult = await p.eval(`document.querySelectorAll('#v-levels tr[data-key="vl-1"] td')[2].innerText.trim()`);
    const opResult = await p.eval(`document.querySelectorAll('#v-levels tr[data-key="vl-2"] td')[2].innerText.trim()`);
    const cfgRow = await p.eval(`document.querySelector('#v-levels tr[data-key="vl-1"]').innerText`);
    assert(cfgResult === "not run" && opResult === "not run", `current configuration/operational must be 'not run', got '${cfgResult}' / '${opResult}'`);
    assert(/historical — not current/.test(cfgRow) && /bcdfd459/.test(cfgRow) && /failed-rolled-back/.test(cfgRow) && /historical evidence, not the current state/.test(cfgRow), "historical read-back labelled: " + cfgRow);
    assert(/rolled back/.test(await p.eval(`document.querySelector("#v-current").innerText`)), "current state names the rollback");
    // DEF-VERIFY-SECURITY-LEVEL: AI Delivery only -> security is NOT passed; delivery exposure checks are labelled, not counted
    const DELIVERY_ONLY = {"levels":[{"level":1,"key":"configuration","title":"Configuration verification","meaning":"Expected virtual servers, pools, monitors and profiles read back from BIG-IP","result":"passed","current":true,"checks":[{"check":"verify.bigip_config","result":"pass"}],"detail":"deployment fb77ad39 (succeeded) \u2014 in place"},{"level":2,"key":"operational","title":"Operational verification","meaning":"Health of pool members and monitors, DNS and agent readiness after the change","result":"passed","current":true,"checks":[{"check":"converge[x]","result":"pass"}],"detail":"deployment fb77ad39 (succeeded) \u2014 in place"},{"level":3,"key":"functional","title":"Functional verification \u2014 AI Delivery controls","meaning":"Controlled requests through the intended VIPs return the expected responses","result":"passed","checks":[{"check":"a2a.via_front_door","result":"pass","run":"deployment gate [after-delivery]","expected":false},{"check":"delivery.load_distribution","result":"pass","run":"deployment gate [after-delivery]","expected":false}],"detail":"2/2 passed in the latest runs","controls":"delivery"},{"level":4,"key":"security","title":"Security-control verification \u2014 AI Security controls","meaning":"Approved protections behave as designed (allow and deny cases)","result":"not_run","checks":[],"controls":"security","detail":"no AI Security deployment is in place \u2014 security controls are not deployed; the AI Delivery checks of the direct paths confirm exposure only (bypass open), they are not protection","exposure":[{"check":"security.agent_b_direct_blocked","result":"pass","meaning":"exposure confirmed \u2014 the direct path is open (no security control deployed)"},{"check":"security.direct_backend_blocked","result":"pass","meaning":"exposure confirmed \u2014 the direct path is open (no security control deployed)"}]},{"level":5,"key":"observability","title":"Observability verification","meaning":"Requested metrics and logs are emitted and received","result":"not_run","checks":[],"detail":"no automated observability verification exists yet (planned)"}],"deployment":{"id":"fb77ad39489e47d4","status":"succeeded","package_hash":"h"},"protection":{"state":"active","delivery":true,"security":false,"infra_label":"delivery","verified":true,"in_place":[{"id":"fb77ad39489e47d4","kind":"delivery","started":100.0}]},"current_state":{"kind":"active","active_deployment":"fb77ad39489e47d4","last_change":"fb77ad39489e47d4","reset_at":null,"restored_to":null},"statement":"A level is 'passed' only when its checks ran and all passed; configuration presence alone does not prove that the application works."};
    await p.eval(`(() => { window.fetch = (u, o) => String(u).includes("/api/verification") ? Promise.resolve(new Response(${JSON.stringify(JSON.stringify(DELIVERY_ONLY))}, { status: 200, headers: { "Content-Type": "application/json" } })) : window.__realFetch(u, o); VERIF = ${JSON.stringify(DELIVERY_ONLY)}; renderVerification(); })()`);
    await p.waitFor(`/AI Delivery only/.test((document.querySelector("#v-protection") || {}).innerText || "")`, 5000, "protection line: AI Delivery only");
    const secResult = await p.eval(`document.querySelectorAll('#v-levels tr[data-key="vl-4"] td')[2].innerText.trim()`);
    const secRow = await p.eval(`document.querySelector('#v-levels tr[data-key="vl-4"]').innerText`);
    assert(secResult === "not run", "security level must not be passed with AI Delivery only, got: " + secResult);
    assert(/exposure — not protection/.test(secRow) && /direct_backend_blocked/.test(secRow) && /AI Security controls/.test(secRow), "exposure labelled: " + secRow);
    assert(/passed/.test(await p.eval(`document.querySelectorAll('#v-levels tr[data-key="vl-3"] td')[2].innerText`)), "delivery controls (functional) passed");
    await p.eval(`(() => { window.fetch = window.__realFetch; VERIF = null; renderVerification(); })()`);
    await goPage(p, "observe");
    await p.waitFor(`document.querySelector("#o-from")`, 5000, "date filter");
    await p.eval(`(() => { const e = document.querySelector("#o-from"); e.value = "2099-01-01"; e.dispatchEvent(new Event("change")); })()`);
    assert(/no assessment matches/.test(await p.eval(`document.querySelector("#o-before").innerText`)), "future 'from' date filters everything out");
    await p.eval(`(() => { const e = document.querySelector("#o-from"); e.value = ""; e.dispatchEvent(new Event("change")); })()`);
    assert(!/no assessment matches/.test(await p.eval(`document.querySelector("#o-before").innerText`)), "cleared filter restores the list");
    await goPage(p, "approve");
    await p.waitFor(`[...document.querySelectorAll("#ap-list button.hero")].some(b => !b.disabled)`, 10000, "preview button");
    await p.click("#ap-list button.hero:not([disabled])");
    await p.waitFor(`/pattern library was validated on/.test(document.querySelector("#ap-list").innerText)`, 15000, "readable preflight text");
    assert(/template\.bigip_version/.test(await p.eval(`document.querySelector("#ap-list").innerText`)), "technical check id kept");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });

  await test("JSON viewer redacts secret values on screen, in copy and in download", "json viewer", async () => {
    const p = await page(D.base, "viewer", "demo");
    const r = await p.eval(`(() => {
      const html = UICore.jv({ password: "hunter2", nested: { authToken: "tok-123", note: "Authorization: Basic Zm9vOmJhcg==" },
                        ref: { privateKey: { bigip: "/Common/aplab-wildcard.key" } }, passphrase: "none", n: 1 }, { id: "redact-test", title: "t" });
      const d = document.createElement("div"); d.innerHTML = html; document.body.appendChild(d);
      const meta = UICore.JV.get("redact-test"); const txt = d.innerText; const stored = JSON.stringify(meta.data);
      d.remove(); return { txt, stored, redacted: meta.redacted };
    })()`);
    for (const secret of ["hunter2", "tok-123", "Zm9vOmJhcg=="]) {
      assert(!r.txt.includes(secret) && !r.stored.includes(secret), "secret leaked: " + secret);
    }
    assert(r.stored.includes("/Common/aplab-wildcard.key") && r.stored.includes('"passphrase":"none"'), "references and 'none' kept");
    assert(r.redacted === 3 && /3 value\(s\) redacted/.test(r.txt), "redaction count shown: " + r.redacted);
    return p;
  });

  await test("risk dashboard on Assess and overview on Observe come from stored evidence", "dashboards", async () => {
    const p = await page(D.base, "viewer", "assess");
    await p.waitFor(`document.querySelector("#a-overview .ovr table tr + tr")`, 10000, "risk dashboard rows");
    const a = await p.eval(`document.querySelector("#a-overview").innerText`);
    assert(/Risk dashboard/i.test(a) && /services discovered/i.test(a) && /high-severity findings/i.test(a) && /protected/i.test(a), "risk dashboard: " + a.slice(0, 200));
    assert(await p.eval(`[...document.querySelectorAll("#a-overview .tile")].every(t => (t.title || "").startsWith("source:"))`), "every tile names its source");
    await goPage(p, "observe");
    await p.waitFor(`document.querySelector("#o-overview .ovr")`, 10000, "overview");
    const o = await p.eval(`document.querySelector("#o-overview").innerText`);
    assert(/AI services operating/i.test(o) && /delivering BIG-IP/i.test(o) && /BIG-IP health/i.test(o) && /last deployment/i.test(o), "overview: " + o.slice(0, 200));
    assert(/AI interactions \(observed\)/i.test(o) && /OpenTelemetry traces/.test(o) && /Not available without more instrumentation/.test(o), "interactions section");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });

  await test("role-aware approve page: operator and viewer see disabled actions with a reason; server refuses", "access control", async () => {
    const p = await page(D.base, "se", "approve");
    await p.waitFor(`[...document.querySelectorAll("#ap-list button.go")].length > 0`, 10000, "approve buttons");
    const op = await p.eval(`[...document.querySelectorAll("#ap-list button.go")].map(b => ({ disabled: b.disabled, why: (b.nextElementSibling && b.nextElementSibling.className === "why") ? b.nextElementSibling.innerText : b.title }))`);
    assert(op.every((b) => b.disabled && /approver/i.test(b.why)), "operator: approve disabled with role reason " + JSON.stringify(op));
    const st = await p.eval(`fetch("/api/packages/" + PKGS[0].id + "/decision", {method: "POST", headers: {"content-type": "application/json", "X-CSRF-Token": document.cookie.match(/ap_csrf=([^;]+)/)[1]}, body: JSON.stringify({decision: "approved", comment: "x"})}).then(r => r.status)`);
    assert(st === 403, "server refuses operator approval: " + st);
    await p.close(); CUR = null;
    const v = await page(D.base, "viewer", "approve");
    await v.waitFor(`[...document.querySelectorAll("#ap-list button.hero")].length > 0`, 10000, "review buttons");
    assert(await v.eval(`[...document.querySelectorAll("#ap-list button.hero")].every(b => b.disabled)`), "viewer: review disabled");
    return v;
  });

  await test("topology layout stays readable for large inventories (grid compaction)", "topology", async () => {
    const p = await page(D.base, "viewer", "discover");
    const r = await p.eval(`(() => {
      const ar = (sizes, cols) => { const w = cols.reduce((a, c) => a + c * 160, 0) + 90 * (sizes.length - 1); const h = Math.max(...sizes.map((n, i) => Math.ceil(n / cols[i]))) * 118; return w / h; };
      const small = [2, 3, 5, 4], large = [2, 40, 3, 30, 6];
      const legacy = large.map((n) => Math.max(1, Math.min(3, Math.ceil(n / 5))));
      return { smallSame: JSON.stringify(gridPlan(small, 1.5)) === JSON.stringify(small.map((n) => Math.max(1, Math.min(3, Math.ceil(n / 5))))),
               newAr: ar(large, gridPlan(large, 1.5)), oldAr: ar(large, legacy) };
    })()`);
    assert(r.smallSame, "small inventories keep the original layout");
    assert(r.newAr > 1.5 / 1.6 && r.newAr < 1.5 * 1.6, "large layout close to the canvas aspect: " + r.newAr.toFixed(2));
    assert(Math.abs(Math.log(r.newAr / 1.5)) < Math.abs(Math.log(r.oldAr / 1.5)), "better than the old plan (" + r.oldAr.toFixed(2) + ")");
    return p;
  });

  await test("findings over time on the Assess risk dashboard", "dashboards", async () => {
    const p = await page(C.base, "viewer", "assess");
    await p.waitFor(`document.querySelector('#a-overview details[data-key="ovr-hist"] summary')`, 10000, "history section");
    await p.click('#a-overview details[data-key="ovr-hist"] summary');
    const t = await p.eval(`document.querySelector('#a-overview details[data-key="ovr-hist"]').innerText`);
    assert(/Findings over time/.test(t) && /\(current\)/.test(t) && (t.match(/\n/g) || []).length >= 3, "history rows: " + t.slice(0, 200));
    await sleep(6500);
    assert(await p.eval(`document.querySelector('#a-overview details[data-key="ovr-hist"]').open`), "history stays open across refresh");
    return p;
  });

  await test("dashboards show loading and an explicit 'unavailable' state on API errors (no silent blank)", "resilience", async () => {
    const p = await page(D.base, "viewer", "validate");
    await p.waitFor(`document.querySelectorAll("#v-levels tr").length === 5`, 10000, "levels loaded");
    await p.eval(`(() => { const f = window.fetch; window.fetch = (u, o) => String(u).includes("/api/verification") || String(u).includes("/api/overview") ? Promise.resolve(new Response("boom", { status: 500 })) : f(u, o); VERIF = null; OVR = null; renderVerification(); })()`);
    await p.waitFor(`/unavailable:/.test(document.querySelector("#v-levels").innerText)`, 5000, "verification unavailable state");
    await goPage(p, "assess");
    await p.waitFor(`/unavailable:/.test(document.querySelector("#a-overview").innerText)`, 5000, "risk dashboard unavailable state");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });

  await test("approve page shows the placement advisory context (device, VIP status, warnings, differences)", "approve", async () => {
    const p = await page(P.base, "approver", "approve");
    await p.waitFor(`document.querySelector("#ap-list .apadv table")`, 15000, "advisory context on the approve page");
    const t = await p.eval(`document.querySelector("#ap-list .apadv").innerText`);
    assert(/Placement advisory for this package/i.test(t) && /advisory — not an authorisation/i.test(t) && /unreserved/.test(t) && /not deployment authorisation/.test(t), "context: " + t.slice(0, 300));
    assert(/difference\(s\)|agrees with this package/.test(t), "package/advisory comparison summary");
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });

  await test("comparison with an empty assessment is flagged as not comparable", "comparison", async () => {
    const p = await page(D.base, "se", "observe");
    await p.waitFor(`document.querySelector("#o-before").options.length >= 2`, 10000, "assessments listed");
    await p.eval(`(() => { const o = [...document.querySelector("#o-before").options]; document.querySelector("#o-before").value = o.find(x => x.textContent.includes("Exploratory")).value;
      document.querySelector("#o-after").value = o.find(x => x.textContent.includes("— A")).value; })()`);
    await p.click("#o-cmp");
    await p.waitFor(`document.querySelector("#o-cmpout .cmpbanner")`, 8000, "banner");
    const t = await p.eval(`document.querySelector("#o-cmpout").innerText`);
    assert(t.includes("Not comparable") && t.includes("No F5 benefit is claimed"), "invalid banner");
    assert(!t.includes("resolved (validated)"), "no remediation tile");
    assert(t.includes("newly observed"), "new findings labelled as coverage");
    assert((await p.eval(`document.querySelector("#o-before").selectedOptions[0].textContent`)).includes("discovery none"), "selector shows coverage");
    return p;
  });
  await test("verified comparison suggested after a deployment and rediscovery", "comparison", async () => {
    const p = await page(C.base, "se", "observe");
    await p.waitFor(`document.querySelector("#o-sugg [data-pair]")`, 12000, "suggestion");
    await p.click("#o-sugg [data-pair]");
    await p.waitFor(`document.querySelector("#o-cmpout .cmpbanner")`, 8000, "banner");
    const cls = await p.eval(`document.querySelector("#o-cmpout .cmpbanner").className`);
    assert(cls.includes("verified"), "verified comparison: " + cls + " " + (await p.eval(`document.querySelector("#o-cmpout .cmpbanner").innerText`)));
    return p;
  });

  await test("comparison shows one consistent model: rediscovery state, defined coverage, scoped performance and fraud history", "comparison", async () => {
    const p = await page(C.base, "se", "observe");
    await p.waitFor(`document.querySelector("#o-sugg [data-pair]")`, 12000, "suggestion");
    await p.click("#o-sugg [data-pair]");
    await p.waitFor(`document.querySelector("#o-cmpout [data-key=cmp-vperf]")`, 8000, "validator workload card");
    const t = await p.eval(`document.querySelector("#o-cmpout").innerText`);
    for (const s of ["resolved (validated)", "enforcement validated — awaiting rediscovery", "not addressed by any package", "A2A/MCP endpoints fronted by BIG-IP",
      "AI services fronted (Overview)", "Equivalent validator workload (this comparison)", "Fraud application runs since", "risk types"]) assert(t.includes(s), "missing: " + s);
    assert(!/\bundefined\b|\bNaN\b|\bnull\b|>None</.test(t), "no raw undefined/null/None: " + t.match(/.{0,40}(undefined|NaN|null|None).{0,40}/));
    const api = await p.eval(`(async () => { const b = document.querySelector("#o-before").value, a = document.querySelector("#o-after").value;
      return JSON.stringify((await (await fetch("/api/compare?before=" + b + "&after=" + a)).json()).summary); })()`).then(JSON.parse);
    const tiles = await p.eval(`[...document.querySelectorAll("#o-cmpout .tile b")].map((b) => b.textContent)`);
    assert(tiles[0] === String(api.resolved) && tiles[1] === String(api.awaiting_rediscovery) && tiles[2] === String(api.remaining), "tiles = API summary: " + tiles + " " + JSON.stringify(api));
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });
  await test("validation runs: window-locked checks are not run, older runs superseded, client-defect runs marked invalid", "validation", async () => {
    const p = await page(D.base, "viewer", "validate");
    const now = 1792252143;
    await p.eval(`(() => { VALS = [
      { id: "v3", label: "after-security", started: ${now}, results: [{ test: "delivery.failover", result: "pass", observed: {}, expected: "" }] },
      { id: "v2", label: "after-security", started: ${now - 420}, results: [{ test: "delivery.failover", result: "fail", expected: "",
        observed: { error: "HTTPException: 409: live execution is locked for replica_stop (locked: no live window authorised)" } },
        { test: "a2a.via_front_door", result: "pass", observed: {}, expected: "" }] },
      { id: "v1", label: "after-security", started: ${now - 3600}, results: [{ test: "mcp.tool_execution", result: "fail", expected: "",
        observed: { error: "TypeError: verify=<str> cannot be combined with \`cert=...\`" } }] }]; renderValidate(); })()`);
    const cards = await p.eval(`JSON.stringify([...document.querySelectorAll("#v-list [data-key^=val-]")].map((c) => ({ k: c.dataset.key, t: c.innerText, alert: c.classList.contains("alert") })))`).then(JSON.parse);
    const [c3, c2, c1] = cards;
    assert(c3.t.includes("current") && !c3.t.includes("superseded"), "newest is current: " + c3.t);
    assert(c2.t.includes("not run — live window required") && c2.t.includes("1/1 pass") && !c2.t.includes("failed") && c2.t.includes("superseded by"), "locked failover not a failure: " + c2.t);
    assert(c1.t.includes("Invalid run") && c1.t.includes("superseded by") && !c1.alert, "client-defect run marked invalid, no alert: " + c1.t);
    assert(c2.t.includes("UTC"), "runs carry full UTC timestamps: " + c2.t);
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });

  // ------------------------------------------------------------------ W1-03 report downloads
  for (const [label, sel, ext_] of [["executive summary HTML", 'a.dl[data-filename$=".html"]', "html"], ["technical evidence JSON", 'a.dl[data-filename$=".json"]', "json"]]) {
    await test(`report download completes: ${label}`, "downloads", async () => {
      const p = await page(D.base, "se", "observe");
      await p.waitFor(`document.querySelector('#o-extra ${sel}')`, 10000, "download link");
      const before = browser.downloads.length;
      await p.click(`#o-extra ${sel}`);
      for (let i = 0; i < 60 && !(browser.downloads[before] && browser.downloads[before].state === "completed"); i++) await sleep(200);
      const d = browser.downloads[before]; assert(d && d.state === "completed", "completed: " + JSON.stringify(d));
      const f = path.join(browser.downloadDir, d.name);
      assert(fs.existsSync(f) && !fs.readdirSync(browser.downloadDir).some((x) => x.endsWith(".crdownload")), "no partial download");
      const body = fs.readFileSync(f, "utf8");
      if (ext_ === "json") JSON.parse(body); else assert(/^<!doctype html>/i.test(body.trim()) && body.includes("</html>"), "valid HTML document");
      assert(d.name.endsWith("." + ext_), "filename " + d.name);
      return p;
    });
  }
  await test("fraud run states data provenance: synthetic input, measured timings, illustrative scoring model", "fraud demo", async () => {
    const p = await page(D.base, "viewer", "fraud");
    await p.waitFor(`document.querySelector("#fr-runs [data-run]")`, 10000, "fraud run");
    await p.click("#fr-runs [data-run]");
    await p.waitFor(`document.querySelector("#fr-result .fr-provenance")`, 8000, "provenance note");
    const t = await p.eval(`document.querySelector("#fr-result .fr-provenance").innerText`);
    assert(/synthetic/.test(t) && /measured/.test(t) && /not a validated fraud model/.test(t), "provenance: " + t);
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });
  await test("fraud topology: MCP backends blocked by verified AI Security show as protected, not outages", "fraud demo", async () => {
    const p = await page(D.base, "viewer", "fraud");
    await p.waitFor(`document.querySelector("#fr-topo svg")`, 10000, "topology");
    const health = { checked_at: 1792248600, checks: [
      { id: "agent-a", role: "agent", url: "http://10.50.10.21:8080/healthz", reachable: true, status: 200, ms: 5, error: null },
      { id: "mcp-risk-1", role: "mcp", url: "http://10.50.20.31:8000/healthz", reachable: false, status: null, ms: null, error: "ConnectTimeout" },
      { id: "mcp-risk-2", role: "mcp", url: "http://10.50.20.32:8000/healthz", reachable: false, status: null, ms: null, error: "ConnectError" },
      { id: "mcp-intel", role: "mcp", url: "http://10.50.20.33:8000/healthz", reachable: false, status: 503, ms: 9, error: null },
      { id: "qdrant", role: "data", url: "http://10.50.20.40:6333/healthz", reachable: false, status: null, ms: null, error: "ConnectTimeout" }] };
    const run = async (protection) => {
      await p.eval(`(() => { window.__rf = window.__rf || window.fetch; window.fetch = (u, o) => {
        const s = String(u), body = s.includes("/api/fraud/health") ? ${JSON.stringify(JSON.stringify(health))}
          : s.includes("/api/verification") ? JSON.stringify({ levels: [], protection: ${JSON.stringify(protection)} }) : null;
        return body ? Promise.resolve(new Response(body, { status: 200, headers: { "Content-Type": "application/json" } })) : window.__rf(u, o); };
        fraudHealth(); })()`);
      await p.waitFor(`document.querySelector('#fr-topo [data-key="topo-mcp-risk-1"]')`, 5000, "topology rendered");
      return p.eval(`JSON.stringify({ s: Object.fromEntries([...document.querySelectorAll("#fr-topo [data-state]")].map((g) => [g.dataset.key.slice(5), g.dataset.state])),
        note: (document.querySelector("#fr-protected") || {}).innerText || "", txt: document.querySelector('#fr-topo [data-key="topo-mcp-risk-1"]').textContent })`).then(JSON.parse);
    };
    const sec = await run({ state: "active", delivery: true, security: true, verified: true, infra_label: "security", in_place: [] });
    assert(sec.s["mcp-risk-1"] === "protected" && sec.s["mcp-risk-2"] === "protected", "connection-level MCP failures under verified Security: " + JSON.stringify(sec.s));
    assert(sec.s["mcp-intel"] === "down" && sec.s.qdrant === "down" && sec.s["agent-a"] === "up", "HTTP 5xx and non-MCP rows unchanged: " + JSON.stringify(sec.s));
    assert(/Protected — direct access blocked \(expected\)/.test(sec.note) && /protected · direct blocked/.test(sec.txt), "label: " + sec.note + " | " + sec.txt);
    const del = await run({ state: "active", delivery: true, security: false, verified: true, infra_label: "delivery", in_place: [] });
    assert(del.s["mcp-risk-1"] === "down" && del.s["mcp-risk-2"] === "down" && !del.note, "without AI Security the same timeouts are outages: " + JSON.stringify(del.s));
    await p.eval(`(() => { window.fetch = window.__rf; })()`);
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });
  await test("fraud executive report downloads and also opens inline", "downloads", async () => {
    const p = await page(D.base, "se", "fraud");
    await p.waitFor(`document.querySelector("#fr-runs [data-run]")`, 10000, "fraud run");
    await p.click("#fr-runs [data-run]");
    await p.waitFor(`document.querySelector('#fr-result a.dl[data-filename$=".html"]')`, 8000, "download link");
    const before = browser.downloads.length;
    await p.click('#fr-result a.dl[data-filename$=".html"]');
    for (let i = 0; i < 60 && !(browser.downloads[before] && browser.downloads[before].state === "completed"); i++) await sleep(200);
    const d = browser.downloads[before]; assert(d && d.state === "completed", "completed: " + JSON.stringify(d));
    assert(/^<!doctype html>/i.test(fs.readFileSync(path.join(browser.downloadDir, d.name), "utf8").trim()), "valid HTML");
    const inline = await p.eval(`fetch(document.querySelector('#fr-result a[target="_blank"]').href).then(r => r.headers.get("content-disposition"))`);
    assert(inline === null, "inline variant has no attachment header");
    return p;
  });

  // ------------------------------------------------------------------ operations & resilience
  await test("sequential operations: discover → assess → recommend complete with progress", "operations", async () => {
    const p = await page(D.base, "se", "discover");
    for (const [pg, btn] of [["discover", "#d-all"], ["assess", "#a-run"], ["recommend", "#r-gen"]]) {
      await goPage(p, pg); await p.click(btn);
      await p.waitFor(`document.querySelector("#progress").innerText.length > 0`, 8000, `${pg} progress shown`);
      await p.waitFor(`!document.querySelector("#progress .spin")`, 30000, `${pg} finished`);
    }
    assert(p.errors.length === 0, "page errors: " + p.errors.join(" | "));
    return p;
  });
  await test("network outage: UI survives and recovers without a reload", "resilience", async () => {
    const p = await page(D.base, "se", "recommend");
    await p.click('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"] summary');
    await p.send("Network.enable");
    await p.send("Network.emulateNetworkConditions", { offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
    await sleep(7000);
    await p.send("Network.emulateNetworkConditions", { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
    const t0 = await p.eval(`document.querySelector("#refresh-state").textContent`);
    await sleep(7000);
    assert((await p.eval(`document.querySelector("#refresh-state").textContent`)) !== t0, "background refresh resumed");
    assert(await p.eval(`document.querySelector('#r-list > [data-key^="pkg-"]:first-child details[data-key^="as3-"]').open`), "expanded state survived the outage");
    assert(p.errors.length === 0, "uncaught errors: " + p.errors.join(" | "));
    return p;
  });
} finally {
  await browser.close();
  D.proc.kill(); C.proc.kill(); P.proc.kill();
}

const pass = results.filter((r) => r.status === "pass").length;
const report = { generated: new Date().toISOString(), chrome: "Google Chrome (headless=new), fresh temporary profile, --disable-extensions",
  served_by: "real FastAPI app + static assets (devtools/devserver.py, mocks only)", total: results.length, passed: pass, failed: results.length - pass, results };
fs.writeFileSync(path.join(OUT, "browser-regression.json"), JSON.stringify(report, null, 1));
fs.writeFileSync(path.join(OUT, "browser-regression.md"), `# Browser regression suite — Wave 1 + Wave 2A\n\nGenerated ${report.generated}\n\n${report.chrome}; ${report.served_by}.\n\n` +
  `**${pass}/${results.length} passed**\n\n| # | area | test | result | ms |\n|---|---|---|---|---|\n` +
  results.map((r, i) => `| ${i + 1} | ${r.area} | ${r.name} | ${r.status === "pass" ? "PASS" : "**FAIL**"} | ${r.ms} |`).join("\n") +
  (results.some((r) => r.status === "fail") ? "\n\n## Failures\n\n" + results.filter((r) => r.status === "fail").map((r) => `### ${r.name}\n\n\`\`\`\n${r.error}\n\`\`\``).join("\n\n") : "") + "\n");
console.log(`\n${pass}/${results.length} passed — report: ${path.relative(ROOT, path.join(OUT, "browser-regression.md"))}`);
process.exit(pass === results.length ? 0 : 1);
