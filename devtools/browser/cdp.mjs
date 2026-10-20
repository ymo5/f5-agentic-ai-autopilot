// Minimal, dependency-free Chrome DevTools Protocol driver for the browser regression suite.
// Launches a CLEAN Chrome (fresh temporary profile, extensions disabled) and performs REAL input events
// (mouse, keyboard) — no synthetic element.click() shortcuts for user actions.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const CHROME = process.env.CHROME_BIN || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class Conn {
  constructor(url) { this.url = url; this.id = 0; this.pending = new Map(); this.listeners = []; }
  async open() {
    this.ws = new WebSocket(this.url);
    this.ws.onmessage = (m) => {
      const d = JSON.parse(m.data);
      if (d.id && this.pending.has(d.id)) { const { res, rej } = this.pending.get(d.id); this.pending.delete(d.id); d.error ? rej(new Error(`${d.error.message} ${d.error.data || ""}`)) : res(d.result); }
      else if (d.method) this.listeners.forEach((l) => l(d));
    };
    await new Promise((r, j) => { this.ws.onopen = r; this.ws.onerror = j; });
    return this;
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((res, rej) => {
      const t = setTimeout(() => { this.pending.delete(id); rej(new Error(`CDP ${method} timed out after 30 s`)); }, 30000);
      this.pending.set(id, { res: (v) => { clearTimeout(t); res(v); }, rej: (e) => { clearTimeout(t); rej(e); } });
      this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  on(fn) { this.listeners.push(fn); }
  close() { try { this.ws.close(); } catch { /* ignore */ } }
}

export class Browser {
  static async launch({ downloadDir } = {}) {
    const b = new Browser();
    b.profile = fs.mkdtempSync(path.join(os.tmpdir(), "ap-chrome-clean-"));
    b.downloadDir = downloadDir || fs.mkdtempSync(path.join(os.tmpdir(), "ap-dl-"));
    b.proc = spawn(CHROME, ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${b.profile}`, "--disable-extensions",
      "--no-first-run", "--no-default-browser-check", "--disable-component-extensions-with-background-pages", "--disable-sync",
      "--window-size=1500,1000", "about:blank"], { stdio: "ignore" });
    const portFile = path.join(b.profile, "DevToolsActivePort");
    let port, wsPath;   // Chrome creates the file before writing it: wait for both lines
    for (let i = 0; i < 150 && !(port && wsPath); i++) {
      if (fs.existsSync(portFile)) [port, wsPath] = fs.readFileSync(portFile, "utf8").trim().split("\n");
      if (!(port && wsPath)) await sleep(100);
    }
    if (!(port && wsPath)) throw new Error("Chrome did not publish its DevTools port");
    b.conn = await new Conn(`ws://127.0.0.1:${port}${wsPath}`).open();
    await b.conn.send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: b.downloadDir, eventsEnabled: true });
    b.downloads = [];
    b.conn.on((d) => {
      if (d.method === "Browser.downloadWillBegin") b.downloads.push({ guid: d.params.guid, url: d.params.url, name: d.params.suggestedFilename, state: "started" });
      if (d.method === "Browser.downloadProgress") { const x = b.downloads.find((y) => y.guid === d.params.guid); if (x) x.state = d.params.state; }
    });
    return b;
  }
  async extensionsLoaded() {   // proves the profile is clean: no extension targets/background pages
    const { targetInfos } = await this.conn.send("Target.getTargets");
    return targetInfos.filter((t) => t.url.startsWith("chrome-extension://")).length;
  }
  async grant(origin) {
    await this.conn.send("Browser.grantPermissions", { origin, permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"] });
  }
  async newPage() {
    const { targetId } = await this.conn.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await this.conn.send("Target.attachToTarget", { targetId, flatten: true });
    const p = new Page(this.conn, sessionId, targetId);
    await p.init();
    await p.send("Page.bringToFront");
    return p;
  }
  async close() {
    try { await Promise.race([this.conn.send("Browser.close"), sleep(2000)]); } catch { /* ignore */ }
    this.conn.close();
    // Chrome owns renderer/helper children and may still hold the profile after Browser.close.
    // Wait for the process to exit before removing the profile; otherwise a long suite leaks
    // targets/processes and later CDP calls become nondeterministic.
    const exited = new Promise((resolve) => {
      if (this.proc.exitCode !== null) return resolve();
      this.proc.once("exit", resolve);
    });
    try { if (this.proc.exitCode === null) this.proc.kill(); } catch { /* ignore */ }
    await Promise.race([exited, sleep(2000)]);
    if (this.proc.exitCode === null) {
      try { this.proc.kill("SIGKILL"); } catch { /* ignore */ }
      await Promise.race([exited, sleep(1000)]);
    }
    try { fs.rmSync(this.profile, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

export class Page {
  constructor(conn, sessionId, targetId) { this.c = conn; this.s = sessionId; this.targetId = targetId; this.errors = []; this.console = []; }
  send(m, p) { return this.c.send(m, p, this.s); }
  async init() {
    this.c.on((d) => {
      if (d.sessionId !== this.s) return;
      if (d.method === "Runtime.exceptionThrown") this.errors.push(d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text);
      if (d.method === "Runtime.consoleAPICalled" && d.params.type === "error") this.console.push(d.params.args.map((a) => a.value ?? a.description).join(" "));
    });
    await this.send("Runtime.enable"); await this.send("Page.enable");
    await this.send("Emulation.setDeviceMetricsOverride", { width: 1500, height: 1000, deviceScaleFactor: 1, mobile: false });
    // A presenter's window is focused and visible; headless background tabs can report document.hidden = true, which
    // (correctly) pauses the app's background refresh. Emulate the real condition explicitly.
    await this.send("Emulation.setFocusEmulationEnabled", { enabled: true });
    try { await this.send("Page.setWebLifecycleState", { state: "active" }); } catch { /* not supported: ignore */ }
  }
  async goto(url, settle = 1500) { await this.send("Page.navigate", { url }); await sleep(settle); }
  async eval(expr) {
    const r = await this.send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true, userGesture: true });
    if (r.exceptionDetails) throw new Error(`eval failed: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}\n  in: ${expr.slice(0, 200)}`);
    return r.result.value;
  }
  async waitFor(expr, timeout = 10000, what = expr) {
    const t0 = Date.now();
    while (Date.now() - t0 < timeout) { try { if (await this.eval(expr)) return true; } catch { /* retry */ } await sleep(150); }
    throw new Error(`timeout waiting for: ${what}`);
  }
  async box(sel) {
    const b = await this.eval(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return null;
      e.scrollIntoView({ block: "center", inline: "center" }); const r = e.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height }; })()`);
    if (!b) throw new Error(`element not found: ${sel}`);
    return b;
  }
  async mouse(type, x, y, extra = {}) { await this.send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1, ...extra }); }
  async clickAt(x, y) { await this.mouse("mouseMoved", x, y); await this.mouse("mousePressed", x, y); await this.mouse("mouseReleased", x, y); }
  async click(sel) {
    // Real mouse click, confirmed: the target must receive the click event. Layout can shift between measuring and
    // dispatching (e.g. a finished-operation banner disappearing), so a click that lands elsewhere is retried.
    for (let attempt = 0; attempt < 3; attempt++) {
      let b = await this.box(sel);
      for (let i = 0; i < 10; i++) { await sleep(60); const c = await this.box(sel); if (Math.abs(c.x - b.x) < 1 && Math.abs(c.y - b.y) < 1) break; b = c; }
      const x = b.x + b.w / 2, y = b.y + b.h / 2;
      const hit = await this.eval(`(() => { const t = document.querySelector(${JSON.stringify(sel)}), e = document.elementFromPoint(${x}, ${y});
        window.__clickOk = false; t.addEventListener("click", () => { window.__clickOk = true; }, { once: true, capture: true });
        return !e ? "nothing" : (t === e || t.contains(e) || e.contains(t)) ? "" : (e.id ? "#" + e.id : e.tagName + "." + e.className); })()`);
      if (hit && attempt === 2) throw new Error(`click on ${sel} would hit ${hit} instead (element covered)`);
      if (hit) { await sleep(250); continue; }
      await this.clickAt(x, y); await sleep(120);
      if (await this.eval(`window.__clickOk === true`)) return;
      await sleep(250);
    }
    throw new Error(`click on ${sel} did not reach the element after 3 attempts (layout kept moving)`);
  }
  async drag(x1, y1, x2, y2) {
    await this.mouse("mouseMoved", x1, y1); await this.mouse("mousePressed", x1, y1);
    for (let i = 1; i <= 8; i++) await this.mouse("mouseMoved", x1 + ((x2 - x1) * i) / 8, y1 + ((y2 - y1) * i) / 8, { buttons: 1 });
    await this.mouse("mouseReleased", x2, y2);
  }
  async type(text) { for (const ch of text) await this.send("Input.dispatchKeyEvent", { type: "char", text: ch }); }
  async key(key, code, modifiers = 0, keyCode = 0) {
    await this.send("Input.dispatchKeyEvent", { type: "rawKeyDown", key, code, modifiers, windowsVirtualKeyCode: keyCode, nativeVirtualKeyCode: keyCode });
    await this.send("Input.dispatchKeyEvent", { type: "keyUp", key, code, modifiers, windowsVirtualKeyCode: keyCode, nativeVirtualKeyCode: keyCode });
  }
  async close() { try { await this.c.send("Target.closeTarget", { targetId: this.targetId }); } catch { /* ignore */ } }
  async shot(file) { const r = await this.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(file, Buffer.from(r.data, "base64")); }
}

export { sleep };
