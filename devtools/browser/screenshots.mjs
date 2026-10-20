// Capture documentation screenshots from the OFFLINE simulated demo (devtools/devserver.py). No lab system is contacted.
//   AP_PYTHON=.venv-demo/bin/python node devtools/browser/screenshots.mjs [out-dir]
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Browser } from "./cdp.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const OUT = path.resolve(process.argv[2] || path.join(ROOT, "docs/screenshots"));
const PORT = 8799;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
fs.mkdirSync(OUT, { recursive: true });
const srv = spawn(process.env.AP_PYTHON || path.join(ROOT, ".venv-demo/bin/python"), [path.join(ROOT, "devtools/devserver.py"), String(PORT), "failed-then-deployed"], { stdio: ["ignore", "pipe", "pipe"] });
let log = ""; srv.stdout.on("data", (d) => (log += d)); srv.stderr.on("data", (d) => (log += d));
for (let i = 0; i < 120 && !log.includes("dev server http"); i++) await sleep(500);
if (!log.includes("dev server http")) { console.error(log.slice(-2000)); process.exit(1); }
await sleep(1500);
const browser = await Browser.launch();
const shots = [["discover", "operator", "se"], ["assess", "operator", "se"], ["recommend", "operator", "se"], ["approve", "approver", "approver"],
  ["deploy", "approver", "approver"], ["validate", "operator", "se"], ["observe", "viewer", "viewer"], ["fraud", "operator", "se"], ["aiops", "viewer", "viewer"]];
try {
  for (const [pg, , user] of shots) {
    const p = await browser.newPage();
    await p.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
    await p.goto(`http://127.0.0.1:${PORT}/dev-login?u=${user}&page=${pg}`, 2500);
    await sleep(3500);
    await p.shot(path.join(OUT, `${pg}.png`));
    console.log("captured", pg);
    await p.close?.();
  }
} finally { await browser.close(); srv.kill(); }
