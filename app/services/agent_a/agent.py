"""Fraud Investigation Agent (Agent A) — A2A client.

Works an alert queue (synthetic rules-engine alerts), delegates each investigation to the Risk
Assessment Agent over A2A (Agent Card discovery -> streaming SendMessage), records status updates
and the final artifact, and exposes an operator UI/API on the management network.
Note: the A2A client follows the URL advertised in the Agent Card — if the card advertises a direct
backend address, traffic bypasses any proxy in front of the card endpoint (a discoverable finding).
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
import uuid

import httpx
import uvicorn
from a2a.client import A2ACardResolver, ClientConfig, create_client
from a2a.helpers import new_text_message
from a2a.types import Role, SendMessageRequest
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from google.protobuf.json_format import MessageToDict
from opentelemetry import trace
from pydantic import BaseModel, Field

from aplab import telemetry

from .scenario import ScenarioReq

tracer = telemetry.setup("agent-a-fraud-investigation", **{"gen_ai.agent.name": "fraud-investigation-agent"})
AGENT_B_URL = os.environ.get("AGENT_B_URL", "http://10.50.10.22:9000")
DATA = json.load(open(os.environ.get("APLAB_DATA", "/data/synthetic.json")))
ALERTS = [a["alert_id"] for a in DATA["alerts"]]
DB = os.environ.get("AGENT_A_DB", "/var/lib/agent-a/results.db")
os.makedirs(os.path.dirname(DB), exist_ok=True)
con = sqlite3.connect(DB, check_same_thread=False)
con.execute("""CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, alert_id TEXT, started REAL, finished REAL,
               state TEXT, trace_id TEXT, agent_b_url TEXT, card_url TEXT, updates TEXT, result TEXT, error TEXT)""")
con.commit()
app = FastAPI(title="Fraud Investigation Agent")
_sem = asyncio.Semaphore(int(os.environ.get("AGENT_A_MAX_CONCURRENCY", "4")))


def _d(msg) -> dict:
    try:
        return MessageToDict(msg, preserving_proto_field_name=True)
    except Exception:
        return {"repr": repr(msg)[:500]}


async def investigate(alert_id: str, scenario: dict | None = None) -> dict:
    inv_id = str(uuid.uuid4())
    async with _sem:
        with tracer.start_as_current_span("investigate_alert", attributes={"aplab.alert_id": alert_id,
                                                                            "gen_ai.operation.name": "invoke_agent"}) as span:
            trace_id = format(span.get_span_context().trace_id, "032x")
            row = {"id": inv_id, "alert_id": alert_id, "started": time.time(), "state": "submitted", "trace_id": trace_id,
                   "agent_b_url": AGENT_B_URL, "card_url": None, "updates": [], "result": None, "error": None}
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, read=600.0),
                                             verify=os.environ.get("AGENT_A_CA_BUNDLE") or True) as http:
                    card = await A2ACardResolver(httpx_client=http, base_url=AGENT_B_URL).get_agent_card()
                    row["card_url"] = card.supported_interfaces[0].url if card.supported_interfaces else None
                    span.set_attribute("a2a.agent_card.url", row["card_url"] or "")
                    client = await create_client(agent=card, client_config=ClientConfig(streaming=True, httpx_client=http))
                    text = f"Assess {alert_id}. Return decision, risk level and rationale."
                    if scenario:   # operator-composed synthetic scenario travels inline (validated by both agents)
                        text += " SCENARIO-JSON: " + json.dumps(scenario, separators=(",", ":"))
                    msg = new_text_message(text, role=Role.ROLE_USER)
                    async for chunk in client.send_message(SendMessageRequest(message=msg)):
                        d = _d(chunk)
                        row["updates"].append(d)
                        blob = json.dumps(d)
                        if "TASK_STATE_COMPLETED" in blob or "TASK_STATE_FAILED" in blob:
                            row["state"] = "completed" if "TASK_STATE_COMPLETED" in blob else "failed"
                        for art in _find(d, "artifact"):
                            for p in art.get("parts", []):
                                if p.get("text"):
                                    try:
                                        row["result"] = json.loads(p["text"])
                                    except json.JSONDecodeError:
                                        row["result"] = {"text": p["text"]}
                    await client.close()
                if row["state"] == "submitted":
                    row["state"] = "completed" if row["result"] else "unknown"
            except Exception as e:
                row["state"], row["error"] = "error", f"{type(e).__name__}: {e}"[:800]
                span.record_exception(e)
                span.set_status(trace.StatusCode.ERROR)
            row["finished"] = time.time()
            con.execute("INSERT INTO investigations VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (row["id"], alert_id, row["started"], row["finished"], row["state"], trace_id, AGENT_B_URL,
                         row["card_url"], json.dumps(row["updates"])[:200000], json.dumps(row["result"]), row["error"]))
            con.commit()
            return row


def _find(obj, key):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, dict):
                yield v
            else:
                yield from _find(v, key)
    elif isinstance(obj, list):
        for v in obj:
            yield from _find(v, key)


class InvestigateReq(BaseModel):
    alert_id: str = Field(pattern=r"^ALERT-\d{4}$")


class WorkloadReq(BaseModel):
    count: int = Field(default=8, ge=1, le=50)
    concurrency: int = Field(default=2, ge=1, le=4)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "agent": "fraud-investigation", "agent_b_url": AGENT_B_URL, "alerts": len(ALERTS),
            "capabilities": ["alerts", "scenarios"]}


@app.get("/api/alerts")
async def alerts():
    return DATA["alerts"]


@app.post("/api/investigate")
async def api_investigate(req: InvestigateReq):
    if req.alert_id not in ALERTS:
        raise HTTPException(404, "unknown alert")
    return await investigate(req.alert_id)


@app.post("/api/investigate-scenario")
async def api_investigate_scenario(req: ScenarioReq):
    """Synthetic normal / operator-composed scenario (validated model; synthetic accounts only)."""
    if req.scenario.account_id not in {a["account_id"] for a in DATA["accounts"]}:
        raise HTTPException(404, "unknown synthetic account")
    return await investigate(req.scenario.scenario_id, req.scenario.model_dump(mode="json"))


@app.post("/api/workload")
async def api_workload(req: WorkloadReq):
    """Bounded synthetic workload (max 50 investigations, max concurrency 4)."""
    global _sem
    _sem = asyncio.Semaphore(req.concurrency)
    ids = [ALERTS[i % len(ALERTS)] for i in range(req.count)]
    rows = await asyncio.gather(*(investigate(a) for a in ids))
    return {"submitted": len(rows), "states": {s: sum(r["state"] == s for r in rows) for s in {r["state"] for r in rows}},
            "trace_ids": [r["trace_id"] for r in rows]}


@app.get("/api/investigations")
async def investigations(limit: int = 50):
    cur = con.execute("SELECT id, alert_id, started, finished, state, trace_id, agent_b_url, card_url, result, error "
                      "FROM investigations ORDER BY started DESC LIMIT ?", (min(limit, 500),))
    cols = [c[0] for c in cur.description]
    return [{**dict(zip(cols, r)), "result": json.loads(r[8]) if r[8] else None} for r in cur.fetchall()]


@app.get("/", response_class=HTMLResponse)
async def ui():
    return """<!doctype html><html><head><title>Fraud Investigation Agent</title>
<style>body{font-family:system-ui;margin:2rem;background:#0f1419;color:#e6e6e6}button{margin:2px;padding:6px 10px}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid #333;padding:4px;text-align:left}
code{color:#9cdcfe}</style></head><body>
<h2>Fraud Investigation Agent (Agent A) &mdash; A2A client</h2><p>Delegates to the Risk Assessment Agent over A2A. Synthetic data only.</p>
<div id=alerts></div><p><button onclick="wl()">Run bounded workload (8)</button></p><h3>Investigations</h3><table id=t></table>
<script>
async function load(){const a=await (await fetch('/api/alerts')).json();
document.getElementById('alerts').innerHTML=a.map(x=>`<button onclick="inv('${x.alert_id}')">${x.alert_id}</button>`).join('');
const r=await (await fetch('/api/investigations')).json();
document.getElementById('t').innerHTML='<tr><th>alert</th><th>state</th><th>decision</th><th>risk</th><th>by</th><th>replicas</th><th>card url</th><th>trace</th><th>s</th></tr>'+
r.map(x=>{const s=(x.result||{}).assessment||{};return `<tr><td>${x.alert_id}</td><td>${x.state}</td><td>${s.decision||''}</td><td>${s.risk_level||''}</td><td>${s.generated_by||''}</td><td>${((x.result||{}).replicas_used||[]).join(',')}</td><td><code>${x.card_url||''}</code></td><td><code>${x.trace_id.slice(0,12)}</code></td><td>${x.finished?(x.finished-x.started).toFixed(1):''}</td></tr>`}).join('');}
async function inv(id){await fetch('/api/investigate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({alert_id:id})});load()}
async function wl(){await fetch('/api/workload',{method:'POST',headers:{'content-type':'application/json'},body:'{"count":8,"concurrency":2}'});load()}
load();setInterval(load,5000);</script></body></html>"""


if __name__ == "__main__":
    uvicorn.run(telemetry.asgi(app), host=os.environ.get("BIND_HOST", "0.0.0.0"), port=int(os.environ.get("BIND_PORT", "8080")))
