"""Isolated UI development server — NEVER deployed (outside app/, not pushed by scripts/push-src.sh).

Runs the real web app against a temporary database with the test-suite mocks (MockBigip/MockHosts, fixture scan +
traces); no network access to the lab. Adds /dev-login?u=<user> for headless screenshots. Usage:
    app/.venv/bin/python devtools/devserver.py [port] [scenario]
scenario: empty | discovered | failed-then-deployed (default) | compare (adds a rediscovery after the successful deployment)
          | placement-evidence (discovered + a synthetic complete per-device Observe snapshot, ingested)
Every scenario first creates an assessment with NO discovery evidence (regression fixture for misleading comparisons).
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "app" / "tests"))
tmp = tempfile.mkdtemp(prefix="ap-dev-")
os.environ.update(AUTOPILOT_CONFIG=str(ROOT / "deploy/autopilot/autopilot.yaml"), AUTOPILOT_DB=f"{tmp}/ap.db",
                  AUTOPILOT_SNAPSHOTS=f"{tmp}/snaps", AS3_SCHEMA=str(ROOT / "packages/vendor/as3-schema-3.56.0-10.json"),
                  AUTOPILOT_SESSION_SECRET="d" * 40, LLM_PROVIDER="none")
os.environ.pop("LLM_BASE_URL", None)

import uvicorn  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.responses import RedirectResponse  # noqa: E402

import conftest as fx  # noqa: E402  (fixture data only)
from autopilot import auth, operations, web  # noqa: E402
from autopilot.deployer.engine import DeploymentRefused, Engine  # noqa: E402
from autopilot.deployer.executors import MockBigip, MockHosts  # noqa: E402
from autopilot.sources import enumerate as e_src, ingest as i_src  # noqa: E402

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
SCENARIO = sys.argv[2] if len(sys.argv) > 2 else "failed-then-deployed"


AGENT_B_BACKEND = {**fx.SCAN[0], "ip": "10.50.20.22",   # the live lab: Agent B also answers on its backend NIC (same card)
                   "agent_card": {**fx.SCAN[0]["agent_card"], "advertised_urls": ["http://10.50.10.22:9000/"]}}


async def fake_scan(*a, **k):
    return fx.SCAN + [AGENT_B_BACKEND]


async def fake_traces(*a, **k):
    return [fx.TRACE]
e_src.scan, i_src.fetch_traces = fake_scan, fake_traces
e_src.zone_transfer = lambda s, z: [{"name": "mcp-risk-1.aplab.internal", "type": "A", "value": "10.50.20.31"}]
bigip, hosts, gate = MockBigip(), MockHosts(), {"result": "pass"}


async def validator(profile):
    return [{"test": t, "result": gate["result"] if t == "delivery.failover" else "pass", "observed": {"profile": profile}, "expected": "pass"}
            for t in ("a2a.agent_card", "a2a.via_front_door", "mcp.tool_execution", "delivery.load_distribution", "delivery.failover")]
eng = Engine(web.STORE, bigip, hosts, validator, mock=True)


async def fake_validate(cfg, profile, actions=None, on_result=None):   # never touches the network
    res = await validator(profile)
    for r in res:
        if on_result:
            on_result(r)
    return res
web.validate.run = fake_validate
WINDOW = {"phase": "locked", "reason": "no live window authorised (dev)", "_unused": "live", "not_after": time.time() + 7200, "cleanup_until": time.time() + 9000, "remaining_s": 7200, "authorized_by": "dev fixture"}


class Dev:
    async def _w(self, c):
        try:
            return await c
        except DeploymentRefused as e:
            raise HTTPException(409, str(e))

    async def state(self):
        fp, st = await eng.fingerprint()
        return {"fingerprint": fp, **st, "live": True, "window": WINDOW}

    async def preflight(self, pkg):
        fp, st = await eng.fingerprint()
        return {"fingerprint": fp, "checks": await eng.preflight(pkg, st)}

    async def deploy(self, pkg, aid, user):
        await asyncio.sleep(2)
        return await self._w(eng.deploy(pkg, aid, user))

    async def rollback(self, did, user):
        return await self._w(eng.rollback(did, user))

    async def reset_demo(self, user, c):
        return await self._w(eng.reset_demo(user, c))

    async def observe_raw(self):
        return await eng.observe_raw()

    async def validation_action(self, req):
        return await self._w(eng.validation_action(req))

    async def health(self):
        return {"status": "ok", "live": True, "window": WINDOW}


from autopilot import fraud  # noqa: E402
from autopilot.deployer.control import WindowControl  # noqa: E402
import test_fraud as tf  # noqa: E402  (trace fixture)
import httpx  # noqa: E402


class DevBroker:      # flips the dev window like ap-live-window would
    async def call(self, action, **p):
        if action == "open":
            WINDOW.update(phase="live", not_after=time.time() + p["minutes"] * 60, cleanup_until=time.time() + (p["minutes"] + p["grace"]) * 60,
                          remaining_s=p["minutes"] * 60, authorized_by=p["by"])
        if action == "close":
            WINDOW.update(phase="locked", reason="closed (dev)")
        return {"ok": True, "rc": 0, "message": f"{action} (dev broker)", "version": 1}


CONTROL = WindowControl(web.STORE, DevBroker(), lambda: WINDOW)
async def _ctl(coro):
    from autopilot.deployer.control import ControlError
    try:
        return await coro
    except ControlError as e:
        raise HTTPException(e.status, str(e))
Dev.window_open = lambda self, b: _ctl(CONTROL.open(b["username"], b["password"], b["minutes"], b["grace"], b["reason"]))
Dev.window_close = lambda self, b: _ctl(CONTROL.close(b["username"], b["role"], b["reason"]))
Dev.window_broker = lambda self: CONTROL.broker_health()


async def _diag(self):
    return {"reachable": True, **(await eng.capabilities()), "virtual_servers": 0, "tenant_present": bigip.tenant is not None}
Dev.diagnostics_bigip = _diag


def _agent_a(req: httpx.Request):   # dev fixture standing in for Agent A / health endpoints (never the lab)
    if req.url.path == "/healthz":
        return httpx.Response(200, json={"status": "ok", "agent_b_url": "http://10.50.10.22:9000", "capabilities": ["alerts", "scenarios"]})
    if req.url.path.startswith("/api/investigate"):
        import time as _t
        _t.sleep(3)
        return httpx.Response(200, json={"state": "completed", "trace_id": tf.TRACE_ID, "agent_b_url": "http://10.50.10.22:9000",
                                         "updates": [{"statusUpdate": {"status": {"state": "TASK_STATE_WORKING"}}}], "error": None,
                                         "result": {"assessment": {"decision": "escalate", "risk_level": "high", "confidence": 0.86,
                                                                   "rationale": "Several sub-$5 card-not-present authorisations across merchants (dev fixture).",
                                                                   "recommended_actions": ["Block card", "Contact customer"], "generated_by": "llm:dev-fixture"},
                                                    "model_scores": [{"transaction_id": "TXN-501", "score": 0.91, "band": "high", "replica": "risk-scoring-1"},
                                                                     {"transaction_id": "TXN-502", "score": 0.44, "band": "medium", "replica": "risk-scoring-2"}],
                                                    "rag_patterns": [{"pattern_id": "FP-001", "name": "Card testing", "score": 0.83}],
                                                    "case_file": "CASE-7000", "replicas_used": ["risk-scoring-1", "risk-scoring-2"]}})
    return httpx.Response(200, json={"status": "ok"})


_Real = httpx.AsyncClient


class _DevClient(_Real):
    def __init__(self, *a, **k):
        k.pop("verify", None)
        super().__init__(*a, transport=httpx.MockTransport(_agent_a), **k)
httpx.AsyncClient = _DevClient


async def _trace(j, tid, wait_s=20):
    return tf.trace()
fraud.fetch_trace = _trace
web.DEPLOYER = Dev()
for u, r in (("viewer", "viewer"), ("se", "operator"), ("approver", "approver"), ("owner", "owner")):
    auth.add_user(web.STORE.db, u, r, fx.PW)


@web.app.get("/dev-login")
async def dev_login(u: str = "se", page: str = "discover"):
    role = {"viewer": "viewer", "se": "operator", "approver": "approver", "owner": "owner"}[u]
    resp = RedirectResponse(f"/#{page}")
    resp.set_cookie(auth.COOKIE, auth.issue(u, role), httponly=True, samesite="strict")
    resp.set_cookie(auth.CSRF_COOKIE, auth.new_csrf(), httponly=False, samesite="strict")
    return resp


async def scenario():
    from fastapi.testclient import TestClient
    operations.INLINE = True
    se, ap = TestClient(web.app), TestClient(web.app)
    se.post("/api/login", json={"username": "se", "password": fx.PW})
    ap.post("/api/login", json={"username": "approver", "password": fx.PW})
    se.headers["X-CSRF-Token"], ap.headers["X-CSRF-Token"] = se.cookies.get("ap_csrf"), ap.cookies.get("ap_csrf")
    se.post("/api/assessment/new", json={"name": "Exploratory — no discovery yet"})
    time.sleep(0.05)
    se.post("/api/assessment/new", json={"name": "Customer AI environment — A"})
    if SCENARIO == "empty":
        return
    se.post("/api/ops/discover", json={"methods": ["observe", "enumerate", "ingest"]})
    se.post("/api/ops/describe", json={"text": "The fraud agent hands cases to a risk agent over A2A; the risk agent uses an MCP "
                                              "scoring service with two replicas and an intel MCP server. All MCP traffic goes through "
                                              "the BIG-IP. The MCP servers are authenticated."})
    if SCENARIO == "discovered":
        return
    if SCENARIO == "placement-evidence":
        # a SYNTHETIC complete collector snapshot for a simulated BIG-IP (documentation address), uploaded and ingested the
        # same way an owner-run scripts/observe-collect.sh snapshot would be — the advisory can then select a device
        import hashlib
        from test_observe_evidence import raw_device
        web.TOKEN_SHA256 = hashlib.sha256(b"dev-token").hexdigest()
        snap = raw_device(label="lab-sim", mgmt="192.0.2.40", hostname="bigip-sim.example.test", collected_at=time.time())
        TestClient(web.app).post("/api/observe/snapshot", json=snap, headers={"Authorization": "Bearer dev-token"})
        se.post("/api/discover/observe/snapshots")
        se.post("/api/ops/recommend")
        return
    se.post("/api/ops/recommend")
    pk = {p["kind"]: p["id"] for p in ap.get("/api/packages").json()}
    gate["result"] = "fail"
    ap.get(f"/api/packages/{pk['delivery']}/review")
    ap.post(f"/api/packages/{pk['delivery']}/decision", json={"decision": "approved", "comment": "rehearsal 1"})
    ap.post(f"/api/ops/deploy/{pk['delivery']}")
    gate["result"] = "pass"
    ap.get(f"/api/packages/{pk['delivery']}/review")
    ap.post(f"/api/packages/{pk['delivery']}/decision", json={"decision": "approved", "comment": "after fix"})
    ap.post(f"/api/ops/deploy/{pk['delivery']}")
    se.post("/api/ops/validate", json={"profile": "before"})
    se.post("/api/ops/investigate", json={"scenario_id": "ALERT-9000"})
    if SCENARIO == "compare":
        time.sleep(0.05)
        se.post("/api/assessment/new", json={"name": "Customer AI environment — after Delivery"})
        se.post("/api/ops/discover", json={"methods": ["observe", "enumerate", "ingest"]})


if __name__ == "__main__":
    import threading

    def boot():
        asyncio.run(scenario())
        operations.INLINE = False
    t = threading.Thread(target=boot)
    t.start()
    t.join()
    print(f"dev server http://127.0.0.1:{PORT}/dev-login?u=se  (db {tmp})", flush=True)
    uvicorn.run(web.app, host="127.0.0.1", port=PORT, log_level="warning")
