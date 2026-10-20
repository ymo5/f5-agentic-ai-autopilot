"""Shared fixtures: real web app + approval logic + deployment engine + policy, with mock BIG-IP/host executors."""
from __future__ import annotations

import pathlib
import sys

import pytest
from fastapi import HTTPException

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CFG = ROOT.parent / "deploy" / "autopilot" / "autopilot.yaml"
SCHEMA = ROOT.parent / "packages" / "vendor" / "as3-schema-3.56.0-10.json"


def span(sid, proc, name, kind, tags, parent=None, dur=5000):
    t = [{"key": "span.kind", "value": kind}] + [{"key": k, "value": v} for k, v in tags.items()]
    return {"spanID": sid, "processID": proc, "operationName": name, "duration": dur, "tags": t,
            "references": [{"refType": "CHILD_OF", "spanID": parent}] if parent else []}


def proc(svc, inst=None):
    tags = [{"key": "host.name", "value": svc}]
    if inst:
        tags.append({"key": "service.instance.id", "value": inst})
    return {"serviceName": svc, "tags": tags}


TRACE = {"traceID": "t1", "processes": {"pa": proc("agent-a-fraud-investigation"), "pb": proc("agent-b-risk-assessment"),
                                         "pr": proc("mcp-risk-scoring", "risk-scoring-1")}, "spans": [
    span("a1", "pa", "investigate_alert", "internal", {"gen_ai.agent.name": "fraud-investigation-agent"}),
    span("a2", "pa", "POST", "client", {"http.url": "http://10.50.10.22:9000/"}, "a1"),
    span("b1", "pb", "POST /", "server", {"http.host": "10.50.10.22:9000", "net.peer.ip": "10.50.10.21", "http.target": "/"}, "a2"),
    span("b2", "pb", "assess_fraud_alert", "internal", {"gen_ai.agent.name": "risk-assessment-agent", "a2a.task.id": "x"}, "b1"),
    span("r1", "pr", "POST /mcp", "server", {"http.host": "10.50.20.31:8000", "net.peer.ip": "10.50.20.22", "http.target": "/mcp"}, "b2"),
    span("r2", "pr", "tools/call score_transaction", "server", {"mcp.method.name": "tools/call", "gen_ai.tool.name": "score_transaction",
                                                                  "mcp.protocol.version": "2025-11-25"}, "r1"),
]}
TOOLS = [{"name": "score_transaction", "annotations": {"readOnlyHint": True}}, {"name": "model_info", "annotations": {}}]
INTEL_TOOLS = [{"name": "get_alert", "annotations": {}}, {"name": "freeze_account", "annotations": {"destructiveHint": True}}]
SCAN = [
    {"ip": "10.50.10.22", "port": 9000, "protocol": "a2a", "kind": "a2a_agent", "name": "Risk Assessment Agent",
     "agent_card": {"name": "Risk Assessment Agent", "advertised_urls": ["http://10.50.10.22:9000/"], "skills": ["assess"],
                    "security_schemes": [], "streaming": True}},
    *[{"ip": ip, "port": 8000, "protocol": "mcp", "kind": "mcp_server", "name": "risk-scoring",
       "mcp": {"server_name": "risk-scoring", "server_version": "x", "protocol_version": "2025-11-25", "tools": TOOLS,
               "toolset_fingerprint": "abc", "authenticated": False}} for ip in ("10.50.20.31", "10.50.20.32")],
    {"ip": "10.50.20.33", "port": 8000, "protocol": "mcp", "kind": "mcp_server", "name": "fraud-intel",
     "mcp": {"server_name": "fraud-intel", "server_version": "x", "protocol_version": "2025-11-25", "tools": INTEL_TOOLS,
             "toolset_fingerprint": "def", "authenticated": False}},
]
PW = "correct-horse-battery-staple"


class Ctx:
    pass


@pytest.fixture()
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPILOT_CONFIG", str(CFG))
    monkeypatch.setenv("AUTOPILOT_DB", str(tmp_path / "ap.db"))
    monkeypatch.setenv("AUTOPILOT_SNAPSHOTS", str(tmp_path / "snaps"))
    monkeypatch.setenv("AS3_SCHEMA", str(SCHEMA))
    monkeypatch.setenv("AUTOPILOT_SESSION_SECRET", "x" * 40)
    monkeypatch.setenv("LLM_PROVIDER", "none")
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    for m in [k for k in sys.modules if k.startswith("autopilot")]:
        del sys.modules[m]
    from fastapi.testclient import TestClient

    from autopilot import auth, operations, web
    operations.INLINE = True
    from autopilot.deployer.engine import DeploymentRefused, Engine
    from autopilot.deployer.executors import MockBigip, MockHosts
    from autopilot.sources import enumerate as e_src
    from autopilot.sources import ingest as i_src

    async def fake_scan(*a, **k):
        return SCAN

    async def fake_traces(*a, **k):
        return [TRACE]
    monkeypatch.setattr(e_src, "scan", fake_scan)
    monkeypatch.setattr(e_src, "zone_transfer", lambda s, z: [{"name": "mcp-risk-1.aplab.internal", "type": "A", "value": "10.50.20.31"}])
    monkeypatch.setattr(i_src, "fetch_traces", fake_traces)

    c = Ctx()
    c.web, c.bigip, c.hosts = web, MockBigip(), MockHosts()
    c.gate = {"result": "pass"}

    async def validator(profile):
        return [{"test": "mock.gate", "result": c.gate["result"], "observed": {"profile": profile}, "expected": "pass"}]
    c.engine = Engine(web.STORE, c.bigip, c.hosts, validator, mock=True)

    class InProcessDeployer:
        async def _w(self, coro):
            try:
                return await coro
            except DeploymentRefused as e:
                raise HTTPException(409, str(e))

        async def state(self):
            fp, st = await c.engine.fingerprint()
            return {"fingerprint": fp, **st, "live": False, "window": c.engine.window_status()}

        async def preflight(self, pkg):
            fp, st = await c.engine.fingerprint()
            return {"fingerprint": fp, "checks": await c.engine.preflight(pkg, st)}

        async def deploy(self, pkg, approval_id, user):
            return await self._w(c.engine.deploy(pkg, approval_id, user))

        async def rollback(self, did, user):
            return await self._w(c.engine.rollback(did, user))

        async def reset_demo(self, user, confirmation):
            return await self._w(c.engine.reset_demo(user, confirmation))

        async def observe_raw(self):
            return await c.engine.observe_raw()

        async def validation_action(self, req):
            return await self._w(c.engine.validation_action(req))

        async def health(self):
            return {"status": "ok", "live": False, "window": c.engine.window_status()}

        async def window_open(self, body):
            return await self._ctl(c.control.open(body["username"], body["password"], body["minutes"], body["grace"], body["reason"]))

        async def window_close(self, body):
            return await self._ctl(c.control.close(body["username"], body["role"], body["reason"]))

        async def window_broker(self):
            return await c.control.broker_health()

        async def diagnostics_bigip(self):
            return {"reachable": True, **(await c.engine.capabilities())}

        async def _ctl(self, coro):
            from autopilot.deployer.control import ControlError
            try:
                return await coro
            except ControlError as e:
                raise HTTPException(e.status, str(e))
    class FakeBroker:   # records calls; behaves like ap-window-broker (bounds re-checked there too)
        def __init__(self):
            self.calls, self.fail = [], None

        async def call(self, action, **p):
            self.calls.append((action, p))
            if self.fail:
                return {"ok": False, "error": self.fail}
            return {"ok": True, "rc": 0, "message": f"{action.upper()} ok"}
    from autopilot.deployer.control import WindowControl
    c.broker = FakeBroker()
    c.control = WindowControl(web.STORE, c.broker, c.engine.window_status)
    web.DEPLOYER = InProcessDeployer()
    for u, r in (("viewer1", "viewer"), ("se1", "operator"), ("approver1", "approver"), ("owner1", "owner")):
        auth.add_user(web.STORE.db, u, r, PW)
    c.anon = TestClient(web.app)
    c.clients = {}
    for u, r in (("viewer1", "viewer"), ("se1", "operator"), ("approver1", "approver"), ("owner1", "owner")):
        cl = TestClient(web.app)
        assert cl.post("/api/login", json={"username": u, "password": PW}).status_code == 200
        cl.headers["X-CSRF-Token"] = cl.cookies.get("ap_csrf")   # the UI echoes the CSRF cookie on every POST
        c.clients[r] = cl
    c.op, c.ap, c.viewer, c.owner = c.clients["operator"], c.clients["approver"], c.clients["viewer"], c.clients["owner"]
    return c


def discover(c):
    c.op.post("/api/discover/enumerate")
    c.op.post("/api/discover/ingest")
    pk = c.op.post("/api/recommend").json()["packages"]
    return {p["kind"]: p["id"] for p in pk}


def review(c, pid, client=None):
    """Preview, diff & preflight — required (and recorded) before an approval can be granted."""
    r = (client or c.ap).get(f"/api/packages/{pid}/review")
    assert r.status_code == 200, r.text
    return r.json()
