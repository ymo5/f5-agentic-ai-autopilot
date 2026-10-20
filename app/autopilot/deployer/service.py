"""autopilot-deployer — separate service holding device credentials; never reachable by the LLM.

Listens on 127.0.0.1:8100 (host network on AP-AUTOPILOT-01). Callers must present X-Deployer-Token (shared only
with autopilot-web). Every request that executes anything is re-authorised here: approval verification against
the shared database, role check of the human named in the request, policy checks, time-bounded live window
(window.py; the window file is the only source of live authorisation and is re-read on every operation).
Credentials: read from files in /run/secrets (mounted only into this container).
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os

import uvicorn
import yaml
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .. import validate as validation
from ..store import Store
from . import broker as broker_mod
from . import control, converge, policy, trafficgen
from .engine import DeploymentRefused, Engine
from .executors import BigipExecutor, ExecError, HostExecutor
from .window import Window, default_path

SECRETS = os.environ.get("DEPLOYER_SECRETS", "/run/secrets/deployer")
CFG = yaml.safe_load(open(os.environ.get("AUTOPILOT_CONFIG", "/etc/autopilot/autopilot.yaml")))


def _read(name: str) -> str:
    return open(os.path.join(SECRETS, name)).read().strip()


def _cred(name: str) -> tuple[str, str]:
    d = json.loads(_read(name))
    return d["username"], d["password"]


store = Store(os.environ.get("AUTOPILOT_DB", "/var/lib/autopilot/autopilot.db"))
engine = Engine(store,
                BigipExecutor(CFG["observe"]["bigip_mgmt"], _read("bigip_cert_sha256"), _cred("bigip_deployer.json"), _cred("bigip_observer.json")),
                HostExecutor(os.path.join(SECRETS, "apdeploy_ed25519"), os.path.join(SECRETS, "known_hosts")),
                validator=None, window=Window(default_path(), store.db, audit=store.audit), cfg=CFG)
engine.probes = converge.Probes(engine.bigip, policy.TENANT, validation.CA, validation.VALIDATOR)
BROKER = broker_mod.from_env(SECRETS)
engine.validator = lambda profile: validation.run(CFG, profile, actions=lambda req: engine.validation_action(req, internal=True))
app = FastAPI(title="autopilot-deployer")


async def _ticker():
    """Audit window transitions (opened / expired / closed) even when nobody is using the UI."""
    while True:
        try:
            engine.window.transition(store.audit)
        except Exception:  # never let the ticker die; enforcement does not depend on it
            pass
        await asyncio.sleep(15)


@app.on_event("startup")
async def _start_ticker():
    engine.window.transition(store.audit)
    asyncio.create_task(_ticker())


def _live() -> dict:
    w = engine.window_status()
    return {"live": w["phase"] == "live", "window": w}


def token(x_deployer_token: str = Header(default="")) -> None:
    if not hmac.compare_digest(x_deployer_token, _read("deployer_token")):
        raise HTTPException(401, "bad deployer token")


class Who(BaseModel):
    username: str
    role: str


class DeployReq(BaseModel):
    package: dict
    approval_id: str
    user: Who


class ResetReq(BaseModel):
    user: Who
    confirmation: str


class RollbackReq(BaseModel):
    deployment_id: str
    user: Who


@app.get("/state", dependencies=[Depends(token)])
async def state():
    try:
        fp, st = await engine.fingerprint()
        return {"fingerprint": fp, **st, **_live(), "scope": {"tenant": policy.TENANT, "hosts": list(policy.HOSTS)}}
    except (ExecError, OSError) as e:
        raise HTTPException(502, f"device/host state unavailable: {e}")


@app.get("/observe-raw", dependencies=[Depends(token)])
async def observe_raw():
    try:
        return await engine.observe_raw()
    except (ExecError, OSError) as e:
        raise HTTPException(502, f"BIG-IP read failed: {e}")


@app.post("/preflight", dependencies=[Depends(token)])
async def preflight(r: DeployReq):
    fp, st = await engine.fingerprint()
    return {"fingerprint": fp, "checks": await engine.preflight(r.package, st)}


@app.post("/deploy", dependencies=[Depends(token)])
async def deploy(r: DeployReq):
    try:
        return await engine.deploy(r.package, r.approval_id, r.user.model_dump())
    except DeploymentRefused as e:
        raise HTTPException(409, str(e))


@app.post("/rollback", dependencies=[Depends(token)])
async def rollback(r: RollbackReq):
    try:
        return await engine.rollback(r.deployment_id, r.user.model_dump())
    except DeploymentRefused as e:
        raise HTTPException(409, str(e))


@app.post("/validation-action", dependencies=[Depends(token)])
async def validation_action(req: dict):
    try:
        return await engine.validation_action(req)
    except DeploymentRefused as e:
        raise HTTPException(409, str(e))


@app.post("/reset-demo", dependencies=[Depends(token)])
async def reset_demo(r: ResetReq):
    try:
        return await engine.reset_demo(r.user.model_dump(), r.confirmation)
    except DeploymentRefused as e:
        raise HTTPException(409, str(e))


class WindowOpenReq(BaseModel):
    username: str
    password: str
    minutes: int
    grace: int
    reason: str


class WindowCloseReq(BaseModel):
    username: str
    role: str
    reason: str


CONTROL = control.WindowControl(store, BROKER, engine.window_status)


@app.post("/window/open", dependencies=[Depends(token)])
async def window_open(r: WindowOpenReq):
    try:
        return await CONTROL.open(r.username, r.password, r.minutes, r.grace, r.reason)
    except control.ControlError as e:
        raise HTTPException(e.status, str(e))


@app.post("/window/close", dependencies=[Depends(token)])
async def window_close(r: WindowCloseReq):
    try:
        return await CONTROL.close(r.username, r.role, r.reason)
    except control.ControlError as e:
        raise HTTPException(e.status, str(e))


@app.get("/window/broker", dependencies=[Depends(token)])
async def window_broker():
    return await CONTROL.broker_health()


TRAFFICGEN = trafficgen.TrafficgenControl(store, trafficgen.client_from_env(SECRETS), engine.window_status)


class TgStartReq(BaseModel):
    username: str
    preset: str
    confirm: str


class TgStopReq(BaseModel):
    username: str
    confirm: str


@app.get("/trafficgen/status", dependencies=[Depends(token)])
async def trafficgen_status():
    return await TRAFFICGEN.status()


@app.post("/trafficgen/start", dependencies=[Depends(token)])
async def trafficgen_start(r: TgStartReq):
    try:
        return await TRAFFICGEN.start(r.username, r.preset, r.confirm)
    except trafficgen.TrafficgenError as e:
        raise HTTPException(e.status, str(e))


@app.post("/trafficgen/stop", dependencies=[Depends(token)])
async def trafficgen_stop(r: TgStopReq):
    try:
        return await TRAFFICGEN.stop(r.username, r.confirm)
    except trafficgen.TrafficgenError as e:
        raise HTTPException(e.status, str(e))


@app.get("/diagnostics/bigip", dependencies=[Depends(token)])
async def diagnostics_bigip():
    """Read-only BIG-IP health for the control centre: version, AS3, clock skew, REST latency, memory, tenant, VS count."""
    try:
        caps = await engine.capabilities()
        code, vs = await engine.bigip.get("/mgmt/tm/ltm/virtual")
        return {"reachable": True, **caps, "virtual_servers": len((vs or {}).get("items", [])) if code == 200 else None,
                "tenant_present": (await engine.bigip.as3_get_tenant()) is not None}
    except (ExecError, OSError) as e:
        return {"reachable": False, "error": str(e)[:300]}


@app.get("/healthz")
async def healthz():
    return {"status": "ok", **_live(), "tenant": policy.TENANT}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("DEPLOYER_PORT", "8100")))
