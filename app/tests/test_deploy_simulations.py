"""Deployment failure simulations (mock executors; real engine, policy, approvals). A simulated deployment is labelled
mode=mock and is never reported as a real one."""
from __future__ import annotations

import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import discover, review  # noqa: E402
from test_wave2a import a2a, trace_b, world  # noqa: E402,F401
from test_wave3_placement import AGENT_C, LAB_SCAN  # noqa: E402


def approve(ctx, pid):
    review(ctx, pid)
    assert ctx.ap.post(f"/api/packages/{pid}/decision", json={"decision": "approved", "comment": "sim"}).status_code == 200


def test_rollback_failure_is_reported_as_such_never_as_success(ctx):
    ids = discover(ctx)
    approve(ctx, ids["delivery"])
    ctx.bigip.drop_objects.add("mcp_fraud_intel")          # verification fails -> rollback
    ctx.bigip.fail_on = {"delete"}                           # ... and the rollback itself fails
    d = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()
    assert d["status"] == "failed-rollback-failed" and d["mode"] == "mock"
    pk = next(p for p in ctx.ap.get("/api/packages").json() if p["id"] == ids["delivery"])
    diag = pk["deployments"][0]["diagnosis"]
    assert diag["rollback"].startswith("FAILED") and "Reset Demo Environment" in diag["next_actions"]


def test_as3_timeout_fails_safely_and_rolls_back(ctx):
    ids = discover(ctx)
    approve(ctx, ids["delivery"])
    orig = ctx.bigip.as3_post

    async def slow(decl):
        if decl.get("action") == "deploy":
            raise asyncio.TimeoutError("AS3 deploy did not answer within the timeout (simulated)")
        return await orig(decl)
    ctx.bigip.as3_post = slow
    d = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()
    assert d["status"].startswith("failed") and d["status"] != "succeeded" and d["mode"] == "mock"
    assert any(s["status"] == "failed" for s in d["steps"])


def test_configuration_level_reports_failed_after_missing_objects(ctx):
    ids = discover(ctx)
    approve(ctx, ids["delivery"])
    ctx.bigip.drop_objects.add("mcp_fraud_intel")
    assert ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()["status"] == "failed-rolled-back"
    v = {l["key"]: l for l in ctx.viewer.get("/api/verification").json()["levels"]}
    # rolled back: the current configuration is not run; the failed read-back is preserved as labelled history (L1c)
    assert v["configuration"]["result"] == "not_run" and v["configuration"]["history"]["result"] == "failed"
    assert "historical evidence" in v["configuration"]["detail"] and v["observability"]["result"] == "not_run"


def test_deployer_accepts_a_multi_agent_package(world, monkeypatch):
    from autopilot import web
    d = web.CFG["design"]
    monkeypatch.setitem(d["front_doors"], "a2a", [dict(d["front_doors"]["a2a"]), {"name": "agent-c.aplab.internal", "vip": "10.50.10.103"}])
    monkeypatch.setitem(d["profiles"]["baseline"]["dns"], "agent-c.aplab.internal", "10.50.20.40")
    world.run(LAB_SCAN + [a2a("10.50.20.40", port=9100, card=AGENT_C)], [trace_b()], name="multi-agent deploy")
    assert world.op.post("/api/recommend").status_code == 200
    pid = next(p["id"] for p in world.viewer.get("/api/packages").json() if p["kind"] == "delivery")
    approve(world, pid)
    r = world.ap.post(f"/api/packages/{pid}/deploy").json()
    assert r["status"] == "succeeded" and r["mode"] == "mock", r
    tenant = world.bigip.tenant
    apps = [k for k in tenant if k.startswith("a2a_")]
    assert len(apps) == 2 and any(k.startswith("a2a_receptionist_agent") for k in apps)
    vips = {tenant[k]["service"]["virtualAddresses"][0] for k in apps}
    assert vips == {"10.50.10.100", "10.50.10.103"}
