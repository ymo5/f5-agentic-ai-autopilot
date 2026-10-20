"""Approval A live findings (2026-10-19, deployment 30096d6a3bbf4ecf -> failed-rolled-back-unverified), reproduced offline.

1. data.bigip_statistics: BIG-IP's REST counters trail the data plane; read once right after the probes they showed only the
   earliest request (sent s3/rag/llm 2/2/2, numberReqs 1/0/0, stats_s3 1/1/1). Fix: re-read until the SAME criteria hold or a
   bounded settle time ends — never relaxed; counters that do not move still fail.
2. The rollback declaration dropped the AS3 document `label`, so the restored device (tenant identical to B2) no longer matched
   its verified state hash. Fix: keep the captured document label/remark.
3. The post-rollback convergence to 'security' probed the mTLS MCP VIPs without a client certificate (TLS handshake alert ->
   ConvergenceTimeout -> failed-rolled-back-unverified). Fix: mtls for the security profile (both rollback paths).
"""
from __future__ import annotations

import asyncio
import copy
import json

import pytest

from conftest import ctx, review  # noqa: F401
from test_data_delivery_inc2 import DD, Lab, dctx, dd_on, deploy, discover, lab_factory, run_checks  # noqa: F401

LIVE = {"sent": {"s3": 2, "rag": 2, "llm": 2}, "reqs": {"s3": 1, "rag": 0, "llm": 0}}


class LaggingCounters:
    """BIG-IP REST statistics that become visible only `stale_reads` reads after the requests (offline model of the lag)."""

    def __init__(self, lab, stale_reads):
        self.lab, self.stale_reads, self.calls, self.first = lab, stale_reads, 0, None

    async def actions(self, req):
        self.calls += 1
        snap = await self.lab.actions(req)
        if self.calls == 1:
            self.first = copy.deepcopy(snap)
            return snap
        if self.calls <= 1 + self.stale_reads:
            stale = copy.deepcopy(self.first)
            stale["members"] = snap["members"]
            return stale
        return snap


def cfg_with(lab, **settle):
    c = lab.cfg()
    c["validation"]["data"].update(settle)
    return c


# ------------------------------------------------------------------ 1. statistics settle
def test_live_failure_reproduced_when_counters_are_read_once(lab_factory):
    lab = lab_factory()
    lag = LaggingCounters(lab, stale_reads=3)
    r = run_checks(lab, cfg=cfg_with(lab, stats_settle_s=0), actions=lag.actions)
    st = r["data.bigip_statistics"]
    assert st["result"] == "fail" and st["observed"]["sent_requests"] == LIVE["sent"]
    assert st["observed"]["virtual_server_http_requests"] == {"s3": 0, "rag": 0, "llm": 0} and st["observed"]["settle"]["samples"] == 1
    for t in ("data.s3_via_front_door", "data.s3_sigv4_enforced", "data.rag_via_front_door", "data.llm_via_front_door"):
        assert r[t]["result"] == "pass", t                          # functional checks passed, exactly as live


def test_lagging_counters_pass_once_they_become_visible(lab_factory):
    lab = lab_factory()
    lag = LaggingCounters(lab, stale_reads=3)
    r = run_checks(lab, cfg=cfg_with(lab, stats_settle_s=5, stats_poll_s=0.05), actions=lag.actions)
    st = r["data.bigip_statistics"]
    assert st["result"] == "pass", st
    assert st["observed"]["virtual_server_http_requests"] == LIVE["sent"] and st["observed"]["settle"]["samples"] == 4
    assert st["observed"]["s3_statistics_delta"] == {"s3_requests": 2, "s3_unsigned": 1, "s3_resp_4xx": 2}


def test_counters_that_never_move_still_fail_after_the_bounded_settle(lab_factory):
    lab = lab_factory(counting=False)                                 # traffic that did not traverse the counted path
    r = run_checks(lab, cfg=cfg_with(lab, stats_settle_s=0.4, stats_poll_s=0.1))
    st = r["data.bigip_statistics"]
    assert st["result"] == "fail" and st["observed"]["settle"]["seconds"] >= 0.4 and st["observed"]["settle"]["samples"] >= 2


def test_partial_counts_matching_the_live_evidence_still_fail(lab_factory):
    lab = lab_factory()

    async def partial(req):                                           # live numbers, frozen: never reaches what was sent
        snap = await lab.actions(req)
        if partial.n:
            for s, n in LIVE["reqs"].items():
                snap["virtual_servers"][s]["http.numberReqs"] = partial.base[s] + n
        else:
            partial.base = {s: v["http.numberReqs"] for s, v in snap["virtual_servers"].items()}
        partial.n += 1
        return snap
    partial.n = 0
    r = run_checks(lab, cfg=cfg_with(lab, stats_settle_s=0.3, stats_poll_s=0.1), actions=partial)
    assert r["data.bigip_statistics"]["result"] == "fail"
    assert r["data.bigip_statistics"]["observed"]["virtual_server_http_requests"] == LIVE["reqs"]


def test_settle_never_relaxes_the_s3_statistics_criteria(lab_factory):
    lab = lab_factory()

    async def no_s3_4xx(req):                                         # requests counted, but the S3 4xx counter never moves
        snap = await lab.actions(req)
        snap["s3_statistics"]["s3_resp_4xx"] = 0
        return snap
    r = run_checks(lab, cfg=cfg_with(lab, stats_settle_s=0.3, stats_poll_s=0.1), actions=no_s3_4xx)
    assert r["data.bigip_statistics"]["result"] == "fail"


# ------------------------------------------------------------------ 2. rollback keeps the AS3 document identity
def test_rollback_keeps_the_document_label_so_the_verified_state_hash_matches(tmp_path, monkeypatch):
    monkeypatch.setenv("AS3_SCHEMA", "unused")
    from autopilot.deployer import engine as E
    from autopilot.deployer.executors import MockBigip, MockHosts
    from autopilot.store import Store
    eng = E.Engine(Store(str(tmp_path / "ap.db")), MockBigip(), MockHosts(), None, mock=True)
    eng.hosts.profile = {h: "security" for h in eng.hosts.profile}
    tenant = {"class": "Tenant", "Shared": {"class": "Application", "template": "shared"}}
    captured = {"class": "ADC", "label": "F5 Agentic AI Autopilot", "AP_AI": tenant}      # what live fingerprint() records
    posted = []
    real_post = eng.bigip.as3_post

    async def capture(decl):
        posted.append(copy.deepcopy(decl))
        return await real_post(decl)
    eng.bigip.as3_post = capture

    async def no_readback(decl):
        return {"verified_objects": 0}
    eng._verify_bigip = no_readback
    asyncio.run(eng._restore({"tenant": captured, "hosts": dict(eng.hosts.profile)}))
    adc = posted[-1]["declaration"]
    assert adc["label"] == "F5 Agentic AI Autopilot" and adc["AP_AI"] == tenant
    # the device's GET document after this POST (id/controls/schemaVersion/updateMode are excluded from the hash)
    after = {k: v for k, v in adc.items() if k not in ("id", "updateMode", "controls", "schemaVersion")}
    assert E.state_hash(after, eng.hosts.profile) == E.state_hash(captured, eng.hosts.profile)


# ------------------------------------------------------------------ 3. post-rollback convergence uses mTLS for 'security'
def test_automatic_rollback_converges_security_with_mtls(dctx):
    from autopilot import validate
    ids = discover(dctx)
    deploy(dctx, ids["delivery"]); deploy(dctx, ids["security"])
    lab = Lab(); cfg = lab.cfg(); cfg["validation"]["data"].update(stats_settle_s=0.2, stats_poll_s=0.05)
    dctx.bigip.member_state["10.50.20.41:8333"] = "offline"              # gate fails -> automatic rollback

    async def gate(profile):
        out = []
        await validate.data_checks(cfg, lambda req: dctx.engine.validation_action(req, internal=True),
                                   lambda t, ok, o, e, skipped=False: out.append({"test": t, "result": "skipped" if skipped else "pass" if ok else "fail"}))
        return out
    seen = []

    async def fake_converge(profile, tenant_present, changed_at, mtls=False):
        seen.append({"profile": profile, "mtls": mtls}); return {"converged": True}
    dctx.engine.validator, dctx.engine._converge = gate, fake_converge
    dctx.engine.cfg, dctx.engine.probes = dctx.engine.cfg or {"design": {}}, dctx.engine.probes or object()
    try:
        d = deploy(dctx, ids["data"])
    finally:
        lab.close()
    assert d["status"] == "failed-rolled-back", d
    assert {"profile": "security", "mtls": True} in seen
    assert any(s["step"] == "converge[rollback → security]" and s["status"] == "ok" for s in d["steps"])
