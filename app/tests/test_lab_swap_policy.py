"""LAB-ONLY swap policy (owner decision 2026-10-19): for devices listed in autopilot.yaml lab_policy.swap_informational_devices
(BIG-IP_C 192.0.2.16), swap utilisation is reported but never fails, warns or is required — in the deployer preflight and the
placement health evaluation. Genuine health failures still block. Without the key (production default) nothing changes."""
from __future__ import annotations

import asyncio
import time

import pytest

LAB = "192.0.2.16"
LAB_CFG = {"observe": {"bigip_mgmt": LAB}, "lab_policy": {"swap_informational_devices": [LAB]}}
AS3 = {"class": "AS3", "action": "deploy", "declaration": {"class": "ADC", "schemaVersion": "3.56.0", "AP_AI": {"class": "Tenant"}}}


def engine(cfg=None, host=LAB):
    from autopilot.deployer.engine import Engine
    from autopilot.deployer.executors import MockBigip, MockHosts
    from autopilot.store import Store
    import tempfile, os
    bigip = MockBigip()
    bigip.host = host
    return Engine(Store(os.path.join(tempfile.mkdtemp(), "ap.db")), bigip, MockHosts(), None, mock=True, cfg=cfg)


def caps(swap=99.0, other=80.0, rest=0.3, memory=True):
    return {"bigip_version": "21.1.0.3", "as3_version": "3.56.0", "self_ips": ["10.50.10.10", "10.50.20.10"],
            "certificates": ["/Common/aplab-ca.crt", "/Common/aplab-wildcard.crt"], "clock_skew_s": 1.0, "rest_latency_s": rest,
            "memory": {"other_used_pct": other, "swap_used_pct": swap, "other_total_mb": 2800, "swap_total_mb": 1000} if memory else None}


def preflight(eng, **kw):
    pkg = {"assessment_id": "a", "body": {"as3": AS3, "dependencies": []}}
    checks = asyncio.run(eng.preflight(pkg, {"capabilities": caps(**kw), "tenant": None, "hosts": {}}))
    return {c["check"]: c for c in checks}


def ok_all(ch):
    return all(c["ok"] for c in ch.values())


# ------------------------------------------------------------------ deployer preflight
@pytest.mark.parametrize("swap", [0.0, 46.0, 75.0, 77.2, 95.0, 99.9, 100.0])
def test_swap_alone_never_blocks_the_lab_device(swap):
    ch = preflight(engine(LAB_CFG), swap=swap)
    m = ch["resource.control_plane_memory"]
    assert m["ok"] and m["level"] == "pass" and ok_all(ch), m          # no fail, and no warning either
    assert f"swap {swap}%" in m["detail"] and "swap informational — lab policy for 192.0.2.16" in m["detail"]


def test_production_default_unchanged_without_the_lab_key():
    ch = preflight(engine(None), swap=99.0)
    assert not ch["resource.control_plane_memory"]["ok"]                 # default: swap >= 95 % still fails
    ch = preflight(engine(None), swap=80.0)
    assert ch["resource.control_plane_memory"]["ok"] and ch["resource.control_plane_memory"]["level"] == "warn"


def test_policy_is_scoped_to_the_listed_device_only():
    ch = preflight(engine(LAB_CFG, host="192.0.2.99"), swap=99.0)     # another BIG-IP is not covered
    assert not ch["resource.control_plane_memory"]["ok"]


@pytest.mark.parametrize("kw,check", [({"other": 95.0}, "resource.control_plane_memory"),      # control-plane exhaustion
                                      ({"other": 99.0, "swap": 10.0}, "resource.control_plane_memory"),
                                      ({"memory": False}, "resource.control_plane_memory"),    # memory statistics unreadable
                                      ({"rest": 10.0}, "resource.rest_latency")])               # management API unresponsive
def test_genuine_health_failures_still_block_the_lab_device(kw, check):
    ch = preflight(engine(LAB_CFG), **kw)
    assert not ch[check]["ok"] and not ok_all(ch)


def test_as3_unavailable_still_blocks_the_lab_device():
    eng = engine(LAB_CFG)
    pkg = {"assessment_id": "a", "body": {"as3": AS3, "dependencies": []}}
    c = caps(swap=99.0); c["as3_version"] = None
    ch = {x["check"]: x for x in asyncio.run(eng.preflight(pkg, {"capabilities": c, "tenant": None, "hosts": {}}))}
    assert not ch["template.as3_version"]["ok"]


# ------------------------------------------------------------------ placement health (advisory) mirrors the deployer
def device(swap, other=80.0, mgmt=LAB):
    f = lambda v, st="observed": {"value": v, "status": st, "evidence": []}
    return {"id": "dev1", "evidence_id": "e1", "provisioned": f({"ltm": "nominal"}), "as3_installed": f(True), "mgmt": f(mgmt),
            "ha": {"status": "observed", "value": {"failover_state": "active", "mode": "standalone"}},
            "health": {"status": "observed", "value": {"control_plane_memory_pct": other, "swap_pct": swap, "rest_latency_s": 0.3,
                                                       "sampled_at": time.time()}, "evidence_state": "observed"}}


def health(d, cfg):
    from autopilot import placement, placement_policy
    pol = placement_policy.load(cfg)
    return next(c for c in placement._device_checks(d, pol, time.time()) if c["check"] == "health")


@pytest.mark.parametrize("swap", [75.0, 95.0, 100.0])
def test_placement_never_fails_or_warns_on_swap_for_the_lab_device(swap):
    h = health(device(swap), LAB_CFG)
    assert h["result"] == "pass" and not h.get("warnings"), h


def test_placement_default_and_other_devices_unchanged():
    assert health(device(99.0), {"observe": {"bigip_mgmt": LAB}})["result"] == "fail"              # no lab key
    assert health(device(99.0, mgmt="192.0.2.99"), LAB_CFG)["result"] == "fail"                  # not listed


def test_placement_control_plane_exhaustion_still_fails_on_the_lab_device():
    assert health(device(10.0, other=96.0), LAB_CFG)["result"] == "fail"


def test_default_policy_digest_is_unchanged_without_the_lab_key():
    from autopilot import placement_policy
    assert placement_policy.load(None)["digest"] == placement_policy.load({"observe": {}})["digest"]
    assert placement_policy.load(LAB_CFG)["digest"] != placement_policy.load(None)["digest"]       # lab policy is visible
