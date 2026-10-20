"""Phase 2 — the REAL BIG-IP_C capture (minimized, sanitized; see fixtures/wave3/README.md) through the parser and the
placement advisory. Offline: no network (socket guard); evaluation time is fixed relative to the capture time."""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_wave2a import no_network, trace_b, world  # noqa: E402,F401
from test_wave3_placement import LAB_SCAN, POLICY, svc  # noqa: E402

FX = pathlib.Path(__file__).resolve().parent / "fixtures" / "wave3" / "bigip_c_real_capture_min.json"
REAL = json.loads(FX.read_text())
CAPTURED = REAL["_meta"]["collected_at"]


def model():
    from autopilot.sources import observe
    return observe.normalize(REAL)


def real_device():
    from autopilot import placement
    m = model()
    return placement.device_from_model("bigip:192.0.2.16", m, mgmt="192.0.2.16", evidence_id="ev-real-bigip-c",
                                       origin="real capture (Phase 1)", mgmt_status="observed")


def plan(now):
    from autopilot import identity, placement, web
    idn = identity.reconcile(web.STORE)
    return placement.evaluate(idn, [real_device()], callers=placement.callers_from_store(web.STORE, idn), member_policy=POLICY, now=now)


# ------------------------------------------------------------------ parser against real response structures
def test_real_identity_provisioning_and_as3():
    m = model()
    assert m["device"]["version"] == "21.1.0.3" and m["device"]["build"] == "0.0.20" and m["device"]["edition"] == "Point Release 3"
    assert m["device"]["provisioned"] == {"ltm": "nominal"} and m["device"]["as3_installed"] is True and m["as3_version"] == "3.56.0"
    assert m["device_ref"] == {"label": "BIG-IP_C", "mgmt": "192.0.2.16"} and m["device"]["hostname"] is None   # host name not in the share


def test_real_self_ips_subnets_and_empty_routes():
    m = model()
    nets = {n["name"]: n for n in m["self_ip_networks"]}
    assert nets["/Common/self_agent"]["network"] == "10.50.10.10/24" and nets["/Common/self_backend"]["network"] == "10.50.20.10/24"
    assert all(n["route_domain"] == 0 and n["floating"] is False and n["traffic_group"] == "/Common/traffic-group-local-only" for n in nets.values())
    assert m["routes"] == [] and m["evidence_state"]["routes"] == "observed"        # empty list = observed: no static routes


def test_real_ha_is_active_standalone_not_a_pair():
    m = model()
    assert m["ha"] == {"failover_state": "active", "summary": "1/1 active", "mode": "standalone", "sync_failover_groups": 0, "device_group": None}
    groups = [(g["fullPath"], g["type"]) for g in REAL["device_group"]["body"]["items"]]
    assert groups == [("/Common/device_trust_group", "sync-only"), ("/Common/gtm", "sync-only")]


def test_real_health_values_and_methods():
    from autopilot.deployer import engine
    m = model()
    h = m["health"]
    assert (h["control_plane_memory_pct"], h["swap_pct"], h["host_memory_pct_info"], h["cpu_pct"], h["rest_latency_s"]) == (75.0, 91.1, 33.1, 10.5, 1.191)
    assert h["sampled_at"] == CAPTURED and h["rest_latency_method"] == "slowest of 21 read-only GETs in this collection"
    assert REAL["_meta"]["timings_s"]["pool_stats"] == 1.191                       # the slowest single GET
    pf = engine._memory(REAL["memory"]["body"])                                   # preflight's own arithmetic on the real body
    assert (pf["other_used_pct"], pf["swap_used_pct"]) == (75.0, 91.1)


def test_real_evidence_states_distinguish_missing_collections():
    st = model()["evidence_state"]
    assert {k: st[k] for k in ("self_ip_networks", "routes", "ha", "health", "cpu", "as3", "provision")} == dict.fromkeys(
        ("self_ip_networks", "routes", "ha", "health", "cpu", "as3", "provision"), "observed")
    assert st["virtuals"] == "missing" and st["pools"] == "missing"                # not in the share: never "observed: none"


# ------------------------------------------------------------------ placement on the real device
def test_real_bigip_c_selected_with_swap_warning_when_fresh(world, no_network):
    from autopilot import placement
    world.run(LAB_SCAN, [trace_b()], name="real evidence")
    p = plan(CAPTURED + 300)
    assert p["status"] == "decided"
    for name in ("Risk Assessment Agent", "risk-scoring", "fraud-intel"):
        s = svc(p, name)
        assert s["selected"]["device"] == "bigip:192.0.2.16"
        e = s["eligible"][0]
        hc = next(c for c in e["checks"] if c["check"] == "health")
        assert hc["result"] == "pass" and hc["warnings"] == ["swap_pct 91.1 >= 75.0 (warn)"] and e["rank_key"]["health_warnings"] == 1
        ex = s["selected"]["explanation"]
        assert "Health warning (not a failure): swap_pct 91.1 >= 75.0 (warn)." in ex["unverified_assumptions"]
        assert placement.L3_ONLY in ex["unverified_assumptions"] and ex["deployment_readiness"] == placement.NOT_PREFLIGHT
        assert any("existing BIG-IP coverage not evaluated" in u for u in s["uncertainty"])
    b = svc(p, "Risk Assessment Agent")["selected"]["pool_members"]
    assert [m["address"] for m in b] == ["10.50.20.22:9000"]


def test_real_capture_goes_stale_after_30_minutes(world, no_network):
    world.run(LAB_SCAN, [trace_b()], name="real stale")
    p = plan(CAPTURED + 1801)
    s = svc(p, "fraud-intel")
    hc = next(c for c in s["unverified"][0]["checks"] if c["check"] == "health")
    assert p["status"] == "abstained" and hc["evidence_state"] == "stale" and s["selected"] is None


def test_real_vips_stay_unverified_without_virtual_server_evidence(world, no_network):
    from autopilot import advisory, identity, placement, web
    world.run(LAB_SCAN, [trace_b()], name="real vips")
    idn = identity.reconcile(web.STORE)
    a = advisory.advise(idn, [real_device()], advisory.environment_from_cfg(web.CFG), callers=placement.callers_from_store(web.STORE, idn),
                        member_policy=POLICY, now=CAPTURED + 300, deploy_targets=["192.0.2.16"])
    for p in a["proposals"]:
        v = p["proposal"]["vip"]
        checks = {c["check"]: c for c in v["checks"]}
        assert v["reservation"] == "unreserved" and v["verification"] == "unverified"
        assert checks["address_conflict"]["result"] == "unknown" and "not collected" in checks["address_conflict"]["detail"]
        assert checks["on_device_subnet"]["result"] == "pass" and "inside self IP subnet 10.50.10.0/24 (/Common/self_agent)" == checks["on_device_subnet"]["detail"]
        assert p["proposal"]["deployment_engine"]["supported"] is True
    assert {p["service"]["name"]: p["proposal"]["vip"]["address"] for p in a["proposals"]} == {
        "Risk Assessment Agent": "10.50.10.100", "risk-scoring": "10.50.10.101", "fraud-intel": "10.50.10.102"}


def test_share_v2_minimization_is_parser_lossless(tmp_path):
    """observe-share.py v2 output (this fixture) parses identically when re-run through the script."""
    import subprocess
    root = pathlib.Path(__file__).resolve().parents[2]
    out = tmp_path / "again.json"
    subprocess.run([sys.executable, "-I", str(root / "scripts" / "observe-share.py"), str(FX), str(out)], check=True, capture_output=True)
    from autopilot.sources import observe
    assert observe.normalize(json.loads(out.read_text())) == model()
    assert len(FX.read_bytes()) < 20000
