"""Wave 3 M2 — read-only placement advisory: health policy, VIP candidates, provenance, identity mapping, package comparison.

Offline only: patched discovery inputs, the stored lab Observe model and synthetic fixtures. A socket guard proves no
network access; table counts and package hashes prove the advisory changes nothing.
"""
from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import INTEL_TOOLS  # noqa: E402
from test_wave2a import a2a, mcp, no_network, trace_b, world  # noqa: E402,F401  (fixtures + helpers)
from test_wave3_placement import AGENT_C, LAB, LAB_SCAN, NOW, POLICY, TWO, fixture_devices, lab_device  # noqa: E402

ENV = TWO["environment"]


def advise(devices, env=None, ipam=None, **kw):
    from autopilot import advisory, identity, placement, web
    idn = identity.reconcile(web.STORE)
    return advisory.advise(idn, devices, env or ENV, callers=placement.callers_from_store(web.STORE, idn),
                           telemetry=advisory.telemetry_from_store(web.STORE, idn),
                           packages=advisory.packages_from_store(web.STORE, idn["assessment_id"]), ipam=ipam, member_policy=POLICY,
                           **{"now": NOW, **kw})


def prop(a, name):
    return next(p for p in a["proposals"] if p["service"]["name"] == name)


def prov(p, obj):
    return [x for x in p["proposal"]["provenance"] if x["object"] == obj]


def lab_env():
    from autopilot import advisory, web
    return advisory.environment_from_cfg(web.CFG)


# ------------------------------------------------------------------ 1. versioned health policy, reconciled with preflight
def test_default_health_policy_mirrors_deployer_preflight_without_changing_it():
    from autopilot import placement_policy as pp
    from autopilot.deployer import engine
    p = pp.load({})
    assert p["version"] == "placement-health/v1.1" and p["origin"] == "built-in" and len(p["digest"]) == 16
    assert p["max_sample_age_s"] == 1800 and pp.load({"placement": {"health_policy": "placement-health/v1"}})["max_sample_age_s"] is None
    assert pp.PREFLIGHT["control_plane_memory_pct"]["fail"] == engine.MEMORY_FAIL_PCT
    assert pp.PREFLIGHT["swap_pct"] == {"fail": engine.SWAP_FAIL_PCT, "warn": engine.SWAP_WARN_PCT, "check": "resource.control_plane_memory"}
    assert (pp.PREFLIGHT["rest_latency_s"]["fail"], pp.PREFLIGHT["rest_latency_s"]["warn"]) == (engine.REST_FAIL_S, engine.REST_WARN_S)
    for k, pf in pp.PREFLIGHT.items():          # v1 is exactly preflight's fail/warn levels
        assert (p["metrics"][k]["fail"], p["metrics"][k]["warn"]) == (pf["fail"], pf["warn"]) and p["metrics"][k]["required"]
    assert p["metrics"]["cpu_pct"]["fail"] is None      # preflight has no CPU check: placement never fails on CPU


def test_health_policy_overrides_may_only_be_stricter():
    from autopilot import placement_policy as pp
    s = pp.load({"placement": {"health_policy": {"base": "placement-health/v1.1", "metrics": {"swap_pct": {"warn": 50, "fail": 80}},
                                                 "max_sample_age_s": 600}}})
    assert s["version"] == "placement-health/v1.1+override" and s["metrics"]["swap_pct"]["fail"] == 80 and s["max_sample_age_s"] == 600
    with pytest.raises(pp.PolicyError):          # freshness may only be shortened
        pp.load({"placement": {"health_policy": {"base": "placement-health/v1.1", "max_sample_age_s": 3600}}})
    assert s["digest"] != pp.load({})["digest"]
    for bad in ({"swap_pct": {"fail": 99}}, {"rest_latency_s": {"fail": None}}, {"bogus": {"fail": 1}}, {"swap_pct": {"warn": 96}}):
        with pytest.raises(pp.PolicyError):
            pp.load({"placement": {"health_policy": {"metrics": bad}}})
    with pytest.raises(pp.PolicyError):
        pp.load({"placement": {"health_policy": "placement-health/v0"}})


def test_stricter_policy_changes_the_decision(world, no_network):
    from autopilot import placement_policy as pp
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="strict")

    def swap(m):
        m["bigip-a"]["health"]["swap_pct"] = 85
    strict = pp.load({"placement": {"health_policy": {"metrics": {"swap_pct": {"warn": 50, "fail": 80}}}}})
    assert prop(advise(fixture_devices(swap)), "fraud-intel")["proposal"]["device"] == "bigip-a"          # v1: warning only
    assert prop(advise(fixture_devices(swap), policy=strict), "fraud-intel")["proposal"]["device"] == "bigip-b"


# ------------------------------------------------------------------ 2. VIP candidates and address conflicts
def test_configured_vip_conflicting_with_an_observed_virtual_is_skipped(world, no_network):
    world.run(LAB_SCAN, [trace_b()], name="vip conflict")

    def occupy(m):
        m["bigip-a"]["virtuals"].append({"name": "/Other/app/vs_x", "address": "10.50.10.101", "port": 8443, "pool": None})
    a = advise(fixture_devices(occupy))
    vip = prop(a, "risk-scoring")["proposal"]["vip"]
    assert vip["skipped"][0]["address"] == "10.50.10.101" and "virtual server /Other/app/vs_x" in vip["skipped"][0]["reasons"][0]
    assert vip["address"] == "10.50.10.97" and vip["source"].startswith("lowest free address in approved pool 10.50.10.96/28")
    assert prop(a, "Risk Assessment Agent")["proposal"]["vip"]["address"] == "10.50.10.100"   # its own configured VIP
    assert prop(a, "fraud-intel")["proposal"]["vip"]["address"] == "10.50.10.102"
    used = [p["proposal"]["vip"]["address"] for p in a["proposals"] if p["proposal"]]
    assert len(used) == len(set(used))                                                       # never proposed twice


def test_self_ip_virtual_and_endpoint_conflicts_and_pool_exhaustion(world, no_network):
    world.run([a2a("10.50.30.41", port=9100, card=AGENT_C)], [], name="conflicts")

    def busy(m):
        m["bigip-b"]["virtuals"].append({"name": "/Other/app/vs_y", "address": "10.50.30.9", "port": 443, "pool": None})
    env = copy.deepcopy(ENV)
    env["vip_pools"] = [{"device": "bigip-b", "network": "10.50.30.8/30", "source": "test pool"}]       # hosts .9 and .10
    v = prop(advise(fixture_devices(busy), env), AGENT_C["name"])["proposal"]["vip"]
    assert v["address"] is None and v["label"] == "No VIP candidate" and "every address" in v["reason"]
    reasons = {s["address"]: s["reasons"][0] for s in v["skipped"]}
    assert "virtual server /Other/app/vs_y" in reasons["10.50.30.9"] and "self IP /Common/self_robot" in reasons["10.50.30.10"]
    env["vip_pools"] = [{"device": "bigip-b", "network": "10.50.30.40/30", "source": "test pool"}]      # hosts .41 (Agent C) and .42
    v = prop(advise(fixture_devices(busy), env), AGENT_C["name"])["proposal"]["vip"]
    assert v["address"] == "10.50.30.42" and "discovered endpoint 10.50.30.41:9100" in v["skipped"][0]["reasons"][0]


def test_no_vip_pool_for_the_selected_device(world, no_network):
    world.run([a2a("10.50.30.40", port=9100, card=AGENT_C)], [], name="no pool")
    env = copy.deepcopy(ENV)
    env["vip_pools"] = [p for p in env["vip_pools"] if p["device"] != "bigip-b"]
    v = prop(advise(fixture_devices(), env), AGENT_C["name"])["proposal"]["vip"]
    assert v["address"] is None and v["reason"] == "no approved VIP pool is configured for bigip-b"


# ------------------------------------------------------------------ 3. missing / present IPAM
def test_without_ipam_every_vip_is_unreserved_and_unverified(world, no_network):
    world.run(LAB_SCAN + [a2a("10.50.30.40", port=9100, card=AGENT_C)], [trace_b()], name="no ipam")
    a = advise(fixture_devices())
    assert a["ipam"]["authoritative"] is False and "unreserved, unverified" in a["ipam"]["statement"]
    vips = [p["proposal"]["vip"] for p in a["proposals"]]
    assert len(vips) == 4 and all(v["reservation"] == "unreserved" and v["verification"] == "unverified" for v in vips)
    assert all(next(c for c in v["checks"] if c["check"] == "ipam")["result"] == "unknown" for v in vips)
    assert all(v["label"] == "Proposed VIP candidate — unreserved, unverified" for v in vips)
    assert prop(a, AGENT_C["name"])["proposal"]["vip"]["address"] == "10.50.10.115"   # .113/.114 are observed virtual servers


def test_authoritative_ipam_confirms_or_rejects_but_never_reserves(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="ipam")
    ipam = {"provider": "fixture-ipam", "authoritative": True, "evidence_id": "fx-ipam", "available": ["10.50.10.96/28"], "allocated": {}}
    v = prop(advise(fixture_devices(), ipam=ipam), "fraud-intel")["proposal"]["vip"]
    assert v["verification"] == "ipam-confirmed-available" and v["reservation"] == "unreserved" and "IPAM reports it available" in v["label"]
    ipam["allocated"] = {"10.50.10.102": "team-x"}
    v = prop(advise(fixture_devices(), ipam=ipam), "fraud-intel")["proposal"]["vip"]
    assert v["skipped"][0] == {"address": "10.50.10.102", "reasons": ["allocated in fixture-ipam to team-x"]} and v["address"] == "10.50.10.97"
    v = prop(advise(fixture_devices(), ipam={**ipam, "authoritative": False}), "fraud-intel")["proposal"]["vip"]
    assert v["verification"] == "unverified"


# ------------------------------------------------------------------ 4. unknown subnet / route information
def test_lab_evidence_gives_provisional_proposals_with_unverified_provenance(world, no_network):
    world.run(LAB_SCAN, [trace_b()], name="lab")
    a = advise([lab_device()], lab_env())
    assert a["status"] == "abstained" and a["deployable"] is False and a["advisory"] is True
    p = prop(a, "risk-scoring")
    pr = p["proposal"]
    assert pr["status"] == "provisional" and pr["device"] == "bigip:192.0.2.16" and pr["virtual_server"] == "10.50.10.101:443"
    assert prov(p, "target_bigip")[0]["status"] == "unverified" and {x["status"] for x in prov(p, "pool_member")} == {"unverified"}
    sub = next(c for c in pr["vip"]["checks"] if c["check"] == "on_device_subnet")
    assert sub["result"] == "unknown" and "self IP subnets not recorded" in sub["detail"]
    assert pr["vip"]["source"] == "configured assignment autopilot.yaml design.front_doors.mcp.risk-scoring"
    b = prop(a, "Risk Assessment Agent")["proposal"]
    assert b["pool_members"] == ["10.50.20.22:9000"] and b["virtual_server"] == "10.50.10.100:443"


def test_abstaining_on_two_unverified_devices_lists_the_alternative(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="two unverified")

    def strip(m):
        for d in m.values():
            d.pop("health")
    p = prop(advise(fixture_devices(strip)), "fraud-intel")
    assert p["decision"] == "abstain" and p["proposal"]["device"] == "bigip-a" and [x["device"] for x in p["alternatives"]] == ["bigip-b"]
    alt = p["alternatives"][0]["vip"]
    assert p["proposal"]["vip"]["address"] == "10.50.10.102" and alt["address"] == "10.50.10.115"   # .102 is outside bigip-b's pool
    assert "outside bigip-b's approved pool" in alt["skipped"][0]["reasons"][0] and alt["verification"] == "unverified"


# ------------------------------------------------------------------ 5. provenance of every proposed object
def test_provenance_covers_vip_members_monitor_persistence_tls_and_target(world, no_network):
    world.run(LAB_SCAN, [trace_b()], name="provenance")
    a = advise(fixture_devices())
    rs = prop(a, "risk-scoring")
    objs = {x["object"] for x in rs["proposal"]["provenance"]}
    assert {"target_bigip", "virtual_address", "virtual_port", "pool_member", "monitor", "persistence", "tls_client_side", "snat",
            "tenant", "application"} <= objs
    assert prov(rs, "target_bigip")[0]["status"] == "inferred" and prov(rs, "target_bigip")[0]["evidence_ids"] == ["fx-bigip-a"]
    assert {x["status"] for x in prov(rs, "pool_member")} == {"observed"} and all(x["evidence_ids"] for x in prov(rs, "pool_member"))
    per = prov(rs, "persistence")[0]
    assert per["value"] == "universal (Mcp-Session-Id iRule)" and per["status"] == "observed" and "2025-11-25" in per["rule"]
    assert prov(prop(a, "fraud-intel"), "persistence")[0]["value"] is None                  # single member
    assert prov(rs, "monitor")[0]["value"] == "mon_mcp" and prov(prop(a, "Risk Assessment Agent"), "monitor")[0]["value"] == "mon_a2a"
    tls = prov(rs, "tls_client_side")[0]
    assert tls["value"] == "tls_server (certificate /Common/aplab-wildcard.crt)" and tls["status"] == "configured" and "mtls" in tls["rule"]
    assert "A2A front doors keep server TLS" in prov(prop(a, "Risk Assessment Agent"), "tls_client_side")[0]["rule"]
    statuses = {x["status"] for p in a["proposals"] for x in p["proposal"]["provenance"]}
    assert statuses <= {"observed", "inferred", "configured", "unknown", "unverified"}


def test_persistence_is_undetermined_without_telemetry(world, no_network):
    world.run([mcp("10.50.20.31"), mcp("10.50.20.32")], [], name="no telemetry")
    per = prov(prop(advise(fixture_devices()), "risk-scoring"), "persistence")[0]
    assert per["value"] == "undetermined" and per["status"] == "unknown"


# ------------------------------------------------------------------ 6. canonical identity → endpoints → proposed service
def test_canonical_service_mappings(world, no_network):
    world.run(LAB_SCAN, [trace_b()], name="mapping")
    a = advise(fixture_devices())
    m = {x["service"]["name"]: x for x in a["mappings"]}
    b = m["Risk Assessment Agent"]
    assert len(b["instances"]) == 1 and [e["address"] for e in b["instances"][0]["endpoints"]] == ["10.50.10.22:9000", "10.50.20.22:9000"]
    assert {e["address"]: e["proposed_member"] for e in b["instances"][0]["endpoints"]} == {"10.50.10.22:9000": False, "10.50.20.22:9000": True}
    assert b["proposed"] == {"status": "selected", "device": "bigip-a", "application": "a2a_risk_assessment_agent",
                             "virtual_server": "10.50.10.100:443", "pool_members": ["10.50.20.22:9000"]}
    rs = m["risk-scoring"]
    assert len(rs["instances"]) == 2 and all(e["proposed_member"] for i in rs["instances"] for e in i["endpoints"])
    assert rs["proposed"]["application"] == "mcp_risk_scoring"


def test_unresolved_identity_maps_to_no_service(world, no_network):
    world.run([a2a("10.50.10.22"), a2a("10.50.10.23")], [], name="twins")
    a = advise(fixture_devices())
    assert [x["proposed"]["status"] for x in a["mappings"]] == ["ineligible", "ineligible"]
    assert all(p["proposal"] is None for p in a["proposals"])


# ------------------------------------------------------------------ 7. comparison with the configured package (read-only)
def _pkg_fingerprint(store):
    return [(r["id"], hashlib.sha256((r["body"] + r["target"]).encode()).hexdigest())
            for r in store.db.execute("SELECT id, body, target FROM package ORDER BY id")]


def test_lab_comparison_agrees_on_values_and_flags_the_unverified_target(world, no_network):
    from autopilot import advisory, web
    world.run(LAB_SCAN, [trace_b()], name="cmp lab")
    assert world.op.post("/api/recommend").status_code == 200
    web.STORE.add_evidence("observe", "bigip-icontrol-rest (offline fixture)", "fixture", {"origin": "fixture", "model": LAB["model"]})
    tables = [r[0] for r in web.STORE.db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    before = ({t: web.STORE.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}, _pkg_fingerprint(web.STORE),
              web.STORE.db.total_changes)
    a = advisory.build(web.STORE, web.CFG)
    after = ({t: web.STORE.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}, _pkg_fingerprint(web.STORE),
             web.STORE.db.total_changes)
    assert before == after
    C = a["comparison"]
    assert {p["kind"] for p in C["packages_compared"]} == {"delivery", "security"}
    kinds = {(d["field"], d["kind"]) for d in C["disagreements"]}
    assert kinds == {("target_bigip", "advisory_abstains")}, C["disagreements"]
    assert C["agreements"] > 0
    assert all("not verified by evidence" in d["explanation"] for d in C["disagreements"])


def test_two_device_comparison_reports_target_and_missing_service(world, no_network):
    from autopilot import advisory, web
    world.run(LAB_SCAN + [a2a("10.50.30.40", port=9100, card=AGENT_C)], [trace_b()], name="cmp two")
    assert world.op.post("/api/recommend").status_code == 200
    fp = _pkg_fingerprint(web.STORE)
    a = advisory.build(web.STORE, web.CFG, extra_devices=fixture_devices(), environment=ENV, now=NOW)
    assert _pkg_fingerprint(web.STORE) == fp
    d = a["comparison"]["disagreements"]
    tgt = [x for x in d if x["field"] == "target_bigip"]
    assert tgt and all(x["kind"] == "difference" and x["explanation"] == "different target device" for x in tgt)
    miss = [x for x in d if x["kind"] == "missing_from_package"]
    assert [x["service"] for x in miss] == [AGENT_C["name"]] and miss[0]["advisory_value"] == "10.50.10.115:443"
    assert not [x for x in d if x["field"] in ("virtual_server", "pool_members", "monitor", "persistence", "tls")], d


# ------------------------------------------------------------------ 8. API: read-only, viewer, no network
def test_advisory_api_is_read_only_and_viewer_accessible(world, no_network):
    from autopilot import web
    world.run(LAB_SCAN, [trace_b()], name="api")
    world.op.post("/api/recommend")
    fp, ch = _pkg_fingerprint(web.STORE), web.STORE.db.total_changes
    r = world.viewer.get("/api/recommendations/advisory")
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["advisory"] is True and a["deployable"] is False and a["engine"]["llm"] is False and a["engine"]["network"] is False
    assert a["summary"]["devices"] == 0 and a["status"] == "abstained"             # no Observe evidence in this assessment
    assert all(p["proposal"] is None and "no BIG-IP device is recorded" in p["reasons"][-1] for p in a["proposals"] if p["eligibility"] == "eligible")
    assert _pkg_fingerprint(web.STORE) == fp and web.STORE.db.total_changes == ch
    assert world.anon.get("/api/recommendations/advisory").status_code == 401
    assert world.viewer.get("/api/recommendations/advisory?assessment=nope").status_code == 404
    assert world.op.post("/api/recommendations/advisory").status_code == 405


def test_advisory_is_deterministic(world, no_network):
    world.run(LAB_SCAN + [a2a("10.50.30.40", port=9100, card=AGENT_C)], [trace_b()], name="det")
    x, y = advise(fixture_devices()), advise(list(reversed(fixture_devices())))
    assert json.dumps(x, sort_keys=True) == json.dumps(y, sort_keys=True)


def test_advisory_module_has_no_network_llm_package_or_write_paths():
    src = (pathlib.Path(__file__).resolve().parents[1] / "autopilot" / "advisory.py").read_text()
    for banned in ("httpx", "socket", "requests", "aplab.llm", "from .llm", "from . import packages", "executors", "INSERT", "UPDATE ",
                   "DELETE", "from . import approvals"):
        assert banned not in src, banned
    js = (pathlib.Path(__file__).resolve().parents[1] / "autopilot" / "static" / "app.js").read_text()
    block = js[js.index("Wave 3: placement advisory"):js.index('document.addEventListener("click", (e) => { if (e.target.closest("#adv-reload"))')]
    assert "post(" not in block and 'api("/api/recommendations/advisory")' in block


def test_application_name_difference_is_reported_as_naming(world, no_network):
    from autopilot import advisory, web
    world.run(LAB_SCAN, [trace_b()], name="naming")
    world.op.post("/api/recommend")
    pk = copy.deepcopy(advisory.packages_from_store(web.STORE, web.STORE.current()["id"]))   # in-memory copy only
    for p in pk:
        for a in p["body"]["architecture"]:
            if a["application"].startswith("a2a_"):
                a["application"] = "a2a_agent_b"
    a = advise([lab_device()], lab_env())
    rows = advisory.compare(a["proposals"], pk, [lab_device()])["disagreements"]
    naming = [r for r in rows if r["field"] == "application"]
    assert naming and all(r["kind"] == "naming" and r["package_value"] == "a2a_agent_b" and r["advisory_value"] == "a2a_risk_assessment_agent"
                          for r in naming)
