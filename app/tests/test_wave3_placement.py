"""Wave 3 M1 — offline, evidence-based BIG-IP placement.

Inputs are the stored lab Observe model (copied offline from a backup), synthetic device fixtures and patched discovery
results. A socket guard proves placement opens no network connections; row counts prove it writes nothing.
"""
from __future__ import annotations

import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import INTEL_TOOLS  # noqa: E402
from test_wave2a import a2a, mcp, no_network, trace_b, world  # noqa: E402,F401  (fixtures + helpers)

FX = pathlib.Path(__file__).resolve().parent / "fixtures" / "wave3"
LAB = json.loads((FX / "lab_stored_observe.json").read_text())
TWO = json.loads((FX / "two_bigip.json").read_text())
AGENT_C = {"name": "Receptionist Agent (Agent C, synthetic XGO scenario)", "skills": ["greet_visitor", "explain_demo"],
           "security_schemes": [], "streaming": False, "bindings": ["JSONRPC"]}
LAB_SCAN = [a2a("10.50.10.22"), a2a("10.50.20.22", url="http://10.50.10.22:9000/"), mcp("10.50.20.31"), mcp("10.50.20.32"),
            mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")]
POLICY = ["10.50.20.0/24"]
NOW = 1792000300          # fixture health samples are 5 min old at evaluation time


def lab_device():
    from autopilot import placement
    return placement.device_from_model("bigip:192.0.2.16", LAB["model"], mgmt=LAB["mgmt"], evidence_id=LAB["evidence_id"],
                                       origin="stored Observe evidence (offline copy)", mgmt_status="configured",
                                       configured={"self_ips": [placement.fact("10.50.20.10", "configured", "autopilot.yaml design.self_backend")]})


def fixture_devices(mutate=None):
    from autopilot import placement
    devs = copy.deepcopy(TWO["devices"])
    if mutate:
        mutate({d["id"]: d["model"] for d in devs})
    return [placement.device_from_model(d["id"], d["model"], mgmt=d["mgmt"], evidence_id=d["evidence_id"], origin="synthetic fixture")
            for d in devs]


def plan(devices, **kw):
    from autopilot import identity, placement, web
    idn = identity.reconcile(web.STORE)
    kw.setdefault("now", NOW)
    return placement.evaluate(idn, devices, callers=placement.callers_from_store(web.STORE, idn), member_policy=POLICY, **kw)


def svc(p, name):
    return next(s for s in p["services"] if s["service"]["name"] == name)


# ------------------------------------------------------------------ 1. existing lab: strict abstention
def test_lab_stored_evidence_abstains(world, no_network):
    world.run(LAB_SCAN, [trace_b()], name="lab")
    p = plan([lab_device()])
    assert p["status"] == "abstained" and p["summary"]["selected"] == 0
    for name in ("Risk Assessment Agent", "risk-scoring", "fraud-intel"):
        s = svc(p, name)
        assert s["eligibility"] == "eligible" and s["decision"] == "abstain" and s["selected"] is None and s["eligible"] == []
        (u,) = s["unverified"]
        assert u["device"] == "bigip:192.0.2.16" and "rank_key" not in u
        res = {c["check"]: c["result"] for c in u["checks"]}
        assert res == {"ltm_provisioned": "pass", "as3_available": "pass", "ha_state": "unknown", "health": "unknown",
                       "backend_reachability": "unknown"}
        assert all("/24 or shorter" in a for a in u["assumptions"]) and u["assumptions"]
    # configured self IPs are shown but never satisfy a check
    assert p["devices"][0]["configured"]["self_ips"][0]["status"] == "configured"
    assert p["devices"][0]["mgmt"]["status"] == "configured"
    assert {s["network"]["status"] for s in p["devices"][0]["self_ips"]} == {"unknown"}
    assert {(m["device"], m["check"]) for m in p["missing"]} == {
        ("bigip:192.0.2.16", "ha_state"), ("bigip:192.0.2.16", "health"), ("bigip:192.0.2.16", "backend_reachability")}


def test_assess_store_reads_stored_observe_evidence_and_writes_nothing(world, no_network):
    from autopilot import placement, web
    world.run(LAB_SCAN, [trace_b()], name="lab via store")
    web.STORE.add_evidence("observe", "bigip-icontrol-rest (offline fixture)", "fixture", {"origin": "fixture", "model": LAB["model"]})
    tables = [r[0] for r in web.STORE.db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    counts = lambda: {t: web.STORE.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}  # noqa: E731
    before, changes = counts(), web.STORE.db.total_changes
    p = placement.assess_store(web.STORE, web.CFG)
    assert counts() == before and web.STORE.db.total_changes == changes
    assert p["status"] == "abstained" and p["limits"]["member_policy"] == ["10.50.20.0/24"]
    (d,) = p["devices"]
    assert d["id"] == "bigip:192.0.2.16" and d["hostname"]["value"] == "big-ip.c" and d["hostname"]["status"] == "observed"
    assert [f["value"] for f in d["configured"]["self_ips"]] == ["10.50.10.10", "10.50.20.10"]


# ------------------------------------------------------------------ 2. two fully specified devices
def test_two_bigip_decisions(world, no_network):
    world.run(LAB_SCAN + [a2a("10.50.30.40", port=9100, card=AGENT_C)], [trace_b()], name="two devices")
    p = plan(fixture_devices())
    assert p["status"] == "decided" and p["summary"]["selected"] == 4
    b = svc(p, "Risk Assessment Agent")
    assert b["selected"]["device"] == "bigip-a"
    (m,) = b["selected"]["pool_members"]
    assert m["address"] == "10.50.20.22:9000"                       # the backend interface today's design also uses
    assert m["why"] == ["direct reachability", "preferred over 10.50.10.22:9000: inside the deployer's current member range (configured)"]
    ifs = {o["address"]: o for o in next(e for e in b["eligible"] if e["device"] == "bigip-a")["members"][0]["interfaces"]}
    assert ifs["10.50.10.22:9000"]["on_caller_subnet"] and not ifs["10.50.20.22:9000"]["on_caller_subnet"]   # Agent A calls from 10.50.10.21
    assert any("more headroom" in w for w in b["selected"]["why"])  # both devices reach Agent B directly
    rs = svc(p, "risk-scoring")
    assert rs["selected"]["device"] == "bigip-a" and [x["address"] for x in rs["selected"]["pool_members"]] == ["10.50.20.31:8000", "10.50.20.32:8000"]
    assert any("all pool members directly connected" in w for w in rs["selected"]["why"])
    e_b = next(e for e in rs["eligible"] if e["device"] == "bigip-b")
    assert all(o["reach"]["via"] == "route" for mm in e_b["members"] for o in mm["interfaces"])
    assert svc(p, "fraud-intel")["selected"]["device"] == "bigip-a"


def test_shadow_lab_profile_matches_current_package_targets(world, no_network):
    """With lab-shaped, fully observed evidence the engine reproduces today's pool members (compared as data only)."""
    from autopilot import web
    world.run(LAB_SCAN, [trace_b()], name="shadow")
    p = plan([d for d in fixture_devices() if d["id"] == "bigip-a"])
    got = {s["service"]["name"]: [m["address"] for m in s["selected"]["pool_members"]] for s in p["services"] if s["selected"]}
    backend = web.CFG["design"]["agent_backend_addresses"]["10.50.10.22"]
    assert got == {"Risk Assessment Agent": [f"{backend}:9000"], "risk-scoring": ["10.50.20.31:8000", "10.50.20.32:8000"],
                   "fraud-intel": ["10.50.20.33:8000"]}


# ------------------------------------------------------------------ 3. Agent C (synthetic, robot-inspired)
def test_agent_c_on_robot_subnet_selects_the_device_that_reaches_it(world, no_network):
    world.run([a2a("10.50.30.40", port=9100, card=AGENT_C)], [], name="agent c")
    c = svc(plan(fixture_devices()), AGENT_C["name"])
    assert c["decision"] == "selected" and c["selected"]["device"] == "bigip-b" and "only eligible device" in c["selected"]["why"]
    (r,) = c["rejected"]
    assert r["device"] == "bigip-a" and r["reasons"] == ["no self IP subnet or static route in route domain 0 reaches 10.50.30.40"]
    assert any("no authentication declared" == t.get("detail") for t in c["traits"])


def test_agent_c_on_management_lan_abstains(world, no_network):
    """The robot's LAN is only covered by bigip-b's default route: reachability is not established -> abstain."""
    world.run([a2a("192.0.2.167", port=9100, card=AGENT_C)], [], name="agent c lan")
    c = svc(plan(fixture_devices()), AGENT_C["name"])
    assert c["decision"] == "abstain" and c["selected"] is None
    assert [u["device"] for u in c["unverified"]] == ["bigip-b"]
    rc = next(x for x in c["unverified"][0]["checks"] if x["check"] == "backend_reachability")
    assert rc["result"] == "unknown" and "only a default route covers 192.0.2.167" in rc["detail"]
    assert [r["device"] for r in c["rejected"]] == ["bigip-a"]


# ------------------------------------------------------------------ 4. eligibility classes
def test_already_covered_service_is_not_placed(world, no_network):
    world.run(LAB_SCAN, [trace_b()], name="covered")

    def cover(m):
        m["bigip-b"]["virtuals"].append({"name": "/AP_AI/mcp_fraud_intel/service", "address": "10.50.10.102", "port": 443,
                                         "pool": "/AP_AI/mcp_fraud_intel/pool"})
        m["bigip-b"]["pools"].append({"name": "/AP_AI/mcp_fraud_intel/pool", "members": [
            {"name": "10.50.20.33:8000", "address": "10.50.20.33"}]})
    p = plan(fixture_devices(cover))
    f = svc(p, "fraud-intel")
    assert f["eligibility"] == "already_covered" and f["decision"] == "not_placed" and f["selected"] is None
    assert f["coverage"][0]["device"] == "bigip-b" and f["coverage"][0]["members"] == ["10.50.20.33:8000"]
    assert f["coverage"][0]["status"] == "observed"
    assert p["summary"]["already_covered"] == 1 and p["status"] == "decided"


def test_unresolved_identity_is_ineligible(world, no_network):
    world.run([a2a("10.50.10.22"), a2a("10.50.10.23")], [], name="twins")
    p = plan(fixture_devices())
    twins = [s for s in p["services"] if s["service"]["name"] == "Risk Assessment Agent"]
    assert len(twins) == 2 and {s["eligibility"] for s in twins} == {"ineligible"}
    assert all("service identity unresolved" in s["eligibility_reasons"][0] for s in twins)
    assert p["status"] == "nothing_to_place"


def test_non_a2a_mcp_services_are_out_of_scope(world, no_network):
    world.run(LAB_SCAN, [trace_b()], name="scope")
    p = plan(fixture_devices())
    kinds = {s["kind"] for s in p["out_of_scope"]}
    assert kinds and not kinds & {"a2a_agent", "mcp_server"}
    assert all("A2A agents and MCP servers only" in s["reason"] for s in p["out_of_scope"])


# ------------------------------------------------------------------ 5. hard checks
def test_hard_check_failures_reject_with_reasons(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="checks")

    def degrade(m):
        m["bigip-a"]["health"]["swap_pct"] = 96
        m["bigip-a"]["health"]["rest_latency_s"] = 10.5
        m["bigip-b"]["ha"] = {"failover_state": "standby", "device_group": "dg-edge"}
    f = svc(plan(fixture_devices(degrade)), "fraud-intel")
    assert f["decision"] == "no_eligible_device" and f["selected"] is None
    rs = {r["device"]: r["reasons"] for r in f["rejected"]}
    assert rs["bigip-a"] == ["above placement-health/v1.1 fail level: swap_pct 96 >= 95.0, rest_latency_s 10.5 >= 10.0"]
    assert rs["bigip-b"] == ["standby unit — configuration belongs on the active member of dg-edge"]


def test_preflight_warn_levels_rank_lower_but_do_not_reject(world, no_network):
    """BIG-IP_C's recorded state (swap 91 %, REST 2.8 s) is a preflight WARNING, not a failure: eligible, ranked lower."""
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="warn")

    def warn(m):
        m["bigip-a"]["health"].update(swap_pct=91, rest_latency_s=2.8)
        m["bigip-b"]["self_ips"].append({"name": "/Common/self_backend", "address": "10.50.20.11/24", "vlan": "/Common/vlan_backend"})
    f = svc(plan(fixture_devices(warn)), "fraud-intel")
    a = next(e for e in f["eligible"] if e["device"] == "bigip-a")
    assert {e["device"] for e in f["eligible"]} == {"bigip-a", "bigip-b"} and a["rank_key"]["health_warnings"] == 2
    assert f["selected"]["device"] == "bigip-b" and any("fewer health-policy warnings" in w for w in f["selected"]["why"])


def test_route_domain_and_module_checks(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="rd")

    def change(m):
        m["bigip-a"]["self_ips"][1]["address"] = "10.50.20.10%2/24"
        m["bigip-b"]["device"]["provisioned"] = {"asm": "nominal"}
    f = svc(plan(fixture_devices(change)), "fraud-intel")
    rs = {r["device"]: r["reasons"] for r in f["rejected"]}
    assert rs["bigip-a"] == ["10.50.20.33 is only inside 10.50.20.0/24 in route domain 2; pool members are placed in route domain 0"]
    assert rs["bigip-b"] == ["LTM is not provisioned"]


def test_unknown_reachability_on_one_device_does_not_block_a_verified_one(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="mixed")

    def strip(m):
        for s in m["bigip-a"]["self_ips"]:
            s["address"] = s["address"].split("/")[0]
    f = svc(plan(fixture_devices(strip)), "fraud-intel")
    assert f["selected"]["device"] == "bigip-b" and [u["device"] for u in f["unverified"]] == ["bigip-a"]
    assert f["selected"]["pool_members"][0]["why"] == ["route reachability"]


def test_unknown_reachability_everywhere_abstains(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="unknown")

    def strip(m):
        for d in m.values():
            for s in d["self_ips"]:
                s["address"] = s["address"].split("/")[0]
            d.pop("routes")
    p = plan(fixture_devices(strip))
    f = svc(p, "fraud-intel")
    assert f["decision"] == "abstain" and {u["device"] for u in f["unverified"]} == {"bigip-a", "bigip-b"} and p["status"] == "abstained"


def test_customer_preference_ranks_only_among_eligible(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="pref")
    f = svc(plan(fixture_devices(), preferences={"device": "bigip-b"}), "fraud-intel")
    assert f["selected"]["device"] == "bigip-b" and any("customer preference (configured)" in w for w in f["selected"]["why"])

    def strip(m):
        m["bigip-b"].pop("health")
    f = svc(plan(fixture_devices(strip), preferences={"device": "bigip-b"}), "fraud-intel")
    assert f["selected"]["device"] == "bigip-a"     # an unverified preferred device is never selected


# ------------------------------------------------------------------ 6. determinism, statuses, isolation
def test_decision_is_deterministic_and_order_independent(world, no_network):
    world.run(LAB_SCAN + [a2a("10.50.30.40", port=9100, card=AGENT_C)], [trace_b()], name="det")
    a = plan(fixture_devices())
    b = plan(list(reversed(fixture_devices())))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True) and a["decision_digest"] == b["decision_digest"]


def test_every_check_and_fact_uses_the_four_status_vocabulary(world, no_network):
    world.run(LAB_SCAN, [trace_b()], name="vocab")
    for p in (plan(fixture_devices()), plan([lab_device()])):
        statuses = set()

        def walk(o):
            if isinstance(o, dict):
                if "status" in o and ("check" in o or "source" in o):
                    statuses.add(o["status"])
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(p)
        assert statuses and statuses <= {"observed", "inferred", "configured", "unknown"}
        assert p["engine"]["llm"] is False and p["engine"]["advisory_only"] is True


def test_module_has_no_network_llm_or_package_dependencies():
    src = (pathlib.Path(__file__).resolve().parents[1] / "autopilot" / "placement.py").read_text()
    for banned in ("httpx", "socket", "requests", "aplab.llm", "from .llm", "packages", "executors", "INSERT", "UPDATE ", "DELETE"):
        assert banned not in src, banned


def test_empty_provisioning_response_is_unknown_not_a_failure(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="empty provision")

    def empty(m):
        m["bigip-a"]["device"]["provisioned"] = {}
    f = svc(plan(fixture_devices(empty)), "fraud-intel")
    a = next(u for u in f["unverified"] if u["device"] == "bigip-a")
    assert next(c for c in a["checks"] if c["check"] == "ltm_provisioned")["result"] == "unknown"
    assert f["selected"]["device"] == "bigip-b"
