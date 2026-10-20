"""M3 finding guidance and M7 verification levels (offline; read-only views)."""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import discover  # noqa: E402
from test_wave2a import no_network, world  # noqa: E402,F401


# ------------------------------------------------------------------ M3 guidance
def test_every_catalog_rule_has_guidance_without_exploit_claims():
    from autopilot import catalog, guidance
    for rule, meta in catalog.RULES.items():
        g = guidance.for_rule(rule, meta["class"])
        assert g["impact"] and g["mitigation"] and g["limitations"] and g["confidence"] in ("high", "medium-high", "medium"), rule
        assert (g["control"] is None) == (meta["package"] is None) or rule == "S-007", rule        # no control promised without a package
        text = " ".join(str(v) for v in g.values()).lower()
        for claim in ("exploit", "cve-", "attacker can", "guaranteed"):
            assert claim not in text, (rule, claim)
    assert guidance.for_rule("X-999", None)["confidence"] == "unknown"


def test_grouped_findings_carry_guidance(ctx):
    discover(ctx)
    g = ctx.viewer.get("/api/state").json()["findings_grouped"]
    assert g and all({"impact", "mitigation", "control", "confidence", "confidence_basis", "limitations"} <= set(x["guidance"]) for x in g)
    s2 = next((x for x in g if x["rule_id"] == "S-002"), None)
    if s2:
        assert s2["guidance"]["confidence"] == "high" and "does not by itself show" in s2["guidance"]["limitations"]


# ------------------------------------------------------------------ M7 verification levels
def _dep(status="succeeded", steps=(("verify.bigip_config", "ok"), ("converge", "ok")), proven=("delivery.failover", "a2a.via_front_door")):
    return {"id": "d1234567", "status": status, "package_hash": "h", "steps": [{"step": s, "status": st} for s, st in steps], "proven_by": list(proven),
            "started": 1}


def test_levels_not_run_without_deployment_or_validation():
    from autopilot import verification
    v = verification.summarize([], [])
    assert [l["result"] for l in v["levels"]] == ["not_run"] * 5


def test_levels_passed_failed_inconclusive():
    from autopilot import verification
    vals = [{"label": "after-delivery", "started": 3, "results": [{"test": "delivery.failover", "result": "pass"}]},
            {"label": "after-delivery", "started": 2, "results": [{"test": "a2a.via_front_door", "result": "fail"}]}]
    v = {l["key"]: l for l in verification.summarize([_dep()], vals)["levels"]}
    assert v["configuration"]["result"] == "passed" and v["operational"]["result"] == "passed"
    assert v["functional"]["result"] == "failed"                       # newest post-deployment result per test: a2a.via_front_door fail
    assert v["security"]["result"] == "not_run" and v["observability"]["result"] == "not_run"
    vals = [{"label": "after-delivery", "started": 2, "results": [{"test": "delivery.failover", "result": "pass"}]}]
    v = {l["key"]: l for l in verification.summarize([_dep()], vals)["levels"]}
    assert v["functional"]["result"] == "inconclusive" and "a2a.via_front_door" in v["functional"]["detail"]   # expected but not run


def test_failed_deployment_is_never_configuration_passed():
    from autopilot import verification
    d = _dep(status="failed-rolled-back", steps=(("verify.bigip_config", "failed"), ("rollback", "ok")))
    v = {l["key"]: l for l in verification.summarize([d], [])["levels"]}
    # the configuration was removed again: the CURRENT level is not run; the failed read-back is kept as history
    assert v["configuration"]["result"] == "not_run" and v["configuration"]["history"]["result"] == "failed"
    assert "historical evidence" in v["configuration"]["detail"] and v["operational"]["result"] == "not_run"


def test_verification_api_read_only(ctx):
    from autopilot import web
    discover(ctx)
    ch = web.STORE.db.total_changes
    r = ctx.viewer.get("/api/verification")
    assert r.status_code == 200 and len(r.json()["levels"]) == 5 and web.STORE.db.total_changes == ch
    assert ctx.anon.get("/api/verification").status_code == 401


# ------------------------------------------------------------------ M4 naming strategy v1
def test_a2a_application_named_after_the_advertised_endpoint_asset(world, no_network):
    from autopilot import advisory, identity, web
    from test_wave2a import a2a, trace_b
    world.run([a2a("10.50.10.22"), a2a("10.50.20.22", url="http://10.50.10.22:9000/")], [trace_b()], name="naming")
    web.STORE.db.execute("UPDATE asset SET name='agent-b' WHERE key='ep:10.50.10.22:9000'")
    web.STORE.db.execute("UPDATE asset SET name='agent-b-svc' WHERE key='ep:10.50.20.22:9000'")
    idn = identity.reconcile(web.STORE)
    naming = advisory.naming_from_store(web.STORE, idn)
    svc = next(s for s in idn["services"] if s["kind"] == "a2a_agent")
    assert naming[svc["id"]] == "agent-b" and advisory.app_name(svc, naming) == "a2a_agent_b"
    assert advisory.app_name(svc) == "a2a_risk_assessment_agent"            # fallback without asset names


# ------------------------------------------------------------------ Part 5.4 / 12.3 overview dashboard
def test_overview_answers_the_six_questions_from_stored_evidence(ctx):
    from autopilot import web
    ids = discover(ctx)
    assert ctx.op.post("/api/discover/observe").status_code == 200
    ch = web.STORE.db.total_changes
    o = ctx.viewer.get("/api/overview").json()
    assert web.STORE.db.total_changes == ch                                       # read-only
    Q = o["questions"]
    assert set(Q) == {"operating", "protected", "at_risk", "delivering", "healthy", "changed"} and all(Q[k]["source"] for k in Q)
    st = ctx.viewer.get("/api/state").json()
    assert sum(Q["at_risk"]["findings_by_severity"].values()) == len(st["findings"])
    assert Q["operating"]["value"] == len(o["services"]) and Q["protected"]["yes"] == 0     # baseline: nothing fronted yet
    assert {s["protected"] for s in o["services"] if s["endpoints"]} <= {"no", "unknown"}
    # after an approved (mock) deployment and a fresh Observe, fronted services show as protected by the delivering device
    from conftest import review
    review(ctx, ids["delivery"])
    assert ctx.ap.post(f"/api/packages/{ids['delivery']}/decision", json={"decision": "approved", "comment": "t"}).status_code == 200
    assert ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()["status"] == "succeeded"
    assert ctx.op.post("/api/discover/observe").status_code == 200
    o2 = ctx.viewer.get("/api/overview").json()
    assert o2["questions"]["changed"]["last_deployment"]["status"] == "succeeded"
    prot = {s["name"]: s["delivered_by"] for s in o2["services"] if s["protected"] == "yes"}
    assert prot == {"fraud-intel": ["bigip:192.0.2.16"], "risk-scoring": ["bigip:192.0.2.16"]}   # MCP front doors observed
    assert o2["questions"]["delivering"]["devices"] == ["bigip:192.0.2.16"]
    assert ctx.anon.get("/api/overview").status_code == 401


def test_findings_history_counts_by_assessment(world):
    from conftest import SCAN, TRACE
    world.run(SCAN, [TRACE], name="first")
    world.run(SCAN[:1], [], name="second")
    o = world.viewer.get("/api/overview").json()
    h = o["history"]
    assert [x["name"] for x in h][:2] == ["second", "first"] and h[0]["current"] and not h[1]["current"]
    from autopilot import web
    for x in h[:2]:
        n = web.STORE.db.execute("SELECT COUNT(*) FROM finding WHERE assessment_id=?", (x["assessment_id"],)).fetchone()[0]
        assert sum(x["findings"].values()) == n


def test_overview_interactions_come_from_traces_and_name_unavailable_metrics(ctx):
    discover(ctx)
    o = ctx.viewer.get("/api/overview").json()["interactions"]
    assert o["edges"] and o["source"].startswith("OpenTelemetry traces")
    e = next(x for x in o["edges"] if x["protocol"] == "mcp")
    assert e["calls"] >= 1 and e["errors"] is not None and "p50_ms" in e and e["n"] is not None
    assert any("external observability source" in x for x in o["not_available"])                    # no invented telemetry



def test_baseline_runs_are_never_counted_as_deployment_verification():
    """Live finding (L1 acceptance): a 'before' run passing must not show functional/security as passed."""
    from autopilot import verification
    base = [{"label": "before", "started": 5, "results": [{"test": "a2a.via_front_door", "result": "pass"},
                                                          {"test": "security.direct_backend_blocked", "result": "pass"}]}]
    v = {l["key"]: l for l in verification.summarize([], base)["levels"]}
    assert v["functional"]["result"] == "not_run" and v["security"]["result"] == "not_run"
    assert "baseline ('before')" in v["functional"]["detail"] and "no successful deployment" in v["functional"]["detail"]
    old = [{"label": "after-delivery", "started": 0.5, "results": [{"test": "a2a.via_front_door", "result": "pass"}]}]   # before the deployment
    v = {l["key"]: l for l in verification.summarize([_dep()], old + base)["levels"]}
    assert v["functional"]["result"] == "not_run"                                     # stale (pre-deployment) runs never count
    assert v["functional"]["checks"] and all(c["result"] == "not_run" and c["expected"] for c in v["functional"]["checks"])
