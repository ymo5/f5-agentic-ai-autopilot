"""Effective protection state for verification, reports and run labels (DEF-VERIFY-SECURITY-LEVEL, DEF-REPORT-CURRENT-STATE).

L4 (2026-10-15) showed verification level 4 "security: passed 2/2" with only AI Delivery deployed: the delivery gate's
security.* tests assert that the direct paths are still OPEN (exposure), not that protection works. Reports also counted
any historically 'succeeded' deployment as protection. Both now derive from verification.current_state()/protection().
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from autopilot import verification  # noqa: E402

DELIVERY_GATE = [{"test": "a2a.via_front_door", "result": "pass"}, {"test": "delivery.load_distribution", "result": "pass"},
                 {"test": "security.direct_backend_blocked", "result": "pass"}, {"test": "security.agent_b_direct_blocked", "result": "pass"}]
SECURITY_GATE = [{"test": "a2a.via_front_door", "result": "pass"}, {"test": "security.unauthenticated_rejected", "result": "pass"},
                 {"test": "security.unauthorized_tool_denied", "result": "pass"}, {"test": "security.direct_backend_blocked", "result": "pass"}]


def dep(i, kind, status="succeeded", t=100.0, proven=()):
    return {"id": f"d{i}", "kind": kind, "status": status, "package_hash": "h", "started": t, "finished": t + 10, "proven_by": list(proven),
            "steps": [{"step": "verify.bigip_config", "status": "ok"}, {"step": "converge[x]", "status": "ok"}]}


def gate(label, t, results):
    return {"label": f"deployment gate [{label}]", "started": t, "results": results}


def run(deps, vals=(), resets=()):
    deps = sorted(deps, key=lambda d: d["started"], reverse=True)
    v = verification.summarize(deps, sorted(vals, key=lambda x: x["started"], reverse=True), list(resets))
    return {l["key"]: l for l in v["levels"]}, v["protection"]


def test_baseline_has_no_protection_and_no_security_result():
    L, P = run([])
    assert P == {"state": "none", "delivery": False, "security": False, "infra_label": "baseline", "verified": False, "in_place": []}
    assert L["security"]["result"] == "not_run" and L["functional"]["result"] == "not_run"


def test_l4_case_delivery_only_never_shows_security_passed():
    L, P = run([dep(1, "delivery")], [gate("after-delivery", 105, DELIVERY_GATE)])
    assert L["functional"]["result"] == "passed" and L["functional"]["controls"] == "delivery"
    assert L["security"]["result"] == "not_run" and L["security"]["controls"] == "security"
    assert "no AI Security deployment is in place" in L["security"]["detail"] and "exposure only" in L["security"]["detail"]
    assert {e["check"] for e in L["security"]["exposure"]} == {"security.direct_backend_blocked", "security.agent_b_direct_blocked"}
    assert all("exposure confirmed" in e["meaning"] for e in L["security"]["exposure"])
    assert P["delivery"] and not P["security"] and P["infra_label"] == "delivery" and P["verified"]
    assert "AI Delivery" in L["functional"]["title"] and "AI Security" in L["security"]["title"]


def test_security_level_comes_only_from_after_security_evidence_of_the_deployment_in_place():
    d1, d2 = dep(1, "delivery", t=100), dep(2, "security", t=200, proven=("security.unauthenticated_rejected",))
    L, P = run([d1, d2], [gate("after-delivery", 105, DELIVERY_GATE), gate("after-security", 205, SECURITY_GATE)])
    assert L["security"]["result"] == "passed" and P["security"] and P["infra_label"] == "security"
    assert {c["check"] for c in L["security"]["checks"]} == {"security.unauthenticated_rejected", "security.unauthorized_tool_denied",
                                                             "security.direct_backend_blocked"}
    bad = [dict(t, result="fail") if t["test"] == "security.unauthorized_tool_denied" else t for t in SECURITY_GATE]
    L, _ = run([d1, d2], [gate("after-security", 205, bad)])
    assert L["security"]["result"] == "failed"
    L, _ = run([d1, d2], [gate("after-delivery", 205, DELIVERY_GATE)])      # security deployed, only delivery-profile evidence
    assert L["security"]["result"] == "not_run"


def test_failed_security_deployment_rolled_back_leaves_delivery_and_no_security():
    L, P = run([dep(1, "delivery", t=100), dep(2, "security", "failed-rolled-back", t=200)],
               [gate("after-security", 205, SECURITY_GATE)])
    assert P["state"] == "restored" and P["delivery"] and not P["security"] and not P["verified"] and P["infra_label"] == "delivery"
    assert L["security"]["result"] == "not_run" and L["configuration"]["result"] == "inconclusive"


def test_manual_rollback_of_security_removes_security_protection():
    _, P = run([dep(1, "delivery", t=100), dep(2, "security", "rolled-back", t=200)])
    assert P["delivery"] and not P["security"] and [x["id"] for x in P["in_place"]] == ["d1"]


def test_reset_demo_clears_all_protection_and_failed_reset_is_unverified():
    deps = [dep(1, "delivery", t=100), dep(2, "security", t=200)]
    L, P = run(deps, [gate("after-security", 205, SECURITY_GATE)], [{"ts": 300, "ok": True}])
    assert P == {"state": "baseline", "delivery": False, "security": False, "infra_label": "baseline", "verified": False, "in_place": []}
    assert L["security"]["result"] == "not_run" and L["configuration"]["history"]["deployment"] == "d2"
    _, P = run(deps, [], [{"ts": 300, "ok": False}])
    assert P["infra_label"] == "unverified" and not P["delivery"] and not P["security"]


def test_new_delivery_deployment_replaces_the_security_layer():
    _, P = run([dep(1, "delivery", t=100), dep(2, "security", t=200), dep(3, "delivery", t=300)])
    assert P["delivery"] and not P["security"] and [x["id"] for x in P["in_place"]] == ["d3"]


def test_unverified_outcomes_claim_no_protection():
    for st in ("failed", "failed-rollback-failed", "failed-rolled-back-unverified", "running"):
        _, P = run([dep(1, "delivery", t=100), dep(2, "security", st, t=200)])
        assert P["infra_label"] == "unverified" and not P["delivery"] and not P["security"], st


# ------------------------------------------------------------------ end to end: real engine + store, mock infrastructure
def test_verification_reports_and_run_labels_follow_the_effective_state(ctx):
    from conftest import discover, review
    from autopilot import report, web

    proven = {}

    def results(profile):
        base = SECURITY_GATE if profile == "after-security" else DELIVERY_GATE
        names = {t["test"] for t in base} | set(proven.get(profile, ()))
        return [{"test": n, "result": "pass", "observed": {}, "expected": ""} for n in sorted(names)]

    async def validator(profile):
        return results(profile)
    ctx.engine.validator = validator

    def approve(pid):
        review(ctx, pid)
        assert ctx.ap.post(f"/api/packages/{pid}/decision", json={"decision": "approved", "comment": "t"}).status_code == 200

    ids = discover(ctx)
    before = web.STORE.current()["id"]
    for p in ctx.viewer.get("/api/packages").json():          # every test each package expects passes in its own profile
        proven["after-" + p["kind"]] = (p["body"].get("expected_outcomes") or {}).get("proven_by") or []
    levels = lambda: {l["key"]: l for l in ctx.viewer.get("/api/verification").json()["levels"]}    # noqa: E731

    approve(ids["delivery"])
    assert ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()["status"] == "succeeded"
    L = levels()
    assert L["functional"]["result"] == "passed" and L["security"]["result"] == "not_run" and L["security"]["exposure"]
    assert web._infra_label() == "delivery"

    approve(ids["security"])
    sec = ctx.ap.post(f"/api/packages/{ids['security']}/deploy").json()
    assert sec["status"] == "succeeded"
    assert levels()["security"]["result"] == "passed" and web._infra_label() == "security"

    assert ctx.ap.post(f"/api/deployments/{sec['id']}/rollback").status_code == 200        # security removed, delivery restored
    L = levels()
    assert L["security"]["result"] == "not_run" and web._infra_label() == "delivery"
    deps = {d["id"]: d for d in report.linked_deployments(web.STORE, before)}
    assert deps[sec["id"]]["in_place"] is False and deps[sec["id"]]["now"].startswith("historical")

    r = ctx.ap.post("/api/ops/reset-demo", json={"confirmation": "RESET DEMO ENVIRONMENT"})
    assert r.status_code == 200, r.text
    assert web._infra_label() == "baseline" and levels()["configuration"]["result"] == "not_run"
    deps = report.linked_deployments(web.STORE, before)
    assert deps and not any(d["in_place"] for d in deps)
    after = ctx.op.post("/api/assessment/new", json={"name": "after"}).json()["id"]
    html = report.executive_html(web.STORE, after, before)
    assert "<b>0</b>approved F5 changes in place now" in html and "Historical (succeeded, since removed" in html
    assert "No deployment is in place" in html and report.security_results(web.STORE, after) == []
