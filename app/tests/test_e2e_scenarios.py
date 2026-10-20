"""M11 integrated offline end-to-end scenario: Discover -> Assess -> Recommend -> Approve -> (mock) Deploy -> Verify.

Real engine, approvals, policy and deployer logic with the mock BIG-IP/host executors from conftest; the placement advisory
uses the REAL BIG-IP_C capture (fixtures/wave3/bigip_c_real_capture_min.json) as Observe evidence. No network access.
The other scenario classes (B-J) map to existing tests — see docs/70-improvement-program/20-integrated-e2e-report.md.
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import discover, review  # noqa: E402

FX = pathlib.Path(__file__).resolve().parent / "fixtures" / "wave3" / "bigip_c_real_capture_min.json"


def test_scenario_a_full_workflow_with_real_bigip_evidence(ctx):
    from autopilot import advisory, placement, web
    from autopilot.sources import observe
    # Discover + Assess + Recommend (packages)
    ids = discover(ctx)
    st = ctx.viewer.get("/api/state").json()
    assert st["findings"] and all("guidance" in g for g in st["findings_grouped"])
    # Recommend (advisory) on the real BIG-IP_C capture
    real = json.loads(FX.read_text())
    web.STORE.add_evidence("observe", "real capture (fixture)", "real BIG-IP_C", {"origin": "fixture", "model": observe.normalize(real)})
    adv = advisory.build(web.STORE, web.CFG, now=real["_meta"]["collected_at"] + 300)
    assert adv["status"] == "decided" and adv["deployment_readiness"] == placement.NOT_PREFLIGHT
    assert {p["proposal"]["device"] for p in adv["proposals"] if p["proposal"]} == {"bigip:192.0.2.16"}
    assert all(p["proposal"]["deployment_engine"]["supported"] for p in adv["proposals"] if p["proposal"])
    # Approve: viewer and operator cannot; preflight review required; approver can
    assert ctx.viewer.post(f"/api/packages/{ids['delivery']}/decision", json={"decision": "approved", "comment": "x"}).status_code == 403
    assert ctx.op.post(f"/api/packages/{ids['delivery']}/decision", json={"decision": "approved", "comment": "x"}).status_code == 403
    review(ctx, ids["delivery"])
    r = ctx.ap.post(f"/api/packages/{ids['delivery']}/decision", json={"decision": "approved", "comment": "e2e"})
    assert r.status_code == 200, r.text
    # the advisory never deploys or approves anything by itself
    acts = [a["action"] for a in ctx.ap.get("/api/audit").json()["rows"]]
    assert "deployment.started" not in acts
    # Deploy (mock executors, real engine + policy) through the authorised path only
    d = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()
    assert d["status"] == "succeeded" and d["mode"] == "mock"
    # Verify: run the after-delivery validation, then read the verification levels
    assert ctx.op.post("/api/ops/validate", json={"profile": "after-delivery"}).status_code == 200
    v = {l["key"]: l for l in ctx.viewer.get("/api/verification").json()["levels"]}
    assert v["observability"]["result"] == "not_run"                      # never claimed
    # the mock validator only reports "mock.gate": the package's expected functional tests never ran -> not_run, listed by name
    assert v["functional"]["result"] == "not_run" and "a2a.via_front_door" in v["functional"]["detail"]
    assert v["configuration"]["result"] in ("passed", "not_run")
    acts = [a["action"] for a in ctx.ap.get("/api/audit").json()["rows"]]
    assert {"package.approved", "deployment.started", "deployment.succeeded"} <= set(acts)


def test_scenario_e_deploy_without_review_or_approval_is_refused(ctx):
    ids = discover(ctx)
    r = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy")
    assert r.status_code in (403, 409, 422) and not [x for x in ctx.bigip.calls if x[0] in ("POST", "DELETE")]
    r = ctx.ap.post(f"/api/packages/{ids['delivery']}/decision", json={"decision": "approved", "comment": "no review"})
    assert r.status_code >= 400 and ("review" in r.text.lower() or "preflight" in r.text.lower()), (r.status_code, r.text)
