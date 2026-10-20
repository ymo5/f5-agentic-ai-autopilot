"""AI Data Delivery after the Security stage is already DEPLOYED and VERIFIED (live defect 2026-10-18, assessment "ABC").

Live: a fresh assessment after Delivery + Security were deployed and validated (21/21) has only D-006, S-004, S-006, S-008 —
the Delivery/Security findings are closed — and Recommend produced no packages, because the data package was gated on open
Delivery/Security findings, and the deployer's `sequence.requires` only accepted a Security deployment in the SAME assessment.
The mock lab cannot close those findings from evidence, so the tests narrow Recommend's findings to the live rule set (the
only simulated element); discovery, review, approval, preflight, deploy, read-back, gate and rollback run unchanged.
"""
from __future__ import annotations

import json

import pytest

from conftest import ctx, review  # noqa: F401
from test_data_delivery_inc2 import DATA_TESTS, DD, dctx, dd_on, deploy, discover  # noqa: F401

LIVE_RULES = {"D-006", "S-004", "S-006", "S-008"}          # findings of the live assessment after Security was deployed


def live_like_findings(monkeypatch):
    from autopilot import assess, packages
    real = assess.findings
    monkeypatch.setattr(packages.assess, "findings", lambda store: [f for f in real(store) if f["rule_id"] in LIVE_RULES])


def security_deployed_then_new_assessment(c, monkeypatch):
    ids = discover(c)
    assert deploy(c, ids["delivery"])["status"] == "succeeded"
    sec = deploy(c, ids["security"])
    assert sec["status"] == "succeeded"
    sec_pkg = next(p for p in c.ap.get("/api/packages").json() if p["kind"] == "security")
    c.op.post("/api/assessment/new", json={"name": "ABC"})
    live_like_findings(monkeypatch)
    for ep in ("/api/discover/enumerate", "/api/discover/ingest"):    # findings are narrowed to the live set above
        assert c.op.post(ep).status_code == 200
    return sec, sec_pkg


def recommend(c):
    return {p["kind"]: p["id"] for p in c.op.post("/api/recommend").json()["packages"]}


def tenant(as3):
    return as3["declaration"]["AP_AI"] if "declaration" in as3 else as3["AP_AI"]


def test_data_package_is_recommended_on_the_deployed_security_stage(dctx, monkeypatch):
    from autopilot import data_delivery as D
    sec, sec_pkg = security_deployed_then_new_assessment(dctx, monkeypatch)
    ids = recommend(dctx)
    assert list(ids) == ["data"]                                    # earlier stages are NOT regenerated
    data = next(p for p in dctx.ap.get("/api/packages").json() if p["kind"] == "data")
    body = data["body"]
    assert body["base_deployment"] == sec["id"]
    assert body["as3"] == D.extend(sec_pkg["body"]["as3"], DD)       # exactly the DEPLOYED Security declaration + additions
    st, dt = tenant(sec_pkg["body"]["as3"]), tenant(body["as3"])
    assert all(dt[k] == v for k, v in st.items() if k != "Shared") and all(dt["Shared"][o] == v for o, v in st["Shared"].items())
    assert body["as3_diff"]["modified_existing"] == [] and "deployed" in body["as3_diff"]["base"].lower()
    assert body["requires"] == "security" and body["gate_profile"] == "after-data" and body["dependencies"] == []
    assert data["validation"]["valid"] is True and body["expected_outcomes"]["proven_by"] == DATA_TESTS
    assert data["recommendation"]["finding_ids"]


def test_full_sequence_on_the_deployed_security_stage_and_rollback(dctx, monkeypatch):
    sec, _ = security_deployed_then_new_assessment(dctx, monkeypatch)
    sec_tenant = json.loads(json.dumps(dctx.bigip.tenant))
    ids = recommend(dctx)
    d = deploy(dctx, ids["data"])
    assert d["status"] == "succeeded", d
    steps = [s["step"] for s in d["steps"]]
    assert steps[0] == "preflight" and "verify.bigip_config" in steps and steps[-1] == "gate.validate[after-data]"
    t = dctx.bigip.tenant
    assert {"s3_seaweedfs", "rag_qdrant", "llm_ollama"} <= set(t)
    assert all(t[k] == v for k, v in sec_tenant.items() if k != "Shared") and all(t["Shared"][o] == v for o, v in sec_tenant["Shared"].items())
    assert dctx.ap.post(f"/api/deployments/{d['id']}/rollback").status_code == 200
    assert dctx.bigip.tenant == sec_tenant and set(dctx.hosts.profile.values()) == {"security"}


def test_no_data_package_without_a_succeeded_security_deployment(dctx, monkeypatch):
    discover(dctx)                                                  # nothing deployed
    dctx.op.post("/api/assessment/new", json={"name": "ABC"})
    live_like_findings(monkeypatch)
    for ep in ("/api/discover/enumerate", "/api/discover/ingest"):
        dctx.op.post(ep)
    assert recommend(dctx) == {}


def test_no_data_package_when_latest_succeeded_deployment_is_not_security(dctx, monkeypatch):
    ids = discover(dctx)
    assert deploy(dctx, ids["delivery"])["status"] == "succeeded"   # only Delivery is in place
    dctx.op.post("/api/assessment/new", json={"name": "ABC"})
    live_like_findings(monkeypatch)
    for ep in ("/api/discover/enumerate", "/api/discover/ingest"):
        dctx.op.post(ep)
    assert recommend(dctx) == {}


@pytest.mark.parametrize("drift", ["tenant", "host_profile"])
def test_deployer_refuses_when_device_is_not_in_the_verified_security_state(dctx, monkeypatch, drift):
    security_deployed_then_new_assessment(dctx, monkeypatch)
    ids = recommend(dctx)
    if drift == "tenant":                                           # out-of-band change after the Security deployment
        dctx.bigip.tenant["Shared"]["tcp_ai"]["idleTimeout"] = 901
    else:
        dctx.hosts.profile["ap-agent-b"] = "delivery"
    writes = len([x for x in dctx.bigip.calls if x[0] in ("POST", "DELETE")])
    review(dctx, ids["data"])
    r = dctx.ap.post(f"/api/packages/{ids['data']}/decision", json={"decision": "approved", "comment": "t"})
    assert r.status_code == 409 and "sequence.requires" in r.json()["detail"]
    assert dctx.ap.post(f"/api/packages/{ids['data']}/deploy").status_code == 409
    assert len([x for x in dctx.bigip.calls if x[0] in ("POST", "DELETE")]) == writes      # nothing written to BIG-IP


def test_deployer_refuses_a_data_package_that_alters_the_base_security_objects(dctx, monkeypatch):
    from autopilot import web
    security_deployed_then_new_assessment(dctx, monkeypatch)
    ids = recommend(dctx)
    row = web.STORE.db.execute("SELECT body FROM package WHERE id=?", (ids["data"],)).fetchone()
    body = json.loads(row["body"])
    tenant(body["as3"])["Shared"]["irule_mcp_policy"]["iRule"] = "when HTTP_REQUEST { }"   # tampered Security object
    web.STORE.db.execute("UPDATE package SET body=? WHERE id=?", (json.dumps(body), ids["data"]))
    review(dctx, ids["data"])
    r = dctx.ap.post(f"/api/packages/{ids['data']}/decision", json={"decision": "approved", "comment": "t"})
    assert r.status_code == 409 and "sequence.base_preserved" in r.json()["detail"]


def test_fresh_lab_sequence_is_unchanged(dctx):
    ids = discover(dctx)                                            # nothing deployed yet: delivery, security, data as before
    assert list(ids) == ["delivery", "security", "data"]
    data = next(p for p in dctx.ap.get("/api/packages").json() if p["kind"] == "data")
    assert "base_deployment" not in data["body"]


@pytest.mark.parametrize("case", ["base_rolled_back", "base_is_delivery", "base_verified_state_missing", "base_superseded"])
def test_stale_or_failed_base_deployment_blocks_approval_and_deploy(dctx, monkeypatch, case):
    from autopilot import web
    sec, _ = security_deployed_then_new_assessment(dctx, monkeypatch)
    ids = recommend(dctx)
    db = web.STORE.db
    if case == "base_rolled_back":                       # base no longer succeeded (e.g. rolled back after Recommend)
        db.execute("UPDATE deployment SET status='rolled-back' WHERE id=?", (sec["id"],))
    elif case == "base_is_delivery":                     # package points at a non-Security deployment
        dlv = db.execute("SELECT d.id FROM deployment d JOIN package p ON p.id=d.package_id WHERE p.kind='delivery' "
                         "AND d.status='succeeded'").fetchone()["id"]
        row = db.execute("SELECT body FROM package WHERE id=?", (ids["data"],)).fetchone()
        body = json.loads(row["body"]); body["base_deployment"] = dlv
        db.execute("UPDATE package SET body=? WHERE id=?", (json.dumps(body), ids["data"]))
    elif case == "base_verified_state_missing":          # no verified state recorded for the base
        db.execute("DELETE FROM verified_state WHERE deployment_id=?", (sec["id"],))
    else:                                                # device moved on: its current verified state belongs to a newer deployment
        h = db.execute("SELECT state_hash FROM verified_state WHERE deployment_id=?", (sec["id"],)).fetchone()["state_hash"]
        db.execute("UPDATE verified_state SET deployment_id='newer-deployment' WHERE state_hash=?", (h,))
    writes = len([x for x in dctx.bigip.calls if x[0] in ("POST", "DELETE")])
    rv = dctx.ap.get(f"/api/packages/{ids['data']}/review")
    r = dctx.ap.post(f"/api/packages/{ids['data']}/decision", json={"decision": "approved", "comment": "t"})
    assert r.status_code == 409, (rv.status_code, r.text)
    assert "sequence.requires" in r.json()["detail"] or "requires a successful, validated AI Security deployment" in r.json()["detail"]
    assert dctx.ap.post(f"/api/packages/{ids['data']}/deploy").status_code == 409
    assert len([x for x in dctx.bigip.calls if x[0] in ("POST", "DELETE")]) == writes          # nothing written to BIG-IP
