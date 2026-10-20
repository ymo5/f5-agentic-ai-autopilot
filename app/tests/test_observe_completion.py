"""Observe dashboard accuracy (2026-10-18 owner review): workflow stage 7 completes only on genuine post-deployment evidence;
client agents are 'n/a' (no inbound BIG-IP virtual server needed); an LLM endpoint without a virtual server stays unprotected
and says why (outside the AI Delivery/Security package scope, open finding S-008)."""
from __future__ import annotations

import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import discover  # noqa: E402
from test_report_accuracy import LOCKED, _deploy, _learn, _live_like, _run, _validator  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _ov(ctx):
    return ctx.viewer.get("/api/overview").json()


def _crit(o):
    return {c["key"]: c["ok"] for c in o["observe_completion"]["criteria"]}


def _rediscover(ctx):
    time.sleep(0.01)
    for m in ("observe", "enumerate", "ingest"):
        assert ctx.op.post(f"/api/discover/{m}").status_code == 200


# ------------------------------------------------------------------ Observe completion criteria
def test_observe_is_not_complete_until_rediscovery_after_the_deployments(ctx):
    from autopilot import web
    _live_like(ctx)                                     # live 2026-10-17: the current discovery predates Delivery and Security
    ch = web.STORE.db.total_changes
    o = _ov(ctx)
    _ov(ctx)                                            # viewing the dashboard (repeatedly) never completes the stage
    assert web.STORE.db.total_changes == ch             # read-only
    oc = o["observe_completion"]
    assert oc["complete"] is False and _crit(o) == {"deployments": True, "validation": True, "fresh_evidence": False, "protection": False}
    assert "rediscover after the latest deployment" in oc["next"] and all(s in oc["next"] for s in ("observe", "enumerate", "ingest"))
    _rediscover(ctx)                                    # the explicit action the workflow asks for
    o = _ov(ctx)
    assert o["observe_completion"]["complete"] is True and all(_crit(o).values()) and o["observe_completion"]["next"] is None


def test_partial_rediscovery_is_not_enough(ctx):
    _live_like(ctx)
    time.sleep(0.01)
    assert ctx.op.post("/api/discover/observe").status_code == 200       # Observe only: Enumerate and Ingest are still stale
    oc = _ov(ctx)["observe_completion"]
    assert oc["complete"] is False and "enumerate" in oc["next"] and "ingest" in oc["next"] and "observe," not in oc["next"]


def test_observe_needs_ai_security_in_place_not_only_delivery(ctx):
    proven = _validator(ctx)
    ids = discover(ctx)
    assert ctx.op.post("/api/discover/observe").status_code == 200
    _learn(ctx, proven)
    _deploy(ctx, ids["delivery"])
    _rediscover(ctx)
    o = _ov(ctx)
    assert o["observe_completion"]["complete"] is False and _crit(o)["deployments"] is False
    assert "in place: delivery" in o["observe_completion"]["criteria"][0]["detail"]


def test_a_failing_latest_after_security_validation_blocks_completion(ctx):
    from autopilot import web
    _live_like(ctx)
    _rediscover(ctx)
    assert _ov(ctx)["observe_completion"]["complete"] is True
    aid = web.STORE.current()["id"]
    _run(web, aid, "after-security", [{"test": "security.tool_policy", "result": "fail", "observed": {}}], t=time.time() + 1)
    o = _ov(ctx)
    assert o["observe_completion"]["complete"] is False and _crit(o)["validation"] is False
    # a newer run whose only non-pass is a window-locked check (not run) is not a failure
    _run(web, aid, "after-security", [{"test": "security.tool_policy", "result": "pass", "observed": {}},
                                      {"test": "delivery.failover", "result": "fail", "observed": LOCKED}], t=time.time() + 2)
    o = _ov(ctx)
    assert o["observe_completion"]["complete"] is True and "1 not run" in o["observe_completion"]["criteria"][1]["detail"]


def test_protection_state_must_be_established_by_the_evidence(ctx, monkeypatch):
    from autopilot import overview
    _live_like(ctx)
    _rediscover(ctx)
    real = overview.placement.devices_from_store
    monkeypatch.setattr(overview.placement, "devices_from_store",
                        lambda *a, **k: [{**d, "virtuals_state": "missing"} for d in real(*a, **k)])
    o = _ov(ctx)
    assert o["observe_completion"]["complete"] is False and _crit(o)["protection"] is False
    assert o["observe_completion"]["criteria"][3]["detail"].startswith("protection state not established")


def test_stage_strip_takes_observe_only_from_the_server_verdict():
    js = (ROOT / "app/autopilot/static/app.js").read_text()
    assert "observe: false" not in js
    assert "observe: !!(OVR && !OVR.error && OVR.observe_completion && OVR.observe_completion.complete)" in js
    assert '"n/a": "skipped"' in js                                         # neutral grey badge, never green


# ------------------------------------------------------------------ protection classification
def test_client_agent_is_not_applicable_and_keeps_its_findings(ctx):
    _live_like(ctx)
    o = _ov(ctx)
    a = next(s for s in o["services"] if s["name"] == "agent-a-fraud-investigation")
    assert a["kind"] == "ai_agent" and a["protected"] == "n/a" and a["delivered_by"] == []
    assert a["protection_note"] == "client — no inbound virtual server needed" and "client agent" in a["protected_basis"]
    assert "S-001" in a["rules"]                                             # its outbound-path finding is still reported
    P = o["questions"]["protected"]
    assert P["not_applicable"] == 1 and P["applicable"] == o["questions"]["operating"]["value"] - 1
    assert P["yes"] + P["no"] + P["unknown"] == P["applicable"]
    # services BIG-IP should front keep their real state: nothing else became 'n/a'
    assert all(s["protected"] in ("yes", "no", "unknown") for s in o["services"] if s["kind"] != "ai_agent")


def test_a_client_agent_that_is_actually_fronted_still_shows_yes(ctx, monkeypatch):
    from autopilot import overview
    _live_like(ctx)
    real_cov, real_rec = overview.placement._coverage, overview.identity.reconcile

    def rec(store, aid):
        out = real_rec(store, aid)
        out["services"] = [{**s, "endpoints": s["endpoints"] or [{"address": "10.50.10.21:8080", "asset_id": "x", "role": "agent"}]}
                           if s["kind"] == "ai_agent" else s for s in out["services"]]
        return out
    monkeypatch.setattr(overview.identity, "reconcile", rec)
    monkeypatch.setattr(overview.placement, "_coverage", lambda s, d: real_cov(s, d) or (
        [{"device": "bigip:192.0.2.16", "virtual": "/AP_AI/agent_a/service", "destination": "10.50.10.110:443"}] if s["kind"] == "ai_agent" else []))
    a = next(s for s in _ov(ctx)["services"] if s["kind"] == "ai_agent")
    assert a["protected"] == "yes" and a["protection_note"] is None


def _with_llm(monkeypatch, s008=True):
    from autopilot import overview
    real_rec, real_find = overview.identity.reconcile, overview.assess.findings

    def rec(store, aid):
        out = real_rec(store, aid)
        out["services"] = out["services"] + [{"id": "svc-llm", "name": "llm", "kind": "llm_endpoint", "classification": "LLM endpoint",
                                              "verified": True, "grouping": "single", "asset_ids": ["asset-llm"],
                                              "endpoints": [{"address": "10.50.20.45:11434", "asset_id": "asset-llm", "role": "llm"}]}]
        return out

    def find(store):
        extra = [{"id": "f-s008", "rule_id": "S-008", "severity": "medium", "asset_ids": ["asset-llm"]}] if s008 else []
        return real_find(store) + extra
    monkeypatch.setattr(overview.identity, "reconcile", rec)
    monkeypatch.setattr(overview.assess, "findings", find)


def test_llm_without_a_virtual_server_stays_unprotected_and_says_why(ctx, monkeypatch):
    _live_like(ctx)
    _with_llm(monkeypatch)
    o = _ov(ctx)
    llm = next(s for s in o["services"] if s["name"] == "llm")
    assert llm["protected"] == "no" and llm["delivered_by"] == []            # genuinely unprotected: red, never 'n/a' or green
    assert llm["protection_note"] == "outside AI Delivery/Security package scope · open finding S-008"
    assert "outside the current AI Delivery/Security package scope" in llm["protected_basis"] and "S-008" in llm["protected_basis"]
    assert o["questions"]["protected"]["no"] >= 1


def test_llm_note_names_s008_only_when_the_finding_is_open(ctx, monkeypatch):
    _live_like(ctx)
    _with_llm(monkeypatch, s008=False)
    llm = next(s for s in _ov(ctx)["services"] if s["name"] == "llm")
    assert llm["protected"] == "no" and llm["protection_note"] == "outside AI Delivery/Security package scope" and "S-008" not in llm["protected_basis"]
