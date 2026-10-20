"""v2 product guarantees: approval lifecycle, read-only polling, operations/progress, audit filtering, Describe analysis,
finding classification/grouping, identity attribution, recommendation explanations."""
from __future__ import annotations

import asyncio
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import TRACE, discover, proc, review, span  # noqa: E402


def approve(c, pid):
    return c.ap.post(f"/api/packages/{pid}/decision", json={"decision": "approved", "comment": "t"})


def pkgs(c, client=None):
    return {p["kind"]: p for p in (client or c.ap).get("/api/packages").json()}


def audit_actions(c, **q):
    qs = "&".join(f"{k}={v}" for k, v in q.items())
    return [r["action"] for r in c.ap.get(f"/api/audit?{qs}").json()["rows"]]


# ------------------------------------------------------------------ approval lifecycle
def test_approval_requires_passing_fresh_preflight(ctx):
    ids = discover(ctx)
    r = approve(ctx, ids["delivery"])
    assert r.status_code == 409 and "Preview, diff & preflight" in r.json()["detail"]
    assert pkgs(ctx)["delivery"]["lifecycle"]["state"] == "proposed"
    review(ctx, ids["delivery"])
    lc = pkgs(ctx)["delivery"]["lifecycle"]
    assert lc["state"] == "ready_for_approval" and lc["actions"]["approve"]["allowed"]
    ctx.web.STORE.db.execute("UPDATE package_review SET created=created-3600")            # stale preflight
    r = approve(ctx, ids["delivery"])
    assert r.status_code == 409 and "older than" in r.json()["detail"]
    review(ctx, ids["delivery"])
    ctx.hosts.profile["ap-agent-a"] = "delivery"                                          # device drift after preflight
    r = approve(ctx, ids["delivery"])
    assert r.status_code == 409 and "device state changed" in r.json()["detail"]


def test_duplicate_approvals_are_refused_by_the_backend(ctx):
    ids = discover(ctx)
    review(ctx, ids["delivery"])
    assert approve(ctx, ids["delivery"]).status_code == 200
    for _ in range(3):                                                                   # repeated clicks / API calls
        r = approve(ctx, ids["delivery"])
        assert r.status_code == 409 and "duplicate approvals" in r.json()["detail"]
    n = ctx.web.STORE.db.execute("SELECT COUNT(*) FROM approval WHERE package_id=? AND decision='approved'", (ids["delivery"],)).fetchone()[0]
    assert n == 1
    lc = pkgs(ctx)["delivery"]["lifecycle"]
    assert lc["state"] == "approved" and not lc["actions"]["approve"]["allowed"] and "duplicate" in lc["actions"]["approve"]["reason"]


def test_retry_after_failure_requires_review_new_approval_and_never_reuses_consumed(ctx):
    ids = discover(ctx)
    ctx.gate["result"] = "fail"
    review(ctx, ids["delivery"])
    a1 = approve(ctx, ids["delivery"]).json()
    d1 = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()
    assert d1["status"] == "failed-rolled-back"
    p = pkgs(ctx)["delivery"]
    assert p["lifecycle"]["state"] == "failed" and p["deployments"][0]["diagnosis"]["failed_step"].startswith("gate.validate")
    assert "Request a new approval" in " ".join(p["deployments"][0]["diagnosis"]["next_actions"])
    r = approve(ctx, ids["delivery"])                                                    # preflight predates the failure
    assert r.status_code == 409 and "failed after the last preflight" in r.json()["detail"]
    r = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy")                            # consumed approval cannot be reused
    assert r.status_code == 409
    ctx.gate["result"] = "pass"
    review(ctx, ids["delivery"])
    a2 = approve(ctx, ids["delivery"]).json()
    assert a2["id"] != a1["id"]
    assert ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()["status"] == "succeeded"
    assert pkgs(ctx)["delivery"]["lifecycle"]["state"] == "deployed"
    r = approve(ctx, ids["delivery"])
    assert r.status_code == 409


def test_revoke_and_role_based_actions(ctx):
    ids = discover(ctx)
    review(ctx, ids["delivery"])
    a = approve(ctx, ids["delivery"]).json()
    view = pkgs(ctx, ctx.viewer)["delivery"]["lifecycle"]["actions"]
    assert not any(v["allowed"] for v in view.values()) and view["deploy"]["reason"] == "approver role required"
    op = pkgs(ctx, ctx.op)["delivery"]["lifecycle"]["actions"]
    assert op["review"]["allowed"] and not op["approve"]["allowed"] and not op["deploy"]["allowed"]
    assert ctx.op.post(f"/api/approvals/{a['id']}/revoke", json={"reason": "x"}).status_code == 403
    assert ctx.ap.post(f"/api/approvals/{a['id']}/revoke", json={"reason": "changed my mind"}).status_code == 200
    assert pkgs(ctx)["delivery"]["lifecycle"]["state"] == "revoked"
    assert ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").status_code == 409
    assert "approval.revoked" in audit_actions(ctx, category="approval")


def test_security_blocked_until_delivery_succeeded(ctx):
    ids = discover(ctx)
    sec = pkgs(ctx)["security"]["lifecycle"]
    assert sec["blocked"] and not sec["actions"]["deploy"]["allowed"]
    review(ctx, ids["delivery"])
    approve(ctx, ids["delivery"])
    ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy")
    review(ctx, ids["security"])
    sec = pkgs(ctx)["security"]["lifecycle"]
    assert not sec["blocked"] and sec["state"] == "ready_for_approval"


# ------------------------------------------------------------------ polling / assessment / audit
def test_polling_state_is_read_only_and_finding_ids_are_stable(ctx):
    discover(ctx)
    db = ctx.web.STORE.db
    n_audit = db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    ids1 = sorted(r[0] for r in db.execute("SELECT id FROM finding"))
    for _ in range(5):
        assert ctx.viewer.get("/api/state").status_code == 200
    assert db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == n_audit           # no assessment.run per poll
    assert sorted(r[0] for r in db.execute("SELECT id FROM finding")) == ids1
    ctx.op.post("/api/ops/assess")                                                     # re-assess unchanged evidence
    assert sorted(r[0] for r in db.execute("SELECT id FROM finding")) == ids1
    assert db.execute("SELECT COUNT(*) FROM audit WHERE action='assessment.run'").fetchone()[0] <= 2


def test_audit_filters(ctx):
    ids = discover(ctx)
    review(ctx, ids["delivery"])
    approve(ctx, ids["delivery"])
    rows = ctx.ap.get("/api/audit?category=approval").json()
    assert rows["rows"] and all(r["category"] == "approval" for r in rows["rows"])
    assert {"package.preflight", "package.approved"} <= {r["action"] for r in rows["rows"]}
    assert all(r["actor"] == "approver1" for r in ctx.ap.get("/api/audit?actor=approver1").json()["rows"])
    assert ctx.ap.get("/api/audit?q=preflight").json()["rows"]


# ------------------------------------------------------------------ operations
def test_operations_record_progress_and_results(ctx):
    r = ctx.op.post("/api/ops/discover", json={"methods": ["enumerate", "ingest"]}).json()
    o = ctx.op.get(f"/api/ops/{r['id']}").json()
    assert o["status"] == "succeeded" and [s["name"].split(" —")[0] for s in o["steps"]] == ["Enumerate", "Ingest", "Assess"]
    assert all(s["status"] == "ok" for s in o["steps"]) and o["result"]["assessment"]["findings"] > 0
    assert o["eta_s"] is None                                                          # no history -> no ETA claimed
    r = ctx.op.post("/api/ops/recommend").json()
    assert ctx.op.get(f"/api/ops/{r['id']}").json()["result"]["packages"]
    assert ctx.viewer.post("/api/ops/discover", json={"methods": ["enumerate"]}).status_code == 403


def test_eta_only_with_enough_history(ctx):
    from autopilot import operations
    db = ctx.web.STORE.db
    now = time.time()
    for i in range(3):
        db.execute("INSERT INTO operation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (f"h{i}", "validate", "v", "succeeded", "x", "a",
                   now - 1000, now - 1000 + 100, "", "[]", None, None, None))
    db.execute("INSERT INTO operation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", ("cur", "validate", "v", "running", "x", "a", now - 40, None, "",
               "[]", None, None, None))
    o = operations.get(ctx.web.STORE, "cur")
    assert 55 <= o["eta_s"] <= 61 and "median of 3" in o["eta_basis"]


def test_busy_operations_are_refused(ctx):
    db = ctx.web.STORE.db
    db.execute("INSERT INTO operation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", ("run1", "discover", "Discover", "running", "se1", "a",
               time.time(), None, "", "[]", None, None, None))
    r = ctx.op.post("/api/ops/describe", json={"text": "The fraud agent calls an MCP scoring service."})
    assert r.status_code == 409 and "still running" in r.json()["detail"]


# ------------------------------------------------------------------ Describe analysis / findings
def test_describe_analysis_reports_claims_contradictions_and_follow_ups(ctx):
    discover(ctx)
    ctx.op.post("/api/ops/describe", json={"text": "The fraud agent calls an MCP risk scoring service. All MCP traffic goes through the "
                                                   "BIG-IP load balancer. The MCP servers are authenticated. A billing agent exists."})
    a = ctx.op.get("/api/describe/analysis").json()
    d = a["descriptions"][0]
    assert d["generated_by"].startswith("deterministic") and d["components"]
    statuses = {c["claim"]: c["status"] for c in d["claims"]}
    assert statuses.get("behind_bigip") == "contradicted" and statuses.get("authenticated") == "contradicted"
    assert a["contradictions"] and all(c["evidence"] for c in a["contradictions"])
    assert a["follow_up_questions"]
    g = {x["rule_id"]: x for x in ctx.op.get("/api/state").json()["findings_grouped"]}
    assert g["S-007"]["class"] == "contradicted_claim"
    assert list(g)[0] == "S-007"                                                       # contradictions listed first


def test_findings_grouped_and_classified(ctx):
    discover(ctx)
    st = ctx.op.get("/api/state").json()
    g = {x["rule_id"]: x for x in st["findings_grouped"]}
    assert g["S-002"]["class"] == "confirmed_vulnerability" and g["S-002"]["count"] == len([f for f in st["findings"] if f["rule_id"] == "S-002"])
    assert len(g["S-002"]["affected"]) >= 3 and g["D-003"]["class"] == "inferred_risk" and g["D-001"]["class"] == "architectural_gap"
    assert g["S-004"]["package"] is None and "not yet approved" in g["S-004"]["not_addressed"]
    assert "approved CIDRs" in st["scope"]["statement"] and st["scope"]["cidrs"]
    assert set(st["sources"]) == {"observe", "describe", "enumerate", "ingest"}


def test_recommendation_explanations_and_correct_closures(ctx):
    ids = discover(ctx)
    p = pkgs(ctx)
    dl, sc = p["delivery"]["body"], p["security"]["body"]
    assert "S-001" not in dl["expected_outcomes"]["closes"] and "S-001" in sc["expected_outcomes"]["closes"]
    ex = dl["explanation"]
    assert ex["business_value"] and ex["affected_services"] and ex["change_summary"]
    assert {f["rule"] for f in ex["findings_addressed"]} >= {"D-001", "D-002"}
    assert any(x["rule"] == "S-004" for x in ex["not_addressed"])
    assert any(c["object"] == "Virtual server + pool" for c in ex["change_summary"])
    assert sc["explanation"]["deployment_dependencies"][0].startswith("AI Delivery deployed")
    vips = {x["application"]: x["virtual_server"] for x in dl["architecture"]}
    assert vips["mcp_risk_scoring"] == "10.50.10.101:443" and vips["mcp_fraud_intel"] == "10.50.10.102:443"   # by server name
    assert "S-004" not in sc["expected_outcomes"]["closes"]


# ------------------------------------------------------------------ identity attribution
def test_context_less_callers_keyed_by_peer_and_attributed_only_with_evidence():
    from autopilot.sources.ingest import correlate
    t2 = {"traceID": "t2", "processes": {"pr": proc("mcp-risk-scoring", "risk-scoring-1"), "px": proc("probe")}, "spans": [
        span("s1", "pr", "POST /mcp", "server", {"http.host": "10.50.20.31:8000", "net.peer.ip": "10.50.20.22", "http.target": "/mcp"}),
        span("s2", "pr", "GET /healthz", "server", {"http.host": "10.50.20.31:8000", "net.peer.ip": "10.50.20.22", "http.target": "/healthz"}),
        span("s3", "pr", "GET /healthz", "server", {"http.host": "10.50.20.31:8000", "net.peer.ip": "10.50.20.63", "http.target": "/healthz"}),
    ]}
    out = correlate([TRACE, t2], set(), set(), peer_names={"10.50.20.22": "agent-b-svc", "10.50.20.63": "otel"})
    callers = {(e["caller"], e["protocol"]) for e in out["edges"]}
    assert ("agent-b-risk-assessment", "mcp") in callers                                 # context-less MCP call merged into agent B
    assert not any(c.startswith("client@agent-b-svc") or c == "client@otel" for c, _ in callers)   # never DNS-labelled keys
    assert ("client@10.50.20.22", "http") in callers                                      # host-level probe stays separate
    assert ("client@10.50.20.63", "http") in callers                                      # unknown host: unattributed
    assert out["attributions"] and out["attributions"][0]["attributed_to"] == "agent-b-risk-assessment"
    assert out["peer_hosts"]["10.50.20.22"] == ["agent-b-risk-assessment"]


def test_engine_level_preflight_refusal_writes_nothing(ctx):
    ids = discover(ctx)
    pkg = ctx.web._pkg(ids["security"])
    st = asyncio.run(ctx.engine.fingerprint())[0]
    a = ctx.web.approvals.record(ctx.web.STORE.db, assessment_id=pkg["assessment_id"], pkg=pkg, device_fingerprint=st, decision="rejected",
                                 user={"username": "approver1", "role": "approver"})
    ctx.web.STORE.db.execute("UPDATE approval SET decision='approved' WHERE id=?", (a["id"],))   # bypass UI rules to hit the engine
    d = asyncio.run(ctx.engine.deploy(pkg, a["id"], {"username": "approver1", "role": "approver"}))
    assert d["status"] == "refused-preflight" and "rollback" not in [s["step"] for s in d["steps"]]
    assert [c for c in ctx.bigip.calls if c[0] in ("POST", "DELETE")] == []
    assert json.loads(json.dumps(d))["error"].count("sequence.requires") == 1


def test_s007_package_and_tests_follow_the_contradicted_claim():
    from autopilot import catalog
    assert catalog.meta("S-007", "Customer assertion contradicted: 'behind_bigip' (MCP)")["package"] == "delivery"
    m = catalog.meta("S-007", "Customer assertion contradicted: 'authenticated' (MCP servers)")
    assert m["package"] == "security" and "security.unauthenticated_rejected" in m["tests"]
    assert catalog.meta("S-007", "Customer assertion contradicted: 'other' (x)")["package"] is None


def test_ingest_window_starts_at_last_infrastructure_change(ctx):
    from autopilot.engine import Engine
    eng = ctx.web.ENGINE
    assert eng.ingest_window() == (None, "traffic of the last 3h")
    ids = discover(ctx)
    review(ctx, ids["delivery"])
    approve(ctx, ids["delivery"])
    ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy")
    since, why = eng.ingest_window()
    assert since and time.time() - since < 60 and "last infrastructure change" in why
    assert isinstance(eng, Engine)


def test_reconciliation_never_matches_across_kinds_and_refuses_ties(ctx):
    discover(ctx)
    st = ctx.web.STORE
    eid = st.add_evidence("describe", "llm:test", "t", {})
    d1 = st.claim_asset(eid, "describe", "described:fraud-agent", "a2a_agent", "fraud_agent", {"asserted_kind": "a2a_agent"})
    d2 = st.claim_asset(eid, "describe", "described:risk-intel-server", "mcp_server", "risk_intel_server", {"asserted_kind": "mcp_server"})
    ctx.web.ENGINE.reconcile()
    keys = {a["key"] for a in st.assets()}
    names = {a["name"]: a for a in st.assets()}
    # 'fraud_agent' must not be merged into the fraud-intel MCP server (different kind)
    assert not any("fraud_agent" in (a["attrs"].get("described_as") or []) and a["kind"] in ("mcp_server", "mcp_service") for a in st.assets())
    # 'risk_intel_server' matches risk-scoring and fraud-intel equally -> ambiguous -> stays asserted
    assert "described:risk-intel-server" in keys
    assert d1 and d2 and names


def test_claim_text_fallback_and_bigip_self_label():
    from autopilot import claims
    assert claims  # module import
    from autopilot.sources.ingest import correlate
    t = {"traceID": "t9", "processes": {"pr": proc("mcp-risk-scoring", "risk-scoring-1")}, "spans": [
        span("m1", "pr", "POST /mcp", "server", {"http.host": "10.50.20.31:8000", "net.peer.ip": "10.50.20.10", "http.target": "/mcp"})]}
    out = correlate([t], {"10.50.20.10"}, set())
    e = next(e for e in out["edges"] if e["caller"] == "client@10.50.20.10")
    assert e["paths"] == {"via_bigip": 1}


def test_describe_claims_without_text_get_readable_text(ctx):
    discover(ctx)
    st = ctx.web.STORE
    st.add_evidence("describe", "llm:test", "SE description", {"text": "x", "author": "se1", "provenance": {"generated_by": "llm:test"},
                    "extraction": {"components": [], "relationships": [], "control_claims": [{"claim": "behind_bigip", "subject": "mcp servers", "text": None}]}})
    a = ctx.op.get("/api/describe/analysis").json()
    c = a["descriptions"][-1]["claims"][0]
    assert c["text"] == "mcp servers is behind bigip" and c["status"] == "contradicted"
    assert all('""' not in q for q in a["follow_up_questions"])


def test_component_kind_consistency_with_name():
    from autopilot.engine import _kind_hint
    assert _kind_hint("risk_agent", "mcp_server") == "a2a_agent"
    assert _kind_hint("risk agent MCP server", "a2a_agent") == "mcp_server"
    assert _kind_hint("intel_mcp_server", "mcp_server") == "mcp_server"
    assert _kind_hint("vector store", "vector_db") == "vector_db"
