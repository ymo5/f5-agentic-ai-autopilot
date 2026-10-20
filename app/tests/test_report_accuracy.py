"""Customer-report accuracy (doc 38 audit, 2026-10-17): one comparison model, correctly timestamped evidence, no stale or
artificial resolution. Each test names the audit defect it guards."""
from __future__ import annotations

import asyncio
import copy
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import TRACE, discover, review  # noqa: E402

LOCKED = {"error": "HTTPException: 409: live execution is locked for replica_stop (locked: no live window authorised)"}
DEFECT = {"error": "TypeError: verify=<str> cannot be combined with `cert=...`"}


# ------------------------------------------------------------------ helpers
def _validator(ctx, fail=()):
    """Every proving test of each package passes in its own profile (as the deployment gates would observe)."""
    proven = {}

    async def validator(profile):
        names = (set(proven.get("after-delivery", ())) | {"a2a.streaming"}
                 | (set(proven.get("after-security", ())) if profile == "after-security" else set()))
        return [{"test": n, "result": "fail" if n in fail else "pass", "observed": {}, "expected": ""} for n in sorted(names)]
    ctx.engine.validator = validator
    return proven


def _learn(ctx, proven):
    for p in ctx.viewer.get("/api/packages").json():
        proven["after-" + p["kind"]] = (p["body"].get("expected_outcomes") or {}).get("proven_by") or []


def _deploy(ctx, pid):
    review(ctx, pid)
    r = ctx.ap.post(f"/api/packages/{pid}/decision", json={"decision": "approved", "comment": "t"})
    assert r.status_code == 200, r.text
    d = ctx.ap.post(f"/api/packages/{pid}/deploy").json()
    assert d["status"] == "succeeded", d
    return d["id"]


def _assessment(ctx, name):
    aid = ctx.op.post("/api/assessment/new", json={"name": name}).json()["id"]
    ids = discover(ctx)
    assert ctx.op.post("/api/discover/observe").status_code == 200
    return aid, ids


def _run(w, aid, label, results, t=None):
    rid = f"v{time.time_ns()}"
    w.STORE.db.execute("INSERT INTO validation_run VALUES (?,?,?,?,?,?)", (rid, aid, label, t or time.time(), t or time.time(), json.dumps(results)))
    return rid


def _outcomes(cmp_):
    return {(f["rule_id"], f["title"]): f["outcome"] for f in cmp_["findings"]}


def _live_like(ctx):
    """The 2026-10-17 sequence: baseline discovery → Delivery → 'after' discovery → Security deployed AFTER that discovery."""
    from autopilot import web
    proven = _validator(ctx)
    ids = discover(ctx)
    assert ctx.op.post("/api/discover/observe").status_code == 200
    _learn(ctx, proven)
    before = web.STORE.current()["id"]
    d1 = _deploy(ctx, ids["delivery"])
    time.sleep(0.01)
    after, ids2 = _assessment(ctx, "after")
    time.sleep(0.01)
    d2 = _deploy(ctx, ids2["delivery"])                   # live: Delivery 48c7 replaced by 5319 after the 'after' discovery
    s1 = _deploy(ctx, ids2["security"])
    return web, before, after, (d1, d2), s1


# ------------------------------------------------------------------ defect 3: Jaeger window
def test_jaeger_query_uses_an_explicit_window_and_drops_traces_that_started_before_it(monkeypatch):
    from autopilot.sources import ingest
    now, calls = 1_800_000_000.0, []

    class R:
        def __init__(self, d):
            self.d = d

        def json(self):
            return self.d

    class Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, params=None):
            if url.endswith("/api/services"):
                return R({"data": ["agent-b", "jaeger-all-in-one"]})
            calls.append(params)
            old = {"traceID": "old", "spans": [{"startTime": int((now - 4 * 3600) * 1e6)}, {"startTime": int((now - 60) * 1e6)}]}
            new = {"traceID": "new", "spans": [{"startTime": int((now - 60) * 1e6)}]}
            return R({"data": [old, new]})
    monkeypatch.setattr(ingest.httpx, "AsyncClient", Client)
    st = {}
    out = asyncio.run(ingest.fetch_traces("http://j", "3h", 2, None, stats=st, now=now))
    assert [t["traceID"] for t in out] == ["new"]                                      # began 4 h ago: outside "last 3h"
    assert calls == [{"service": "agent-b", "limit": 2, "start": int((now - 10800) * 1e6), "end": int(now * 1e6)}]
    assert "lookback" not in calls[0]                                                   # Jaeger ignores it — never rely on it
    assert st == {"start": now - 10800, "end": now, "truncated_services": ["agent-b"], "dropped_before_window": 1}
    calls.clear()
    asyncio.run(ingest.fetch_traces("http://j", "3h", 5, now - 600, stats=st, now=now))
    assert calls[0]["start"] == int((now - 600) * 1e6)                                  # since the last infrastructure change


def test_ingest_evidence_states_the_real_window_and_truncation(ctx, monkeypatch):
    from autopilot import web
    from autopilot.sources import ingest as i_src

    async def traces(*a, stats=None, **k):
        stats.update(start=1_800_000_000.0, end=1_800_003_600.0, truncated_services=["mcp-risk-scoring"], dropped_before_window=4)
        return [TRACE]
    monkeypatch.setattr(i_src, "fetch_traces", traces)
    ctx.op.post("/api/discover/enumerate")
    assert ctx.op.post("/api/discover/ingest").status_code == 200
    ev = [e for e in web.STORE.evidence() if e["source"] == "ingest"][-1]
    assert "window 2027-01-15 08:00:00–09:00:00 UTC" in ev["summary"] and "search limit" in ev["summary"] and "mcp-risk-scoring" in ev["summary"]
    raw = json.loads(web.STORE.db.execute("SELECT raw FROM evidence WHERE id=?", (ev["id"],)).fetchone()[0])
    assert raw["window"]["start"] == 1_800_000_000.0 and raw["window"]["dropped_before_window"] == 4


# ------------------------------------------------------------------ validation evidence rules (defect 8)
def test_window_locked_checks_are_not_run_and_client_defect_runs_are_invalid():
    from autopilot import validation_evidence as ve
    assert ve.effective({"test": "delivery.failover", "result": "fail", "observed": LOCKED}) == "not_run"
    assert ve.effective({"test": "delivery.failover", "result": "fail", "observed": {"error": "timeout"}}) == "fail"
    assert ve.run_note([{"test": "x", "result": "fail", "observed": DEFECT}]).startswith("invalid run")
    assert "did not run" in ve.run_note([{"test": "delivery.failover", "result": "fail", "observed": LOCKED}])
    assert ve.run_note([{"test": "x", "result": "pass", "observed": {}}]) is None


# ------------------------------------------------------------------ defects 1 + 2: stale 'after', outdated linked deployment
def test_after_discovery_older_than_security_reports_awaiting_rediscovery_never_resolved(ctx):
    from autopilot import report
    w, before, after, (d1, d2), s1 = _live_like(ctx)
    c = report.compare(w.STORE, before, after)
    sec_rows = [f for f in c["findings"] if f.get("package") == "security"]
    assert sec_rows and not any(f["outcome"].startswith("resolved") for f in sec_rows)
    assert any(f["outcome"].startswith("awaiting rediscovery") for f in sec_rows)
    waiting = [f for f in c["findings"] if f["outcome"].startswith("awaiting rediscovery")]
    assert c["summary"]["awaiting_rediscovery"] == len(waiting)
    for f in waiting:                                    # every claim carries its evidence: in-place deployment + passing tests + times
        assert f["evidence"]["deployment_in_place"]["id"] == {"delivery": d2, "security": s1}[f["package"]] and f["evidence"]["after_discovered_at"] < f["evidence"]["deployment_in_place"]["started"]
        assert f["evidence"]["tests"] and all(t["result"] == "pass" and t["at"] >= f["evidence"]["deployment_in_place"]["started"] for t in f["evidence"]["tests"])
    cp = c["comparability"]
    assert {d["id"] for d in cp["post_discovery_deployments"]} == {d2, s1}
    assert "newer protection not yet rediscovered" in cp["label"] and any("predates protection now in place" in r for r in cp["reasons"])
    linked = cp["linked_successful_deployments"]                # the deployment the discovery saw, and what it is now
    assert [d["id"] for d in linked] == [d1] and linked[0]["in_place"] is False and linked[0]["now"].startswith(f"superseded by {d2}")
    assert c["summary"]["remaining"] == sum(f["outcome"].startswith("remaining") for f in c["findings"])
    assert c["summary"]["not_addressed"] == sum(f["outcome"] == "remaining — not addressed by any package" for f in c["findings"])
    assert c["summary"]["findings_before"] == len(c["findings"]) and c["summary"]["risk_types_before"] == len({f["rule_id"] for f in c["findings"]})


def test_failed_latest_validation_and_invalid_runs(ctx):
    from autopilot import report
    w, before, after, _, _ = _live_like(ctx)
    base = _outcomes(report.compare(w.STORE, before, after))
    waiting = [k for k, v in base.items() if v.startswith("awaiting rediscovery")]
    need = report.catalog.tests_for(waiting[0][0], waiting[0][1])
    # a newer run invalidated by the validator client defect changes nothing
    _run(w, after, "after-security", [{"test": t, "result": "fail", "observed": DEFECT} for t in need])
    assert _outcomes(report.compare(w.STORE, before, after)) == base
    # a newer genuine failure of a proving test removes the claim
    _run(w, after, "after-security", [{"test": t, "result": "fail", "observed": {"status": 200}} for t in need])
    now = _outcomes(report.compare(w.STORE, before, after))
    assert now[waiting[0]].startswith("remaining — deployed after this discovery; latest validation failed")


def test_window_locked_failover_does_not_flip_a_resolved_finding(ctx):
    from autopilot import report
    w, before, after, _, _ = _live_like(ctx)
    base = _outcomes(report.compare(w.STORE, before, after))
    assert base[next(k for k in base if k[0] == "D-002")] == "resolved (validated)"
    _run(w, after, "after-security", [{"test": "delivery.failover", "result": "fail", "observed": LOCKED}])
    assert _outcomes(report.compare(w.STORE, before, after)) == base
    runs = report.annotate_runs([dict(r) | {"results": json.loads(r["results"])} for r in w.STORE.db.execute(
        "SELECT * FROM validation_run WHERE assessment_id=?", (after,))])
    assert runs[-1]["effective"] == {"pass": 0, "fail": 0, "not_run": 1, "ran": 0} and "did not run" in runs[-1]["note"]


def test_rediscovery_after_security_is_the_only_way_to_resolved(ctx):
    """After a fresh discovery the stale category disappears: findings are resolved or remaining on current evidence."""
    from autopilot import report
    w, before, _, _, _ = _live_like(ctx)
    time.sleep(0.01)
    after2, _ = _assessment(ctx, "after-security")
    c = report.compare(w.STORE, before, after2)
    assert c["summary"]["awaiting_rediscovery"] == 0 and not c["comparability"]["post_discovery_deployments"]
    for f in c["findings"]:
        if f["outcome"] == "resolved (validated)":
            assert f["evidence"]["tests"] and all(t["result"] == "pass" for t in f["evidence"]["tests"])
    # the mock scan still reports unauthenticated MCP servers: rediscovery keeps them visible as remaining
    assert any(f["rule_id"] == "S-002" and f["outcome"] == "remaining" for f in c["findings"])


# ------------------------------------------------------------------ defect 4: D-003 / S-009 / D-005 clear on evidence only
def test_controls_clear_only_with_evidence_from_a_deployment_in_place_before_the_observe(ctx, monkeypatch):
    from autopilot import web
    from autopilot.sources import ingest as i_src
    slow = copy.deepcopy(TRACE)
    for s in slow["spans"]:
        if s["spanID"] == "b1":                                   # 45 s A2A task through BIG-IP to the pooled agent: D-005 applies
            s["duration"] = 45_000_000
            s["tags"] = [{"key": "span.kind", "value": "server"}, {"key": "http.host", "value": "10.50.20.22:9000"},
                         {"key": "net.peer.ip", "value": "10.50.20.10"}, {"key": "http.target", "value": "/"}]

    async def traces(*a, **k):
        return [slow]
    monkeypatch.setattr(i_src, "fetch_traces", traces)
    proven = _validator(ctx)
    ids = discover(ctx)
    assert ctx.op.post("/api/discover/observe").status_code == 200
    _learn(ctx, proven)
    rules = lambda: {r[0] for r in web.STORE.db.execute("SELECT rule_id FROM finding WHERE assessment_id=?", (web.STORE.current()["id"],))}  # noqa: E731
    assert {"D-003", "D-005", "S-009"} <= rules()                  # baseline: nothing deployed
    _deploy(ctx, ids["delivery"])
    time.sleep(0.01)
    _, ids2 = _assessment(ctx, "delivery")
    assert "D-003" not in rules() and "D-005" not in rules()       # persistence / streaming evidenced for the in-place Delivery
    assert "S-009" in rules()                                      # no Security: rate limiting not evidenced
    _deploy(ctx, ids2["delivery"])
    _deploy(ctx, ids2["security"])
    assert ctx.op.post("/api/discover/ingest").status_code == 200   # re-assess the SAME (pre-Security) discovery
    assert "S-009" in rules()                                      # later test results never rewrite an older discovery
    time.sleep(0.01)
    _assessment(ctx, "security")
    assert "S-009" not in rules()                                  # Security in place before this Observe + rate_limited passed


def test_s009_stays_when_the_rate_limit_test_failed(ctx):
    from autopilot import web
    proven = _validator(ctx, fail=())
    ids = discover(ctx)
    assert ctx.op.post("/api/discover/observe").status_code == 200
    _learn(ctx, proven)
    _deploy(ctx, ids["delivery"])
    _, ids2 = _assessment(ctx, "d")
    _deploy(ctx, ids2["delivery"])
    _deploy(ctx, ids2["security"])
    aid, _ = _assessment(ctx, "s")
    _run(web, aid, "after-security", [{"test": "security.rate_limited", "result": "fail", "observed": {"429": 0}}])
    assert ctx.op.post("/api/discover/ingest").status_code == 200
    assert "S-009" in {r[0] for r in web.STORE.db.execute("SELECT rule_id FROM finding WHERE assessment_id=?", (aid,))}


# ------------------------------------------------------------------ defects 5–7 + export consistency
def test_coverage_metrics_are_defined_and_match_the_overview(ctx):
    from autopilot import report
    w, before, after, _, _ = _live_like(ctx)
    c = report.compare(w.STORE, before, after)
    ca = c["coverage"]["after"]
    assert ca["ai_endpoints_behind_bigip"] == sum(e["fronted"] for e in ca["endpoints"]) and ca["ai_endpoints"] == len(ca["endpoints"])
    o = ctx.viewer.get("/api/overview").json()
    assert ca["services"]["fronted"] == o["questions"]["protected"]["yes"] and ca["services"]["total"] == o["questions"]["operating"]["value"]
    assert set(c["coverage"]["definitions"]) == {"endpoints", "services", "scope"}
    html = report.executive_html(w.STORE, after, before)
    assert "A2A/MCP endpoints fronted by BIG-IP" in html and "AI services behind BIG-IP" not in html
    assert f"AI services fronted by BIG-IP (Overview definition): {ca['services']['fronted']} of {ca['services']['total']}" in html


def test_performance_never_prints_none_and_claims_nothing_without_a_baseline(ctx):
    from autopilot import report
    w, before, after, _, _ = _live_like(ctx)
    vp = report.compare(w.STORE, before, after)["validation_performance"]
    assert vp["rows"][0]["profile"] == "before" and vp["rows"][0]["measured"] is False and vp["comparable"] is False
    assert "no before/after performance comparison is claimed" in vp["statement"]
    _run(w, "some-other-assessment", "before", [{"test": "perf.mcp_tool_latency", "result": "pass", "observed": {"p50_ms": 9, "p95_ms": 9}}])
    assert report.compare(w.STORE, before, after)["validation_performance"]["rows"][0]["measured"] is False   # other assessments never count
    _run(w, before, "before", [{"test": "perf.mcp_tool_latency", "result": "pass", "observed": {"p50_ms": 30.0, "p95_ms": 41.0}}])
    _run(w, after, "after-security", [{"test": "perf.mcp_tool_latency", "result": "pass", "observed": {"p50_ms": 46.3, "p95_ms": 53.4}}])
    vp = report.compare(w.STORE, before, after)["validation_performance"]
    assert vp["comparable"] and vp["rows"][0]["mcp_p50_ms"] == 30.0 and vp["rows"][-1]["mcp_p50_ms"] == 46.3
    for page in (report.executive_html(w.STORE, after, before), report.html_report(w.STORE, after, before)):
        assert ">None<" not in page and "None ms" not in page


def test_fraud_history_is_timestamped_scoped_and_says_when_security_is_unproven(ctx):
    from autopilot import report
    w, before, after, _, _ = _live_like(ctx)
    b0 = w.STORE.db.execute("SELECT created FROM assessment WHERE id=?", (before,)).fetchone()[0]

    def fr(rid, t, infra):
        w.STORE.db.execute("INSERT INTO fraud_run (id, created, scenario_id, state, seconds, infra_state, summary, response) VALUES (?,?,?,?,?,?,?,?)",
                           (rid, t, "ALERT-9001", "completed", 70.0, infra, json.dumps({"paths": {"a2a": ["direct"]}}), "{}"))
    fr("old", b0 - 86400, "delivery")                  # an earlier day: outside this comparison
    fr("base", b0 + 1, "baseline")
    fh = report.compare(w.STORE, before, after)["fraud_runs"]
    assert [r["id"] for r in fh["runs"]] == ["base"] and fh["runs"][0]["created_utc"].endswith("UTC") and fh["runs"][0]["infra_state"] == "baseline"
    assert fh["note"] and "since AI Security was deployed" in fh["note"]
    fr("sec", time.time() + 1, "security")
    fh = report.compare(w.STORE, before, after)["fraud_runs"]
    assert fh["note"] is None and fh["infra_states"] == ["baseline", "security"]
    html = report.executive_html(w.STORE, after, before)
    assert fh["runs"][0]["created_utc"] in html and "infrastructure at run time" in html


def test_executive_technical_and_bundle_share_one_model(ctx):
    from autopilot import report
    w, before, after, _, _ = _live_like(ctx)
    _run(w, after, "after-security", [{"test": "delivery.failover", "result": "fail", "observed": LOCKED}], t=time.time() - 5)
    _run(w, after, "after-security", [{"test": "delivery.failover", "result": "pass", "observed": {}}])
    b = report.evidence_bundle(w.STORE, after, before)
    c = b["comparison"]
    assert b["performance"] == c["validation_performance"] and b["fraud_runs"] == c["fraud_runs"]
    runs = [v for v in b["validation_runs"] if v["assessment_id"] == after]
    assert runs[0]["superseded_by"] == runs[1]["id"] and runs[1]["superseded_by"] is None
    s = c["summary"]
    ex = report.executive_html(w.STORE, after, before)
    assert f"<b>{s['resolved']}</b>risks resolved" in ex and f"<b>{s['awaiting_rediscovery']}</b>enforcement validated" in ex
    assert f"<b>{s['remaining']}</b>remaining ({s['not_addressed']} not addressed" in ex
    tech = report.html_report(w.STORE, after, before)
    assert f"<b>{s['resolved']}</b>resolved (validated)" in tech and f"<b>{s['awaiting_rediscovery']}</b>enforcement validated" in tech
    assert "not run (live window required)" in tech and "superseded by" in tech
    json.dumps(b, default=str)                                       # exportable
