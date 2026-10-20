"""Wave 1 regression tests: evidence navigation, trust levels, comparison accuracy, latency statistics, downloads, caching.

One test per confirmed defect from the manual review (see docs/70-improvement-program/backlog.md, W1-*).
"""
from __future__ import annotations

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import TRACE, discover, review  # noqa: E402


def full_discover(c):
    for m in ("observe", "enumerate", "ingest"):
        r = c.op.post(f"/api/discover/{m}")
        assert r.status_code == 200, r.text


# ------------------------------------------------------------------ W1-08 latency statistics (p95 < p50 defect)
def test_percentiles_are_monotonic_and_report_sample_count():
    from autopilot.stats import latency_summary, percentile
    for vals in ([5.0, 100.0], [1, 2], [3], [10, 1, 7, 2, 9, 4, 8], list(range(1, 101))):
        s = latency_summary(vals)
        assert s["p50"] <= s["p95"] <= s["max"], (vals, s)       # old code: p95 = min(values) for n=2
        assert s["n"] == len(vals)
    assert percentile([5.0, 100.0], 95) == 100.0 and percentile([5.0, 100.0], 50) == 5.0
    assert latency_summary([1, 2])["p95_reliable"] is False and latency_summary(list(range(30)))["p95_reliable"] is True
    assert latency_summary([]) is None


def test_ingest_edges_never_show_p95_below_p50_and_split_operations(ctx):
    from autopilot.sources import ingest
    corr = ingest.correlate([TRACE], set(), set(), set(), set(), {})
    for e in corr["edges"]:
        lat = e["latency_ms"]
        if lat:
            assert lat["p50"] <= lat["p95"] <= lat["max"] and lat["n"] >= 1
            assert e["latency_source"] and isinstance(e["latency_by_operation"], dict)


# ------------------------------------------------------------------ W1-04/05 topology & evidence navigation
def test_asset_dossier_has_identity_protocol_findings_and_trust(ctx):
    full_discover(ctx)
    st = ctx.viewer.get("/api/state").json()
    agent = next(n for n in st["graph"]["nodes"] if n["kind"] == "a2a_agent" and n["key"] == "ep:10.50.10.22:9000")
    d = ctx.viewer.get(f"/api/assets/{agent['id']}").json()
    assert d["identity"]["ip"] == "10.50.10.22" and d["identity"]["port"] == "9000" and "A2A" in d["identity"]["protocol"]
    assert d["agent_card"]["name"] == "Risk Assessment Agent" and d["agent_card"]["security_schemes"] == []
    assert any(f["rule_id"] == "S-004" for f in d["findings"])                 # A2A agent advertises no authentication
    assert all(c["trust"]["level"] for c in d["claims"]) and d["verified"] is True
    assert all({"peer", "path", "evidence_ids"} <= set(c) for c in d["communications"])
    assert "relationships" in d                                                # backwards compatible field kept


def test_mcp_dossier_lists_tools_with_privilege_and_replicas(ctx):
    full_discover(ctx)
    st = ctx.viewer.get("/api/state").json()
    svc = next(n for n in st["graph"]["nodes"] if n["kind"] == "mcp_service" and n["name"] == "fraud-intel")
    rep = next(n for n in st["graph"]["nodes"] if n["key"] == "ep:10.50.20.33:8000")
    d = ctx.viewer.get(f"/api/assets/{rep['id']}").json()
    tools = {t["name"]: t for t in d["mcp"]["tools"]}
    assert tools["freeze_account"]["privileged"] is True and tools["get_alert"]["privileged"] is False
    assert d["mcp"]["authenticated"] is False and any(x["id"] == svc["id"] for x in d["service_of"])
    risk = next(n for n in st["graph"]["nodes"] if n["kind"] == "mcp_service" and n["name"] == "risk-scoring")
    assert len(ctx.viewer.get(f"/api/assets/{risk['id']}").json()["replicas"]) == 2   # replicas stay individually identifiable


def test_relationship_dossier_carries_trace_evidence(ctx):
    full_discover(ctx)
    st = ctx.viewer.get("/api/state").json()
    e = next(x for x in st["graph"]["edges"] if x["kind"].startswith("calls_"))
    d = ctx.viewer.get(f"/api/relationships/{e['id']}").json()
    assert d["from"]["id"] == e["source"] and d["to"]["id"] == e["target"] and d["evidence_ids"]
    assert all(c["trust"]["level"] == "otel_observation" for c in d["claims"] if c["source"] == "ingest")
    assert ctx.viewer.get("/api/relationships/nope").status_code == 404


def test_scoped_evidence_contains_only_the_selected_service(ctx):
    full_discover(ctx)
    st = ctx.viewer.get("/api/state").json()
    rep = next(n for n in st["graph"]["nodes"] if n["key"] == "ep:10.50.20.33:8000")
    fp = next(e for e in ctx.viewer.get("/api/evidence").json() if e["method"] == "protocol-fingerprint")
    ev = ctx.viewer.get(f"/api/evidence/{fp['id']}?asset={rep['id']}").json()
    assert len(ev["raw"]) == 4                                                  # full document still available
    assert [x["ip"] for x in ev["scoped"]["content"]] == ["10.50.20.33"]       # ...but the scoped view is one endpoint
    assert ev["trust"]["level"] == "protocol_fingerprint"


def test_trust_levels_never_present_customer_statements_as_verified():
    from autopilot import trust
    assert trust.describe("describe", "llm:qwen")["verified"] is False
    assert trust.describe("describe", "deterministic-parser")["level"] == "customer_assertion"
    assert trust.level("enumerate", "dns-axfr") == "dns_metadata" and trust.LEVELS["dns_metadata"]["verified"] is False
    assert trust.level("enumerate", "protocol-fingerprint") == "protocol_fingerprint"
    assert trust.level("ingest", "otel") == "otel_observation" and trust.level("observe", "bigip") == "bigip_config"
    assert trust.rel_level("has_replica", "enumerate", "protocol-fingerprint") == "inferred"


def test_grouped_findings_link_to_assets_and_evidence(ctx):
    full_discover(ctx)
    st = ctx.viewer.get("/api/state").json()
    ids = {n["id"] for n in st["graph"]["nodes"]}
    for g in st["findings_grouped"]:
        assert all(a["id"] in ids for a in g["affected"])
        assert all(set(i["asset_ids"]) <= ids and i["evidence_ids"] for i in g["items"])


# ------------------------------------------------------------------ W1-06 misleading before/after comparisons
def test_empty_assessment_vs_discovered_is_not_comparable(ctx):
    empty = ctx.op.post("/api/assessment/new", json={"name": "exploratory"}).json()["id"]
    after = ctx.op.post("/api/assessment/new", json={"name": "discovered"}).json()["id"]
    full_discover(ctx)
    c = ctx.viewer.get(f"/api/compare?before={empty}&after={after}").json()
    assert c["counts"]["before"]["findings"] == 0 and c["counts"]["after"]["findings"] > 0     # the "0 → 19" case
    assert c["comparability"]["status"] == "invalid" and c["comparability"]["claims_allowed"] is False
    assert all("not evidence that security deteriorated" in f["interpretation"] for f in c["new_in_after"])
    html = ctx.viewer.get(f"/api/report/{after}/executive?before={empty}").text
    assert "No F5 benefit is claimed" in html


def test_two_discoveries_without_deployment_are_exploratory_only(ctx):
    a = ctx.op.post("/api/assessment/new", json={"name": "one"}).json()["id"]
    full_discover(ctx)
    b = ctx.op.post("/api/assessment/new", json={"name": "two"}).json()["id"]
    full_discover(ctx)
    c = ctx.viewer.get(f"/api/compare?before={a}&after={b}").json()["comparability"]
    assert c["status"] == "exploratory" and not c["claims_allowed"]
    assert any("no successful, linked F5 deployment" in r for r in c["reasons"])
    rev = ctx.viewer.get(f"/api/compare?before={b}&after={a}").json()["comparability"]
    assert rev["status"] == "invalid"                                         # reversed order is rejected


def test_verified_comparison_needs_linked_successful_deployment_and_changed_bigip_state(ctx):
    before = ctx.op.post("/api/assessment/new", json={"name": "baseline"}).json()["id"]
    full_discover(ctx)
    pk = {p["kind"]: p["id"] for p in ctx.op.post("/api/recommend").json()["packages"]}
    review(ctx, pk["delivery"])
    ctx.ap.post(f"/api/packages/{pk['delivery']}/decision", json={"decision": "approved", "comment": "t"})
    assert ctx.ap.post(f"/api/packages/{pk['delivery']}/deploy").json()["status"] == "succeeded"
    after = ctx.op.post("/api/assessment/new", json={"name": "after delivery"}).json()["id"]
    full_discover(ctx)
    c = ctx.viewer.get(f"/api/compare?before={before}&after={after}").json()["comparability"]
    assert c["after"]["virtual_servers"] and c["before"]["virtual_servers"] == 0
    assert c["status"] == "verified" and c["claims_allowed"] and c["linked_successful_deployments"]


def test_assessment_list_exposes_coverage_and_suggestions(ctx):
    ctx.op.post("/api/assessment/new", json={"name": "empty"})
    ctx.op.post("/api/assessment/new", json={"name": "full"})
    full_discover(ctx)
    rows = ctx.viewer.get("/api/assessments").json()
    by = {r["name"]: r for r in rows}
    assert by["empty"]["discovery"] == "none" and by["full"]["discovery"] == "complete" and by["full"]["current"]
    assert by["full"]["infra_state"].startswith("baseline") and {"id", "name", "created", "status"} <= set(by["full"])
    assert "pairs" in ctx.viewer.get("/api/assessments/suggestions").json()


# ------------------------------------------------------------------ W1-03 downloads, W1-09 asset caching
def test_report_downloads_have_one_correct_contract(ctx):
    full_discover(ctx)
    aid = ctx.viewer.get("/api/state").json()["assessment"]["id"]
    for url, ctype, name in ((f"/api/report/{aid}/executive?download=1", "text/html", f"autopilot-executive-summary-{aid}.html"),
                             (f"/api/report/{aid}/evidence", "application/json", f"autopilot-technical-evidence-{aid}.json")):
        r = ctx.viewer.get(url)
        assert r.status_code == 200 and r.headers["content-type"].startswith(ctype)
        assert f'filename="{name}"' in r.headers["content-disposition"] and r.headers["content-disposition"].startswith("attachment")
        assert int(r.headers["content-length"]) == len(r.content) and r.headers["cache-control"] == "no-store"
        assert r.headers["x-content-type-options"] == "nosniff"
    inline = ctx.viewer.get(f"/api/report/{aid}/executive")
    assert "content-disposition" not in inline.headers and inline.text.lstrip().lower().startswith("<!doctype html")
    assert ctx.anon.get(f"/api/report/{aid}/evidence").status_code == 401


def test_index_pins_assets_to_content_hash_and_requires_revalidation(ctx):
    r = ctx.anon.get("/")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-cache"
    refs = re.findall(r'/static/([\w.-]+\.(?:js|css))\?v=([0-9a-f]{12})"', r.text)
    assert {n for n, _ in refs} >= {"app.js", "ui-core.js", "app.css"}
    assert ctx.anon.get("/static/app.js").headers["cache-control"] == "no-cache"
