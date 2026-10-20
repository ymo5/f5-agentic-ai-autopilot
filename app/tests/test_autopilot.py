"""Autopilot guarantees: empty start, evidence traceability, assertion handling, reset semantics, no hardcoded UI.

Discovery *inputs* are fixtures shaped exactly like real Jaeger / scan output; all correlation, reconciliation,
assessment and package code under test is the production code.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sqlite3
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CFG = ROOT.parent / "deploy" / "autopilot" / "autopilot.yaml"
SCHEMA = ROOT.parent / "packages" / "vendor" / "as3-schema-3.56.0-10.json"


from conftest import PW, SCAN, TRACE, proc, span  # noqa: E402


def test_new_assessment_starts_empty(ctx):
    client = ctx.op
    s = client.get("/api/state").json()
    assert s["counters"]["assets"] == 0 and s["counters"]["relationships"] == 0
    assert s["counters"]["findings"] == 0 and s["counters"]["evidence"] == 0
    assert s["graph"] == {"nodes": [], "edges": []} and s["findings"] == [] and s["gaps"] == []
    assert client.get("/api/packages").json() == []


def test_progressive_discovery_and_traceable_findings(ctx):
    client, web = ctx.op, ctx.web
    r1 = client.post("/api/discover/enumerate").json()
    after_enum = client.get("/api/state").json()["counters"]["assets"]
    assert r1["fingerprinted"] == 4 and after_enum > 0
    client.post("/api/discover/ingest")
    s = client.get("/api/state").json()
    assert s["counters"]["assets"] >= after_enum and s["counters"]["relationships"] > 0
    findings = s["findings"]
    assert findings, "expected findings from evidence"
    db = sqlite3.connect(os.environ["AUTOPILOT_DB"])
    aid = s["assessment"]["id"]
    for f in findings:
        assert f["evidence_ids"], f"finding {f['rule_id']} has no evidence"
        for eid in f["evidence_ids"]:
            row = db.execute("SELECT assessment_id FROM evidence WHERE id=?", (eid,)).fetchone()
            assert row and row[0] == aid, f"finding {f['rule_id']} cites evidence outside this assessment"
        for a in f["asset_ids"]:
            cited = {c[0] for c in db.execute("SELECT evidence_id FROM asset_claim WHERE asset_id=?", (a,))}
            assert cited, f"asset {a} in finding {f['rule_id']} has no claims"
    rules = {f["rule_id"] for f in findings}
    assert {"D-001", "D-002", "D-003", "S-002", "S-003", "S-005"} <= rules
    for a in s["graph"]["nodes"]:
        assert a["sources"], "every asset must name its discovery source"


def test_description_is_asserted_not_verified(ctx):
    client = ctx.op
    r = client.post("/api/discover/describe", json={"text": "The fraud team runs an MCP risk scoring service behind the BIG-IP. "
                                                          "It is load balanced and authenticated."}).json()
    assert r["generated_by"].startswith("deterministic") and "NOT an LLM" in r["generated_by"]
    s = client.get("/api/state").json()
    assert s["graph"]["nodes"] and all(n["status"] == "asserted" for n in s["graph"]["nodes"])
    assert all(n["confidence"] <= 0.3 for n in s["graph"]["nodes"])
    assert s["findings"] == [], "assertions alone must not produce findings"


def test_assertion_contradicted_by_telemetry(ctx):
    client, web = ctx.op, ctx.web
    st = web.STORE
    eid = st.add_evidence("describe", "test", "SE says agent-b to risk goes via BIG-IP", {})
    src = st.claim_asset(eid, "describe", "described:agent-b", "a2a_agent", "agent-b")
    dst = st.claim_asset(eid, "describe", "ep:10.50.20.31:8000", "mcp_server", "risk")
    st.claim_rel(eid, "describe", src, dst, "calls_mcp", "via_bigip")
    e2 = st.add_evidence("ingest", "test", "observed direct", {})
    st.claim_rel(e2, "ingest", src, dst, "calls_mcp", "direct")
    rel = next(r for r in st.rels() if r["kind"] == "calls_mcp")
    assert rel["status"] == "conflicted" and rel["assertion_contradicted"]
    web.ENGINE.assess()
    assert any(f["rule_id"] == "S-007" for f in client.get("/api/state").json()["findings"])


def test_reset_clears_workspace_keeps_audit(ctx):
    client, web = ctx.op, ctx.web
    client.post("/api/discover/enumerate")
    db = sqlite3.connect(os.environ["AUTOPILOT_DB"])
    audit_before = db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    client.post("/api/assessment/reset")
    s = client.get("/api/state").json()
    assert s["counters"]["assets"] == 0 and s["counters"]["evidence"] == 0 and s["findings"] == []
    assert db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] > audit_before
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("DELETE FROM audit")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE audit SET actor='x'")


def test_ui_has_no_hardcoded_topology():
    static = ROOT / "autopilot" / "static"
    pat = re.compile(r"\b(10\.50\.\d+\.\d+|192\.168\.\d+\.\d+)\b|risk-scoring|fraud-intel|agent-b|agent-a|ALERT-\d|qdrant|seaweed", re.I)
    for f in ("index.html", "app.js", "app.css"):
        hits = pat.findall((static / f).read_text())
        assert not hits, f"{f} contains hardcoded topology: {hits[:5]}"
    js = (static / "app.js").read_text()
    assert "cy.add" in js and "/api/state" in js  # graph only populated from API data


def test_packages_validate_against_as3_schema(ctx):
    client = ctx.op
    client.post("/api/discover/enumerate")
    client.post("/api/discover/ingest")
    pk = client.post("/api/recommend").json()["packages"]
    kinds = {p["kind"]: p for p in pk}
    assert {"delivery", "security"} <= set(kinds), kinds.keys()
    for k in ("delivery", "security"):
        assert kinds[k]["validation"]["valid"] is True, kinds[k]["validation"]
    listed = client.get("/api/packages").json()
    assert all(p["recommendation"]["finding_ids"] for p in listed)


def test_ingest_excludes_discovery_system_traffic():
    from autopilot.sources import ingest as i_src
    t = {"traceID": "t2", "processes": {"pa": proc("autopilot"), "pr": proc("mcp-risk-scoring", "risk-scoring-1")}, "spans": [
        span("x1", "pa", "GET", "client", {"http.url": "http://10.50.20.31:8000/healthz"}),
        span("x2", "pr", "GET /healthz", "server", {"http.host": "10.50.20.31:8000", "net.peer.ip": "10.50.20.5", "http.target": "/healthz"}, "x1"),
        span("y2", "pr", "GET /.well-known/agent-card.json", "server", {"http.host": "10.50.20.31:8000", "net.peer.ip": "10.50.20.5",
             "http.target": "/.well-known/agent-card.json", "http.status_code": 404})]}
    corr = i_src.correlate([TRACE, t], set(), set(), {"autopilot"}, {"10.50.20.5"})
    assert not any("autopilot" in e["caller"] or "10.50.20.5" in e["peer_addresses"] for e in corr["edges"])
    assert "a2a_server" not in corr["services"]["mcp-risk-scoring"]["roles"], "404 card probe must not make an MCP server an A2A agent"
    mcp = [e for e in corr["edges"] if e["protocol"] == "mcp"]
    assert mcp and mcp[0]["tools"] == {"score_transaction": 1} and mcp[0]["mcp_protocol_versions"] == ["2025-11-25"]


def test_control_claim_contradiction_is_traceable(ctx):
    client, web = ctx.op, ctx.web
    client.post("/api/discover/enumerate")
    client.post("/api/discover/ingest")
    st = web.STORE
    eid = st.add_evidence("describe", "llm:test:model", "SE description", {"extraction": {"components": [], "relationships": [],
          "control_claims": [{"subject": "MCP servers", "claim": "authenticated", "text": "MCP servers require authentication"}]}})
    web.ENGINE.assess()
    f = [x for x in client.get("/api/state").json()["findings"] if x["rule_id"] == "S-007"]
    assert f and eid in f[0]["evidence_ids"] and len(f[0]["evidence_ids"]) > 1  # assertion + contradicting technical evidence
