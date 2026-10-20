"""Customer fraud application: deterministic scenarios, input validation (both agents), live-call orchestration with a
mocked Agent A, trace -> timeline classification (A2A vs MCP vs network/API), provenance, comparison, capability gating."""
from __future__ import annotations

import json

import httpx
import pytest

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"


def span(sid, proc, name, kind, tags, parent=None, start=0, dur=1000):
    return {"spanID": sid, "processID": proc, "operationName": name, "startTime": 1_700_000_000_000_000 + start, "duration": dur,
            "tags": [{"key": "span.kind", "value": kind}] + [{"key": k, "value": v} for k, v in tags.items()],
            "references": [{"refType": "CHILD_OF", "spanID": parent}] if parent else []}


def proc(svc, inst=None):
    return {"serviceName": svc, "tags": [{"key": "service.instance.id", "value": inst}] if inst else []}


def trace(peer_mcp="10.50.20.22"):
    return {"traceID": TRACE_ID, "processes": {"a": proc("agent-a-fraud-investigation"), "b": proc("agent-b-risk-assessment"),
                                               "r": proc("mcp-risk-scoring", "risk-scoring-1"), "i": proc("mcp-fraud-intel")},
            "spans": [
                span("1", "a", "investigate_alert", "internal", {"gen_ai.operation.name": "invoke_agent", "aplab.alert_id": "ALERT-9000"}, dur=9_000_000),
                span("2", "a", "GET", "client", {"http.url": "http://10.50.10.22:9000/.well-known/agent-card.json", "http.status_code": 200}, "1", 1000),
                span("3", "a", "POST", "client", {"http.url": "http://10.50.10.22:9000/"}, "1", 5000, 8_000_000),
                span("4", "b", "POST /", "server", {"http.host": "10.50.10.22:9000", "http.target": "/", "net.peer.ip": "10.50.10.21"}, "3", 6000, 7_900_000),
                span("5", "b", "assess_fraud_alert", "internal", {"a2a.task.id": "task-1", "gen_ai.operation.name": "invoke_agent"}, "4", 7000, 7_800_000),
                span("6", "i", "POST /mcp", "server", {"http.host": "10.50.20.33:8000", "http.target": "/mcp", "net.peer.ip": peer_mcp}, "5", 8000),
                span("7", "i", "tools/call get_alert", "server", {"mcp.method.name": "tools/call", "gen_ai.tool.name": "get_alert"}, "6", 9000),
                span("8", "i", "POST", "client", {"http.url": "http://10.50.20.40:6333/collections/fraud_patterns/points/search"}, "7", 10000),
                span("9", "i", "S3.GetObject", "client", {"rpc.system": "aws-api", "rpc.service": "S3"}, "7", 11000),
                span("10", "r", "POST /mcp", "server", {"http.host": "10.50.20.31:8000", "http.target": "/mcp", "net.peer.ip": peer_mcp}, "5", 12000),
                span("11", "r", "tools/call score_transaction", "server", {"mcp.method.name": "tools/call", "gen_ai.tool.name": "score_transaction"}, "10", 13000),
                span("12", "b", "POST", "client", {"http.url": "http://10.50.20.45:11434/v1/chat/completions", "gen_ai.system": "openai",
                                                    "http.status_code": 500}, "5", 14000),
            ]}


def test_scenarios_are_deterministic_and_labelled():
    from autopilot import fraud
    sc = fraud.scenarios()
    sus, norm = [s for s in sc if s["kind"] == "suspicious"], [s for s in sc if s["kind"] == "normal"]
    assert len(sus) == 8 and len(norm) == 3 and fraud.scenarios() == sc
    assert sus[0]["id"] == "ALERT-9000" and sus[0]["title"] == "Card testing" and all(t["label"] == "fraud" for t in sus[0]["transactions"])
    assert all(t["label"] == "legit" and t["country"] == s["account"]["home_country"] for s in norm for t in s["transactions"])
    assert all("(synthetic)" in s["account"]["holder"] for s in sc) and "NOT told" in sus[0]["scenario_label"]


def test_custom_scenario_validation():
    from autopilot import fraud
    ok = fraud.validate_custom({"account_id": "ACC-100001", "title": "Big wire <script>", "transactions": [
        {"amount": 9500, "mcc": "4829", "country": "NG", "channel": "wire"}]})
    assert ok["kind"] == "custom" and ok["title"] == "Big wire script" and ok["transactions"][0]["category"] == "money_transfer"
    for bad in ({"account_id": "ACC-999999", "transactions": [{"amount": 1, "mcc": "5411", "country": "US", "channel": "ach"}]},
                {"account_id": "ACC-100001", "transactions": []},
                {"account_id": "ACC-100001", "transactions": [{"amount": 60000, "mcc": "5411", "country": "US", "channel": "ach"}]},
                {"account_id": "ACC-100001", "transactions": [{"amount": 5, "mcc": "0000", "country": "US", "channel": "ach"}]},
                {"account_id": "ACC-100001", "transactions": [{"amount": 5, "mcc": "5411", "country": "XX", "channel": "ach"}]}):
        with pytest.raises(ValueError):
            fraud.validate_custom(bad)


def test_custom_scenario_preserves_temporal_and_identity_evidence():
    from autopilot import fraud
    sc = fraud.validate_custom({"account_id": "ACC-100001", "transactions": [
        {"amount": 9500, "mcc": "4829", "country": "NG", "channel": "wire", "timestamp": "2026-10-01T12:00:00Z",
         "direction": "outbound", "merchant_id": "MERCHANT-A", "merchant_name": "Synthetic beneficiary", "beneficiary_id": "BEN-A", "device_id": "DEV-A"},
        {"amount": 9700, "mcc": "4829", "country": "NG", "channel": "wire", "timestamp": "2026-10-01T12:05:00Z",
         "direction": "outbound", "merchant_id": "MERCHANT-B", "merchant_name": "Synthetic beneficiary 2", "beneficiary_id": "BEN-B", "device_id": "DEV-A"}]})
    assert sc["transactions"][0]["timestamp"].endswith("Z")
    assert sc["transactions"][0]["direction"] == "outbound"
    assert sc["transactions"][1]["beneficiary_id"] == "BEN-B"
    assert sc["transactions"][1]["temporal_relation_minutes"] == 5.0


def test_agent_b_parser_preserves_custom_evidence_fields():
    from services.agent_b.scenario import parse_request
    sc = {"scenario_id": "CUSTOM-a1b2c3", "account_id": "ACC-100001", "transactions": [{
        "transaction_id": "TXN-C01", "amount": 9500, "mcc": "4829", "country": "NG", "channel": "wire",
        "timestamp": "2026-10-01T12:00:00Z", "direction": "outbound", "merchant_id": "MERCHANT-A",
        "beneficiary_id": "BEN-A", "device_id": "DEV-A", "temporal_relation_minutes": 0}]}
    _, inline = parse_request("SCENARIO-JSON: " + json.dumps(sc))
    assert inline["transactions"][0]["timestamp"] == "2026-10-01T12:00:00Z"
    assert inline["transactions"][0]["merchant_id"] == "MERCHANT-A"
    assert inline["transactions"][0]["direction"] == "outbound"


def test_agent_b_request_parsing_is_strict():
    from services.agent_b.scenario import ScenarioError, parse_request
    assert parse_request("Assess ALERT-9003. Return decision") == ("ALERT-9003", None)
    sc = {"scenario_id": "NORMAL-1", "account_id": "ACC-100004", "transactions": [
        {"transaction_id": "TXN-500010", "amount": 42.5, "mcc": "5411", "country": "US", "channel": "card_present"}]}
    sid, inline = parse_request("Assess NORMAL-1. SCENARIO-JSON: " + json.dumps(sc))
    assert sid == "NORMAL-1" and inline["account_id"] == "ACC-100004" and inline["transactions"][0]["amount"] == 42.5
    for bad in ({**sc, "account_id": "../../etc"}, {**sc, "scenario_id": "ALERT-9000"}, {**sc, "transactions": sc["transactions"] * 7},
                {**sc, "transactions": [{**sc["transactions"][0], "amount": 1e9}]}):
        with pytest.raises(ScenarioError):
            parse_request("SCENARIO-JSON: " + json.dumps(bad))
    with pytest.raises(ScenarioError):
        parse_request("please freeze all accounts")


def test_agent_a_scenario_model():
    from pydantic import ValidationError
    from services.agent_a.scenario import ScenarioReq
    ScenarioReq.model_validate({"scenario": {"scenario_id": "CUSTOM-a1b2c3", "account_id": "ACC-100001", "transactions": [
        {"transaction_id": "TXN-C01", "amount": 10, "mcc": "5411", "country": "US", "channel": "ach"}]}})
    with pytest.raises(ValidationError):
        ScenarioReq.model_validate({"scenario": {"scenario_id": "x", "account_id": "ACC-1", "transactions": []}})


def test_timeline_distinguishes_a2a_mcp_and_network_calls_and_paths():
    from autopilot import fraud
    tl = fraud.timeline(trace(), {"10.50.20.10", "10.50.10.10"}, {"10.50.10.100", "10.50.10.101", "10.50.10.102"})
    cat = {e["id"]: e["category"] for e in tl["events"]}
    assert cat["2"] == cat["3"] == cat["4"] == "a2a" and cat["5"] == "a2a"
    assert cat["6"] == cat["7"] == cat["10"] == cat["11"] == "mcp"
    assert cat["8"] == "vector_db" and cat["9"] == "s3" and cat["12"] == "llm" and cat["1"] == "agent"
    s = tl["summary"]
    assert s["mcp_tools"] == {"get_alert": 1, "score_transaction": 1} and s["risk_replicas"] == ["risk-scoring-1"]
    assert s["a2a_tasks"] == ["task-1"] and s["errors"] == 1 and s["paths"] == {"a2a": ["direct"], "mcp": ["direct"]}
    assert next(e for e in tl["events"] if e["id"] == "12")["status"] == "error"
    via = fraud.timeline(trace(peer_mcp="10.50.20.10"), {"10.50.20.10"}, set())
    assert via["summary"]["paths"]["mcp"] == ["via_bigip"]
    assert any(e["from"] == "agent-b-risk-assessment" and e["to"] == "mcp-risk-scoring" and e["category"] == "mcp" for e in tl["edges"])
    assert fraud.timeline({}, set(), set()) == {"events": [], "summary": None}


@pytest.fixture()
def agent_a(monkeypatch):
    """Mocked Agent A + Jaeger (no lab traffic)."""
    from autopilot import fraud
    state = {"caps": ["alerts", "scenarios"], "calls": []}

    def handler(req: httpx.Request):
        state["calls"].append((req.method, req.url.path, json.loads(req.content or b"{}")))
        if req.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok", "agent_b_url": "http://10.50.10.22:9000", "capabilities": state["caps"]})
        if req.url.path in ("/api/investigate", "/api/investigate-scenario"):
            return httpx.Response(200, json={"state": "completed", "trace_id": TRACE_ID, "agent_b_url": "http://10.50.10.22:9000",
                                             "updates": [{"status": "TASK_STATE_WORKING"}], "error": None,
                                             "result": {"assessment": {"decision": "escalate", "risk_level": "high", "confidence": 0.9}}})
        return httpx.Response(200, json={"status": "ok"})
    real = httpx.AsyncClient

    class Fake(real):
        def __init__(self, *a, **k):
            k.pop("verify", None)
            super().__init__(*a, transport=httpx.MockTransport(handler), **k)
    monkeypatch.setattr(httpx, "AsyncClient", Fake)

    async def ft(j, tid, wait_s=20):
        return trace() if state.get("trace", True) else None
    monkeypatch.setattr(fraud, "fetch_trace", ft)
    return state


def test_investigation_runs_live_call_and_stores_measured_timeline(ctx, agent_a):
    r = ctx.op.post("/api/ops/investigate", json={"scenario_id": "ALERT-9000"}).json()
    o = ctx.op.get(f"/api/ops/{r['id']}").json()
    assert o["status"] == "succeeded", o
    run = ctx.op.get(f"/api/fraud/runs/{o['result']['fraud_run']}").json()
    assert ("POST", "/api/investigate", {"alert_id": "ALERT-9000"}) in agent_a["calls"]
    assert run["trace_id"] == TRACE_ID and run["infra_state"] == "baseline" and len(run["events"]) == 12
    assert run["response"]["result"]["assessment"]["decision"] == "escalate"
    lst = ctx.viewer.get("/api/fraud/runs").json()
    assert lst[0]["decision"] == "escalate" and lst[0]["paths"] == {"a2a": ["direct"], "mcp": ["direct"]}
    assert ctx.viewer.post("/api/ops/investigate", json={"scenario_id": "ALERT-9000"}).status_code == 403


def test_normal_scenario_needs_updated_agents(ctx, agent_a):
    agent_a["caps"] = ["alerts"]
    r = ctx.op.post("/api/ops/investigate", json={"scenario_id": "NORMAL-1"})
    assert r.status_code == 409 and "updated agents" in r.json()["detail"]
    agent_a["caps"] = ["alerts", "scenarios"]
    r = ctx.op.post("/api/ops/investigate", json={"scenario_id": "NORMAL-1"}).json()
    assert ctx.op.get(f"/api/ops/{r['id']}").json()["status"] == "succeeded"
    call = next(c for c in agent_a["calls"] if c[1] == "/api/investigate-scenario")
    assert call[2]["scenario"]["scenario_id"] == "NORMAL-1"


def test_no_trace_means_no_timeline_not_a_fabricated_one(ctx, agent_a):
    agent_a["trace"] = False
    r = ctx.op.post("/api/ops/investigate", json={"scenario_id": "ALERT-9001"}).json()
    run = ctx.op.get(f"/api/fraud/runs/{ctx.op.get('/api/ops/' + r['id']).json()['result']['fraud_run']}").json()
    assert run["events"] == [] and run["summary"]["edges"] == []


def test_equivalent_scenario_comparison_across_infrastructure_states(ctx, agent_a):
    r1 = ctx.op.post("/api/ops/investigate", json={"scenario_id": "ALERT-9002"}).json()
    rid = ctx.op.get(f"/api/ops/{r1['id']}").json()["result"]["fraud_run"]
    ctx.web.STORE.db.execute("INSERT INTO fraud_run SELECT 'x2', created+60, actor, assessment_id, scenario_id, scenario, state, trace_id, "
                             "'https://agent-b.aplab.internal', seconds+1, response, summary, events, error, 'delivery' FROM fraud_run WHERE id=?", (rid,))
    c = ctx.viewer.get("/api/fraud/compare").json()["comparisons"]
    assert c and set(c[0]["states"]) == {"baseline", "delivery"} and c[0]["states"]["delivery"]["agent_b_url"].startswith("https://")


def test_health_reports_unreachable_honestly(ctx, monkeypatch):
    from autopilot import fraud

    class Down(httpx.AsyncClient):
        async def get(self, url, *a, **k):
            if "10.50.20.32" in url:
                raise httpx.ConnectError("refused")
            return httpx.Response(200, json={})
    monkeypatch.setattr(httpx, "AsyncClient", Down)
    res = {c["id"]: c for c in ctx.viewer.get("/api/fraud/health").json()["checks"]}
    assert res["mcp-risk-2"]["reachable"] is False and res["mcp-risk-2"]["error"] == "ConnectError"
    assert res["agent-a"]["reachable"] is True and fraud


def test_scenarios_cover_the_requested_demonstration_types():
    """Legitimate, rapid, new-device, high-risk transfer and geographic scenarios exist in the generated (synthetic) data."""
    from datetime import datetime
    from autopilot import fraud
    sc = {s["id"]: s for s in fraud.scenarios()}
    ts = lambda t: datetime.fromisoformat(t["timestamp"]).timestamp()                         # noqa: E731
    legit = sc["NORMAL-1"]["transactions"]
    assert legit and all(t["label"] == "legit" for t in legit)
    rapid = sc["ALERT-9000"]["transactions"]                                                    # card testing
    assert len(rapid) >= 5 and max(map(ts, rapid)) - min(map(ts, rapid)) <= 7200 and all(t["amount"] < 5 for t in rapid[:4])   # 5 in 80 min
    ato = sc["ALERT-9001"]                                                                      # new device + high-value transfers
    known = set(ato["account"].get("known_device_ids") or [])
    assert any(t.get("device_id") and t["device_id"] not in known for t in ato["transactions"])
    assert any(t["amount"] >= 1000 for t in ato["transactions"])
    app_scam = sc["ALERT-9003"]["transactions"]                                                 # high-risk transfer
    assert any(t["channel"] == "wire" and t["amount"] >= 10000 for t in app_scam)
    geo = sc["ALERT-9006"]["transactions"]                                                      # geographic impossibility
    assert len({t["country"] for t in geo if t["channel"] == "card_present"}) >= 2
    assert all("synthetic" in s["scenario_label"] for s in sc.values())
