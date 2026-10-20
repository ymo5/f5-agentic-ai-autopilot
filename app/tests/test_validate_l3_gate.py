"""Regression tests for the two L3 'after-delivery' gate failures of 2026-10-15 (deployment bcdfd45982644ff9, doc 27).

1. mcp.discovery.intel — the validator crashed parsing fraud-intel's list-typed tool result (AttributeError inside the MCP
   client's TaskGroup, reported as an opaque ExceptionGroup). The server had answered (3 x 200 in its log).
2. delivery.load_distribution — 12 'stateless' calls reused one keep-alive connection; a BIG-IP virtual server without
   OneConnect picks the member per client connection, so all 12 went to one replica.

Integration tests use the REAL MCP servers on 127.0.0.1 behind a per-connection load balancer (tests/mcp_lb_harness.py).
(The historical pre-fix validator copy used to reproduce both failures is not part of the public repository.)
"""
from __future__ import annotations

import asyncio
import collections
import pathlib

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from autopilot import validate
from mcp_lb_harness import lab

class _Res:
    def __init__(self, sc):
        self.structured_content, self.content = sc, []


# ---------------------------------------------------------------- unit
def test_replica_ignores_list_typed_results_instead_of_raising():
    assert validate._replica(_Res({"result": [{"alert_id": "ALERT-9000"}]})) is None
    assert validate._replica(_Res({"result": {"replica": "risk-scoring-2"}})) == "risk-scoring-2"
    assert validate._replica(_Res({"replica": "risk-scoring-1", "model_version": "x"})) == "risk-scoring-1"


def test_err_reports_the_leaf_cause_of_exception_groups():
    inner = AttributeError("'list' object has no attribute 'get'")
    e = ExceptionGroup("unhandled errors in a TaskGroup", [ExceptionGroup("unhandled errors in a TaskGroup", [inner])])
    msg = validate.err(e)
    assert msg == "AttributeError: 'list' object has no attribute 'get'"
    assert validate.err(ValueError("x")) == "ValueError: x"
    assert len(validate.err(RuntimeError("y" * 1000))) == 300


def test_verdicts_are_not_weakened():
    ok = validate.distribution_ok
    assert ok(["risk-scoring-1", "risk-scoring-2"] * 6, True)
    assert not ok(["risk-scoring-2"] * 12, True)                       # one replica is still a failure with LB expected
    assert not ok(["risk-scoring-1", None] * 6, True)                  # every request must name its replica
    assert not ok([], True)
    assert ok(["risk-scoring-1"] * 12, False) and not ok(["risk-scoring-1", "risk-scoring-2"], False)   # baseline
    d = validate.discovery_ok
    assert d({"tools": ["a"], "missing_tools": [], "probe_ok": True, "error": None})
    assert not d({"tools": ["a"], "missing_tools": ["get_alert"], "probe_ok": True, "error": None})
    assert not d({"tools": ["a"], "missing_tools": [], "probe_ok": False, "error": None})
    assert not d({"error": "ConnectError: refused"}) and not d(None)


def test_discovery_expectations_match_the_tools_agent_b_calls():
    agent_b = (pathlib.Path(__file__).resolve().parents[1] / "services" / "agent_b" / "agent.py").read_text()
    for tool in validate.DISCOVERY["intel"][1] - {"list_open_alerts"}:
        assert f'intel.call_tool("{tool}"' in agent_b
    assert 'risk.call_tool("score_transaction"' in agent_b


# ---------------------------------------------------------------- integration (real MCP servers, loopback)
@pytest.fixture(scope="module")
def L():
    with lab(persist=True) as env:
        yield env


def test_intel_discovery_via_front_door_lists_tools_and_probes(L):
    p = asyncio.run(validate._discover(L["intel"], *validate.DISCOVERY["intel"]))
    assert validate.discovery_ok(p), p
    assert p["server_name"] == "fraud-intel" and p["probe"] == "list_open_alerts"
    assert {"freeze_account", "export_customer_data"} <= set(p["tools"])   # discovery reports everything advertised
    assert asyncio.run(validate._tool(L["intel"], "auto", 1, tool="list_open_alerts")) == [None]


def test_risk_discovery_via_load_balanced_vip(L):
    p = asyncio.run(validate._discover(L["risk_vip"], *validate.DISCOVERY["risk"]))
    assert validate.discovery_ok(p) and p["server_name"] == "risk-scoring", p


def test_discovery_fails_when_an_expected_tool_is_missing(L):
    probe, expected = validate.DISCOVERY["intel"]
    p = asyncio.run(validate._discover(L["intel"], probe, expected | {"not_a_tool"}))
    assert not validate.discovery_ok(p) and p["missing_tools"] == ["not_a_tool"]


def test_discovery_failure_reports_the_real_cause(L):
    dead = L["intel"].rsplit(":", 1)[0] + ":9/mcp"
    with pytest.raises(BaseException) as ei:
        asyncio.run(validate._discover(dead, *validate.DISCOVERY["intel"]))
    assert "TaskGroup" not in validate.err(ei.value)


def test_stateless_requests_use_independent_connections_and_spread(L):
    n0 = len(L["lb"].connections)
    reps = asyncio.run(validate._tool(L["risk_vip"], "auto", 12))
    conns = L["lb"].connections[n0:]
    assert len(conns) == 12 and len({port for port, _ in conns}) == 12
    assert validate.distribution_ok(reps, True)
    assert collections.Counter(reps) == {"risk-scoring-1": 6, "risk-scoring-2": 6}


def test_connection_reuse_pins_one_member_which_is_why_the_test_must_not_reuse(L):
    """The measurement trap itself: 12 calls over ONE keep-alive client reach one member through a per-connection LB."""
    async def reuse():
        out = []
        async with httpx2.AsyncClient(timeout=30) as http:
            for _ in range(12):
                async with Client(streamable_http_client(L["risk_vip"], http_client=http), mode="auto") as c:
                    out.append(validate._replica(await c.call_tool("score_transaction", validate.SCORE_ARGS)))
        return out
    n0 = len(L["lb"].connections)
    reps = asyncio.run(reuse())
    assert len(L["lb"].connections) - n0 == 1 and not validate.distribution_ok(reps, True)


def test_legacy_session_persists_by_session_id_across_connections(L):
    n0 = len(L["lb"].connections)
    sess = asyncio.run(validate._tool(L["risk_vip"], "legacy", 6))
    assert None not in sess and len(set(sess)) == 1
    assert len(L["lb"].connections) - n0 >= 2       # the session spanned several connections: persistence, not reuse


def test_session_persistence_test_detects_missing_persistence():
    """Without Mcp-Session-Id persistence the session's requests reach the other replica, which does not know the session:
    the call fails ('Session not found'), which run() records as delivery.session_persistence = fail."""
    with lab(persist=False) as env:
        with pytest.raises(BaseException) as ei:
            asyncio.run(validate._tool(env["risk_vip"], "legacy", 6))
    assert "Session not found" in validate.err(ei.value)


def test_waves_spread_even_when_another_client_holds_a_connection_to_one_member(L):
    """Least-connections + an idle connection held by another client (e.g. Agent B's keep-alive pool): sequential
    independent connections all go to the other member — correct LB behaviour, false test failure. Overlapping waves
    (validate.LB_WAVE) still reach both members."""
    import socket
    lb = L["lb"]
    held = socket.create_connection(("127.0.0.1", lb.port))
    held.sendall(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n")      # incomplete request: the connection stays open
    try:
        for _ in range(50):
            if sum(lb.active.values()) >= 1:
                break
            asyncio.run(asyncio.sleep(0.02))
        busy = lb.connections[-1][1]
        assert lb.active[busy] == 1
        seq = asyncio.run(validate._tool(L["risk_vip"], "auto", 6))
        assert len(set(seq)) == 1                                          # all on the idle member
        waves = asyncio.run(validate._tool(L["risk_vip"], "auto", 12, concurrency=validate.LB_WAVE))
        assert validate.distribution_ok(waves, True), collections.Counter(waves)
    finally:
        held.close()


# ---------------------------------------------------------------- run() wiring (network layers stubbed)
class _Resp:
    def __init__(self, body, code=200):
        self._b, self.status_code = body, code

    def json(self):
        return self._b

    def raise_for_status(self):
        pass


class _FakeHttp:
    """Stands in for validate.httpx.AsyncClient: agents configured for the delivery front doors, everything healthy."""
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, *a, **k):
        if url.endswith(":8080/healthz"):
            return _Resp({"agent_b_url": "https://agent-b.aplab.internal"})
        if "agent-card" in url:
            return _Resp({"skills": [{"id": "assess"}], "supportedInterfaces": [{"url": "https://agent-b.aplab.internal/"}]})
        if url.endswith("/healthz") and ":9000" in url:
            return _Resp({"mcp_risk_url": "https://mcp-risk.aplab.internal/mcp", "mcp_intel_url": "https://mcp-intel.aplab.internal/mcp"})
        if "/api/traces/" in url:
            return _Resp({"data": [{"processes": {str(i): {"serviceName": s} for i, s in enumerate(
                ["agent-a-fraud-investigation", "agent-b-risk-assessment", "mcp-risk-scoring", "mcp-fraud-intel"])}}]})
        return _Resp({}, 200)                                  # direct backend probes: open in delivery

    async def post(self, url, *a, **k):
        return _Resp({"state": "completed", "result": {"assessment": {"decision": "escalate"}, "replicas_used": ["risk-scoring-1"]},
                      "updates": ["TASK_STATE_WORKING"] * 3, "trace_id": "t1"})


def _run_gate(monkeypatch, discover, tool, profile="after-delivery", raw=None, raw_legacy=None):
    import yaml
    from conftest import CFG
    monkeypatch.setattr(validate.httpx, "AsyncClient", _FakeHttp)
    monkeypatch.setattr(validate.socket, "gethostbyname", lambda h: "10.50.10.100")
    monkeypatch.setattr(validate, "_discover", discover)
    monkeypatch.setattr(validate, "_tool", tool)
    real_sleep = asyncio.sleep

    async def no_wait(s, *a, **k):
        await real_sleep(0)
    monkeypatch.setattr(validate.asyncio, "sleep", no_wait)
    if raw:
        monkeypatch.setattr(validate, "_raw_mcp", raw)
    if raw_legacy:
        monkeypatch.setattr(validate, "_raw_legacy", raw_legacy)
    res = asyncio.run(validate.run(yaml.safe_load(open(CFG)), profile))
    return {r["test"]: r for r in res}


async def _good_discover(url, probe, expected, cert=None):
    return {"server_name": "x", "protocol_version": "2026-07-28", "tools": sorted(expected), "missing_tools": [], "probe": probe,
            "probe_ok": True, "error": None}


def _tool_stub(replicas_for_12, calls):
    async def tool(url, mode, n, cert=None, tool="score_transaction", args=None, concurrency=1):
        calls.append((mode, n, concurrency))
        if mode == "legacy":
            return ["risk-scoring-2"] * n
        if n == 12:
            return list(replicas_for_12)
        return ["risk-scoring-1"] * n
    return tool


def test_gate_passes_discovery_and_distribution_with_independent_waves(monkeypatch):
    calls = []
    by = _run_gate(monkeypatch, _good_discover, _tool_stub(["risk-scoring-1", "risk-scoring-2"] * 6, calls))
    for t in ("mcp.discovery.risk", "mcp.discovery.intel", "mcp.tool_execution", "delivery.load_distribution", "delivery.session_persistence"):
        assert by[t]["result"] == "pass", by[t]
    assert ("auto", 12, validate.LB_WAVE) in calls
    ld = by["delivery.load_distribution"]["observed"]
    assert ld["independent_connections"] == 12 and "one TCP connection per request" in ld["method"]
    assert by["mcp.discovery.intel"]["observed"]["result"]["probe"] == "list_open_alerts"
    assert by["delivery.failover"]["result"] == "skipped"          # no deployer actions in this unit test


def test_gate_still_fails_when_one_replica_serves_everything(monkeypatch):
    by = _run_gate(monkeypatch, _good_discover, _tool_stub(["risk-scoring-2"] * 12, []))
    assert by["delivery.load_distribution"]["result"] == "fail"
    assert by["delivery.load_distribution"]["observed"]["replicas"] == {"risk-scoring-2": 12}


def test_gate_discovery_failure_names_the_real_cause(monkeypatch):
    async def broken(url, probe, expected, cert=None):
        if "intel" in url:
            raise ExceptionGroup("unhandled errors in a TaskGroup", [ConnectionResetError("peer reset")])
        return await _good_discover(url, probe, expected)
    by = _run_gate(monkeypatch, broken, _tool_stub(["risk-scoring-1", "risk-scoring-2"] * 6, []))
    r = by["mcp.discovery.intel"]
    assert r["result"] == "fail" and r["observed"]["result"]["error"] == "ConnectionResetError: peer reset"
    assert by["mcp.discovery.risk"]["result"] == "pass"


def test_gate_discovery_fails_on_missing_agent_tool(monkeypatch):
    async def partial(url, probe, expected, cert=None):
        d = await _good_discover(url, probe, expected)
        if "intel" in url:
            d["tools"] = [t for t in d["tools"] if t != "get_case_document"]
            d["missing_tools"] = ["get_case_document"]
        return d
    by = _run_gate(monkeypatch, partial, _tool_stub(["risk-scoring-1", "risk-scoring-2"] * 6, []))
    assert by["mcp.discovery.intel"]["result"] == "fail"


# ---------------------------------------------------------------- B1 (doc 34): decoy-header gate test
async def _raw_ok(url, tool, cert=None):
    if cert is None:
        return -1                                    # no client certificate -> TLS reject
    if tool == "freeze_account" or cert == validate.UNAUTHORIZED:
        return 403
    return 200 if tool == "model_info" else 429


def test_security_gate_reports_decoy_header_denied_only_on_policy_403(monkeypatch):
    seen = []

    async def denied(url, tool, headers, cert=None):
        seen.append((url, tool, headers, cert))
        return 403

    async def bypassed(url, tool, headers, cert=None):
        return 400 if "Mcp-Name" not in headers else 403    # the forged-method request reached the server

    by = _run_gate(monkeypatch, _good_discover, _tool_stub(["risk-scoring-1", "risk-scoring-2"] * 6, []), "after-security", _raw_ok, denied)
    assert by["security.decoy_header_denied"]["result"] == "pass"
    assert {s[1] for s in seen} == {"freeze_account"} and all(s[3] == validate.VALIDATOR for s in seen) and "intel" in seen[0][0]
    assert {tuple(sorted(s[2].items())) for s in seen} == {(("Mcp-Method", "tools/list"),), (("Mcp-Method", "tools/call"), ("Mcp-Name", "model_info"))}
    by = _run_gate(monkeypatch, _good_discover, _tool_stub(["risk-scoring-1", "risk-scoring-2"] * 6, []), "after-security", _raw_ok, bypassed)
    assert by["security.decoy_header_denied"]["result"] == "fail"
    assert by["security.decoy_header_denied"]["observed"]["http"]["forged Mcp-Method tools/list"] == 400
