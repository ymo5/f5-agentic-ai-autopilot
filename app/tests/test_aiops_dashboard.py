"""AI Operations dashboard v2 (read-only) — offline tests against the stored ALERT-9001 timeline (sanitised fraud_run.events),
a stub deployer (BIG-IP statistics), a stub Jaeger and temp files. No lab system is contacted."""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import shutil
import stat
import subprocess
import time

import httpx
import pytest

FIX = pathlib.Path(__file__).parent / "fixtures" / "aiops"
STATIC = pathlib.Path(__file__).resolve().parents[1] / "autopilot" / "static"
TRACE_ID = "1f297622bc60f8c26e0a8257cb1472e7"
AGENT_ID = "b91e4a84-ed5a-4333-b017-5a85f28c11fc"


def fx(name):
    return json.loads((FIX / name).read_text())


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture()
def env():
    return {}


DATA_STATUS = {"members": [{"service": "s3", "member": "10.50.20.41", "port": 8333, "availability": "available", "enabled": "enabled"},
                           {"service": "llm", "member": "10.50.20.45", "port": 11434, "availability": "available", "enabled": "enabled"}],
               "virtual_servers": {"s3": {"http.numberReqs": 5, "clientside.totConns": 5, "clientside.curConns": 0, "secret_field": "x"},
                                   "rag": {"http.numberReqs": 19, "clientside.totConns": 18}, "llm": {"http.numberReqs": 11}},
               "s3_statistics": {"s3_get_object": 3, "s3_unsigned": 1, "s3_resp_4xx": 2, "s3_requests": 5, "not-a-counter": 9},
               "source": "BIG-IP iControl REST GET (observer)"}


def jaeger_trace():
    """A small post-Step-1b investigation trace in Jaeger's JSON shape (data calls through the 10.50.10.103-105 VIPs)."""
    def sp(sid, proc, name, kind, tags, start, dur, parent=None):
        t = [{"key": "span.kind", "value": kind}] + [{"key": k, "value": v} for k, v in tags.items()]
        return {"spanID": sid, "processID": proc, "operationName": name, "startTime": start, "duration": dur, "tags": t,
                "references": [{"refType": "CHILD_OF", "spanID": parent}] if parent else []}
    P = lambda s: {"serviceName": s, "tags": []}
    t0 = 1_800_000_000_000_000
    return {"traceID": TRACE_ID, "processes": {"a": P("agent-a-fraud-investigation"), "b": P("agent-b-risk-assessment"), "i": P("mcp-fraud-intel")},
            "spans": [sp("1", "a", "investigate_alert", "internal", {"gen_ai.operation.name": "invoke_agent"}, t0, 75_000_000),
                      sp("2", "a", "POST", "client", {"http.url": "https://agent-b.aplab.internal/"}, t0 + 100, 74_900_000, "1"),
                      sp("2s", "b", "POST /", "server", {"http.target": "/", "net.peer.ip": "10.50.20.10", "a2a.task.id": "t1"}, t0 + 2000, 74_800_000, "2"),
                      sp("3", "i", "tools/call search_fraud_patterns", "server", {"mcp.method.name": "tools/call", "http.target": "/mcp",
                                                                                 "net.peer.ip": "10.50.20.10"}, t0 + 130_000, 550_000, "2"),
                      sp("4", "i", "POST", "client", {"http.url": "http://10.50.10.105:11434/api/embed"}, t0 + 380_000, 160_000, "3"),
                      sp("5", "i", "POST", "client", {"http.url": "http://10.50.10.104:6333/collections/fraud_patterns/points/query"}, t0 + 570_000, 50_000, "3"),
                      sp("6", "i", "S3.GetObject", "client", {"rpc.system": "aws-api", "server.address": "10.50.10.103"}, t0 + 650_000, 10_000, "3"),
                      sp("7", "b", "chat qwen2.5:3b", "client", {"http.url": "http://10.50.10.105:11434/v1/chat/completions", "gen_ai.system": "openai",
                                                                  "gen_ai.usage.input_tokens": 1500, "gen_ai.usage.output_tokens": 160,
                                                                  "gen_ai.prompt": "SECRET PROMPT TEXT"}, t0 + 910_000, 74_530_000, "2")]}


# design.data_delivery of the live autopilot.yaml (41de2f68); the repository test config used by conftest predates it
LIVE_DATA_DELIVERY = {"s3": {"vip": "10.50.10.103", "port": 8333, "members": ["10.50.20.41:8333"], "host": "s3.aplab.internal"},
                      "rag": {"vip": "10.50.10.104", "port": 6333, "members": ["10.50.20.40:6333"], "host": "qdrant.aplab.internal"},
                      "llm": {"vip": "10.50.10.105", "port": 11434, "members": ["10.50.20.45:11434"], "host": "llm.aplab.internal"}}
DATA_VIPS = frozenset({"10.50.10.103", "10.50.10.104", "10.50.10.105", "s3.aplab.internal", "qdrant.aplab.internal", "llm.aplab.internal"})
DATA_BACKENDS = frozenset({"10.50.20.41", "10.50.20.40", "10.50.20.45"})


def test_data_vips_come_from_the_design(ctx):
    a, _ = make(ctx, None, {})
    assert a.data_vips == DATA_VIPS and a.data_backends == DATA_BACKENDS


def make(ctx, fake=None, env=None, http_get=None, tg_dir=None, deployer=None, clock=None, trace_fetch=None, summary_dir=""):
    from autopilot import aiops
    calls = []

    async def dep(req):
        calls.append(req)
        if deployer:
            return await deployer(req)
        return DATA_STATUS if req["action"] == "data_status" else {"members": [{"member": "/AP_AI/10.50.20.31", "port": 8000,
                                                                                  "availability": "available", "enabled": "enabled"}]}
    clk = clock or time.time
    cfg = {**ctx.web.CFG, "design": {**ctx.web.CFG["design"], "data_delivery": LIVE_DATA_DELIVERY}}   # test config predates B4
    a = aiops.AIOps(cfg, ctx.web.STORE, dep, http_get=http_get, trafficgen_dir=tg_dir, clock=clk,
                    trace_fetch=trace_fetch, summary_dir=summary_dir)
    ctx.web.AIOPS = a
    return a, calls


# ------------------------------------------------------------------ API contract, roles, ranges, fixed queries
ROUTES = ("/api/aiops/overview", "/api/aiops/delivery", "/api/aiops/security", "/api/aiops/investigations", "/api/aiops/trafficgen")


def test_routes_require_sign_in_and_allow_viewer(ctx, env):
    make(ctx, None, env)
    for p in ROUTES:
        assert ctx.anon.get(p).status_code == 401, p
        assert ctx.viewer.get(p).status_code == 200, p


def test_range_is_allow_listed(ctx, env):
    make(ctx, None, env)
    for p in ("/api/aiops/delivery", "/api/aiops/overview", "/api/aiops/security"):
        for bad in ("7d", "1h;drop", "", "3600"):
            assert ctx.viewer.get(f"{p}?range={bad}").status_code == 400
    for good in ("15m", "1h", "6h", "24h"):
        assert ctx.viewer.get(f"/api/aiops/security?range={good}").status_code == 200


def test_browser_cannot_supply_queries_or_destinations(ctx, env):
    _, calls = make(ctx, None, env)
    assert ctx.viewer.get("/api/aiops/overview?range=1h&query=up&url=http://evil.example/&instance=10.0.0.1&address=1.2.3.4").status_code == 200
    assert calls and all(set(c) == {"action"} and c["action"] in ("data_status", "pool_status") for c in calls)


def test_path_route_validates_source_and_id(ctx):
    make(ctx, None, {})
    for bad in ("/api/aiops/investigations/other/6d6811e929304bb2/path", "/api/aiops/investigations/autopilot/xyz/path",
                "/api/aiops/investigations/agent_a/../../etc/path", "/api/aiops/investigations/agent_a/not-a-uuid/path"):
        assert ctx.viewer.get(bad).status_code in (400, 404), bad
    assert ctx.anon.get(f"/api/aiops/investigations/agent_a/{AGENT_ID}/path").status_code == 401


# ------------------------------------------------------------------ value kinds (issue 2)
def test_value_kinds_and_range_independence_of_lifetime(ctx, env):
    make(ctx, None, env)
    d15 = ctx.viewer.get("/api/aiops/delivery?range=15m").json()
    d24 = ctx.viewer.get("/api/aiops/delivery?range=24h").json()
    assert set(d15) == {"range", "bigip"}
    bg = d15["bigip"]
    assert set(bg) >= {"lifetime", "delta"} and bg["lifetime"]["s3_statistics"] == {"s3_get_object": 3, "s3_unsigned": 1, "s3_resp_4xx": 2, "s3_requests": 5}
    assert bg["lifetime"] == d24["bigip"]["lifetime"]                        # the range selector never changes lifetime counters
    assert bg["lifetime"]["data_vips"]["llm"]["http.numberReqs"] == 11
    assert "secret_field" not in json.dumps(bg)


def test_delta_between_deployer_reads_with_reset_detection(ctx, env):
    clk = Clock()
    reads = [dict(DATA_STATUS), {**DATA_STATUS, "s3_statistics": {"s3_get_object": 5, "s3_unsigned": 1, "s3_resp_4xx": 2, "s3_requests": 1},
                                  "virtual_servers": {"s3": {"http.numberReqs": 7}, "rag": {"http.numberReqs": 19}, "llm": {"http.numberReqs": 12}}}]

    async def dep(req):
        return reads[0] if req["action"] == "data_status" and len(reads) == 2 else reads[-1] if req["action"] == "data_status" else {"members": []}
    a, _ = make(ctx, None, {}, deployer=dep, clock=clk)
    d1 = ctx.viewer.get("/api/aiops/delivery").json()["bigip"]
    assert d1["delta"] is None                                                # one read: no delta yet
    reads.pop(0); clk.t += 45
    d2 = ctx.viewer.get("/api/aiops/delivery").json()["bigip"]
    assert d2["delta"]["seconds"] == 45 and d2["delta"]["s3"]["s3_get_object"] == 2
    assert d2["delta"]["s3"]["s3_requests"] is None and "s3_requests" in d2["delta"]["resets"]
    assert d2["delta"]["data_vips"]["s3"]["http.numberReqs"] == 2 and d2["delta"]["data_vips"]["llm"]["http.numberReqs"] == 1


# ------------------------------------------------------------------ deployment gates vs independent runs (issue 1)
def _seed_deployments(db):
    def dep(did, pkg, kind, title, status, started, gate, det):
        db.execute("INSERT INTO package (id, assessment_id, kind, title, target, body, validation, created) VALUES (?,?,?,?,?,?,?,?)",
                   (pkg, "a", kind, title, "{}", "{}", "{}", started))
        steps = [{"step": "preflight", "status": "ok", "detail": []}, {"step": f"gate.validate[{gate}]", "status": "ok" if isinstance(det, dict) else "failed",
                                                                         "started": started + 100, "detail": det}]
        db.execute("INSERT INTO deployment (id, assessment_id, package_id, approval_id, package_hash, status, mode, requested_by, started, finished, steps, previous_state, error) "
                   "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (did, "a", pkg, "ap", "h", status, "live", "approver", started, started + 120, json.dumps(steps), "{}", None))
    passed = lambda n: {"passed": True, "results": [{"test": f"t{i}", "result": "pass", "observed": {}, "expected": "x"} for i in range(n)]}
    dep("531966d4a8a84ff9", "p1", "delivery", "AI Delivery — BIG-IP virtual servers", "succeeded", 1792248181.0, "after-delivery", passed(17))
    dep("6cefd937e7e749c8", "p2", "security", "AI Security — mTLS agent identity", "succeeded", 1792248387.0, "after-security", passed(21))
    dep("30096d6a3bbf4ecf", "p3", "data", "AI Data Delivery — S3, RAG, inference", "rolled-back", 1792369128.0, "after-data", "statistics did not settle")
    dep("f7c281bed34a4346", "p4", "data", "AI Data Delivery — S3, RAG, inference", "succeeded", 1792379226.0, "after-data", passed(27))
    db.execute("INSERT INTO validation_run VALUES (?,?,?,?,?,?)", ("e41f8132bb6a4535", "x", "after-security", 1792362423.0, 1792362424.0,
                                                                   json.dumps([{"test": f"s{i}", "result": "pass"} for i in range(21)])))
    db.commit()


def test_gate_validations_from_deployment_journal_and_independent_runs_separate(ctx):
    make(ctx, None, {})
    _seed_deployments(ctx.web.STORE.db)
    s = ctx.viewer.get("/api/aiops/security").json()
    latest = s["gates"]["latest"]
    assert [(g["gate"], g["deployment"], g["counts"], g["total"], g["origin"]) for g in latest] == [
        ("after-data", "f7c281bed34a4346", {"pass": 27}, 27, "deployment_gate"),
        ("after-security", "6cefd937e7e749c8", {"pass": 21}, 21, "deployment_gate"),
        ("after-delivery", "531966d4a8a84ff9", {"pass": 17}, 17, "deployment_gate")]
    rolled = [h for h in s["gates"]["history"] if h["deployment"] == "30096d6a3bbf4ecf"][0]
    assert rolled["gate_status"] == "failed" and rolled["total"] is None and "did not settle" in rolled["error"]
    assert [(r["origin"], r["label"], r["counts"]) for r in s["independent"]["runs"]] == [("independent_run", "after-security", {"pass": 21})]
    o = ctx.viewer.get("/api/aiops/overview").json()
    assert o["security"]["gates"][0]["deployment"] == "f7c281bed34a4346" and o["security"]["gates"][0]["counts"] == {"pass": 27}


def test_deployer_failure_isolated_and_read_only_actions(ctx, env):
    async def broken(req):
        raise RuntimeError("deployment service unavailable")
    make(ctx, None, env, deployer=broken)
    d = ctx.viewer.get("/api/aiops/delivery").json()
    assert d["bigip"]["state"] == "unavailable"
    _, calls = make(ctx, None, env)
    for p in ROUTES:
        ctx.viewer.get(p)
    assert {c["action"] for c in calls} == {"data_status", "pool_status"}


# ------------------------------------------------------------------ investigations, execution path, durable summaries
def _agent_list(trace=TRACE_ID):
    return [{"id": AGENT_ID, "alert_id": "ALERT-9001", "started": 1792381062.0, "finished": 1792381137.48, "state": "completed", "trace_id": trace,
             "card_url": "https://agent-b.aplab.internal/", "error": None,
             "result": {"assessment": {"decision": "escalate", "risk_level": "high", "confidence": 0.91, "rationale": "CASE CONTENT should not be shown"}}}]


def test_execution_path_from_stored_autopilot_timeline():
    from autopilot import aiops
    p = aiops.execution_path(fx("fraud_run_alert9001_timeline.json"), DATA_VIPS, DATA_BACKENDS)
    st = {s["stage"]: s for s in p["stages"]}
    assert p["total_ms"] == 77726.0 and p["spans"] == 159 and p["tokens"] == {"input": 1573, "output": 167}
    assert (st["mcp"]["calls"], st["embed"]["calls"], st["vector_db"]["calls"], st["s3"]["calls"]) == (34, 1, 1, 1)
    mcp_sum = sum(e["duration_ms"] for e in fx("fraud_run_alert9001_timeline.json")["events"] if e["category"] == "mcp")
    assert st["chat"]["busy_ms"] == 71027.5 and 0 < st["mcp"]["busy_ms"] < mcp_sum            # union of intervals, not the sum
    assert st["embed"]["paths"] == ["direct"] and st["s3"]["paths"] == ["direct"]                 # pre-Step-1 run: honest "direct"
    assert st["mcp"]["paths"] == ["via_bigip"] and st["a2a"]["paths"] == ["via_bigip"]          # server spans decide A2A / MCP
    blob = json.dumps(p)
    assert "attrs" not in blob and "http://" not in blob and "target" not in blob


def test_agent_a_path_from_jaeger_is_stored_sanitised(ctx, tmp_path):
    fetches = []

    async def jaeger(tid):
        fetches.append(tid)
        return jaeger_trace()

    async def agent(url):
        return _agent_list()
    sd = tmp_path / "trace-summaries"
    make(ctx, None, {}, http_get=agent, trace_fetch=jaeger, summary_dir=str(sd))
    r = ctx.viewer.get(f"/api/aiops/investigations/agent_a/{AGENT_ID}/path").json()
    assert r["state"] == "ok" and r["persisted"] is True and r["trace_url"].endswith(f"/trace/{TRACE_ID}")
    st = {s["stage"]: s for s in r["path"]["stages"]}
    assert st["embed"]["paths"] == ["via_bigip"] and st["vector_db"]["paths"] == ["via_bigip"] and st["s3"]["paths"] == ["via_bigip"]
    assert st["a2a"]["paths"] == ["via_bigip"] and st["mcp"]["paths"] == ["via_bigip"]
    assert st["chat"]["paths"] == ["via_bigip"] and st["chat"]["busy_ms"] == 74530.0 and r["path"]["tokens"] == {"input": 1500, "output": 160}
    f = sd / f"{TRACE_ID}.json"
    assert f.exists() and stat.S_IMODE(f.stat().st_mode) == 0o640
    raw = f.read_text()
    for forbidden in ("SECRET PROMPT TEXT", "http://", "10.50.10.105", "CASE CONTENT", "attrs", "rationale"):
        assert forbidden not in raw, forbidden
    r2 = ctx.viewer.get(f"/api/aiops/investigations/agent_a/{AGENT_ID}/path").json()
    assert r2["detail"].startswith("stored summary") and fetches == [TRACE_ID]                 # served from the store, no 2nd Jaeger read


def test_expired_trace_is_reported_honestly(ctx, tmp_path):
    async def gone(tid):
        return None

    async def agent(url):
        return _agent_list()
    make(ctx, None, {}, http_get=agent, trace_fetch=gone, summary_dir=str(tmp_path / "s"))
    r = ctx.viewer.get(f"/api/aiops/investigations/agent_a/{AGENT_ID}/path").json()
    assert r["state"] == "trace_expired" and "9–10 h" in r["detail"] and "path" not in r


def test_jaeger_down_and_summary_store_disabled(ctx):
    async def down(tid):
        raise httpx.ConnectError("refused")

    async def agent(url):
        return _agent_list()
    make(ctx, None, {}, http_get=agent, trace_fetch=down, summary_dir="")
    assert ctx.viewer.get(f"/api/aiops/investigations/agent_a/{AGENT_ID}/path").json()["state"] == "unavailable"

    async def ok(tid):
        return jaeger_trace()
    make(ctx, None, {}, http_get=agent, trace_fetch=ok, summary_dir="")
    r = ctx.viewer.get(f"/api/aiops/investigations/agent_a/{AGENT_ID}/path").json()
    assert r["state"] == "ok" and r["persisted"] is False
    assert ctx.viewer.get("/api/aiops/investigations").json()["summary_store"] == "disabled"


def test_summary_store_is_bounded(ctx, tmp_path, monkeypatch):
    from autopilot import aiops
    monkeypatch.setattr(aiops, "MAX_SUMMARIES", 3)
    a, _ = make(ctx, None, {}, summary_dir=str(tmp_path / "s"))
    path = aiops.execution_path({"events": [], "summary": {}})
    for i in range(6):
        assert a._store_summary(f"{i:032x}", path)
        os.utime(tmp_path / "s" / f"{i:032x}.json", (1000 + i, 1000 + i))
    assert sorted(p.name for p in (tmp_path / "s").iterdir()) == [f"{i:032x}.json" for i in (3, 4, 5)]
    assert a._store_summary("../../etc/passwd", path) is False


def test_investigations_list_captures_bounded_and_caches_agent_a(ctx, tmp_path):
    from autopilot import aiops
    gets, fetches = [], []

    async def agent(url):
        gets.append(url)
        return [{**_agent_list(f"{i:032x}")[0], "id": f"{i:08x}-0000-4000-8000-000000000000"} for i in range(6)]

    async def jaeger(tid):
        fetches.append(tid)
        return {**jaeger_trace(), "traceID": tid}
    clk = Clock()
    make(ctx, None, {}, http_get=agent, trace_fetch=jaeger, summary_dir=str(tmp_path / "s"), clock=clk)
    d = ctx.viewer.get("/api/aiops/investigations").json()
    assert len(fetches) == aiops.TRACE_CAPTURE_PER_REFRESH == 3
    assert [r["path_state"] for r in d["agent_a"]["runs"]].count("stored") == 3
    r0 = d["agent_a"]["runs"][0]
    assert (r0["decision"], r0["risk"], r0["confidence"], r0["duration"]["seconds"]) == ("escalate", "high", 0.91, 75.5)
    assert "CASE CONTENT" not in json.dumps(d) and "rationale" not in json.dumps(d)
    clk.t += 120
    ctx.viewer.get("/api/aiops/investigations")
    assert len(gets) == 1                                                  # Agent A polled at most every 300 s
    clk.t += 200
    ctx.viewer.get("/api/aiops/investigations")
    assert len(gets) == 2 and len(fetches) == 6                            # next refresh captures the next three


def test_autopilot_investigation_path_uses_stored_timeline(ctx):
    make(ctx, None, {})
    tl = fx("fraud_run_alert9001_timeline.json")
    ctx.web.STORE.db.execute("INSERT INTO fraud_run (id, created, actor, assessment_id, scenario_id, scenario, state, trace_id, agent_b_url, seconds, response, summary, events, error, infra_state) "
                             "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("6d6811e929304bb2", 1.0, "se1", "a", "ALERT-9001", json.dumps({"title": "Account takeover", "kind": "alert"}),
                                                                         "completed", TRACE_ID, "x", 71.6, json.dumps({"result": {"assessment": {"decision": "escalate"}}}),
                                                                         json.dumps(tl["summary"]), json.dumps(tl["events"]), None, None))
    ctx.web.STORE.db.commit()
    r = ctx.viewer.get("/api/aiops/investigations/autopilot/6d6811e929304bb2/path").json()
    assert r["state"] == "ok" and r["persisted"] is True and r["path"]["spans"] == 159
    assert ctx.viewer.get("/api/aiops/investigations/autopilot/0000000000000000/path").json()["state"] == "not_found"


# ------------------------------------------------------------------ traffic generator (read-only files)
def _tg(tmp_path, running=False):
    base = tmp_path / "ap-trafficgen"; (base / "state").mkdir(parents=True)
    st = {"started": "2026-10-19T04:20:11Z", "mode": "bounded 900s", "updated": "2026-10-19T04:35:07Z",
          "workloads": {"pa_a2a_card": {"runs": 8, "ok": 8, "unexpected": 0, "unavailable": 0, "error": 0, "requests": 8, "bytes": 5664, "avg_ms": 40.3,
                                        "targets": {"A2A_VIP": {"address": "10.50.10.100:443", "bigip_object": "/AP_AI/a2a_risk_assessment_agent/service"}},
                                        "last_result": {"outcome": "ok", "detail": "free text not exposed"}},
                        "pa_vector_query": {"runs": 6, "ok": 6, "requests": 12}, "bad name!": {"runs": 99}}}
    run = base / "runs" / "20261019T043547Z"; run.mkdir(parents=True)
    (run / "status.json").write_text(json.dumps(st))
    (run / "container.txt").write_text("0 2026-10-19T04:20:10.771Z 2026-10-19T04:35:12.385Z [--duration 900 --only pa_a2a_card,pa_vector_query,pa_embed --max-rpm 4]\n")
    lines = [json.dumps({"ts": "2026-10-19T04:20:11Z", "event": "start"})]
    for i, ms in enumerate([90.9, 59.1, 35.6, 30.2, 11.1, 12.0, 25.0, 40.0]):
        lines.append(json.dumps({"ts": f"2026-10-19T04:{20 + i * 2:02d}:16Z", "workload": "pa_a2a_card", "outcome": "ok", "ms": ms, "detail": "x"}))
    (run / "run.log").write_text("\n".join(lines) + "\n")
    if running:
        (base / "state" / "status.json").write_text(json.dumps({**st, "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
    return base


def test_trafficgen_run_summaries_rates_and_latency(ctx, tmp_path):
    make(ctx, None, {}, tg_dir=str(_tg(tmp_path)))
    d = ctx.viewer.get("/api/aiops/trafficgen").json()
    assert d["state"] == "ok" and d["status"] == "idle" and d["current"] is None
    r = d["runs"][0]
    assert r["duration"]["seconds"] == 902.0 and r["totals"]["requests"] == 20 and r["rate"]["requests_per_min"] == 1.33
    assert r["rate"]["success_pct"] == 100.0 and list(r["workloads"]) == ["pa_a2a_card", "pa_vector_query"]
    assert r["latency_ms"]["pa_a2a_card"] == {"n": 8, "p50": 35.6, "p95": 90.9, "max": 90.9}
    assert len(r["runs_per_minute"]) == 8 and "free text" not in json.dumps(d)


def test_trafficgen_running_and_not_installed(ctx, tmp_path):
    make(ctx, None, {}, tg_dir=str(_tg(tmp_path, running=True)))
    d = ctx.viewer.get("/api/aiops/trafficgen").json()
    assert d["status"] == "running" and d["current"]["running"] is True
    make(ctx, None, {}, tg_dir=str(tmp_path / "missing"))
    assert ctx.viewer.get("/api/aiops/trafficgen").json()["state"] == "not_installed"


def test_only_the_bounded_trafficgen_controls_are_exposed(ctx):
    """tgctl-web supersedes the v2.x 'no controls' guard: the ONLY state-changing AI Operations routes are the two preset
    controls (preset id + typed confirmation; see test_release_tgctl*.py); everything else under /api/aiops stays GET-only."""
    aiops_routes = [r for r in ctx.web.app.routes if getattr(r, "path", "").startswith("/api/aiops")]
    mutating = sorted(r.path for r in aiops_routes if not getattr(r, "methods", {"GET"}) <= {"GET", "HEAD"})
    assert mutating == ["/api/aiops/trafficgen/start", "/api/aiops/trafficgen/stop"]
    assert all(r.methods == {"POST"} for r in aiops_routes if r.path in mutating)
    assert [r.path for r in aiops_routes if "control" in r.path] == ["/api/aiops/trafficgen/control"]


# ------------------------------------------------------------------ overview
def test_overview_from_bigip_gates_investigations_and_generator(ctx, env, tmp_path):
    _seed_deployments(ctx.web.STORE.db)

    async def agent(url):
        return _agent_list()
    make(ctx, None, env, http_get=agent, tg_dir=str(_tg(tmp_path)))
    o = ctx.viewer.get("/api/aiops/overview?range=1h").json()
    assert [t["app"] for t in o["vips"]] == ["a2a_risk_assessment_agent", "mcp_risk_scoring", "mcp_fraud_intel", "s3_seaweedfs", "rag_qdrant", "llm_ollama"]
    s3 = next(t for t in o["vips"] if t["app"] == "s3_seaweedfs")
    assert s3["source"] == "bigip" and s3["lifetime"]["requests"] == 5
    assert next(t for t in o["vips"] if t["app"] == "mcp_risk_scoring")["source"] is None
    assert o["investigation"]["alert"] == "ALERT-9001" and o["trafficgen"]["last_run"]["run"] == "20261019T043547Z"
    assert set(o["states"]) == {"bigip", "gates", "agent_a", "trafficgen"}


# ------------------------------------------------------------------ UI
def test_ui_wiring_preserves_existing_pages():
    html = (STATIC / "index.html").read_text(); js = (STATIC / "app.js").read_text()
    assert html.index('src="/static/aiops.js"') < html.index('src="/static/app.js"')
    for p in ("demo", "fraud", "control", "aiops", "discover", "assess", "recommend", "approve", "deploy", "validate", "observe", "audit"):
        assert f'"{p}"' in js.split("const PAGES = ")[1].split(";")[0] and f'id="p-{p}"' in html


def _node_render(tmp_path, tab, data, extra=""):
    harness = tmp_path / "h.js"
    harness.write_text("""
const vm = require('vm'), fs = require('fs');
const esc = (x) => String(x ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let out = '';
const el = {querySelectorAll: () => []};
const ctx = {esc, badge: (v, c) => `<span class="badge b-${esc(c)}">${esc(v)}</span>`, patch: (e, h) => { out = h; }, api: async () => ({}),
  localStorage: {getItem: () => null, setItem: () => {}}, document: {getElementById: () => el, hidden: false}, window: {}, setTimeout: () => 0, clearTimeout: () => {}, PAGE: 'aiops', console, Date};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8') + '\\nAIOPS.tab = ' + JSON.stringify(process.argv[3]) + '; AIOPS.data[AIOPS.tab] = ' + process.argv[4] + '; AIOPS.at[AIOPS.tab] = 1; ' + process.argv[5] + '; aiRender();', ctx);
process.stdout.write(out);
""")
    p = subprocess.run(["node", str(harness), str(STATIC / "aiops.js"), tab, json.dumps(data), extra], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    return p.stdout


@pytest.mark.skipif(not shutil.which("node"), reason="node not available")
def test_ui_renders_every_tab_live_shapes_and_escapes(ctx, env, tmp_path):
    _seed_deployments(ctx.web.STORE.db)

    async def agent(url):
        x = _agent_list(); x[0]["alert_id"] = "<img src=x onerror=alert(1)>"
        return x

    async def jaeger(tid):
        return jaeger_trace()
    make(ctx, None, env, http_get=agent, tg_dir=str(_tg(tmp_path)), trace_fetch=jaeger, summary_dir=str(tmp_path / "s"))
    for tab, path in (("overview", "overview"), ("delivery", "delivery"), ("security", "security"), ("investigations", "investigations"),
                      ("trafficgen", "trafficgen")):
        data = ctx.viewer.get(f"/api/aiops/{path}").json()
        extra = ""
        if tab == "investigations":
            pth = ctx.viewer.get(f"/api/aiops/investigations/agent_a/{AGENT_ID}/path").json()
            extra = f"AIOPS.path = {json.dumps(pth)}; AIOPS.pathKey = 'agent_a/{AGENT_ID}'"
        h = _node_render(tmp_path, tab, data, extra)
        assert "<img" not in h and 'onerror=alert(1)>' not in h, tab
        assert "LIFETIME" in h and "IN RANGE" not in h, tab                      # kind legend on every tab
        if tab == "security":
            assert "f7c281bed34a4346" in h and "27 pass" in h and "Deployment gate validations" in h and "Independent validation runs" in h
        if tab == "investigations":
            assert "Embeddings (Ollama)" in h and "via BIG-IP" in h and "busy" in h and "1500 in / 160 out" in h
        if tab == "trafficgen":
            assert "1.3/min" in h or "1.3" in h
        if tab == "overview":
            assert "after-data 27/27" in h


@pytest.mark.skipif(not shutil.which("node"), reason="node not available")
def test_ui_states_render(tmp_path):
    states = {"delivery": {"bigip": {"state": "unavailable", "detail": "<b>x</b>"}},
              "security": {"gates": {"state": "ok", "latest": [], "history": []}, "independent": {"state": "unavailable", "detail": "<b>x</b>", "runs": []}},
              "trafficgen": {"state": "not_installed", "detail": "not mounted", "runs": []}}
    for tab, data in states.items():
        h = _node_render(tmp_path, tab, data)
        assert "<b>x</b>" not in h and 'href="javascript:' not in h
    h = _node_render(tmp_path, "investigations", {"agent_a": {"state": "ok", "runs": []}, "autopilot": {"state": "ok", "runs": []}},
                     "AIOPS.path = {state: 'trace_expired', detail: 'gone'}; AIOPS.pathKey = 'agent_a/x'")
    assert "trace expired" in h


def test_ui_polling_is_visibility_aware():
    js = (STATIC / "aiops.js").read_text()
    assert "document.hidden" in js and "visibilitychange" in js and "60000" in js
    assert "setInterval" not in js


# ------------------------------------------------------------------ v2.1: remembered expiry, settle window, errors never cached
def test_v21_expired_trace_is_remembered(ctx, tmp_path):
    fetches = []

    async def gone(tid):
        fetches.append(tid)
        return None

    async def agent(url):
        return _agent_list()
    make(ctx, None, {}, http_get=agent, trace_fetch=gone, summary_dir=str(tmp_path / "s"))
    for _ in range(4):
        r = ctx.viewer.get(f"/api/aiops/investigations/agent_a/{AGENT_ID}/path").json()
        assert r["state"] == "trace_expired"
        ctx.viewer.get("/api/aiops/investigations")
    assert fetches == [TRACE_ID]                                             # one Jaeger read, then remembered
    assert "remembered" in r["detail"]


def test_v21_jaeger_errors_are_never_remembered(ctx, tmp_path):
    calls, mode = [], {"m": "error"}

    async def flaky(tid):
        calls.append(mode["m"])
        if mode["m"] == "error":
            raise httpx.ConnectError("refused")
        if mode["m"] == "5xx":
            raise httpx.HTTPStatusError("503", request=httpx.Request("GET", "http://j/"), response=httpx.Response(503))
        return jaeger_trace()

    async def agent(url):
        return _agent_list()
    make(ctx, None, {}, http_get=agent, trace_fetch=flaky, summary_dir=str(tmp_path / "s"))
    url = f"/api/aiops/investigations/agent_a/{AGENT_ID}/path"
    assert ctx.viewer.get(url).json()["state"] == "unavailable"
    mode["m"] = "5xx"
    r = ctx.viewer.get(url).json()
    assert r["state"] == "unavailable" and "retry" in r["detail"]
    mode["m"] = "ok"
    r = ctx.viewer.get(url).json()
    assert r["state"] == "ok" and r["persisted"] is True                       # recovered: never treated as expired
    assert calls == ["error", "5xx", "ok"]


def test_v21_settle_window_prevents_partial_summaries(ctx, tmp_path):
    from autopilot import aiops
    clk = Clock(1792381137.48 + 30)                                          # 30 s after the investigation finished
    fetches = []

    async def j(tid):
        fetches.append(tid)
        return jaeger_trace()

    async def agent(url):
        return _agent_list()
    a, _ = make(ctx, None, {}, http_get=agent, trace_fetch=j, summary_dir=str(tmp_path / "s"), clock=clk)
    r = ctx.viewer.get(f"/api/aiops/investigations/agent_a/{AGENT_ID}/path").json()
    assert r["state"] == "pending" and fetches == []
    assert ctx.viewer.get("/api/aiops/investigations").json()["agent_a"]["runs"][0]["path_state"] == "pending"
    assert TRACE_ID not in a._expired
    clk.t += aiops.JAEGER_SETTLE_S                                           # settled
    a._cache.clear()
    r = ctx.viewer.get(f"/api/aiops/investigations/agent_a/{AGENT_ID}/path").json()
    assert r["state"] == "ok" and r["persisted"] is True and fetches == [TRACE_ID]


def test_v21_404_inside_settle_window_is_not_remembered(ctx, tmp_path):
    from autopilot import aiops
    a, _ = make(ctx, None, {}, summary_dir=str(tmp_path / "s"), clock=Clock(1000.0))

    async def gone(tid):
        return None
    a.trace_fetch = gone
    r = asyncio.run(a._path_for_trace(TRACE_ID, finished=1000.0 - 10))
    assert r["state"] == "pending" and TRACE_ID not in a._expired
    r = asyncio.run(a._path_for_trace(TRACE_ID, finished=1000.0 - aiops.JAEGER_SETTLE_S - 1))
    assert r["state"] == "trace_expired" and TRACE_ID in a._expired


def test_v21_expired_runs_do_not_consume_the_capture_budget(ctx, tmp_path):
    fetches = []

    async def agent(url):
        return [{**_agent_list(f"{i:032x}")[0], "id": f"{i:08x}-0000-4000-8000-000000000000"} for i in range(6)]

    async def j(tid):
        fetches.append(tid)
        return None if int(tid, 16) < 3 else {**jaeger_trace(), "traceID": tid}
    clk = Clock(1_800_000_000.0)
    make(ctx, None, {}, http_get=agent, trace_fetch=j, summary_dir=str(tmp_path / "s"), clock=clk)
    d1 = ctx.viewer.get("/api/aiops/investigations").json()
    assert [r["path_state"] for r in d1["agent_a"]["runs"]][:3] == ["trace_expired"] * 3 and len(fetches) == 3
    d2 = ctx.viewer.get("/api/aiops/investigations").json()
    assert len(fetches) == 6 and [r["path_state"] for r in d2["agent_a"]["runs"]][3:] == ["stored"] * 3
    ctx.viewer.get("/api/aiops/investigations")
    assert len(fetches) == 6                                                  # nothing left to ask Jaeger


def test_v21_expired_memory_is_bounded(ctx, monkeypatch):
    from autopilot import aiops
    monkeypatch.setattr(aiops, "EXPIRED_MAX", 5)
    a, _ = make(ctx, None, {}, clock=Clock(10_000.0))

    async def gone(tid):
        return None
    a.trace_fetch = gone
    for i in range(9):
        asyncio.run(a._path_for_trace(f"{i:032x}", finished=1.0))
    assert len(a._expired) == 5 and f"{8:032x}" in a._expired and f"{0:032x}" not in a._expired



# ------------------------------------------------------------------ v2.2: endpoint normalisation and path classification
def test_v22_endpoint_host_normalisation():
    from autopilot import aiops
    ok = {"http://10.50.10.105:11434/v1": "10.50.10.105", "10.50.10.105": "10.50.10.105", "10.50.10.105:11434": "10.50.10.105",
          "HTTP://10.50.10.105/": "10.50.10.105", "https://LLM.aplab.internal:443/v1/chat/completions?x=1": "llm.aplab.internal",
          " 10.50.20.45 ": "10.50.20.45", "http://10.50.20.45:11434/api/embed": "10.50.20.45", "s3.aplab.internal.": "s3.aplab.internal"}
    for v, want in ok.items():
        assert aiops.endpoint_host(v) == want, v
    for bad in (None, "", "   ", "http://", "http://:80/x", "10.50.10.105:99999", "10.50.10.105:abc", "999.1.1.1", "ftp://10.50.10.105/",
                "http://[::1]:80/", "fe80::1", "user@10.50.10.105", "10.50.10.105/v1", "not a host", "http://10.50.10.105:11434/v1 x",
                "x" * 3000, 12345, {"host": "10.50.10.105"}):
        assert aiops.endpoint_host(bad) is None, bad


def test_v22_classify_data_endpoint():
    from autopilot import aiops
    c = lambda *v: aiops.classify_data_endpoint(v, DATA_VIPS, DATA_BACKENDS)
    assert c("http://10.50.10.105:11434/v1", None) == "via_bigip"                   # the ALERT-9001 chat span shape
    assert c("10.50.10.105", None) == "via_bigip" and c(None, "http://llm.aplab.internal:11434/api/embed") == "via_bigip"
    assert c("10.50.20.45", None) == "direct" and c(None, "http://10.50.20.45:11434/api/embed") == "direct"
    for unknown in ((None, None), ("garbage::", None), ("203.0.113.9", None), (None, "http://agent-b.aplab.internal/"), ("", "")):
        assert c(*unknown) == "unknown", unknown                                      # never assumed direct
    assert c("garbage::", "http://10.50.10.104:6333/collections/x/points/query") == "via_bigip"    # one usable endpoint is enough


def test_v22_no_name_resolution_or_network(monkeypatch):
    import socket
    from autopilot import aiops
    def boom(*a, **k):
        raise AssertionError("no DNS / network access allowed during classification")
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "create_connection"):
        monkeypatch.setattr(socket, name, boom)
    assert aiops.endpoint_host("http://llm.aplab.internal:11434/v1") == "llm.aplab.internal"
    assert aiops.classify_data_endpoint(("http://llm.aplab.internal:11434/v1",), DATA_VIPS, DATA_BACKENDS) == "via_bigip"


def _alert9001_path():
    from autopilot import aiops, fraud
    tr = fx("jaeger_alert9001_74915e93_sanitised.json")
    tl = fraud.timeline(tr, {"10.50.20.10", "10.50.10.10"}, {"10.50.10.100", "10.50.10.101", "10.50.10.102"})
    return tr, aiops.execution_path(tl, DATA_VIPS, DATA_BACKENDS)


def test_v22_alert9001_live_trace_all_stages_via_bigip():
    tr, p = _alert9001_path()
    st = {s["stage"]: s for s in p["stages"]}
    assert len(tr["spans"]) == 143 and p["spans"] == 143 and p["total_ms"] == 18382.8 and p["errors"] == 0
    assert {k: st[k]["paths"] for k in st} == {k: ["via_bigip"] for k in ("a2a", "mcp", "embed", "vector_db", "s3", "chat")}
    assert {k: st[k]["calls"] for k in st} == {"a2a": 2, "mcp": 34, "embed": 1, "vector_db": 1, "s3": 1, "chat": 2}
    assert (st["embed"]["busy_ms"], st["vector_db"]["busy_ms"], st["s3"]["busy_ms"], st["chat"]["busy_ms"]) == (300.0, 46.9, 11.7, 17101.6)
    assert (st["a2a"]["busy_ms"], st["mcp"]["busy_ms"], st["mcp"]["max_call_ms"]) == (18291.5, 1121.3, 702.0)
    assert p["tokens"] == {"input": 1573, "output": 168} and p["bigip_paths"] == {"a2a": ["via_bigip"], "mcp": ["via_bigip"]}


def test_v22_alert9001_only_paths_change_against_the_v21_summary():
    """The persisted v2.1 summary (captured live 21:31Z) differs from the v2.2 recomputation only in the chat stage's paths."""
    _, p = _alert9001_path()
    v21_chat = {"stage": "chat", "label": "LLM reasoning (Ollama chat)", "observed": True, "calls": 2, "busy_ms": 17101.6, "max_call_ms": 17101.6,
                "first_ms": 1188.7, "errors": 0, "paths": ["direct", "via_bigip"]}
    chat = next(s for s in p["stages"] if s["stage"] == "chat")
    assert {k: v for k, v in chat.items() if k != "paths"} == {k: v for k, v in v21_chat.items() if k != "paths"} and chat["paths"] == ["via_bigip"]


def test_v22_mixed_and_unknown_paths():
    from autopilot import aiops
    ev = lambda i, tgt, addr=None: {"id": str(i), "parent": None, "service": "mcp-fraud-intel", "category": "llm", "kind": "client", "name": "POST",
                                    "start_ms": i * 10.0, "duration_ms": 5.0, "status": "ok", "target": tgt, "path": "direct",
                                    "attrs": {"server.address": addr} if addr else {}}
    mixed = aiops.execution_path({"events": [ev(1, "http://10.50.10.105:11434/api/embed"), ev(2, "http://10.50.20.45:11434/api/embed")], "summary": {}}, DATA_VIPS, DATA_BACKENDS)
    assert next(s for s in mixed["stages"] if s["stage"] == "embed")["paths"] == ["direct", "via_bigip"]
    unk = aiops.execution_path({"events": [ev(1, "http://203.0.113.7:11434/api/embed"), ev(2, None, "::bad::")], "summary": {}}, DATA_VIPS, DATA_BACKENDS)
    assert next(s for s in unk["stages"] if s["stage"] == "embed")["paths"] == ["unknown"]                # fraud.timeline's "direct" is not trusted
    none = aiops.execution_path({"events": [ev(1, "http://10.50.10.105:11434/api/embed")], "summary": {}})  # no design data -> unknown, not direct
    assert next(s for s in none["stages"] if s["stage"] == "embed")["paths"] == ["unknown"]


def test_v22_dashboard_route_and_persisted_summary_for_the_live_trace(ctx, tmp_path):
    async def jaeger(tid):
        return fx("jaeger_alert9001_74915e93_sanitised.json")

    async def agent(url):
        return [{"id": "55c03926-f602-4880-b3ae-9bc9c71a4c73", "alert_id": "ALERT-9001", "started": 1792445206.0, "finished": 1792445224.3,
                 "state": "completed", "trace_id": "74915e93362a9d0ba73e97cd0b79f252", "card_url": "https://agent-b.aplab.internal/", "error": None,
                 "result": {"assessment": {"decision": "escalate", "risk_level": "high", "confidence": 0.91}}}]
    make(ctx, None, {}, http_get=agent, trace_fetch=jaeger, summary_dir=str(tmp_path / "s"), clock=Clock(1792445465.0))
    r = ctx.viewer.get("/api/aiops/investigations/agent_a/55c03926-f602-4880-b3ae-9bc9c71a4c73/path").json()
    assert r["state"] == "ok" and r["persisted"] is True
    assert all(s["paths"] == ["via_bigip"] for s in r["path"]["stages"])
    f = tmp_path / "s" / "74915e93362a9d0ba73e97cd0b79f252.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o640
    raw = f.read_text()
    assert set(json.loads(raw)) == {"bigip_paths", "captured_at", "errors", "services", "source", "spans", "stages", "tokens", "total_ms", "trace_id"}
    for bad in ("http", "://", "10.50.", "rationale", "prompt", "attrs", "escalate", "ALERT-9001"):
        assert bad not in raw, bad


@pytest.mark.skipif(not shutil.which("node"), reason="node not available")
def test_v22_ui_labels_unknown_and_mixed(tmp_path):
    base = {"stage": "embed", "label": "Embeddings (Ollama)", "observed": True, "calls": 1, "busy_ms": 1, "max_call_ms": 1, "first_ms": 0, "errors": 0}
    for paths, want in ((["unknown"], "path unknown"), (["direct", "via_bigip"], "mixed: via BIG-IP + direct"), (["unknown", "via_bigip"], "some spans unclassified"),
                        (["via_bigip"], "via BIG-IP")):
        h = _node_render(tmp_path, "investigations", {"agent_a": {"state": "ok", "runs": []}, "autopilot": {"state": "ok", "runs": []}},
                         "AIOPS.path = " + json.dumps({"state": "ok", "path": {"total_ms": 10, "spans": 1, "errors": 0, "stages": [{**base, "paths": paths}]}}) + "; AIOPS.pathKey = 'agent_a/x'")
        assert want in h, paths
