"""Customer fraud application experience (Phase 1): scenarios, live investigations, real A2A/MCP timeline.

Provenance rules (shown in the UI):
  scenario input   — from the deterministic synthetic dataset (aplab.synthdata, the same generator and seed the lab
                     services were loaded with) or composed by the operator from synthetic accounts/merchant categories
  live measured    — returned by Agent A's API for this run, or read from the distributed trace in Jaeger
  unavailable      — a source that could not be reached / produced nothing (stated, never filled in)
Nothing here fabricates telemetry: a timeline exists only if Jaeger returned spans for the run's trace id.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx

from aplab import synthdata

SCHEMA = """
CREATE TABLE IF NOT EXISTS fraud_run (id TEXT PRIMARY KEY, created REAL, actor TEXT, assessment_id TEXT, scenario_id TEXT,
  scenario TEXT, state TEXT, trace_id TEXT, agent_b_url TEXT, seconds REAL, response TEXT, summary TEXT, events TEXT, error TEXT,
  infra_state TEXT);
"""
INJECTED = ["FP-001", "FP-002", "FP-003", "FP-005", "FP-007", "FP-009", "FP-010", "FP-004"]   # synthdata injection order
SAFE_ATTRS = ("http.method", "http.request.method", "http.target", "url.path", "http.status_code", "http.response.status_code",
              "net.peer.ip", "client.address", "server.address", "server.port", "mcp.method.name", "mcp.protocol.version",
              "mcp.session.id", "gen_ai.tool.name", "gen_ai.agent.name", "gen_ai.operation.name", "gen_ai.system", "gen_ai.request.model",
              "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens", "a2a.task.id", "a2a.agent_card.url", "aplab.alert_id",
              "aplab.decision", "rpc.system", "rpc.service", "rpc.method", "service.instance.id", "otel.status_code", "error")
_DATA = None


def classification_coherence(sc: dict, result: dict | None) -> dict:
    """Independent post-response check; never changes the agent's decision."""
    assessment = (result or {}).get("assessment") or {}
    observed = [str(x) for x in (assessment.get("matched_patterns") or [])]
    expected = None
    if sc.get("kind") == "suspicious":
        expected = next((p["pattern_id"] for p in dataset()["fraud_patterns"] if p["name"] == sc.get("title")), None)
    if not expected:
        return {"status": "not_applicable", "expected_pattern_id": None, "observed_pattern_ids": observed,
                "reason": "No ground-truth fraud pattern applies to this normal or custom scenario."}
    if expected in observed:
        return {"status": "coherent", "expected_pattern_id": expected, "observed_pattern_ids": observed,
                "reason": "Agent assessment explicitly matched the independently derived scenario pattern."}
    return {"status": "disagreement", "expected_pattern_id": expected, "observed_pattern_ids": observed,
            "reason": "Agent assessment did not explicitly match the independently derived scenario pattern."}


def dataset() -> dict:
    global _DATA
    if _DATA is None:
        _DATA = synthdata.build()
    return _DATA


def scenarios() -> list[dict]:
    d = dataset()
    acct = {a["account_id"]: a for a in d["accounts"]}
    txn = {t["transaction_id"]: t for t in d["transactions"]}
    pat = {p["pattern_id"]: p for p in d["fraud_patterns"]}
    out = []
    for k, al in enumerate(d["alerts"]):
        p = pat[INJECTED[k]]
        out.append({"id": al["alert_id"], "kind": "suspicious", "title": p["name"], "alert_id": al["alert_id"],
                    "account": acct[al["account_id"]], "trigger": al["trigger"], "transactions": [txn[i] for i in al["transaction_ids"]],
                    "scenario_label": f"injected synthetic pattern {p['pattern_id']} ({p['name']}) — the agents are NOT told this label",
                    "requires": "alerts"})
    lows = sorted([a for a in d["accounts"] if a["kyc_risk"] == "low"], key=lambda a: a["account_id"])[:3]
    titles = ["Routine everyday spending", "Regular domestic card use", "Normal monthly activity"]
    for i, a in enumerate(lows):
        legit = sorted([t for t in d["transactions"] if t["account_id"] == a["account_id"] and t["label"] == "legit"
                        and t["country"] == a["home_country"] and t["amount"] < 250], key=lambda t: t["timestamp"], reverse=True)[:3]
        out.append({"id": f"NORMAL-{i + 1}", "kind": "normal", "title": titles[i], "account": a, "trigger": "operator test (no alert)",
                    "transactions": legit, "scenario_label": "legitimate synthetic transactions in the customer's home country",
                    "requires": "scenarios"})
    return out


CHANNELS = ["card_present", "ecommerce", "ach", "wire", "p2p"]
COUNTRIES = ["US", "CA", "GB", "DE", "MX", "BR", "NG", "RO", "SG"]


def validate_custom(sc: dict) -> dict:
    """Operator-composed scenario: synthetic account + up to 6 transactions with bounded, typed fields."""
    d = dataset()
    acct = {a["account_id"]: a for a in d["accounts"]}
    if sc.get("account_id") not in acct:
        raise ValueError("account must be one of the synthetic accounts")
    txs = sc.get("transactions") or []
    if not 1 <= len(txs) <= 6:
        raise ValueError("1..6 transactions required")
    clean = []
    base_time = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    for i, t in enumerate(txs):
        try:
            amt = round(float(t["amount"]), 2)
        except (KeyError, TypeError, ValueError):
            raise ValueError(f"transaction {i + 1}: amount must be a number")
        if not 0.01 <= amt <= 50000:
            raise ValueError(f"transaction {i + 1}: amount must be 0.01..50,000")
        if str(t.get("mcc")) not in d["mcc"]:
            raise ValueError(f"transaction {i + 1}: unknown merchant category")
        if t.get("country") not in COUNTRIES or t.get("channel") not in CHANNELS:
            raise ValueError(f"transaction {i + 1}: country/channel not allowed")
        ts = t.get("timestamp") or (base_time + timedelta(minutes=i * 5)).isoformat().replace("+00:00", "Z")
        try:
            datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"transaction {i + 1}: timestamp must be ISO-8601") from e
        direction = t.get("direction") or ("inbound" if t.get("channel") in {"ach", "p2p"} and i == 0 else "outbound")
        if direction not in {"inbound", "outbound", "credit", "debit"}:
            raise ValueError(f"transaction {i + 1}: invalid direction")
        def clean_id(key, prefix):
            value = str(t.get(key) or f"{prefix}-{i + 1:02d}")
            if not re.fullmatch(r"[A-Z0-9_-]{1,32}", value):
                raise ValueError(f"transaction {i + 1}: invalid {key}")
            return value
        clean.append({"transaction_id": f"TXN-C{i + 1:02d}", "amount": amt, "mcc": str(t["mcc"]), "category": d["mcc"][str(t["mcc"])],
                      "country": t["country"], "channel": t["channel"], "currency": "USD", "timestamp": str(ts),
                      "direction": direction, "merchant_id": clean_id("merchant_id", "CUSTOM-MERCHANT"),
                      "merchant_name": str(t.get("merchant_name") or f"Synthetic custom merchant {i + 1}")[:80],
                      "beneficiary_id": clean_id("beneficiary_id", "CUSTOM-BENEFICIARY") if direction in {"outbound", "debit"} else None,
                      "sender_id": clean_id("sender_id", "CUSTOM-SENDER") if direction in {"inbound", "credit"} else None,
                      "device_id": clean_id("device_id", "CUSTOM-DEVICE"),
                      "temporal_relation_minutes": float(t.get("temporal_relation_minutes", i * 5))})
    title = re.sub(r"[^A-Za-z0-9 ,.'()-]", "", str(sc.get("title") or "Custom test transaction"))[:60]
    return {"id": f"CUSTOM-{uuid.uuid4().hex[:6]}", "kind": "custom", "title": title, "account": acct[sc["account_id"]],
            "trigger": "operator-composed test", "transactions": clean, "scenario_label": "composed by the operator from synthetic data",
            "requires": "scenarios"}


async def capabilities(agent_a: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            h = (await c.get(f"{agent_a}/healthz")).json()
        caps = h.get("capabilities") or ["alerts"]
        return {"reachable": True, "capabilities": caps, "agent_b_url": h.get("agent_b_url"),
                "note": None if "scenarios" in caps else "This Agent A version investigates the dataset's alert scenarios only; normal and custom "
                                                         "scenarios need the updated agents (prepared, not yet deployed)."}
    except (httpx.HTTPError, ValueError) as e:
        return {"reachable": False, "capabilities": [], "error": f"{type(e).__name__}: {e}"[:200]}


async def health(checks: list[dict]) -> list[dict]:
    async def one(ch):
        t0 = time.time()
        try:
            async with httpx.AsyncClient(timeout=4) as c:
                r = await c.get(ch["url"])
            return {**ch, "reachable": r.status_code < 500, "status": r.status_code, "ms": round((time.time() - t0) * 1000), "error": None}
        except httpx.HTTPError as e:
            return {**ch, "reachable": False, "status": None, "ms": None, "error": f"{type(e).__name__}"}
    return list(await asyncio.gather(*(one(c) for c in checks)))


# ---------------------------------------------------------------- trace -> timeline
def _tags(span: dict) -> dict:
    return {t["key"]: t["value"] for t in span.get("tags", [])}


def categorise(svc: str, t: dict, name: str) -> str:
    url = str(t.get("http.url") or t.get("url.full") or "")
    target = str(t.get("http.target") or t.get("url.path") or "")
    if t.get("mcp.method.name") or (t.get("span.kind") == "server" and target.startswith("/mcp")) or "/mcp" in url:
        return "mcp"
    if t.get("a2a.task.id") or "agent-card" in url or "agent-card" in target or name in ("SendMessage", "SendStreamingMessage") \
            or (svc.startswith("agent-b") and t.get("span.kind") == "server" and target in ("/", "")):
        return "a2a"
    if t.get("gen_ai.system") or any(x in url for x in ("/chat/completions", "/api/chat", "/api/generate", "/api/embed", "/v1/embeddings")):
        return "llm"
    if "/collections/" in url:
        return "vector_db"
    if t.get("rpc.system") == "aws-api":
        return "s3"
    if t.get("gen_ai.operation.name") == "invoke_agent":
        return "agent"
    if t.get("span.kind") == "client" and svc.startswith("agent-a") and url:
        return "a2a"
    return "http"


def timeline(trace: dict, bigip_addresses: set[str], vips: set[str]) -> dict:
    procs = trace.get("processes") or {}
    spans = trace.get("spans") or []
    if not spans:
        return {"events": [], "summary": None}
    t0 = min(s["startTime"] for s in spans)
    evs, tools, replicas, tasks, errors, paths = [], {}, set(), set(), 0, {}
    for s in sorted(spans, key=lambda x: x["startTime"]):
        p = procs.get(s["processID"], {})
        ptags = {x["key"]: x["value"] for x in p.get("tags", [])}
        svc = p.get("serviceName", "?")
        t = _tags(s)
        cat = categorise(svc, t, s.get("operationName", ""))
        status_code = int(t.get("http.status_code") or t.get("http.response.status_code") or 0)
        recoverable = s.get("operationName") == "a2a.server.events.event_queue_v2.EventQueueSource.dequeue_event" and not status_code \
            and not t.get("exception.message") and not t.get("exception.type")
        err = (bool(t.get("error")) or str(t.get("otel.status_code", "")).upper() == "ERROR" or status_code >= 500) and not recoverable
        error_detail = str(t.get("error") or t.get("exception.message") or t.get("exception.type") or "")[:240] if (err or recoverable) else None
        errors += err
        peer = t.get("net.peer.ip") or t.get("client.address")
        url = t.get("http.url") or t.get("url.full")
        host = urlsplit(url).hostname if url and "://" in url else (str(t.get("http.host") or "").split(":")[0] or None)
        path = None
        if t.get("span.kind") == "server" and peer:
            path = "via_bigip" if peer in bigip_addresses else "direct"
        elif host:
            path = "via_bigip" if host in vips else "direct"
        if cat in ("a2a", "mcp") and path and t.get("span.kind") == "server":
            paths.setdefault(cat, set()).add(path)
        if t.get("gen_ai.tool.name") and t.get("span.kind") == "server":
            tools[t["gen_ai.tool.name"]] = tools.get(t["gen_ai.tool.name"], 0) + 1
        if ptags.get("service.instance.id") and svc.startswith("mcp-risk"):
            replicas.add(ptags["service.instance.id"])
        if t.get("a2a.task.id"):
            tasks.add(t["a2a.task.id"])
        parent = next((r["spanID"] for r in s.get("references", []) if r.get("refType") == "CHILD_OF"), None)
        evs.append({"id": s["spanID"], "parent": parent, "service": svc, "instance": ptags.get("service.instance.id"),
                    "name": s.get("operationName"), "category": cat, "kind": t.get("span.kind"),
                    "start_ms": round((s["startTime"] - t0) / 1000, 1), "duration_ms": round(s["duration"] / 1000, 1),
                    "status": "error" if err else "recoverable" if recoverable else "ok", "http_status": status_code or None, "peer": peer,
                    "target": url.split("?")[0] if url else (t.get("http.host") and f"{t.get('http.host')}{t.get('http.target', '')}"),
                    "path": path, "error_detail": error_detail,
                    "attrs": {k: t[k] for k in SAFE_ATTRS if k in t}})
    end = max(s["startTime"] + s["duration"] for s in spans)
    counts = {}
    for e in evs:
        counts[e["category"]] = counts.get(e["category"], 0) + 1
    edges = {}
    by_id = {e["id"]: e for e in evs}
    for e in evs:
        par = by_id.get(e["parent"])
        if par and par["service"] != e["service"]:
            k = (par["service"], e["service"], e["category"])
            ed = edges.setdefault(k, {"from": par["service"], "to": e["service"], "category": e["category"], "count": 0, "paths": set()})
            ed["count"] += 1
            if e["path"]:
                ed["paths"].add(e["path"])
        elif e["kind"] == "client" and e["category"] in ("llm", "vector_db", "s3"):
            tgt = urlsplit(e["target"]).netloc if e["target"] and "://" in e["target"] else (e["target"] or e["category"])
            k = (e["service"], tgt, e["category"])
            ed = edges.setdefault(k, {"from": e["service"], "to": tgt, "category": e["category"], "count": 0, "paths": set()})
            ed["count"] += 1
            if e["path"]:
                ed["paths"].add(e["path"])
    error_spans = [{k: e.get(k) for k in ("id", "service", "name", "http_status", "error_detail", "target", "path")}
                   for e in evs if e["status"] == "error"]
    recoverable_spans = [{k: e.get(k) for k in ("id", "service", "name", "http_status", "error_detail", "target", "path")}
                         for e in evs if e["status"] == "recoverable"]
    return {"events": evs, "edges": [{**v, "paths": sorted(v["paths"])} for v in edges.values()],
            "summary": {"trace_id": trace.get("traceID"), "spans": len(evs), "duration_ms": round((end - t0) / 1000, 1),
                        "services": sorted({e["service"] for e in evs}), "by_category": counts, "errors": errors,
                        "mcp_tools": tools, "risk_replicas": sorted(replicas), "a2a_tasks": sorted(tasks),
                        "paths": {k: sorted(v) for k, v in paths.items()}, "error_spans": error_spans,
                        "recoverable_spans": recoverable_spans}}


async def fetch_trace(jaeger: str, trace_id: str, wait_s: float = 20) -> dict | None:
    """Poll Jaeger until the trace's span count is stable (span export is batched)."""
    last, stable, t0 = -1, 0, time.time()
    data = None
    async with httpx.AsyncClient(timeout=10) as c:
        while time.time() - t0 < wait_s:
            try:
                r = await c.get(f"{jaeger}/api/traces/{trace_id}")
                d = (r.json().get("data") or [None])[0] if r.status_code == 200 else None
            except (httpx.HTTPError, ValueError):
                d = None
            n = len((d or {}).get("spans") or [])
            if d and n == last:
                stable += 1
                if stable >= 2:
                    return d
            else:
                stable = 0
            last, data = n, d or data
            await asyncio.sleep(2)
    return data
