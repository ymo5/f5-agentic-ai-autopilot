"""Deterministic validation framework — records actual results, never simulated ones.

Profiles:
  before          — direct paths (deliberate baseline gaps present)
  after-delivery  — A2A/MCP through BIG-IP virtual servers; LB, monitor, persistence, failover
  after-security  — + mTLS identity, tool authorisation, rate limiting, bypass blocked
Targets are read from what the running agents are configured to use. Host/BIG-IP-side actions (replica stop/start,
pool member status, Agent B direct probe) are delegated to `actions` (the deployer's narrow validation endpoint);
when no actions provider exists those tests are reported as 'skipped', not passed.
Every network operation is guarded: an unreachable endpoint becomes a named failing test that states the endpoint and
the error (never an unexplained exception), and tests that depend on it are reported as failed with the precondition.
"""
from __future__ import annotations

import asyncio
import collections
import json
import os
import re
import socket
import ssl
import time
from typing import Awaitable, Callable
from urllib.parse import urlsplit

import httpx
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from .mcpclient import mcp_probe
from .stats import latency_summary

PROFILES = {
    "before": {"via_bigip": False, "lockdown": False, "lb": False, "security": False},
    "after-delivery": {"via_bigip": True, "lockdown": False, "lb": True, "security": False},
    "after-security": {"via_bigip": True, "lockdown": True, "lb": True, "security": True},
    # AI Data Delivery (opt-in): everything after-security proves, plus the S3 / RAG / inference front doors (data.*)
    "after-data": {"via_bigip": True, "lockdown": True, "lb": True, "security": True, "data": True},
}
DATA_SERVICES = ("s3", "rag", "llm")
SIGV4_REFUSALS = {"InvalidAccessKeyId", "SignatureDoesNotMatch", "AccessDenied"}


def _stat_delta(before: dict, after: dict, key: str) -> int | None:
    b, a = (before or {}).get(key), (after or {}).get(key)
    return None if a is None or b is None else a - b


async def data_checks(cfg: dict, actions, rec) -> None:
    """after-data: read-only checks of the AI Data Delivery virtual servers. Nothing is written, no model is invoked.
    Statistics are compared before/after the probes (BIG-IP's own counters, read through the deployer's observer)."""
    dd = (cfg.get("design") or {}).get("data_delivery") or {}
    missing = [s for s in DATA_SERVICES if s not in dd]
    if missing:
        rec("data.precondition", False, {"missing": missing}, "design.data_delivery defines s3, rag and llm")
        return
    base = {s: f"http://{dd[s]['vip']}:{dd[s]['port']}" for s in DATA_SERVICES}
    sent = {s: 0 for s in DATA_SERVICES}

    async def status():
        if not actions:
            return None
        try:
            return await actions({"action": "data_status"})
        except Exception as e:  # noqa: BLE001 - reported as a failing check, never raised
            return {"error": err(e)}

    before = await status()
    # ---- pool / monitor health (BIG-IP's view)
    want = sorted(m for s in DATA_SERVICES for m in dd[s]["members"])
    if before is None:
        rec("data.pools_healthy", False, {"error": "no deployer validation actions"}, "BIG-IP data pool members available", skipped=True)
    else:
        mem = {f"{m.get('member')}:{m.get('port')}": m for m in (before.get("members") or [])}
        bad = {k: (mem.get(k) or {}).get("availability", "absent") for k in want
               if (mem.get(k) or {}).get("availability") != "available" or (mem.get(k) or {}).get("enabled") != "enabled"}
        rec("data.pools_healthy", not bad and "error" not in before, {"members": {k: (mem.get(k) or {}).get("availability") for k in want},
            "not_ready": bad, "error": before.get("error")}, "every data pool member available and enabled (BIG-IP health monitor up)")
    # ---- S3 through the VIP: unauthenticated request must reach SeaweedFS and be refused by it
    s3h = {"Host": dd["s3"]["host"]}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{base['s3']}/", headers=s3h)
        sent["s3"] += 1
        code = re.search(r"<Code>([^<]+)</Code>", r.text or "")
        rec("data.s3_via_front_door", bool(r.status_code == 403 and code and code.group(1) == "AccessDenied"),
            {"url": f"{base['s3']}/", "status": r.status_code, "s3_error": code.group(1) if code else None},
            "S3 API answers through the BIG-IP S3 virtual server and refuses the unauthenticated request (403 AccessDenied)")
    except httpx.HTTPError as e:
        rec("data.s3_via_front_door", False, {"url": f"{base['s3']}/", "error": err(e)}, "S3 virtual server reachable")
    # ---- SigV4 is verified end-to-end (BIG-IP passes Authorization unchanged): an invalid signature must be refused
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
        s3 = boto3.client("s3", endpoint_url=base["s3"], region_name="us-east-1", aws_access_key_id="AKIDAPVALIDATIONINVALID0",
                          aws_secret_access_key="invalid-validation-signature", config=Config(s3={"addressing_style": "path"},
                          retries={"max_attempts": 1}, connect_timeout=5, read_timeout=10))
        try:
            await asyncio.to_thread(s3.list_buckets)
            sent["s3"] += 1
            rec("data.s3_sigv4_enforced", False, {"result": "listed buckets with an invalid signature"}, "invalid SigV4 signature refused (403)")
        except ClientError as e:
            sent["s3"] += 1
            ec, hs = e.response.get("Error", {}).get("Code"), e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            rec("data.s3_sigv4_enforced", hs == 403 and ec in SIGV4_REFUSALS, {"status": hs, "s3_error": ec},
                "invalid SigV4 signature refused by SeaweedFS through BIG-IP (403 InvalidAccessKeyId / SignatureDoesNotMatch)")
        except BotoCoreError as e:
            rec("data.s3_sigv4_enforced", False, {"error": err(e)}, "S3 virtual server reachable for a signed request")
    except ImportError as e:
        rec("data.s3_sigv4_enforced", False, {"error": err(e)}, "boto3 available in the validator")
    # ---- optional: an authorised, read-only S3 listing (only when an approved validation identity is configured)
    pref = ((cfg.get("validation") or {}).get("data") or {}).get("s3_credentials_env")
    if pref and os.environ.get(f"{pref}_ACCESS_KEY_ID") and os.environ.get(f"{pref}_SECRET_ACCESS_KEY"):
        try:
            import boto3
            from botocore.config import Config
            s3a = boto3.client("s3", endpoint_url=base["s3"], region_name="us-east-1", aws_access_key_id=os.environ[f"{pref}_ACCESS_KEY_ID"],
                               aws_secret_access_key=os.environ[f"{pref}_SECRET_ACCESS_KEY"],
                               config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))
            res = await asyncio.to_thread(s3a.list_buckets)
            sent["s3"] += 1
            rec("data.s3_sigv4_authorized_read", True, {"buckets": len(res.get("Buckets", []))}, "approved read-only identity lists buckets (200)")
        except Exception as e:  # noqa: BLE001
            rec("data.s3_sigv4_authorized_read", False, {"error": err(e)}, "approved read-only identity lists buckets (200)")
    # ---- RAG (Qdrant) through the VIP
    coll = dd["rag"].get("collection")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            rz = await c.get(f"{base['rag']}/readyz"); sent["rag"] += 1
            cl = await c.get(f"{base['rag']}/collections"); sent["rag"] += 1
        names = [x.get("name") for x in ((cl.json() if cl.status_code == 200 else {}).get("result") or {}).get("collections", [])]
        rec("data.rag_via_front_door", rz.status_code == 200 and "all shards are ready" in rz.text and cl.status_code == 200 and (not coll or coll in names),
            {"readyz": rz.status_code, "collections": names}, f"Qdrant ready and serving collections through the RAG virtual server{f' (incl. {coll})' if coll else ''}")
    except (httpx.HTTPError, ValueError) as e:
        rec("data.rag_via_front_door", False, {"url": base["rag"], "error": err(e)}, "RAG virtual server reachable")
    # ---- inference (Ollama) through the VIP — metadata only, no generation
    model = dd["llm"].get("model")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            vr = await c.get(f"{base['llm']}/api/version"); sent["llm"] += 1
            tg = await c.get(f"{base['llm']}/api/tags"); sent["llm"] += 1
        models = [m.get("name") for m in ((tg.json() if tg.status_code == 200 else {}).get("models") or [])]
        rec("data.llm_via_front_door", vr.status_code == 200 and "version" in (vr.json() or {}) and tg.status_code == 200 and (not model or model in models),
            {"version_status": vr.status_code, "models": models}, f"Ollama answers through the inference virtual server{f' and serves {model}' if model else ''}")
    except (httpx.HTTPError, ValueError) as e:
        rec("data.llm_via_front_door", False, {"url": base["llm"], "error": err(e)}, "inference virtual server reachable")
    # ---- BIG-IP's own counters moved by at least what this validation sent (proves the traffic traversed BIG-IP)
    if before is None:
        rec("data.bigip_statistics", False, {"error": "no deployer validation actions"}, "BIG-IP counters observed", skipped=True)
        return

    def evaluate(after):
        vs_b, vs_a = before.get("virtual_servers") or {}, after.get("virtual_servers") or {}
        # REQUEST accounting: the HTTP profile's numberReqs per virtual server must grow by at least the requests this check
        # sent (keep-alive can carry several requests on one connection, so connection counts are informational only).
        # Counters can only be inflated by other traffic, never deflated: a pass needs both these deltas AND the per-service
        # protocol checks above (the probe responses themselves came from the VIP addresses).
        reqs = {s: _stat_delta(vs_b.get(s), vs_a.get(s), "http.numberReqs") for s in DATA_SERVICES}
        conns = {s: _stat_delta(vs_b.get(s), vs_a.get(s), "clientside.totConns") for s in DATA_SERVICES}
        st_b, st_a = before.get("s3_statistics") or {}, after.get("s3_statistics") or {}
        s3d = {k: _stat_delta(st_b, st_a, k) for k in ("s3_requests", "s3_unsigned", "s3_resp_4xx")}
        missing = [f"{s}.http.numberReqs" for s in DATA_SERVICES if reqs[s] is None] + [f"stats_s3.{k}" for k, v in s3d.items() if v is None]
        ok = (not missing and all(reqs[s] >= sent[s] for s in DATA_SERVICES) and s3d["s3_requests"] >= sent["s3"]
              and s3d["s3_unsigned"] >= 1 and s3d["s3_resp_4xx"] >= 2 and "error" not in before and "error" not in after)
        return ok, {"sent_requests": sent, "virtual_server_http_requests": reqs, "virtual_server_connections_info": conns,
                    "s3_statistics_delta": s3d, "unreadable_counters": missing, "source": "BIG-IP iControl REST (read-only observer), live"}

    # BIG-IP's REST statistics trail the data plane by a few seconds (live 2026-10-19: the counters read immediately after
    # the probes showed only the earliest request). Re-read until the SAME criteria hold or the bounded settle time ends;
    # the criteria are never relaxed and a counter that never moves still fails.
    vd = (cfg.get("validation") or {}).get("data") or {}
    settle_s, poll_s = float(vd.get("stats_settle_s", 30)), float(vd.get("stats_poll_s", 2))
    t0, samples = time.monotonic(), 0
    while True:
        after = await status(); samples += 1
        ok, obs = evaluate(after or {"error": "no counters"})
        if ok or time.monotonic() - t0 >= settle_s:
            break
        await asyncio.sleep(poll_s)
    obs["settle"] = {"samples": samples, "seconds": round(time.monotonic() - t0, 1), "limit_s": settle_s}
    rec("data.bigip_statistics", ok, obs,
        "per-VIP HTTP request counters and the S3 statistics profile increase by at least the requests this validation sent")



SCORE_ARGS = {"amount": 950.0, "mcc": "4829", "country": "MX", "home_country": "US", "channel": "wire",
              "account_age_days": 400, "kyc_risk": "low", "recent_txn_count_24h": 1}
# delivery.load_distribution: 12 stateless calls, each on its own connection, in waves of LB_WAVE overlapping connections
LB_WAVE = 4
# MCP discovery through the configured front door: a read-only no-argument probe tool, and the tools the agents depend on
# (Agent B: services/agent_b/agent.py) that tools/list must advertise.
DISCOVERY = {
    "risk": ("model_info", frozenset({"score_transaction", "model_info"})),
    "intel": ("list_open_alerts", frozenset({"list_open_alerts", "get_alert", "get_account_profile", "get_recent_transactions",
                                            "search_fraud_patterns", "get_case_document"})),
}
PKI = os.environ.get("AUTOPILOT_PKI", "/opt/aplab/pki")
CA = f"{PKI}/ca.pem"
VALIDATOR = (f"{PKI}/ap-validator.pem", f"{PKI}/ap-validator.key")
UNAUTHORIZED = (f"{PKI}/ap-unauthorized.pem", f"{PKI}/ap-unauthorized.key")


def _replica(res) -> str | None:
    sc = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
    if isinstance(sc, dict):
        sc = sc.get("result", sc) if set(sc) == {"result"} else sc
        return sc.get("replica") if isinstance(sc, dict) else None     # list-typed tool results name no replica
    for c in getattr(res, "content", []):
        if getattr(c, "type", "") == "text":
            try:
                return json.loads(c.text).get("replica")
            except (ValueError, AttributeError):
                pass
    return None


def _tls_context(cert=None) -> ssl.SSLContext:
    """Create a verified TLS context and, when requested, load the mTLS identity.

    httpx2 does not allow a CA path in ``verify`` together with a ``cert`` tuple.
    Loading the client chain into the context preserves CA validation, hostname
    verification, and the validator identity without relying on that incompatible
    combination of arguments.
    """
    ctx = ssl.create_default_context(cafile=CA)
    if cert is not None:
        ctx.load_cert_chain(certfile=cert[0], keyfile=cert[1])
    return ctx


def _tls(url: str, cert=None) -> dict:
    if not url.startswith("https"):
        return {}
    return {"verify": _tls_context(cert)}


_SENSITIVE_EXCEPTION = re.compile(
    r"(?is)(-----BEGIN [^-]+-----.*?-----END [^-]+-----|(?:authorization|cookie|token|password|secret|private[_ -]?key)\s*[:=]\s*[^;\s]+)"
)


def _safe_exception_text(value: object) -> str:
    return _SENSITIVE_EXCEPTION.sub("[REDACTED]", str(value))[:1000]


def exception_chain(e: BaseException) -> list[dict[str, str]]:
    """Return the bounded complete exception chain without credentials or payloads."""
    out: list[dict[str, str]] = []
    seen: set[int] = set()

    def walk(x: BaseException) -> None:
        if id(x) in seen or len(out) >= 32:
            return
        seen.add(id(x))
        if isinstance(x, BaseExceptionGroup):
            for sub in x.exceptions:
                walk(sub)
            return
        out.append({"type": type(x).__name__, "message": _safe_exception_text(x)})
        if x.__cause__ is not None:
            walk(x.__cause__)
        elif x.__context__ is not None and not x.__suppress_context__:
            walk(x.__context__)

    walk(e)
    return out


def err(e: BaseException, limit: int = 300) -> str:
    """One line naming the actual cause. The MCP client runs inside anyio TaskGroups, so failures arrive wrapped in
    ExceptionGroups whose str() hides the cause ("unhandled errors in a TaskGroup"); report the leaf exceptions."""
    leaves = [f"{item['type']}: {item['message']}" for item in exception_chain(e)]
    return "; ".join(leaves)[:limit]


async def _tool(url: str, mode: str, n: int, cert=None, tool="score_transaction", args=None, concurrency: int = 1) -> list[str]:
    """n tools/call requests; returns the serving replica per call (None when the result names none).

    auto (stateless 2026-07-28): every call uses its own HTTP client, i.e. its own TCP connection, so every request is an
    independent load-balancing decision. A BIG-IP virtual server without OneConnect chooses the pool member once per
    client connection; reusing one keep-alive connection pins every call to one member and says nothing about load
    balancing (L3 gate 2026-10-15, doc 27). `concurrency` > 1 sends the calls in waves of overlapping connections, so a
    least-connections pool also spreads them when another client holds an idle connection to one member.
    legacy (2025-xx): one MCP session; the client keeps no idle connections, so the session's requests arrive on separate
    connections and stay on one replica only through Mcp-Session-Id persistence, not through connection reuse."""
    if args is None:
        args = SCORE_ARGS if tool == "score_transaction" else {}
    if mode == "legacy":
        out = []
        http = httpx2.AsyncClient(timeout=30, limits=httpx2.Limits(max_keepalive_connections=0), **_tls(url, cert))
        try:
            async with Client(streamable_http_client(url, http_client=http), mode="legacy") as c:
                for _ in range(n):
                    out.append(_replica(await c.call_tool(tool, args)))
        finally:
            await http.aclose()
        return out

    async def one():
        http = httpx2.AsyncClient(timeout=30, **_tls(url, cert))
        try:
            async with Client(streamable_http_client(url, http_client=http), mode="auto") as c:
                return _replica(await c.call_tool(tool, args))
        finally:
            await http.aclose()
    out = []
    for i in range(0, n, max(1, concurrency)):
        wave = await asyncio.gather(*(one() for _ in range(min(max(1, concurrency), n - i))), return_exceptions=True)
        failed = next((r for r in wave if isinstance(r, BaseException)), None)
        if failed is not None:
            raise failed
        out += wave
    return out


async def _raw_legacy(url: str, tool: str, headers: dict, cert=None) -> int:
    """One legacy-shaped (no Mcp-Protocol-Version) tools/call with extra, possibly forged, headers; returns the HTTP status
    (-1 on TLS/connection failure). Used to prove the AI Security policy inspects the body and ignores decoy headers."""
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {}}}
    try:
        async with httpx.AsyncClient(timeout=10, **_tls(url, cert)) as c:
            r = await c.post(url, json=body, headers={"Accept": "application/json, text/event-stream", **headers})
        return r.status_code
    except (httpx.HTTPError, ssl.SSLError, OSError):
        return -1


async def _discover(url: str, probe_tool: str, expected: frozenset, cert=None) -> dict:
    """MCP discovery: initialise, tools/list, and one read-only probe call — all on one connection."""
    http = httpx2.AsyncClient(timeout=30, **_tls(url, cert))
    try:
        async with Client(streamable_http_client(url, http_client=http), mode="auto") as c:
            tools = sorted(t.name for t in (await c.list_tools()).tools)
            res = await c.call_tool(probe_tool, {})
            info = c.server_info
            return {"server_name": getattr(info, "name", None), "protocol_version": c.protocol_version, "tools": tools,
                    "missing_tools": sorted(expected - set(tools)), "probe": probe_tool, "probe_ok": not res.is_error, "error": None}
    finally:
        await http.aclose()


async def _raw_mcp(url: str, tool: str, cert=None) -> int:
    return (await _raw_mcp_result(url, tool, cert))['status']


async def _raw_mcp_result(url: str, tool: str, cert=None) -> dict:
    """Return status and transport evidence separately; -1 is never treated as an HTTP policy response."""
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {}, "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": {"name": "ap-validator", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {}}}}
    try:
        async with httpx.AsyncClient(timeout=10, **_tls(url, cert)) as c:
            r = await c.post(url, json=body, headers={"Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2026-07-28",
                                                      "Mcp-Method": "tools/call", "Mcp-Name": tool})
        return {"status": r.status_code, "transport_error": None}
    except (httpx.HTTPError, ssl.SSLError, OSError) as exc:
        return {"status": -1, "transport_error": err(exc), "transport_error_chain": exception_chain(exc)}


async def _rate_limit_probe(url: str, cert, total: int, concurrency: int = 4, *, fresh_window: bool = False) -> list[dict]:
    """Probe the fixed-window policy without conflating client pressure with HTTP 429.

    A fresh calendar-minute key is required when the same identity has already made
    validation requests.  The Security gate uses one sequential request per wave for
    this final proof so connection resets cannot be mistaken for policy responses.
    """
    if fresh_window:
        await asyncio.sleep(60 - (time.time() % 60) + 0.05)
    out = []

    async def one(sequence: int) -> dict:
        timestamp = time.time()
        result = dict(await _raw_mcp_result(url, "model_info", cert))
        status = result.get("status", -1)
        result.update(sequence=sequence, timestamp=timestamp, client_identity="ap-validator",
                      calendar_minute=int(timestamp // 60),
                      outcome=f"http_{status}" if status != -1 else "transport_error")
        return result

    for start in range(0, total, max(1, concurrency)):
        count = min(max(1, concurrency), total - start)
        wave = await asyncio.gather(*(one(start + offset + 1) for offset in range(count)))
        out.extend(wave)
    return out


def _rate_limit_verdict(samples: list[dict], limit: int) -> tuple[bool, dict]:
    """Return a rate-limit verdict, making calendar-window crossings inconclusive."""
    counts = collections.Counter(x.get("status", -1) for x in samples)
    transport = [x.get("transport_error") for x in samples if x.get("status") == -1]
    minutes = sorted({x.get("calendar_minute") for x in samples})
    crossed = len(minutes) != 1
    detail = {"burst": len(samples), "responses": dict(counts), "requests": samples,
              "transport_errors": transport, "calendar_minute_keys": minutes,
              "calendar_minute_crossed": crossed, "concurrency": 1,
              "client_certificate": "ap-validator", "protocol": "MCP 2026-07-28 over HTTPS"}
    return bool(counts.get(429)) and not transport and not crossed, detail


def discovery_ok(p: dict | None) -> bool:
    """MCP discovery verdict for the front-door branch: tools/list advertises every expected tool and the probe call succeeded."""
    return bool(p) and not p.get("error") and not p.get("missing_tools") and bool(p.get("probe_ok"))


def distribution_ok(reps: list, expect_lb: bool) -> bool:
    """Every request named its replica, and >= 2 replicas served them exactly when load balancing is expected."""
    return bool(reps) and None not in reps and (len(set(reps)) >= 2) == expect_lb


async def run(cfg: dict, profile: str, actions: Callable[[dict], Awaitable[dict]] | None = None,
              on_result: Callable[[dict], None] | None = None) -> list[dict]:
    exp = PROFILES[profile]
    out: list[dict] = []

    def rec(test, ok, observed, expectation, skipped=False):
        out.append({"test": test, "result": "skipped" if skipped else ("pass" if ok else "fail"), "observed": observed, "expected": expectation})
        if on_result:
            on_result(out[-1])

    va = cfg["validation"]["agent_a_api"]
    b_health = cfg["validation"].get("agent_b_health", "http://10.50.10.22:9000/healthz")
    pre = {}
    for name, url in (("agent_a_api", f"{va}/healthz"), ("agent_b_api", b_health)):
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(url)
            r.raise_for_status()
            pre[name] = r.json()
        except (httpx.HTTPError, ValueError) as e:
            rec(f"precondition.{name}", False, {"url": url, "error": err(e)}, f"{name} answers /healthz (agent running and listening)")
    if len(pre) < 2:
        rec("precondition.summary", False, {"not_run": "A2A, MCP, delivery and security tests"},
            "all tests require both agents to be reachable; fix the precondition and re-run")
        return out
    a, bh = pre["agent_a_api"], pre["agent_b_api"]
    b_url = a["agent_b_url"]
    front = urlsplit(b_url).hostname
    try:
        front_ip = socket.gethostbyname(front)
    except OSError:
        front_ip = None
    vips = {cfg["design"]["a2a_vip"], *cfg["design"]["mcp_vips"]}
    # ---------------- A2A
    card_url = f"{b_url.rstrip('/')}/.well-known/agent-card.json"
    try:
        async with httpx.AsyncClient(timeout=30, verify=CA if b_url.startswith("https") else True) as c:
            r = await c.get(card_url)
        status, card = r.status_code, (r.json() if r.status_code == 200 else {})
    except (httpx.HTTPError, ValueError, ssl.SSLError) as e:
        status, card = err(e), {}
    adv = [i.get("url") for i in card.get("supportedInterfaces", [])]
    rec("a2a.agent_card", status == 200 and bool(card.get("skills")), {"url": card_url, "status": status, "advertised": adv}, "valid A2A 1.0 Agent Card")
    rec("a2a.via_front_door", (front_ip in vips) == exp["via_bigip"], {"agent_b_url": b_url, "resolves_to": front_ip},
        "Agent A -> BIG-IP A2A virtual server" if exp["via_bigip"] else "direct (baseline)")
    if exp["via_bigip"]:
        rec("a2a.card_advertises_front_door", all(urlsplit(u or "").hostname == front for u in adv),
            {"front_door": front, "advertised_hosts": [urlsplit(u or "").hostname for u in adv]}, "card URL = BIG-IP front door")
    else:
        rec("a2a.card_advertises_front_door", True, {"advertised_hosts": [urlsplit(u or "").hostname for u in adv]}, "informational in baseline")
    t0 = time.time()
    try:
        async with httpx.AsyncClient(timeout=600) as c:
            inv = (await c.post(f"{va}/api/investigate", json={"alert_id": "ALERT-9002"})).json()
    except (httpx.HTTPError, ValueError) as e:
        inv = {"state": "error", "error": err(e)}
    inv["_seconds"] = round(time.time() - t0, 1)
    working = sum(1 for u in inv.get("updates", []) if "TASK_STATE_WORKING" in str(u))
    rec("a2a.task_roundtrip", inv.get("state") == "completed" and bool(inv.get("result")),
        {"state": inv.get("state"), "decision": ((inv.get("result") or {}).get("assessment") or {}).get("decision"),
         "replicas": (inv.get("result") or {}).get("replicas_used"), "seconds": round(time.time() - t0, 1), "error": inv.get("error")},
        "task completed with artifact")
    rec("a2a.streaming", working >= 2, {"status_updates": len(inv.get("updates", [])), "working_updates": working}, ">= 2 streamed WORKING updates")
    # ---------------- MCP
    risk_url, intel_url = bh.get("mcp_risk_url"), bh.get("mcp_intel_url")
    cert = VALIDATOR if exp["security"] else None
    rec("mcp.via_front_door", (urlsplit(risk_url).hostname not in ("10.50.20.31", "10.50.20.32")) == exp["via_bigip"],
        {"agent_b_mcp_risk_url": risk_url, "agent_b_mcp_intel_url": intel_url}, "Agent B -> BIG-IP MCP virtual servers" if exp["via_bigip"] else "direct (baseline)")
    if not exp["security"]:
        for name, url in (("risk", risk_url), ("intel", intel_url)):
            if url.startswith("https"):
                try:
                    p = await _discover(url, *DISCOVERY[name])
                    ok = discovery_ok(p)
                except BaseException as e:
                    p, ok = {"error": err(e)}, False
            else:
                p = await mcp_probe(url)
                ok = bool(p and p.get("tools"))
            rec(f"mcp.discovery.{name}", ok,
                {"url": url, "tools": p and p.get("tools"),
                 "result": p and {k: p.get(k) for k in ("server_name", "protocol_version", "error", "probe", "probe_ok", "missing_tools")}},
                "MCP discovery via configured front door: initialise, tools/list advertises the tools the agents use, read-only probe call succeeds")
    reps: list = []
    try:
        reps = await _tool(risk_url, "auto", 12, cert=cert, concurrency=LB_WAVE)
        rec("mcp.tool_execution", len(reps) == 12, {"calls": len(reps), "connections": "one per call"}, "12/12 score_transaction calls succeed")
    except BaseException as e:
        rec("mcp.tool_execution", False, {"error": err(e)}, "12/12 calls succeed")
    # ---------------- performance (informational; same workload in every profile -> comparable before/after)
    lat = []
    try:
        for _ in range(10):
            t1 = time.time()
            await _tool(risk_url, "auto", 1, cert=cert)
            lat.append(round((time.time() - t1) * 1000, 1))
        ls = latency_summary(lat)
        rec("perf.mcp_tool_latency", True, {"calls": len(lat), "p50_ms": ls["p50"], "p95_ms": ls["p95"], "p95_reliable": ls["p95_reliable"],
                                            "max_ms": ls["max"], "metric": "MCP tools/call round trip (client-measured, sequential)", "path": "via BIG-IP" if exp["via_bigip"] else "direct"},
            "10 sequential score_transaction calls measured (informational)")
    except BaseException as e:
        rec("perf.mcp_tool_latency", False, {"completed": len(lat), "error": err(e)}, "10 sequential calls measured")
    rec("perf.a2a_investigation", inv.get("state") == "completed", {"task_seconds": inv.get("_seconds"),
                                                                    "path": "via BIG-IP" if exp["via_bigip"] else "direct"},
        "A2A investigation duration measured (informational)")
    dist = dict(collections.Counter(reps))
    rec("delivery.load_distribution", distribution_ok(reps, exp["lb"]),
        {"replicas": dist, "requests": len(reps), "independent_connections": len(reps),
         "method": f"stateless tools/call, one TCP connection per request, waves of {LB_WAVE} concurrent"},
        ">= 2 replicas serve 12 independent stateless requests (one connection each)" if exp["lb"] else "single replica (no load balancing) in baseline")
    try:
        sess = await _tool(risk_url, "legacy", 6, cert=cert)
        rec("delivery.session_persistence", bool(sess) and None not in sess and len(set(sess)) == 1,
            {"replicas_in_session": dict(collections.Counter(sess)), "connections": "no idle-connection reuse (Mcp-Session-Id persistence)"},
            "all calls in one MCP session served by one replica")
    except BaseException as e:
        rec("delivery.session_persistence", False, {"error": err(e)}, "session completes on one replica")
    # ---------------- failover + health monitor (BIG-IP must mark the stopped replica down; service continues)
    if exp["via_bigip"]:
        if actions is None:
            rec("delivery.failover", False, {}, "requires deployer validation actions", skipped=True)
        else:
            obs = {}

            def down(p):
                return any("offline" in str(m).lower() or "down" in str(m).lower() for m in p.get("members", []))

            async def poll(pred, limit=45):
                t = time.time()
                while True:
                    p = await actions({"action": "pool_status"})
                    if pred(p) or time.time() - t > limit:
                        return p, round(time.time() - t, 1)
                    await asyncio.sleep(3)
            ok = False
            try:
                obs["stop"] = await actions({"action": "replica", "op": "stop", "n": 1})
                obs["pool_after_stop"], obs["seconds_until_marked_down"] = await poll(down)   # monitor: interval 5 s, timeout 16 s
                fo = await _tool(risk_url, "auto", 6, cert=cert)
                obs["replicas_during_outage"] = dict(collections.Counter(fo))
                ok = set(fo) == {"risk-scoring-2"} and down(obs["pool_after_stop"])
            except BaseException as e:
                obs["error"] = err(e)
            finally:
                try:
                    obs["start"] = await actions({"action": "replica", "op": "start", "n": 1})
                    obs["pool_after_restore"], obs["seconds_until_restored"] = await poll(lambda p: p.get("members") and not down(p))
                    restored = not down(obs["pool_after_restore"])
                except BaseException as e:
                    obs["restore_error"], restored = err(e), False
            rec("delivery.failover", ok and restored, obs, "monitor marks replica 1 down; all traffic served by replica 2; replica 1 restored and marked up")
    # ---------------- security
    if exp["security"]:
        risk_vip = risk_url
        intel_vip = intel_url
        rec("security.authorized_tool_allowed", (await _raw_mcp(risk_vip, "model_info", VALIDATOR)) == 200,
            {"identity": "ap-validator", "tool": "model_info"}, "allowed identity + allowed tool -> 200")
        code = await _raw_mcp(intel_vip, "freeze_account", VALIDATOR)
        rec("security.unauthorized_tool_denied", code == 403, {"identity": "ap-validator", "tool": "freeze_account", "http": code}, "403")
        code = await _raw_mcp(risk_vip, "model_info", None)
        rec("security.unauthenticated_rejected", code in (-1, 401, 403), {"client_certificate": None, "http_or_tls": code}, "TLS reject or 401")
        unknown = await _raw_mcp_result(risk_vip, "model_info", UNAUTHORIZED)
        rec("security.unknown_identity_denied", unknown["status"] == 403,
            {"identity": "ap-unauthorized", "http": unknown["status"], "transport_error": unknown["transport_error"],
             "transport_error_chain": unknown.get("transport_error_chain", []),
             "interpretation": "HTTP policy denial" if unknown["status"] == 403 else "TLS/transport failure" if unknown["status"] == -1 else "HTTP response"},
            "403 after successful mTLS handshake; transport failure is not policy evidence")
        # B1 (doc 34): a legacy request may not skip body inspection with forged Mcp-Method / Mcp-Name headers
        decoy = {"forged Mcp-Method tools/list": await _raw_legacy(intel_vip, "freeze_account", {"Mcp-Method": "tools/list"}, VALIDATOR),
                 "forged Mcp-Name model_info": await _raw_legacy(intel_vip, "freeze_account",
                                                                 {"Mcp-Method": "tools/call", "Mcp-Name": "model_info"}, VALIDATOR)}
        rec("security.decoy_header_denied", all(c == 403 for c in decoy.values()), {"identity": "ap-validator", "tool": "freeze_account", "http": decoy},
            "legacy tools/call with forged headers -> 403 from the policy (body inspected, headers not trusted)")
    # ---------------- direct backend (bypass)
    direct = {}
    async with httpx.AsyncClient(timeout=3) as c:
        for ep in ("10.50.20.31:8000", "10.50.20.32:8000", "10.50.20.33:8000"):
            try:
                direct[ep] = (await c.get(f"http://{ep}/healthz")).status_code
            except httpx.HTTPError as e:
                direct[ep] = type(e).__name__
    reachable = [k for k, v in direct.items() if v == 200]
    rec("security.direct_backend_blocked", (not reachable) == exp["lockdown"], {"from": "10.50.20.5 (non-BIG-IP)", "results": direct},
        "direct access blocked" if exp["lockdown"] else "direct access open (baseline bypass present)")
    if actions is not None:
        try:
            p = await actions({"action": "probe_agent_b_direct"})
        except BaseException as e:
            p = {"error": err(e), "http_code": "error"}
        blocked = p.get("http_code") in ("000", "", None)
        rec("security.agent_b_direct_blocked", blocked == exp["lockdown"], p, "Agent B cannot reach MCP backend directly" if exp["lockdown"] else "baseline: open")
    # ---------------- trace propagation
    await asyncio.sleep(6)
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            tr = (await c.get(f"{cfg['ingest']['jaeger_url']}/api/traces/{inv.get('trace_id')}")).json().get("data") or [{}]
    except (httpx.HTTPError, ValueError):
        tr = [{}]
    svcs = sorted({p["serviceName"] for p in (tr[0].get("processes") or {}).values()})
    need = {"agent-a-fraud-investigation", "agent-b-risk-assessment", "mcp-risk-scoring", "mcp-fraud-intel"}
    rec("otel.trace_propagation", need <= set(svcs), {"trace_id": inv.get("trace_id"), "services": svcs}, "one trace across agent-a, agent-b, both MCP services")
    # ---------------- AI Data Delivery front doors (after-data only; before the rate-limit test, which must stay last)
    if exp.get("data"):
        await data_checks(cfg, actions, rec)
    # ---------------- rate limit LAST (consumes the identity's window)
    if exp["security"]:
        limit = cfg["design"]["rate_limit_per_min"]
        samples = await _rate_limit_probe(risk_url, VALIDATOR, limit + 1, concurrency=1, fresh_window=True)
        ok, detail = _rate_limit_verdict(samples, limit)
        rec("security.rate_limited", ok, detail,
            f"HTTP 429 after {limit} successful requests/min per identity; transport errors or a crossed calendar window are inconclusive")
    return out
