"""Post-change convergence barrier: wait until the lab has actually reached the state a step produced, *before*
any validation runs. Root cause of the first Part B rehearsal failure (2026-10-13): `ap-dep-apply profile` recreates the
agent containers and returns in < 1 s; the validation gate connected to Agent A's API ~0.1 s later, before uvicorn was
listening (connection refused -> httpx "All connection attempts failed"). DNS (CoreDNS `reload 10s`, record TTL 60 s),
BIG-IP health monitors and the agents' new configuration all converge on their own clocks.

The barrier polls read-only probes until every check passes or the bounded timeout expires. It never repeats an
infrastructure write and never relaxes a validation; on timeout it raises ConvergenceTimeout with the exact checks that
did not converge and their last observed values (the engine then performs its normal automatic rollback).

Checks for a target host profile (expectations come from `design.profiles` in autopilot.yaml):
  agent.<name>       /healthz answers 200 and reports the profile's configured URLs
  card.advertises    Agent Card advertises the expected host (front door after delivery, direct in baseline)
  dns.<name>         the authoritative lab DNS server answers with the profile's addresses
  dns.cache_hold     resolver caches may still hold the previous answer: wait the record TTL after the change
  bigip.pools        (tenant present) every AP_AI pool member is 'available'
  vip.<name>         (tenant present) TLS to the VIP verifies against the lab CA and a protocol request succeeds
"""
from __future__ import annotations

import asyncio
import json
import ssl
import time
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx

MCP_DISCOVER = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": {"name": "ap-converge", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {}}}}, separators=(",", ":"))


class ConvergenceTimeout(Exception):
    def __init__(self, message: str, report: dict):
        super().__init__(message)
        self.report = report


def spec_for(cfg: dict, profile: str, tenant_present: bool, mtls: bool = False) -> dict:
    """Build the convergence spec for a host profile from autopilot.yaml (no hard-coded lab values here)."""
    d, c = cfg["design"], cfg.get("convergence") or {}
    prof = d["profiles"][profile]
    vips = []
    if tenant_present:
        fd = d["front_doors"]
        vips.append({"name": fd["a2a"]["name"], "address": fd["a2a"]["vip"], "probe": "a2a_card", "mtls": False})
        for m in fd["mcp"].values():
            vips.append({"name": m["name"], "address": m["vip"], "probe": "mcp_discover", "mtls": mtls})
    return {"profile": profile, "timeout_s": float(c.get("timeout_s", 180)), "poll_s": float(c.get("poll_s", 2)),
            "dns_server": c.get("dns_server"), "dns": dict(prof.get("dns") or {}), "dns_cache_hold_max_s": float(c.get("dns_cache_hold_max_s", 120)),
            "agents": prof.get("agents") or {}, "card": prof.get("card"), "pools": tenant_present, "vips": vips,
            "vip_retry_s": float(c.get("vip_retry_s", 15))}


class Probes:
    """Real read-only probes. Tests substitute an object with the same async methods."""

    def __init__(self, bigip=None, tenant: str = "AP_AI", ca: str | None = None, client_cert: tuple | None = None):
        self.bigip, self.tenant, self.ca, self.client_cert = bigip, tenant, ca, client_cert

    async def http_json(self, url: str) -> tuple[int, Any]:
        async with httpx.AsyncClient(timeout=3) as c:
            r = await c.get(url)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, None

    async def dns(self, server: str, name: str) -> tuple[list[str], int]:
        import dns.asyncquery
        import dns.message
        import dns.rdatatype
        q = dns.message.make_query(name, "A")
        r = await dns.asyncquery.udp(q, server, timeout=2)
        ips, ttl = [], 0
        for rr in r.answer:
            if rr.rdtype == dns.rdatatype.A:
                ips += [x.address for x in rr]
                ttl = max(ttl, rr.ttl)
        return sorted(ips), ttl

    async def pool_members(self) -> list[dict]:
        code, pools = await self.bigip.get(f"/mgmt/tm/ltm/pool?$filter=partition+eq+{self.tenant}")
        out = []
        for p in (pools or {}).get("items", []) if code == 200 else []:
            _, st = await self.bigip.get(f"/mgmt/tm/ltm/pool/{p['fullPath'].replace('/', '~')}/members/stats")
            for e in (st or {}).get("entries", {}).values():
                x = e["nestedStats"]["entries"]
                out.append({"pool": p["fullPath"], "member": f"{x.get('addr', {}).get('description')}:{x.get('port', {}).get('value')}",
                            "availability": x.get("status.availabilityState", {}).get("description"),
                            "enabled": x.get("status.enabledState", {}).get("description")})
        return out

    async def vip(self, address: str, name: str, probe: str, mtls: bool) -> tuple[bool, str]:
        ctx = ssl.create_default_context(cafile=self.ca) if self.ca else ssl.create_default_context()
        if mtls and self.client_cert:
            ctx.load_cert_chain(*self.client_cert)
        kw: dict = {"verify": ctx, "timeout": 5}
        ext = {"sni_hostname": name}
        try:
            async with httpx.AsyncClient(**kw) as c:
                if probe == "a2a_card":
                    r = await c.get(f"https://{address}/.well-known/agent-card.json", headers={"Host": name}, extensions=ext)
                    ok = r.status_code == 200 and "skills" in r.text
                else:
                    r = await c.post(f"https://{address}/mcp", content=MCP_DISCOVER, extensions=ext,
                                     headers={"Host": name, "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                                              "Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"})
                    ok = r.status_code == 200 and "capabilities" in r.text
            return ok, f"HTTP {r.status_code}"
        except (httpx.HTTPError, ssl.SSLError, OSError) as e:
            return False, f"{type(e).__name__}: {e}"[:160]


async def _check_once(spec: dict, probes, changed_at: float, now: float, state: dict) -> dict[str, dict]:
    res: dict[str, dict] = {}

    async def guard(name, fn):
        try:
            res[name] = await fn()
        except Exception as e:  # a probe error is a not-yet-converged observation, never a pass
            res[name] = {"ok": False, "observed": f"{type(e).__name__}: {e}"[:200]}

    for agent, a in spec["agents"].items():
        async def f(a=a):
            code, body = await probes.http_json(a["healthz"])
            if code != 200 or not isinstance(body, dict):
                return {"ok": False, "observed": f"HTTP {code}"}
            wrong = {k: body.get(k) for k, v in (a.get("expect") or {}).items() if str(body.get(k) or "").rstrip("/") != str(v).rstrip("/")}
            return {"ok": not wrong, "observed": wrong or "configured as expected"}
        await guard(f"agent.{agent}", f)
    if spec.get("card"):
        async def card():
            code, body = await probes.http_json(spec["card"]["url"])
            hosts = [urlsplit(i.get("url") or "").hostname for i in (body or {}).get("supportedInterfaces", [])] if code == 200 else []
            return {"ok": bool(hosts) and all(h == spec["card"]["advertises_host"] for h in hosts), "observed": hosts or f"HTTP {code}"}
        await guard("card.advertises", card)
    ttl_seen = 0
    for name, want in spec["dns"].items():
        async def dq(name=name, want=want):
            nonlocal ttl_seen
            ips, ttl = await probes.dns(spec["dns_server"], name)
            ttl_seen = max(ttl_seen, ttl)
            return {"ok": ips == [want], "observed": ips}
        await guard(f"dns.{name}", dq)
    if spec["dns"]:
        hold = min(max(ttl_seen, state.get("ttl", 0)), spec["dns_cache_hold_max_s"])
        state["ttl"] = hold
        left = changed_at + hold - now
        res["dns.cache_hold"] = {"ok": left <= 0, "observed": f"{max(0, round(left))} s until previously cached answers (TTL {round(hold)} s) expire"}
    if spec["pools"]:
        async def pools():
            m = await probes.pool_members()
            bad = [x for x in m if x["availability"] != "available"]
            return {"ok": bool(m) and not bad, "observed": {"members": len(m), "not_available": bad}}
        await guard("bigip.pools", pools)
    # VIP probes go through the BIG-IP virtual servers; under AI Security the MCP ones present the validator identity and
    # count against its per-minute rate limit (doc 34, finding B2). So they are spent only when they can prove something:
    # deferred until agents, DNS (incl. cache hold) and pool members have converged in this attempt, not repeated once
    # passed, and retried at most every `vip_retry_s` after a failure. A VIP still has to pass while everything else has.
    others_ok = all(r["ok"] for r in res.values())
    passed, last = state.setdefault("vip_passed", {}), state.setdefault("vip_last_probe", {})
    if not others_ok:
        passed.clear()                                  # something regressed: VIPs are re-proven after re-convergence
    for v in spec["vips"]:
        key = f"vip.{v['name']}"
        if key in passed:
            res[key] = {"ok": True, "observed": passed[key] + " (passed; not re-probed)"}
            continue
        if not others_ok:
            res[key] = {"ok": False, "observed": "deferred until agents, DNS and pool members have converged (saves rate-limited probes)"}
            continue
        if now - last.get(key, float("-inf")) < spec.get("vip_retry_s", 15):
            res[key] = {"ok": False, "observed": state.get("vip_detail", {}).get(key, "not yet probed") + f" — next probe within {spec.get('vip_retry_s', 15):g} s"}
            continue

        async def vp(v=v):
            ok, detail = await probes.vip(v["address"], v["name"], v["probe"], v.get("mtls", False))
            return {"ok": ok, "observed": f"{v['name']} -> {v['address']}:443 {detail}"}
        last[key] = now
        await guard(key, vp)
        state.setdefault("vip_detail", {})[key] = res[key]["observed"]
        if res[key]["ok"]:
            passed[key] = res[key]["observed"]
    return res


async def wait(spec: dict, probes, changed_at: float | None = None, clock: Callable[[], float] = time.time,
               sleep: Callable[[float], Awaitable] = asyncio.sleep) -> dict:
    """Poll until all checks pass (returns a report) or raise ConvergenceTimeout(report)."""
    t0 = clock()
    changed_at = t0 if changed_at is None else changed_at
    first_ok: dict[str, float] = {}
    state: dict = {}
    attempts = 0
    while True:
        attempts += 1
        now = clock()
        res = await _check_once(spec, probes, changed_at, now, state)
        for k, r in res.items():
            if r["ok"]:
                first_ok.setdefault(k, round(now - t0, 1))
            else:
                first_ok.pop(k, None)
        report = {"profile": spec["profile"], "attempts": attempts, "elapsed_s": round(now - t0, 1),
                  "checks": {k: {**r, "converged_after_s": first_ok.get(k)} for k, r in res.items()}}
        if all(r["ok"] for r in res.values()):
            return report
        if now - t0 >= spec["timeout_s"]:
            pending = {k: r["observed"] for k, r in res.items() if not r["ok"]}
            raise ConvergenceTimeout(f"environment did not converge to profile '{spec['profile']}' within {int(spec['timeout_s'])} s; "
                                     f"not converged: {json.dumps(pending, default=str)[:600]}", report)
        await sleep(spec["poll_s"])
