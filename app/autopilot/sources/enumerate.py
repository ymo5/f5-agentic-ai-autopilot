"""ENUMERATE — approved infrastructure inventory, DNS zone transfer, and in-scope protocol fingerprinting.

Only addresses inside the approved scope (config `enumerate.scope_cidrs` + `enumerate.approved_hosts`) are
ever contacted, with bounded concurrency and timeouts. Fingerprints use the real protocols:
  A2A  -> GET /.well-known/agent-card.json (A2A 1.0 Agent Card)
  MCP  -> MCP initialize + tools/list with the official SDK client (no credentials presented)
  Qdrant, S3, OpenAI-compatible/Ollama LLM, OTLP/HTTP collector, DNS
"""
from __future__ import annotations

import asyncio
import ipaddress
import json

import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone
import httpx

from ..mcpclient import mcp_probe

PROBE_PORTS = [53, 443, 4318, 6333, 8000, 8080, 8333, 9000, 11434]


async def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        w.close()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def _fingerprint(http: httpx.AsyncClient, ip: str, port: int) -> dict | None:
    base = f"http://{ip}:{port}"
    if port == 53:
        try:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers, r.lifetime = [ip], 2
            r.resolve("localhost.", "A", raise_on_no_answer=False)
            return {"protocol": "dns", "kind": "dns_server"}
        except Exception:
            return {"protocol": "tcp", "kind": "unknown"}
    try:
        r = await http.get(f"{base}/.well-known/agent-card.json")
        if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
            card = r.json()
            if "skills" in card and ("supportedInterfaces" in card or "url" in card):
                ifaces = card.get("supportedInterfaces") or [{"url": card.get("url"), "protocolBinding": "JSONRPC"}]
                return {"protocol": "a2a", "kind": "a2a_agent", "name": card.get("name"),
                        "agent_card": {"name": card.get("name"), "version": card.get("version"),
                                       "advertised_urls": [i.get("url") for i in ifaces],
                                       "bindings": [i.get("protocolBinding") for i in ifaces],
                                       "protocol_versions": [i.get("protocolVersion") for i in ifaces],
                                       "skills": [s.get("id") for s in card.get("skills", [])],
                                       "streaming": (card.get("capabilities") or {}).get("streaming", False),
                                       "security_schemes": list((card.get("securitySchemes") or {}).keys())}}
    except (httpx.HTTPError, ValueError):
        pass
    mcp = await mcp_probe(f"{base}/mcp")
    if mcp:
        return {"protocol": "mcp", "kind": "mcp_server", "name": mcp["server_name"], "mcp": mcp}
    try:
        r = await http.get(f"{base}/collections")
        if r.status_code == 200 and "collections" in r.text and r.json().get("status") == "ok":
            root = (await http.get(f"{base}/")).json()
            return {"protocol": "http", "kind": "vector_db", "name": "qdrant",
                    "vector_db": {"product": "qdrant", "version": root.get("version"), "unauthenticated_read": True,
                                  "collections": [c["name"] for c in r.json()["result"]["collections"]]}}
        if r.status_code in (401, 403) and "qdrant" in r.text.lower():
            return {"protocol": "http", "kind": "vector_db", "name": "qdrant", "vector_db": {"unauthenticated_read": False}}
    except (httpx.HTTPError, ValueError, KeyError):
        pass
    try:
        r = await http.get(f"{base}/")
        if ("<Error>" in r.text and ("AccessDenied" in r.text or "NoSuchBucket" in r.text)) or "ListAllMyBucketsResult" in r.text:
            return {"protocol": "http", "kind": "object_store", "name": "s3",
                    "s3": {"anonymous_list": "ListAllMyBucketsResult" in r.text, "server": r.headers.get("server")}}
    except httpx.HTTPError:
        pass
    for path in ("/api/tags", "/v1/models"):
        try:
            r = await http.get(f"{base}{path}")
            if r.status_code == 200:
                d = r.json()
                models = [m.get("name") or m.get("id") for m in (d.get("models") or d.get("data") or [])]
                if models:
                    return {"protocol": "http", "kind": "llm_endpoint", "name": f"llm@{ip}",
                            "llm": {"api": "ollama" if path == "/api/tags" else "openai", "models": models,
                                    "unauthenticated": True}}
        except (httpx.HTTPError, ValueError):
            pass
    try:
        r = await http.post(f"{base}/v1/traces", content=b"", headers={"content-type": "application/x-protobuf"})
        if r.status_code in (200, 400) and port in (4318, 55681):
            return {"protocol": "otlp-http", "kind": "otel_collector", "name": f"otel@{ip}"}
    except httpx.HTTPError:
        pass
    return {"protocol": "tcp", "kind": "unknown"}


async def scan(scope_cidrs: list[str], approved_hosts: list[str], ports: list[int] | None = None,
               concurrency: int = 128, timeout: float = 0.6) -> list[dict]:
    targets = {str(h) for c in scope_cidrs for h in ipaddress.ip_network(c).hosts()} | set(approved_hosts)
    sem = asyncio.Semaphore(concurrency)
    ports = ports or PROBE_PORTS

    async def one(ip: str, port: int):
        async with sem:
            return (ip, port) if await _tcp_open(ip, port, timeout) else None

    open_ = [x for x in await asyncio.gather(*(one(ip, p) for ip in sorted(targets) for p in ports)) if x]
    out = []
    async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as http:
        fp_sem = asyncio.Semaphore(16)

        async def fp(ip, port):
            async with fp_sem:
                return {"ip": ip, "port": port, **(await _fingerprint(http, ip, port) or {})}

        out = await asyncio.gather(*(fp(ip, p) for ip, p in open_))
    return sorted(out, key=lambda r: (ipaddress.ip_address(r["ip"]), r["port"]))


def zone_transfer(server: str, zone: str) -> list[dict]:
    z = dns.zone.from_xfr(dns.query.xfr(server, zone, lifetime=5))
    recs = []
    for name, node in z.nodes.items():
        for rds in node.rdatasets:
            for rd in rds:
                recs.append({"name": f"{name}.{zone}".replace("@.", ""), "type": dns.rdatatype.to_text(rds.rdtype),
                             "value": rd.to_text()})
    return recs


def in_scope(ip: str, scope_cidrs: list[str], approved_hosts: list[str]) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return ip in approved_hosts or any(a in ipaddress.ip_network(c) for c in scope_cidrs)


def dumps(x) -> str:
    return json.dumps(x, default=str)
