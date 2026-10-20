"""INGEST — correlate OpenTelemetry traces (Jaeger query API) into communication paths.

Two passes over the observed spans (never configuration):
  1. Roles: a service is an A2A server only if it served a 200 Agent Card or executed A2A tasks; an MCP
     server only if it produced MCP spans (mcp.method.name). Each service instance's listen address is
     learned from its inbound HTTP spans (http.host / server.address).
  2. Edges: inbound HTTP spans give caller -> endpoint with the *actual peer address* (direct vs BIG-IP);
     MCP server spans (parented to the client via MCP `_meta`) add tools + protocol versions to the same edge;
     client spans to uninstrumented endpoints (Qdrant, S3, LLM) add the remaining dependencies.
The discovery system's own traffic (configured services / sensor addresses) is excluded.
Identity reconciliation: callers without trace context are keyed by their network peer address (`client@<ip>`), never
by a DNS label, so the same peer can never appear under two names. Such an edge is attributed to an instrumented
service only when evidence proves it: the service's traced spans arrive from that same address AND the service has a
traced edge to the same target over the same protocol. Anything else stays an explicitly unattributed peer.
"""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

import httpx

from ..stats import latency_summary


def _tags(span: dict) -> dict:
    return {t["key"]: t["value"] for t in span.get("tags", [])}


def _hostport(value: str | None) -> tuple[str, int] | None:
    if not value:
        return None
    if "://" in value:
        u = urlsplit(value)
        if not u.hostname:
            return None
        return u.hostname, u.port or (443 if u.scheme == "https" else 80)
    host, _, port = value.rpartition(":")
    if host and port.isdigit():
        return host, int(port)
    return None


async def fetch_traces(jaeger_url: str, lookback: str = "2h", limit: int = 400, since: float | None = None,
                       stats: dict | None = None, now: float | None = None) -> list[dict]:
    """Traces that STARTED inside [since, now] — or inside the last `lookback` when `since` is not given.

    The window is always sent as explicit start/end: the Jaeger query API ignores a `lookback` parameter (that is a UI setting),
    so a "last 3h" query used to return the whole retention (doc 38). Traces that began before the window (a span inside it can
    match the search) are dropped as well. `stats` (optional) receives the effective window and the services whose search hit
    `limit`, i.e. where older traces inside the window may be missing."""
    import time as _t
    end = _t.time() if now is None else now
    start = since if since else end - _seconds(lookback)
    if stats is not None:
        stats.update(start=start, end=end, truncated_services=[], dropped_before_window=0)
    async with httpx.AsyncClient(timeout=20) as c:
        services = (await c.get(f"{jaeger_url}/api/services")).json().get("data") or []
        traces: dict[str, dict] = {}
        for svc in services:
            if svc.startswith("jaeger"):
                continue
            params = {"service": svc, "limit": limit, "start": int(start * 1e6), "end": int(end * 1e6)}
            d = (await c.get(f"{jaeger_url}/api/traces", params=params)).json()
            got = d.get("data") or []
            if stats is not None and len(got) >= limit:
                stats["truncated_services"].append(svc)
            for t in got:
                first = min((s.get("startTime") or 0 for s in t.get("spans") or []), default=0) / 1e6
                if first and first < start:
                    if stats is not None and t["traceID"] not in traces:
                        stats["dropped_before_window"] += 1
                    continue
                traces[t["traceID"]] = t
    return list(traces.values())


def _seconds(lookback: str) -> int:
    return int(lookback[:-1]) * {"h": 3600, "m": 60, "s": 1}[lookback[-1]]


def correlate(traces: list[dict], bigip_addresses: set[str], vip_addresses: set[str],
              exclude_services: set[str] | None = None, exclude_peers: set[str] | None = None,
              peer_names: dict[str, str] | None = None) -> dict:
    exclude_services, exclude_peers, peer_names = exclude_services or set(), exclude_peers or set(), peer_names or {}
    services: dict[str, dict] = {}
    inst_listen: dict[tuple[str, str], set] = defaultdict(set)

    def pinfo(t, span):
        p = t["processes"][span["processID"]]
        tags = {x["key"]: x["value"] for x in p.get("tags", [])}
        return p["serviceName"], tags.get("service.instance.id") or tags.get("host.name") or "", tags

    # ---------------- pass 1: roles + listen addresses
    for t in traces:
        for s in t["spans"]:
            name, inst, ptags = pinfo(t, s)
            info = services.setdefault(name, {"service": name, "hosts": set(), "instances": set(), "listen": set(),
                                              "roles": set(), "agent_name": None})
            info["hosts"].add(ptags.get("host.name"))
            if ptags.get("service.instance.id"):
                info["instances"].add(ptags["service.instance.id"])
            tg = _tags(s)
            if tg.get("gen_ai.agent.name"):
                info["agent_name"] = tg["gen_ai.agent.name"]
            if tg.get("a2a.task.id"):
                info["roles"].add("a2a_server")
            if tg.get("mcp.method.name") and tg.get("span.kind") == "server":
                info["roles"].add("mcp_server")
            if tg.get("mcp.method.name") and tg.get("span.kind") == "client":
                info["roles"].add("mcp_client")
            if tg.get("span.kind") == "server" and (tg.get("http.host") or tg.get("server.address")):
                target = tg.get("http.target") or tg.get("url.path") or ""
                if "agent-card" in target and int(tg.get("http.status_code") or 0) == 200:
                    info["roles"].add("a2a_server")
                hp = _hostport(tg.get("http.host")) or (tg.get("server.address"), int(tg.get("server.port") or 0))
                if hp and hp[1]:
                    inst_listen[(name, inst)].add(f"{hp[0]}:{hp[1]}")
                    info["listen"].add(f"{hp[0]}:{hp[1]}")
            if tg.get("span.kind") == "client" and "agent-card" in (tg.get("http.url") or tg.get("url.full") or ""):
                info["roles"].add("a2a_client")

    edges: dict[tuple, dict] = {}
    addr_owner: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))   # peer ip -> instrumented caller -> spans
    addr_inst: dict[str, set] = defaultdict(set)   # peer ip -> {(caller service, caller instance)} (identity evidence)

    def edge(caller, target, proto, path=None, **kw):
        e = edges.setdefault((caller, target, proto), {
            "caller": caller, "target": target, "protocol": proto, "paths": defaultdict(int), "calls": 0, "errors": 0,
            "durations_ms": [], "op_durations_ms": defaultdict(list), "tools": defaultdict(int), "mcp_protocol_versions": set(), "peer_addresses": set(),
            "replicas": set(), "trace_ids": set()})
        if path:
            e["paths"][path] += 1
        for k, v in kw.items():
            if not v:
                continue
            if k == "tool":
                e["tools"][v] += 1
            elif k == "mcp_version":
                e["mcp_protocol_versions"].add(v)
            elif k == "peer":
                e["peer_addresses"].add(v)
            elif k == "replica":
                e["replicas"].add(v)
            elif k == "trace_id":
                e["trace_ids"].add(v)
        return e

    def proto_for(server_svc: str, http_target: str) -> str:
        roles = services.get(server_svc, {}).get("roles", set())
        if "mcp_server" in roles and http_target.startswith("/mcp"):
            return "mcp"
        if "a2a_server" in roles and (http_target in ("/", "") or "agent-card" in http_target):
            return "a2a"
        return "http"

    # ---------------- pass 2: edges
    for t in traces:
        spans = {s["spanID"]: s for s in t["spans"]}
        children = defaultdict(list)
        for s in t["spans"]:
            for r in s.get("references", []):
                if r["refType"] == "CHILD_OF":
                    children[r["spanID"]].append(s)
        for s in t["spans"]:
            name, inst, ptags = pinfo(t, s)
            if name in exclude_services:
                continue
            tg = _tags(s)
            kind = tg.get("span.kind")
            parent = next((spans.get(r["spanID"]) for r in s.get("references", []) if r["refType"] == "CHILD_OF"), None)
            parent_svc = pinfo(t, parent)[0] if parent else None

            if kind == "server" and (tg.get("http.host") or tg.get("server.address")):
                hp = _hostport(tg.get("http.host")) or (tg.get("server.address"), int(tg.get("server.port") or 0))
                if not hp or not hp[1]:
                    continue
                peer = tg.get("net.peer.ip") or tg.get("client.address")
                if parent_svc in exclude_services or peer in exclude_peers:
                    continue
                target = f"{hp[0]}:{hp[1]}"
                caller = parent_svc if parent_svc and parent_svc != name else f"client@{peer or 'unknown-peer'}"
                if parent_svc and parent_svc != name and peer and peer not in bigip_addresses:
                    addr_owner[peer][parent_svc] += 1
                    addr_inst[peer].add((parent_svc, pinfo(t, parent)[1]))
                path = "via_bigip" if (peer in bigip_addresses or hp[0] in vip_addresses) else "direct"
                proto = proto_for(name, tg.get("http.target") or tg.get("url.path") or "")
                e = edge(caller, target, proto, path, peer=peer, trace_id=t["traceID"], replica=ptags.get("service.instance.id"))
                e["calls"] += 1
                e["durations_ms"].append(s["duration"] / 1000.0)
                op = f"{tg.get('http.method') or tg.get('http.request.method') or ''} {(tg.get('http.target') or tg.get('url.path') or '').split('?')[0]}".strip()
                e["op_durations_ms"][op or "request"].append(s["duration"] / 1000.0)
                e["server_service"] = name
                if int(tg.get("http.status_code") or tg.get("http.response.status_code") or 200) >= 500:
                    e["errors"] += 1

            elif kind == "server" and tg.get("mcp.method.name"):
                # MCP span parented to the client's span (via _meta) or to the server's own HTTP span:
                # walk up to the first ancestor in a different service = the caller.
                anc = parent
                while anc is not None and pinfo(t, anc)[0] == name:
                    anc = next((spans.get(r["spanID"]) for r in anc.get("references", []) if r["refType"] == "CHILD_OF"), None)
                parent_svc = pinfo(t, anc)[0] if anc is not None else None
                if not parent_svc or parent_svc in exclude_services:
                    continue
                for target in inst_listen.get((name, inst), ()):
                    e = edge(parent_svc, target, "mcp", None, tool=tg.get("gen_ai.tool.name"),
                             mcp_version=tg.get("mcp.protocol.version"), replica=ptags.get("service.instance.id"),
                             trace_id=t["traceID"])
                    e["server_service"] = name

            elif kind == "client":
                url = tg.get("http.url") or tg.get("url.full")
                hp = _hostport(url) or (_hostport(f"{tg['server.address']}:{tg.get('server.port')}") if tg.get("server.address") else None)
                if not hp or any(_tags(c).get("span.kind") == "server" for c in children.get(s["spanID"], [])):
                    continue   # instrumented target: edge comes from the server side
                if tg.get("mcp.method.name"):
                    continue
                if tg.get("rpc.system") == "aws-api":
                    proto = "s3" if tg.get("rpc.service") == "S3" else "aws-api"
                elif tg.get("gen_ai.system") or (url and ("/chat/completions" in url or "/api/embed" in url)):
                    proto = "llm"
                elif url and "/collections/" in url:
                    proto = "vector_db"
                else:
                    proto = "http"
                target = f"{hp[0]}:{hp[1]}"
                e = edge(name, target, proto, "via_bigip" if hp[0] in vip_addresses else "direct", trace_id=t["traceID"])
                e["calls"] += 1
                e["durations_ms"].append(s["duration"] / 1000.0)
                e["op_durations_ms"][s.get("operationName") or "request"].append(s["duration"] / 1000.0)
                e["latency_source"] = "client span (caller-measured; target not instrumented)"

    # ---------------- identity attribution of context-less callers (see module docstring)
    attributions = []
    for key in [k for k in edges if k[0].startswith("client@")]:
        caller, target, proto = key
        ip = caller.split("@", 1)[1]
        owners = addr_owner.get(ip, {})
        if len(owners) == 1:
            owner = next(iter(owners))
            if (owner, target, proto) in edges:
                src, dst = edges.pop(key), edges[(owner, target, proto)]
                for k2, v in src["paths"].items():
                    dst["paths"][k2] += v
                dst["calls"] += src["calls"]
                dst["errors"] += src["errors"]
                dst["durations_ms"] += src["durations_ms"]
                for k2, v in src["op_durations_ms"].items():
                    dst["op_durations_ms"][k2] += v
                for k2, v in src["tools"].items():
                    dst["tools"][k2] += v
                for k2 in ("mcp_protocol_versions", "peer_addresses", "replicas", "trace_ids"):
                    dst[k2] |= src[k2]
                attributions.append({"peer": ip, "attributed_to": owner, "target": target, "protocol": proto, "calls": src["calls"],
                                     "evidence": f"{owners[owner]} traced span(s) from {ip} carry {owner}'s trace context, and {owner} "
                                                 f"has a traced {proto} edge to {target}"})
    hosts_of = {ip: sorted(o) for ip, o in addr_owner.items()}

    out_edges = []
    for e in edges.values():
        if not e["calls"] and not e["tools"]:
            continue
        d = e["durations_ms"]
        out_edges.append({**{k: v for k, v in e.items() if k not in ("durations_ms", "op_durations_ms")},
                          "paths": dict(e["paths"]), "tools": dict(e["tools"]), "mcp_protocol_versions": sorted(e["mcp_protocol_versions"]),
                          "peer_addresses": sorted(e["peer_addresses"]), "replicas": sorted(e["replicas"]),
                          "trace_ids": sorted(e["trace_ids"])[:20], "trace_count": len(e["trace_ids"]),
                          "latency_ms": latency_summary(d),
                          # per operation: an A2A edge mixes card GETs (ms) with streaming task POSTs (s) — never one percentile
                          "latency_by_operation": {k: latency_summary(v) for k, v in sorted(e["op_durations_ms"].items())},
                          "latency_source": e.get("latency_source", "server span (request handling incl. streamed response)"),
                          "mixed_operations": len(e["op_durations_ms"]) > 1})
    out_services = {k: {**v, "hosts": sorted(x for x in v["hosts"] if x), "instances": sorted(v["instances"]),
                        "listen": sorted(v["listen"]), "roles": sorted(v["roles"])}
                    for k, v in services.items() if k not in exclude_services}
    return {"services": out_services, "edges": out_edges, "trace_count": len(traces), "attributions": attributions,
            "peer_hosts": hosts_of,
            # identity evidence for canonical service reconciliation (Wave 2A): which runtime instance serves / emits an address
            "instance_listen": {svc: {inst or "": sorted(a) for (sv, inst), a in inst_listen.items() if sv == svc}
                                for svc in {sv for sv, _ in inst_listen} if svc not in exclude_services},
            "peer_instances": {ip: sorted([list(x) for x in v]) for ip, v in addr_inst.items()}}
