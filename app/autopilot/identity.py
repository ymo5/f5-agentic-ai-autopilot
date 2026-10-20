"""Canonical service identity (Wave 2A) — a derived, read-only view over STORED evidence. No network access.

Four levels, never conflated:
  logical service   what the service is (one A2A agent, one MCP service, one instrumented workload)
  runtime instance  one running copy of it; several instances of one logical service are REPLICAS
  network endpoint  an address:port (the existing `ep:` assets, which are never modified or deleted)
  unresolved        a possible relationship the evidence does not settle — reported, never silently merged

Merge rules (evidence-based; names and Agent Cards alone never merge two agents):
  * endpoints belong to the same logical service when telemetry binds them to the same OpenTelemetry service, or when
    instance evidence ties an endpoint to an instance of that service (below);
  * endpoints belong to the same runtime instance when telemetry shows the same instance serving / emitting from both
    addresses (Ingest `instance_listen`, `peer_instances`), or the bound service has exactly one observed instance;
  * MCP endpoints with the same server name AND tool-set fingerprint are grouped as one logical service, labelled
    *inferred* (protocol metadata only) unless telemetry corroborates it — this is the existing replica model D-001 uses;
  * A2A endpoints with an identical Agent Card but no corroborating telemetry stay SEPARATE services, linked by an
    unresolved "possibly the same service" relationship; identical cards bound to different telemetry services are noted
    and kept separate; similar names with different capabilities are noted and kept separate.
Every service carries `basis` (evidence statements), `grouping` (corroborated | inferred | single | unresolved-candidate),
a confidence, the evidence ids, and first/last seen timestamps taken from the stored claims.
"""
from __future__ import annotations

import hashlib
import json
import re

ENDPOINT_KINDS = {"a2a_agent", "ai_agent", "mcp_server", "vector_db", "object_store", "llm_endpoint", "otel_collector",
                  "dns_server", "workload"}
CLASSIFICATION = {"a2a_agent": "A2A agent", "ai_agent": "AI agent (client)", "mcp_server": "MCP server", "vector_db": "vector database",
                  "object_store": "object store", "llm_endpoint": "LLM endpoint", "otel_collector": "telemetry collector",
                  "dns_server": "DNS server", "workload": "instrumented workload"}
CONFIDENCE = {"corroborated": 0.9, "single": 0.85, "inferred": 0.6, "unresolved-candidate": 0.5}


def _sid(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def _norm(name: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def card_digest(card: dict | None) -> str | None:
    """Agent Card identity WITHOUT addresses, version or authentication: name, skills, bindings, streaming.
    Security schemes and version are tracked as attributes, so adding authentication is reported as an auth change of
    the SAME agent instead of a different agent appearing."""
    if not card or not card.get("name"):
        return None
    core = {"name": card.get("name"), "skills": sorted(str(s) for s in (card.get("skills") or [])),
            "bindings": sorted(str(b) for b in (card.get("bindings") or []) if b), "streaming": bool(card.get("streaming"))}
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()[:16]


def _latest_ingest(store, aid: str) -> dict:
    row = store.db.execute("SELECT raw FROM evidence WHERE assessment_id=? AND source='ingest' ORDER BY collected_at DESC LIMIT 1",
                           (aid,)).fetchone()
    try:
        return json.loads(row["raw"]) if row else {}
    except (TypeError, ValueError):
        return {}


def reconcile(store, aid: str | None = None) -> dict:
    """Canonical services for one assessment, derived from its stored assets, relationships and ingest evidence."""
    aid = aid or store.current()["id"]
    assets = store.assets(aid)
    rels = store.rels(aid)
    by_id = {a["id"]: a for a in assets}
    ing = _latest_ingest(store, aid)
    services_t = ing.get("services") or {}
    inst_listen = ing.get("instance_listen") or {}
    peer_inst = ing.get("peer_instances") or {}
    peer_hosts = ing.get("peer_hosts") or {}

    listen_svc = {addr: svc for svc, info in services_t.items() for addr in (info.get("listen") or [])}
    listen_inst = {addr: (svc, inst) for svc, m in inst_listen.items() for inst, addrs in m.items() for addr in addrs}

    def single_instance(svc: str) -> str | None:
        info = services_t.get(svc) or {}
        insts = set(info.get("instances") or []) or set(info.get("hosts") or [])
        return next(iter(insts)) if len(insts) == 1 else None

    # ---------------- endpoint records
    eps = []
    for a in assets:
        k = a["key"]
        if not (k.startswith("ep:") or k.startswith("otel:")) or (a["kind"] not in ENDPOINT_KINDS):
            continue
        at = a["attrs"]
        addr = k.split(":", 1)[1] if k.startswith("ep:") else None
        ip = addr.rsplit(":", 1)[0] if addr else None
        card = at.get("agent_card") if isinstance(at.get("agent_card"), dict) else None
        mcp = at.get("mcp") if isinstance(at.get("mcp"), dict) else None
        r = {"asset": a, "addr": addr, "ip": ip, "card": card, "digest": card_digest(card), "mcp": mcp, "basis": [],
             "svc": at.get("otel_service") or (listen_svc.get(addr) if addr else None) or (k.split(":", 1)[1] if k.startswith("otel:") else None),
             "inst": None, "inst_basis": None}
        if r["svc"]:
            r["basis"].append(f"telemetry binds {addr or 'this workload'} to OpenTelemetry service '{r['svc']}'")
        if addr and addr in listen_inst:
            r["svc"], r["inst"] = listen_inst[addr]
            r["inst_basis"] = f"telemetry: instance '{r['inst'] or r['svc']}' of '{r['svc']}' serves {addr}"
        elif r["svc"] and single_instance(r["svc"]):
            r["inst"] = single_instance(r["svc"])
            r["inst_basis"] = f"'{r['svc']}' has exactly one observed instance ('{r['inst']}')"
        eps.append(r)

    # instance evidence for endpoints with no telemetry of their own: the address emits traced spans of an instance of a
    # service whose OTHER endpoint serves an identical Agent Card / MCP identity -> same instance, another interface.
    for r in [e for e in eps if not e["svc"] and e["ip"]]:
        owners = [tuple(x) for x in (peer_inst.get(r["ip"]) or [])] or [(s, None) for s in (peer_hosts.get(r["ip"]) or [])]
        if len({s for s, _ in owners}) != 1:
            continue
        svc, inst = owners[0]
        inst = inst or single_instance(svc)
        twins = [e for e in eps if e is not r and e["svc"] == svc and (
            (r["digest"] and e["digest"] == r["digest"]) or
            (r["mcp"] and e["mcp"] and (r["mcp"].get("server_name"), r["mcp"].get("toolset_fingerprint")) ==
             (e["mcp"].get("server_name"), e["mcp"].get("toolset_fingerprint"))))]
        if twins and inst:
            r["svc"], r["inst"] = svc, inst
            r["basis"].append(f"address {r['ip']} emits traced spans of '{svc}' (instance '{inst}'), and {r['addr']} serves the same "
                              f"protocol identity as {twins[0]['addr']}")
            r["inst_basis"] = f"telemetry: instance '{inst}' of '{svc}' uses address {r['ip']}; identical protocol identity"

    # ---------------- logical grouping
    unresolved, notes = [], []
    groups: dict[str, dict] = {}
    by_digest: dict[str, list] = {}
    for r in eps:
        if not r["svc"] and r["digest"]:
            by_digest.setdefault(r["digest"], []).append(r)
    mcp_owner: dict[tuple, set] = {}   # MCP identity -> telemetry services that serve it (for adopting un-instrumented replicas)
    for r in eps:
        if r["svc"] and r["mcp"]:
            mcp_owner.setdefault((r["mcp"].get("server_name"), r["mcp"].get("toolset_fingerprint")), set()).add(r["svc"])
    mcp_count: dict[tuple, int] = {}
    for r in eps:
        if r["mcp"] and not r["svc"]:
            k2 = (r["mcp"].get("server_name"), r["mcp"].get("toolset_fingerprint"))
            mcp_count[k2] = mcp_count.get(k2, 0) + 1
    for r in eps:
        a = r["asset"]
        r["membership"] = "corroborated" if r["svc"] else None
        mid = (r["mcp"].get("server_name"), r["mcp"].get("toolset_fingerprint")) if r["mcp"] else None
        if not r["svc"] and mid and len(mcp_owner.get(mid, ())) == 1:
            owner = next(iter(mcp_owner[mid]))
            key, grouping, r["membership"] = f"otel:{owner}", "corroborated", "inferred"
            r["basis"].append(f"{r['addr']} serves the same MCP server name and tool-set fingerprint as telemetry service '{owner}' "
                              "(no telemetry of its own — membership inferred)")
        elif r["svc"]:
            key, grouping = f"otel:{r['svc']}", "corroborated"
        elif r["mcp"] and r["mcp"].get("server_name") and mcp_count.get(mid, 0) == 1:
            key, grouping = f"mcp:{r['mcp']['server_name']}:{r['mcp'].get('toolset_fingerprint')}", "single"
        elif r["mcp"] and r["mcp"].get("server_name"):
            r["membership"] = "inferred"
            key, grouping = f"mcp:{r['mcp']['server_name']}:{r['mcp'].get('toolset_fingerprint')}", "inferred"
        elif r["digest"]:
            dup = by_digest.get(r["digest"], [])
            key = f"a2a:{r['digest']}" + (f"@{r['addr']}" if len(dup) > 1 else "")
            grouping = "unresolved-candidate" if len(dup) > 1 else "single"
        else:
            key, grouping = f"ep:{r['addr']}" if r["addr"] else a["key"], "single"
        g = groups.setdefault(key, {"key": key, "members": [], "grouping": grouping, "basis": []})
        if CONFIDENCE.get(grouping, 0) > CONFIDENCE.get(g["grouping"], 0):
            g["grouping"] = grouping
        g["members"].append(r)
        for b in r["basis"]:
            if b not in g["basis"]:
                g["basis"].append(b)
    for d, members in by_digest.items():
        if len(members) > 1:
            unresolved.append({"type": "possibly_same_service", "endpoints": [m["addr"] for m in members],
                               "asset_ids": [m["asset"]["id"] for m in members],
                               "basis": [f"identical Agent Card ('{members[0]['card'].get('name')}', same skills)"],
                               "why_unresolved": "no telemetry or instance evidence ties these endpoints together — an identical Agent "
                                                 "Card alone does not prove they are the same agent (could be separate deployments)"})
    # identical cards bound to DIFFERENT telemetry services: noted, kept separate
    seen: dict[str, set] = {}
    for r in eps:
        if r["digest"] and r["svc"]:
            seen.setdefault(r["digest"], set()).add(r["svc"])
    for d, svcs in seen.items():
        if len(svcs) > 1:
            notes.append({"type": "identical_card_different_telemetry", "services": sorted(svcs),
                          "detail": "identical Agent Card served by different OpenTelemetry services — kept as separate services"})

    # ---------------- services, instances, endpoints
    out, index = [], {}
    for key, g in groups.items():
        sid = _sid(key)
        ms = g["members"]
        kinds = [m["asset"]["kind"] for m in ms]
        kind = next((k for k in ("a2a_agent", "mcp_server", "ai_agent", "llm_endpoint", "vector_db", "object_store", "otel_collector",
                                 "dns_server", "workload") if k in kinds), kinds[0])
        insts: dict[str, dict] = {}
        for m in ms:
            if m["inst"] is not None:
                ik, status, basis = f"{key}#{m['inst']}", "resolved", m["inst_basis"]
            else:
                ik, status = f"{key}#{m['addr'] or m['asset']['key']}", "provisional"
                basis = "no instance identity observed — one provisional instance per endpoint"
            inst = insts.setdefault(ik, {"id": _sid(ik), "key": ik, "label": m["inst"] or m["addr"] or m["asset"]["name"],
                                         "status": status, "basis": basis, "endpoints": []})
            inst["endpoints"].append(m["asset"]["id"])
        instances = list(insts.values())
        prov = [i for i in instances if i["status"] == "provisional"]
        if g["grouping"] == "corroborated" and len(instances) > 1 and prov:
            unresolved.append({"type": "instance_relationship_unknown", "service_key": key,
                               "endpoints": [ms_["addr"] for ms_ in ms if ms_["inst"] is None],
                               "why_unresolved": "these endpoints belong to the same logical service, but whether they are interfaces of one "
                                                 "instance or separate replicas is not observed"})
        endpoints = []
        for i in instances:
            for asid in i["endpoints"]:
                a = by_id[asid]
                role = "interface" if len(i["endpoints"]) > 1 else "sole endpoint"
                mem = next((m.get("membership") for m in ms if m["asset"]["id"] == asid), None) or "single"
                if a["key"].startswith("ep:"):
                    endpoints.append({"asset_id": asid, "address": a["key"].split(":", 1)[1], "instance_id": i["id"], "role": role, "membership": mem,
                                      "last_seen": a["last_seen"], "first_seen": a["first_seen"]})
                index[asid] = {"service_id": sid, "service_key": key, "instance_id": i["id"], "role": role, "membership": mem,
                               "instances": len(instances), "grouping": g["grouping"]}
        card = next((m["card"] for m in ms if m["card"]), None)
        mcp = next((m["mcp"] for m in ms if m["mcp"]), None)
        tools = (mcp or {}).get("tools") or []
        replicas = len(instances) if len(instances) > 1 else 0
        out.append({
            "id": sid, "key": key, "kind": kind, "classification": CLASSIFICATION.get(kind, kind),
            "name": (card or {}).get("name") or (mcp or {}).get("server_name") or next((m["svc"] for m in ms if m["svc"]), None) or ms[0]["asset"]["name"],
            "grouping": g["grouping"], "confidence": CONFIDENCE.get(g["grouping"], 0.5),
            "basis": g["basis"] or (["protocol metadata only (same MCP server name and tool-set fingerprint)"] if g["grouping"] == "inferred" else
                                    ["single endpoint"]),
            "verified": g["grouping"] in ("corroborated", "single") and any(set(m["asset"]["sources"]) & {"enumerate", "ingest", "observe"} for m in ms),
            "telemetry_service": next((m["svc"] for m in ms if m["svc"]), None),
            "instances": instances, "replicas": replicas,
            "replica_status": None if not replicas else ("resolved" if all(i["status"] == "resolved" for i in instances) else "provisional"),
            "endpoints": endpoints,
            "capabilities": {"skills": (card or {}).get("skills") or [], "tools": [t.get("name") for t in tools],
                             "privileged_tools": [t.get("name") for t in tools if (t.get("annotations") or {}).get("destructiveHint")
                                                  or (t.get("annotations") or {}).get("openWorldHint")]},
            "auth": {"security_schemes": (card or {}).get("security_schemes") if card else None,
                     "mcp_authenticated": (mcp or {}).get("authenticated") if mcp else None},
            "versions": sorted({str(v) for v in [(m["card"] or {}).get("version") for m in ms] + [(m["mcp"] or {}).get("server_version") for m in ms] if v}),
            "card_digest": next((m["digest"] for m in ms if m["digest"]), None),
            "sources": sorted({s for m in ms for s in m["asset"]["sources"]}),
            "evidence_ids": sorted({c["evidence_id"] for m in ms for c in m["asset"]["claims"]}),
            "first_seen": min(m["asset"]["first_seen"] for m in ms), "last_seen": max(m["asset"]["last_seen"] for m in ms),
            "asset_ids": [m["asset"]["id"] for m in ms],
        })
    # similar names, different capabilities: noted, never merged
    byname: dict[str, list] = {}
    for s in out:
        if s["kind"] == "a2a_agent":
            byname.setdefault(_norm(s["name"]), []).append(s)
    for n, ss in byname.items():
        if len(ss) > 1 and len({s["card_digest"] for s in ss}) > 1:
            notes.append({"type": "similar_name_not_merged", "services": [s["id"] for s in ss], "name": ss[0]["name"],
                          "detail": "same or similar name but different Agent Card capabilities — separate services"})
    # relationships between services (from stored edges)
    rel_out = []
    for r in rels:
        if not r["kind"].startswith("calls_"):
            continue
        s, d = index.get(r["src"]), index.get(r["dst"])
        rel_out.append({"from": s["service_id"] if s else None, "from_asset": r["src"], "to": d["service_id"] if d else None, "to_asset": r["dst"],
                        "protocol": r["kind"][6:], "path": r["observed_path"], "rel_id": r["id"]})
    out.sort(key=lambda s: (s["kind"], s["name"] or ""))
    return {"assessment_id": aid, "services": out, "unresolved": unresolved, "notes": notes, "relationships": rel_out,
            "endpoint_index": index,
            "summary": {"services": len(out), "endpoints": sum(len(s["endpoints"]) for s in out),
                        "instances": sum(len(s["instances"]) for s in out), "unresolved": len(unresolved),
                        "telemetry_evidence": bool(ing), "instance_evidence": bool(inst_listen or peer_inst)}}
