"""Deterministic ADC (AI Delivery) and security (AI Security) assessment over discovered evidence.

Each rule inspects assets/relationships and emits a finding only with the evidence ids that support it.
No rule fires on an empty workspace; no finding is created without at least one evidence id.
Rules also emit *coverage gaps* (what we could not determine and which method would close the gap).
"""
from __future__ import annotations

import hashlib
import json
import time

from . import capabilities, catalog, claims, validation_evidence
from .store import Store

PRIVILEGED_HINTS = ("freeze", "delete", "transfer", "export", "wire", "close_account", "update", "write")


def _controls(store: Store, assets: list[dict]):
    """Control evidence usable by THIS assessment: a validation result counts only for a deployment that is in place now AND was
    already in place when this assessment's BIG-IP state was observed — otherwise the discovery describes an older state and
    later test results must not change what it shows (doc 38: no mixing of time bases)."""
    observed_at = max((c.get("ts") or 0 for a in assets if a["kind"] in ("adc", "bigip_virtual") for c in a["claims"]
                       if c.get("source") == "observe"), default=0)
    if not observed_at:
        return lambda kind, test: None
    place = {k: d for k, d in validation_evidence.in_place(store).items() if (d["started"] or 0) <= observed_at}
    all_runs = validation_evidence.runs(store) if place else []
    return lambda kind, test: validation_evidence.validated(store, kind, test, all_runs, place)


def _ev(*items) -> list[str]:
    out = []
    for it in items:
        for c in it.get("claims", []):
            if c["evidence_id"] not in out:
                out.append(c["evidence_id"])
    return out


def evaluate(store: Store, cfg: dict) -> tuple[list[dict], list[dict]]:
    """Pure evaluation of all rules over the current evidence. Never writes."""
    assets = store.assets()
    rels = store.rels()
    by_id = {a["id"]: a for a in assets}
    findings: list[dict] = []
    gaps: list[dict] = []

    def add(rule, category, severity, title, detail, asset_list, ev_ids):
        ev_ids = [e for e in ev_ids if e]
        if not ev_ids:
            return
        findings.append({"rule_id": rule, "category": category, "severity": severity, "title": title, "detail": detail,
                         "asset_ids": [a["id"] for a in asset_list], "evidence_ids": ev_ids})

    adcs = [a for a in assets if a["kind"] == "adc"]
    vips = {a["key"].split(":", 1)[1] for a in assets if a["attrs"].get("is_vip")}
    pool_members = {a["key"].split(":", 1)[1] for a in assets if a["attrs"].get("bigip_pool_member_of")}
    pool_of = {a["key"].split(":", 1)[1]: a["attrs"]["bigip_pool_member_of"] for a in assets if a["attrs"].get("bigip_pool_member_of")}
    fronting = lambda addrs: [v for v in assets if v["kind"] == "bigip_virtual" and v["attrs"].get("pool") in {pool_of.get(x) for x in addrs}]  # noqa: E731
    control = _controls(store, assets)
    calls = [r for r in rels if r["kind"].startswith("calls_")]
    observed_sources = {c["source"] for a in assets for c in a["claims"]}

    # ------------------------------------------------------------- AI DELIVERY
    for svc in [a for a in assets if a["kind"] == "mcp_service" and (a["attrs"].get("replica_count") or 0) >= 2]:
        replicas = [by_id[r["dst"]] for r in rels if r["src"] == svc["id"] and r["kind"] == "has_replica" and r["dst"] in by_id]
        rkeys = {r["key"].split(":", 1)[1] for r in replicas}
        inbound = [r for r in calls if by_id.get(r["dst"], {}).get("key", "").split(":", 1)[-1] in rkeys]
        used = {by_id[r["dst"]]["key"].split(":", 1)[1] for r in inbound}
        lb = rkeys & pool_members
        if not lb:
            idle = sorted(rkeys - used) if inbound else []
            detail = (f"{len(replicas)} replicas of MCP service '{svc['name']}' exist ({', '.join(sorted(rkeys))}) but no BIG-IP "
                      f"pool load-balances them." + (f" Observed traffic reaches only {', '.join(sorted(used))}; "
                                                     f"{', '.join(idle)} receive{'s' if len(idle) == 1 else ''} no traffic." if idle else ""))
            add("D-001", "delivery", "high", f"MCP service '{svc['name']}' has replicas but no load balancing", detail,
                [svc] + replicas, _ev(svc, *replicas, *inbound))
            add("D-002", "delivery", "high", f"No health monitoring for MCP service '{svc['name']}'",
                "No BIG-IP pool or health monitor covers these replicas, so a failed replica keeps receiving traffic and "
                "clients see errors instead of failover.", [svc] + replicas, _ev(svc, *replicas))
        versions = sorted({v for r in inbound for c in r["claims"] for v in (c["attrs"].get("mcp_protocol_versions") or [])})
        persisted = lb == rkeys and any(capabilities.status(v, "persistence") == "present" for v in fronting(rkeys))
        if any(v < "2026-07-28" for v in versions) and not persisted and not (lb == rkeys and control("delivery", "delivery.session_persistence")):
            add("D-003", "delivery", "medium", f"Stateful MCP sessions require persistence for '{svc['name']}'",
                f"Clients negotiate MCP protocol {', '.join(versions)} (initialize + Mcp-Session-Id). Sessions are held per "
                "replica, so load balancing needs session persistence keyed on the Mcp-Session-Id header.",
                [svc], _ev(*inbound))
    for r in calls:
        dst = by_id.get(r["dst"])
        if dst and r["kind"] == "calls_a2a" and r["observed_path"] == "direct" and dst["key"].split(":", 1)[1] not in vips:
            add("D-004", "delivery", "medium", f"A2A agent '{dst['name']}' served from a single endpoint without ADC",
                "A2A tasks (including SSE streaming) reach the agent directly; there is no health monitoring, TLS offload, "
                "or connection management in the path.", [dst], _ev(r, dst))
    stream = [r for r in calls if r["kind"] == "calls_a2a"]
    if stream:
        lat = [c["attrs"].get("latency_ms") for r in stream for c in r["claims"] if c["attrs"].get("latency_ms")]
        mx = max((l["max"] for l in lat), default=0)
        dsts = {by_id[r["dst"]]["key"].split(":", 1)[1] for r in stream if r["dst"] in by_id}
        handled = bool(dsts) and dsts <= (pool_members | vips) and control("delivery", "a2a.streaming")
        if mx > 30000 and not handled:
            add("D-005", "delivery", "low", "Long-lived A2A streams need extended idle timeouts",
                f"Observed A2A task durations up to {mx/1000:.0f}s; default TCP idle/HTTP response timeouts on a proxy "
                "would cut streams. Use OneConnect off, no response buffering/compression for text/event-stream, idle >= 600s.",
                [by_id[r["dst"]] for r in stream if r["dst"] in by_id], _ev(*stream))

    # ------------------------------------------------------------- AI SECURITY
    for r in calls:
        dst = by_id.get(r["dst"])
        if not dst:
            continue
        addr = dst["key"].split(":", 1)[1]
        if r["kind"] in ("calls_mcp", "calls_a2a") and r["observed_path"] == "direct" and (adcs or vips):
            add("S-001", "security", "high", f"Traffic bypasses BIG-IP to '{dst['name']}' ({addr})",
                f"Telemetry shows {by_id.get(r['src'], {}).get('name', 'a client')} calling {addr} directly while an ADC is "
                "present. Controls applied on the BIG-IP (authentication, rate limits, tool policy) are not enforced on this path.",
                [dst] + ([by_id[r["src"]]] if r["src"] in by_id else []), _ev(r, dst))
        if r["assertion_contradicted"]:
            add("S-007", "security", "high", f"Customer assertion contradicted by telemetry for '{dst['name']}'",
                f"The description asserted path {r['asserted_paths']} but observed path is '{r['observed_path']}'.",
                [dst], _ev(r))
    for a in assets:
        if a["kind"] == "mcp_server" and (a["attrs"].get("mcp") or {}).get("authenticated") is False:
            m = a["attrs"]["mcp"]
            add("S-002", "security", "high", f"MCP server '{a['name']}' accepts unauthenticated clients",
                f"An MCP initialize + tools/list from the discovery sensor succeeded without credentials "
                f"(server {m.get('server_name')} {m.get('server_version')}, protocol {m.get('protocol_version')}, "
                f"{len(m.get('tools', []))} tools exposed).", [a], _ev(a))
            priv = [t for t in m.get("tools", []) if (t.get("annotations") or {}).get("destructiveHint")
                    or any(h in t["name"] for h in PRIVILEGED_HINTS)]
            if priv:
                callers = [r for r in calls if r["dst"] == a["id"]]
                used = {t for r in callers for c in r["claims"] for t in (c["attrs"].get("tools") or {})}
                unused = [t["name"] for t in priv if t["name"] not in used]
                if unused:
                    add("S-003", "security", "high", f"Excessive tool exposure on '{a['name']}'",
                        f"Privileged tools {unused} are callable by any client, but observed agent traffic only uses "
                        f"{sorted(used) or 'none of them'}. Apply per-agent tool allow-lists (least privilege).",
                        [a], _ev(a, *callers))
        if a["kind"] == "a2a_agent" and a["attrs"].get("agent_card"):
            card = a["attrs"]["agent_card"]
            if not card.get("security_schemes"):
                add("S-004", "security", "medium", f"A2A agent '{a['name']}' advertises no authentication",
                    "The Agent Card declares no securitySchemes; any client on the network can submit tasks.", [a], _ev(a))
            own = a["key"].split(":", 1)[1]
            for u in card.get("advertised_urls", []):
                if own.split(":")[0] in (u or "") and own.split(":")[0] not in vips:
                    add("S-005", "security", "medium", f"Agent Card for '{a['name']}' advertises its direct endpoint",
                        f"Clients follow the card URL {u}; even if the card is fetched through a proxy, task traffic goes "
                        "direct. Advertise the BIG-IP virtual server address instead.", [a], _ev(a))
        if a["kind"] == "vector_db" and (a["attrs"].get("vector_db") or {}).get("unauthenticated_read"):
            add("S-006", "security", "medium", f"Vector database '{a['name']}' readable without authentication",
                f"Collections {a['attrs']['vector_db'].get('collections')} are listable without an API key.", [a], _ev(a))
        if a["kind"] == "llm_endpoint" and (a["attrs"].get("llm") or {}).get("unauthenticated"):
            add("S-008", "security", "medium", f"LLM endpoint '{a['name']}' has no authentication or rate limiting",
                f"Models {a['attrs']['llm'].get('models')} can be invoked by any host in scope.", [a], _ev(a))
    # D-006 (opt-in): AI data services the AI Data Delivery pattern can front (design.data_delivery), not fronted by a BIG-IP pool
    dd = (cfg.get("design") or {}).get("data_delivery")
    if dd:
        kinds = {"object_store": ("s3", "S3 object store"), "vector_db": ("rag", "vector database"), "llm_endpoint": ("llm", "LLM endpoint")}
        for a in assets:
            svc, label = kinds.get(a["kind"], (None, None))
            addr = a["key"].split(":", 1)[1] if ":" in a["key"] else ""
            if not svc or addr not in (dd.get(svc) or {}).get("members", []) or addr in pool_members or addr in vips:
                continue
            add("D-006", "delivery", "medium", f"AI data service '{a['name']}' ({label}) served without an ADC",
                f"The {label} at {addr} is reached directly: no health monitoring, no single observable front door and no "
                "request telemetry in the path. The AI Data Delivery package adds a BIG-IP virtual server for it.", [a], _ev(a))
    # S-007: customer control claims (Describe) checked against technical evidence (claims.verify)
    for v in claims.verify(store):
        if v["status"] == "contradicted":
            add("S-007", "security", "high", f"Customer assertion contradicted: '{v['claim']}' ({v['subject']})",
                f"The description states \"{(v['text'] or '')[:160]}\", but technical evidence contradicts it for: "
                f"{', '.join(v.get('contradicted_for') or v['targets'])}. {v['explanation']}",
                [by_id[i] for i in v["target_ids"] if i in by_id], [v["describe_evidence"]] + v["evidence"])
    rate_limit_state = capabilities.aggregate(assets, "rate_limiting")
    for r in calls:
        if r["kind"] == "calls_mcp":
            total = sum((c["attrs"].get("calls") or 0) for c in r["claims"] if c["source"] == "ingest")
            dst = by_id.get(r["dst"])
            fronted = bool(dst) and dst["key"].split(":", 1)[1] in (pool_members | vips)
            # a VS rate limit applies only to traffic through the VS: direct calls must be via BIG-IP or blocked by the lockdown
            through = r["observed_path"] == "via_bigip" or bool(control("security", "security.direct_backend_blocked"))
            if total and rate_limit_state != "present" and not (fronted and through and control("security", "security.rate_limited")):
                qualifier = ("no verified rate-limiting evidence; enforcement is unknown"
                             if rate_limit_state == "unknown" else "no rate-limiting control was evidenced")
                add("S-009", "security", "medium", f"No rate limiting on MCP calls to '{dst['name'] if dst else r['dst']}'",
                    f"{total} MCP calls observed with {qualifier}. Persistence, authentication, tool authorization, and "
                    "rate limiting are assessed as separate capabilities; an attached iRule alone is not proof.",
                    [dst] if dst else [], _ev(r))

    # ------------------------------------------------------------- coverage gaps
    if "observe" not in observed_sources:
        gaps.append({"gap": "ADC configuration unknown", "close_with": "observe"})
    if "ingest" not in observed_sources:
        gaps.append({"gap": "No runtime communication paths observed (telemetry not ingested)", "close_with": "ingest"})
    elif not calls:
        gaps.append({"gap": "Ingest found no traffic in its window (after an infrastructure change only traffic since that change "
                            "is used)", "close_with": "Validate (generates live A2A/MCP traffic), then Ingest again"})
    if "enumerate" not in observed_sources:
        gaps.append({"gap": "Service endpoints and protocols not verified", "close_with": "enumerate"})
    for a in assets:
        if a["status"] == "asserted":
            gaps.append({"gap": f"Described component '{a['name']}' not yet matched to technical evidence",
                         "close_with": "enumerate/ingest", "asset_id": a["id"]})
    for a in assets:
        if a["kind"] in ("mcp_server", "a2a_agent") and not any(r["dst"] == a["id"] and r["kind"].startswith("calls_") for r in rels):
            gaps.append({"gap": f"No observed clients for '{a['name']}' ({a['key'].split(':', 1)[1]})",
                         "close_with": "ingest (generate or wait for traffic)", "asset_id": a["id"]})

    return findings, gaps


def _fid(aid: str, f: dict, keys: dict) -> str:
    ident = json.dumps([aid, f["rule_id"], f["title"], sorted(keys.get(a, a) for a in f["asset_ids"])])
    return hashlib.sha256(ident.encode()).hexdigest()[:16]


def run(store: Store, cfg: dict, actor: str = "autopilot", reason: str = "discovery") -> dict:
    """Evaluate and persist findings. Finding ids are deterministic (rule + title + affected assets), so unchanged findings
    keep their ids; the audit records an assessment only when the set of findings actually changes."""
    findings, gaps = evaluate(store, cfg)
    aid = store.current()["id"]
    keys = {a["id"]: a["key"] for a in store.assets()}
    with store.lock:
        have = {r["id"] for r in store.db.execute("SELECT id FROM finding WHERE assessment_id=?", (aid,))}
        want = {}
        for f in findings:
            want.setdefault(_fid(aid, f, keys), f)
        removed, added = have - set(want), set(want) - have
        for fid in removed:
            store.db.execute("DELETE FROM finding WHERE id=?", (fid,))
        for fid in added:
            f = want[fid]
            store.db.execute("INSERT OR IGNORE INTO finding VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (fid, aid, f["rule_id"], f["category"], f["severity"], f["title"], f["detail"],
                              json.dumps(f["asset_ids"]), json.dumps(f["evidence_ids"]), time.time()))
    if added or removed:
        store.audit(actor, "assessment.run", aid, {"reason": reason, "findings": len(want), "added": len(added), "removed": len(removed),
                                                   "rules": sorted({f["rule_id"] for f in want.values()})})
    return {"findings": len(want), "added": len(added), "removed": len(removed), "gaps": gaps}


def findings(store: Store) -> list[dict]:
    aid = store.current()["id"]
    rows = store.db.execute("SELECT * FROM finding WHERE assessment_id=? ORDER BY CASE severity WHEN 'high' THEN 0 "
                            "WHEN 'medium' THEN 1 ELSE 2 END, rule_id", (aid,)).fetchall()
    return [{**dict(r), "asset_ids": json.loads(r["asset_ids"]), "evidence_ids": json.loads(r["evidence_ids"]),
             **{k: v for k, v in catalog.meta(r["rule_id"], r["title"]).items() if k in ("issue", "class", "class_label", "basis", "package", "tests", "not_addressed")}}
            for r in rows]
