"""Read-only views that make discovery evidence navigable (Wave 1).

  asset_dossier()      everything known about one asset: identity, protocol details, claims with trust levels, findings,
                       observed communications, related recommendations, replicas/interfaces.
  edge_dossier()       one relationship: claims, observed path, calls/latency/tools and the trace ids that prove it.
  scoped_evidence()    an evidence document reduced to the parts that mention one asset (raw stays one click away).
  assessment_profile() what an assessment actually covers (sources, evidence, infra state, deployments) — used to stop
                       misleading before/after comparisons.
  comparability()      whether two assessments can be compared and what kind of comparison it is.
Nothing here writes to the database or touches the network.
"""
from __future__ import annotations

import json
import time

from . import catalog, trust, verification

KIND_LABEL = {"a2a_agent": "A2A agent", "ai_agent": "AI agent (client)", "a2a_endpoint": "advertised A2A URL", "mcp_server": "MCP server",
              "mcp_service": "MCP service (logical, replicas)", "vector_db": "vector database", "object_store": "object store",
              "llm_endpoint": "LLM endpoint", "adc": "BIG-IP", "bigip_virtual": "BIG-IP virtual server", "bigip_pool": "BIG-IP pool",
              "bigip_vip": "BIG-IP VIP", "analytics": "analytics", "otel_collector": "OpenTelemetry collector", "dns_server": "DNS server",
              "client": "client", "client_app": "client", "workload": "instrumented workload", "asserted_component": "described (unverified)"}
PROTOCOL = {"a2a_agent": "A2A (JSON-RPC over HTTP, Agent Card)", "a2a_endpoint": "A2A", "mcp_server": "MCP (Streamable HTTP)",
            "mcp_service": "MCP", "vector_db": "Qdrant REST", "object_store": "S3 API", "llm_endpoint": "OpenAI-compatible / Ollama API",
            "otel_collector": "OTLP/HTTP", "dns_server": "DNS", "adc": "iControl REST (management)"}
SECURITY_RULES = {"S-001", "S-002", "S-003", "S-004", "S-005", "S-006", "S-007", "S-008", "S-009"}


def _addr(a: dict) -> str | None:
    k = a["key"]
    return k.split(":", 1)[1] if k.startswith("ep:") else a["attrs"].get("address")


def _findings(store, aid: str | None = None) -> list[dict]:
    q = "SELECT * FROM finding WHERE assessment_id=?"
    out = []
    for r in store.db.execute(q, (aid or store.current()["id"],)):
        f = dict(r)
        f["asset_ids"], f["evidence_ids"] = json.loads(f["asset_ids"]), json.loads(f["evidence_ids"])
        m = catalog.meta(f["rule_id"], f["title"])
        f.update({"issue": m.get("issue"), "class": m.get("class"), "class_label": m.get("class_label"), "package": m.get("package")})
        f["domain"] = "security" if f["rule_id"] in SECURITY_RULES else "delivery"
        out.append(f)
    return out


def _packages(store) -> list[dict]:
    out = []
    for r in store.db.execute("SELECT id, kind, title, body FROM package WHERE assessment_id=?", (store.current()["id"],)):
        b = json.loads(r["body"])
        x = b.get("explanation") or {}
        out.append({"id": r["id"], "kind": r["kind"], "title": r["title"], "rules": [f["rule"] for f in x.get("findings_addressed", [])],
                    "services": x.get("affected_services") or [], "text": json.dumps(b.get("as3") or {})})
    return out


def asset_dossier(store, asset_id: str) -> dict | None:
    assets = store.assets()
    by = {a["id"]: a for a in assets}
    a = by.get(asset_id)
    if not a:
        return None
    at, rels = a["attrs"], [r for r in store.rels() if asset_id in (r["src"], r["dst"])]
    addr = _addr(a)
    ip, port = (addr.rsplit(":", 1) + [None])[:2] if addr else (None, None)
    card, mcp = at.get("agent_card"), at.get("mcp")
    identity = {"name": a["name"], "key": a["key"], "kind": a["kind"], "kind_label": KIND_LABEL.get(a["kind"], a["kind"]),
                "protocol": PROTOCOL.get(a["kind"], at.get("protocol") or "—"), "address": addr, "ip": ip, "port": port,
                "dns_names": at.get("dns_names") or [], "fqdn": (at.get("dns_names") or [None])[0],
                "otel_service": at.get("otel_service"), "same_host_as": at.get("same_host_as") or [],
                "described_as": at.get("described_as") or []}
    # replicas / logical service membership
    replicas = [by[r["dst"]] for r in rels if r["kind"] == "has_replica" and r["src"] == asset_id and r["dst"] in by]
    service_of = [by[r["src"]] for r in rels if r["kind"] == "has_replica" and r["dst"] == asset_id and r["src"] in by]
    related_ids = {asset_id} | {x["id"] for x in replicas} | {x["id"] for x in service_of}
    # Wave 2A: a finding about an agent applies to every interface of the same canonical runtime instance
    from . import identity as _canonical
    view = _canonical.reconcile(store)
    ix = view["endpoint_index"].get(asset_id)
    if ix:
        related_ids |= {e for s_ in view["services"] if s_["id"] == ix["service_id"] for i in s_["instances"] if i["id"] == ix["instance_id"]
                        for e in i["endpoints"]}
    fs = [f for f in _findings(store) if related_ids & set(f["asset_ids"])]
    rules = {f["rule_id"] for f in fs}
    names = {a["name"], *(identity["dns_names"]), *(identity["described_as"]), *([identity["otel_service"]] if identity["otel_service"] else []),
             *[x["name"] for x in service_of]}
    pk = []
    for p in _packages(store):
        why = []
        if rules & set(p["rules"]):
            why.append("addresses " + ", ".join(sorted(rules & set(p["rules"]))))
        if names & set(p["services"]):
            why.append("lists this service as affected")
        if ip and ip in p["text"]:
            why.append(f"AS3 references {ip}")
        if why:
            pk.append({"id": p["id"], "kind": p["kind"], "title": p["title"], "why": why})
    comms = []
    for r in rels:
        other = by.get(r["dst"] if r["src"] == asset_id else r["src"], {})
        ing = [c for c in r["claims"] if c["source"] == "ingest"]
        last = ing[-1]["attrs"] if ing else {}
        comms.append({"id": r["id"], "kind": r["kind"], "direction": "outbound" if r["src"] == asset_id else "inbound",
                      "peer": {"id": other.get("id"), "name": other.get("name"), "key": other.get("key")},
                      "path": r["observed_path"], "status": r["status"], "calls": last.get("calls"), "tools": last.get("tools") or {},
                      "latency_ms": last.get("latency_ms"), "trace_ids": (last.get("trace_ids") or [])[:5],
                      "evidence_ids": sorted({c["evidence_id"] for c in r["claims"]}),
                      "trust": sorted({trust.rel_level(r["kind"], c["source"], c.get("method")) for c in r["claims"]})})
    claims = [{**c, "trust": trust.describe(c["source"], c.get("method"))} for c in a["claims"]]
    levels = sorted({c["trust"]["level"] for c in claims}, key=lambda k: -trust.LEVELS[k]["rank"])
    return {**a, "identity": identity, "relationships": rels, "claims": claims, "trust_levels": levels,
            "verified": any(trust.LEVELS[k]["verified"] for k in levels),
            "agent_card": card and {"name": card.get("name"), "description": card.get("description"), "version": card.get("version"),
                                    "skills": card.get("skills") or [], "advertised_urls": card.get("advertised_urls") or [],
                                    "security_schemes": card.get("security_schemes") or [], "streaming": card.get("streaming")},
            "mcp": mcp and {"server_name": mcp.get("server_name"), "server_version": mcp.get("server_version"),
                            "protocol_version": mcp.get("protocol_version"), "authenticated": mcp.get("authenticated"),
                            "toolset_fingerprint": mcp.get("toolset_fingerprint"),
                            "tools": [{"name": t.get("name"), "annotations": t.get("annotations") or {},
                                       "privileged": bool((t.get("annotations") or {}).get("destructiveHint") or (t.get("annotations") or {}).get("openWorldHint"))}
                                      for t in mcp.get("tools") or []]},
            "replicas": [{"id": x["id"], "name": x["name"], "key": x["key"]} for x in replicas],
            "service_of": [{"id": x["id"], "name": x["name"], "key": x["key"]} for x in service_of],
            "findings": [{"id": f["id"], "rule_id": f["rule_id"], "title": f["title"], "issue": f["issue"], "severity": f["severity"],
                          "class": f["class"], "class_label": f["class_label"], "domain": f["domain"], "package": f["package"],
                          "evidence_ids": f["evidence_ids"]} for f in fs],
            "communications": comms, "recommendations": pk}


def edge_dossier(store, rel_id: str) -> dict | None:
    rels = {r["id"]: r for r in store.rels()}
    r = rels.get(rel_id)
    if not r:
        return None
    by = {a["id"]: a for a in store.assets()}
    claims = [{**c, "trust": trust.describe(c["source"], c.get("method"))} for c in r["claims"]]
    ing = [c for c in r["claims"] if c["source"] == "ingest"]
    last = ing[-1]["attrs"] if ing else {}
    return {**r, "claims": claims,
            "from": {k: by.get(r["src"], {}).get(k) for k in ("id", "name", "key")}, "to": {k: by.get(r["dst"], {}).get(k) for k in ("id", "name", "key")},
            "protocol": r["kind"][6:] if r["kind"].startswith("calls_") else r["kind"],
            "observed": {k: last.get(k) for k in ("calls", "errors", "tools", "latency_ms", "latency_by_operation", "latency_source",
                                                  "mixed_operations", "peer_addresses", "replicas", "paths", "trace_count")},
            "trace_ids": last.get("trace_ids") or [], "evidence_ids": sorted({c["evidence_id"] for c in r["claims"]})}


def _needles(store, asset_id: str | None) -> set[str]:
    if not asset_id:
        return set()
    d = asset_dossier(store, asset_id)
    if not d:
        return set()
    out = set()
    for x in [d] + d["replicas"]:
        k = x["key"]
        if k.startswith("ep:"):
            hp = k.split(":", 1)[1]
            out |= {hp, hp.rsplit(":", 1)[0]}
    i = d["identity"]
    out |= {n for n in [i.get("otel_service"), *(i.get("dns_names") or [])] if n}
    if d.get("mcp") and d["mcp"].get("server_name"):
        out.add(d["mcp"]["server_name"])
    return {n for n in out if n and len(n) >= 4}


def _prune(node, needles: set[str]):
    """Keep only the sub-trees whose serialisation mentions a needle; dict keys that match keep their whole value."""
    def hit(x):
        s = json.dumps(x, default=str) if not isinstance(x, str) else x
        return any(n in s for n in needles)
    if isinstance(node, list):
        kept = [_prune(x, needles) for x in node if hit(x)]
        return kept
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if any(n in str(k) for n in needles):
                out[k] = v
            elif hit(v):
                out[k] = _prune(v, needles) if isinstance(v, (dict, list)) else v
        return out
    return node


def scoped_evidence(store, ev: dict, asset_id: str | None) -> dict:
    raw = json.loads(ev["raw"]) if isinstance(ev.get("raw"), str) else ev.get("raw")
    t = trust.describe(ev["source"], ev.get("method"))
    out = {**{k: v for k, v in ev.items() if k != "raw"}, "trust": t, "raw": raw, "raw_size": len(json.dumps(raw, default=str))}
    needles = _needles(store, asset_id)
    if asset_id and needles:
        sc = _prune(raw, needles)
        out.update(scoped={"asset_id": asset_id, "matched_on": sorted(needles), "content": sc,
                           "size": len(json.dumps(sc, default=str))})
    return out


# ------------------------------------------------------------------ assessment profiles & comparability
def assessment_profile(store, aid: str) -> dict:
    row = store.db.execute("SELECT * FROM assessment WHERE id=?", (aid,)).fetchone()
    if not row:
        return {}
    src = {r["source"]: {"evidence": r["n"], "last": r["last"]} for r in store.db.execute(
        "SELECT source, COUNT(*) n, MAX(collected_at) last FROM evidence WHERE assessment_id=? GROUP BY source", (aid,))}
    cnt = lambda t: store.db.execute(f"SELECT COUNT(*) FROM {t} WHERE assessment_id=?", (aid,)).fetchone()[0]
    technical = [s for s in ("observe", "enumerate", "ingest") if s in src]
    vs = store.db.execute("SELECT COUNT(*) FROM asset WHERE assessment_id=? AND kind='bigip_virtual'", (aid,)).fetchone()[0]
    ai = store.db.execute("SELECT COUNT(*) FROM asset WHERE assessment_id=? AND kind IN ('a2a_agent','mcp_server') AND key LIKE 'ep:%'",
                          (aid,)).fetchone()[0]
    # infrastructure state at the time of this assessment: from Observe (BIG-IP config) and validation labels, never assumed
    labels = [r["label"] for r in store.db.execute("SELECT label FROM validation_run WHERE assessment_id=? ORDER BY started", (aid,))]
    infra = ("unknown — Observe not run" if "observe" not in src else
             "baseline (no virtual servers)" if vs == 0 else f"F5 in path ({vs} virtual servers)")
    deps = [dict(r) for r in store.db.execute(
        "SELECT d.id, d.status, d.started, d.finished, p.kind FROM deployment d LEFT JOIN package p ON p.id=d.package_id "
        "WHERE d.assessment_id=? ORDER BY d.started", (aid,))]
    complete = len(technical) == 3
    return {"id": aid, "name": row["name"], "created": row["created"], "status": row["status"], "sources": src,
            "technical_sources": technical, "discovery": "complete" if complete else "partial" if technical else "none",
            "counts": {"evidence": cnt("evidence"), "assets": cnt("asset"), "findings": cnt("finding"), "packages": cnt("package"),
                       "validations": len(labels)},
            "ai_endpoints": ai, "virtual_servers": vs if "observe" in src else None, "infra_state": infra, "validation_labels": labels,
            "deployments": deps, "succeeded_deployments": [d for d in deps if d["status"] == "succeeded"]}


def comparability(store, before: str, after: str) -> dict:
    """Classify a before/after pair. Only 'verified' comparisons may be presented as F5 impact."""
    b, a = assessment_profile(store, before), assessment_profile(store, after)
    reasons, kind = [], "verified"
    if not b or not a:
        return {"status": "invalid", "label": "Unknown assessment", "reasons": ["one of the assessments does not exist"], "claims_allowed": False}
    if before == after:
        return {"status": "invalid", "label": "Same assessment", "reasons": ["before and after are the same assessment"], "claims_allowed": False,
                "before": b, "after": a}
    if b["created"] > a["created"]:
        reasons.append("'before' was created after 'after' — the order is reversed")
        kind = "invalid"
    if b["discovery"] == "none" or a["discovery"] == "none":
        reasons.append("one side has no technical discovery evidence — a change in findings would only reflect discovery coverage")
        kind = "invalid" if kind != "invalid" else kind
    missing = sorted(set(b["technical_sources"]) ^ set(a["technical_sources"]))
    if missing and kind == "verified":
        reasons.append(f"discovery coverage differs ({', '.join(missing)} ran on only one side) — exploratory comparison only")
        kind = "exploratory"
    discovered_at = (a["sources"].get("observe") or {}).get("last") or max(
        (v.get("last") or 0 for v in a["sources"].values()), default=0) or None
    linked = [d for d in store.db.execute(
        "SELECT d.id, d.status, d.started, p.kind FROM deployment d LEFT JOIN package p ON p.id=d.package_id WHERE d.started >= ? AND d.started <= ?",
        (b["created"], discovered_at or a["created"] + 10 ** 9)).fetchall()]
    prot = verification.protection_from_store(store)
    place = {d["kind"]: d for d in prot["in_place"]}
    ok = []
    for d in (dict(x) for x in linked if x["status"] == "succeeded"):
        now = place.get(d["kind"] or "delivery")
        d["in_place"] = bool(now and now["id"] == d["id"])
        d["now"] = ("in place" if d["in_place"] else f"superseded by {now['id']} ({d['kind'] or 'delivery'}, in place)" if now
                    else "no longer in place (rolled back, reset or replaced)")
        ok.append(d)
    post = [{"id": d["id"], "kind": d["kind"], "started": d["started"]} for d in prot["in_place"]
            if discovered_at and (d["started"] or 0) > discovered_at]
    if kind == "verified" and not ok:
        reasons.append("no successful, linked F5 deployment between the two assessments — differences are not F5 impact")
        kind = "exploratory"
    if kind == "verified" and a["infra_state"] == b["infra_state"]:
        reasons.append("Observe shows the same BIG-IP state on both sides")
        kind = "exploratory"
    label = {"verified": "Verified before/after (linked deployment, comparable discovery)",
             "exploratory": "Exploratory comparison — not evidence of F5 impact",
             "invalid": "Not comparable"}[kind]
    hm = lambda t: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "unknown"  # noqa: E731
    if kind == "verified":
        reasons.append("linked successful deployment(s) — the state the 'after' discovery observed: "
                       + "; ".join(f"{d['id']} ({d['kind'] or 'delivery'}, {hm(d['started'])}) — {d['now']}" for d in ok)
                       + "; discovery coverage identical")
    if post:
        reasons.append(f"the 'after' discovery ({hm(discovered_at)}) predates protection now in place: "
                       + "; ".join(f"{d['kind']} {d['id']} deployed {hm(d['started'])}" for d in post)
                       + " — its effect is not in this discovery. Findings it addresses are reported as 'awaiting rediscovery', "
                         "never as resolved; run a new discovery to measure it.")
        if kind == "verified":
            label = f"Verified before/after for the state discovered at {hm(discovered_at)} — newer protection not yet rediscovered"
    if not prot["verified"] and prot["state"] not in ("none",):
        reasons.append(f"the effective deployment state is '{prot['state']}' (not verified) — no protection is claimed as in place")
    return {"status": kind, "label": label, "reasons": reasons, "claims_allowed": kind == "verified",
            "linked_successful_deployments": ok, "after_discovered_at": discovered_at, "post_discovery_deployments": post,
            "before": b, "after": a}


def suggest_pairs(store, profiles: list[dict]) -> list[dict]:
    """Suggest meaningful pairs: consecutive complete-discovery assessments with a successful deployment in between."""
    full = sorted([p for p in profiles if p.get("discovery") == "complete"], key=lambda p: p["created"])
    out = []
    for i in range(len(full) - 1):
        c = comparability(store, full[i]["id"], full[i + 1]["id"])
        if c["status"] != "invalid":
            out.append({"before": full[i]["id"], "after": full[i + 1]["id"], "status": c["status"], "label": c["label"]})
    return list(reversed(out))[:5]
