"""Wave 3 M2 — read-only placement advisory: VIP candidates, configuration provenance, identity mapping, package comparison.

Built on the M1 placement engine (placement.py). Pure functions plus SELECT-only adapters over stored evidence:
  * no network access, no LLM, no writes to the store;
  * never generates, modifies or approves a package — the existing package is only READ for comparison;
  * VIP candidates are UNRESERVED. They are UNVERIFIED unless authoritative IPAM evidence says the address is available
    (and even then they stay unreserved: nothing here reserves an address). Active ARP/ICMP or DNS checks are never run.

Every proposed value carries provenance: {object, value, source, status, evidence_ids, rule}, with status one of
observed | inferred | configured | unknown (as in placement.py), plus `unverified` for values on an unverified target.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re

from . import placement, placement_policy

LEGACY_SESSION_BEFORE = "2026-07-28"     # MCP protocol versions older than this need Mcp-Session-Id persistence (as packages.py)
TEMPLATE = {
    "a2a_agent": {"pattern": "a2a-delivery", "monitor": "mon_a2a",
                  "monitor_detail": 'HTTP GET /.well-known/agent-card.json, expect "skills"', "protocol_basis": "Agent Card"},
    "mcp_server": {"pattern": "mcp-delivery", "monitor": "mon_mcp",
                   "monitor_detail": 'HTTP POST /mcp server/discover, expect "capabilities"', "protocol_basis": "MCP initialize"},
}
NOT_CHECKED = ["forward/reverse DNS for the address (no stored DNS evidence for VIPs)",
               "ARP / ICMP liveness (an active network action — not performed)"]


def _p(obj: str, value, source: str, status: str, evidence_ids=(), rule: str | None = None, **extra) -> dict:
    assert status in ("observed", "inferred", "configured", "unknown", "unverified")
    return {"object": obj, "value": value, "source": source, "status": status, "evidence_ids": sorted(set(evidence_ids)),
            "rule": rule, **extra}


def app_name(svc: dict, naming: dict | None = None) -> str:
    """AS3 application name (naming strategy v1, documented in doc 19):
      MCP  mcp_<server name>                                   (as packages.py)
      A2A  a2a_<slug of the endpoint asset name>, where the endpoint is the one the Agent Card advertises, else the lowest
           endpoint address (as packages.py, which names the agent after its client-facing endpoint asset);
           falls back to the canonical service name when no asset name is known."""
    if svc["kind"] == "mcp_server":
        return f"mcp_{svc['name'].replace('-', '_')}"
    base = (naming or {}).get(svc["id"]) or svc["name"] or ""
    return "a2a_" + re.sub(r"[^a-z0-9]+", "_", base.lower())[:40]


# --------------------------------------------------------------------------------------------- environment (configured)
def environment_from_cfg(cfg: dict) -> dict:
    """The approved environment configuration for the lab: VIP pool = the deployer's VIP allow-list (read, not changed),
    front-door assignments, TLS objects and tenant from autopilot.yaml design."""
    from .deployer import policy
    d = cfg.get("design") or {}
    mgmt = (cfg.get("observe") or {}).get("bigip_mgmt")
    fd = json.loads(json.dumps(d.get("front_doors") or {}))
    base_dns = (((d.get("profiles") or {}).get("baseline") or {}).get("dns") or {})
    if fd.get("a2a"):
        fd["a2a"]["backend_hint"] = base_dns.get(fd["a2a"].get("name"))
        fd["a2a"]["backend_hint_source"] = "autopilot.yaml design.profiles.baseline.dns"
    fd["source"] = "autopilot.yaml design.front_doors"
    return {"tenant": d.get("tenant"), "port": 443,
            "vip_pools": [{"device": f"bigip:{mgmt}", "network": str(policy.VIP_RANGE),
                           "source": "deployer policy VIP_RANGE (the approved VIP allow-list; read-only)"}],
            "tls": {"certificate": d.get("cert_object"), "key": d.get("key_object"), "ca_bundle": d.get("ca_bundle_object"),
                    "source": "autopilot.yaml design"},
            "front_doors": fd, "source": "autopilot.yaml + deployer policy (configured)"}


def _assignment(svc: dict, env: dict) -> dict | None:
    fd = env.get("front_doors") or {}
    if svc["kind"] == "mcp_server":
        m = (fd.get("mcp") or {}).get(svc["name"])
        if m:
            return {"vip": m["vip"], "name": m.get("name"), "source": f"{fd.get('source', 'environment')}.mcp.{svc['name']}",
                    "basis": f"keyed by the MCP server name '{svc['name']}' reported in initialize"}
    if svc["kind"] == "a2a_agent" and fd.get("a2a"):
        hint = fd["a2a"].get("backend_hint")
        ips = {e["address"].rpartition(":")[0] for e in svc["endpoints"]}
        if hint and hint in ips:
            return {"vip": fd["a2a"]["vip"], "name": fd["a2a"].get("name"), "source": f"{fd.get('source', 'environment')}.a2a",
                    "basis": f"front-door name {fd['a2a'].get('name')} resolves to {hint} (a {svc['name']} endpoint) in "
                             f"{fd['a2a'].get('backend_hint_source', 'the environment')}"}
    return None


# --------------------------------------------------------------------------------------------- VIP candidates (W3-04, no IPAM)
def _occupancy(identity: dict, devices: list[dict]) -> dict[str, list[str]]:
    occ: dict[str, list[str]] = {}
    for d in devices:
        for v in d["virtuals"]:
            if v.get("address"):
                occ.setdefault(v["address"], []).append(f"virtual server {v['name']} ({v['address']}:{v.get('port')}) on {d['id']}")
        for s in d["self_ips"]:
            occ.setdefault(s["address"], []).append(f"self IP {s['name']} on {d['id']}")
    for s in identity["services"]:
        for e in s["endpoints"]:
            occ.setdefault(e["address"].rpartition(":")[0], []).append(f"discovered endpoint {e['address']} ({s['name']})")
    return occ


def _ipam_check(ip: str, ipam: dict | None) -> dict:
    if not ipam or not ipam.get("authoritative"):
        return placement._check("ipam", "unknown", "unknown", "no authoritative IPAM — availability not verified"
                                + (f" ({ipam.get('provider')} is not authoritative)" if ipam else ""))
    ev = [ipam.get("evidence_id")] if ipam.get("evidence_id") else []
    if ip in (ipam.get("allocated") or {}):
        return placement._check("ipam", "fail", "observed", f"allocated in {ipam['provider']} to {ipam['allocated'][ip]}", ev)
    a = ipaddress.ip_address(ip)
    if any(a in ipaddress.ip_network(n, strict=False) for n in ipam.get("available") or []):
        return placement._check("ipam", "pass", "observed", f"available in {ipam['provider']} (not reserved by Autopilot)", ev)
    return placement._check("ipam", "unknown", "observed", f"{ipam['provider']} has no record for {ip}", ev)


def _subnet_check(ip: str, d: dict) -> dict:
    a = ipaddress.ip_address(ip)
    known = [s for s in d["self_ips"] if s["network"]["status"] == "observed"]
    for s in known:
        if a in ipaddress.ip_network(s["network"]["value"]):
            return placement._check("on_device_subnet", "pass", "inferred", f"inside self IP subnet {s['network']['value']} ({s['name']})",
                                    [d["evidence_id"]])
    if len(known) < len(d["self_ips"]):
        return placement._check("on_device_subnet", "unknown", "unknown", "self IP subnets not recorded — cannot tell whether clients reach it")
    return placement._check("on_device_subnet", "unknown", "inferred", "not on a self IP subnet — needs upstream routing to the device "
                            "(not verifiable from evidence)", [d["evidence_id"]])


def _vip_for(svc: dict, d: dict, env: dict, occ: dict, taken: dict, ipam: dict | None, device_verified: bool,
            devs_all: list | None = None) -> dict:
    devs_all = devs_all or [d]
    pools = [p for p in env.get("vip_pools") or [] if p["device"] == d["id"]]
    asg = _assignment(svc, env)
    out = {"device": d["id"], "port": env.get("port", 443), "reservation": "unreserved", "not_checked": NOT_CHECKED, "skipped": [],
           "assignment": asg}
    if not pools:
        return {**out, "address": None, "verification": "none", "label": "No VIP candidate",
                "reason": f"no approved VIP pool is configured for {d['id']}"}
    nets = [ipaddress.ip_network(p["network"]) for p in pools]
    order = []
    if asg:
        if any(ipaddress.ip_address(asg["vip"]) in n for n in nets):
            order.append((asg["vip"], f"configured assignment {asg['source']}", "configured"))
        else:
            out["skipped"].append({"address": asg["vip"], "reasons": [f"configured assignment {asg['source']} is outside {d['id']}'s approved pool"]})
    for p, n in zip(pools, nets):
        for h in n.hosts():
            order.append((str(h), f"lowest free address in approved pool {n} ({p['source']})", "configured"))
    seen = set()
    for ip, src, st in order:
        if ip in seen:
            continue
        seen.add(ip)
        checks = [placement._check("approved_pool", "pass", "configured", f"inside {', '.join(str(n) for n in nets if ipaddress.ip_address(ip) in n)}")]
        blind = [x["id"] for x in devs_all if x.get("virtuals_state", "observed") != "observed"]
        if ip in occ:
            checks.append(placement._check("address_conflict", "fail", "observed", "in use: " + "; ".join(occ[ip]),
                                           [d["evidence_id"]]))
        elif blind:
            checks.append(placement._check("address_conflict", "unknown", "unknown",
                                           "virtual servers not collected on " + ", ".join(blind) + " — a conflict with an existing "
                                           "virtual server cannot be excluded (self IPs and discovered endpoints checked)",
                                           evidence_state="missing"))
        else:
            checks.append(placement._check("address_conflict", "pass", "observed",
                                           "not used by any virtual server or self IP on registered devices, nor by a discovered endpoint"))
        if ip in taken:
            checks.append(placement._check("not_assigned_elsewhere", "fail", "configured", taken[ip]))
        else:
            checks.append(placement._check("not_assigned_elsewhere", "pass", "configured", "not assigned to another service"))
        checks.append(_ipam_check(ip, ipam))
        checks.append(_subnet_check(ip, d))
        bad = [c for c in checks if c["result"] == "fail"]
        if bad:
            if len(out["skipped"]) < 8:
                out["skipped"].append({"address": ip, "reasons": [c["detail"] for c in bad]})
            continue
        confirmed = device_verified and all(c["result"] == "pass" for c in checks)
        verification = "ipam-confirmed-available" if confirmed else "unverified"
        label = ("Proposed VIP candidate — unreserved; IPAM reports it available" if confirmed else
                 "Proposed VIP candidate — unreserved, unverified")
        return {**out, "address": ip, "source": src, "status": st, "verification": verification, "label": label, "checks": checks,
                "uncertainty": [c["detail"] for c in checks if c["result"] == "unknown"]}
    return {**out, "address": None, "verification": "none", "label": "No VIP candidate",
            "reason": f"every address in the approved pool(s) of {d['id']} conflicts or is assigned"}


# --------------------------------------------------------------------------------------------- per-service proposal + provenance
def _provisional_members(ev: dict) -> list[dict]:
    """On an unverified device: per instance, the interface the M1 preference order would choose among interfaces whose
    reachability is not FAILED (unknown allowed). Labelled provisional."""
    out = []
    for m in ev["members"]:
        if m["chosen"]:
            out.append({**m["chosen"], "provisional": False})
            continue
        opts = [o for o in m["interfaces"] if o["reach"]["result"] != "fail"]
        if not opts:
            out.append({"address": None, "why": ["no interface the device could reach"], "provisional": True})
            continue
        opts.sort(key=lambda o: (o["reach"]["via"] != "direct", o["in_member_policy"] is False, o["on_caller_subnet"], placement._ipkey(o["address"])))
        why = ["provisional — reachability not established"]
        if len(opts) > 1:
            why.append("same interface preference as a verified placement (direct, member range, not on caller subnet, lowest address)")
        out.append({"address": opts[0]["address"], "why": why, "provisional": True})
    return out


def _persistence(svc: dict, members: list[dict], versions: list[str]) -> dict:
    ev = svc["evidence_ids"]
    if svc["kind"] != "mcp_server":
        return _p("persistence", None, "template a2a-delivery", "configured", rule="A2A front doors carry no session persistence")
    if len([m for m in members if m.get("address")]) < 2:
        return _p("persistence", None, "template mcp-delivery", "configured", rule="single pool member — persistence not needed")
    if not versions:
        return _p("persistence", "undetermined", "telemetry", "unknown", ev,
                  "MCP protocol versions not recorded by telemetry — whether Mcp-Session-Id persistence is needed is unknown")
    legacy = sorted(v for v in versions if v < LEGACY_SESSION_BEFORE)
    if legacy:
        return _p("persistence", "universal (Mcp-Session-Id iRule)", "telemetry: observed MCP protocol versions", "observed", ev,
                  f"replicated MCP service with session-based protocol version(s) {', '.join(legacy)} (< {LEGACY_SESSION_BEFORE})")
    return _p("persistence", None, "telemetry: observed MCP protocol versions", "observed", ev,
              f"all observed versions ({', '.join(sorted(versions))}) are stateless — no persistence")


def _proposal(svc: dict, ev: dict, device: dict, verified: bool, env: dict, vip: dict, rec: dict, versions: list[str],
              naming: dict | None = None) -> dict:
    members = [{**m, "provisional": False} for m in (rec["selected"]["pool_members"] if verified else [])] or _provisional_members(ev)
    tpl = TEMPLATE[svc["kind"]]
    st = "inferred" if verified else "unverified"
    tls = env.get("tls") or {}
    prov = [
        _p("target_bigip", device["id"], "placement engine (Wave 3 M1)", st, [device["evidence_id"]],
           "; ".join(rec["selected"]["why"]) if verified else "unverified candidate — " + "; ".join(
               c["detail"] for c in ev["checks"] if c["result"] == "unknown"), hostname=device["hostname"]["value"]),
        _p("tenant", env.get("tenant"), env.get("source", "environment"), "configured"),
        _p("application", app_name(svc, naming), f"template {tpl['pattern']} naming", "configured", rule="pattern-library naming from the service name"),
        _p("virtual_address", vip.get("address"), vip.get("source") or vip.get("reason") or "none",
           "configured" if vip.get("address") else "unknown", rule=vip.get("label"), reservation="unreserved",
           verification=vip.get("verification")),
        _p("virtual_port", env.get("port", 443), f"template {tpl['pattern']} (HTTPS front door)", "configured"),
        *[_p("pool_member", m.get("address"), "discovered: Enumerate / Ingest endpoint evidence",
             "unverified" if m.get("provisional") else "observed", svc["evidence_ids"], "; ".join(m.get("why") or []))
          for m in members],
        _p("monitor", tpl["monitor"], f"template {tpl['pattern']}", "configured", svc["evidence_ids"],
           f"{tpl['monitor_detail']} — chosen because the service speaks {svc['classification']} ({tpl['protocol_basis']} observed)"),
        _persistence(svc, members, versions),
        _p("tls_client_side", f"tls_server (certificate {tls.get('certificate')})", tls.get("source", "environment"), "configured",
           rule="AI Delivery stage: TLS with the approved certificate; " + (
               f"the AI Security stage replaces it with tls_server_mtls (client certificates from {tls.get('ca_bundle')})"
               if svc["kind"] == "mcp_server" else "A2A front doors keep server TLS in the AI Security stage (mTLS applies to MCP)")),
        _p("server_side", "HTTP to pool members (no server-side TLS profile)", f"template {tpl['pattern']}", "configured",
           rule="members are reached at the discovered address:port"),
        _p("snat", "auto", "deployer policy (snat must be auto)", "configured"),
    ]
    return {"device": device["id"], "status": "selected" if verified else "provisional", "application": app_name(svc, naming),
            "virtual_server": f"{vip['address']}:{vip['port']}" if vip.get("address") else None,
            "pool_members": [m.get("address") for m in members], "monitor": tpl["monitor"],
            "persistence": next(x for x in prov if x["object"] == "persistence")["value"], "vip": vip, "provenance": prov}


# --------------------------------------------------------------------------------------------- package comparison (read-only)
def _pkg_device_matches(target: str, device: dict) -> bool:
    mg = device["mgmt"]["value"]
    return bool(mg) and re.search(rf"(^|\s){re.escape(mg)}(\s|$)", target or "") is not None


def compare(proposals: list[dict], packages: list[dict], devices: list[dict]) -> dict:
    """Disagreements between the advisory and the current configured packages. Packages are only read."""
    devs = {d["id"]: d for d in devices}
    by_service = {p["service"]["id"]: p for p in proposals}
    rows, agreements, matched = [], 0, set()
    for pkg in packages:
        kind = pkg["kind"]
        for a in (pkg["body"].get("architecture") or []):
            pm = set(a["pool_members"])
            cand = [p for p in proposals if pm & set(p["service"]["endpoints"])] or [p for p in proposals if (p.get("proposal") or {}).get("application") == a["application"]]
            if not cand:
                rows.append({"package": kind, "application": a["application"], "service": None, "field": "service",
                             "package_value": a["virtual_server"], "advisory_value": None, "kind": "not_in_advisory",
                             "explanation": "no canonical A2A/MCP service in the advisory maps to this package application"})
                continue
            p = cand[0]
            matched.add(p["service"]["id"])
            prop = p.get("proposal")
            if not prop:
                rows.append({"package": kind, "application": a["application"], "service": p["service"]["name"], "field": "placement",
                             "package_value": a["virtual_server"], "advisory_value": p["decision"], "kind": "advisory_does_not_place",
                             "explanation": f"advisory decision is '{p['decision']}' ({'; '.join(p.get('reasons') or []) or 'see placement'})"})
                continue
            tgt_ok = _pkg_device_matches(pkg["target"], devs[prop["device"]])
            # AI Security (mcp-security) adds mTLS on MCP front doors only; A2A front doors keep server TLS in both stages
            exp_tls = "tls_server_mtls" if kind == "security" and p["service"]["kind"] == "mcp_server" else "tls_server"
            fields = [
                ("target_bigip", pkg["target"], f"{prop['device']} ({prop['status']})", tgt_ok and prop["status"] == "selected",
                 "advisory abstains: the package's target is not verified by evidence" if tgt_ok and prop["status"] != "selected"
                 else "different target device" if not tgt_ok else ""),
                ("virtual_server", a["virtual_server"], prop["virtual_server"], a["virtual_server"] == prop["virtual_server"], ""),
                ("pool_members", sorted(a["pool_members"]), sorted(x for x in prop["pool_members"] if x), sorted(a["pool_members"]) == sorted(x for x in prop["pool_members"] if x), ""),
                ("monitor", a["monitor"], prop["monitor"], a["monitor"] == prop["monitor"], ""),
                ("persistence", a["persistence"], bool(prop["persistence"]) if prop["persistence"] != "undetermined" else "undetermined",
                 prop["persistence"] != "undetermined" and a["persistence"] == bool(prop["persistence"]), ""),
                ("tls", a["tls"], exp_tls, a["tls"] == exp_tls, ""),
            ]
            if a["application"] != prop["application"]:
                rows.append({"package": kind, "application": a["application"], "service": p["service"]["name"], "field": "application",
                             "package_value": a["application"], "advisory_value": prop["application"], "kind": "naming",
                             "explanation": "same service, different AS3 application name (informational; matched by pool members)"})
            for f, pv, av, ok, why in fields:
                if ok:
                    agreements += 1
                    continue
                k = "advisory_abstains" if f == "target_bigip" and tgt_ok else "difference"
                rows.append({"package": kind, "application": a["application"], "service": p["service"]["name"], "field": f,
                             "package_value": pv, "advisory_value": av, "kind": k,
                             "explanation": why or ("advisory value is provisional (target unverified)" if prop["status"] != "selected" else "")})
    for p in proposals:
        if p["eligibility"] == "eligible" and p["service"]["id"] not in matched and packages:
            rows.append({"package": "all", "application": None, "service": p["service"]["name"], "field": "service",
                         "package_value": None, "advisory_value": (p.get("proposal") or {}).get("virtual_server") or p["decision"],
                         "kind": "missing_from_package",
                         "explanation": "eligible canonical service has no virtual server in the current package"})
    return {"packages_compared": [{"id": x["id"], "kind": x["kind"], "target": x["target"]} for x in packages],
            "agreements": agreements, "disagreements": rows,
            "note": "comparison only — the configured packages, their approvals and the deployer are not modified"}


# --------------------------------------------------------------------------------------------- advisory
def advise(identity: dict, devices: list[dict], env: dict, *, callers=None, telemetry=None, packages=(), ipam=None,
           preferences=None, member_policy=None, policy=None, now=None, deploy_targets=None, naming=None) -> dict:
    pol = policy or placement_policy.load()
    plc = placement.evaluate(identity, devices, callers=callers, preferences=preferences, member_policy=member_policy, policy=pol, now=now)
    svcs = {s["id"]: s for s in identity["services"]}
    devs = {d["id"]: d for d in devices}
    versions = (telemetry or {}).get("mcp_protocol_versions") or {}
    occ = _occupancy(identity, devices)
    taken: dict[str, str] = {}
    for s in identity["services"]:          # configured front-door VIPs are reserved for the service they are assigned to
        a = _assignment(s, env) if s["kind"] in placement.PLACEABLE else None
        if a:
            taken.setdefault(a["vip"], f"configured for {s['name']} ({a['source']})")
    engine_targets = sorted(deploy_targets or [])

    def support(dev_id: str) -> dict:
        mg = devs[dev_id]["mgmt"]["value"]
        ok = bool(mg) and mg in engine_targets
        return {"supported": ok, "status": "configured",
                "detail": ("Autopilot's deployment engine targets this device — deployment still needs approval, preview, diff and "
                           "on-device preflight" if ok else
                           "advisory only — Autopilot's deployment engine cannot deploy to this device (it targets "
                           + (", ".join(engine_targets) or "no device") + ")")}
    proposals, mappings = [], []
    for rec in plc["services"]:
        svc = svcs[rec["service"]["id"]]
        out = {"service": rec["service"], "eligibility": rec["eligibility"], "decision": rec["decision"],
               "reasons": rec["eligibility_reasons"] + ([rec["decision_reason"]] if rec.get("decision_reason") else []),
               "uncertainty": rec["uncertainty"], "coverage": rec["coverage"], "proposal": None, "alternatives": []}
        targets = ([(rec["selected"]["device"], True)] if rec["decision"] == "selected" else
                   [(e["device"], False) for e in rec["unverified"]] if rec["decision"] == "abstain" else [])
        for i, (dev_id, verified) in enumerate(targets):
            ev = next(e for e in rec["eligible"] + rec["unverified"] if e["device"] == dev_id)
            own = {k: v for k, v in taken.items() if not v.startswith(f"configured for {svc['name']} ")}
            vip = _vip_for(svc, devs[dev_id], env, occ, own, ipam, verified, devices)
            prop = _proposal(svc, ev, devs[dev_id], verified, env, vip, rec, versions.get(svc["id"]) or [], naming)
            prop["deployment_engine"] = support(dev_id)
            if i == 0:
                out["proposal"] = prop
                if vip.get("address"):
                    taken.setdefault(vip["address"], f"proposed for {svc['name']} in this advisory")
            else:
                out["alternatives"].append(prop)
        proposals.append(out)
        sel = {m for m in ((out["proposal"] or {}).get("pool_members") or []) if m}
        mappings.append({"service": {k: svc[k] for k in ("id", "name", "kind", "classification", "grouping", "confidence")},
                         "instances": [{"label": i["label"], "status": i["status"], "endpoints": [
                             {"address": e["address"], "role": e["role"], "membership": e["membership"], "proposed_member": e["address"] in sel}
                             for e in svc["endpoints"] if e["instance_id"] == i["id"]]} for i in svc["instances"]],
                         "proposed": ({"status": out["proposal"]["status"], "device": out["proposal"]["device"],
                                       "application": out["proposal"]["application"], "virtual_server": out["proposal"]["virtual_server"],
                                       "pool_members": out["proposal"]["pool_members"]} if out["proposal"] else
                                      {"status": "already_covered", "existing": rec["coverage"]} if rec["eligibility"] == "already_covered" else
                                      {"status": rec["decision"] if rec["eligibility"] == "eligible" else rec["eligibility"], "reasons": out["reasons"]})})
    res = {
        "advisory": True, "deployable": False, "deployment_readiness": placement.NOT_PREFLIGHT, "evaluated_at": plc["evaluated_at"],
        "engine": {**placement.ENGINE, "name": "placement-advisory", "version": "w3-m2"},
        "assessment_id": identity.get("assessment_id"), "status": plc["status"], "summary": plc["summary"],
        "health_policy": plc["limits"]["health_policy"],
        "ipam": ({"provider": ipam.get("provider"), "authoritative": bool(ipam.get("authoritative")), "evidence_id": ipam.get("evidence_id")}
                 if ipam else {"provider": None, "authoritative": False,
                               "statement": "No authoritative IPAM is configured: every VIP is an unreserved, unverified candidate."}),
        "environment": {k: env.get(k) for k in ("tenant", "port", "vip_pools", "tls", "front_doors", "source")},
        "deployment_engine": {"targets": engine_targets, "source": "deployer configuration (observe.bigip_mgmt, pinned certificate); read-only",
                              "statement": "Eligible for a placement recommendation is not the same as supported by the deployment "
                                           "engine: only the listed device(s) can be deployed to by Autopilot.",
                              "devices": {d["id"]: support(d["id"]) for d in devices}},
        "proposals": proposals, "mappings": mappings,
        "comparison": compare(proposals, list(packages), devices),
        "placement": plc,
        "notices": ["Advisory only: not a package, not approved, never sent to a device.",
                    "Evidence: stored discovery and Observe records only — no network access was made to produce this view.",
                    "VIP candidates are unreserved; Autopilot does not reserve addresses."],
    }
    res["digest"] = hashlib.sha256(json.dumps(res, sort_keys=True, default=str).encode()).hexdigest()
    return res


# --------------------------------------------------------------------------------------------- stored-evidence adapter (read-only)
def telemetry_from_store(store, identity: dict) -> dict:
    idx = identity["endpoint_index"]
    out: dict[str, set] = {}
    for r in store.rels(identity["assessment_id"]):
        if r["kind"] == "calls_mcp" and r["dst"] in idx:
            for c in r["claims"]:
                out.setdefault(idx[r["dst"]]["service_id"], set()).update(str(v) for v in c["attrs"].get("mcp_protocol_versions") or [])
    return {"mcp_protocol_versions": {k: sorted(v) for k, v in out.items()}}


def naming_from_store(store, identity: dict) -> dict:
    """service id -> asset name used for the A2A application name (strategy v1, see app_name)."""
    assets = {a["id"]: a for a in store.assets(identity["assessment_id"])}
    out = {}
    for s in identity["services"]:
        if s["kind"] != "a2a_agent" or not s["endpoints"]:
            continue
        adv = set()
        for aid in s["asset_ids"]:
            card = (assets.get(aid) or {}).get("attrs", {}).get("agent_card") or {}
            for u in card.get("advertised_urls") or []:
                m = re.match(r"^https?://([^/]+)", str(u))
                if m:
                    adv.add(m.group(1))
        eps = sorted(s["endpoints"], key=lambda e: placement._ipkey(e["address"]))
        pick = next((e for e in eps if e["address"] in adv), eps[0])
        name = (assets.get(pick["asset_id"]) or {}).get("name")
        if name:
            out[s["id"]] = name
    return out


def packages_from_store(store, aid: str) -> list[dict]:
    return [{"id": r["id"], "kind": r["kind"], "title": r["title"], "target": r["target"], "body": json.loads(r["body"])}
            for r in store.db.execute("SELECT id, kind, title, target, body FROM package WHERE assessment_id=? ORDER BY created", (aid,))]


def build(store, cfg: dict, aid: str | None = None, *, extra_devices=None, environment=None, ipam=None, preferences=None,
          now=None) -> dict:
    """The advisory for one assessment from stored evidence. SELECT-only."""
    from . import identity as ident
    from .deployer import policy
    aid = aid or store.current()["id"]
    idn = ident.reconcile(store, aid)
    devs = placement.devices_from_store(store, cfg, aid) + list(extra_devices or [])
    return advise(idn, devs, environment or environment_from_cfg(cfg), callers=placement.callers_from_store(store, idn),
                  telemetry=telemetry_from_store(store, idn), packages=packages_from_store(store, aid), ipam=ipam,
                  preferences=preferences, member_policy=[str(policy.MEMBER_RANGE)], policy=placement_policy.load(cfg), now=now,
                  deploy_targets=[m for m in [(cfg.get("observe") or {}).get("bigip_mgmt")] if m], naming=naming_from_store(store, idn))
