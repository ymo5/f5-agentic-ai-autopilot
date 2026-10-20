"""Wave 3 M1 — deterministic, evidence-based BIG-IP placement (offline, advisory only).

Pure functions over STORED evidence and offline fixtures. Nothing here opens a network connection, calls an LLM, writes to
the store, or feeds package generation or the deployer: the result is a recommendation record for human review.

Information status, never conflated:
  observed    read from stored evidence (a device's Observe model; Enumerate/Ingest for services)
  inferred    derived by a stated deterministic rule from observed facts only (e.g. subnet containment)
  configured  declared in configuration or by the customer (autopilot.yaml design, preferences) — shown, never proof
  unknown     not present in the evidence

Strict rule: a device is ELIGIBLE for a service only when every hard check passes on observed/inferred facts. A check that
has no facts (or only configured ones) is UNKNOWN. A device with no failed check but at least one unknown check is an
UNVERIFIED candidate — listed unranked, never selected. A service with no eligible device gets an ABSTAIN decision.

Hard checks (per device): LTM provisioned, AS3 available, HA failover state usable, health within the versioned placement
health policy (placement_policy.py — aligned with the deployer's preflight; warnings rank a device lower, never reject it).
Hard check (per service x device): every runtime instance of the service has at least one interface the device reaches —
directly (a self IP subnet in route domain 0 contains it) or through a specific static route whose gateway is on a self IP
subnet. The management address never counts, and a default route alone does not establish reachability.

Ranking among eligible devices is lexicographic, in this order (each step is reported):
  1. customer preference (configured; a preference, not evidence)
  2. all chosen pool members directly connected (no routed members)
  3. fewer health-policy warnings
  4. co-location: existing virtual servers on the device that already front related services
  5. headroom proxy: fewer existing virtual servers
  6. device id (final deterministic tie-break)
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time

from . import placement_policy

ENGINE = {"name": "placement", "version": "w3-m1", "llm": False, "network": False, "advisory_only": True}
PLACEABLE = {"a2a_agent", "mcp_server"}
MEMBER_ROUTE_DOMAIN = 0     # AS3 tenant pool members carry no %RD -> route domain 0 (also recorded in the health policy)
_SELF = re.compile(r"^(?P<ip>[0-9.]+)(?:%(?P<rd>\d+))?(?:/(?P<len>\d+))?$")
_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def fact(value, status: str, source: str, evidence_ids=(), detail: str | None = None) -> dict:
    assert status in ("observed", "inferred", "configured", "unknown")
    f = {"value": value, "status": status, "source": source, "evidence_ids": sorted(set(evidence_ids))}
    if detail:
        f["detail"] = detail
    return f


def _check(name: str, result: str, status: str, detail: str, evidence_ids=(), **extra) -> dict:
    assert result in ("pass", "fail", "unknown")
    return {"check": name, "result": result, "status": status, "detail": detail, "evidence_ids": sorted(set(evidence_ids)), **extra}


def _ipkey(addr: str):
    ip, _, port = addr.rpartition(":") if addr.count(":") == 1 else (addr, "", "0")
    return (int(ipaddress.ip_address(ip)), int(port or 0))


# --------------------------------------------------------------------------------------------- device registry (W3-02)
STATE_TEXT = {"missing": "not collected", "permission_denied": "permission denied (HTTP 401/403) for the collector's account",
              "unsupported": "not supported by this device (HTTP 400/404/501)", "malformed": "response not in the expected shape",
              "failed": "collection failed (timeout, TLS/connection error or HTTP 5xx)", "stale": "sample older than the freshness limit"}


def _state_of(model: dict, key: str, present: bool) -> str:
    return (model.get("evidence_state") or {}).get(key) or ("observed" if present else "missing")


def device_from_model(device_id: str, model: dict, *, mgmt: str | None, evidence_id: str, origin: str,
                      mgmt_status: str = "observed", configured: dict | None = None) -> dict:
    """Registry record from a normalized Observe model (observe.normalize shape, incl. the Wave 3 additive keys
    self_ip_networks / routes / ha / health / evidence_state / collected_at). Fixtures may instead give self IP `address` in
    raw iControl form with prefix (`10.50.20.10/24`, `10.60.0.10%2/24`). Fields the model does not contain are unknown —
    never filled in — and every fact records WHY it is unknown (evidence_state)."""
    ev = [evidence_id]
    dev = model.get("device") or {}
    nets = {n["name"]: n for n in model.get("self_ip_networks") or [] if n.get("name")}
    self_state = _state_of(model, "self_ip_networks", bool(model.get("self_ips")))
    selfs = []
    for s in model.get("self_ips") or []:
        m = _SELF.match(str(s.get("address", "")))
        if not m:
            continue
        rec = {"name": s.get("name"), "vlan": s.get("vlan"), "address": m["ip"]}
        n = nets.get(s.get("name"))
        if n:
            rec["network"] = fact(str(ipaddress.ip_network(n["network"], strict=False)), "observed", "observe: net/self", ev)
            rec["route_domain"] = fact(int(n.get("route_domain") or 0), "observed", "observe: net/self", ev)
            rec["floating"] = n.get("floating")
        elif m["len"] is not None:   # raw iControl form: prefix present; %RD omitted means route domain 0
            rec["network"] = fact(str(ipaddress.ip_network(f"{m['ip']}/{m['len']}", strict=False)), "observed", "observe: net/self", ev)
            rec["route_domain"] = fact(int(m["rd"] or 0), "observed", "observe: net/self", ev)
        else:
            why = STATE_TEXT.get(self_state, "self IP stored without prefix length (subnet not recorded)") if self_state != "observed" \
                else "self IP stored without prefix length (subnet not recorded)"
            rec["network"] = fact(None, "unknown", "observe: net/self", ev, why)
            rec["route_domain"] = fact(None, "unknown", "observe: net/self", ev, "route domain not recorded")
        selfs.append(rec)
    routes = None
    if model.get("routes") is not None:
        routes = []
        for r in model["routes"]:
            if "route_domain" in r:               # normalized by observe.placement_evidence
                if r.get("via") in ("blackhole", "pool", "other"):
                    continue
                routes.append({"name": r.get("name"), "network": str(ipaddress.ip_network(r["network"], strict=False)),
                               "route_domain": int(r["route_domain"]), "gw": r.get("gw"), "via": r.get("via") or "gw"})
                continue
            net = str(r.get("network", ""))
            m = re.match(r"^(default|[0-9.]+(?:%(\d+))?/\d+)$", net)
            if not m:
                continue
            cidr = "0.0.0.0/0" if net == "default" else re.sub(r"%\d+", "", net)
            routes.append({"name": r.get("name"), "network": str(ipaddress.ip_network(cidr, strict=False)),
                           "route_domain": int(m.group(2) or 0), "gw": r.get("gw"), "via": "gw"})
    st_routes = _state_of(model, "routes", routes is not None)
    st_ha = _state_of(model, "ha", bool(model.get("ha")))
    st_health = _state_of(model, "health", bool(model.get("health")))
    health = dict(model["health"]) if model.get("health") else None
    if health is not None and health.get("sampled_at") is None and model.get("collected_at") is not None:
        health["sampled_at"] = model["collected_at"]
    prov = dev.get("provisioned")
    return {
        "id": device_id,
        "hostname": fact(dev.get("hostname"), "observed" if dev.get("hostname") else "unknown", "observe: sys/global-settings", ev),
        "mgmt": fact(mgmt, mgmt_status if mgmt else "unknown",
                     "configuration" if mgmt_status == "configured" else "collector target (pinned TLS key)", ev,
                     "management address — never counted as data-plane reachability"),
        "version": fact(dev.get("version"), "observed" if dev.get("version") else "unknown", "observe: sys/version", ev),
        "provisioned": fact(prov, "observed" if prov is not None else "unknown", "observe: sys/provision", ev),
        "as3_installed": fact(dev.get("as3_installed"), "observed" if dev.get("as3_installed") is not None else "unknown",
                              "observe: appsvcs/info", ev),
        "self_ips": selfs,
        "routes": {**fact(routes, "observed" if routes is not None else "unknown", "observe: net/route", ev,
                          None if routes is not None else "static routes " + STATE_TEXT.get(st_routes, st_routes)), "evidence_state": st_routes},
        "ha": {**fact(model.get("ha"), "observed" if model.get("ha") else "unknown", "observe: cm/failover-status + cm/device-group", ev,
                      None if model.get("ha") else "HA / failover state " + STATE_TEXT.get(st_ha, st_ha)), "evidence_state": st_ha},
        "health": {**fact(health, "observed" if health else "unknown", "observe: sys/memory + collector timing", ev,
                          None if health else "health sample " + STATE_TEXT.get(st_health, st_health)), "evidence_state": st_health},
        "collected_at": model.get("collected_at"),
        "self_state": self_state if self_state != "observed" or not all(x["network"]["status"] == "observed" for x in selfs) else "observed",
        "as3_state": (model.get("evidence_state") or {}).get("as3"),
        "provision_state": (model.get("evidence_state") or {}).get("provision"),
        # legacy models (no evidence_state) always came with the virtual/pool collections, so they count as observed
        "virtuals_state": (model.get("evidence_state") or {}).get("virtuals") or "observed",
        "virtuals": model.get("virtuals") or [],
        "pools": model.get("pools") or [],
        "configured": configured or {},
        "evidence_id": evidence_id,
        "origin": origin,
    }


def _device_checks(d: dict, pol: dict, now: float) -> list[dict]:
    ev = [d["evidence_id"]]
    out = []
    prov = d["provisioned"]
    pst_ = (d.get("provision_state") or "observed")
    if prov["status"] == "unknown" or not prov["value"]:   # an empty list is a missing/empty response, not proof that LTM is off
        out.append(_check("ltm_provisioned", "unknown", "unknown", "provisioning not recorded (empty or missing sys/provision response)"
                          if pst_ == "observed" else "provisioning " + STATE_TEXT.get(pst_, pst_), evidence_state=pst_ if pst_ != "observed" else "missing"))
    else:
        lvl = (prov["value"] or {}).get("ltm")
        out.append(_check("ltm_provisioned", "pass" if lvl else "fail", "observed",
                          f"LTM provisioned ({lvl})" if lvl else "LTM is not provisioned", ev))
    a, ast = d["as3_installed"], d.get("as3_state") or "observed"
    if a["value"] is False and ast not in ("observed", "unsupported"):   # the legacy flag reads any non-200 as "not installed"
        out.append(_check("as3_available", "unknown", "unknown", "AS3 status " + STATE_TEXT.get(ast, ast), evidence_state=ast))
    else:
        out.append(_check("as3_available", "unknown" if a["status"] == "unknown" else ("pass" if a["value"] else "fail"), a["status"],
                          {True: "AS3 installed", False: "AS3 not installed" + (" (appsvcs/info: HTTP 404)" if ast == "unsupported" else ""),
                           None: "AS3 status not recorded"}[a["value"]], ev if a["status"] != "unknown" else ()))
    ha = d["ha"]
    if ha["status"] == "unknown":
        out.append(_check("ha_state", "unknown", "unknown", ha["detail"], evidence_state=ha["evidence_state"]))
    else:
        st = str(ha["value"].get("failover_state") or "").lower()
        grp, mode = ha["value"].get("device_group"), ha["value"].get("mode")
        if not st:
            out.append(_check("ha_state", "unknown", "unknown", "failover state not recorded" + (f" ({mode})" if mode else ""),
                              evidence_state="missing"))
        elif st in pol["ha_usable"] or (st == "active" and mode == "standalone"):
            out.append(_check("ha_state", "pass", "observed", f"failover state {st}" + (f", {mode}" if mode else "") +
                              (f" (device group {grp})" if grp else ""), ev, evidence_state="observed"))
        elif st == "standby":
            out.append(_check("ha_state", "fail", "observed", f"standby unit — configuration belongs on the active member of {grp or 'its device group'}",
                              ev, evidence_state="observed"))
        else:
            out.append(_check("ha_state", "fail", "observed", f"failover state '{st}' is not usable", ev, evidence_state="observed"))
    h = d["health"]
    pv = pol["version"]
    req = [k for k, m in pol["metrics"].items() if m["required"]]
    if h["status"] == "unknown":
        out.append(_check("health", "unknown", "unknown", f"{h['detail']} ({pv} requires {', '.join(req)})", evidence_state=h["evidence_state"]))
        return out
    sampled, max_age = h["value"].get("sampled_at"), pol.get("max_sample_age_s")
    if max_age is not None:
        if sampled is None:
            out.append(_check("health", "unknown", "unknown", "health sample has no timestamp — freshness cannot be established",
                              ev, evidence_state="missing"))
            return out
        age = now - float(sampled)
        if age > max_age:
            out.append(_check("health", "unknown", "observed", f"sample is {int(age // 60)} min old (> {int(max_age // 60)} min, {pv}) — "
                              "collect a fresh snapshot", ev, evidence_state="stale", sample_age_s=round(age)))
            return out
        if age < -300:
            out.append(_check("health", "unknown", "observed", "sample time is in the future (collector clock skew)", ev,
                              evidence_state="stale", sample_age_s=round(age)))
            return out
    over, warn, missing = [], [], []
    swap_info = str((d.get("mgmt") or {}).get("value")) in set(pol.get("swap_informational_devices") or [])   # LAB-ONLY
    for k, m in pol["metrics"].items():
        v = h["value"].get(k)
        if k == "swap_pct" and swap_info:
            continue                                  # reported in the health sample; never fail, warn or required here
        if v is None:
            if m["required"]:
                missing.append(k)
        elif m["fail"] is not None and v >= m["fail"]:
            over.append(f"{k} {v} >= {m['fail']}")
        elif m["warn"] is not None and v >= m["warn"]:
            warn.append(f"{k} {v} >= {m['warn']} (warn)")
    age_txt = {} if sampled is None else {"sample_age_s": round(now - float(sampled))}
    if over:
        out.append(_check("health", "fail", "observed", f"above {pv} fail level: " + ", ".join(over), ev, warnings=warn,
                          evidence_state="observed", **age_txt))
    elif missing:
        out.append(_check("health", "unknown", "observed", f"required by {pv} but not sampled: " + ", ".join(missing), ev, warnings=warn,
                          evidence_state="missing", **age_txt))
    else:
        out.append(_check("health", "pass", "observed", f"within {pv} fail levels" + (f"; warnings: {', '.join(warn)}" if warn else ""),
                          ev, warnings=warn, evidence_state="observed", **age_txt))
    return out


def _reach(d: dict, ip: str) -> dict:
    """How device d reaches backend address ip (route domain 0). result pass|fail|unknown; via direct|route."""
    a = ipaddress.ip_address(ip)
    ev = [d["evidence_id"]]
    known = [s for s in d["self_ips"] if s["network"]["status"] == "observed"]
    unknown_selfs = [s for s in d["self_ips"] if s["network"]["status"] != "observed"]
    for s in sorted(known, key=lambda s: s["address"]):
        net = ipaddress.ip_network(s["network"]["value"])
        if a in net:
            if s["route_domain"]["value"] == MEMBER_ROUTE_DOMAIN:
                return {"result": "pass", "via": "direct", "status": "inferred", "evidence_ids": ev,
                        "detail": f"{ip} is inside self IP subnet {net} ({s['name']}, {s['vlan']})"}
            return {"result": "fail", "via": None, "status": "inferred", "evidence_ids": ev,
                    "detail": f"{ip} is only inside {net} in route domain {s['route_domain']['value']}; pool members are placed in "
                              f"route domain {MEMBER_ROUTE_DOMAIN}"}
    if unknown_selfs:
        hint = [s for s in unknown_selfs if ipaddress.ip_network(f"{s['address']}/24", strict=False) == ipaddress.ip_network(f"{ip}/24", strict=False)]
        return {"result": "unknown", "via": None, "status": "unknown", "evidence_ids": ev,
                "detail": f"self IP subnet(s) not recorded ({', '.join(s['address'] for s in unknown_selfs)}) — cannot establish whether {ip} is reachable",
                "assumption": (f"unverified assumption: {ip} would be directly connected to {hint[0]['address']} ({hint[0]['name']}) "
                               "if that self IP's prefix is /24 or shorter") if hint else None}
    routes = d["routes"]
    if routes["status"] == "unknown":
        return {"result": "unknown", "via": None, "status": "unknown", "evidence_ids": ev,
                "detail": f"{ip} is not on a self IP subnet and static routes are unknown ({STATE_TEXT.get(routes['evidence_state'], routes['evidence_state'])})"}
    best, default = None, False
    for r in routes["value"]:
        net = ipaddress.ip_network(r["network"])
        if r["route_domain"] != MEMBER_ROUTE_DOMAIN or a not in net:
            continue
        if net.prefixlen == 0:
            default = True
            continue
        if r.get("via") == "interface":       # interface route: the destination is on the VLAN itself
            if best is None or net.prefixlen > ipaddress.ip_network(best["network"]).prefixlen:
                best = r
            continue
        gw_ok = r.get("gw") and any(ipaddress.ip_address(r["gw"]) in ipaddress.ip_network(s["network"]["value"])
                                    and s["route_domain"]["value"] == MEMBER_ROUTE_DOMAIN for s in known)
        if gw_ok and (best is None or net.prefixlen > ipaddress.ip_network(best["network"]).prefixlen):
            best = r
    if best:
        return {"result": "pass", "via": "route", "status": "inferred", "evidence_ids": ev,
                "detail": f"{ip} via static route {best['network']} " + (f"(gateway {best['gw']} on a self IP subnet)" if best.get("gw")
                                                                         else "(interface route)")}
    if default:
        return {"result": "unknown", "via": None, "status": "inferred", "evidence_ids": ev,
                "detail": f"only a default route covers {ip} — reachability not established"}
    return {"result": "fail", "via": None, "status": "inferred", "evidence_ids": ev,
            "detail": f"no self IP subnet or static route in route domain {MEMBER_ROUTE_DOMAIN} reaches {ip}"}


# --------------------------------------------------------------------------------------------- service eligibility (W3-01)
def _coverage(svc: dict, devices: list[dict]) -> list[dict]:
    addrs = {e["address"] for e in svc["endpoints"]}
    out = []
    for d in devices:
        pools = {p["name"]: p for p in d["pools"]}
        for v in d["virtuals"]:
            p = pools.get(v.get("pool"))
            if not p:
                continue
            mem = sorted({f"{m.get('address') or m['name'].rpartition(':')[0]}:{m['name'].rpartition(':')[2]}" for m in p["members"]} & addrs,
                         key=_ipkey)
            if mem:
                out.append({"device": d["id"], "virtual": v["name"], "destination": f"{v.get('address')}:{v.get('port')}",
                            "pool": p["name"], "members": mem, "status": "observed", "evidence_ids": [d["evidence_id"]]})
    return sorted(out, key=lambda c: (c["device"], c["virtual"]))


def _traits(svc: dict) -> list[dict]:
    ev = svc["evidence_ids"]
    t = [fact(svc["classification"], "observed" if svc.get("verified") else "inferred", "identity: " + svc["grouping"], ev)]
    card_auth = (svc.get("auth") or {}).get("security_schemes")
    if svc["kind"] == "a2a_agent":
        t.append(fact(card_auth or [], "observed", "Agent Card securitySchemes", ev,
                      "no authentication declared" if not card_auth else None))
    if svc["kind"] == "mcp_server":
        ma = (svc.get("auth") or {}).get("mcp_authenticated")
        t.append(fact(ma, "observed" if ma is not None else "unknown", "MCP initialize", ev,
                      "MCP accepted unauthenticated sessions" if ma is False else None))
    if svc["replicas"]:
        t.append(fact(svc["replicas"], "observed" if svc["replica_status"] == "resolved" else "inferred", "identity: instances", ev,
                      f"{svc['replicas']} replicas ({svc['replica_status']}) — load-balanced pool" +
                      ("; MCP session persistence needed" if svc["kind"] == "mcp_server" else "")))
    return t


def _eligibility(svc: dict, devices: list[dict], unresolved: list[dict]) -> tuple[str, list[str], list[dict]]:
    if svc["kind"] not in PLACEABLE:
        return "out_of_scope", [f"{svc['classification']} — Wave 3 places A2A agents and MCP servers only"], []
    if not svc["endpoints"]:
        return "ineligible", ["no network endpoint observed (telemetry-only workload) — nothing to put in a pool"], []
    if svc["grouping"] == "unresolved-candidate":
        others = [u for u in unresolved if u["type"] == "possibly_same_service" and set(u["asset_ids"]) & set(svc["asset_ids"])]
        eps = sorted({e for u in others for e in u["endpoints"]} - {e["address"] for e in svc["endpoints"]}, key=_ipkey)
        return "ineligible", [f"service identity unresolved — possibly the same service as {', '.join(eps) or 'another endpoint'}; "
                              "pool membership cannot be decided until identity evidence resolves it"], []
    cov = _coverage(svc, devices)
    if cov:
        covered = {m for c in cov for m in c["members"]}
        gaps = sorted({e["address"] for e in svc["endpoints"]} - covered, key=_ipkey)
        why = [f"already fronted by {c['virtual']} ({c['destination']}) on {c['device']}: members {', '.join(c['members'])}" for c in cov]
        if gaps:
            why.append(f"endpoints not in that pool (observed): {', '.join(gaps)} — review whether they are interfaces or uncovered replicas")
        return "already_covered", why, cov
    return "eligible", [], []


# --------------------------------------------------------------------------------------------- placement (W3-03)
def _members_on(d: dict, svc: dict, callers: list[str], member_policy: list[str] | None) -> tuple[dict, list[dict]]:
    """Per runtime instance: reachability of each interface and the chosen interface. Returns (check, members)."""
    insts = {i["id"]: i for i in svc["instances"]}
    by_inst: dict[str, list] = {}
    for e in svc["endpoints"]:
        by_inst.setdefault(e["instance_id"], []).append(e)
    caller_nets = {ipaddress.ip_network(f"{c}/24", strict=False) for c in callers}
    policy_nets = [ipaddress.ip_network(n) for n in member_policy or []]
    members, worst = [], "pass"
    rank = {"pass": 0, "unknown": 1, "fail": 2}
    for iid in sorted(by_inst, key=lambda i: min(_ipkey(e["address"]) for e in by_inst[i])):
        opts = []
        for e in sorted(by_inst[iid], key=lambda e: _ipkey(e["address"])):
            ip = e["address"].rpartition(":")[0]
            r = _reach(d, ip)
            opts.append({"address": e["address"], "role": e["role"], "membership": e["membership"], "reach": r,
                         "in_member_policy": (any(ipaddress.ip_address(ip) in n for n in policy_nets) if policy_nets else None),
                         "on_caller_subnet": any(ipaddress.ip_address(ip) in n for n in caller_nets)})
        ok = [o for o in opts if o["reach"]["result"] == "pass"]
        if ok:
            pick = lambda o: (o["reach"]["via"] != "direct", o["in_member_policy"] is False, o["on_caller_subnet"], _ipkey(o["address"]))  # noqa: E731
            ok.sort(key=pick)
            ch = ok[0]
            why = [f"{ch['reach']['via']} reachability"]
            if len(ok) > 1:   # report the rule that decided between the chosen interface and the runner-up
                labels = ("directly connected (the other is routed)", "inside the deployer's current member range (configured)",
                          "not on an observed caller subnet, so callers must use the front door", "lowest address (deterministic tie-break)")
                i = next(i for i, (x, y) in enumerate(zip(pick(ch), pick(ok[1]))) if x != y)
                why.append(f"preferred over {ok[1]['address']}: {labels[i]}")
            res, chosen = "pass", {"address": ch["address"], "why": why}
        else:
            res = "unknown" if any(o["reach"]["result"] == "unknown" for o in opts) else "fail"
            chosen = None
        i = insts.get(iid) or {}
        members.append({"instance": i.get("label"), "instance_status": i.get("status"), "result": res, "chosen": chosen,
                        "interfaces": opts})
        if rank[res] > rank[worst]:
            worst = res
    def describe(m):
        txt = (f"{m['chosen']['address']} ({next(o['reach']['detail'] for o in m['interfaces'] if o['address'] == m['chosen']['address'])})"
               if m["chosen"] else " / ".join(o["reach"]["detail"] for o in m["interfaces"]))
        sole = len(m["interfaces"]) == 1 and m["instance"] == m["interfaces"][0]["address"]
        return txt if sole else f"instance {m['instance']}: {txt}"
    det = "; ".join(describe(m) for m in members)
    status = "inferred" if worst != "unknown" else "unknown"
    es = "observed"
    if worst == "unknown":   # name the evidence that is missing (register #18)
        if any(x["network"]["status"] != "observed" for x in d["self_ips"]):
            es = d.get("self_state") if d.get("self_state") not in (None, "observed") else "missing"
        elif d["routes"]["status"] != "observed":
            es = d["routes"].get("evidence_state") or "missing"
        else:
            es = "insufficient"   # observed evidence, but only a default route covers the member
    return _check("backend_reachability", worst, status, det, [d["evidence_id"]], evidence_state=es), members


NOT_PREFLIGHT = ("Placement is advisory and is not deployment authorisation: it makes no claim about deployment readiness. "
                 "Preview, configuration diff and the deployer's on-device preflight decide at deployment time, after human approval.")
L3_ONLY = ("Reachability is layer-3 only (self IP subnets and static routes): packet filters, firewalls, port lockdown and the "
           "service port itself are not tested.")


def _explain_selected(svc: dict, ev: dict, d: dict, why: list[str], uncertainty: list[str]) -> dict:
    """Why this device, which evidence supports it, and what remains unverified."""
    checks = ev["checks"]
    hc = next((c for c in checks if c["check"] == "health"), {})
    routed = [o for m in ev["members"] for o in m["interfaces"] if m["chosen"] and o["address"] == m["chosen"]["address"] and o["reach"]["via"] == "route"]
    assumptions = [L3_ONLY]
    if routed:
        assumptions.append("Routed pool members depend on the upstream gateway forwarding traffic, which BIG-IP evidence cannot show: "
                           + ", ".join(o["address"] for o in routed))
    assumptions.append("Dynamic routing (if configured) is not collected; only static routes and connected subnets were evaluated.")
    if hc.get("sample_age_s") is not None:
        assumptions.append(f"Health was sampled {round(hc['sample_age_s'] / 60)} min before this evaluation and can change before deployment.")
    for w in hc.get("warnings") or []:
        assumptions.append(f"Health warning (not a failure): {w}.")
    assumptions += uncertainty
    return {
        "why_selected": why,
        "checks_passed": [f"{c['check']}: {c['detail']}" for c in checks],
        "supporting_evidence": [
            {"evidence_id": d["evidence_id"], "what": f"BIG-IP Observe record for {d['id']} ({d['origin']})", "collected_at": d.get("collected_at")},
            *[{"evidence_id": e, "what": f"discovery evidence for {svc['name']}"} for e in sorted(set(svc["evidence_ids"]))]],
        "unverified_assumptions": assumptions,
        "deployment_readiness": NOT_PREFLIGHT,
    }


def _colocated(d: dict, related_addrs: set[str]) -> int:
    pools = {p["name"]: p for p in d["pools"]}
    n = 0
    for v in d["virtuals"]:
        p = pools.get(v.get("pool")) or {"members": []}
        if any(f"{m.get('address') or m['name'].rpartition(':')[0]}:{m['name'].rpartition(':')[2]}" in related_addrs for m in p["members"]):
            n += 1
    return n


def evaluate(identity: dict, devices: list[dict], *, callers: dict[str, list[str]] | None = None,
             preferences: dict | None = None, member_policy: list[str] | None = None, policy: dict | None = None,
             now: float | None = None) -> dict:
    """Placement decision for every canonical A2A/MCP service. Deterministic: same inputs -> byte-identical output."""
    callers = callers or {}
    pol = policy or placement_policy.load()
    now = time.time() if now is None else now
    pref = (preferences or {}).get("device")
    devices = sorted(devices, key=lambda d: d["id"])
    dchecks = {d["id"]: _device_checks(d, pol, now) for d in devices}
    svc_by_id = {s["id"]: s for s in identity["services"]}
    related: dict[str, set] = {}
    for r in identity.get("relationships") or []:
        for a, b in ((r.get("from"), r.get("to")), (r.get("to"), r.get("from"))):
            if a and b and b in svc_by_id:
                related.setdefault(a, set()).update(e["address"] for e in svc_by_id[b]["endpoints"])
    results, out_of_scope, missing = [], [], {}
    for svc in sorted(identity["services"], key=lambda s: (s["kind"], s["name"] or "", s["id"])):
        elig, reasons, cov = _eligibility(svc, devices, identity.get("unresolved") or [])
        head = {"id": svc["id"], "name": svc["name"], "kind": svc["kind"], "grouping": svc["grouping"], "confidence": svc["confidence"],
                "endpoints": sorted((e["address"] for e in svc["endpoints"]), key=_ipkey)}
        if elig == "out_of_scope":
            out_of_scope.append({**head, "reason": reasons[0]})
            continue
        rec = {"service": head, "eligibility": elig, "eligibility_reasons": reasons, "coverage": cov, "traits": _traits(svc),
               "uncertainty": [], "evidence_ids": sorted(set(svc["evidence_ids"]))}
        blind = [d["id"] for d in devices if d.get("virtuals_state", "observed") != "observed"]
        if blind and elig == "eligible":
            rec["uncertainty"].append("existing BIG-IP coverage not evaluated on " + ", ".join(blind) +
                                      " (virtual servers not collected) — the service may already be fronted there")
        if svc.get("replica_status") == "provisional":
            rec["uncertainty"].append("instance relationship not observed — each endpoint is treated as its own instance and must be reachable")
        if svc["grouping"] == "inferred":
            rec["uncertainty"].append("grouping from protocol metadata only (same MCP server name and tool-set fingerprint)")
        if elig != "eligible":
            rec.update(decision="not_placed", selected=None, eligible=[], unverified=[], rejected=[])
            results.append(rec)
            continue
        evals = []
        for d in devices:
            rc, members = _members_on(d, svc, callers.get(svc["id"], []), member_policy)
            checks = dchecks[d["id"]] + [rc]
            verdict = "rejected" if any(c["result"] == "fail" for c in checks) else (
                "unverified" if any(c["result"] == "unknown" for c in checks) else "eligible")
            ev = {"device": d["id"], "hostname": d["hostname"]["value"], "verdict": verdict, "checks": checks, "members": members}
            if verdict == "unverified":
                ev["assumptions"] = sorted({o["reach"]["assumption"] for m in members for o in m["interfaces"] if o["reach"].get("assumption")})
            for c in checks:
                if c["result"] == "unknown":
                    det = ("reachability of service endpoints not established — see each service's checks"
                           if c["check"] == "backend_reachability" else c["detail"])
                    missing.setdefault((d["id"], c["check"]), {"device": d["id"], "check": c["check"], "detail": det, "services": []})[
                        "services"].append(svc["name"])
            evals.append(ev)
        eligible = [e for e in evals if e["verdict"] == "eligible"]
        dev_by_id = {d["id"]: d for d in devices}
        for e in eligible:
            d = dev_by_id[e["device"]]
            direct = all(o["reach"]["via"] == "direct" for m in e["members"] for o in m["interfaces"] if m["chosen"] and o["address"] == m["chosen"]["address"])
            col = _colocated(d, related.get(svc["id"], set()))
            hw = len(next(c for c in e["checks"] if c["check"] == "health").get("warnings") or [])
            e["rank_key"] = {"preferred": e["device"] == pref, "all_direct": direct, "health_warnings": hw, "colocated_virtuals": col,
                             "existing_virtuals": len(d["virtuals"]), "device_id": e["device"]}
        eligible.sort(key=lambda e: (not e["rank_key"]["preferred"], not e["rank_key"]["all_direct"], e["rank_key"]["health_warnings"],
                                     -e["rank_key"]["colocated_virtuals"],
                                     e["rank_key"]["existing_virtuals"], e["device"]))
        sel = None
        if eligible:
            top = eligible[0]
            why = ["all hard checks pass on observed/inferred evidence"]
            if len(eligible) > 1:
                nxt = eligible[1]["rank_key"]
                for k, label in (("preferred", "customer preference (configured)"), ("all_direct", "all pool members directly connected"),
                                 ("health_warnings", "fewer health-policy warnings"),
                                 ("colocated_virtuals", "co-located with related services"), ("existing_virtuals", "more headroom (fewer virtual servers)"),
                                 ("device_id", "deterministic tie-break on device id")):
                    if top["rank_key"][k] != nxt[k]:
                        why.append(f"ranked above {eligible[1]['device']}: {label}")
                        break
            else:
                why.append("only eligible device")
            sel = {"device": top["device"], "pool_members": [m["chosen"] for m in top["members"]], "why": why,
                   "evidence_ids": sorted(set(svc["evidence_ids"]) | {dev_by_id[top["device"]]["evidence_id"]})}
            sel["explanation"] = _explain_selected(svc, top, dev_by_id[top["device"]], why, rec["uncertainty"])
        rec.update(decision="selected" if sel else ("abstain" if not evals or any(e["verdict"] == "unverified" for e in evals) else "no_eligible_device"),
                   selected=sel, eligible=eligible,
                   unverified=sorted([e for e in evals if e["verdict"] == "unverified"], key=lambda e: e["device"]),
                   rejected=[{"device": e["device"], "reasons": [c["detail"] for c in e["checks"] if c["result"] == "fail"],
                              "checks": e["checks"], "members": e["members"]} for e in evals if e["verdict"] == "rejected"])
        if not sel:
            rec["explanation"] = {
                "why_not_selected": None,   # filled below
                "missing_evidence": [{"device": e["device"], "check": c["check"], "evidence_state": c.get("evidence_state") or "unknown",
                                      "detail": c["detail"]} for e in rec["unverified"] for c in e["checks"] if c["result"] == "unknown"],
                "rejections": [{"device": r["device"], "reasons": r["reasons"]} for r in rec["rejected"]],
                "unverified_assumptions": sorted({a for e in rec["unverified"] for a in e.get("assumptions") or []}),
                "deployment_readiness": NOT_PREFLIGHT}
            rec["decision_reason"] = ("no BIG-IP device is recorded in the evidence (no Observe record) — nothing can be verified"
                                      if not evals else
                                      "no device passes every hard check on trusted evidence; unverified candidates are listed, not ranked"
                                      if rec["decision"] == "abstain" else "every registered device fails at least one hard check")
        if rec.get("explanation") and rec["explanation"].get("why_not_selected") is None:
            rec["explanation"]["why_not_selected"] = rec["decision_reason"]
        results.append(rec)
    placeable = [r for r in results if r["eligibility"] == "eligible"]
    chosen = [r for r in placeable if r["decision"] == "selected"]
    status = ("nothing_to_place" if not placeable else "decided" if len(chosen) == len(placeable) else "partial" if chosen else
              "abstained" if any(r["decision"] == "abstain" for r in placeable) else "no_eligible_device")
    out = {
        "engine": ENGINE, "assessment_id": identity.get("assessment_id"), "status": status,
        "summary": {"services_considered": len(results), "eligible": len(placeable),
                    "already_covered": sum(r["eligibility"] == "already_covered" for r in results),
                    "ineligible": sum(r["eligibility"] == "ineligible" for r in results), "selected": len(chosen),
                    "abstained": sum(r["decision"] == "abstain" for r in placeable),
                    "no_eligible_device": sum(r["decision"] == "no_eligible_device" for r in placeable),
                    "out_of_scope": len(out_of_scope), "devices": len(devices)},
        "devices": [{"id": d["id"], "hostname": d["hostname"], "mgmt": d["mgmt"], "version": d["version"], "provisioned": d["provisioned"],
                     "as3_installed": d["as3_installed"], "self_ips": d["self_ips"], "routes": d["routes"], "ha": d["ha"], "health": d["health"],
                     "virtual_servers": fact(len(d["virtuals"]), "observed", "observe: ltm/virtual", [d["evidence_id"]]),
                     "configured": d["configured"], "checks": dchecks[d["id"]], "origin": d["origin"], "evidence_id": d["evidence_id"]}
                    for d in devices],
        "services": results, "out_of_scope": out_of_scope,
        "missing": sorted(missing.values(), key=lambda m: (m["device"], m["check"])),
        "deployment_readiness": NOT_PREFLIGHT, "evaluated_at": now,
        "limits": {"health_policy": {k: pol.get(k) for k in ("version", "digest", "origin", "status", "metrics", "max_sample_age_s")},
                   "ha_usable": pol["ha_usable"], "member_route_domain": pol["member_route_domain"], "member_policy": member_policy},
    }
    out["decision_digest"] = hashlib.sha256(json.dumps(out, sort_keys=True, default=str).encode()).hexdigest()
    return out


# --------------------------------------------------------------------------------------------- stored-evidence adapters (read-only)
def devices_from_store(store, cfg: dict, aid: str) -> list[dict]:
    """One registry record per BIG-IP: the latest stored Observe evidence for each device of the assessment. A device is
    identified by the collector's target (`device_ref.mgmt`, reached over a pinned TLS key); evidence without a device
    reference (the deployer path, older snapshots) belongs to the configured `observe.bigip_mgmt` (status configured)."""
    cfg_mgmt = (cfg.get("observe") or {}).get("bigip_mgmt")
    d = cfg.get("design") or {}
    latest: dict[str, tuple] = {}
    for row in store.db.execute("SELECT id, method, raw, collected_at FROM evidence WHERE assessment_id=? AND source='observe' "
                                "ORDER BY collected_at DESC, id", (aid,)):
        model = (json.loads(row["raw"]) or {}).get("model") or {}
        ref = model.get("device_ref") or {}
        mgmt = ref.get("mgmt") or cfg_mgmt
        if mgmt and mgmt not in latest:
            latest[mgmt] = (row, model, "observed" if ref.get("mgmt") else "configured")
    out = []
    for mgmt, (row, model, mst) in sorted(latest.items()):
        configured = {}
        if mgmt == cfg_mgmt:
            configured = {"self_ips": [fact(d[k], "configured", f"autopilot.yaml design.{k}") for k in ("self_agent", "self_backend") if d.get(k)],
                          "vlans": [fact(d[k], "configured", f"autopilot.yaml design.{k}") for k in ("vlan_agent", "vlan_backend") if d.get(k)]}
        label = (model.get("device_ref") or {}).get("label")
        out.append(device_from_model(f"bigip:{mgmt}", model, mgmt=mgmt, evidence_id=row["id"],
                                     origin=f"stored Observe evidence ({row['method']})" + (f", device label '{label}'" if label else ""),
                                     mgmt_status=mst, configured=configured))
    return out


def callers_from_store(store, identity: dict) -> dict[str, list[str]]:
    """Observed caller IPs per service, from stored communication edges (used only to pick an interface): the peer
    addresses telemetry recorded on the edge, else an address in the caller's endpoint key."""
    assets = {a["id"]: a for a in store.assets(identity["assessment_id"])}
    idx = identity["endpoint_index"]
    out: dict[str, set] = {}
    for r in store.rels(identity["assessment_id"]):
        if not r["kind"].startswith("calls_") or r["dst"] not in idx:
            continue
        ips = {p for c in r["claims"] for p in (c["attrs"].get("peer_addresses") or []) if _IP.fullmatch(str(p))}
        m = _IP.search(assets[r["src"]]["key"]) if r["src"] in assets else None
        if not ips and m:
            ips = {m.group(1)}
        out.setdefault(idx[r["dst"]]["service_id"], set()).update(ips)
    return {k: sorted(v, key=lambda x: int(ipaddress.ip_address(x))) for k, v in out.items()}


def assess_store(store, cfg: dict, aid: str | None = None, *, extra_devices: list[dict] | None = None,
                 preferences: dict | None = None, now: float | None = None) -> dict:
    """Placement over one assessment's stored evidence. Read-only: SELECTs only."""
    from . import identity as ident
    from .deployer import policy
    aid = aid or store.current()["id"]
    idn = ident.reconcile(store, aid)
    devs = devices_from_store(store, cfg, aid) + list(extra_devices or [])
    return evaluate(idn, devs, callers=callers_from_store(store, idn), preferences=preferences,
                    member_policy=[str(policy.MEMBER_RANGE)], policy=placement_policy.load(cfg), now=now)
