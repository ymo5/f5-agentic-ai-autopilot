"""Discovery engine: turns source outputs into evidence + claims, reconciles, then assesses.

Canonical identity keys (deduplication):
  ep:<ip>:<port>          network service endpoint (A2A agent, MCP server, vector DB, S3, LLM, OTLP, DNS)
  mcpsvc:<name>:<toolsig> logical MCP service (replicas = endpoints with the same server name + tool set)
  otel:<service.name>     instrumented workload seen only as a client (e.g. an agent with no listener)
  bigip:<mgmt>            BIG-IP device; bigip-vs:<path>, bigip-pool:<path>
  described:<slug>        component asserted by the customer, not (yet) matched to technical evidence
"""
from __future__ import annotations

import ipaddress
import re
import time

from aplab.llm import LLM

from . import assess
from .sources import describe as d_src
from .sources import enumerate as e_src
from .sources import ingest as i_src
from .sources import observe as o_src
from .store import Store


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60]


def _kind_hint(name: str, kind: str | None) -> str | None:
    """Deterministic consistency check of the LLM's component kind against the component's own name: a component
    the customer calls an 'agent' (and not an MCP server/tool) is an agent; one called 'mcp …' is an MCP server."""
    t = set(re.findall(r"[a-z0-9]+", (name or "").lower().replace("_", " ")))
    if "agent" in t and not t & {"mcp", "server", "tool", "tools"} and kind not in ("a2a_agent", "ai_agent"):
        return "a2a_agent"
    if "mcp" in t and kind not in ("mcp_server", "mcp_service"):
        return "mcp_server"
    return kind


def _tokens(s: str) -> set[str]:
    stop = {"the", "a", "an", "service", "server", "agent", "and", "of", "for", "our", "with", "mcp", "a2a"}
    return {t for t in re.findall(r"[a-z0-9]+", (s or "").lower()) if t not in stop and len(t) > 2}


class Engine:
    def __init__(self, store: Store, cfg: dict, llm: LLM) -> None:
        self.s, self.cfg, self.llm = store, cfg, llm
        self.running: dict[str, float] = {}

    # ------------------------------------------------------------------ OBSERVE
    def observe(self, raw: dict, origin: str) -> dict:
        model = o_src.normalize(raw)
        dev = model["device"]
        # the collector's target identifies the device (multi-BIG-IP); otherwise the configured device, as before
        mgmt = (model.get("device_ref") or {}).get("mgmt") or self.cfg["observe"]["bigip_mgmt"]
        eid = self.s.add_evidence("observe", f"bigip-icontrol-rest ({origin})",
                                  f"BIG-IP {dev.get('version')} {mgmt}: {len(model['virtuals'])} virtual servers, "
                                  f"{len(model['pools'])} pools, {len(model['self_ips'])} self IPs, AS3 "
                                  f"{'installed' if dev.get('as3_installed') else 'not installed'}", {"origin": origin, "model": model})
        bid = self.s.claim_asset(eid, "observe", f"bigip:{mgmt}", "adc", dev.get("hostname") or f"BIG-IP {mgmt}",
                                 {"mgmt_address": mgmt, **dev, "self_ips": [x["address"] for x in model["self_ips"]],
                                  "vlans": [v["name"] for v in model["vlans"]], "virtual_count": len(model["virtuals"])})
        pool_ids = {}
        for p in model["pools"]:
            pid = self.s.claim_asset(eid, "observe", f"bigip-pool:{p['name']}", "bigip_pool", p["name"], p)
            pool_ids[p["name"]] = pid
            self.s.claim_rel(eid, "observe", bid, pid, "hosts_config", "unknown")
            for m in p["members"]:
                ip, _, port = m["name"].rpartition(":")
                ep = self.s.claim_asset(eid, "observe", f"ep:{m.get('address') or ip.split('%')[0]}:{port}", "unknown",
                                        m["name"], {"bigip_pool_member_of": p["name"], "member_state": m.get("state")})
                self.s.claim_rel(eid, "observe", pid, ep, "load_balances", "via_bigip",
                                 {"monitor": p["monitor"], "lb_mode": p["lb_mode"]})
        for v in model["virtuals"]:
            vid = self.s.claim_asset(eid, "observe", f"bigip-vs:{v['name']}", "bigip_virtual", v["name"], v)
            self.s.claim_rel(eid, "observe", bid, vid, "hosts_config", "unknown")
            if v.get("address") and v.get("port"):
                fe = self.s.claim_asset(eid, "observe", f"ep:{v['address']}:{v['port']}", "bigip_vip", v["name"],
                                        {"vip_of": v["name"], "is_vip": True})
                self.s.claim_rel(eid, "observe", fe, vid, "implemented_by", "via_bigip")
            if v.get("pool") in pool_ids:
                self.s.claim_rel(eid, "observe", vid, pool_ids[v["pool"]], "forwards_to", "via_bigip")
        self.s.audit("autopilot", "discovery.observe", self.s.current()["id"], {"evidence": eid, "origin": origin})
        return {"evidence_id": eid, "virtuals": len(model["virtuals"]), "pools": len(model["pools"])}

    def bigip_context(self) -> tuple[set[str], set[str]]:
        """Addresses that identify BIG-IP-traversed traffic, taken only from Observe evidence."""
        selfs, vips = set(), set()
        for a in self.s.assets():
            if a["kind"] == "adc":
                selfs |= set(a["attrs"].get("self_ips") or [])
            if a["attrs"].get("is_vip"):
                vips.add(a["key"].split(":")[1])
        return selfs, vips

    # ------------------------------------------------------------------ DESCRIBE
    async def describe(self, text: str, author: str) -> dict:
        data, prov = await d_src.interpret(text, self.llm)
        eid = self.s.add_evidence("describe", prov["generated_by"],
                                  f"SE description by {author}: {len(data['components'])} components, "
                                  f"{len(data['relationships'])} relationships, {len(data['control_claims'])} control claims",
                                  {"text": text, "author": author, "extraction": data, "provenance": prov})
        ids = {}
        for c in data["components"]:
            key = f"described:{_slug(c['name'])}"
            kind = _kind_hint(c["name"], c.get("kind"))
            extra = {"llm_kind": c.get("kind"), "kind_corrected": "component name contradicts the extracted kind"} if kind != c.get("kind") else {}
            ids[c["name"]] = self.s.claim_asset(eid, "describe", key, kind or "asserted_component", c["name"],
                                                {"asserted_kind": kind, "asserted_address": c.get("address"),
                                                 "asserted_replicas": c.get("replicas"), "notes": c.get("notes"), **extra})
        for r in data["relationships"]:
            src, dst = ids.get(r.get("from")), ids.get(r.get("to"))
            if src and dst:
                self.s.claim_rel(eid, "describe", src, dst, r.get("protocol") or "unknown", r.get("path") or "unknown",
                                 {"asserted": True})
        for cl in data["control_claims"]:
            tgt = next((i for n, i in ids.items() if _tokens(n) & _tokens(cl.get("subject", ""))), None)
            if tgt:
                a = next(x for x in self.s.assets() if x["id"] == tgt)
                claims = a["attrs"].get("asserted_controls", []) + [cl.get("claim")]
                self.s.claim_asset(eid, "describe", a["key"], a["kind"], a["name"], {"asserted_controls": sorted(set(claims))})
        self.reconcile()
        self.s.audit(author, "discovery.describe", self.s.current()["id"], {"evidence": eid, **prov})
        return {"evidence_id": eid, **prov, "components": len(data["components"])}

    # ------------------------------------------------------------------ ENUMERATE
    async def enumerate(self) -> dict:
        ec = self.cfg["enumerate"]
        results = {}
        inv_eid = self.s.add_evidence("enumerate", "approved-inventory", f"Approved scope: {', '.join(ec['scope_cidrs'])} "
                                      f"+ {len(ec['approved_hosts'])} approved hosts", ec)
        for h in ec.get("inventory", []):
            self.s.claim_asset(inv_eid, "enumerate", h["key"], h["kind"], h["name"], h.get("attrs", {}))
        try:
            recs = e_src.zone_transfer(ec["dns_server"], ec["dns_zone"])
            eid = self.s.add_evidence("enumerate", "dns-axfr", f"Zone transfer {ec['dns_zone']} from {ec['dns_server']}: {len(recs)} records", recs)
            names: dict[str, list[str]] = {}
            for r in recs:
                if r["type"] == "A":
                    names.setdefault(r["value"], []).append(r["name"])
            results["dns"] = {"records": len(recs), "evidence_id": eid}
        except Exception as e:  # recorded as a coverage gap, not silently ignored
            eid = self.s.add_evidence("enumerate", "dns-axfr", f"Zone transfer failed: {type(e).__name__}", {"error": str(e)})
            names, results["dns"] = {}, {"error": str(e)}
        scan = await e_src.scan(ec["scope_cidrs"], ec["approved_hosts"], ec.get("ports"))
        sid = self.s.add_evidence("enumerate", "protocol-fingerprint",
                                  f"Probed {len(scan)} open endpoints in approved scope", scan)
        groups: dict[str, list[str]] = {}
        for r in scan:
            if r.get("kind") in (None, "unknown"):
                continue
            attrs = {k: v for k, v in r.items() if k not in ("ip", "port", "kind")}
            attrs["dns_names"] = names.get(r["ip"], [])
            attrs["address"] = f"{r['ip']}:{r['port']}"
            nm = (attrs["dns_names"][0].split(".")[0] if attrs["dns_names"] else None) or r.get("name") or attrs["address"]
            ep = self.s.claim_asset(sid, "enumerate", f"ep:{r['ip']}:{r['port']}", r["kind"], nm, attrs)
            if r["kind"] == "mcp_server" and isinstance(r.get("mcp"), dict):
                m = r["mcp"]
                gkey = f"mcpsvc:{m['server_name']}:{m['toolset_fingerprint']}"
                groups.setdefault(gkey, []).append(ep)
            if r["kind"] == "a2a_agent":
                for u in ((r.get("agent_card") or {}).get("advertised_urls") or []):   # tolerate partial/malformed cards
                    hp = i_src._hostport(u)
                    if hp and f"{hp[0]}:{hp[1]}" != f"{r['ip']}:{r['port']}":
                        adv = self.s.claim_asset(sid, "enumerate", f"ep:{hp[0]}:{hp[1]}", "a2a_endpoint", u, {"advertised_by_card": True})
                        self.s.claim_rel(sid, "enumerate", ep, adv, "advertises", "unknown")
        for gkey, members in groups.items():
            name = gkey.split(":")[1]
            gid = self.s.claim_asset(sid, "enumerate", gkey, "mcp_service", name,
                                     {"replica_count": len(members), "grouping": "same MCP server name and tool-set fingerprint"})
            for m in members:
                self.s.claim_rel(sid, "enumerate", gid, m, "has_replica", "unknown")
        self.reconcile()
        self.s.audit("autopilot", "discovery.enumerate", self.s.current()["id"], {"endpoints": len(scan)})
        return {"endpoints": len(scan), "fingerprinted": sum(1 for r in scan if r.get("kind") not in (None, "unknown")),
                "mcp_services": len(groups), **results}

    # ------------------------------------------------------------------ INGEST
    async def ingest(self) -> dict:
        ic = self.cfg["ingest"]
        since, why = self.ingest_window()
        win: dict = {}
        traces = await i_src.fetch_traces(ic["jaeger_url"], ic.get("lookback", "2h"), ic.get("limit", 400), since, stats=win)
        if win.get("start"):
            why += (f"; window {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(win['start']))}–"
                    f"{time.strftime('%H:%M:%S UTC', time.gmtime(win['end']))}")
        if win.get("truncated_services"):
            why += f"; search limit {ic.get('limit', 400)} reached for {', '.join(win['truncated_services'])} — older traces in the window not read"
        selfs, vips = self.bigip_context()
        peer_names = {}
        for a in self.s.assets():
            if a["key"].startswith("ep:") and a["attrs"].get("dns_names"):
                peer_names.setdefault(a["key"].split(":")[1], a["attrs"]["dns_names"][0].split(".")[0])
        corr = i_src.correlate(traces, selfs, vips, set(ic.get("exclude_services", [])), set(ic.get("exclude_peers", [])), peer_names)
        corr["window"] = {"since": since, "reason": why, "start": win.get("start"), "end": win.get("end"),
                          "truncated_services": win.get("truncated_services", []), "dropped_before_window": win.get("dropped_before_window", 0)}
        eid = self.s.add_evidence("ingest", "otel-traces (jaeger query api)",
                                  f"{corr['trace_count']} traces, {len(corr['services'])} instrumented services, "
                                  f"{len(corr['edges'])} communication paths ({why})", corr)
        svc_asset = {}
        for name, info in corr["services"].items():
            kind = "a2a_agent" if "a2a_server" in info["roles"] else "mcp_server" if "mcp_server" in info["roles"] else \
                   "ai_agent" if (info["agent_name"] or "a2a_client" in info["roles"]) else "workload"
            if info["listen"]:
                for addr in info["listen"]:
                    svc_asset.setdefault(name, []).append(self.s.claim_asset(
                        eid, "ingest", f"ep:{addr}", kind, name, {"otel_service": name, "otel_instances": info["instances"],
                                                                  "hosts": info["hosts"], "roles": info["roles"],
                                                                  "agent_name": info["agent_name"]}))
            else:
                svc_asset[name] = [self.s.claim_asset(eid, "ingest", f"otel:{name}", kind, info["agent_name"] or name,
                                                      {"otel_service": name, "hosts": info["hosts"], "roles": info["roles"],
                                                       "agent_name": info["agent_name"]})]
        kind_by_proto = {"s3": "object_store", "vector_db": "vector_db", "llm": "llm_endpoint", "mcp": "mcp_server",
                         "a2a": "a2a_agent", "http": "unknown"}
        for e in corr["edges"]:
            caller = e["caller"]
            if caller in svc_asset:
                src = svc_asset[caller][0]
            else:
                peer = caller.split("@")[-1]
                runs = corr.get("peer_hosts", {}).get(peer) or []
                known = [a for a in self.s.assets() if a["key"].startswith(f"ep:{peer}:") and a["kind"] not in ("unknown", "bigip_vip")]
                if peer in selfs:
                    label, runs = f"BIG-IP self IP {peer} (health monitors / SNAT-translated traffic)", []
                elif known:   # the address belongs to an enumerated service: name it after that evidence, not a span hint
                    label, runs = f"Unattributed client {peer} (address of {known[0]['name']})", []
                else:
                    label = f"Unattributed client {peer}" + (f" (host of {', '.join(runs)})" if runs else
                                                              f" ({peer_names[peer]})" if peer in peer_names else "")
                src = self.s.claim_asset(eid, "ingest", f"client:{peer}", "client", label,
                                         {"peer": peer, "dns_names": [n for ip, n in peer_names.items() if ip == peer],
                                          "same_host_as": runs,
                                          "note": "caller sent no trace context; identified by network peer address only"})
            dst = self.s.claim_asset(eid, "ingest", f"ep:{e['target']}", kind_by_proto.get(e["protocol"], "unknown"),
                                     e.get("server_service") or e["target"], {"observed_protocol": e["protocol"]})
            p = e["paths"]
            path = "via_bigip" if p.get("via_bigip") and not p.get("direct") else "direct" if p.get("direct") else "unknown"
            self.s.claim_rel(eid, "ingest", src, dst, f"calls_{e['protocol']}", path,
                             {k: e[k] for k in ("calls", "errors", "latency_ms", "tools", "mcp_protocol_versions", "peer_addresses",
                                                "replicas", "trace_count", "trace_ids", "paths")})
        for at in corr.get("attributions", []):
            self.s.audit("autopilot", "identity.attributed", self.s.current()["id"], {**at, "evidence_id": eid})
        self.reconcile()
        self.s.audit("autopilot", "discovery.ingest", self.s.current()["id"], {"traces": corr["trace_count"],
                                                                                "attributed_peers": len(corr.get("attributions", []))})
        return {"traces": corr["trace_count"], "services": len(corr["services"]), "paths": len(corr["edges"])}

    def ingest_window(self) -> tuple[float | None, str]:
        """Observed paths must describe the CURRENT environment: after any infrastructure change (deployment, rollback,
        Reset Demo) only traffic since that change is ingested, otherwise pre-change paths would be reported as current."""
        import time as _t
        db = self.s.db
        changes = [r[0] for r in db.execute("SELECT MAX(COALESCE(finished, started)) FROM deployment WHERE status NOT IN "
                                            "('refused-preflight','refused-window-closed','failed-no-changes','running')")]
        changes += [r[0] for r in db.execute("SELECT MAX(ts) FROM audit WHERE action IN ('deployment.rolled-back','reset_demo.verified',"
                                             "'reset_demo.verification-failed')")]
        last = max([c for c in changes if c] or [0])
        lb = self.cfg["ingest"].get("lookback", "2h")
        lb_s = int(lb[:-1]) * {"h": 3600, "m": 60, "s": 1}[lb[-1]]
        if last and last > _t.time() - lb_s:
            return last, f"traffic since the last infrastructure change at {_t.strftime('%H:%M:%S UTC', _t.gmtime(last))}"
        return None, f"traffic of the last {lb}"

    # ------------------------------------------------------------------ RECONCILE
    def reconcile(self) -> int:
        """Merge described components into technical assets when identity evidence matches (name/alias/address)."""
        assets = self.s.assets()
        described = [a for a in assets if a["key"].startswith("described:")]
        technical = [a for a in assets if not a["key"].startswith("described:") and set(a["sources"]) - {"describe"}]
        compat = {"a2a_agent": {"a2a_agent", "ai_agent"}, "ai_agent": {"a2a_agent", "ai_agent"}, "mcp_server": {"mcp_server", "mcp_service"},
                  "mcp_service": {"mcp_server", "mcp_service"}}
        merged = 0
        for d in described:
            addr = d["attrs"].get("asserted_address")
            ak = d["attrs"].get("asserted_kind")
            best, score, second = None, 0.0, 0.0
            for t in technical:
                if addr and (t["key"].endswith(addr) or addr in str(t["attrs"].get("address"))):
                    best, score, second = t, 1.0, 0.0
                    break
                if ak not in (None, "unknown", "asserted_component", "client_app") and t["kind"] not in compat.get(ak, {ak}):
                    continue   # a name match never crosses component kinds (an "agent" is not an MCP server)
                aliases = " ".join([t["name"]] + list(t["attrs"].get("dns_names") or []) +
                                   [str(t["attrs"].get(k) or "") for k in ("otel_service", "agent_name", "server_name")] +
                                   [str((t["attrs"].get("mcp") or {}).get("server_name") or ""),
                                    str((t["attrs"].get("agent_card") or {}).get("name") or "")])
                ov = _tokens(d["name"]) & _tokens(aliases)
                kind_ok = d["attrs"].get("asserted_kind") in (t["kind"], None, "unknown") or \
                    (d["attrs"].get("asserted_kind") == "mcp_server" and t["kind"] == "mcp_service")
                sc = len(ov) / max(1, len(_tokens(d["name"]))) + (0.25 if kind_ok else 0)
                if ov and sc > score:
                    best, score, second = t, sc, score
                elif ov and sc > second:
                    second = sc
            if best and score < 1.0 and score - second < 0.01:   # two equally good candidates: ambiguous, do not guess
                best, score = None, 0.0
            if not best or score < 0.75:   # unique-kind fallback: exactly one technical asset of the asserted kind
                same = [t for t in technical if t["kind"] in compat.get(ak, {ak}) and not t["key"].startswith(("otel:", "client:"))]
                if len(same) == 1:
                    best, score = same[0], 0.75
            if best and score >= 0.75:
                eid = self.s.add_evidence("describe", "reconciliation",
                                          f"Matched described '{d['name']}' to discovered '{best['name']}' (score {score:.2f})",
                                          {"described": d["key"], "matched": best["key"], "score": score})
                self.s.merge_assets(best["id"], d["id"], eid, "name/alias/address match")
                merged += 1
        return merged

    # ------------------------------------------------------------------ ASSESS
    def assess(self) -> dict:
        return assess.run(self.s, self.cfg)
