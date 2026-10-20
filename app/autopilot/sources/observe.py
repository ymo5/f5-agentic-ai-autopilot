"""OBSERVE — BIG-IP configuration and traffic statistics (read-only).

Two collection modes produce the same normalized model:
  * snapshot: raw iControl REST GET responses collected by the operator workstation
    (scripts/observe-collect.sh, credentials stay in the macOS Keychain) and uploaded to Autopilot;
  * live: direct GETs from Autopilot using a dedicated read-only BIG-IP account (requires owner approval
    to create that account; not configured by default).
Only GET requests are ever issued.
"""
from __future__ import annotations

import httpx

ENDPOINTS = {
    "version": "/mgmt/tm/sys/version",
    "provision": "/mgmt/tm/sys/provision",
    "global": "/mgmt/tm/sys/global-settings",
    "vlan": "/mgmt/tm/net/vlan",
    "self": "/mgmt/tm/net/self",
    "virtual": "/mgmt/tm/ltm/virtual?expandSubcollections=true",
    "virtual_stats": "/mgmt/tm/ltm/virtual/stats",
    "pool": "/mgmt/tm/ltm/pool?expandSubcollections=true",
    "pool_stats": "/mgmt/tm/ltm/pool/stats",
    "monitor_http": "/mgmt/tm/ltm/monitor/http",
    "monitor_https": "/mgmt/tm/ltm/monitor/https",
    "rule": "/mgmt/tm/ltm/rule",
    "persistence_universal": "/mgmt/tm/ltm/persistence/universal",
    "clientssl": "/mgmt/tm/ltm/profile/client-ssl",
    "as3": "/mgmt/shared/appsvcs/info",
    "log_destination": "/mgmt/tm/sys/log-config/destination/management-port",
}

# Wave 3 placement evidence: extra read-only GETs used ONLY by the operator-run collector (scripts/observe-collect.sh) and
# parsed by normalize(). Deliberately separate from ENDPOINTS, which the privileged deployer iterates from its own image:
# the deployer's collection does not change, now or after a future deployer rebuild.
PLACEMENT_ENDPOINTS = {
    "route": "/mgmt/tm/net/route",
    "failover_status": "/mgmt/tm/cm/failover-status",
    "device_group": "/mgmt/tm/cm/device-group?expandSubcollections=true",
    "memory": "/mgmt/tm/sys/memory",
    "cpu": "/mgmt/tm/sys/cpu",            # optional (placement-only CPU warning)
}
OPTIONAL_PLACEMENT = {"cpu"}


async def collect_live(base_url: str, username: str, password: str, verify: bool | str = False) -> dict:
    raw = {}
    async with httpx.AsyncClient(base_url=base_url, auth=(username, password), verify=verify, timeout=20) as c:
        for k, path in ENDPOINTS.items():
            r = await c.get(path)
            raw[k] = {"status": r.status_code, "body": r.json() if "json" in r.headers.get("content-type", "") else None}
    return raw


def _items(raw: dict, key: str) -> list[dict]:
    b = (raw.get(key) or {}).get("body") or {}
    return b.get("items") or []


def _stat_entries(raw: dict, key: str) -> dict:
    b = (raw.get(key) or {}).get("body") or {}
    out = {}
    for url, v in (b.get("entries") or {}).items():
        ent = v.get("nestedStats", {}).get("entries", {})
        name = (ent.get("tmName") or {}).get("description") or url.rsplit("/", 2)[-2].replace("~", "/")
        out[name] = {k: (x.get("value") if "value" in x else x.get("description")) for k, x in ent.items()}
    return out


def normalize(raw: dict) -> dict:
    ver = {}
    for v in (((raw.get("version") or {}).get("body") or {}).get("entries") or {}).values():
        ver = {k: x.get("description") for k, x in v["nestedStats"]["entries"].items()}
    vstats = _stat_entries(raw, "virtual_stats")
    pstats = _stat_entries(raw, "pool_stats")
    pools = {}
    for p in _items(raw, "pool"):
        members = (p.get("membersReference") or {}).get("items") or []
        pools[p["fullPath"]] = {
            "name": p["fullPath"], "lb_mode": p.get("loadBalancingMode"), "monitor": (p.get("monitor") or "").strip() or None,
            "members": [{"name": m["name"], "address": m.get("address"), "state": m.get("state"), "session": m.get("session")} for m in members],
            "stats": {k: pstats.get(p["fullPath"], {}).get(k) for k in ("serverside.curConns", "serverside.totConns", "status.availabilityState")},
        }
    virtuals = []
    for v in _items(raw, "virtual"):
        dest = v.get("destination", "").split("/")[-1]
        addr, _, port = dest.rpartition(":") if ":" in dest else dest.rpartition(".")
        profiles = [x["fullPath"] for x in (v.get("profilesReference") or {}).get("items") or []]
        st = vstats.get(v["fullPath"], {})
        virtuals.append({
            "name": v["fullPath"], "address": addr.split("%")[0], "port": int(port) if port.isdigit() else None,
            "pool": v.get("pool"), "profiles": profiles, "rules": v.get("rules") or [],
            "persist": [x.get("name") for x in v.get("persist") or []],
            "snat": (v.get("sourceAddressTranslation") or {}).get("type"),
            "enabled": v.get("enabled", True),
            "stats": {k: st.get(k) for k in ("clientside.totConns", "clientside.curConns", "status.availabilityState")},
        })
    return {
        "device": {"version": ver.get("Version"), "build": ver.get("Build"), "edition": ver.get("Edition"),
                   "hostname": ((raw.get("global") or {}).get("body") or {}).get("hostname"),
                   "provisioned": {p["name"]: p["level"] for p in _items(raw, "provision") if p.get("level") != "none"},
                   "as3_installed": (raw.get("as3") or {}).get("status") == 200},
        "vlans": [{"name": x["fullPath"], "interfaces": [i["name"] for i in (x.get("interfacesReference") or {}).get("items", [])]} for x in _items(raw, "vlan")],
        "self_ips": [{"name": x["fullPath"], "address": x["address"].split("/")[0].split("%")[0], "vlan": x.get("vlan")} for x in _items(raw, "self")],
        "virtuals": virtuals, "pools": list(pools.values()),
        "monitors": [m["fullPath"] for k in ("monitor_http", "monitor_https") for m in _items(raw, k)],
        "irules": [r["fullPath"] for r in _items(raw, "rule") if not r["fullPath"].startswith("/Common/_sys_")],
        "persistence_profiles": [p["fullPath"] for p in _items(raw, "persistence_universal")],
        "clientssl_profiles": [{"name": p["fullPath"], "peer_cert_mode": p.get("peerCertMode")} for p in _items(raw, "clientssl")],
        "mgmt_log_destinations": [d["fullPath"] for d in _items(raw, "log_destination")],
        **placement_evidence(raw),
    }


# ------------------------------------------------------------------ Wave 3 placement evidence (additive model keys)
# Evidence states, never conflated:
#   observed           HTTP 200 with a parseable body
#   missing            not part of this collection (e.g. the deployer path, or an older collector)
#   permission_denied  HTTP 401 / 403 — the collector's account may not read it
#   unsupported        HTTP 400 / 404 / 501 — the endpoint or module is not available on this device
#   malformed          HTTP 200 but the body does not have the expected shape
#   failed             no HTTP answer (timeout, TLS or connection error) or HTTP 5xx
# ("stale" is decided at evaluation time from collected_at; see placement_policy max_sample_age_s.)
def _state(raw: dict, key: str) -> str:
    if key not in raw:
        return "missing"
    code = (raw.get(key) or {}).get("status")
    if code in (401, 403):
        return "permission_denied"
    if code in (400, 404, 501):
        return "unsupported"
    if code == 200:
        return "observed" if isinstance((raw.get(key) or {}).get("body"), (dict, list)) else "malformed"
    return "failed"


def _find_key(o, key):
    if isinstance(o, dict):
        if key in o:
            return o
        for v in o.values():
            r = _find_key(v, key)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = _find_key(v, key)
            if r is not None:
                return r
    return None


def memory_usage(body) -> dict | None:
    """Control-plane ('Other') and swap utilisation from /mgmt/tm/sys/memory — the same arithmetic as the deployer's
    preflight (deployer/engine.py _memory), copied so the web side never imports the deployer; a test keeps them equal."""
    e = _find_key(body, "otherMemoryTotal")
    if not e:
        return None
    val = lambda k: (e.get(k) or {}).get("value") if isinstance(e.get(k), dict) else e.get(k)  # noqa: E731
    try:
        ot, ou, st, su = (float(val(k)) for k in ("otherMemoryTotal", "otherMemoryUsed", "swapTotal", "swapUsed"))
        return {"other_used_pct": round(100 * ou / ot, 1) if ot else None, "swap_used_pct": round(100 * su / st, 1) if st else 0.0,
                "other_total_mb": round(ot / 1048576), "swap_total_mb": round(st / 1048576)}
    except (TypeError, ValueError):
        return None


def _cpu_pct(body) -> float | None:
    """Mean (100 - one-minute idle) over the CPUs listed by /mgmt/tm/sys/cpu; None if the shape is not recognised."""
    idles = []

    def walk(o):
        if isinstance(o, dict):
            if "oneMinAvgIdle" in o:
                v = o["oneMinAvgIdle"]
                v = v.get("value") if isinstance(v, dict) else v
                try:
                    idles.append(float(v))
                except (TypeError, ValueError):
                    pass
            for x in o.values():
                walk(x)
        elif isinstance(o, list):
            for x in o:
                walk(x)
    walk(body)
    return round(100 - sum(idles) / len(idles), 1) if idles else None


def _addr(text: str):
    """'10.1.0.0%2/16' -> ('10.1.0.0', 2, 16); route domain 0 when %RD is omitted (iControl convention)."""
    import re
    m = re.match(r"^([0-9.]+)(?:%(\d+))?(?:/(\d+))?$", str(text or ""))
    return (m.group(1), int(m.group(2) or 0), int(m.group(3)) if m.group(3) else None) if m else None


def placement_evidence(raw: dict) -> dict:
    meta = raw.get("_meta") if isinstance(raw.get("_meta"), dict) else {}
    st = {k: _state(raw, k) for k in ("self", "route", "failover_status", "device_group", "memory", "cpu", "as3", "provision", "virtual", "pool")}
    out: dict = {"collection": {k: {"http_status": (raw.get(k) or {}).get("status") if k in raw else None, "state": v} for k, v in st.items()},
                 "collected_at": meta.get("collected_at"),
                 "collector": meta.get("collector"),
                 "device_ref": meta.get("device") if isinstance(meta.get("device"), dict) else None}
    # self IP subnets (already collected by every path; the legacy self_ips list keeps its original shape)
    nets = []
    if st["self"] == "observed":
        for x in _items(raw, "self"):
            a = _addr(x.get("address"))
            if a and a[2] is not None:
                nets.append({"name": x.get("fullPath"), "address": a[0], "route_domain": a[1], "prefixlen": a[2],
                             "network": f"{a[0]}/{a[2]}", "vlan": x.get("vlan"), "floating": x.get("floating") == "enabled",
                             "traffic_group": x.get("trafficGroup")})
        if _items(raw, "self") and not nets:
            st["self"] = "malformed"
    out["self_ip_networks"] = nets
    # static routes
    routes = None
    if st["route"] == "observed":
        routes = []
        for r in _items(raw, "route"):
            net = str(r.get("network", ""))
            if net in ("default", "default-inet6") or ":" in net:
                if net == "default":
                    routes.append({"name": r.get("fullPath"), "network": "0.0.0.0/0", "route_domain": 0,
                                   "gw": (_addr(r.get("gw")) or [None])[0], "via": "gw" if r.get("gw") else "other"})
                continue
            a = _addr(net)
            if not a or a[2] is None:
                continue
            via = "gw" if r.get("gw") else "interface" if r.get("tmInterface") else "blackhole" if r.get("blackhole") else "pool" if r.get("pool") else "other"
            routes.append({"name": r.get("fullPath"), "network": f"{a[0]}/{a[2]}", "route_domain": a[1],
                           "gw": (_addr(r.get("gw")) or [None])[0], "interface": r.get("tmInterface"), "via": via})
    out["routes"] = routes
    # HA: failover status + sync-failover device group membership
    ha: dict = {}
    if st["failover_status"] == "observed":
        node = _find_key(raw["failover_status"]["body"], "status")
        val = (node or {}).get("status")
        val = val.get("description") if isinstance(val, dict) else val
        if isinstance(val, str) and val:
            ha["failover_state"] = val.strip().lower()
            summ = (node or {}).get("summary")
            summ = summ.get("description") if isinstance(summ, dict) else summ
            if isinstance(summ, str) and summ:
                ha["summary"] = summ                       # informational, e.g. "1/1 active"
        else:
            st["failover_status"] = "malformed"
    if st["device_group"] == "observed":
        groups = [g for g in _items(raw, "device_group") if g.get("type") == "sync-failover"]
        clustered = [g for g in groups if len(((g.get("devicesReference") or {}).get("items") or [])) > 1]
        ha["mode"] = "clustered" if clustered else "standalone"   # sync-only groups (trust, gtm) never imply an HA pair
        ha["sync_failover_groups"] = len(groups)
        ha["device_group"] = clustered[0].get("fullPath") or clustered[0].get("name") if clustered else None
    out["ha"] = ha or None
    # health (memory + swap from sys/memory; REST latency from the collector's own timing of each read-only GET)
    health: dict = {}
    if st["memory"] == "observed":
        m = memory_usage(raw["memory"]["body"])
        if m:
            health.update(control_plane_memory_pct=m["other_used_pct"], swap_pct=m["swap_used_pct"])
            host = _find_key(raw["memory"]["body"], "memoryTotal")      # informational only; not a policy metric
            hv = lambda k: (host.get(k) or {}).get("value") if isinstance(host.get(k), dict) else host.get(k)  # noqa: E731
            try:
                health["host_memory_pct_info"] = round(100 * float(hv("memoryUsed")) / float(hv("memoryTotal")), 1)
            except (TypeError, ValueError, ZeroDivisionError, AttributeError):
                pass
        else:
            st["memory"] = "malformed"
    if st["cpu"] == "observed":
        c = _cpu_pct(raw["cpu"]["body"])
        if c is not None:
            health["cpu_pct"] = c
            health["cpu_method"] = "100 - mean one-minute idle across the listed CPUs"
        else:
            st["cpu"] = "malformed"
    timings = {k: v for k, v in (meta.get("timings_s") or {}).items() if isinstance(v, (int, float))}
    if timings:
        health["rest_latency_s"] = round(max(timings.values()), 3)
        health["rest_latency_method"] = f"slowest of {len(timings)} read-only GETs in this collection"
    if health:
        health["sampled_at"] = meta.get("collected_at")
    out["health"] = health or None
    a3 = (raw.get("as3") or {}).get("body") if st["as3"] == "observed" else None
    out["as3_version"] = a3.get("version") if isinstance(a3, dict) and isinstance(a3.get("version"), str) else None
    for k in out["collection"]:
        out["collection"][k]["state"] = st[k]
    out["evidence_state"] = {
        "self_ip_networks": st["self"], "routes": st["route"],
        "ha": "observed" if st["failover_status"] == "observed" and st["device_group"] == "observed" else
              next(s for s in (st["failover_status"], st["device_group"]) if s != "observed"),
        "health": "observed" if st["memory"] == "observed" and timings else (st["memory"] if st["memory"] != "observed" else "missing"),
        "cpu": st["cpu"],
        "as3": st["as3"], "provision": st["provision"],
        "virtuals": st["virtual"], "pools": st["pool"],    # lets placement tell "observed: none" from "not collected"
    }
    return out
