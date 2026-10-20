"""Environment profiles for the F5 AI workload simulator (standard library only, Python 3.9+).

An environment profile says, for one lab, which endpoints the simulator may contact, which workloads exist there,
which of them are actually available, how each target is reached (transport, TLS, client identity), which operations
are allowed and what the traffic budgets are.

Two locks protect the destination set:
  1. APPROVED below is pinned in code, per environment. A profile file can only *select* from it; an address that is not
     pinned here is refused even if a profile names it.
  2. The profile file itself is not editable from the Control Center UI. The UI can only choose between profiles.

Environments
  project-b  AI Data Delivery (frozen reference lab, BIG-IP 192.0.2.49). The legacy behaviour: the runtime config is
             sim-config.json, unchanged, and the allow-list equals f5_ai_workload_sim.ALLOWED.
  project-a  Agentic AI Autopilot (BIG-IP_C 192.0.2.16, isolated 10.50.10.0/24 agent network, mTLS on the MCP VIPs).

A workload is AVAILABLE only if every destination it uses is configured. A destination whose BIG-IP virtual server does
not exist is NOT CONFIGURED; the simulator never substitutes the backend address (that would bypass BIG-IP and
misattribute the traffic to F5 delivery). Known backend addresses are listed in FORBIDDEN_DIRECT so that the refusal is
explicit and testable.
"""
import json, os, re

LEGACY_ENV = "project-b"

# ---------------------------------------------------------------------------------------------- pinned destinations
APPROVED = {
    "project-b": {
        "10.1.10.130:8001": "MCP_VIP", "10.1.10.131:8001": "MCP_JSON_VIP", "10.1.10.132:8001": "MCP_RATE_VIP",
        "10.1.10.133:8001": "MCP_HSL_VIP", "10.1.10.135:8001": "MCP_AIMCP_VIP", "10.1.10.134:8001": "AI_SSE_VIP",
        "10.1.10.100:8333": "S3_VIP", "10.1.10.110:8501": "CHATBOT_VIP", "10.1.10.120:8000": "VECTOR_VIP",
        "127.0.0.1:9464": "collector", "10.1.10.10:9464": "collector", "192.0.2.50:9464": "collector",
        "127.0.0.1:11434": "Ollama (local)",
    },
    "project-a": {
        "10.50.10.100:443": "A2A_VIP (/AP_AI/a2a_risk_assessment_agent)",
        "10.50.10.101:443": "MCP_RISK_VIP (/AP_AI/mcp_risk_scoring)",
        "10.50.10.102:443": "MCP_INTEL_VIP (/AP_AI/mcp_fraud_intel)",
        "192.0.2.61:8080": "Agent A API (management LAN)",
        "192.0.2.60:8000": "Autopilot UI (management LAN, health only)",
        "10.50.10.103:8333": "S3_VIP (/AP_AI/s3_seaweedfs)",
        "10.50.10.104:6333": "RAG_VIP (/AP_AI/rag_qdrant)",
        "10.50.10.105:11434": "INFERENCE_VIP (/AP_AI/llm_ollama)",
    },
}

# Backend addresses that exist in Project A but sit BEHIND BIG-IP_C. Contacting them directly would bypass F5.
FORBIDDEN_DIRECT = {
    "10.50.20.41:8333": "SeaweedFS S3 backend",
    "10.50.20.40:6333": "Qdrant backend",
    "10.50.20.45:11434": "Ollama backend",
    "10.50.20.31:8000": "MCP risk-scoring replica 1",
    "10.50.20.32:8000": "MCP risk-scoring replica 2",
    "10.50.20.33:8000": "MCP fraud-intel backend",
    "10.50.20.22:9000": "Agent B backend",
    "10.50.10.22:9000": "Agent B (direct)",
}

# Operation classes the code knows how to perform. A profile may narrow them, never widen them.
KNOWN_MCP_METHODS = ("initialize", "notifications/initialized", "tools/list", "tools/call", "server/discover", "ping")
KNOWN_S3_OPS = ("HeadObject", "GetObject", "ListObjectsV2")
KNOWN_QDRANT_OPS = ("GET /collections/{collection}", "POST /collections/{collection}/points/query")
# Plain-HTTP operations per BIG-IP-delivered destination: bounded inference (no model pull / delete / create) and A2A discovery.
KNOWN_HTTP_OPS = {"INFERENCE_VIP": ("POST /api/embed", "POST /v1/chat/completions", "POST /api/generate"),
                  "A2A_VIP": ("GET /.well-known/agent-card.json",)}

# Test-only environments, registered from unit tests through register_test_environment(); never from files or the UI.
_TEST_ENVS = {}

STATUSES = ("configured", "not_configured")
WL_AVAILABLE, WL_NOT_CONFIGURED, WL_NOT_SUPPORTED, WL_REQUIRES_IDENTITY, WL_REQUIRES_CREDENTIALS = (
    "available", "not_configured", "not_supported", "requires_identity", "requires_credentials")


class ProfileError(ValueError):
    pass


def register_test_environment(name, approved):
    """Unit tests only: an offline environment whose endpoints are local mock servers (127.0.0.1:<port>)."""
    if not name.startswith("offline-test"):
        raise ProfileError("test environments must be named offline-test*")
    if any(not re.match(r"^127\.0\.0\.1:\d{1,5}$", hp) for hp in approved):
        raise ProfileError("test environments may only approve 127.0.0.1 endpoints")
    _TEST_ENVS[name] = dict(approved)


def approved(env):
    if env in APPROVED:
        return dict(APPROVED[env])
    if env in _TEST_ENVS:
        return dict(_TEST_ENVS[env])
    raise ProfileError(f"unknown environment {env!r}")


def environments():
    return sorted(APPROVED)


def hostport(address):
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$", address or "")
    if not m:
        raise ProfileError(f"destination address must be IPv4:port, got {address!r}")
    return m.group(1), int(m.group(2))


# ---------------------------------------------------------------------------------------------- loading + validation
def load(path):
    with open(path) as f:
        prof = json.load(f)
    validate(prof)
    return prof


def validate(prof):
    """Structural + safety validation. Raises ProfileError listing every problem."""
    errs = []
    env = prof.get("environment")
    try:
        pinned = approved(env)
    except ProfileError as e:
        raise ProfileError(str(e))
    tls = prof.get("tls") or {}
    for name, d in (prof.get("destinations") or {}).items():
        st = d.get("status")
        if st not in STATUSES:
            errs.append(f"destination {name}: status must be one of {STATUSES}"); continue
        if st == "not_configured":
            if d.get("address"):
                errs.append(f"destination {name}: a not_configured destination must not carry an address")
            if not d.get("reason"):
                errs.append(f"destination {name}: not_configured requires a reason")
            continue
        try:
            hostport(d.get("address"))
        except ProfileError as e:
            errs.append(f"destination {name}: {e}"); continue
        if d["address"] in FORBIDDEN_DIRECT:
            errs.append(f"destination {name}: {d['address']} is a backend behind BIG-IP ({FORBIDDEN_DIRECT[d['address']]}); "
                        "direct access would bypass F5 and is refused")
        elif d["address"] not in pinned:
            errs.append(f"destination {name}: {d['address']} is not an approved {env} endpoint")
        if d.get("scheme") not in ("http", "https"):
            errs.append(f"destination {name}: scheme must be http or https")
        if d.get("scheme") == "https":
            if d.get("tls_verify") is False and env != LEGACY_ENV:
                errs.append(f"destination {name}: TLS verification may only be disabled in the legacy {LEGACY_ENV} profile")
            if env != LEGACY_ENV and not d.get("server_name"):
                errs.append(f"destination {name}: https requires server_name (certificate hostname verification)")
            if d.get("auth") == "mtls" and not (tls.get("client_identity") or {}).get("cert_file_env"):
                errs.append(f"destination {name}: mtls requires tls.client_identity.cert_file_env")
            if env != LEGACY_ENV and not tls.get("ca_file_env"):
                errs.append(f"destination {name}: https requires tls.ca_file_env (lab CA)")
    dests = prof.get("destinations") or {}
    ops = prof.get("allowed_operations") or {}
    bad_m = set(ops.get("mcp_methods", [])) - set(KNOWN_MCP_METHODS)
    if bad_m:
        errs.append(f"allowed_operations.mcp_methods: unknown {sorted(bad_m)}")
    if set(ops.get("s3", [])) - set(KNOWN_S3_OPS):
        errs.append("allowed_operations.s3: only read operations HeadObject / GetObject / ListObjectsV2 are supported")
    if set(ops.get("qdrant", [])) - set(KNOWN_QDRANT_OPS):
        errs.append("allowed_operations.qdrant: only read-only collection info and points/query are supported")
    for dn, known in KNOWN_HTTP_OPS.items():
        extra = set((ops.get("http") or {}).get(dn, [])) - set(known)
        if extra:
            errs.append(f"allowed_operations.http.{dn}: only {list(known)} are supported, not {sorted(extra)}")
    g = prof.get("activity_guard")
    if g is not None:
        gd = dests.get(g.get("destination"))
        if gd is None or gd.get("via_bigip"):
            errs.append("activity_guard: destination must be a management-plane destination (Agent A API), not a BIG-IP VIP")
        gp = (g.get("path") or "").split("?")[0]
        if f"GET {gp}" not in (ops.get("http") or {}).get(g.get("destination"), []):
            errs.append(f"activity_guard: GET {gp} is not an allowed operation for {g.get('destination')}")
        if not isinstance(g.get("quiet_s"), int) or not 60 <= g["quiet_s"] <= 3600:
            errs.append("activity_guard: quiet_s must be 60..3600")
    insts = prof.get("instances") or {}
    for name, w in (prof.get("workloads") or {}).items():
        if w.get("instance") not in insts:
            errs.append(f"workload {name}: unknown instance {w.get('instance')!r}")
        for dn in workload_destinations(w):
            if dn not in dests:
                errs.append(f"workload {name}: unknown destination {dn!r}")
        for k in ("url", "urls", "endpoint", "host", "port"):
            if k in w:
                errs.append(f"workload {name}: raw '{k}' is not allowed in a profile; reference a destination by name")
        if w.get("defer_while_investigating") and not prof.get("activity_guard"):
            errs.append(f"workload {name}: defer_while_investigating requires a profile-level activity_guard")
        if w.get("status") == WL_NOT_SUPPORTED and not w.get("reason"):
            errs.append(f"workload {name}: not_supported requires a reason")
        if w.get("kind") == "mcp_identity_authz":
            probe = w.get("deny_probe_tool")
            if probe and probe not in ops.get("mcp_deny_probe_tools", []):
                errs.append(f"workload {name}: deny probe tool {probe!r} is not in allowed_operations.mcp_deny_probe_tools")
        for t in (w.get("tools") or {}).values():
            if t not in ops.get("mcp_tools", []):
                errs.append(f"workload {name}: tool {t!r} is not in allowed_operations.mcp_tools")
        if w.get("allowed_tool") and w["allowed_tool"] not in ops.get("mcp_tools", []):
            errs.append(f"workload {name}: tool {w['allowed_tool']!r} is not in allowed_operations.mcp_tools")
    b = prof.get("budgets") or {}
    for name, i in insts.items():
        rpm = i.get("max_requests_per_minute")
        cap = b.get("max_requests_per_minute_cap", 60)
        if not isinstance(rpm, int) or not 1 <= rpm <= min(60, cap):
            errs.append(f"instance {name}: max_requests_per_minute must be 1..{min(60, cap)}")
    for name, w in (prof.get("workloads") or {}).items():
        if w.get("status") == WL_NOT_SUPPORTED:
            continue
        if not isinstance(w.get("max_per_hour"), int) or not 1 <= w["max_per_hour"] <= 120:
            errs.append(f"workload {name}: max_per_hour must be 1..120")
        if not isinstance(w.get("interval_s"), (int, float)) or w["interval_s"] < 10:
            errs.append(f"workload {name}: interval_s must be >= 10")
    if errs:
        raise ProfileError("; ".join(errs))
    return True


def workload_destinations(w):
    out = list(w.get("destinations") or [])
    if w.get("destination"):
        out.append(w["destination"])
    return out


# ---------------------------------------------------------------------------------------------- availability
def identity_ready(prof, environ=None):
    """(ready, reason) for the client identity: the environment variables must name readable files."""
    env = os.environ if environ is None else environ
    ci = (prof.get("tls") or {}).get("client_identity") or {}
    if not ci:
        return False, "no client identity defined"
    missing = [v for v in (ci.get("cert_file_env"), ci.get("key_file_env")) if v and not env.get(v)]
    if missing:
        why = "not provisioned" if not ci.get("provisioned") else "environment not set"
        return False, f"client certificate {why} ({', '.join(missing)} unset)"
    for v in (ci.get("cert_file_env"), ci.get("key_file_env")):
        if v and not os.path.isfile(env[v]):
            return False, f"{v} does not point to a readable file"
    return True, "client certificate present"


def ca_ready(prof, environ=None):
    env = os.environ if environ is None else environ
    v = (prof.get("tls") or {}).get("ca_file_env")
    if not v:
        return True, "no CA required"
    if not env.get(v):
        return False, f"lab CA not configured ({v} unset)"
    if not os.path.isfile(env[v]):
        return False, f"{v} does not point to a readable file"
    return True, "lab CA present"


def credentials_ready(spec, environ=None):
    env = os.environ if environ is None else environ
    names = [n for n in (spec or {}).values() if n]
    missing = [n for n in names if not env.get(n)]
    return (not missing), (f"credentials not set ({', '.join(missing)})" if missing else "credentials present")


def availability(prof, environ=None):
    """Per workload: {status, reason, destinations:[...], via_bigip, auth}. Static profile facts + runtime readiness
    (identity / CA / credentials are checked by environment-variable presence only; secret values are never read here)."""
    dests = prof.get("destinations") or {}
    out = {}
    for name, w in (prof.get("workloads") or {}).items():
        dn = workload_destinations(w)
        info = {"kind": w.get("kind", name), "instance": w.get("instance"), "destinations": dn,
                "via_bigip": all(dests.get(d, {}).get("via_bigip") for d in dn) if dn else False,
                "auth": sorted({dests.get(d, {}).get("auth", "none") for d in dn}) or ["none"],
                "enabled": w.get("enabled", True)}
        if w.get("status") == WL_NOT_SUPPORTED:
            info.update(status=WL_NOT_SUPPORTED, reason=w["reason"])
        elif any(dests.get(d, {}).get("status") != "configured" for d in dn):
            nc = [d for d in dn if dests.get(d, {}).get("status") != "configured"]
            reasons = "; ".join(f"{d}: {dests[d].get('reason')}" for d in nc if d in dests)
            info.update(status=WL_NOT_CONFIGURED, reason=reasons, missing=nc,
                        planned={d: dests[d].get("planned_address") for d in nc if dests.get(d, {}).get("planned_address")})
        elif w.get("defer_while_investigating") and \
                (dests.get((prof.get("activity_guard") or {}).get("destination")) or {}).get("status") != "configured":
            info.update(status=WL_NOT_CONFIGURED, reason="activity guard destination is not configured: guarded LLM workloads "
                        "never run without it (fail closed)")
        else:
            info.update(status=WL_AVAILABLE, reason="all destinations configured")
            needs_tls = any(dests[d].get("scheme") == "https" for d in dn)
            if needs_tls:
                ok, why = ca_ready(prof, environ)
                if not ok:
                    info.update(status=WL_REQUIRES_IDENTITY, reason=why)
            if info["status"] == WL_AVAILABLE and (w.get("requires_identity") or any(dests[d].get("auth") == "mtls" for d in dn)):
                ok, why = identity_ready(prof, environ)
                if not ok:
                    info.update(status=WL_REQUIRES_IDENTITY, reason=why)
            if info["status"] == WL_AVAILABLE and w.get("credentials_env"):
                ok, why = credentials_ready(w["credentials_env"], environ)
                if not ok:
                    info.update(status=WL_REQUIRES_CREDENTIALS, reason=why)
        out[name] = info
    return out


# ---------------------------------------------------------------------------------------------- resolution for the engine
def target(prof, dname, path=None):
    """A resolved, allow-listed target for the engine: url (as the server sees it), connect address, TLS spec."""
    d = (prof.get("destinations") or {})[dname]
    if d.get("status") != "configured":
        raise ProfileError(f"{dname} is not configured: {d.get('reason')}")
    host, port = hostport(d["address"])
    name = d.get("server_name") or host
    p = path if path is not None else d.get("path", "/")
    url = f"{d['scheme']}://{name}{'' if (d['scheme'], port) in (('http', 80), ('https', 443)) else ':' + str(port)}{p}"
    tls = None
    if d["scheme"] == "https":
        t = prof.get("tls") or {}
        ci = t.get("client_identity") or {}
        tls = {"verify": d.get("tls_verify", True), "server_name": d.get("server_name"), "ca_file_env": t.get("ca_file_env"),
               "cert_file_env": ci.get("cert_file_env") if d.get("auth") == "mtls" else None,
               "key_file_env": ci.get("key_file_env") if d.get("auth") == "mtls" else None}
    return {"name": dname, "url": url, "address": d["address"], "connect_host": host, "connect_port": port,
            "scheme": d["scheme"], "via_bigip": bool(d.get("via_bigip")), "auth": d.get("auth", "none"), "tls": tls,
            "bigip_object": d.get("bigip_object")}


def activity_guard(prof):
    """Resolved Agent A activity guard (profile key activity_guard) for workloads with defer_while_investigating."""
    g = prof.get("activity_guard") or {}
    if not g.get("destination"):
        raise ProfileError("defer_while_investigating requires a profile-level activity_guard with a destination")
    return {"target": target(prof, g["destination"]), "path": g.get("path", "/api/investigations?limit=5"),
            "quiet_s": int(g.get("quiet_s", 600))}


def resolve(prof, instance, environ=None):
    """(instance_cfg, {workload: cfg}) in the engine's unified shape. Workloads that are not AVAILABLE are returned with
    `_unavailable` set (the engine refuses to construct them; dry-run lists them with their reason)."""
    insts = prof.get("instances") or {}
    if instance not in insts:
        raise SystemExit(f"--instance must be one of {sorted(insts)}")
    inst = {k: v for k, v in insts[instance].items() if not k.startswith("_")}
    inst["environment"] = prof["environment"]
    av = availability(prof, environ)
    out = {}
    for name, w in (prof.get("workloads") or {}).items():
        if w.get("instance") != instance:
            continue
        cfg = {k: v for k, v in w.items() if k not in ("instance", "destination", "destinations") and not k.startswith("_")}
        a = av[name]
        if a["status"] != WL_AVAILABLE:
            cfg["_unavailable"] = {"status": a["status"], "reason": a["reason"]}
        else:
            cfg["targets"] = {dn: target(prof, dn) for dn in workload_destinations(w)}
            if w.get("defer_while_investigating"):
                cfg["_guard"] = activity_guard(prof)
        cfg["_ops"] = prof.get("allowed_operations") or {}
        out[name] = cfg
    return inst, out


def summary(prof, environ=None):
    """Read model for the Control Center environment page (no secret values, only env-variable names and presence)."""
    av = availability(prof, environ)
    ca_ok, ca_why = ca_ready(prof, environ)
    id_ok, id_why = identity_ready(prof, environ)
    ci = (prof.get("tls") or {}).get("client_identity") or {}
    return {"environment": prof["environment"], "label": prof.get("label"), "summary": prof.get("summary"),
            "network": prof.get("network"), "frozen": bool(prof.get("frozen")),
            "destinations": [{"name": n, **{k: v for k, v in d.items() if not k.startswith("_")},
                              "pinned": d.get("address") in approved(prof["environment"]) if d.get("address") else None}
                             for n, d in (prof.get("destinations") or {}).items()],
            "workloads": av, "budgets": prof.get("budgets") or {},
            "instances": {n: {k: v for k, v in i.items() if not k.startswith("_")} for n, i in (prof.get("instances") or {}).items()},
            "allowed_operations": prof.get("allowed_operations") or {},
            "auth": {"ca": {"env": (prof.get("tls") or {}).get("ca_file_env"), "ready": ca_ok, "detail": ca_why},
                     "client_identity": {"cn": ci.get("cn"), "cert_env": ci.get("cert_file_env"), "key_env": ci.get("key_file_env"),
                                         "provisioned": bool(ci.get("provisioned")), "ready": id_ok, "detail": id_why,
                                         "required_allowlist": ci.get("required_allowlist"), "note": ci.get("note")} if ci else None},
            "telemetry": prof.get("telemetry") or {}, "metric_sources": prof.get("metric_sources") or {}}
