"""AI Operations dashboard — read model (web container, READ-ONLY towards every infrastructure source).

Areas and authoritative sources (nothing here writes to a device, the deployer, Jaeger, Agent A or the database):
  Overview             KPIs assembled from the blocks below (no additional source).
  AI Data Delivery     BIG-IP statistics for the AI data virtual servers / pools through the deployer's read-only
                       `data_status` / `pool_status` actions (observer account), including the S3 statistics iRule counters.
  AI Security          Autopilot validations: deployment GATE validations from the deployment journal (deployment.steps)
                       and INDEPENDENT runs (validation_run), always labelled with their origin.
  Fraud investigations Agent A's investigation list (GET, cached 5 min) + Autopilot fraud runs; per-stage execution path from
                       Jaeger via the existing fraud.timeline() (or the stored timeline of Autopilot-run investigations).
  Traffic Generator    status.json / archived runs of ap-trafficgen (read-only bind mount).

Value kinds — every number the API returns sits under one of these keys, and the UI labels it accordingly:
  lifetime    cumulative counter since the device/profile counter was last reset (no time range applies)
  delta       difference between the two most recent deployer reads made by this server (seconds given), resets detected
  duration    elapsed time of an investigation / run / stage (measured by spans or by the generator client)

Durable trace summaries: Jaeger keeps traces for only ~9-10 h in this lab. A SANITISED summary of an investigation's
execution path (stage names, span counts, busy/max milliseconds, BIG-IP path flags, token counts reported by the agent
spans, error counts — no URLs, prompts, case text, rationale or attribute values) is stored as one JSON file per trace in
AUTOPILOT_TRACE_SUMMARY_DIR (default /var/lib/autopilot/trace-summaries, inside Autopilot's own data volume; no database
table). Bounded (MAX_SUMMARIES files, MAX_SUMMARY_BYTES each), atomic writes, set to "" to disable.

Safety properties (tested): the browser chooses an area, a range from RANGES and an investigation id (validated) — never a
query, URL or destination. (The range parameter is accepted for API compatibility; the BIG-IP and validation blocks report
lifetime / delta values and are not range-dependent.)
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx

RANGES = {"15m": (900, 60), "1h": (3600, 60), "6h": (21600, 300), "24h": (86400, 900)}
BIGIP_CACHE_S = 30
AGENT_A_CACHE_S = 300               # each Agent A list call creates a trace in Jaeger: poll rarely
TRACE_CAPTURE_PER_REFRESH = 3
JAEGER_SETTLE_S = 120               # spans are exported in batches: summarise only investigations finished at least this long ago
EXPIRED_MAX = 2000                  # remembered "Jaeger no longer has this trace" verdicts (bounded, in memory)
MAX_SUMMARIES = 500
MAX_SUMMARY_BYTES = 32 * 1024
APPS = (("a2a_risk_assessment_agent", "A2A · Agent B", "security"), ("mcp_risk_scoring", "MCP risk-scoring", "security"),
        ("mcp_fraud_intel", "MCP fraud-intel", "security"), ("s3_seaweedfs", "S3 (SeaweedFS)", "data"),
        ("rag_qdrant", "RAG (Qdrant)", "data"), ("llm_ollama", "LLM (Ollama)", "data"))
DATA_SVC_APP = {"s3": "s3_seaweedfs", "rag": "rag_qdrant", "llm": "llm_ollama"}
STAGES = (("a2a", "A2A · Agent A → Agent B"), ("mcp", "MCP tools (risk / fraud-intel)"), ("embed", "Embeddings (Ollama)"),
          ("vector_db", "RAG retrieval (Qdrant)"), ("s3", "S3 case documents"), ("chat", "LLM reasoning (Ollama chat)"))
_TENANT = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_TRACE = re.compile(r"^[0-9a-f]{16,32}$")
_RUN_DIR = re.compile(r"^\d{8}T\d{6}Z$")
_WORKLOAD = re.compile(r"^[a-z0-9_]{1,40}$")
_AP_RUN = re.compile(r"^[0-9a-f]{16}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_GATE = re.compile(r"^gate\.validate\[([a-z0-9_-]{1,40})\]$")


class SourceError(Exception):
    """A data source failed; `state` is one of the dashboard states."""
    def __init__(self, state: str, detail: str):
        super().__init__(detail)
        self.state, self.detail = state, detail[:300]


def section(state: str, detail: str = "", **data) -> dict:
    return {"state": state, "detail": detail, "as_of": time.time(), **data}


def _num(v) -> float | None:
    try:
        x = float(v)
        return x if x == x else None
    except (TypeError, ValueError):
        return None


def _pct(vals, p):
    v = sorted(x for x in vals if x is not None)
    if not v:
        return None
    return round(v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))], 1)


# ================================================================== execution path from a trace timeline
def _union_ms(intervals: list[tuple[float, float]]) -> float:
    tot, cur_s, cur_e = 0.0, None, None
    for s, e in sorted(intervals):
        if cur_e is None or s > cur_e:
            if cur_e is not None:
                tot += cur_e - cur_s
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    if cur_e is not None:
        tot += cur_e - cur_s
    return round(tot, 1)


_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def endpoint_host(value) -> str | None:
    """Host of an endpoint written as a URL ("http://10.50.10.105:11434/v1"), "host:port" or a bare host — None when missing
    or malformed. Pure string parsing with urllib.parse: no DNS lookup, no network access. IPv6 is not used in this lab and is
    treated as malformed (-> unknown)."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > 2048 or any(c.isspace() for c in v):
        return None
    if "://" in v:
        try:
            u = urlsplit(v)
            host, _ = u.hostname, u.port            # .port raises ValueError on a malformed / out-of-range port
        except ValueError:
            return None
        if u.scheme.lower() not in ("http", "https"):
            return None
    else:
        if v.count(":") > 1 or "/" in v or "@" in v:
            return None
        host, _, port = v.partition(":")
        if _ and (not port.isdigit() or not 0 < int(port) < 65536):
            return None
    host = (host or "").lower().rstrip(".")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return host if all(int(o) <= 255 for o in host.split(".")) else None
    if _HOSTNAME.match(host) and not re.match(r"^[\d.]+$", host):
        return host
    return None


def classify_data_endpoint(candidates, vips, backends) -> str:
    """via_bigip | direct | unknown for one data call (embed / RAG / S3 / LLM chat). A known data VIP (address or its design
    DNS name) is via_bigip, a known backend member is direct, anything else — including malformed or absent endpoints — unknown."""
    hosts = [h for h in (endpoint_host(c) for c in candidates) if h]
    if any(h in vips for h in hosts):
        return "via_bigip"
    if any(h in backends for h in hosts):
        return "direct"
    return "unknown"


def _stage_of(e: dict) -> str | None:
    cat, tgt = e.get("category"), str(e.get("target") or "")
    if cat == "llm":
        return "embed" if ("/api/embed" in tgt or "/v1/embeddings" in tgt or "embed" in str(e.get("name") or "").lower()) else "chat"
    return cat if cat in ("a2a", "mcp", "vector_db", "s3") else None


def execution_path(timeline: dict, data_vips: set | frozenset = frozenset(), data_backends: set | frozenset = frozenset()) -> dict:
    """Sanitised per-stage summary of a fraud.timeline() result. Busy time = union of the stage's span intervals (nested and
    parallel spans are not double-counted); calls = client spans (server spans for MCP); tokens only from agent span attributes
    (gen_ai.usage.*), never estimated. Data calls (embed / RAG / S3 / LLM chat client spans) are classified from the span's
    `server.address` and URL with classify_data_endpoint(): `data_vips` = data VIP addresses and their design DNS names,
    `data_backends` = the design's backend members. A2A / MCP use the server span's peer (BIG-IP self IP), as fraud.timeline does."""
    evs = (timeline or {}).get("events") or []
    summ = (timeline or {}).get("summary") or {}
    stages = {}
    tok_in = tok_out = 0
    for e in evs:
        st = _stage_of(e)
        a = e.get("attrs") or {}
        ti, to = _num(a.get("gen_ai.usage.input_tokens")), _num(a.get("gen_ai.usage.output_tokens"))
        tok_in += int(ti or 0); tok_out += int(to or 0)
        if not st:
            continue
        counted = (e.get("kind") == "server") if st == "mcp" else (e.get("kind") == "client")
        s = stages.setdefault(st, {"intervals": [], "calls": 0, "max_ms": 0.0, "first_ms": None, "errors": 0, "paths": set()})
        start, dur = float(e.get("start_ms") or 0), float(e.get("duration_ms") or 0)
        s["intervals"].append((start, start + dur))
        s["first_ms"] = start if s["first_ms"] is None else min(s["first_ms"], start)
        s["errors"] += e.get("status") == "error"
        # A2A / MCP: the BIG-IP path is decided on the server span (peer = BIG-IP self IP), as fraud.timeline's own summary does;
        # client spans name the front door by DNS name, which cannot be matched to a VIP address here.
        if st in ("a2a", "mcp"):
            path = e.get("path") if e.get("kind") == "server" else None
        elif e.get("kind") == "client":
            path = classify_data_endpoint((a.get("server.address"), e.get("target")), data_vips, data_backends)
        else:
            path = None
        if path:
            s["paths"].add(path)
        if counted:
            s["calls"] += 1
            s["max_ms"] = max(s["max_ms"], dur)
    out = []
    for key, label in STAGES:
        s = stages.get(key)
        if not s:
            out.append({"stage": key, "label": label, "observed": False})
            continue
        out.append({"stage": key, "label": label, "observed": True, "calls": s["calls"], "busy_ms": _union_ms(s["intervals"]),
                    "max_call_ms": round(s["max_ms"], 1), "first_ms": round(s["first_ms"], 1), "errors": s["errors"],
                    "paths": sorted(s["paths"])})
    return {"trace_id": summ.get("trace_id") if _TRACE.match(str(summ.get("trace_id") or "")) else None,
            "total_ms": _num(summ.get("duration_ms")), "spans": int(summ.get("spans") or len(evs)), "errors": int(summ.get("errors") or 0),
            "services": [str(x)[:60] for x in (summ.get("services") or [])][:12],
            "bigip_paths": {k: sorted(v) for k, v in (summ.get("paths") or {}).items() if k in ("a2a", "mcp")},
            "tokens": {"input": tok_in, "output": tok_out} if (tok_in or tok_out) else None,
            "stages": out}


# ================================================================== the dashboard service
class AIOps:
    def __init__(self, cfg: dict, store, deployer_action: Callable[[dict], Awaitable[dict]],
                 http_get: Callable[[str], Awaitable[Any]] | None = None, trafficgen_dir: str | None = None,
                 clock: Callable[[], float] = time.time, trace_fetch: Callable[[str], Awaitable[Any]] | None = None,
                 summary_dir: str | None = None):
        self.cfg, self.store, self.deployer_action, self.clock = cfg, store, deployer_action, clock
        obs, design = cfg.get("observe") or {}, cfg.get("design") or {}
        self.instance, self.tenant = obs.get("bigip_mgmt"), design.get("tenant", "AP_AI")
        self.http_get = http_get or _http_get_json
        self.tg_dir = trafficgen_dir or os.environ.get("AUTOPILOT_TRAFFICGEN_DIR", "/var/lib/ap-trafficgen")
        ing = cfg.get("ingest") or {}
        j = (ing.get("jaeger_ui") or ing.get("jaeger_url") or "").rstrip("/")
        self.jaeger = j if re.match(r"^https?://[\w.-]+(:\d+)?$", j) else None
        self.trace_fetch = trace_fetch or self._jaeger_get
        self.agent_a = ((cfg.get("fraud_app") or {}).get("agent_a_api") or "").rstrip("/")
        self.summary_dir = summary_dir if summary_dir is not None else os.environ.get("AUTOPILOT_TRACE_SUMMARY_DIR", "/var/lib/autopilot/trace-summaries")
        self.paths = ({design.get("self_backend"), design.get("self_agent")} - {None}, {design.get("a2a_vip"), *(design.get("mcp_vips") or [])} - {None})
        dd = [v for v in ((design.get("data_delivery") or {}).values()) if isinstance(v, dict)]
        self.data_vips = frozenset(h for h in (endpoint_host(str(v.get(k) or "")) for v in dd for k in ("vip", "host")) if h)
        self.data_backends = frozenset(h for h in (endpoint_host(str(m)) for v in dd for m in (v.get("members") or [])) if h)
        self._cache: dict[str, tuple[float, Any]] = {}
        self._bigip_prev: dict | None = None
        self._bigip_last: dict | None = None
        self._timelines: dict[str, dict] = {}
        self._expired: dict[str, float] = {}       # trace id -> when Jaeger answered "not found" for a settled investigation

    async def _cached(self, key: str, ttl: float, fn):
        hit = self._cache.get(key)
        if hit and self.clock() - hit[0] < ttl:
            return hit[1]
        v = await fn()
        self._cache[key] = (self.clock(), v)
        return v

    # ---------------------------------------------------------------- BIG-IP (deployer, read-only observer)
    async def _bigip(self) -> dict:
        async def go():
            ds = await self.deployer_action({"action": "data_status"})
            ps = await self.deployer_action({"action": "pool_status"})
            return {"t": self.clock(), "ds": ds, "ps": ps}
        try:
            snap = await self._cached("bigip", BIGIP_CACHE_S, go)
        except Exception as e:
            return section("unavailable", f"deployer read failed: {type(e).__name__}: {str(e)[:160]}")
        if self._bigip_last is not snap:
            self._bigip_prev, self._bigip_last = self._bigip_last, snap
        ds, ps = snap["ds"] or {}, snap["ps"] or {}
        vss = {k: {kk: vv for kk, vv in v.items() if kk in ("http.numberReqs", "clientside.totConns", "clientside.curConns",
                                                              "clientside.bitsIn", "clientside.bitsOut")}
               for k, v in (ds.get("virtual_servers") or {}).items() if k in DATA_SVC_APP}
        s3 = {k: v for k, v in (ds.get("s3_statistics") or {}).items() if re.match(r"^s3_[a-z0-9_]{1,40}$", str(k)) and _num(v) is not None}
        members = [{k: m.get(k) for k in ("service", "member", "port", "availability", "enabled")} for m in ds.get("members") or []]
        members += [{"service": "mcp_risk", **{k: m.get(k) for k in ("member", "port", "availability", "enabled")}} for m in ps.get("members") or []]
        delta = None
        prev = self._bigip_prev
        if prev and snap["t"] > prev["t"]:
            d = {"seconds": round(snap["t"] - prev["t"], 1), "resets": [], "s3": {}, "data_vips": {}}
            ps3 = {k: _num(v) for k, v in ((prev["ds"] or {}).get("s3_statistics") or {}).items()}
            for k, v in s3.items():
                if ps3.get(k) is not None:
                    dv = _num(v) - ps3[k]
                    d["s3"][k] = dv if dv >= 0 else None
                    if dv < 0:
                        d["resets"].append(k)
            pv = (prev["ds"] or {}).get("virtual_servers") or {}
            for svc, v in vss.items():
                for kk in ("http.numberReqs", "clientside.totConns"):
                    a, b = _num(v.get(kk)), _num((pv.get(svc) or {}).get(kk))
                    if a is not None and b is not None:
                        d["data_vips"].setdefault(svc, {})[kk] = a - b if a >= b else None
                        if a < b:
                            d["resets"].append(f"{svc}.{kk}")
            delta = d
        return section("ok", ds.get("source") or "BIG-IP iControl REST GET (observer)", read_at=snap["t"],
                       lifetime={"data_vips": vss, "s3_statistics": s3}, delta=delta, members=members)

    # ---------------------------------------------------------------- validations (local DB, read-only)
    def _gates(self) -> dict:
        try:
            rows = self.store.db.execute("SELECT d.id, d.status, d.started, d.finished, d.steps, p.kind, p.title FROM deployment d "
                                         "LEFT JOIN package p ON p.id = d.package_id ORDER BY d.started DESC LIMIT 40").fetchall()
        except Exception as e:
            return section("unavailable", f"database read failed: {type(e).__name__}")
        hist = []
        for r in rows:
            try:
                steps = json.loads(r["steps"] or "[]")
            except ValueError:
                steps = []
            for s in steps if isinstance(steps, list) else []:
                m = _GATE.match(str(s.get("step") or "")) if isinstance(s, dict) else None
                if not m:
                    continue
                det = s.get("detail")
                res = det.get("results") if isinstance(det, dict) and isinstance(det.get("results"), list) else None
                counts: dict[str, int] = {}
                for x in res or []:
                    k = str(x.get("result", "unknown")) if isinstance(x, dict) else "unknown"
                    counts[k] = counts.get(k, 0) + 1
                hist.append({"origin": "deployment_gate", "deployment": r["id"], "deployment_status": r["status"], "package_kind": r["kind"],
                             "package_title": str(r["title"] or "")[:120], "gate": m.group(1), "gate_status": s.get("status"),
                             "started": s.get("started") or r["started"], "total": len(res) if res is not None else None, "counts": counts,
                             "failed_tests": [str(x.get("test"))[:80] for x in res or [] if isinstance(x, dict) and x.get("result") == "fail"][:20],
                             "error": None if res is not None else str(det)[:200]})
        latest = {}
        for h in hist:      # newest first: the latest gate per stage whose deployment is in effect
            if h["deployment_status"] == "succeeded" and h["gate_status"] == "ok" and h["gate"] not in latest:
                latest[h["gate"]] = h
        return section("ok" if hist else "unavailable", "" if hist else "no deployment gate validations recorded",
                       latest=[latest[k] for k in sorted(latest, key=lambda k: -(latest[k]["started"] or 0))], history=hist[:20])

    def _independent(self) -> dict:
        try:
            rows = self.store.db.execute("SELECT id, label, started, finished, results FROM validation_run ORDER BY started DESC LIMIT 200").fetchall()
        except Exception as e:
            return section("unavailable", f"database read failed: {type(e).__name__}")
        latest: dict[str, dict] = {}
        for r in rows:
            lab = r["label"] or "unlabelled"
            if lab in latest:
                continue
            try:
                res = json.loads(r["results"] or "[]")
            except ValueError:
                res = []
            counts: dict[str, int] = {}
            for x in res:
                counts[x.get("result", "unknown")] = counts.get(x.get("result", "unknown"), 0) + 1
            latest[lab] = {"origin": "independent_run", "id": r["id"], "label": lab, "started": r["started"], "total": len(res), "counts": counts,
                           "failed_tests": [str(x.get("test"))[:80] for x in res if x.get("result") == "fail"][:20]}
        return section("ok" if latest else "unavailable", "" if latest else "no independent validation runs recorded",
                       runs=sorted(latest.values(), key=lambda v: -(v["started"] or 0)))

    # ---------------------------------------------------------------- areas
    async def delivery(self, rng: str) -> dict:
        return {"range": rng, "bigip": await self._bigip()}

    async def security(self, rng: str) -> dict:
        return {"range": rng, "gates": self._gates(), "independent": self._independent()}

    # ---------------------------------------------------------------- investigations
    def trace_url(self, trace_id: str | None) -> str | None:
        return f"{self.jaeger}/trace/{trace_id}" if self.jaeger and trace_id and _TRACE.match(trace_id) else None

    async def _agent_a_list(self):
        return await self._cached("agent_a", AGENT_A_CACHE_S, lambda: self.http_get(f"{self.agent_a}/api/investigations?limit=10"))

    def _summary_path(self, trace_id: str) -> str | None:
        if not self.summary_dir or not _TRACE.match(trace_id or ""):
            return None
        return os.path.join(self.summary_dir, f"{trace_id}.json")

    def _load_summary(self, trace_id: str) -> dict | None:
        p = self._summary_path(trace_id)
        try:
            if p and os.path.getsize(p) <= MAX_SUMMARY_BYTES:
                with open(p, encoding="utf-8") as f:
                    d = json.load(f)
                return d if isinstance(d, dict) and d.get("trace_id") == trace_id else None
        except (OSError, ValueError):
            return None
        return None

    def _store_summary(self, trace_id: str, path: dict) -> bool:
        p = self._summary_path(trace_id)
        if not p:
            return False
        data = json.dumps({**path, "trace_id": trace_id, "captured_at": self.clock(), "source": "jaeger"}, separators=(",", ":"))
        if len(data) > MAX_SUMMARY_BYTES:
            return False
        try:
            os.makedirs(self.summary_dir, mode=0o750, exist_ok=True)
            tmp = f"{p}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(data)
            os.chmod(tmp, 0o640)
            os.replace(tmp, p)
            files = sorted((os.path.join(self.summary_dir, n) for n in os.listdir(self.summary_dir) if re.match(r"^[0-9a-f]{16,32}\.json$", n)),
                           key=os.path.getmtime)
            for old in files[:-MAX_SUMMARIES]:
                os.remove(old)
            return True
        except OSError:
            return False

    async def _jaeger_get(self, trace_id: str):
        if not self.jaeger:
            raise SourceError("not_configured", "Jaeger UI not configured")
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as c:
            r = await c.get(f"{self.jaeger}/api/traces/{trace_id}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return ((r.json() or {}).get("data") or [None])[0]

    async def _path_for_trace(self, trace_id: str, capture: bool = True, finished: float | None = None) -> dict:
        """ok | pending | trace_expired | unavailable — stored summary first, then Jaeger (single GET), then persist the summary.

        Only a definitive "not found" from Jaeger for an investigation that finished at least JAEGER_SETTLE_S ago is
        remembered as expired (Jaeger is not asked again). Errors, timeouts and 5xx are reported as `unavailable` and never
        remembered. Investigations that finished less than JAEGER_SETTLE_S ago are `pending`: no Jaeger read, so a summary is
        never built from a trace whose spans are still being exported."""
        stored = self._load_summary(trace_id)
        if stored:
            return section("ok", "stored summary (captured from Jaeger)", path=stored, persisted=True)
        if trace_id in self._timelines:
            return section("ok", "computed from Jaeger (not persisted)", path=self._timelines[trace_id], persisted=False)
        if trace_id in self._expired:
            return section("trace_expired", "trace no longer held by Jaeger (≈ 9–10 h retention in this lab) and no summary was captured "
                                            "(remembered; Jaeger is not queried again)")
        if not capture:
            return section("unknown", "not captured yet")
        age = self.clock() - finished if finished else None
        if age is not None and age < JAEGER_SETTLE_S:
            return section("pending", f"investigation finished {int(max(age, 0))} s ago; summarised once all spans have reached Jaeger "
                                      f"(after {JAEGER_SETTLE_S} s)")
        try:
            tr = await self.trace_fetch(trace_id)
        except SourceError as e:
            return section(e.state, e.detail)
        except Exception as e:
            return section("unavailable", f"Jaeger unavailable ({type(e).__name__}); will retry")
        if not tr:
            self._expired[trace_id] = self.clock()
            while len(self._expired) > EXPIRED_MAX:
                self._expired.pop(next(iter(self._expired)))
            return section("trace_expired", "trace no longer held by Jaeger (in-memory store, ≈ 9–10 h retention in this lab) and no summary was captured")
        from . import fraud
        path = execution_path(fraud.timeline(tr, *self.paths), self.data_vips, self.data_backends)
        persisted = self._store_summary(trace_id, path)
        if not persisted:
            self._timelines[trace_id] = path
            if len(self._timelines) > 100:
                self._timelines.pop(next(iter(self._timelines)))
        return section("ok", "computed from Jaeger" + (" and stored" if persisted else " (not persisted)"), path=path, persisted=persisted)

    async def investigations(self) -> dict:
        try:
            rows = self.store.db.execute("SELECT id, created, scenario_id, scenario, state, trace_id, seconds, error, response "
                                         "FROM fraud_run ORDER BY created DESC LIMIT 10").fetchall()
            runs = []
            for r in rows:
                res = ((json.loads(r["response"]) if r["response"] else {}) or {}).get("result") or {}
                a = res.get("assessment") or {}
                title = ((json.loads(r["scenario"]) if r["scenario"] else {}) or {}).get("title")
                runs.append({"source": "autopilot", "id": r["id"], "alert": r["scenario_id"], "title": title, "started": r["created"],
                             "state": r["state"], "duration": {"seconds": r["seconds"]}, "decision": a.get("decision"),
                             "risk": a.get("risk_level"), "confidence": _num(a.get("confidence")), "error": bool(r["error"]),
                             "trace_url": self.trace_url(r["trace_id"]), "trace_id": r["trace_id"] if _TRACE.match(str(r["trace_id"])) else None,
                             "path_state": "stored"})
            local = section("ok", "", runs=runs)
        except Exception as e:
            local = section("unavailable", f"database read failed: {type(e).__name__}")
        agent = section("not_configured", "fraud_app.agent_a_api not configured")
        if re.match(r"^http://\d{1,3}(\.\d{1,3}){3}:\d{2,5}$", self.agent_a):
            try:
                data = await self._agent_a_list()
                rows, captured = [], 0
                for x in data if isinstance(data, list) else []:
                    res = x.get("result") if isinstance(x.get("result"), dict) else {}
                    a = res.get("assessment") or {}
                    st, fi = _num(x.get("started")), _num(x.get("finished"))
                    host = re.match(r"^https?://([^/:]+)", x.get("card_url") or "")
                    tid = x.get("trace_id") if _TRACE.match(str(x.get("trace_id"))) else None
                    pstate = None
                    if tid:
                        if self._load_summary(tid):
                            pstate = "stored"
                        elif tid in self._timelines:
                            pstate = "ok"
                        elif tid in self._expired:
                            pstate = "trace_expired"     # remembered: no Jaeger read, no capture budget used
                        elif fi and self.clock() - fi < JAEGER_SETTLE_S:
                            pstate = "pending"
                        elif captured < TRACE_CAPTURE_PER_REFRESH and x.get("state") == "completed":
                            captured += 1                # bounded: at most N Jaeger reads per list refresh
                            p = await self._path_for_trace(tid, finished=fi)
                            pstate = "stored" if p.get("persisted") else p["state"]
                    rows.append({"source": "agent_a", "id": str(x.get("id"))[:36], "alert": str(x.get("alert_id"))[:20], "started": st,
                                 "state": str(x.get("state"))[:20], "duration": {"seconds": round(fi - st, 1) if st and fi else None},
                                 "decision": a.get("decision"), "risk": a.get("risk_level"), "confidence": _num(a.get("confidence")),
                                 "front_door": host.group(1) if host else None, "error": bool(x.get("error")),
                                 "trace_url": self.trace_url(tid), "trace_id": tid, "path_state": pstate})
                agent = section("ok", f"cached up to {AGENT_A_CACHE_S} s", runs=rows)
            except Exception as e:
                agent = section("unavailable", f"Agent A investigation list unavailable ({type(e).__name__})")
        return {"autopilot": local, "agent_a": agent, "jaeger_ui": self.jaeger,
                "summary_store": "enabled" if self.summary_dir else "disabled"}

    async def investigation_path(self, source: str, rid: str) -> dict:
        if source == "autopilot":
            if not _AP_RUN.match(rid or ""):
                raise ValueError("invalid investigation id")
            r = self.store.db.execute("SELECT trace_id, events, summary, seconds FROM fraud_run WHERE id=?", (rid,)).fetchone()
            if not r:
                return section("not_found", "unknown investigation")
            if r["events"]:
                tl = {"events": json.loads(r["events"]), "summary": json.loads(r["summary"]) if r["summary"] else {}}
                return section("ok", "timeline stored by Autopilot when the investigation ran", path=execution_path(tl, self.data_vips, self.data_backends), persisted=True,
                               trace_url=self.trace_url(r["trace_id"]))
            if r["trace_id"] and _TRACE.match(r["trace_id"]):
                return {**await self._path_for_trace(r["trace_id"]), "trace_url": self.trace_url(r["trace_id"])}
            return section("unavailable", "no trace recorded for this investigation")
        if source == "agent_a":
            if not _UUID.match(rid or ""):
                raise ValueError("invalid investigation id")
            try:
                data = await self._agent_a_list()
            except Exception as e:
                return section("unavailable", f"Agent A investigation list unavailable ({type(e).__name__})")
            row = next((x for x in data if isinstance(x, dict) and str(x.get("id")) == rid), None) if isinstance(data, list) else None
            tid = row.get("trace_id") if row and _TRACE.match(str(row.get("trace_id"))) else None
            if not tid:
                return section("not_found", "investigation not in Agent A's recent list or without a trace id")
            return {**await self._path_for_trace(tid, finished=_num(row.get("finished"))), "trace_url": self.trace_url(tid)}
        raise ValueError("invalid source")

    # ---------------------------------------------------------------- traffic generator (read-only files)
    def _read_json(self, path: str, limit: int = 1 << 20) -> dict | None:
        try:
            if os.path.getsize(path) > limit:
                return None
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else None
        except (OSError, ValueError):
            return None

    @staticmethod
    def _workloads(st: dict) -> dict:
        out = {}
        keep = ("runs", "ok", "expected_denial", "unexpected", "unavailable", "error", "deferred", "requests", "bytes", "avg_ms", "last_ok")
        for n, w in ((st or {}).get("workloads") or {}).items():
            if not _WORKLOAD.match(str(n)) or not isinstance(w, dict):
                continue
            row = {k: w.get(k) for k in keep if k in w}
            row["targets"] = {str(d)[:20]: {"bigip_object": str((t or {}).get("bigip_object") or "")[:80], "address": str((t or {}).get("address") or "")[:24]}
                              for d, t in ((w.get("targets") or {}).items() if isinstance(w.get("targets"), dict) else [])}
            lr = w.get("last_result") if isinstance(w.get("last_result"), dict) else {}
            row["last_outcome"] = lr.get("outcome")
            out[n] = row
        return out

    @staticmethod
    def _iso(s) -> float | None:
        import calendar
        try:
            return float(calendar.timegm(time.strptime(str(s)[:19], "%Y-%m-%dT%H:%M:%S")))
        except (ValueError, OverflowError):
            return None

    def _run_log(self, path: str) -> dict:
        """Per-workload client latency (p50/p95/max) and a per-minute run series from the generator's JSON run log."""
        lat: dict[str, list] = {}
        minute: dict[int, int] = {}
        try:
            if os.path.getsize(path) > 2 << 20:
                return {}
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.startswith("{"):
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    w = rec.get("workload")
                    if "event" in rec or not isinstance(w, str) or not _WORKLOAD.match(w):
                        continue
                    if isinstance(rec.get("ms"), (int, float)) and rec.get("outcome") in ("ok", "expected_denial"):
                        lat.setdefault(w, []).append(float(rec["ms"]))
                    t = self._iso(rec.get("ts"))
                    if t:
                        minute[int(t // 60 * 60)] = minute.get(int(t // 60 * 60), 0) + 1
        except OSError:
            return {}
        return {"latency_ms": {w: {"n": len(v), "p50": _pct(v, 50), "p95": _pct(v, 95), "max": round(max(v), 1)} for w, v in lat.items()},
                "runs_per_minute": sorted([[k, v] for k, v in minute.items()])}

    def trafficgen(self) -> dict:
        base = self.tg_dir
        if not os.path.isdir(base):
            return section("not_installed", "Traffic Generator state is not mounted into Autopilot (ap-trafficgen not installed or not shared)")
        cur = self._read_json(os.path.join(base, "state", "status.json"))
        current, status = None, "idle"
        if cur:
            upd = self._iso(cur.get("updated"))
            running = upd is not None and self.clock() - upd < 120
            status = "running" if running else "idle (last run not archived)"
            current = {"mode": str(cur.get("mode"))[:40], "started": cur.get("started"), "updated": cur.get("updated"), "running": running,
                       "workloads": self._workloads(cur)}
        runs = []
        try:
            names = sorted((n for n in os.listdir(os.path.join(base, "runs")) if _RUN_DIR.match(n)), reverse=True)[:10]
        except OSError as e:
            return section("unavailable", f"run archive not readable ({type(e).__name__})", status=status, current=current, runs=[])
        for n in names:
            d = os.path.join(base, "runs", n)
            st = self._read_json(os.path.join(d, "status.json")) or {}
            meta = {}
            try:
                with open(os.path.join(d, "container.txt"), encoding="utf-8") as f:
                    parts = f.read(400).split(" ", 3)
                meta = {"exit_code": int(parts[0]), "container_started": parts[1], "container_finished": parts[2],
                        "args": re.sub(r"[^\w ,.\-\[\]]", "", parts[3]).strip()[:160] if len(parts) > 3 else ""}
            except (OSError, ValueError, IndexError):
                pass
            wl = self._workloads(st)
            tot = {k: sum((w.get(k) or 0) for w in wl.values()) for k in ("runs", "ok", "unexpected", "unavailable", "error", "deferred", "requests", "bytes")}
            s0, s1 = self._iso(meta.get("container_started")), self._iso(meta.get("container_finished"))
            dur = round(s1 - s0, 1) if s0 and s1 and s1 >= s0 else None
            log = self._run_log(os.path.join(d, "run.log"))
            runs.append({"run": n, "mode": st.get("mode"), "started": st.get("started"), "updated": st.get("updated"),
                         "stopped_by_stop_file": os.path.exists(os.path.join(d, "STOP")), **meta, "totals": tot,
                         "duration": {"seconds": dur},
                         "rate": {"requests_per_min": round(tot["requests"] / dur * 60, 2) if dur else None,
                                  "success_pct": round(100 * tot["ok"] / tot["runs"], 1) if tot["runs"] else None},
                         "latency_ms": log.get("latency_ms", {}), "runs_per_minute": log.get("runs_per_minute", []), "workloads": wl})
        return section("ok", "run archive (read-only); start / stop through the controlled presets", status=status, current=current, runs=runs)

    # ---------------------------------------------------------------- overview (assembled from the blocks above)
    async def overview(self, rng: str) -> dict:
        d = await self.delivery(rng)
        sec = await self.security(rng)
        inv = await self.investigations()
        tg = self.trafficgen()
        tiles = []
        bg = d["bigip"]
        lifetime_dv = (bg.get("lifetime") or {}).get("data_vips") or {}
        for app, label, area in APPS:
            svc = next((k for k, a in DATA_SVC_APP.items() if a == app), None)
            tiles.append({"app": app, "label": label, "area": area,
                          "lifetime": {"requests": (lifetime_dv.get(svc) or {}).get("http.numberReqs")},
                          "source": "bigip" if svc and svc in lifetime_dv else None})
        gates = sec["gates"].get("latest") or []
        agent_runs = ((inv.get("agent_a") or {}).get("runs") or []) + ((inv.get("autopilot") or {}).get("runs") or [])
        latest_inv = max(agent_runs, key=lambda r: r.get("started") or 0) if agent_runs else None
        last_run = (tg.get("runs") or [None])[0]
        return {"range": rng,
                "states": {"bigip": bg["state"], "gates": sec["gates"]["state"],
                           "agent_a": inv["agent_a"]["state"], "trafficgen": tg["state"]},
                "vips": tiles,
                "security": {"gates": gates},
                "data": {"s3_lifetime": (bg.get("lifetime") or {}).get("s3_statistics"), "s3_delta": (bg.get("delta") or {}).get("s3"),
                         "delta_seconds": (bg.get("delta") or {}).get("seconds")},
                "trafficgen": {"state": tg["state"], "status": tg.get("status"),
                               "last_run": {k: last_run.get(k) for k in ("run", "exit_code", "totals", "rate", "duration")} if last_run else None},
                "investigation": {k: latest_inv.get(k) for k in ("source", "alert", "state", "decision", "risk", "confidence", "duration", "trace_url")} if latest_inv else None}


async def _http_get_json(url: str):
    async with httpx.AsyncClient(timeout=8, follow_redirects=False, trust_env=False) as c:
        r = await c.get(url, headers={"Accept": "application/json"})
        r.raise_for_status()
        return r.json()
