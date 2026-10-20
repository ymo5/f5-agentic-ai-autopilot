"""F5 Agentic AI Autopilot — web service (UI/API, discovery, assessment, recommendation, approval workflow).

Discover -> Assess -> Recommend -> Approve -> Deploy -> Validate -> Observe.
This service holds NO device credentials and cannot deploy: deployment/rollback/reset requests are forwarded to the
separate autopilot-deployer, which re-verifies the hash-bound human approval. The LLM is only used for Describe and
plain-language rationale; it has no session and no path to approval/deployment endpoints.
"""
from __future__ import annotations

import asyncio
import contextlib
import difflib
import hashlib
import hmac
import html
import json
import os
import re
import time
import uuid

import httpx
import uvicorn
import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from aplab import telemetry
from aplab.llm import LLM

from . import aiops, advisory, approvals, guidance, overview, verification, assess, auth, catalog, claims, demo, explorer, fraud, identity, inventory, scheduler, operations, packages, report, throttle, validate
from .engine import Engine
from .store import Store

telemetry.setup("autopilot")
CFG = yaml.safe_load(open(os.environ.get("AUTOPILOT_CONFIG", "/etc/autopilot/autopilot.yaml")))
STORE = Store(os.environ.get("AUTOPILOT_DB", "/var/lib/autopilot/autopilot.db"))
LLM_ = LLM()
ENGINE = Engine(STORE, CFG, LLM_)
STORE.db.executescript(operations.SCHEMA)
STORE.db.executescript(fraud.SCHEMA)
STORE.db.executescript(inventory.SCHEMA)
STORE.db.executescript(scheduler.SCHEMA)
SCHED = scheduler.Scheduler(STORE, CFG)
operations.mark_interrupted(STORE)
TOKEN_SHA256 = os.environ.get("AUTOPILOT_OPERATOR_TOKEN_SHA256", "")
STATIC = os.path.join(os.path.dirname(__file__), "static")
SNAPSHOT_DIR = os.environ.get("AUTOPILOT_SNAPSHOTS", "/var/lib/autopilot/snapshots")
@contextlib.asynccontextmanager
async def _lifespan(_app):
    SCHED.start()   # no-op unless the environment permits scheduling; the loop runs only evidence-only snapshot jobs
    yield


app = FastAPI(title="F5 Agentic AI Autopilot", lifespan=_lifespan)
_locks = {m: asyncio.Lock() for m in ("observe", "describe", "enumerate", "ingest", "validate", "deploy")}
RULE_TESTS = catalog.RULE_TESTS


class DeployerClient:
    """HTTP client for autopilot-deployer (127.0.0.1:8100). Replaced by an in-process client in tests."""

    def __init__(self):
        self.url = os.environ.get("AUTOPILOT_DEPLOYER_URL", "http://127.0.0.1:8100")
        self.token = os.environ.get("AUTOPILOT_DEPLOYER_TOKEN", "")

    async def _call(self, method, path, body=None, timeout=900):
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.request(method, f"{self.url}{path}", json=body, headers={"X-Deployer-Token": self.token})
        if r.status_code >= 400:
            raise HTTPException(r.status_code, r.json().get("detail", r.text) if "json" in r.headers.get("content-type", "") else r.text)
        return r.json()

    async def state(self):
        return await self._call("GET", "/state", timeout=120)

    async def preflight(self, pkg):
        return await self._call("POST", "/preflight", {"package": pkg, "approval_id": "-", "user": {"username": "-", "role": "viewer"}})

    async def deploy(self, pkg, approval_id, user):
        return await self._call("POST", "/deploy", {"package": pkg, "approval_id": approval_id, "user": user})

    async def rollback(self, deployment_id, user):
        return await self._call("POST", "/rollback", {"deployment_id": deployment_id, "user": user})

    async def observe_raw(self):
        return await self._call("GET", "/observe-raw", timeout=120)

    async def validation_action(self, req):
        return await self._call("POST", "/validation-action", req, timeout=120)

    async def reset_demo(self, user, confirmation):
        return await self._call("POST", "/reset-demo", {"user": user, "confirmation": confirmation})

    async def health(self):
        return await self._call("GET", "/healthz", timeout=10)

    async def window_open(self, body):
        return await self._call("POST", "/window/open", body, timeout=150)

    async def window_close(self, body):
        return await self._call("POST", "/window/close", body, timeout=150)

    async def window_broker(self):
        return await self._call("GET", "/window/broker", timeout=20)

    async def diagnostics_bigip(self):
        return await self._call("GET", "/diagnostics/bigip", timeout=60)

    async def trafficgen_status(self):
        return await self._call("GET", "/trafficgen/status", timeout=30)

    async def trafficgen_start(self, body):
        return await self._call("POST", "/trafficgen/start", body, timeout=150)

    async def trafficgen_stop(self, body):
        return await self._call("POST", "/trafficgen/stop", body, timeout=200)


DEPLOYER = DeployerClient()
# AI Operations dashboard (read-only). The deployer is resolved at call time so tests can substitute an in-process deployer.
AIOPS = aiops.AIOps(CFG, STORE, lambda req: DEPLOYER.validation_action(req))
OPERATOR = auth.require("operator")
APPROVER = auth.require("approver")
VIEWER = auth.require("viewer")
OWNER = auth.require("owner")


# ---------------------------------------------------------------- auth
class Login(BaseModel):
    username: str = Field(max_length=60)
    password: str = Field(max_length=200)


CSRF_EXEMPT = {"/api/login", "/api/observe/snapshot"}


@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    """Double-submit CSRF protection for every state-changing API call (cookie value must be echoed in a header).
    Combined with SameSite=strict session cookies, a cross-site page can neither read nor forge the token."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.url.path.startswith("/api/") \
            and request.url.path not in CSRF_EXEMPT:
        c, h = request.cookies.get(auth.CSRF_COOKIE, ""), request.headers.get(auth.CSRF_HEADER, "")
        if not c or not h or not hmac.compare_digest(c, h):
            return JSONResponse({"detail": "CSRF token missing or invalid — sign in again"}, status_code=403)
    return await call_next(request)


@app.post("/api/login")
async def login(l: Login, resp: Response, req: Request):
    key = f"login:{l.username.lower()}"
    try:
        throttle.check_locked(STORE.db, key)
    except throttle.Throttled as e:
        STORE.audit(l.username, "auth.login.throttled", None, {"from": req.client.host if req.client else None})
        raise HTTPException(429, str(e))
    role = auth.verify(STORE.db, l.username, l.password)
    STORE.audit(l.username, "auth.login." + ("ok" if role else "failed"), None, {"from": req.client.host if req.client else None})
    if not role:
        throttle.failure(STORE.db, key, max_failures=5, lock_s=600)
        raise HTTPException(401, "invalid credentials")
    throttle.reset(STORE.db, key)
    sec = _is_https(req)       # cookies are marked Secure as soon as the UI is served over HTTPS (TLS design: doc 24)
    resp.set_cookie(auth.COOKIE, auth.issue(l.username, role), httponly=True, samesite="strict", max_age=auth.TTL, secure=sec)
    resp.set_cookie(auth.CSRF_COOKIE, auth.new_csrf(), httponly=False, samesite="strict", max_age=auth.TTL, secure=sec)
    return {"username": l.username, "role": role}


@app.post("/api/logout")
async def logout(resp: Response):
    resp.delete_cookie(auth.COOKIE)
    resp.delete_cookie(auth.CSRF_COOKIE)
    return {"ok": True}


@app.get("/api/me")
async def me(user=Depends(VIEWER)):
    return user


def operator_token(authorization: str = Header(default="")) -> str:
    tok = authorization.removeprefix("Bearer ").strip()
    if not TOKEN_SHA256 or not hmac.compare_digest(hashlib.sha256(tok.encode()).hexdigest(), TOKEN_SHA256):
        raise HTTPException(401, "operator token required")
    return "operator"


# ---------------------------------------------------------------- state & discovery
def _graph() -> dict:
    assets, rels = STORE.assets(), STORE.rels()

    def aliases(a):
        at = a["attrs"]
        al = list(at.get("dns_names") or []) + [at.get(k) for k in ("otel_service", "agent_name")] + \
            [(at.get("mcp") or {}).get("server_name"), (at.get("agent_card") or {}).get("name")] + list(at.get("described_as") or [])
        return sorted({x for x in al if x})
    fcount: dict[str, dict] = {}
    for f in assess.findings(STORE):
        for x in f["asset_ids"]:
            c = fcount.setdefault(x, {"delivery": 0, "security": 0})
            c["security" if f["rule_id"].startswith("S-") else "delivery"] += 1
    return {"nodes": [{"id": a["id"], "key": a["key"], "kind": a["kind"], "name": a["name"], "status": a["status"], "aliases": aliases(a),
                       "address": a["key"].split(":", 1)[1] if a["key"].startswith("ep:") else a["attrs"].get("address"),
                       "findings": fcount.get(a["id"], {"delivery": 0, "security": 0}),
                       "confidence": a["confidence"], "sources": a["sources"], "first_seen": a["first_seen"]} for a in assets],
            "edges": [{"id": r["id"], "source": r["src"], "target": r["dst"], "kind": r["kind"], "status": r["status"],
                       "observed_path": r["observed_path"], "asserted_paths": r["asserted_paths"], "confidence": r["confidence"],
                       "sources": r["sources"]} for r in rels]}


@app.get("/api/state")
async def state(user=Depends(VIEWER)):
    a = STORE.current()
    gaps = assess.evaluate(STORE, CFG)[1] if STORE.counters()["evidence"] else []   # read-only: polling never re-assesses
    fs = assess.findings(STORE)
    return {"assessment": a, "counters": STORE.counters(), "graph": _graph(), "gaps": gaps, "findings": fs,
            "findings_grouped": _group(fs), "running": [m for m, l in _locks.items() if l.locked()],
            "operations": operations.recent(STORE, 5, active_only=True), "llm": LLM_.describe(), "user": user,
            "observe_mode": CFG["observe"]["mode"], "scope": _scope(), "sources": _sources()}


def _group(fs: list[dict]) -> list[dict]:
    """Repetitive findings grouped by issue type, with affected endpoints and evidence counts."""
    names = {a["id"]: (a["name"], a["key"].split(":", 1)[-1]) for a in STORE.assets()}
    sev = {"high": 0, "medium": 1, "low": 2}
    out: dict[str, dict] = {}
    for f in fs:
        g = out.setdefault(f["rule_id"], {"rule_id": f["rule_id"], "issue": f.get("issue"), "class": f.get("class"),
                                          "class_label": f.get("class_label"), "basis": f.get("basis"), "category": f["category"],
                                          "severity": f["severity"], "package": f.get("package"), "not_addressed": f.get("not_addressed"),
                                          "tests": f.get("tests"), "count": 0, "affected": [], "evidence_ids": [], "items": [],
                                          "guidance": guidance.for_rule(f["rule_id"], f.get("class"))})
        g["count"] += 1
        g["severity"] = min(g["severity"], f["severity"], key=lambda x: sev.get(x, 3))
        for aid in f["asset_ids"]:
            n = names.get(aid)
            if n and not any(x["id"] == aid for x in g["affected"]):
                g["affected"].append({"id": aid, "name": n[0], "endpoint": n[1]})
        g["evidence_ids"] = sorted(set(g["evidence_ids"]) | set(f["evidence_ids"]))
        g["items"].append({"id": f["id"], "title": f["title"], "detail": f["detail"], "package": f.get("package"), "tests": f.get("tests"),
                           "asset_ids": f["asset_ids"], "evidence_ids": f["evidence_ids"]})
        if g["package"] != f.get("package"):
            g["package"] = g["package"] if g["count"] == 1 else "per finding"
    order = {"contradicted_claim": 0, "confirmed_vulnerability": 1, "architectural_gap": 2, "inferred_risk": 3}
    return sorted(out.values(), key=lambda g: (order.get(g["class"], 9), sev.get(g["severity"], 3), g["rule_id"]))


def _scope() -> dict:
    ec = CFG["enumerate"]
    return {"cidrs": ec["scope_cidrs"], "approved_hosts": ec["approved_hosts"], "ports": ec.get("ports"), "dns_zone": ec["dns_zone"],
            "dns_server": ec["dns_server"], "inventory": [h["name"] for h in ec.get("inventory", [])],
            "jaeger_ui": (CFG.get("ingest") or {}).get("jaeger_ui") or (CFG.get("ingest") or {}).get("jaeger_url"),
            "statement": "Enumerate probes ONLY the approved CIDRs, approved hosts and listed ports configured for this engagement, "
                         "plus a zone transfer of the approved lab DNS zone. It never scans outside this scope, never uses "
                         "credentials, and only performs protocol handshakes (MCP initialize/tools/list, A2A Agent Card, HTTP GET)."}


def _sources() -> dict:
    out = {}
    for src in ("observe", "describe", "enumerate", "ingest"):
        r = STORE.db.execute("SELECT COUNT(*) n, MAX(collected_at) last FROM evidence WHERE assessment_id=? AND source=?",
                             (STORE.current()["id"], src)).fetchone()
        out[src] = {"evidence": r["n"], "last_run": r["last"]}
    return out


@app.get("/api/describe/analysis")
async def describe_analysis(user=Depends(VIEWER)):
    """The explicit AI response to Describe: extraction, reconciliation, claim verification, contradictions, follow-ups."""
    evs = [e for e in STORE.evidence() if e["source"] == "describe" and e["method"] != "reconciliation"]
    recon = [json.loads(STORE.evidence(e["id"])[0]["raw"]) for e in STORE.evidence() if e["method"] == "reconciliation"]
    assets = STORE.assets()
    by_key = {a["key"]: a for a in assets}
    verified = claims.verify(STORE)
    gaps = assess.evaluate(STORE, CFG)[1] if STORE.counters()["evidence"] else []
    out = []
    for e in evs:
        raw = json.loads(STORE.evidence(e["id"])[0]["raw"])
        ex, prov = raw.get("extraction") or {}, raw.get("provenance") or {}
        comps = []
        for c in ex.get("components", []):
            key = "described:" + "".join(ch if ch.isalnum() else "-" for ch in c["name"].lower()).strip("-")
            m = next((r for r in recon if r.get("described", "").rstrip("-") == key[:71].rstrip("-")), None)
            matched = by_key.get(m["matched"]) if m else None
            comps.append({**c, "status": "matched" if matched else ("asserted (unmatched)" if key in by_key else "unmatched"),
                          "matched_to": {"name": matched["name"], "key": matched["key"], "score": round(m["score"], 2)} if matched else None})
        out.append({"evidence_id": e["id"], "collected_at": e["collected_at"], "author": raw.get("author"), "text": raw.get("text"),
                    "generated_by": prov.get("generated_by"), "llm": prov.get("llm"), "fallback_reason": prov.get("fallback_reason"),
                    "components": comps, "relationships": ex.get("relationships", []),
                    "claims": [v for v in verified if v["describe_evidence"] == e["id"]]})
    return {"descriptions": out, "contradictions": [v for v in verified if v["status"] == "contradicted"],
            "follow_up_questions": claims.follow_up_questions(STORE, gaps, verified),
            "note": "Extraction is produced by the LLM (or the labelled deterministic parser) and recorded as unverified assertions; "
                    "confirmation/contradiction comes only from technical evidence."}


@app.get("/api/assets/{asset_id}")
async def asset(asset_id: str, user=Depends(VIEWER)):
    """Asset dossier: identity, protocol details, claims with trust levels, findings, communications, recommendations."""
    d = explorer.asset_dossier(STORE, asset_id)
    if not d:
        raise HTTPException(404)
    view = identity.reconcile(STORE)
    ix = view["endpoint_index"].get(asset_id)
    svc = next((x for x in view["services"] if ix and x["id"] == ix["service_id"]), None)
    d["canonical"] = svc and {**ix, "service": {k: svc[k] for k in ("id", "key", "name", "classification", "grouping", "confidence", "basis",
                                                                    "verified", "telemetry_service", "replicas", "replica_status")},
                              "instances": svc["instances"], "endpoints": svc["endpoints"],
                              "unresolved": [u for u in view["unresolved"] if asset_id in (u.get("asset_ids") or [])
                                             or u.get("service_key") == svc["key"]]}
    return d


@app.get("/api/relationships/{rel_id}")
async def relationship(rel_id: str, user=Depends(VIEWER)):
    """One communication edge with its claims, observed metrics and the trace ids that prove it."""
    d = explorer.edge_dossier(STORE, rel_id)
    if not d:
        raise HTTPException(404)
    return d


# ------------------------------------------------------------------ Wave 2A: canonical identity, inventory, schedule
@app.get("/api/services")
async def services(assessment: str | None = None, user=Depends(VIEWER)):
    """Canonical services (logical service -> instances -> endpoints) derived from stored evidence; read-only."""
    if assessment and not STORE.db.execute("SELECT 1 FROM assessment WHERE id=?", (assessment,)).fetchone():
        raise HTTPException(404)
    return identity.reconcile(STORE, assessment)


@app.get("/api/recommendations/advisory")
async def placement_advisory(assessment: str | None = None, user=Depends(VIEWER)):
    """Wave 3 placement advisory (read-only): BIG-IP candidates, unreserved VIP candidates, provenance, identity mapping and
    a comparison with the configured packages. Derived from stored evidence; no network access; changes nothing."""
    if assessment and not STORE.db.execute("SELECT 1 FROM assessment WHERE id=?", (assessment,)).fetchone():
        raise HTTPException(404)
    return advisory.build(STORE, CFG, assessment)


@app.get("/api/inventory/snapshots")
async def inventory_snapshots(user=Depends(VIEWER)):
    rows = STORE.db.execute("SELECT id, created, source_assessment, actor, trigger, reconstructed, digest, prev_id, "
                            "(SELECT COUNT(*) FROM inventory_change c WHERE c.snapshot_id=s.id) AS changes, "
                            "(SELECT COUNT(*) FROM inventory_change c WHERE c.snapshot_id=s.id AND acknowledged_by IS NULL) AS unacknowledged "
                            "FROM inventory_snapshot s ORDER BY created DESC LIMIT 200").fetchall()
    names = {r["id"]: r["name"] for r in STORE.db.execute("SELECT id, name FROM assessment")}
    return [{**dict(r), "assessment_name": names.get(r["source_assessment"])} for r in rows]


@app.get("/api/inventory/snapshots/{sid}")
async def inventory_snapshot(sid: str, user=Depends(VIEWER)):
    r = STORE.db.execute("SELECT * FROM inventory_snapshot WHERE id=?", (sid,)).fetchone()
    if not r:
        raise HTTPException(404)
    return {**inventory._row(r), "changes": inventory.changes(STORE, sid)}


@app.get("/api/inventory/changes")
async def inventory_changes(snapshot: str | None = None, user=Depends(VIEWER)):
    lat = inventory.latest(STORE)
    unack = STORE.db.execute("SELECT COUNT(*) FROM inventory_change WHERE snapshot_id=? AND acknowledged_by IS NULL",
                             (lat["id"],)).fetchone()[0] if lat else 0
    return {"changes": inventory.changes(STORE, snapshot), "latest_snapshot": lat and {k: lat[k] for k in ("id", "created", "trigger", "source_assessment")},
            "unacknowledged_latest": unack}


class SnapshotReq(BaseModel):
    assessment_id: str | None = Field(default=None, max_length=40)


@app.post("/api/inventory/snapshot")
async def inventory_snapshot_create(r: SnapshotReq, user=Depends(OPERATOR)):
    """Record an inventory snapshot from STORED evidence of an assessment (default: current). Opens no connections."""
    aid = r.assessment_id or STORE.current()["id"]
    if not STORE.db.execute("SELECT 1 FROM assessment WHERE id=?", (aid,)).fetchone():
        raise HTTPException(404, "unknown assessment")
    return inventory.record(STORE, aid, user["username"])


class AckReq(BaseModel):
    snapshot_id: str = Field(max_length=40)


@app.post("/api/inventory/changes/ack")
async def inventory_ack(r: AckReq, user=Depends(OPERATOR)):
    n = STORE.db.execute("UPDATE inventory_change SET acknowledged_by=?, acknowledged_at=? WHERE snapshot_id=? AND acknowledged_by IS NULL",
                         (user["username"], time.time(), r.snapshot_id)).rowcount
    STORE.audit(user["username"], "inventory.changes.acknowledged", None, {"snapshot": r.snapshot_id, "count": n})
    return {"acknowledged": n}


class BackfillReq(BaseModel):
    dry_run: bool = True


@app.post("/api/inventory/backfill")
async def inventory_backfill(r: BackfillReq, user=Depends(APPROVER)):
    """Migration aid: reconstruct snapshots from historical assessments' stored evidence (marked reconstructed)."""
    try:
        return inventory.backfill(STORE, user["username"], dry_run=r.dry_run)
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.get("/api/discovery/schedule")
async def schedule_get(user=Depends(VIEWER)):
    return {**scheduler.get(STORE), "permitted": scheduler.permitted(CFG), "allowed_jobs": sorted(scheduler.ALLOWED_JOBS),
            "min_cadence_min": scheduler.MIN_CADENCE,
            "note": "Disabled by default. This milestone's only job builds an inventory snapshot from stored evidence; it opens no "
                    "network connections. Network-active scheduled discovery is Wave 2B and needs separate authorisation."}


class ScheduleReq(BaseModel):
    enabled: bool | None = None
    cadence_min: int | None = Field(default=None, ge=1, le=10080)
    jobs: list[str] | None = None


@app.put("/api/discovery/schedule")
async def schedule_put(r: ScheduleReq, user=Depends(OWNER)):
    try:
        return scheduler.update(STORE, CFG, user["username"], r.enabled, r.cadence_min, r.jobs)
    except scheduler.ScheduleError as e:
        raise HTTPException(e.status, str(e))


@app.get("/api/evidence")
async def evidence_list(user=Depends(VIEWER)):
    return STORE.evidence()


@app.get("/api/evidence/{eid}")
async def evidence_one(eid: str, asset: str | None = None, user=Depends(VIEWER)):
    """Evidence document with its trust level; with ?asset=<id> also the parts of it that concern that asset."""
    ev = STORE.evidence(eid)
    if not ev:
        raise HTTPException(404)
    return explorer.scoped_evidence(STORE, ev[0], asset)


@app.get("/api/assessments")
async def assessments(user=Depends(VIEWER)):
    """Assessments with what each one actually covers, so before/after pairs can be chosen meaningfully."""
    ids = [r["id"] for r in STORE.db.execute("SELECT id FROM assessment ORDER BY created DESC LIMIT 50")]
    return [explorer.assessment_profile(STORE, i) | {"current": i == STORE.current()["id"]} for i in ids]


@app.get("/api/assessments/suggestions")
async def assessment_suggestions(user=Depends(VIEWER)):
    ids = [r["id"] for r in STORE.db.execute("SELECT id FROM assessment ORDER BY created DESC LIMIT 50")]
    return {"pairs": explorer.suggest_pairs(STORE, [explorer.assessment_profile(STORE, i) for i in ids])}


@app.post("/api/assessment/reset")
async def reset(user=Depends(OPERATOR)):
    """Reset Assessment: clears ONLY this workspace. Never calls the deployer, devices or hosts."""
    return STORE.reset(user["username"])


class NewReq(BaseModel):
    name: str = Field(default="Assessment", max_length=80)


@app.post("/api/assessment/new")
async def new(r: NewReq, user=Depends(OPERATOR)):
    return STORE.new_assessment(user["username"], r.name)


async def _run(method: str, coro):
    if _locks[method].locked():
        raise HTTPException(409, f"{method} already running")
    async with _locks[method]:
        t0 = time.time()
        try:
            res = await coro
        except HTTPException:
            raise
        except Exception as e:
            STORE.audit("autopilot", f"discovery.{method}.error", STORE.current()["id"], {"error": str(e)[:500]})
            raise HTTPException(502, f"{method} failed: {type(e).__name__}: {e}")
        ENGINE.assess()
        return {"method": method, "seconds": round(time.time() - t0, 2), **res}


_SNAP_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
_SNAP_HOST = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)$")
DEVICE_SNAPSHOTS = "devices"      # per-device snapshots (Wave 3 collector); legacy single-device files stay at the top level
SNAPSHOT_KEEP = max(1, int(os.environ.get("AUTOPILOT_SNAPSHOT_KEEP", "20")))   # newest uploads kept per device


def _validate_snapshot(raw: dict) -> dict | None:
    """Shape check for an uploaded Observe snapshot. Returns the device reference (Wave 3 collector) or None (legacy)."""
    from .sources import observe as o_src
    allowed = set(o_src.ENDPOINTS) | set(o_src.PLACEMENT_ENDPOINTS) | {"_meta"}
    bad = sorted(k for k in raw if k not in allowed)
    if bad:
        raise HTTPException(422, f"unexpected snapshot keys: {', '.join(bad[:5])}")
    for k, v in raw.items():
        if k != "_meta" and not (isinstance(v, dict) and isinstance(v.get("status"), int)):
            raise HTTPException(422, f"snapshot entry {k} must be {{status: int, body}}")
    meta = raw.get("_meta")
    if meta is None:
        return None
    dev = (meta or {}).get("device") if isinstance(meta, dict) else None
    if not isinstance(dev, dict) or not _SNAP_LABEL.match(str(dev.get("label", ""))) or not _SNAP_HOST.match(str(dev.get("mgmt", ""))):
        raise HTTPException(422, "_meta.device needs a label ([A-Za-z0-9_.-], ≤ 40) and a management address or host name")
    ca = meta.get("collected_at")
    if not isinstance(ca, (int, float)) or not (1.6e9 < ca < time.time() + 600):
        raise HTTPException(422, "_meta.collected_at must be the collection time (epoch seconds, not in the future)")
    t = meta.get("timings_s") or {}
    if not isinstance(t, dict) or any(not isinstance(v, (int, float)) or v < 0 for v in t.values()):
        raise HTTPException(422, "_meta.timings_s must map endpoint keys to non-negative seconds")
    return dev


@app.post("/api/observe/snapshot", dependencies=[Depends(operator_token)])
async def observe_upload(raw: dict):
    dev = _validate_snapshot(raw)
    if dev:
        d = os.path.join(SNAPSHOT_DIR, DEVICE_SNAPSHOTS, dev["label"])
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"{int(raw['_meta']['collected_at'])}-{uuid.uuid4().hex[:6]}.json")
    else:
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        path = os.path.join(SNAPSHOT_DIR, f"bigip-{int(time.time())}.json")
    json.dump(raw, open(path, "w"))
    pruned = []
    if dev:                      # bounded storage: only this device's own folder, newest SNAPSHOT_KEEP files kept
        files = sorted(f for f in os.listdir(os.path.dirname(path)) if f.endswith(".json"))
        for f in files[:-SNAPSHOT_KEEP]:
            os.remove(os.path.join(os.path.dirname(path), f))
            pruned.append(f)
    STORE.audit("operator", "observe.snapshot.uploaded", None, {"path": path, "keys": sorted(raw),
                                                                **({"device": dev} if dev else {}), **({"pruned": pruned} if pruned else {})})
    return {"stored": os.path.basename(path), **({"device": dev["label"]} if dev else {})}


def _device_snapshots() -> list[dict]:
    """Latest uploaded snapshot per device label (Wave 3 collector), newest collection first."""
    base = os.path.join(SNAPSHOT_DIR, DEVICE_SNAPSHOTS)
    out = []
    for label in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        if not _SNAP_LABEL.match(label):
            continue
        files = sorted(f for f in os.listdir(os.path.join(base, label)) if f.endswith(".json"))
        if files:
            out.append({"label": label, "file": files[-1], "path": os.path.join(base, label, files[-1]), "count": len(files)})
    return out


@app.get("/api/observe/snapshots")
async def list_device_snapshots(user=Depends(VIEWER)):
    """Uploaded per-device Observe snapshots (metadata only; read-only)."""
    out = []
    for s in _device_snapshots():
        raw = json.load(open(s["path"]))
        from .sources import observe as o_src
        pe = o_src.placement_evidence(raw)
        out.append({"label": s["label"], "file": s["file"], "snapshots": s["count"], "device": pe["device_ref"],
                    "collected_at": pe["collected_at"], "age_s": round(time.time() - pe["collected_at"]) if pe["collected_at"] else None,
                    "evidence_state": pe["evidence_state"], "collection": pe["collection"]})
    return out


@app.post("/api/discover/observe/snapshots")
async def run_observe_snapshots(user=Depends(OPERATOR)):
    """Normalize the latest uploaded snapshot of EVERY device (owner-run collector, read-only GETs) into Observe evidence.
    No network access from Autopilot; the existing Observe button is unchanged."""
    snaps = _device_snapshots()
    if not snaps:
        raise HTTPException(424, "no per-device Observe snapshot uploaded (run scripts/observe-collect.sh)")

    async def go():
        res = []
        for s in snaps:
            raw = json.load(open(s["path"]))
            ca = (raw.get("_meta") or {}).get("collected_at")
            r = ENGINE.observe(raw, f"operator snapshot {s['label']}/{s['file']} (collected {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ca))})")
            res.append({"device": s["label"], **r})
        STORE.audit(user["username"], "observe.snapshots.ingested", STORE.current()["id"], {"devices": [s["label"] for s in snaps]})
        return {"devices": res}
    return await _run("observe", go())


async def _observe_raw() -> tuple[dict, str]:
    try:
        return await DEPLOYER.observe_raw(), "live read-only (ap-observer)"
    except Exception as e:
        snaps = sorted(f for f in os.listdir(SNAPSHOT_DIR) if f.endswith(".json")) if os.path.isdir(SNAPSHOT_DIR) else []
        if not snaps:
            raise HTTPException(424, f"live Observe unavailable ({e}) and no operator snapshot uploaded")
        return json.load(open(os.path.join(SNAPSHOT_DIR, snaps[-1]))), f"operator snapshot {snaps[-1]}"


@app.post("/api/discover/observe")
async def run_observe(user=Depends(OPERATOR)):
    """Live read-only collection through the deployer (ap-observer); falls back to the latest operator snapshot."""
    raw, origin = await _observe_raw()

    async def go():
        return ENGINE.observe(raw, origin)
    return await _run("observe", go())


class DescribeReq(BaseModel):
    text: str = Field(min_length=10, max_length=6000)


@app.post("/api/discover/describe")
async def run_describe(r: DescribeReq, user=Depends(OPERATOR)):
    return await _run("describe", ENGINE.describe(r.text, user["username"]))


@app.post("/api/discover/enumerate")
async def run_enumerate(user=Depends(OPERATOR)):
    return await _run("enumerate", ENGINE.enumerate())


@app.post("/api/discover/ingest")
async def run_ingest(user=Depends(OPERATOR)):
    return await _run("ingest", ENGINE.ingest())


@app.post("/api/discover/all")
async def run_all(user=Depends(OPERATOR)):
    out = {}
    for m, fn in (("observe", run_observe), ("enumerate", run_enumerate), ("ingest", run_ingest)):
        try:
            out[m] = await fn(user)
        except HTTPException as e:
            out[m] = {"skipped": e.detail}
    return out


# ---------------------------------------------------------------- recommend / review / approve / deploy
def _pkg(pid: str) -> dict:
    r = STORE.db.execute("SELECT * FROM package WHERE id=?", (pid,)).fetchone()
    if not r:
        raise HTTPException(404, "package not found")
    return {**dict(r), "body": json.loads(r["body"]), "validation": json.loads(r["validation"])}


@app.post("/api/recommend")
async def recommend(user=Depends(OPERATOR)):
    ENGINE.assess()
    return {"packages": [{k: p[k] for k in ("id", "kind", "title", "target", "validation")} for p in packages.build(STORE, CFG)]}


def _can(user: dict, role: str) -> bool:
    return auth.ROLES.get(user["role"], 0) >= auth.ROLES[role]


# The privileged deployer accepts deploy / rollback / reset ONLY from the exact "approver" role (deployer/engine.py):
# a two-person rule — the owner opens the live window, an approver performs the change. The web layer mirrors that rule
# so the UI never offers an action the deployer will refuse, and a refusal is clear, audited and creates no operation.
DEPLOY_ROLE = "approver"
DEPLOY_ROLE_REASON = ("performed by an approver account — the deployer requires the approver role for infrastructure changes "
                      "(two-person rule: the owner opens the live window, an approver deploys)")


def _require_deploy_role(user: dict, action: str, ref: dict) -> None:
    if user.get("role") != DEPLOY_ROLE:
        STORE.audit(user["username"], f"{action}.refused", STORE.current()["id"], {**ref, "reason": "role", "role": user.get("role")})
        raise HTTPException(403, f"{action.replace('_', ' ')} must be {DEPLOY_ROLE_REASON}; signed in as role '{user.get('role')}'")


def _infra_busy() -> dict | None:
    r = STORE.db.execute("SELECT title, actor FROM operation WHERE status='running' AND kind IN ('deploy','rollback','reset_demo')").fetchone()
    return dict(r) if r else None


def _lifecycle(p: dict, user: dict) -> dict:
    """Package state + which actions this user may take now (and why not). The backend enforces the same rules."""
    db, now = STORE.db, time.time()
    a, rv = approvals.latest(db, p["id"]), approvals.latest_review(db, p["id"])
    act = approvals.active(db, p["id"], pkg_hash=approvals.package_hash(p))
    deps = p["deployments"]
    last = deps[0] if deps else None
    h = approvals.package_hash(p)
    last_fail_t = max(((d["finished"] or d["started"]) for d in deps if d["status"] in approvals.FAILED), default=0)
    last_decision_t = a["created"] if a and a["decision"] in ("rejected", "changes_requested", "revoked") else 0
    fresh = bool(rv and rv["package_hash"] == h and now - rv["created"] <= approvals.REVIEW_TTL and rv["created"] > max(last_fail_t, last_decision_t))
    blocked = None
    req = p["body"].get("requires")
    if req:
        ok = db.execute("SELECT 1 FROM deployment d JOIN package k ON k.id=d.package_id WHERE d.assessment_id=? AND k.kind=? "
                        "AND d.status='succeeded'", (p["assessment_id"], req)).fetchone()
        if not ok and p["body"].get("base_deployment"):   # stage deployed in an earlier assessment; the deployer's preflight
            ok = db.execute("SELECT 1 FROM deployment d JOIN package k ON k.id=d.package_id WHERE d.id=? AND k.kind=? "   # also requires
                            "AND d.status='succeeded'", (p["body"]["base_deployment"], req)).fetchone()   # its verified device state
        if not ok:
            blocked = f"requires a successful, validated AI {req.title()} deployment first"
    if last and last["status"] == "running":
        state = "deploying"
    elif last and last["status"] == "succeeded":
        state = "deployed"
    elif act:
        state = "approved"
    elif fresh and rv["ok"] and not blocked:
        state = "ready_for_approval"
    elif fresh and not rv["ok"]:
        state = "preflight_failed"
    elif last and last["status"] in approvals.FAILED:
        state = "failed"
    elif a and a["decision"] in ("rejected", "changes_requested", "revoked"):
        state = a["decision"]
    elif a and a["decision"] == "approved" and not a["consumed_by"] and now > a["expires"]:
        state = "approval_expired"
    elif last and last["status"] == "rolled-back":
        state = "rolled_back"
    elif blocked:
        state = "blocked"
    else:
        state = "proposed"
    busy = _infra_busy()

    def act_(allowed: bool, why: str) -> dict:
        return {"allowed": bool(allowed), "reason": None if allowed else why}
    role_ap, role_op = _can(user, "approver"), _can(user, "operator")
    role_dep = user.get("role") == DEPLOY_ROLE
    actions = {
        "review": act_(role_op and state not in ("deploying",), "operator role required" if not role_op else "deployment running"),
        "approve": act_(role_ap and state == "ready_for_approval", "approver role required" if not role_ap else
                        {"approved": "already approved — duplicate approvals are not allowed", "deployed": "already deployed",
                         "deploying": "deployment running", "blocked": blocked}.get(state) or
                        (blocked or "run 'Preview, diff & preflight' first (it must pass and be less than 30 min old)")),
        "reject": act_(role_ap and state not in ("deployed", "deploying", "approved"), "approver role required" if not role_ap else
                       f"not possible while {state.replace('_', ' ')}"),
        "revoke": act_(role_ap and state == "approved", "approver role required" if not role_ap else "no active approval"),
        "deploy": act_(role_dep and state == "approved" and not blocked and not busy, "approver role required" if not role_ap else
                       DEPLOY_ROLE_REASON if not role_dep else
                       blocked or (f"'{busy['title']}' is running" if busy else {"deployed": "already deployed — roll back first to redeploy",
                                                                               "deploying": "deployment running"}.get(state, "needs an active approval"))),
        "rollback": act_(role_dep and state == "deployed" and not busy, "approver role required" if not role_ap else
                         DEPLOY_ROLE_REASON if not role_dep else
                         (f"'{busy['title']}' is running" if busy else "nothing deployed")),
    }
    nxt = {"proposed": "Run Preview, diff & preflight.", "preflight_failed": "Correct the failed preflight checks, then re-run preflight.",
           "ready_for_approval": "An approver reviews the change summary and approves.", "approved": "Deploy within the approval and live window.",
           "deploying": "Deployment in progress — watch the journal.", "deployed": "Validate, then rediscover (New Assessment) and compare.",
           "failed": "Review the failure diagnosis, correct the cause, re-run preflight, request a new approval, retry.",
           "blocked": blocked, "approval_expired": "Re-run preflight and approve again.", "rolled_back": "Re-run preflight to deploy again.",
           "rejected": "Package rejected — regenerate recommendations or re-run preflight to reconsider.",
           "changes_requested": "Modify inputs (rediscover / regenerate) and re-run preflight.",
           "revoked": "Approval revoked — re-run preflight and approve again if still wanted."}.get(state)
    return {"state": state, "actions": actions, "next_step": nxt, "blocked": blocked, "review": rv and {k: rv[k] for k in ("created", "ok", "reviewer", "device_fingerprint")} | {
        "fresh": fresh, "failed_checks": [c["check"] for c in rv["checks"] if not c["ok"]]}, "active_approval": act}


@app.get("/api/packages")
async def list_packages(user=Depends(VIEWER)):
    aid = STORE.current()["id"]
    out = []
    for r in STORE.db.execute("SELECT id FROM package WHERE assessment_id=? ORDER BY created", (aid,)):
        p = _pkg(r["id"])
        p["hash"] = approvals.package_hash(p)
        p["approval"] = approvals.latest(STORE.db, p["id"])
        p["approvals"] = [dict(x) for x in STORE.db.execute("SELECT * FROM approval WHERE package_id=? ORDER BY created DESC", (p["id"],))]
        p["deployments"] = [dict(d) | {"steps": json.loads(d["steps"]), "diagnosis": diagnose(dict(d) | {"steps": json.loads(d["steps"])})}
                            for d in STORE.db.execute("SELECT * FROM deployment WHERE package_id=? ORDER BY started DESC", (p["id"],))]
        rec = STORE.db.execute("SELECT * FROM recommendation WHERE package_id=?", (p["id"],)).fetchone()
        p["recommendation"] = dict(rec) | {"finding_ids": json.loads(rec["finding_ids"])} if rec else None
        p["lifecycle"] = _lifecycle(p, user)
        out.append(p)
    return out


def diagnose(d: dict) -> dict | None:
    """Plain-language failure explanation, rollback status and next actions for a deployment journal."""
    if d["status"] in ("succeeded", "running", "rolled-back"):
        return None
    failed = next((s for s in d["steps"] if s["status"] == "failed" and s["step"] != "rollback"), None)
    rb = next((s for s in d["steps"] if s["step"] == "rollback"), None)
    name, detail = (failed or {}).get("step", ""), str((failed or {}).get("detail", d.get("error") or ""))
    if name.startswith("converge"):
        rep = (failed or {}).get("report") or {}
        pending = [k for k, v in (rep.get("checks") or {}).items() if not v.get("ok")]
        why = (f"The lab did not reach the expected state within the convergence timeout. Not converged: {', '.join(pending) or 'see detail'}. "
               "Validation was not started.")
        nxt = ["Inspect the listed checks (agent health, DNS answers, BIG-IP pool member status, VIP TLS)",
               "Correct the cause (for example a stopped replica or a monitor that cannot reach a member)"]
    elif name.startswith("gate.validate"):
        res = ((failed or {}).get("report") or {}).get("results") or []
        bad = [r["test"] for r in res if r["result"] != "pass"]
        why = (f"Post-deployment validation failed: {', '.join(bad)}." if bad else
               f"Validation could not run: {detail}. Older journals (before v2) failed here when Agent A was still restarting.")
        nxt = ["Open the failed tests' observed vs expected values", "Correct the cause"]
    elif name == "preflight" or d["status"] == "refused-preflight":
        why = f"Preflight refused the package before any change: {detail}"
        nxt = ["Resolve the failed preflight check (e.g. deploy and validate AI Delivery first for AI Security)"]
    elif name.startswith("window.check") or d["status"] == "refused-window-closed":
        why = "The live deployment window was closed before the first change; nothing was modified."
        nxt = ["Ask the owner to open a supervised live window"]
    elif name.startswith("as3"):
        why = f"BIG-IP AS3 rejected the declaration: {detail}"
        nxt = ["Review the AS3 error", "Regenerate the package if inputs changed"]
    elif name.startswith("dependency"):
        why = f"A host dependency step failed: {detail}"
        nxt = ["Check the project host named in the step"]
    else:
        why = d.get("error") or "unknown failure"
        nxt = []
    rollback = ("not needed — no infrastructure change was made" if d["status"] in ("refused-preflight", "refused-window-closed", "failed-no-changes")
                else ("completed — previous state restored and convergence verified" if any(s["step"].startswith("converge[rollback") and s["status"] == "ok" for s in d["steps"])
                      else "completed — previous state restored (convergence check not configured)") if d["status"] == "failed-rolled-back"
                else "completed — previous configuration restored, but convergence was not verified" if d["status"] == "failed-rolled-back-unverified"
                else "FAILED — use Reset Demo or the manual recovery procedure" if d["status"] == "failed-rollback-failed"
                else ("ran" if rb else "not run"))
    return {"failed_step": name or None, "explanation": why, "rollback": rollback,
            "next_actions": nxt + ["Re-run 'Preview, diff & preflight'", "Request a new approval (the consumed approval cannot be reused)", "Deploy again"]
            if d["status"] not in ("failed-rollback-failed",) else ["Reset Demo Environment", "Contact the lab owner (manual recovery, docs/31 §4)"]}


@app.get("/api/packages/{pid}/review")
async def review(pid: str, user=Depends(OPERATOR)):
    """Preview + diff against the CURRENT device tenant + preflight (verified on device) — read-only."""
    p = _pkg(pid)
    try:
        st = await DEPLOYER.state()
        pf = await DEPLOYER.preflight(p)
    except HTTPException as e:
        return {"package": p, "hash": approvals.package_hash(p), "device": None, "error": f"device state unavailable: {e.detail}"}
    current = st.get("tenant") or {}
    desired = p["body"]["as3"]["declaration"][CFG["design"]["tenant"]]
    diff = list(difflib.unified_diff(json.dumps(current, indent=1, sort_keys=True).splitlines(),
                                     json.dumps(desired, indent=1, sort_keys=True).splitlines(),
                                     "device: AP_AI (current)", "proposed: AP_AI", lineterm="", n=2))
    rv = approvals.record_review(STORE.db, p, st["fingerprint"], pf["checks"], user["username"])
    STORE.audit(user["username"], "package.preflight", p["assessment_id"], {"package": pid, "ok": bool(rv["ok"]),
                "failed": [c["check"] for c in pf["checks"] if not c["ok"]], "fingerprint": st["fingerprint"]})
    return {"package": p, "hash": approvals.package_hash(p), "device": {"fingerprint": st["fingerprint"], "capabilities": st["capabilities"],
            "hosts": st["hosts"], "live_deployment_enabled": st.get("live"), "window": st.get("window")},
            "preflight": pf["checks"], "review": {k: rv[k] for k in ("id", "ok", "created", "reviewer")}, "diff": diff[:4000],
            "change_summary": (p["body"].get("explanation") or {}).get("change_summary", [])}


class Decision(BaseModel):
    decision: str = Field(pattern="^(approved|rejected|changes_requested)$")
    comment: str = Field(default="", max_length=500)


@app.post("/api/packages/{pid}/decision")
async def decide(pid: str, d: Decision, user=Depends(APPROVER)):
    p = _pkg(pid)
    st = await DEPLOYER.state()
    try:
        a = approvals.record(STORE.db, assessment_id=p["assessment_id"], pkg=p, device_fingerprint=st["fingerprint"],
                             decision=d.decision, user=user, comment=d.comment)
    except approvals.ApprovalError as e:
        raise HTTPException(409, str(e))
    STORE.db.execute("UPDATE recommendation SET status=?, decided_by=?, decided_at=? WHERE package_id=?",
                     (d.decision, user["username"], time.time(), pid))
    STORE.audit(user["username"], f"package.{d.decision}", p["assessment_id"], {"package": pid, "hash": a["package_hash"],
                                                                                "fingerprint": a["device_fingerprint"], "expires": a["expires"]})
    return a


class Revoke(BaseModel):
    reason: str = Field(default="", max_length=300)


@app.post("/api/approvals/{approval_id}/revoke")
async def revoke(approval_id: str, r: Revoke, user=Depends(APPROVER)):
    try:
        rv = approvals.revoke(STORE.db, approval_id, user["username"], r.reason or "revoked by approver")
    except approvals.ApprovalError as e:
        raise HTTPException(409, str(e))
    STORE.audit(user["username"], "approval.revoked", rv["assessment_id"], {"approval": approval_id, "revocation": rv["id"],
                                                                            "package": rv["package_id"], "reason": r.reason})
    return rv


def _deploy_guard(p: dict, user: dict) -> dict:
    a = approvals.latest(STORE.db, p["id"])
    if not a:
        raise HTTPException(409, "no approval recorded for this package")
    lc = _lifecycle({**p, "deployments": [dict(d) for d in STORE.db.execute(
        "SELECT * FROM deployment WHERE package_id=? ORDER BY started DESC", (p["id"],))]}, user)
    if lc["blocked"]:
        raise HTTPException(409, lc["blocked"])
    return a


@app.post("/api/packages/{pid}/deploy")
async def deploy(pid: str, user=Depends(APPROVER)):
    p = _pkg(pid)
    _require_deploy_role(user, "deployment", {"package": pid})
    a = _deploy_guard(p, user)
    if _locks["deploy"].locked():
        raise HTTPException(409, "a deployment is already running")
    async with _locks["deploy"]:
        return await DEPLOYER.deploy(p, a["id"], user)


@app.get("/api/deployments")
async def deployments(user=Depends(VIEWER)):
    return [dict(d) | {"steps": json.loads(d["steps"])} for d in STORE.db.execute("SELECT * FROM deployment ORDER BY started DESC LIMIT 50")]


@app.post("/api/deployments/{did}/rollback")
async def rollback(did: str, user=Depends(APPROVER)):
    _require_deploy_role(user, "rollback", {"deployment": did})
    return await DEPLOYER.rollback(did, user)


class ResetDemo(BaseModel):
    confirmation: str = Field(max_length=60)


@app.post("/api/demo/reset")
async def reset_demo(r: ResetDemo, user=Depends(APPROVER)):
    """Reset Demo Environment — privileged; executed by the deployer on allow-listed lab resources only."""
    return await DEPLOYER.reset_demo(user, r.confirmation)


@app.get("/api/device")
async def device(user=Depends(VIEWER)):
    return await DEPLOYER.state()


@app.get("/api/window")
async def window(user=Depends(VIEWER)):
    """Live-deployment window status (cheap: deployer /healthz, no device calls)."""
    try:
        h = await DEPLOYER.health()
        return {"available": True, "live": h.get("live"), "window": h.get("window")}
    except Exception as e:
        return {"available": False, "live": False, "window": {"phase": "unknown", "reason": f"deployment service unavailable: {e}"}}


# ---------------------------------------------------------------- validate / compare / report
class ValReq(BaseModel):
    profile: str = Field(default="before", pattern="^(before|after-delivery|after-security|after-data)$")


@app.post("/api/validate")
async def run_validate(v: ValReq, user=Depends(OPERATOR)):
    if _locks["validate"].locked():
        raise HTTPException(409, "validation already running")
    async with _locks["validate"]:
        res = await validate.run(CFG, v.profile, actions=DEPLOYER.validation_action)
        aid = STORE.current()["id"]
        STORE.db.execute("INSERT INTO validation_run VALUES (?,?,?,?,?,?)", (uuid.uuid4().hex[:16], aid, v.profile, time.time(), time.time(), json.dumps(res)))
        STORE.audit(user["username"], "validation.run", aid, {"profile": v.profile, "pass": sum(r["result"] == "pass" for r in res),
                                                              "fail": sum(r["result"] == "fail" for r in res)})
        return {"profile": v.profile, "results": res}


def _attachment(body: str, media_type: str, filename: str) -> Response:
    """One download contract for every report: explicit length, attachment disposition, no caching, no sniffing.
    Plain same-origin GET (session cookie) — no blob: URLs, which privacy/ad-block extensions are known to cancel."""
    data = body.encode("utf-8")
    safe = "".join(c if c.isalnum() or c in "-_." else "-" for c in filename)
    return Response(data, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="{safe}"; filename*=UTF-8\'\'{safe}', "Content-Length": str(len(data)),
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@app.get("/api/overview")
async def overview_dashboard(user=Depends(VIEWER)):
    """Overview: operating / protected / at-risk services, delivering BIG-IP, health, recent changes (stored evidence; read-only)."""
    return overview.build(STORE, CFG)


@app.get("/api/verification")
async def verification_levels(user=Depends(VIEWER)):
    """Verification levels 1-5 for the current assessment, from stored deployment journals and validation runs (read-only)."""
    return verification.from_store(STORE, STORE.current()["id"])


@app.get("/api/validations")
async def validations(user=Depends(VIEWER)):
    aid = STORE.current()["id"]
    return [{**dict(r), "results": json.loads(r["results"])} for r in
            STORE.db.execute("SELECT * FROM validation_run WHERE assessment_id=? ORDER BY started DESC", (aid,))]


def compare(before: str, after: str) -> dict:
    return report.compare(STORE, before, after)


@app.get("/api/compare")
async def api_compare(before: str, after: str, user=Depends(VIEWER)):
    return compare(before, after)


@app.get("/api/report/{aid}", response_class=HTMLResponse)
async def api_report(aid: str, before: str | None = None, user=Depends(VIEWER)):
    if not STORE.db.execute("SELECT 1 FROM assessment WHERE id=?", (aid,)).fetchone():
        raise HTTPException(404)
    return report.html_report(STORE, aid, before)


@app.get("/api/report/{aid}/executive", response_class=HTMLResponse)
async def api_report_exec(aid: str, before: str | None = None, download: int = 0, user=Depends(VIEWER)):
    if not STORE.db.execute("SELECT 1 FROM assessment WHERE id=?", (aid,)).fetchone():
        raise HTTPException(404)
    page = report.executive_html(STORE, aid, before)
    return _attachment(page, "text/html; charset=utf-8", f"autopilot-executive-summary-{aid}.html") if download else HTMLResponse(page)


@app.get("/api/report/{aid}/evidence")
async def api_report_evidence(aid: str, before: str | None = None, user=Depends(VIEWER)):
    if not STORE.db.execute("SELECT 1 FROM assessment WHERE id=?", (aid,)).fetchone():
        raise HTTPException(404)
    body = json.dumps(report.evidence_bundle(STORE, aid, before), default=str, indent=1)
    return _attachment(body, "application/json", f"autopilot-technical-evidence-{aid}.json")


@app.get("/api/perf")
async def api_perf(user=Depends(VIEWER)):
    return {"validation": report.perf_comparison(STORE)}


@app.get("/api/analytics")
async def analytics(user=Depends(VIEWER)):
    rels = [r for r in STORE.rels() if r["kind"].startswith("calls_")]
    by = {a["id"]: a for a in STORE.assets()}
    rows = []
    for r in rels:
        ing = [c for c in r["claims"] if c["source"] == "ingest"]
        if not ing:
            continue
        c = ing[-1]["attrs"]
        rows.append({"from": by.get(r["src"], {}).get("name"), "to": by.get(r["dst"], {}).get("name"), "protocol": r["kind"][6:],
                     "path": r["observed_path"], "calls": c.get("calls"), "errors": c.get("errors"), "latency_ms": c.get("latency_ms"),
                     "tools": c.get("tools"), "replicas": c.get("replicas"), "peers": c.get("peer_addresses")})
    return {"paths": rows}


AUDIT_CATEGORIES = {"auth": ("auth.",), "discovery": ("discovery.", "asset.", "assessment.", "observe."),
                    "approval": ("package.", "approval."), "deployment": ("deployment.", "deploy.", "rollback.", "reset_demo.", "replica_"),
                    "window": ("live_window.",), "validation": ("validation.",), "operation": ("operation.",),
                    "trafficgen": ("trafficgen.",)}


@app.get("/api/audit")
async def audit(limit: int = 200, category: str = "", actor: str = "", q: str = "", assessment: str = "", since: float = 0,
                user=Depends(VIEWER)):
    """Filterable, append-only audit log (newest first)."""
    sql, args = "SELECT * FROM audit WHERE ts >= ?", [since]
    if category in AUDIT_CATEGORIES:
        sql += " AND (" + " OR ".join("action LIKE ?" for _ in AUDIT_CATEGORIES[category]) + ")"
        args += [p + "%" for p in AUDIT_CATEGORIES[category]]
    if actor:
        sql += " AND actor = ?"
        args.append(actor)
    if assessment:
        sql += " AND assessment_id = ?"
        args.append(assessment)
    if q:
        sql += " AND (action LIKE ? OR detail LIKE ?)"
        args += [f"%{q}%", f"%{q}%"]
    rows = [dict(r) for r in STORE.db.execute(sql + " ORDER BY seq DESC LIMIT ?", (*args, min(limit, 2000)))]
    for r in rows:
        r["category"] = next((c for c, ps in AUDIT_CATEGORIES.items() if r["action"].startswith(ps)), "other")
    actors = [r[0] for r in STORE.db.execute("SELECT DISTINCT actor FROM audit ORDER BY actor")]
    return {"rows": rows, "categories": list(AUDIT_CATEGORIES), "actors": actors}


# ---------------------------------------------------------------- customer fraud application (Phase 1)
FRAUD = CFG.get("fraud_app") or {}


def _fraud_paths() -> tuple[set, set]:
    d = CFG["design"]
    return {d["self_backend"], d["self_agent"]}, {d["a2a_vip"], *d["mcp_vips"]}


@app.get("/api/demo/content")
async def demo_content(user=Depends(VIEWER)):
    return demo.content()


@app.get("/api/fraud/scenarios")
async def fraud_scenarios(user=Depends(VIEWER)):
    d = fraud.dataset()
    return {"dataset": {"seed": d["seed"], "synthetic": d["synthetic"], "generated": d["generated"],
                        "note": "Scenario inputs come from the deterministic synthetic dataset the lab services were loaded with (no real customers)."},
            "scenarios": fraud.scenarios(),
            "accounts": [{k: a[k] for k in ("account_id", "holder", "segment", "home_country", "kyc_risk", "avg_monthly_spend")} for a in d["accounts"]],
            "mcc": d["mcc"], "channels": fraud.CHANNELS, "countries": fraud.COUNTRIES,
            "agent": await fraud.capabilities(FRAUD.get("agent_a_api", CFG["validation"]["agent_a_api"]))}


@app.get("/api/fraud/health")
async def fraud_health(user=Depends(VIEWER)):
    return {"checked_at": time.time(), "from": "AP-AUTOPILOT-01 (read-only HTTP GET)", "checks": await fraud.health(FRAUD.get("health") or [])}


class InvestigateReq(BaseModel):
    scenario_id: str | None = Field(default=None, max_length=40)
    custom: dict | None = None


def _infra_label() -> str:
    """Infrastructure state recorded with each fraud run: the protection in place NOW (verification.protection), so runs after a
    rollback or Reset Demo are labelled baseline, and runs in an unverified state are labelled 'unverified', never protected."""
    return verification.protection_from_store(STORE)["infra_label"]


@app.post("/api/ops/investigate")
async def op_investigate(r: InvestigateReq, user=Depends(OPERATOR)):
    agent_a = FRAUD.get("agent_a_api", CFG["validation"]["agent_a_api"])
    if r.custom:
        try:
            sc = fraud.validate_custom(r.custom)
        except ValueError as e:
            raise HTTPException(422, str(e))
    else:
        sc = next((x for x in fraud.scenarios() if x["id"] == r.scenario_id), None)
        if not sc:
            raise HTTPException(404, "unknown scenario")
    caps = await fraud.capabilities(agent_a)
    if not caps["reachable"]:
        raise HTTPException(503, f"Agent A unreachable: {caps.get('error')}")
    if sc["requires"] not in caps["capabilities"]:
        raise HTTPException(409, caps.get("note") or "scenario not supported by the running agents")

    async def fn(op):
        rid = uuid.uuid4().hex[:16]
        op.ref(fraud_run=rid)
        op.step(f"Agent A investigates '{sc['title']}' → delegates to Agent B over A2A (live)")
        t0 = time.time()
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30, read=600)) as c:
                if sc["kind"] == "suspicious":
                    resp = await c.post(f"{agent_a}/api/investigate", json={"alert_id": sc["alert_id"]})
                else:
                    resp = await c.post(f"{agent_a}/api/investigate-scenario", json={"scenario": {
                        "scenario_id": sc["id"], "account_id": sc["account"]["account_id"], "transactions": sc["transactions"]}})
            body = resp.json() if "json" in resp.headers.get("content-type", "") else {"error": resp.text[:300]}
            if resp.status_code >= 400:
                raise RuntimeError(f"Agent A HTTP {resp.status_code}: {body.get('detail') or body.get('error')}")
        except (httpx.HTTPError, ValueError) as e:
            raise RuntimeError(f"Agent A call failed: {type(e).__name__}: {e}")
        if isinstance(body.get("result"), dict):
            body["result"]["classification_coherence"] = fraud.classification_coherence(sc, body["result"])
        secs = round(time.time() - t0, 1)
        op.step("Collect the distributed trace from Jaeger (spans are exported in batches)")
        tr = await fraud.fetch_trace(CFG["ingest"]["jaeger_url"], body.get("trace_id") or "") if body.get("trace_id") else None
        selfs, vips = _fraud_paths()
        tl = fraud.timeline(tr, selfs, vips) if tr else {"events": [], "edges": [], "summary": None}
        STORE.db.execute("INSERT INTO fraud_run VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            rid, time.time(), user["username"], STORE.current()["id"], sc["id"], json.dumps(sc), body.get("state"), body.get("trace_id"),
            body.get("agent_b_url"), secs, json.dumps({k: body.get(k) for k in ("state", "result", "error", "card_url", "updates", "agent_b_url")})[:400000],
            json.dumps({**(tl["summary"] or {}), "edges": tl.get("edges", [])}), json.dumps(tl["events"]), body.get("error"), _infra_label()))
        STORE.audit(user["username"], "fraud.investigation", STORE.current()["id"], {"run": rid, "scenario": sc["id"], "state": body.get("state"),
                                                                                    "trace_id": body.get("trace_id"), "seconds": secs})
        return {"fraud_run": rid, "state": body.get("state"), "seconds": secs, "timeline_spans": len(tl["events"])}
    return await _op("investigate", f"Investigate {sc['id']} — {sc['title']}", user, fn, {"scenario": sc["id"]})


def _frun(row) -> dict:
    d = dict(row)
    for k in ("scenario", "response", "summary", "events"):
        d[k] = json.loads(d[k]) if d[k] else None
    return d


@app.get("/api/fraud/runs/{rid}/evidence")
async def fraud_evidence(rid: str, user=Depends(VIEWER)):
    r = STORE.db.execute("SELECT * FROM fraud_run WHERE id=?", (rid,)).fetchone()
    if not r:
        raise HTTPException(404)
    d = _frun(r)
    body = json.dumps({"provenance": "live measured Agent A/B response and OpenTelemetry spans", **d}, default=str, indent=1)
    return _attachment(body, "application/json", f"fraud-evidence-{rid}.json")


@app.get("/api/fraud/runs/{rid}/executive", response_class=HTMLResponse)
async def fraud_executive(rid: str, download: int = 0, user=Depends(VIEWER)):
    r = STORE.db.execute("SELECT * FROM fraud_run WHERE id=?", (rid,)).fetchone()
    if not r:
        raise HTTPException(404)
    d = _frun(r); a = ((d["response"] or {}).get("result") or {}).get("assessment") or {}; s = d["summary"] or {}
    classification = (d["response"] or {}).get("result", {}).get("classification") or {}
    classification_label = "Suspicious pattern identified" if classification.get("status") == "classified" else "No suspicious pattern identified" if classification.get("normality_score", 0) >= .72 else "Insufficient evidence — abstention"
    operational_label = {"close": "Monitor baseline / no immediate action", "monitor": "Monitor for additional activity", "escalate": "Escalate for investigation"}.get(a.get("decision"), "Unavailable")
    h = ("<!doctype html><html><head><meta charset='utf-8'><title>Meridian Trust Fraud Investigation</title></head><body>"
         f"<h1>Meridian Trust fraud investigation — {html.escape(d['scenario']['title'])}</h1>"
         f"<p><b>Decision:</b> {html.escape(str(a.get('decision', d['state'])))}</p>"
         f"<p><b>Fraud classification:</b> {html.escape(classification_label)} · <b>Operational outcome:</b> {html.escape(operational_label)}</p>"
         f"<p><b>Classifier status:</b> {html.escape(str(classification.get('status', 'unavailable')))} · <b>Classifier confidence:</b> {html.escape(str(classification.get('confidence', 'unavailable')))} · <b>Normality:</b> {html.escape(str(classification.get('normality_score', 'unavailable')))}</p>"
         f"<p><b>Risk:</b> {html.escape(str(a.get('risk_level', 'unavailable')))} · <b>Confidence:</b> {html.escape(str(a.get('confidence', 'unavailable')))}</p>"
         f"<p><b>Rationale:</b> {html.escape(str(a.get('rationale', '')))}</p>"
         f"<p><b>Measured:</b> {d['seconds']}s end-to-end, {s.get('spans', 'unavailable')} trace spans, {s.get('errors', 'unavailable')} error spans.</p>"
         "<p><b>Scope:</b> synthetic Meridian Trust scenario; F5 benefit is not measured by this baseline run.</p></body></html>")
    return _attachment(h, "text/html; charset=utf-8", f"fraud-executive-{rid}.html") if download else HTMLResponse(h)


@app.get("/api/fraud/runs")
async def fraud_runs(limit: int = 30, user=Depends(VIEWER)):
    out = []
    for r in STORE.db.execute("SELECT * FROM fraud_run ORDER BY created DESC LIMIT ?", (min(limit, 200),)):
        d = _frun(r)
        res = ((d["response"] or {}).get("result") or {})
        out.append({k: d[k] for k in ("id", "created", "actor", "scenario_id", "state", "trace_id", "agent_b_url", "seconds", "error", "infra_state")}
                   | {"title": d["scenario"]["title"], "kind": d["scenario"]["kind"], "decision": (res.get("assessment") or {}).get("decision"),
                      "risk_level": (res.get("assessment") or {}).get("risk_level"), "spans": len(d["events"] or []),
                      "paths": (d["summary"] or {}).get("paths")})
    return out


@app.get("/api/fraud/runs/{rid}")
async def fraud_run(rid: str, user=Depends(VIEWER)):
    r = STORE.db.execute("SELECT * FROM fraud_run WHERE id=?", (rid,)).fetchone()
    if not r:
        raise HTTPException(404)
    return _frun(r)


@app.get("/api/fraud/compare")
async def fraud_compare(user=Depends(VIEWER)):
    """Equivalent-scenario comparison: for every scenario run in more than one infrastructure state, the latest run per state."""
    rows = [_frun(r) for r in STORE.db.execute("SELECT * FROM fraud_run WHERE state='completed' ORDER BY created")]
    by: dict = {}
    for r in rows:
        by.setdefault(r["scenario_id"], {})[r["infra_state"]] = r
    out = []
    for sid, states in by.items():
        if len(states) < 2:
            continue
        out.append({"scenario_id": sid, "title": next(iter(states.values()))["scenario"]["title"], "states": {
            st: {"run": r["id"], "seconds": r["seconds"], "trace_ms": (r["summary"] or {}).get("duration_ms"),
                 "paths": (r["summary"] or {}).get("paths"), "errors": (r["summary"] or {}).get("errors"),
                 "decision": (((r["response"] or {}).get("result") or {}).get("assessment") or {}).get("decision"),
                 "agent_b_url": r["agent_b_url"], "created": r["created"]} for st, r in states.items()}})
    return {"comparisons": out, "note": "Same scenario, different infrastructure state; times are live measurements of single runs "
                                        "(LLM inference dominates and varies run to run)."}


# ---------------------------------------------------------------- control centre (live-window authorisation)
WINDOW_PHRASE, CLOSE_PHRASE = "AUTHORIZE LIVE CHANGES", "CLOSE WINDOW"
WINDOW_ENABLES = {
    "live": ["Deploy approved change packages (each still needs its own hash-bound human approval and a passing preflight)",
             "Roll back deployments", "Reset Demo Environment", "Replica stop/start used by the failover validation test"],
    "cleanup": ["Roll back a succeeded deployment to a previously verified state", "Reset Demo Environment (baseline only)",
                "Replica start (restore)"],
    "locked": ["Nothing that changes infrastructure — discovery, assessment, recommendation, approval and validation still work"],
}


class WindowOpen(BaseModel):
    minutes: int = Field(ge=1, le=180)
    grace: int = Field(ge=1, le=30)
    reason: str = Field(min_length=5, max_length=200)
    confirmation: str = Field(max_length=60)
    password: str = Field(min_length=1, max_length=200)


class WindowClose(BaseModel):
    reason: str = Field(min_length=3, max_length=200)
    confirmation: str = Field(max_length=60)


@app.get("/api/control/status")
async def control_status(user=Depends(VIEWER)):
    try:
        h = await DEPLOYER.health()
        dep = {"available": True, "status": h.get("status"), "live": h.get("live")}
        w = h.get("window") or {}
    except Exception as e:
        dep, w = {"available": False, "error": str(e)[:200]}, {"phase": "unknown", "reason": "deployment service unavailable"}
    try:
        br = await DEPLOYER.window_broker()
    except Exception as e:
        br = {"available": False, "error": str(e)[:200]}
    hist = [dict(r) for r in STORE.db.execute("SELECT seq, ts, actor, action, detail FROM audit WHERE action LIKE 'live_window.%' "
                                               "ORDER BY seq DESC LIMIT 25")]
    phase = w.get("phase") if w.get("phase") in WINDOW_ENABLES else "locked"
    return {"deployer": dep, "window": w, "broker": br, "history": hist, "enables_now": WINDOW_ENABLES[phase], "enables": WINDOW_ENABLES,
            "scope": {"device": f"BIG-IP_C {CFG['observe']['bigip_mgmt']}", "tenant": CFG["design"]["tenant"],
                      "hosts": ["ap-ai-services", "ap-agent-a", "ap-agent-b"], "host_actions": "profile baseline|delivery|security, replica stop|start",
                      "never": "frozen lab, ESXi, /Common objects, other tenants"},
            "limits": {"max_minutes": 180, "max_grace": 30},
            "can_open": user["role"] == "owner", "can_close": _can(user, "approver"),
            "separation": "Approving a change package (approver) authorises WHAT may be deployed. Opening a live window (lab owner, "
                          "password re-entry) authorises WHEN live infrastructure may change. A deployment needs both, plus a passing preflight."}


@app.post("/api/control/window/open")
async def control_open(w: WindowOpen, user=Depends(VIEWER)):
    if user["role"] != "owner":
        STORE.audit(user["username"], "live_window.open.refused", None, {"reason": "not lab owner", "role": user["role"]})
        raise HTTPException(403, "only the lab owner can authorise live infrastructure changes")
    if w.confirmation.strip() != WINDOW_PHRASE:
        STORE.audit(user["username"], "live_window.open.refused", None, {"reason": "confirmation phrase not typed"})
        raise HTTPException(422, f"type '{WINDOW_PHRASE}' to confirm")
    return await DEPLOYER.window_open({"username": user["username"], "password": w.password, "minutes": w.minutes,
                                       "grace": w.grace, "reason": w.reason})


@app.post("/api/control/window/close")
async def control_close(w: WindowClose, user=Depends(VIEWER)):
    if not _can(user, "approver"):
        STORE.audit(user["username"], "live_window.close.refused", None, {"reason": "role", "role": user["role"]})
        raise HTTPException(403, "closing a window requires the approver or owner role")
    if w.confirmation.strip() != CLOSE_PHRASE:
        raise HTTPException(422, f"type '{CLOSE_PHRASE}' to confirm")
    return await DEPLOYER.window_close({"username": user["username"], "role": user["role"], "reason": w.reason})


@app.get("/api/diagnostics/bigip")
async def diag_bigip(user=Depends(VIEWER)):
    try:
        return await DEPLOYER.diagnostics_bigip()
    except Exception as e:
        return {"reachable": False, "error": f"deployment service unavailable: {e}"[:300]}


# ---------------------------------------------------------------- AI Operations dashboard (read-only)
def _aiops_range(r: str) -> str:
    if r not in aiops.RANGES:
        raise HTTPException(400, f"range must be one of {sorted(aiops.RANGES)}")
    return r


@app.get("/api/aiops/delivery")
async def aiops_delivery(range: str = "1h", user=Depends(VIEWER)):
    return await AIOPS.delivery(_aiops_range(range))


@app.get("/api/aiops/security")
async def aiops_security(range: str = "1h", user=Depends(VIEWER)):
    return await AIOPS.security(_aiops_range(range))


@app.get("/api/aiops/investigations")
async def aiops_investigations(user=Depends(VIEWER)):
    return await AIOPS.investigations()


@app.get("/api/aiops/overview")
async def aiops_overview(range: str = "1h", user=Depends(VIEWER)):
    return await AIOPS.overview(_aiops_range(range))


@app.get("/api/aiops/investigations/{source}/{rid}/path")
async def aiops_investigation_path(source: str, rid: str, user=Depends(VIEWER)):
    """Per-stage execution path of one investigation (sanitised summary; stored summary, stored Autopilot timeline or Jaeger)."""
    try:
        return await AIOPS.investigation_path(source, rid)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/aiops/trafficgen")
async def aiops_trafficgen(user=Depends(VIEWER)):
    return AIOPS.trafficgen()


# ---------------------------------------------------------------- Traffic Generator controls
# The browser sends only a preset id and the typed confirmation. The deployer re-checks the role against the user database,
# refuses conflicting work and audits; the host broker (ap-trafficgen-broker) owns the fixed argv of every preset.
TG_PRESET_RE = r"^[a-z0-9][a-z0-9-]{2,39}$"
TG_RUN_KEYS = ("preset", "by", "requested_at", "duration_s", "max_rpm", "workloads", "outcome", "rc", "ended", "stopped_by", "stopped_at")


class TgStart(BaseModel):
    model_config = {"extra": "forbid"}
    preset: str = Field(pattern=TG_PRESET_RE)
    confirm: str = Field(max_length=40)


class TgStop(BaseModel):
    model_config = {"extra": "forbid"}
    confirm: str = Field(max_length=40)


def _tg_run(r) -> dict | None:
    return {k: r.get(k) for k in TG_RUN_KEYS} if isinstance(r, dict) else None


async def _tg_deployer(coro):
    try:
        return await coro
    except httpx.HTTPError as e:
        raise HTTPException(503, f"deployment service unreachable ({type(e).__name__})") from e


@app.get("/api/aiops/trafficgen/control")
async def aiops_trafficgen_control(user=Depends(VIEWER)):
    can = _can(user, "operator")
    try:
        st = await _tg_deployer(DEPLOYER.trafficgen_status())
    except HTTPException as e:
        return {"available": False, "reason": str(e.detail)[:200], "can_control": can, "min_role": "operator"}
    cur = _tg_run(st.get("current"))
    c = st.get("container") if isinstance(st.get("container"), dict) else {}
    running = c.get("running")
    timing = None
    if cur and cur.get("requested_at") and running:
        el = max(0.0, time.time() - float(cur["requested_at"]))
        timing = {"elapsed_s": round(el), "remaining_s": max(0, round(float(cur.get("duration_s") or 0) - el))}
    return {"available": bool(st.get("available")), "reason": st.get("reason"), "min_role": st.get("min_role", "operator"),
            "can_control": can, "running": running, "container": {k: c.get(k) for k in ("exists", "running", "started", "finished", "exit_code")},
            "current": cur, "timing": timing, "history": [_tg_run(h) for h in (st.get("history") or [])][-10:],
            "presets": st.get("presets") or {}, "limits": st.get("limits") or {}, "start_blocked": st.get("start_blocked")}


@app.post("/api/aiops/trafficgen/start")
async def aiops_trafficgen_start(b: TgStart, user=Depends(VIEWER)):
    if not _can(user, "operator"):
        STORE.audit(user["username"], "trafficgen.start.refused", None, {"reason": "role", "role": user["role"], "preset": b.preset})
        raise HTTPException(403, "starting the Traffic Generator requires the operator role or higher")
    return await _tg_deployer(DEPLOYER.trafficgen_start({"username": user["username"], "preset": b.preset, "confirm": b.confirm}))


@app.post("/api/aiops/trafficgen/stop")
async def aiops_trafficgen_stop(b: TgStop, user=Depends(VIEWER)):
    if not _can(user, "operator"):
        STORE.audit(user["username"], "trafficgen.stop.refused", None, {"reason": "role", "role": user["role"]})
        raise HTTPException(403, "stopping the Traffic Generator requires the operator role or higher")
    return await _tg_deployer(DEPLOYER.trafficgen_stop({"username": user["username"], "confirm": b.confirm}))


# ---------------------------------------------------------------- operations (background, progress persisted)
async def _op(kind: str, title: str, user: dict, fn, ref: dict | None = None) -> dict:
    try:
        return await operations.start(STORE, kind, title, user["username"], fn, ref)
    except operations.Busy as e:
        raise HTTPException(409, str(e))


@app.get("/api/ops")
async def ops_list(active: int = 0, user=Depends(VIEWER)):
    return operations.recent(STORE, 30, active_only=bool(active))


@app.get("/api/ops/{op_id}")
async def ops_get(op_id: str, user=Depends(VIEWER)):
    o = operations.get(STORE, op_id)
    if not o:
        raise HTTPException(404)
    return o


class DiscoverReq(BaseModel):
    methods: list[str] = Field(default=["observe", "enumerate", "ingest"])


DISCOVER_TITLES = {"observe": "Observe — read BIG-IP configuration (read-only account)",
                   "enumerate": "Enumerate — approved scope: DNS zone, inventory, protocol handshakes",
                   "ingest": "Ingest — correlate OpenTelemetry traces"}


@app.post("/api/ops/discover")
async def op_discover(r: DiscoverReq, user=Depends(OPERATOR)):
    methods = [m for m in r.methods if m in DISCOVER_TITLES]
    if not methods:
        raise HTTPException(422, "no valid discovery method")

    async def fn(op):
        out = {}
        for m in methods:
            op.step(DISCOVER_TITLES[m])
            try:
                if m == "observe":
                    raw, origin = await _observe_raw()
                    out[m] = ENGINE.observe(raw, origin)
                elif m == "enumerate":
                    out[m] = await ENGINE.enumerate()
                else:
                    out[m] = await ENGINE.ingest()
                op.done("ok", out[m])
            except Exception as e:  # one method failing does not hide the others' results
                out[m] = {"error": f"{type(e).__name__}: {getattr(e, 'detail', e)}"[:400]}
                op.done("failed", out[m])
                STORE.audit("autopilot", f"discovery.{m}.error", STORE.current()["id"], out[m])
        op.step("Assess — evaluate delivery and security rules over the evidence")
        out["assessment"] = assess.run(STORE, CFG, user["username"], "discovery")
        out["assessment"].pop("gaps", None)
        failed = [m for m in methods if isinstance(out.get(m), dict) and out[m].get("error")]
        if failed:
            out["_partial"] = "; ".join(f"{m}: {out[m]['error']}" for m in failed)
        return out
    return await _op("discover", "Discover: " + ", ".join(methods), user, fn)


@app.post("/api/ops/describe")
async def op_describe(r: DescribeReq, user=Depends(OPERATOR)):
    async def fn(op):
        op.step("Describe — AI extraction of components, relationships and claims")
        res = await ENGINE.describe(r.text, user["username"])
        op.step("Verify claims against technical evidence and assess")
        res["assessment"] = assess.run(STORE, CFG, user["username"], "describe")
        res["assessment"].pop("gaps", None)
        return res
    return await _op("describe", "Describe (AI interpretation)", user, fn)


@app.post("/api/ops/assess")
async def op_assess(user=Depends(OPERATOR)):
    async def fn(op):
        op.step("Assess — evaluate delivery and security rules over the evidence")
        res = assess.run(STORE, CFG, user["username"], "manual")
        res.pop("gaps", None)
        return res
    return await _op("recommend", "Assess", user, fn)


@app.post("/api/ops/recommend")
async def op_recommend(user=Depends(OPERATOR)):
    async def fn(op):
        op.step("Assess — refresh findings")
        assess.run(STORE, CFG, user["username"], "recommend")
        op.step("Generate packages from the vetted pattern library + AS3 schema validation")
        pk = packages.build(STORE, CFG)
        return {"packages": [{k: p[k] for k in ("id", "kind", "title")} | {"valid": p["validation"]["valid"]} for p in pk]}
    return await _op("recommend", "Recommend", user, fn)


@app.post("/api/ops/validate")
async def op_validate(v: ValReq, user=Depends(OPERATOR)):
    async def fn(op):
        op.step(f"Validation suite '{v.profile}' — live A2A task, MCP calls, path checks")
        done = []

        def on_result(r):
            done.append(r)
            op.steps[-1]["detail"] = {"completed": len(done), "last": r["test"], "failed": [x["test"] for x in done if x["result"] == "fail"]}
            op._save(steps=op.steps, current=f"validation: {r['test']} {r['result']}")
        res = await validate.run(CFG, v.profile, actions=DEPLOYER.validation_action, on_result=on_result)
        aid = STORE.current()["id"]
        STORE.db.execute("INSERT INTO validation_run VALUES (?,?,?,?,?,?)", (uuid.uuid4().hex[:16], aid, v.profile, time.time(), time.time(), json.dumps(res)))
        STORE.audit(user["username"], "validation.run", aid, {"profile": v.profile, "pass": sum(r["result"] == "pass" for r in res),
                                                              "fail": sum(r["result"] == "fail" for r in res)})
        return {"profile": v.profile, "pass": sum(r["result"] == "pass" for r in res), "total": len(res)}
    return await _op("validate", f"Validate ({v.profile})", user, fn)


@app.post("/api/ops/deploy/{pid}")
async def op_deploy(pid: str, user=Depends(APPROVER)):
    p = _pkg(pid)
    _require_deploy_role(user, "deployment", {"package": pid})
    a = _deploy_guard(p, user)

    async def fn(op):
        op.step(f"Deploy {p['kind']} package (journal: preflight → window → AS3 dry-run → AS3 deploy → host steps → converge → validation gate)")
        d = await DEPLOYER.deploy(p, a["id"], user)
        op.ref(deployment=d.get("id"))
        if d.get("status") != "succeeded":
            raise RuntimeError(f"deployment {d.get('id')} {d.get('status')}: {d.get('error')}")
        return {"deployment": d.get("id"), "status": d.get("status")}
    return await _op("deploy", f"Deploy {p['title'].split(' — ')[0]}", user, fn, {"package": pid, "approval": a["id"]})


@app.post("/api/ops/rollback/{did}")
async def op_rollback(did: str, user=Depends(APPROVER)):
    _require_deploy_role(user, "rollback", {"deployment": did})

    async def fn(op):
        op.step("Roll back to the captured previous state, then wait for convergence")
        return await DEPLOYER.rollback(did, user)
    return await _op("rollback", f"Roll back deployment {did[:8]}", user, fn, {"deployment": did})


@app.post("/api/ops/reset-demo")
async def op_reset_demo(r: ResetDemo, user=Depends(APPROVER)):
    _require_deploy_role(user, "reset_demo", {})
    if r.confirmation != "RESET DEMO ENVIRONMENT":
        raise HTTPException(409, "type 'RESET DEMO ENVIRONMENT' to confirm")

    async def fn(op):
        op.step("Reset Demo — delete AS3 tenant AP_AI, host profiles → baseline, converge, verify 'before' profile")
        res = await DEPLOYER.reset_demo(user, r.confirmation)
        if not res.get("ok"):
            raise RuntimeError(f"reset verification failed: {json.dumps(res.get('verify'))[:400]}")
        return res
    return await _op("reset_demo", "Reset Demo Environment", user, fn)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "llm": LLM_.describe(), "assessment": STORE.current()["id"]}


app.mount("/static", StaticFiles(directory=STATIC), name="static")


def _asset_version(name: str) -> str:
    try:
        with open(os.path.join(STATIC, name), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:12]
    except OSError:
        return "missing"


TRUST_PROXY_PROTO = os.environ.get("AUTOPILOT_TRUST_PROXY_PROTO", "") == "1"   # only behind a TLS-terminating proxy we control


def _is_https(request: Request) -> bool:
    """HTTPS if the connection itself is TLS, or — only when explicitly enabled — a trusted proxy says so."""
    if request.url.scheme == "https":
        return True
    return TRUST_PROXY_PROTO and request.headers.get("x-forwarded-proto", "").lower() == "https"


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    """Browser hardening that is safe on today's HTTP origin; HSTS only when the request actually arrived over HTTPS."""
    resp = await call_next(request)
    h = resp.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    if _is_https(request):
        h.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


@app.middleware("http")
async def _static_revalidate(request: Request, call_next):
    """Static assets must be revalidated: a stale cached app.js after a deployment caused 'works in dev, fails in Chrome'."""
    resp = await call_next(request)
    if request.url.path.startswith("/static/") or request.url.path == "/":
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    return resp


@app.get("/")
async def index():
    """index.html with every local asset reference pinned to its content hash (cache-busting without manual ?v= edits)."""
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
        page = f.read()
    import re as _re
    page = _re.sub(r'(/static/[A-Za-z0-9_.\-]+\.(?:js|css))(\?v=[^"]*)?"', lambda m: f'{m.group(1)}?v={_asset_version(m.group(1)[8:])}"', page)
    return HTMLResponse(page)


def server_kwargs(env=os.environ) -> dict:
    """uvicorn settings. TLS is served directly when BOTH TLS_CERTFILE and TLS_KEYFILE are set (design: doc 24); otherwise
    plain HTTP exactly as before. A half-configured TLS setup is refused rather than silently falling back to HTTP."""
    kw = {"host": env.get("BIND_HOST", "127.0.0.1"), "port": int(env.get("BIND_PORT", "8000"))}
    cert, key = env.get("TLS_CERTFILE"), env.get("TLS_KEYFILE")
    if bool(cert) != bool(key):
        raise SystemExit("TLS_CERTFILE and TLS_KEYFILE must be set together")
    if cert:
        import ssl
        for f in (cert, key):
            if not os.path.isfile(f):
                raise SystemExit(f"TLS file not found: {f}")
        kw.update(ssl_certfile=cert, ssl_keyfile=key, ssl_version=ssl.PROTOCOL_TLS_SERVER)
    return kw


if __name__ == "__main__":
    uvicorn.run(telemetry.asgi(app), **server_kwargs())
