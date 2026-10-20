"""Approval-gated deployment engine.

deploy(): approval verification (hash + device fingerprint + expiry + role) -> preflight -> capture rollback state
-> AS3 dry-run -> AS3 deploy -> scoped host dependencies -> validation gate. Any failure => automatic rollback
to the captured state, then the rollback itself is verified. Every step is journalled (status, timing, detail).
Nothing executes outside a valid live window (window.py) unless the executors are mocks (tests). The window is
re-read on every privileged operation and re-checked immediately before the first infrastructure write; an operation
that has passed that point completes (including its automatic rollback). After expiry, a 30-minute cleanup grace allows
only rollback to a previously verified state and Reset Demo to the baseline; afterwards every write is refused.
"""
from __future__ import annotations

import asyncio
import calendar
import hashlib
import json
import time
import uuid
from typing import Awaitable, Callable

from .. import approvals
from . import converge, policy
from .executors import ExecError
from .window import Window

RESET_CONFIRMATION = "RESET DEMO ENVIRONMENT"
TEMPLATE_COMPAT = {"bigip": ("21.1",), "as3_min": (3, 56)}


VERIFIED_SCHEMA = """
CREATE TABLE IF NOT EXISTS verified_state (state_hash TEXT PRIMARY KEY, deployment_id TEXT, created REAL);
"""


class DeploymentRefused(Exception):
    pass


class WindowClosed(DeploymentRefused):
    """Live window not open for this operation; raised before any infrastructure write."""


class PreflightFailed(DeploymentRefused):
    """Preflight refused the package; raised before any infrastructure write."""


class GateFailed(ExecError):
    def __init__(self, message: str, results: list):
        super().__init__(message)
        self.report = {"results": results}


def state_hash(tenant, hosts) -> str:
    return hashlib.sha256(approvals.canonical({"tenant": tenant, "hosts": hosts})).hexdigest()


BASELINE_HASH = state_hash(None, {h: "baseline" for h in policy.HOSTS})


def _tenant_of(as3: dict) -> dict:
    """The AP_AI tenant of an AS3 request ({"class": "AS3", "declaration": {...}}) or of a bare ADC declaration."""
    d = as3.get("declaration", as3) if isinstance(as3, dict) else {}
    return d.get(policy.TENANT) or {}


def _rollback_tenant(captured: object) -> dict:
    """Return only the captured AP_AI Tenant body for a rollback declaration.

    ``fingerprint()`` stores the AS3 response wrapper (an ADC object), while
    test doubles and older records may already contain the inner Tenant.  Do
    not accept an AS3 request, an ADC nested below AP_AI, or an ambiguous
    wrapper: rollback must fail before the first write in those cases.
    """
    if not isinstance(captured, dict):
        raise DeploymentRefused("rollback state tenant must be an object")

    if captured.get("class") == "ADC":
        tenant = captured.get(policy.TENANT)
        other_tenants = [k for k, v in captured.items()
                         if k != policy.TENANT and isinstance(v, dict) and v.get("class") == "Tenant"]
        if other_tenants or not isinstance(tenant, dict) or tenant.get("class") != "Tenant":
            raise DeploymentRefused("rollback state must contain exactly one AP_AI Tenant in the captured ADC wrapper")
        return tenant

    if captured.get("class") == "Tenant":
        if policy.TENANT in captured:
            raise DeploymentRefused("rollback state contains a double-wrapped AP_AI Tenant")
        return captured

    raise DeploymentRefused("rollback state is not a captured ADC wrapper or AP_AI Tenant")


def _rollback_hosts(captured: object) -> dict[str, str]:
    """Validate the host-profile portion of captured rollback state."""
    if not isinstance(captured, dict) or set(captured) != set(policy.HOSTS):
        raise DeploymentRefused(f"rollback state host profiles must be exactly {sorted(policy.HOSTS)}")
    allowed = {"baseline", "delivery", "security"}
    if any(p not in allowed for p in captured.values()):
        raise DeploymentRefused("rollback state contains an unsupported host profile")
    return dict(captured)


def _memory(body) -> dict | None:
    """Control-plane ('Other') and swap utilisation from /mgmt/tm/sys/memory (searched recursively; None if unreadable)."""
    def find(o):
        if isinstance(o, dict):
            if "otherMemoryTotal" in o:
                return o
            for v in o.values():
                r = find(v)
                if r is not None:
                    return r
        elif isinstance(o, list):
            for v in o:
                r = find(v)
                if r is not None:
                    return r
        return None
    e = find(body)
    if not e:
        return None
    val = lambda k: (e.get(k) or {}).get("value") if isinstance(e.get(k), dict) else e.get(k)
    try:
        ot, ou, st, su = (float(val(k)) for k in ("otherMemoryTotal", "otherMemoryUsed", "swapTotal", "swapUsed"))
        return {"other_used_pct": round(100 * ou / ot, 1) if ot else None, "swap_used_pct": round(100 * su / st, 1) if st else 0.0,
                "other_total_mb": round(ot / 1048576), "swap_total_mb": round(st / 1048576)}
    except (TypeError, ValueError):
        return None


MEMORY_FAIL_PCT, SWAP_WARN_PCT, SWAP_FAIL_PCT, REST_WARN_S, REST_FAIL_S = 95.0, 75.0, 95.0, 2.0, 10.0


def _ver(v: str) -> tuple:
    return tuple(int(x) for x in v.split(".")[:2])


class Engine:
    def __init__(self, store, bigip, hosts, validator: Callable[[str], Awaitable[list]] | None,
                 window: Window | None = None, mock: bool = False, cfg: dict | None = None, probes=None):
        self.s, self.bigip, self.hosts, self.validator, self.mock = store, bigip, hosts, validator, mock
        self.cfg, self.probes = cfg, probes   # convergence barrier enabled when both are set
        self.s.db.executescript(approvals.SCHEMA)
        self.s.db.executescript(VERIFIED_SCHEMA)
        self.window = window or Window(None, store.db)
        self._inflight = 0  # deployments / resets past their last window check (may finish, incl. rollback)

    # ---------------------------------------------------------------- live window
    def window_status(self) -> dict:
        return {"phase": "mock", "reason": None} if self.mock else self.window.status()

    def _authorise(self, op: str, user: dict, assessment_id: str | None = None, detail: dict | None = None) -> dict:
        """Fail closed unless the live window permits `op` right now. Every refusal is audited."""
        if self.mock:
            return {"phase": "mock"}
        ok, st = self.window.check(op)
        if not ok:
            self.s.audit(user.get("username", "?"), f"{op}.refused", assessment_id,
                         {**(detail or {}), "reason": st.get("reason"), "phase": st["phase"], "window_id": st.get("window_id")})
            raise WindowClosed(f"live execution is locked for {op} ({st['phase']}: {st.get('reason')})")
        return st

    # ---------------------------------------------------------------- read-only state
    async def host_status(self) -> dict:
        return {h: await self.hosts.run(h, "status") for h in policy.HOSTS}

    async def capabilities(self) -> dict:
        def desc(body, key):
            for e in (body.get("entries") or {}).values():
                return e["nestedStats"]["entries"].get(key, {}).get("description")
        t0 = time.time()
        _, ver = await self.bigip.get("/mgmt/tm/sys/version")
        _, as3 = await self.bigip.get("/mgmt/shared/appsvcs/info", admin=True)
        _, clock = await self.bigip.get("/mgmt/tm/sys/clock")
        _, selfs = await self.bigip.get("/mgmt/tm/net/self")
        _, certs = await self.bigip.get("/mgmt/tm/sys/crypto/cert", admin=True)  # guest role cannot list crypto
        rest_s = round(time.time() - t0, 2)
        _, mem = await self.bigip.get("/mgmt/tm/sys/memory")
        bigip_time = desc(clock, "fullDate") or ""
        try:
            skew = abs(calendar.timegm(time.strptime(bigip_time, "%Y-%m-%dT%H:%M:%SZ")) - time.time())
        except ValueError:
            skew = None
        return {"verified_on_device": True, "bigip_version": desc(ver, "Version"), "as3_version": (as3 or {}).get("version"),
                "self_ips": sorted(x["address"].split("/")[0] for x in selfs.get("items", [])),
                "certificates": sorted(x["name"] for x in certs.get("items", []) if "aplab" in x["name"]),
                "clock_skew_s": skew, "rest_latency_s": rest_s, "memory": _memory(mem)}

    def _swap_informational(self) -> str | None:
        """LAB-ONLY: the target device's management address when autopilot.yaml lists it under
        lab_policy.swap_informational_devices (swap % is then reported but never fails or warns); otherwise None (default)."""
        devices = {str(x) for x in (((self.cfg or {}).get("lab_policy") or {}).get("swap_informational_devices") or [])}
        target = getattr(self.bigip, "host", None) or ((self.cfg or {}).get("observe") or {}).get("bigip_mgmt")
        return str(target) if target and str(target) in devices else None

    async def fingerprint(self) -> tuple[str, dict]:
        caps = await self.capabilities()
        tenant = await self.bigip.as3_get_tenant()
        if isinstance(tenant, dict):
            tenant = {k: v for k, v in tenant.items() if k not in ("id", "updateMode", "controls", "schemaVersion")}
        hosts = {h: d.get("profile") for h, d in (await self.host_status()).items()}
        state = {"bigip_version": caps["bigip_version"], "as3_version": caps["as3_version"], "tenant": tenant, "hosts": hosts}
        return hashlib.sha256(approvals.canonical(state)).hexdigest(), {**state, "capabilities": caps}

    # ---------------------------------------------------------------- preflight
    async def preflight(self, pkg: dict, state: dict) -> list[dict]:
        caps, body = state["capabilities"], pkg["body"]
        checks = []

        def c(name, ok, detail, warn=False):
            checks.append({"check": name, "ok": bool(ok), "level": "fail" if not ok else "warn" if warn else "pass", "detail": detail})
        c("template.bigip_version", any((caps["bigip_version"] or "").startswith(v) for v in TEMPLATE_COMPAT["bigip"]),
          f"device {caps['bigip_version']}; pattern library validated for {TEMPLATE_COMPAT['bigip']}")
        c("template.as3_version", caps["as3_version"] and _ver(caps["as3_version"]) >= TEMPLATE_COMPAT["as3_min"],
          f"AS3 {caps['as3_version']} (>= {'.'.join(map(str, TEMPLATE_COMPAT['as3_min']))} required)")
        c("prereq.self_ips", {"10.50.10.10", "10.50.20.10"} <= set(caps["self_ips"]), caps["self_ips"])
        c("prereq.certificates", {"/Common/aplab-ca.crt", "/Common/aplab-wildcard.crt"} <= set(caps["certificates"]), caps["certificates"])
        c("prereq.clock", caps["clock_skew_s"] is not None and caps["clock_skew_s"] < 120,
          f"skew {caps['clock_skew_s']:.1f} s (BIG-IP clock read as UTC)" if caps["clock_skew_s"] is not None
          else "BIG-IP clock unreadable or not in UTC ISO format — cannot verify time agreement")
        m = caps.get("memory")
        if m is None:
            c("resource.control_plane_memory", False, "BIG-IP memory statistics unreadable — cannot verify control-plane headroom")
        else:
            swap_info = self._swap_informational()   # LAB-ONLY policy: swap reported, never a pass/fail/warn criterion
            bad = (m["other_used_pct"] or 0) >= MEMORY_FAIL_PCT or (not swap_info and m["swap_used_pct"] >= SWAP_FAIL_PCT)
            c("resource.control_plane_memory", not bad,
              f"control plane {m['other_used_pct']}% of {m['other_total_mb']} MB, swap {m['swap_used_pct']}% of {m['swap_total_mb']} MB"
              + (f" (fail ≥ {MEMORY_FAIL_PCT:.0f}%; swap informational — lab policy for {swap_info})" if swap_info else
                 f" (fail ≥ {MEMORY_FAIL_PCT:.0f}% / swap ≥ {SWAP_FAIL_PCT:.0f}%, warn swap ≥ {SWAP_WARN_PCT:.0f}%)"),
              warn=not swap_info and m["swap_used_pct"] >= SWAP_WARN_PCT)
        r = caps.get("rest_latency_s")
        if r is not None:
            c("resource.rest_latency", r < REST_FAIL_S, f"{r} s for the version read (fail ≥ {REST_FAIL_S:.0f} s, warn ≥ {REST_WARN_S:.0f} s)",
              warn=r >= REST_WARN_S)
        v = policy.check_as3(body["as3"])
        c("policy.as3_scope", not v, v or f"tenant {policy.TENANT} only; pattern-library objects only")
        for d in body.get("dependencies", []):
            try:
                policy.check_host_command(d["host"], d["command"])
                c(f"policy.dependency.{d['host']}", True, d["command"])
            except policy.PolicyViolation as e:
                c(f"policy.dependency.{d['host']}", False, str(e))
        req = body.get("requires")
        if req:
            ok = self.s.db.execute("SELECT 1 FROM deployment WHERE assessment_id=? AND status='succeeded' AND package_id IN "
                                   "(SELECT id FROM package WHERE kind=?)", (pkg["assessment_id"], req)).fetchone()
            how = "in this assessment"
            base = None
            if not ok and body.get("base_deployment"):
                # a stage deployed in an EARLIER assessment: admitted only while the device is exactly in the state that
                # deployment verified (live tenant + host profiles = a verified_state recorded by that deployment)
                base = self.s.db.execute("SELECT p.kind, p.body FROM deployment d JOIN package p ON p.id=d.package_id "
                                         "WHERE d.id=? AND d.status='succeeded'", (body["base_deployment"],)).fetchone()
                ok = bool(base) and base["kind"] == req and self.s.db.execute(
                    "SELECT 1 FROM verified_state WHERE state_hash=? AND deployment_id=?",
                    (state_hash(state["tenant"], state["hosts"]), body["base_deployment"])).fetchone() is not None
                how = f"deployment {body['base_deployment']} with the device in its verified state"
            c("sequence.requires", bool(ok) and all(p == req for p in state["hosts"].values()),
              f"requires a validated '{req}' deployment ({how}) and host profiles = {req}; hosts: {state['hosts']}")
            if base:
                bt, nt = (_tenant_of(x) for x in (json.loads(base["body"])["as3"], body["as3"]))
                changed = [k for k, v in bt.items() if k != "Shared" and nt.get(k) != v]
                changed += [f"Shared/{k}" for k, v in (bt.get("Shared") or {}).items() if (nt.get("Shared") or {}).get(k) != v]
                c("sequence.base_preserved", not changed,
                  f"every object of the base '{req}' declaration unchanged" + (f"; changed: {changed}" if changed else ""))
        return checks

    # ---------------------------------------------------------------- deploy
    def _save(self, dep: dict) -> None:
        self.s.db.execute("INSERT OR REPLACE INTO deployment VALUES (:id,:assessment_id,:package_id,:approval_id,:package_hash,"
                          ":status,:mode,:requested_by,:started,:finished,:steps,:previous_state,:error)",
                          {**dep, "steps": json.dumps(dep["steps"]), "previous_state": json.dumps(dep["previous_state"])})

    async def deploy(self, pkg: dict, approval_id: str, user: dict) -> dict:
        if user.get("role") != "approver":
            raise DeploymentRefused("deployment must be requested by a human approver")
        try:
            self._authorise("deploy", user, pkg.get("assessment_id"), {"package": pkg.get("id")})
        except WindowClosed as e:
            self.s.audit(user["username"], "deployment.refused", pkg.get("assessment_id"), {"package": pkg.get("id"), "reason": str(e)})
            raise DeploymentRefused(f"live deployment is locked — {e}")
        fp, state = await self.fingerprint()
        try:
            a = approvals.verify(self.s.db, approval_id, pkg, fp)
        except approvals.ApprovalError as e:
            self.s.audit(user["username"], "deployment.refused", pkg["assessment_id"], {"package": pkg["id"], "reason": str(e)})
            raise DeploymentRefused(str(e))
        dep = {"id": uuid.uuid4().hex[:16], "assessment_id": pkg["assessment_id"], "package_id": pkg["id"], "approval_id": a["id"],
               "package_hash": a["package_hash"], "status": "running", "mode": "mock" if self.mock else "live",
               "requested_by": user["username"], "started": time.time(), "finished": None, "steps": [],
               "previous_state": {"tenant": state["tenant"], "hosts": state["hosts"]}, "error": None}
        approvals.consume(self.s.db, a["id"], dep["id"])
        self._save(dep)
        self.s.audit(user["username"], "deployment.started", pkg["assessment_id"], {"deployment": dep["id"], "package": pkg["id"],
                                                                                    "hash": a["package_hash"], "mode": dep["mode"]})

        async def step(name, coro):
            st = {"step": name, "status": "running", "started": time.time()}
            dep["steps"].append(st)
            self._save(dep)
            try:
                st["detail"] = await coro
                st["status"] = "ok"
            except Exception as e:  # recorded verbatim; never reported as success
                st["status"], st["detail"] = "failed", f"{type(e).__name__}: {e}"[:800]
                if getattr(e, "report", None) is not None:
                    st["report"] = e.report
                raise
            finally:
                st["finished"] = time.time()
                self._save(dep)
            return st["detail"]

        body = pkg["body"]
        auth = lambda: self._authorise("deploy", user, pkg["assessment_id"], {"package": pkg["id"], "deployment": dep["id"]})
        try:
            checks = await step("preflight", self._preflight_step(pkg, state))
            await step("window.check[before dry-run]", self._async(auth))
            await step("as3.dry_run", self._as3(body["as3"], "dry-run"))
            await step("window.check[before first write]", self._async(auth))
            self._inflight += 1  # past the last window check: this deployment may complete, incl. automatic rollback
            await step("as3.deploy", self._as3(body["as3"], "deploy"))
            await step("verify.bigip_config", self._verify_bigip(body["as3"]))
            changed = self._now()
            for d in body.get("dependencies", []):
                await step(f"dependency {d['host']}: {d['command']}", self.hosts.run(d["host"], d["command"]))
            target = self._target_profile(body)
            if target:
                await step(f"verify.host_profiles[{target}]", self._verify_hosts(target))
            if target == "security":
                await step("fingerprint.agent-b[security]", self._agent_b_fingerprint())
            if target and self.cfg and self.probes:
                await step(f"converge[{target}]", self._converge(target, True, changed, mtls=(pkg["kind"] == "security")))
            if self.validator and body.get("gate_profile"):
                await step(f"gate.validate[{body['gate_profile']}]", self._gate(body["gate_profile"]))
            dep["status"] = "succeeded"
            await self._record_verified(dep["id"])
        except WindowClosed as e:  # refused before the first infrastructure write: nothing to roll back
            dep["error"] = f"WindowClosed: {e}"[:800]
            dep["status"] = "refused-window-closed"
        except Exception as e:
            dep["error"] = f"{type(e).__name__}: {e}"[:800]
            if not any(s["step"] == "as3.deploy" for s in dep["steps"]):
                # failed before the first infrastructure write (preflight / dry-run): nothing changed, nothing to roll back
                dep["status"] = "refused-preflight" if isinstance(e, PreflightFailed) else "failed-no-changes"
            else:
                dep["status"] = "failed"
                try:
                    await step("rollback", self._restore(dep["previous_state"]))
                    dep["status"] = "failed-rolled-back"
                except Exception:
                    dep["status"] = "failed-rollback-failed"
                if dep["status"] == "failed-rolled-back" and self.cfg and self.probes:
                    prev = dep["previous_state"]
                    profiles = set((prev.get("hosts") or {}).values())
                    if len(profiles) == 1:
                        try:
                            await step(f"converge[rollback → {next(iter(profiles))}]",
                                       self._converge(next(iter(profiles)), prev.get("tenant") is not None, self._now() - 1,
                                       mtls=next(iter(profiles)) == "security"))
                        except Exception:
                            dep["status"] = "failed-rolled-back-unverified"
        finally:
            if any(s["step"] == "as3.deploy" for s in dep["steps"]):
                self._inflight -= 1
        dep["finished"] = time.time()
        self._save(dep)
        self.s.audit(user["username"], f"deployment.{dep['status']}", pkg["assessment_id"], {"deployment": dep["id"], "error": dep["error"]})
        return dep

    @staticmethod
    async def _async(fn):
        return fn()

    async def _record_verified(self, deployment_id: str) -> None:
        """After a passing validation gate, remember the resulting state as a verified rollback target."""
        try:
            _, st = await self.fingerprint()
            self.s.db.execute("INSERT OR IGNORE INTO verified_state VALUES (?,?,?)",
                              (state_hash(st["tenant"], st["hosts"]), deployment_id, time.time()))
        except Exception:  # not fatal: the state simply cannot be a cleanup-grace rollback target
            pass

    def _is_verified(self, prev: dict) -> bool:
        h = state_hash(prev.get("tenant"), prev.get("hosts"))
        return h == BASELINE_HASH or self.s.db.execute("SELECT 1 FROM verified_state WHERE state_hash=?", (h,)).fetchone() is not None

    async def _preflight_step(self, pkg, state):
        checks = await self.preflight(pkg, state)
        failed = [c for c in checks if not c["ok"]]
        if failed:
            raise PreflightFailed("preflight failed: " + "; ".join(f"{c['check']}: {c['detail']}" for c in failed))
        return checks

    async def _as3(self, decl: dict, action: str):
        d = {**decl, "action": action}
        res = await self.bigip.as3_post(d)
        return [{k: r.get(k) for k in ("tenant", "code", "message", "dryRun")} for r in res.get("results", [])]

    async def _gate(self, profile: str):
        res = await self.validator(profile)
        failed = [r["test"] for r in res if r["result"] != "pass"]
        if failed:
            raise GateFailed(f"validation gate '{profile}' failed: {failed}", res)
        return {"passed": len(res), "results": res}

    async def _verify_bigip(self, as3: dict) -> dict:
        """Never trust API acceptance alone: read the running configuration back and compare it with the declaration."""
        want = []
        for app, b in as3["declaration"][policy.TENANT].items():
            if isinstance(b, dict) and "service" in b:
                sv, pl = b["service"], b["pool"]
                want.append({"vs": f"/{policy.TENANT}/{app}/service", "dest": f"{sv['virtualAddresses'][0]}:{sv['virtualPort']}",
                             "pool": f"/{policy.TENANT}/{app}/pool", "members": sorted(f"{m['serverAddresses'][0]}:{m['servicePort']}" for m in pl["members"]),
                             "monitor": pl["monitors"][0]["use"].split("/")[-1], "irules": sorted(r["use"].split("/")[-1] for r in sv.get("iRules", [])),
                             # HTTPS services: the declared client-SSL profile must be attached (unchanged check).
                             # HTTP services (AI Data Delivery): no client-SSL profile may be attached; a declared statistics
                             # profile must be attached.
                             "tls": sv["serverTLS"]["use"].split("/")[-1] if "serverTLS" in sv else None,
                             "stats": sv["profileStatistics"]["use"].split("/")[-1] if "profileStatistics" in sv else None,
                             # declared VLAN restriction (AI Data Delivery: isolated lab VLANs only) must be in force on the device
                             "vlans": sorted(x["bigip"] for x in sv["allowVlans"]) if sv.get("allowVlans") else None})
        client_ssl = {o for app, b in as3["declaration"][policy.TENANT].items() if app == "Shared" and isinstance(b, dict)
                      for o, x in b.items() if isinstance(x, dict) and x.get("class") == "TLS_Server"}
        problems, seen = [], {}
        for attempt in range(3):
            code, vs = await self.bigip.get(f"/mgmt/tm/ltm/virtual?$filter=partition+eq+{policy.TENANT}&expandSubcollections=true")
            code2, pools = await self.bigip.get(f"/mgmt/tm/ltm/pool?$filter=partition+eq+{policy.TENANT}&expandSubcollections=true")
            vmap = {v.get("fullPath"): v for v in (vs or {}).get("items", [])} if code == 200 else {}
            pmap = {p.get("fullPath"): p for p in (pools or {}).get("items", [])} if code2 == 200 else {}
            problems = []
            for w in want:
                v, p = vmap.get(w["vs"]), pmap.get(w["pool"])
                if not v:
                    problems.append(f"virtual server {w['vs']} not found on device")
                    continue
                if not str(v.get("destination", "")).endswith(w["dest"]):
                    problems.append(f"{w['vs']} destination {v.get('destination')} != {w['dest']}")
                if (v.get("pool") or "") != w["pool"]:
                    problems.append(f"{w['vs']} pool {v.get('pool')} != {w['pool']}")
                rules = sorted(r.split("/")[-1] for r in (v.get("rules") or []))
                if rules != w["irules"]:
                    problems.append(f"{w['vs']} iRules {rules} != {w['irules']}")
                profs = [x.get("name") for x in ((v.get("profilesReference") or {}).get("items") or [])]
                if w["tls"] is not None and profs and w["tls"] not in profs:
                    problems.append(f"{w['vs']} client-SSL profile {w['tls']} not attached ({profs})")
                if w["tls"] is None and set(profs) & client_ssl:
                    problems.append(f"{w['vs']} is declared HTTP but has client-SSL profile(s) {sorted(set(profs) & client_ssl)}")
                if w["stats"] and w["stats"] not in profs:
                    problems.append(f"{w['vs']} statistics profile {w['stats']} not attached ({profs})")
                if w["vlans"] and not (v.get("vlansEnabled") is True and sorted(v.get("vlans") or []) == w["vlans"]):
                    problems.append(f"{w['vs']} VLAN restriction {w['vlans']} not in force (vlansEnabled={v.get('vlansEnabled')}, vlans={v.get('vlans')})")
                if not p:
                    problems.append(f"pool {w['pool']} not found on device")
                    continue
                members = sorted(m.get("name") for m in ((p.get("membersReference") or {}).get("items") or []))
                if members != w["members"]:
                    problems.append(f"{w['pool']} members {members} != {w['members']}")
                if w["monitor"] not in str(p.get("monitor", "")):
                    problems.append(f"{w['pool']} monitor {p.get('monitor')!r} does not reference {w['monitor']}")
                seen[w["vs"]] = {"destination": v.get("destination"), "members": members, "monitor": str(p.get("monitor", "")).strip()}
            if not problems:
                break
            await asyncio.sleep(2)
        if problems:
            raise ExecError("running BIG-IP configuration does not match the approved declaration: " + "; ".join(problems)[:700])
        return {"verified_objects": len(want), "virtual_servers": seen}

    async def _verify_hosts(self, target: str) -> dict:
        st = {h: d.get("profile") for h, d in (await self.host_status()).items()}
        wrong = {h: p for h, p in st.items() if p != target}
        if wrong:
            raise ExecError(f"host profiles not applied: {wrong} (expected '{target}')")
        return st

    async def _agent_b_fingerprint(self) -> dict:
        """Capture Agent B identity immediately after a Security profile switch."""
        result = await self.hosts.run("ap-agent-b", "status fingerprint")
        required = ("container_id", "image_id", "started_at", "mcp_tools_sha256",
                    "ap_dep_apply_sha256", "executable", "profile")
        if not result.get("ok") or any(not result.get(k) for k in required):
            raise ExecError("Agent B runtime fingerprint is incomplete")
        return result

    @staticmethod
    def _target_profile(body: dict) -> str | None:
        profs = {d["command"].split()[1] for d in body.get("dependencies", []) if d["command"].startswith("profile ")}
        return next(iter(profs)) if len(profs) == 1 else None

    def _now(self) -> float:
        return getattr(self.probes, "clock", time.time)()

    async def _converge(self, profile: str, tenant_present: bool, changed_at: float, mtls: bool = False) -> dict:
        return await converge.wait(converge.spec_for(self.cfg, profile, tenant_present, mtls), self.probes, changed_at,
                                   clock=getattr(self.probes, "clock", time.time), sleep=getattr(self.probes, "sleep", asyncio.sleep))

    async def _restore(self, prev: dict):
        out = {}
        tenant = _rollback_tenant(prev.get("tenant")) if prev.get("tenant") is not None else None
        hosts = _rollback_hosts(prev.get("hosts"))
        if tenant is not None:
            adc = {"class": "ADC", "schemaVersion": "3.56.0", "id": "autopilot-rollback", policy.TENANT: tenant}
            doc = prev.get("tenant") if isinstance(prev.get("tenant"), dict) and prev["tenant"].get("class") == "ADC" else {}
            for k in ("label", "remark"):   # keep the captured document identity: it is part of the verified state hash
                if isinstance(doc.get(k), str):
                    adc[k] = doc[k]
            decl = {"class": "AS3", "action": "deploy", "persist": True, "declaration": adc}
            violations = policy.check_as3(decl)
            if violations:
                raise DeploymentRefused("rollback declaration refused by policy: " + "; ".join(violations))
            out["as3"] = await self._as3(decl, "deploy")
            # Post-rollback read-back: AS3 acceptance alone is not proof. The running configuration must match the restored
            # declaration (virtual servers, destinations, pools, members, monitors, iRules, TLS / HTTP / statistics
            # profiles); a mismatch fails the rollback instead of reporting a restored state.
            out["readback"] = await self._verify_bigip(decl)
        else:
            await self.bigip.as3_delete_tenant()
            out["as3"] = f"tenant {policy.TENANT} removed (no previous declaration)"
        for h, p in hosts.items():
            out[h] = (await self.hosts.run(h, f"profile {p}")).get("profile")
        return out

    async def rollback(self, deployment_id: str, user: dict) -> dict:
        if user.get("role") != "approver":
            raise DeploymentRefused("rollback must be requested by a human approver")
        st = self._authorise("rollback", user, None, {"deployment": deployment_id})
        r = self.s.db.execute("SELECT * FROM deployment WHERE id=?", (deployment_id,)).fetchone()
        if not r:
            raise DeploymentRefused("deployment not found")
        prev = json.loads(r["previous_state"])
        if st["phase"] == "cleanup" and not (r["status"] == "succeeded" and self._is_verified(prev)):
            self.s.audit(user["username"], "rollback.refused", r["assessment_id"],
                         {"deployment": deployment_id, "phase": "cleanup", "status": r["status"],
                          "reason": "cleanup grace: only a succeeded deployment whose previous state was verified can be rolled back"})
            raise DeploymentRefused("cleanup grace: rollback is limited to succeeded deployments whose previous state was verified "
                                    "(baseline or a validated deployment); use Reset Demo or the manual recovery procedure")
        self._authorise("rollback", user, r["assessment_id"], {"deployment": deployment_id})  # immediately before the first write
        # Mark the journal before the first infrastructure write.  Restoring BIG-IP/hosts and only updating the
        # journal after convergence left a stale failed-rollback-failed record if the caller or process disappeared
        # during the (bounded but comparatively long) convergence barrier.
        self.s.db.execute("UPDATE deployment SET status=?, finished=? WHERE id=?",
                          ("rollback-in-progress", time.time(), deployment_id))
        self.s.audit(user["username"], "deployment.rollback.started", r["assessment_id"], {"deployment": deployment_id})
        self._inflight += 1
        try:
            try:
                out = await self._restore(prev)
            except Exception as e:
                self.s.audit(user["username"], "deployment.rollback.failed", r["assessment_id"],
                             {"deployment": deployment_id, "error": f"{type(e).__name__}: {e}"[:800]})
                raise

            # This is deliberately an unverified state: the captured state has been written, but convergence has not
            # yet completed.  If the process is interrupted here, the journal remains honest and recoverable.
            unverified = "failed-rolled-back-unverified" if str(r["status"]).startswith("failed") else "rollback-in-progress"
            self.s.db.execute("UPDATE deployment SET status=?, finished=? WHERE id=?",
                              (unverified, time.time(), deployment_id))
            self.s.audit(user["username"], "deployment.rollback.restored", r["assessment_id"],
                         {"deployment": deployment_id, "verified": False, "result": out})

            profiles = set((prev.get("hosts") or {}).values())
            if self.cfg and self.probes and len(profiles) == 1:
                try:
                    out["converge"] = await self._converge(next(iter(profiles)), prev.get("tenant") is not None, self._now() - 1,
                                       mtls=next(iter(profiles)) == "security")
                except Exception as e:
                    out["converge"] = {"error": f"{type(e).__name__}: {e}"[:800]}
                    self.s.db.execute("UPDATE deployment SET status=?, finished=? WHERE id=?",
                                      ("failed-rolled-back-unverified", time.time(), deployment_id))
                    self.s.audit(user["username"], "deployment.rollback.unverified", r["assessment_id"],
                                 {"deployment": deployment_id, "error": out["converge"]["error"]})
                    return out
        finally:
            self._inflight -= 1
        self.s.db.execute("UPDATE deployment SET status='rolled-back' WHERE id=?", (deployment_id,))
        self.s.audit(user["username"], "deployment.rolled-back", r["assessment_id"], {"deployment": deployment_id, "result": out})
        return out

    async def observe_raw(self) -> dict:
        """Read-only BIG-IP collection for OBSERVE (ap-observer account; AS3 info needs the admin read)."""
        from ..sources.observe import ENDPOINTS
        raw = {}
        for k, path in ENDPOINTS.items():
            code, body = await self.bigip.get(path, admin=(k == "as3"))
            raw[k] = {"status": code, "body": body if isinstance(body, (dict, list)) else None}
        return raw

    # ---------------------------------------------------------------- validation actions (narrow, read-mostly)
    async def validation_action(self, req: dict, internal: bool = False) -> dict:
        a = req.get("action")
        if a == "replica" and req.get("op") in ("stop", "start") and str(req.get("n")) in ("1", "2"):
            if not (internal and self._inflight):  # in-flight gate/reset validations may finish
                self._authorise(f"replica_{req['op']}", {"username": req.get("user", "validation")}, None, {"action": req})
            return await self.hosts.run("ap-ai-services", f"replica {req['op']} {req['n']}")
        if a == "probe_agent_b_direct":
            return await self.hosts.run("ap-agent-b", "probe direct-mcp")
        if a == "pool_status":
            code, pools = await self.bigip.get(f"/mgmt/tm/ltm/pool?$filter=partition+eq+{policy.TENANT}")
            members = []
            for p in (pools or {}).get("items", []) if code == 200 else []:
                if "mcp_risk" not in p.get("fullPath", ""):
                    continue
                _, st = await self.bigip.get(f"/mgmt/tm/ltm/pool/{p['fullPath'].replace('/', '~')}/members/stats")
                for e in (st or {}).get("entries", {}).values():
                    x = e["nestedStats"]["entries"]
                    members.append({"member": x.get("nodeName", {}).get("description"), "port": x.get("port", {}).get("value"),
                                    "availability": x.get("status.availabilityState", {}).get("description"),
                                    "enabled": x.get("status.enabledState", {}).get("description")})
            return {"members": members}
        if a == "data_status":
            return await self._data_status()
        raise DeploymentRefused(f"validation action {a} not permitted")

    DATA_APPS = {"s3": "s3_seaweedfs", "rag": "rag_qdrant", "llm": "llm_ollama"}

    async def _data_status(self) -> dict:
        """AI Data Delivery read model for the after-data validation: pool member state, virtual-server connection counters and
        the S3 statistics profile counters. GET only, through the read-only observer account."""
        def entries(body):
            out = {}
            def walk(o):
                if isinstance(o, dict):
                    for k, v in o.items():
                        if isinstance(v, dict) and "value" in v and isinstance(v["value"], (int, float)):
                            out[k.rsplit("/", 1)[-1]] = v["value"]
                        elif isinstance(v, dict) and "description" in v and k.startswith("status."):
                            out[k] = v["description"]
                        else:
                            walk(v)
            walk(body)
            return out
        members, vss = [], {}
        for svc, app in self.DATA_APPS.items():
            base = f"~{policy.TENANT}~{app}"
            code, st = await self.bigip.get(f"/mgmt/tm/ltm/pool/{base}~pool/members/stats")
            for e in ((st or {}).get("entries") or {}).values() if code == 200 else []:
                x = e["nestedStats"]["entries"]
                # BIG-IP reports the member address as addr.description (the format the live convergence probe reads);
                # nodeName ("/AP_AI/10.50.20.41") is the fallback, without its partition prefix.
                addr = x.get("addr", {}).get("description") or str(x.get("nodeName", {}).get("description") or "").rsplit("/", 1)[-1] or None
                members.append({"service": svc, "member": addr, "port": x.get("port", {}).get("value"),
                                "availability": x.get("status.availabilityState", {}).get("description"),
                                "enabled": x.get("status.enabledState", {}).get("description")})
            code, st = await self.bigip.get(f"/mgmt/tm/ltm/virtual/{base}~service/stats")
            if code == 200:
                e = entries(st)
                vss[svc] = {k: e[k] for k in ("clientside.totConns", "clientside.curConns", "clientside.bitsIn", "clientside.bitsOut") if k in e}
            # HTTP REQUEST count on this virtual server (the attached HTTP profile's numberReqs) — the request-accurate
            # counter; connection counts are reported only for information (keep-alive puts many requests on one connection).
            code, st = await self.bigip.get(f"/mgmt/tm/ltm/virtual/{base}~service/profiles/~{policy.TENANT}~Shared~http_ai/stats")
            if code == 200 and "numberReqs" in entries(st):
                vss.setdefault(svc, {})["http.numberReqs"] = entries(st)["numberReqs"]
        code, st = await self.bigip.get(f"/mgmt/tm/ltm/profile/statistics/~{policy.TENANT}~Shared~stats_s3/stats")
        s3 = self._statistics_counters(st) if code == 200 else {}
        return {"members": members, "virtual_servers": vss, "s3_statistics": s3, "source": "BIG-IP iControl REST GET (observer)"}

    @staticmethod
    def _statistics_counters(body) -> dict:
        """Statistics-profile counters. BIG-IP returns them as STRINGS in `description`, keyed by the configured field name
        (e.g. {"s3_requests": {"description": "214"}}), alongside non-counter entries such as tmName / typeId. Only the
        configured AI Data Delivery field names are accepted, parsed as integers."""
        from .. import data_delivery
        want, out = set(data_delivery.STATS_FIELDS), {}
        for entry in ((body or {}).get("entries") or {}).values():
            for name, stat in (((entry or {}).get("nestedStats") or {}).get("entries") or {}).items():
                if name not in want or not isinstance(stat, dict):
                    continue
                v = stat.get("value", stat.get("description"))
                try:
                    out[name] = int(v) if not isinstance(v, bool) else None
                except (TypeError, ValueError):
                    continue
        return {k: v for k, v in out.items() if v is not None}

    # ---------------------------------------------------------------- reset demo
    async def reset_demo(self, user: dict, confirmation: str) -> dict:
        if user.get("role") != "approver":
            raise DeploymentRefused("Reset Demo Environment requires a human approver")
        if confirmation != RESET_CONFIRMATION:
            raise DeploymentRefused(f"type '{RESET_CONFIRMATION}' to confirm")
        # target is fixed: the approved baseline (tenant absent, host profiles baseline, both replicas running)
        st = self._authorise("reset_demo", user, None, {"target": "baseline"})
        self.s.audit(user["username"], "reset_demo.started", None, {"scope": {"bigip": f"AS3 tenant {policy.TENANT}", "hosts": list(policy.HOSTS)},
                                                                    "phase": st["phase"], "window_id": st.get("window_id")})
        self._inflight += 1
        try:
            return await self._reset_baseline(user)
        finally:
            self._inflight -= 1

    async def _reset_baseline(self, user: dict) -> dict:
        steps = {}
        await self.bigip.as3_delete_tenant()
        steps["bigip"] = f"AS3 tenant {policy.TENANT} deleted"
        for h in policy.HOSTS:
            steps[h] = (await self.hosts.run(h, "profile baseline")).get("profile")
        for n in ("1", "2"):
            await self.hosts.run("ap-ai-services", f"replica start {n}")
        if self.cfg and self.probes:
            try:
                steps["converge"] = await self._converge("baseline", False, self._now() - 1)
            except converge.ConvergenceTimeout as e:
                steps["converge"] = {"error": str(e), **e.report}
        verify = {"tenant_absent": await self.bigip.as3_get_tenant() is None,
                  "hosts_baseline": all(d.get("profile") == "baseline" for d in (await self.host_status()).values())}
        if self.validator:
            res = await self.validator("before")
            verify["before_profile"] = {"passed": sum(r["result"] == "pass" for r in res), "total": len(res)}
        ok = verify["tenant_absent"] and verify["hosts_baseline"] and (not self.validator or verify["before_profile"]["passed"] == verify["before_profile"]["total"])
        self.s.audit(user["username"], "reset_demo." + ("verified" if ok else "verification-failed"), None, {"steps": steps, "verify": verify})
        return {"ok": ok, "steps": steps, "verify": verify}
