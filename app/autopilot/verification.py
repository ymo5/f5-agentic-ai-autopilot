"""Verification levels (read-only view over stored deployment journals and validation runs).

Level 1  configuration   the deployer's read-back of the BIG-IP configuration after AS3 (`verify.bigip_config` step)
Level 2  operational     post-change convergence: pool members, monitors, DNS and agent readiness (`converge…` steps)
Level 3  functional      AI Delivery controls: controlled requests through the intended paths (a2a.*, mcp.*, delivery.* tests)
Level 4  security        AI Security controls: enforcement tests (security.* tests) — ONLY from after-security validation of an AI
                         Security deployment that is in place. Delivery-profile security.* tests assert that the bypass is still
                         OPEN (exposure confirmed); they are reported as exposure evidence and never make this level "passed".
Level 5  observability   no automated check exists yet -> always "not run" (Wave 5)

Each level is exactly one of: passed | failed | not_run | inconclusive. A level is "passed" only when it ran and every
required check passed; expected tests that never ran make a level inconclusive, never passed. Nothing here contacts a
device or changes state.
"""
from __future__ import annotations

import json

LEVELS = [
    ("configuration", "Configuration verification", "Expected virtual servers, pools, monitors and profiles read back from BIG-IP"),
    ("operational", "Operational verification", "Health of pool members and monitors, DNS and agent readiness after the change"),
    ("functional", "Functional verification — AI Delivery controls", "Controlled requests through the intended VIPs return the expected responses"),
    ("security", "Security-control verification — AI Security controls", "Approved protections behave as designed (allow and deny cases)"),
    ("observability", "Observability verification", "Requested metrics and logs are emitted and received"),
]


def _level_of_test(name: str) -> str | None:
    if name.startswith("security."):
        return "security"
    if name.split(".")[0] in ("a2a", "mcp", "delivery"):
        return "functional"
    return None


# Deployment statuses that changed nothing (refused or failed before the first infrastructure write).
NO_CHANGE = {"refused-preflight", "refused-window-closed", "failed-no-changes"}
# The deployment's configuration was removed again: infrastructure restored to the state before it (verified).
REMOVED = {"failed-rolled-back", "rolled-back"}
# Infrastructure state after the deployment is not verified.
UNVERIFIED = {"failed", "failed-rollback-failed", "failed-rolled-back-unverified", "running"}


SECURITY_PROFILES = ("after-security",)       # validation profiles whose security.* tests assert enforcement


def _replay(deployments: list[dict], resets: list[dict]) -> dict:
    """Replay every infrastructure change in time order and track what is in place.

    in_place  deployments whose configuration is in place now, oldest first. A successful delivery deployment replaces the
              whole AS3 tenant (and with it any security layer); a successful security deployment layers on top of delivery.
    A manual rollback ('rolled-back') removes that deployment (its previous state is restored); 'failed-rolled-back' never
    stayed in place; a verified Reset Demo clears everything; unverified outcomes make the state unknown until the next
    verified change."""
    events = [(d.get("finished") or d.get("started") or 0, 1, "dep", d) for d in deployments if d.get("status") not in NO_CHANGE]
    events += [(r["ts"], 2, "reset", r) for r in resets]
    stack: list[dict] = []
    unverified, last_dep, last_event = None, None, None
    for _, _, kind, x in sorted(events, key=lambda e: (e[0], e[1])):
        last_event = (kind, x)
        if kind == "reset":
            stack, unverified = [], (None if x.get("ok") else x)
            continue
        st, last_dep = x.get("status"), x
        if st == "succeeded":
            stack = ([d for d in stack if d.get("kind") not in ("security", x.get("kind"))] + [x]) if x.get("kind") == "security" else [x]
            unverified = None
        elif st == "rolled-back":
            stack = [d for d in stack if d["id"] != x["id"]]
        elif st == "failed-rolled-back":
            pass
        else:                                       # failed / failed-rollback-failed / failed-rolled-back-unverified / running
            unverified = x
    return {"in_place": stack, "unverified": unverified, "last_dep": last_dep, "last_event": last_event}


def current_state(deployments: list[dict], resets: list[dict] = ()) -> dict:
    """What configuration is in place NOW, derived from the journals and Reset Demo events (see `_replay`).

    kind: none        no deployment ever changed the infrastructure
          active      the newest change was a successful deployment that has not been rolled back or reset since
          baseline    the newest change was removed again (rollback / Reset Demo) and nothing remains deployed
          restored    removed again, and an earlier deployment's configuration is in place (restored, not re-verified)
          unverified  the newest change left the infrastructure in an unverified state
    `last_change` is the newest changing deployment (its read-back is historical unless kind == active);
    `in_place` lists the deployments whose configuration is in place (empty unless active/restored)."""
    rp = _replay(deployments, list(resets))
    stack, last, ev = rp["in_place"], rp["last_dep"], rp["last_event"]
    if ev is None:
        return {"kind": "none", "active": None, "last_change": None, "in_place": []}
    if rp["unverified"] is not None:
        out = {"kind": "unverified", "active": None, "last_change": last, "in_place": []}
        if ev[0] == "reset":
            out["reset"] = ev[1]
        return out
    if ev[0] == "reset":
        return {"kind": "baseline", "active": None, "last_change": last, "reset": ev[1], "in_place": []}
    if stack and stack[-1] is last:
        return {"kind": "active", "active": last, "last_change": last, "in_place": stack}
    if stack:
        return {"kind": "restored", "active": None, "last_change": last, "restored_to": stack[-1], "in_place": stack}
    return {"kind": "baseline", "active": None, "last_change": last, "in_place": []}


def protection(cur: dict) -> dict:
    """Which protections are in place now — for reports and labels. Only active or restored (verified-rollback) states
    carry protection; historical, removed, reset and unverified deployments never do."""
    place = (cur.get("in_place") or []) if cur.get("kind") in ("active", "restored") else []
    kinds = {d.get("kind") or "delivery" for d in place}
    label = ("unverified" if cur.get("kind") == "unverified" else "security" if "security" in kinds else
             "delivery" if "delivery" in kinds else "baseline")
    return {"state": cur.get("kind"), "delivery": "delivery" in kinds, "security": "security" in kinds, "infra_label": label,
            "verified": cur.get("kind") == "active", "in_place": [{"id": d["id"], "kind": d.get("kind") or "delivery",
                                                                  "started": d.get("started")} for d in place]}


def _journal_checks(dep: dict, prefix: str) -> list[dict]:
    return [s for s in (dep.get("steps") or []) if s.get("step", "").startswith(prefix) and "rollback" not in s.get("step", "")]


def _is_security_run(label) -> bool:
    return any(p in (label or "") for p in SECURITY_PROFILES)


def _test_level(names, latest: dict, expected: list, why_empty: str, baseline: list) -> dict:
    names = sorted(set(names))
    if not names:
        why = why_empty
        if baseline:
            why += f"; {len(baseline)} baseline ('before') validation run(s) exist — they verify the pre-deployment state, not a deployed configuration"
        return {"result": "not_run", "detail": why, "checks": []}
    checks = [{"check": n, "result": (latest.get(n) or {}).get("result", "not_run"), "run": (latest.get(n) or {}).get("run"),
               "expected": n in expected} for n in names]
    rs = [c["result"] for c in checks]
    r = ("failed" if "fail" in rs else "passed" if all(x == "pass" for x in rs) else "not_run" if all(x == "not_run" for x in rs)
         else "inconclusive")
    missing = [c["check"] for c in checks if c["result"] == "not_run"]
    return {"result": r, "checks": checks, "detail": (f"expected by the deployed package(s) but not run: {', '.join(missing)}" if missing
                                                       else f"{rs.count('pass')}/{len(rs)} passed in the latest runs")}


def _when(t) -> str:
    import time as _t
    return _t.strftime("%Y-%m-%d %H:%M UTC", _t.gmtime(t)) if t else "unknown time"


def summarize(deployments: list[dict], validations: list[dict], resets: list[dict] = ()) -> dict:
    cur = current_state(deployments, resets)
    active, last = cur["active"], cur["last_change"]
    ok_deps = [active] if active else []
    out = {}
    # levels 1 + 2 describe the CURRENT configuration: only the journal of the deployment that is still in place counts.
    # A removed deployment's successful read-back is kept as history, never reported as the current result.
    for key, prefix in (("configuration", "verify.bigip_config"), ("operational", "converge")):
        if cur["kind"] == "none":
            out[key] = {"result": "not_run", "detail": "no deployment in this assessment", "checks": []}
            continue
        steps = _journal_checks(last, prefix)
        checks = [{"check": s["step"], "result": {"ok": "pass", "failed": "fail"}.get(s.get("status"), s.get("status"))} for s in steps]
        res = [s.get("status") for s in steps]
        r = ("failed" if "failed" in res else "passed" if res and all(x == "ok" for x in res) else "inconclusive") if steps else "not_run"
        if cur["kind"] == "active":
            out[key] = {"result": r, "current": True, "checks": checks,
                        "detail": f"deployment {last['id'][:8]} ({last['status']}) — in place" if steps else
                                  f"deployment {last['id'][:8]} ({last['status']}) recorded no {prefix} step"}
            continue
        hist = {"deployment": last["id"], "status": last["status"], "result": r, "at": max((s.get("finished") or s.get("started") or 0) for s in steps) if steps else None,
                "checks": checks}
        why = {"baseline": "no deployed configuration is in place now",
               "restored": f"the rollback restored the configuration of deployment {(cur.get('restored_to') or {}).get('id', '?')[:8]}, "
                           "which has not been re-verified since",
               "unverified": "the infrastructure state after it is not verified"}[cur["kind"]]
        how = (f"Reset Demo at {_when(cur['reset']['ts'])}" if cur.get("reset") else f"deployment {last['id'][:8]} ended {last['status']}")
        past = (f"; its {key} check {r} at {_when(hist['at'])} — historical evidence, not the current state" if steps else "")
        out[key] = {"result": "not_run" if cur["kind"] == "baseline" else "inconclusive", "current": False, "checks": [], "history": hist,
                    "detail": f"{how}: {why}{past}. Fresh evidence (a new deployment, or a collection that reads the configuration back) is needed."}
    # levels 3 + 4 from validation runs (newest result per test) against the tests the deployed packages expect.
    # Only runs that test a DEPLOYED state count: post-deployment profiles or the deployment gate, on/after the deployment
    # in place. A "before" (baseline) run verifies the pre-deployment state and is never deployment evidence.
    last_ok = max((d.get("started") or 0 for d in ok_deps), default=None)       # only the deployment in place
    baseline = [v for v in validations if (v.get("label") or "") == "before"]
    eligible = [v for v in validations if (v.get("label") or "") != "before" and last_ok is not None and (v.get("started") or 0) >= last_ok]
    prot = protection(cur)
    no_state = ({"none": "no successful deployment in this assessment", "active": "", "baseline": "no deployed configuration is in place now",
                 "restored": "the configuration in place was restored by a rollback and has not been re-verified",
                 "unverified": "the infrastructure state is not verified"}[cur["kind"]])
    # level 3 — AI Delivery controls
    latest: dict[str, dict] = {}
    for run in eligible:                                      # newest first
        for t in run.get("results") or []:
            latest.setdefault(t["test"], {**t, "run": run.get("label"), "started": run.get("started")})
    expected = sorted({t for d in ok_deps for t in (d.get("proven_by") or [])})
    out["functional"] = _test_level([n for n in set(latest) | set(expected) if _level_of_test(n) == "functional"], latest, expected,
                                    no_state if last_ok is None else "no post-deployment validation test of this level has run", baseline)
    # level 4 — AI Security controls: only when an AI Security deployment is in place, and only from security-profile runs
    sec_dep = next((d for d in reversed(cur.get("in_place") or []) if d.get("kind") == "security"), None) if cur["kind"] == "active" else None
    exposure = sorted({(n, t["result"]) for n, t in latest.items() if _level_of_test(n) == "security" and not _is_security_run(t.get("run"))})
    if sec_dep:
        sec_latest: dict[str, dict] = {}
        for run in eligible:
            if _is_security_run(run.get("label")) and (run.get("started") or 0) >= (sec_dep.get("started") or 0):
                for t in run.get("results") or []:
                    sec_latest.setdefault(t["test"], {**t, "run": run.get("label"), "started": run.get("started")})
        sec_expected = [t for t in (sec_dep.get("proven_by") or []) if _level_of_test(t) == "security"]
        out["security"] = _test_level([n for n in set(sec_latest) | set(sec_expected) if _level_of_test(n) == "security"], sec_latest,
                                      sec_expected, "no after-security validation of the AI Security deployment has run", [])
        out["security"]["controls"] = "security"
    else:
        why = ("an AI Security deployment is in place only after a rollback restored it; it has not been re-verified"
               if prot["security"] else "no AI Security deployment is in place — security controls are not deployed")
        out["security"] = {"result": "not_run", "checks": [], "controls": "security", "detail": why + (
            "; the AI Delivery checks of the direct paths confirm exposure only (bypass open), they are not protection"
            if exposure else ""),
            "exposure": [{"check": n, "result": r, "meaning": "exposure confirmed — the direct path is open (no security control deployed)"
                          if r == "pass" else "delivery-profile expectation not met"} for n, r in exposure]}
    out["functional"]["controls"] = "delivery"
    out["observability"] = {"result": "not_run", "checks": [],
                            "detail": "no automated observability verification exists yet (planned)"}
    return {"levels": [{"level": i + 1, "key": k, "title": t, "meaning": m, **out[k]} for i, (k, t, m) in enumerate(LEVELS)],
            "deployment": ({"id": last["id"], "status": last["status"], "package_hash": last.get("package_hash")} if last else None),
            "protection": prot,
            "current_state": {"kind": cur["kind"], "active_deployment": active["id"] if active else None,
                              "last_change": last["id"] if last else None, "reset_at": (cur.get("reset") or {}).get("ts"),
                              "restored_to": (cur.get("restored_to") or {}).get("id")},
            "statement": "A level is 'passed' only when its checks ran and all passed; configuration presence alone does not prove "
                         "that the application works."}


def deployments_from_store(store, aid: str | None = None) -> list[dict]:
    """Deployments newest first (all assessments when aid is None — the infrastructure is shared)."""
    q = ("SELECT d.*, p.body AS pbody, p.kind AS pkind FROM deployment d LEFT JOIN package p ON p.id = d.package_id "
         + ("WHERE d.assessment_id=? " if aid else "") + "ORDER BY d.started DESC")
    deps = []
    for r in store.db.execute(q, (aid,) if aid else ()):
        body = json.loads(r["pbody"]) if r["pbody"] else {}
        deps.append({"id": r["id"], "status": r["status"], "package_hash": r["package_hash"], "steps": json.loads(r["steps"] or "[]"),
                     "started": r["started"], "finished": r["finished"], "kind": r["pkind"], "package_id": r["package_id"],
                     "proven_by": (body.get("expected_outcomes") or {}).get("proven_by") or []})
    return deps


def resets_from_store(store) -> list[dict]:
    return [{"ts": r["ts"], "ok": r["action"] == "reset_demo.verified"}
            for r in store.db.execute("SELECT ts, action FROM audit WHERE action IN ('reset_demo.verified', 'reset_demo.verification-failed')")]


def protection_from_store(store) -> dict:
    """Effective protection in place NOW across the shared infrastructure (all assessments' deployments + Reset Demo)."""
    return protection(current_state(deployments_from_store(store), resets_from_store(store)))


def from_store(store, aid: str) -> dict:
    deps = deployments_from_store(store, aid)
    vals = [{"label": r["label"], "started": r["started"], "results": json.loads(r["results"] or "[]")}
            for r in store.db.execute("SELECT label, started, results FROM validation_run WHERE assessment_id=? ORDER BY started DESC", (aid,))]
    for d in deps:                      # the deployment's own validation gate counts as a validation run
        for s in d["steps"]:
            if not s.get("step", "").startswith("gate.validate"):
                continue
            rep = s.get("detail") if isinstance(s.get("detail"), dict) else s.get("report")
            res = rep.get("results") if isinstance(rep, dict) else rep if isinstance(rep, list) else []
            if res:
                vals.append({"label": f"deployment gate {s['step'][len('gate.validate'):]}", "started": s.get("started") or 0, "results": res})
    vals.sort(key=lambda v: v["started"] or 0, reverse=True)
    return summarize(deps, vals, resets_from_store(store))
