"""Overview dashboard (read-only): the six operator questions, answered only from stored evidence, each with its source.

  1. Which AI services are operating?        canonical identity (Enumerate / Ingest evidence)
  2. Which services are protected?           an observed BIG-IP virtual server's pool contains the service's endpoints (Observe);
                                             client agents (initiate calls, no inbound front door needed) are 'n/a', never 'yes'
  3. Which services have risks?              assessment findings per service (Assess)
  4. Which BIG-IP is delivering them?        the device whose observed virtual server fronts the service (Observe)
  5. Are the services / BIG-IPs healthy?     placement health check on the latest Observe evidence (policy + freshness)
  6. What changed after deployment?          latest deployment journal + inventory change history (Wave 2A)
History: finding counts by severity per assessment (only assessments that have findings; newest first).

Nothing is estimated: a question the evidence cannot answer says "unknown" with the reason. No network access, no writes.
"""
from __future__ import annotations

import time

from . import assess, identity, inventory, placement, placement_policy, validation_evidence

AI_KINDS = {"a2a_agent", "mcp_server", "ai_agent", "llm_endpoint"}
CLIENT_KINDS = {"ai_agent"}           # initiates calls; BIG-IP protects the services it calls, not an inbound front door of its own
SEV = ("high", "medium", "low")
STAGE_SOURCES = ("observe", "enumerate", "ingest")


def observe_completion(store, aid: str, services: list[dict], virt_known: bool) -> dict:
    """Workflow stage 7 (Observe) is complete only when every criterion holds — never because the page was opened:
      deployments  AI Delivery and AI Security are both in place (verified effective state, verification.current_state);
      validation   the latest qualifying after-security run of the in-place Security deployment ran with no failure
                   (validation_evidence rules: invalid runs ignored, window-locked checks are not run, not failures);
      fresh        the current assessment has Observe, Enumerate and Ingest evidence collected after the latest in-place deployment;
      protection   that evidence establishes the protection state: virtual servers observed and no service 'unknown'."""
    place = validation_evidence.in_place(store)
    crit = []
    dep_ok = "delivery" in place and "security" in place
    crit.append({"key": "deployments", "ok": dep_ok, "detail": "AI Delivery and AI Security deployments in place" if dep_ok else
                 "needs succeeded AI Delivery and AI Security deployments in place (in place: " + (", ".join(sorted(place)) or "none") + ")"})
    after = max((d.get("finished") or d.get("started") or 0) for d in place.values()) if place else None
    sec = place.get("security")
    runs = [r for r in validation_evidence.runs(store) if sec and r["profile"] in validation_evidence.PROFILES["security"]
            and not (r["note"] or "").startswith("invalid run") and r["started"] >= (sec["started"] or 0)]
    eff = [validation_evidence.effective(t) for t in runs[0]["results"]] if runs else []
    val_ok = bool(runs) and "pass" in eff and "fail" not in eff
    crit.append({"key": "validation", "ok": val_ok, "run": runs[0]["id"] if runs else None,
                 "detail": (f"latest after-security validation: {eff.count('pass')} passed, {eff.count('not_run')} not run, "
                            f"{eff.count('fail')} failed") if runs else "needs a passing after-security validation of the in-place Security deployment"})
    last = {s: store.db.execute("SELECT MAX(collected_at) FROM evidence WHERE assessment_id=? AND source=?", (aid, s)).fetchone()[0]
            for s in STAGE_SOURCES}
    stale = [s for s in STAGE_SOURCES if not after or not last[s] or last[s] <= after]
    fresh_ok = dep_ok and not stale
    crit.append({"key": "fresh_evidence", "ok": fresh_ok, "collected": last, "after": after,
                 "detail": "Observe, Enumerate and Ingest evidence collected after the latest deployment" if fresh_ok else
                 ("rediscover after the latest deployment — not yet collected since it finished: " + ", ".join(stale)) if dep_ok else
                 "evidence can only be fresh relative to in-place AI Delivery and AI Security deployments"})
    unknown = [x["name"] for x in services if x["protected"] == "unknown"]
    prot_ok = fresh_ok and virt_known and not unknown
    crit.append({"key": "protection", "ok": prot_ok, "detail": "the fresh evidence establishes the protection state of every service" if prot_ok else
                 "protection state not established" + (f": unknown for {', '.join(unknown)}" if unknown else
                                                       "" if virt_known else ": BIG-IP virtual servers not observed") +
                 ("" if fresh_ok else " (needs fresh evidence)")})
    nxt = next((c["detail"] for c in crit if not c["ok"]), None)
    return {"complete": all(c["ok"] for c in crit), "criteria": crit, "next": nxt,
            "rule": "complete only when deployments, validation, fresh Observe/Enumerate/Ingest evidence and the protection state all hold; "
                    "opening the Observe page never completes it and nothing is rediscovered automatically"}


def build(store, cfg: dict, aid: str | None = None, now: float | None = None) -> dict:
    aid = aid or store.current()["id"]
    now = time.time() if now is None else now
    idn = identity.reconcile(store, aid)
    devices = placement.devices_from_store(store, cfg, aid)
    pol = placement_policy.load(cfg)
    fs = assess.findings(store)
    by_asset: dict[str, list] = {}
    for f in fs:
        for a in f["asset_ids"]:
            by_asset.setdefault(a, []).append(f)
    virt_known = all(d.get("virtuals_state", "observed") == "observed" for d in devices) and bool(devices)
    services = []
    for s in idn["services"]:
        if s["kind"] not in AI_KINDS:
            continue
        cov = placement._coverage(s, devices) if s["endpoints"] else []
        sf = {f["id"]: f for a in s["asset_ids"] for f in by_asset.get(a, [])}.values()
        rules = sorted({f["rule_id"] for f in sf})
        protected = "yes" if cov else ("n/a" if s["kind"] in CLIENT_KINDS else "no" if virt_known and s["endpoints"] else "unknown")
        note = None
        if protected == "n/a":
            note = "client — no inbound virtual server needed"
        elif protected == "no" and s["kind"] == "llm_endpoint":
            note = "outside AI Delivery/Security package scope" + (" · open finding S-008" if "S-008" in rules else "")
        services.append({
            "id": s["id"], "name": s["name"], "kind": s["kind"], "classification": s["classification"],
            "verified": s["verified"], "grouping": s["grouping"], "endpoints": [e["address"] for e in s["endpoints"]],
            "protected": protected, "protection_note": note,
            "protected_basis": ("observed virtual server " + ", ".join(f"{c['virtual']} on {c['device']}" for c in cov)) if cov else
                               ("client agent: it initiates calls and needs no inbound BIG-IP virtual server; BIG-IP protects the services "
                                "it calls (findings on its outbound path still apply)" if protected == "n/a" else
                                "no observed virtual server fronts its endpoints; LLM endpoint protection is outside the current AI "
                                "Delivery/Security package scope" + ("; open finding S-008 (no authentication or rate limiting)" if "S-008" in rules else "")
                                if protected == "no" and s["kind"] == "llm_endpoint" else
                                "no observed virtual server fronts its endpoints" if protected == "no" else
                                "virtual servers not collected or no BIG-IP evidence" if s["endpoints"] else "no listening endpoint"),
            "delivered_by": sorted({c["device"] for c in cov}),
            "findings": {sev: sum(1 for f in sf if f["severity"] == sev) for sev in SEV},
            "rules": rules,
        })
    health = []
    for d in devices:
        hc = next(c for c in placement._device_checks(d, pol, now) if c["check"] == "health")
        health.append({"device": d["id"], "result": hc["result"], "evidence_state": hc.get("evidence_state"), "detail": hc["detail"],
                       "warnings": hc.get("warnings") or [], "collected_at": d.get("collected_at")})
    last_dep = store.db.execute("SELECT d.id, d.status, d.started, d.finished, p.kind FROM deployment d LEFT JOIN package p ON p.id=d.package_id "
                                "WHERE d.assessment_id=? ORDER BY d.started DESC LIMIT 1", (aid,)).fetchone()
    snap = inventory.latest(store)
    recent = inventory.changes(store, snap["id"], limit=20) if snap else []
    names = {a["id"]: a["name"] for a in store.assets(aid)}
    interactions = []
    for r in store.rels(aid):            # telemetry already stored on communication edges (Ingest / OTel); newest claim wins
        if not r["kind"].startswith("calls_") or not r["claims"]:
            continue
        a = max(r["claims"], key=lambda c: c.get("observed_at") or 0)["attrs"]
        lat = a.get("latency_ms") if isinstance(a.get("latency_ms"), dict) else {}
        interactions.append({"from": names.get(r["src"], r["src"]), "to": names.get(r["dst"], r["dst"]), "protocol": r["kind"][6:],
                             "path": r["observed_path"], "calls": a.get("calls"), "errors": a.get("errors"),
                             "p50_ms": lat.get("p50"), "p95_ms": lat.get("p95"), "n": lat.get("n"), "p95_reliable": lat.get("p95_reliable"),
                             "replicas": a.get("replicas") or [], "tools": sorted((a.get("tools") or {}).keys()) if isinstance(a.get("tools"), dict) else []})
    interactions.sort(key=lambda x: (x["protocol"], str(x["from"]), str(x["to"])))
    sev_tot = {sev: sum(1 for f in fs if f["severity"] == sev) for sev in SEV}
    conc = sorted(services, key=lambda x: (-x["findings"]["high"], -x["findings"]["medium"], x["name"] or ""))[:5]
    return {
        "assessment_id": aid, "evaluated_at": now,
        "questions": {
            "operating": {"value": len(services), "source": "canonical identity from Enumerate / Ingest evidence",
                          "by_kind": {k: sum(1 for x in services if x["kind"] == k) for k in sorted(AI_KINDS)}},
            "protected": {"yes": sum(1 for x in services if x["protected"] == "yes"), "no": sum(1 for x in services if x["protected"] == "no"),
                          "unknown": sum(1 for x in services if x["protected"] == "unknown"),
                          "not_applicable": sum(1 for x in services if x["protected"] == "n/a"),
                          "applicable": sum(1 for x in services if x["protected"] != "n/a"),
                          "source": "observed BIG-IP virtual servers and pools (Observe)" if devices else "no BIG-IP Observe evidence"},
            "at_risk": {"services_with_findings": sum(1 for x in services if any(x["findings"].values())), "findings_by_severity": sev_tot,
                        "source": "assessment findings (Assess)"},
            "delivering": {"devices": sorted({d for x in services for d in x["delivered_by"]}), "source": "observed virtual servers (Observe)"},
            "healthy": {"devices": health, "source": f"placement health check, policy {pol['version']} (freshness {pol.get('max_sample_age_s')} s)"},
            "changed": {"last_deployment": dict(last_dep) if last_dep else None,
                        "recent_changes": [{"service": c["service_name"], "type": c["change_type"], "ts": c["ts"]} for c in recent],
                        "source": "deployment journal + inventory change history (record a snapshot after discovery to update)"},
        },
        "history": [{"assessment_id": h["id"], "name": h["name"], "created": h["created"], "current": h["id"] == aid,
                     "findings": {sev: h[sev] for sev in SEV}} for h in store.db.execute(
            "SELECT a.id, a.name, a.created, SUM(f.severity='high') AS high, SUM(f.severity='medium') AS medium, SUM(f.severity='low') AS low "
            "FROM assessment a JOIN finding f ON f.assessment_id = a.id GROUP BY a.id ORDER BY a.created DESC LIMIT 12")],
        "risk": {"unverified_services": [x["name"] for x in services if not x["verified"]], "concentration": [
            {"name": x["name"], "findings": x["findings"], "rules": x["rules"]} for x in conc if any(x["findings"].values())]},
        "services": services,
        "observe_completion": observe_completion(store, aid, services, virt_known),
        "interactions": {"edges": interactions, "source": "OpenTelemetry traces (Ingest): per-edge calls, errors, latency and replicas observed",
                         "not_available": ["HTTP status codes per VIP and per-member request distribution from BIG-IP statistics need a fresh "
                                           "Observe after deployment (virtual/pool stats)", "BIG-IP-side A2A/MCP payload semantics need "
                                           "TLS termination plus iRule/HSL telemetry (configuration change) or an external observability source (not implemented)"]},
        "statement": "Every number comes from stored evidence; 'unknown' means the evidence cannot answer the question.",
    }
