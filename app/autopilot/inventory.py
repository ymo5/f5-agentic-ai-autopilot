"""Inventory snapshots and change history (Wave 2A) — built ONLY from stored evidence; no network access.

A snapshot is the canonical-service view (identity.reconcile) of one assessment at one point in time, plus the
discovery COVERAGE that produced it (which sources ran, the scan scope and ports recorded in the Enumerate evidence,
the telemetry window). Consecutive snapshots are compared; every change carries timestamps and evidence ids.

Absence is never deletion. A service present before but not now is classified from the new snapshot's coverage:
  unreachable  a completed Enumerate scan covered one of its endpoints (address in scope, port in the scanned list)
               and did not find it open;
  unobserved   nothing in this snapshot could have seen it (source not run, outside scan coverage, or telemetry-only
               service without traffic in the window). Missing evidence is not proof of removal.
Missing services are carried forward with their last-seen time and a miss counter; they reappear as "reappeared".
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import time
import uuid

from . import identity

SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory_snapshot (id TEXT PRIMARY KEY, created REAL, source_assessment TEXT, actor TEXT, trigger TEXT,
  reconstructed INTEGER, coverage TEXT, services TEXT, relationships TEXT, digest TEXT, prev_id TEXT);
CREATE TABLE IF NOT EXISTS inventory_change (id TEXT PRIMARY KEY, snapshot_id TEXT, prev_snapshot_id TEXT, ts REAL, service_key TEXT,
  service_name TEXT, change_type TEXT, detail TEXT, evidence_ids TEXT, acknowledged_by TEXT, acknowledged_at REAL);
"""
CHANGE_TYPES = ("new", "changed", "address_changed", "replica_added", "replica_removed", "capabilities_changed", "tools_changed",
                "auth_changed", "version_changed", "relationship_added", "relationship_removed", "unreachable", "unobserved",
                "reappeared")


def _id() -> str:
    return uuid.uuid4().hex[:16]


def coverage(store, aid: str) -> dict:
    """What the assessment's discovery could have seen — derived from its stored evidence."""
    rows = store.db.execute("SELECT id, source, method, collected_at, raw FROM evidence WHERE assessment_id=? ORDER BY collected_at",
                            (aid,)).fetchall()
    cov = {"sources": {}, "scan": None, "telemetry": None}
    for r in rows:
        cov["sources"].setdefault(r["source"], {"last": None, "evidence": 0})
        cov["sources"][r["source"]]["evidence"] += 1
        cov["sources"][r["source"]]["last"] = r["collected_at"]
        if r["source"] == "enumerate" and r["method"] == "approved-inventory":
            try:
                ec = json.loads(r["raw"])
                cov["scan_scope"] = {"scope_cidrs": ec.get("scope_cidrs") or [], "approved_hosts": ec.get("approved_hosts") or [],
                                     "ports": ec.get("ports") or []}
            except (TypeError, ValueError):
                pass
        if r["source"] == "enumerate" and r["method"] == "protocol-fingerprint":
            cov["scan"] = {"at": r["collected_at"], "evidence_id": r["id"]}
        if r["source"] == "ingest":
            try:
                w = (json.loads(r["raw"]) or {}).get("window") or {}
            except (TypeError, ValueError):
                w = {}
            cov["telemetry"] = {"at": r["collected_at"], "evidence_id": r["id"], "since": w.get("since"), "reason": w.get("reason")}
    if cov["scan"] and "scan_scope" in cov:
        cov["scan"].update(cov.pop("scan_scope"))
    return cov


def _covered_by_scan(addr: str, cov: dict) -> bool:
    sc = cov.get("scan") or {}
    if not sc or not addr or "scope_cidrs" not in sc:
        return False
    ip, _, port = addr.rpartition(":")
    try:
        a, p = ipaddress.ip_address(ip), int(port)
    except ValueError:
        return False
    in_scope = ip in (sc.get("approved_hosts") or []) or any(a in ipaddress.ip_network(c) for c in sc.get("scope_cidrs") or [])
    return in_scope and p in (sc.get("ports") or [])


def _service_record(s: dict) -> dict:
    return {"key": s["key"], "id": s["id"], "name": s["name"], "kind": s["kind"], "classification": s["classification"],
            "grouping": s["grouping"], "confidence": s["confidence"], "telemetry_service": s["telemetry_service"],
            "endpoints": sorted(e["address"] for e in s["endpoints"]),
            "instances": sorted([{"key": i["key"], "status": i["status"], "endpoints": len(i["endpoints"])} for i in s["instances"]],
                                key=lambda x: x["key"]),
            "skills": sorted(s["capabilities"]["skills"]), "tools": sorted(s["capabilities"]["tools"]),
            "privileged_tools": sorted(s["capabilities"]["privileged_tools"]), "auth": s["auth"], "versions": s["versions"],
            "card_digest": s["card_digest"], "sources": s["sources"], "evidence_ids": s["evidence_ids"],
            "first_seen": s["first_seen"], "last_seen": s["last_seen"], "status": "observed", "misses": 0}


def build(store, aid: str) -> dict:
    view = identity.reconcile(store, aid)
    svc = {s["key"]: _service_record(s) for s in view["services"]}
    keyof = {s["id"]: s["key"] for s in view["services"]}
    rels = sorted({(keyof.get(r["from"]) or f"asset:{r['from_asset']}", keyof.get(r["to"]) or f"asset:{r['to_asset']}", r["protocol"])
                   for r in view["relationships"]})
    return {"services": svc, "relationships": [list(r) for r in rels], "coverage": coverage(store, aid),
            "unresolved": view["unresolved"]}


def diff(prev: dict | None, cur: dict) -> tuple[list[dict], dict]:
    """Return (changes, carried-forward services). `prev`/`cur` are snapshot bodies (services/relationships/coverage)."""
    changes: list[dict] = []
    ps, cs = (prev or {}).get("services") or {}, dict(cur["services"])
    cov = cur["coverage"]

    def add(t, s, detail, ev=None):
        changes.append({"change_type": t, "service_key": s["key"], "service_name": s["name"], "detail": detail,
                        "evidence_ids": ev if ev is not None else s.get("evidence_ids", [])})

    for k, s in cs.items():
        p = ps.get(k)
        if not p:
            add("new", s, {"endpoints": s["endpoints"], "classification": s["classification"], "grouping": s["grouping"],
                           "first_seen": s["first_seen"]})
            continue
        if p.get("status") != "observed":
            add("reappeared", s, {"previous_status": p.get("status"), "last_seen_before": p.get("last_seen"), "endpoints": s["endpoints"]})
        pe, ce = set(p["endpoints"]), set(s["endpoints"])
        if pe != ce:
            if pe and ce and not (pe & ce):
                add("address_changed", s, {"from": sorted(pe), "to": sorted(ce)})
            else:
                gone = sorted(pe - ce)
                absent = {a: ("unreachable" if _covered_by_scan(a, cov) else "unobserved") for a in gone}
                add("changed", s, {"endpoints_added": sorted(ce - pe), "endpoints_missing": absent})
        pi, ci = len(p["instances"]), len(s["instances"])
        if ci > pi and pi:
            add("replica_added", s, {"instances_before": pi, "instances_now": ci})
        elif ci < pi and ci:
            add("replica_removed", s, {"instances_before": pi, "instances_now": ci,
                                       "note": "fewer instances observed — missing evidence is not proof of removal"})
        if set(p["skills"]) != set(s["skills"]) or (p.get("card_digest") and s.get("card_digest") and p["card_digest"] != s["card_digest"]):
            add("capabilities_changed", s, {"skills_added": sorted(set(s["skills"]) - set(p["skills"])),
                                            "skills_removed": sorted(set(p["skills"]) - set(s["skills"])),
                                            "card_digest": [p.get("card_digest"), s.get("card_digest")]})
        if set(p["tools"]) != set(s["tools"]):
            add("tools_changed", s, {"tools_added": sorted(set(s["tools"]) - set(p["tools"])), "tools_removed": sorted(set(p["tools"]) - set(s["tools"])),
                                     "privileged_added": sorted(set(s["privileged_tools"]) - set(p.get("privileged_tools") or []))})
        if (p.get("auth") or {}) != (s.get("auth") or {}):
            add("auth_changed", s, {"from": p.get("auth"), "to": s.get("auth")})
        if p.get("versions") and s.get("versions") and p["versions"] != s["versions"]:
            add("version_changed", s, {"from": p["versions"], "to": s["versions"]})
    # absent services: carried forward, classified from THIS snapshot's coverage — never deleted
    for k, p in ps.items():
        if k in cs:
            continue
        covered = [a for a in p.get("endpoints") or [] if _covered_by_scan(a, cov)]
        if covered:
            status, why = "unreachable", f"Enumerate scan at {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(cov['scan']['at']))} covered {', '.join(covered)} and did not find it open"
        elif set(p.get("sources") or []) <= {"ingest"} and cov.get("telemetry"):
            status, why = "unobserved", "telemetry-only service with no traffic in this telemetry window (absence of traffic is not removal)"
        elif not cov.get("scan") and not cov.get("telemetry"):
            status, why = "unobserved", "no technical discovery source ran for this snapshot"
        else:
            status, why = "unobserved", "outside the coverage of the sources that ran"
        carried = {**p, "status": status, "misses": int(p.get("misses") or 0) + 1}
        if p.get("status") != status:
            add(status, p, {"reason": why, "last_seen": p.get("last_seen"), "endpoints": p.get("endpoints"), "consecutive_misses": carried["misses"]},
                ev=[(cov.get("scan") or {}).get("evidence_id")] if status == "unreachable" else [])
        cs[k] = carried
    pr, cr = {tuple(x) for x in (prev or {}).get("relationships") or []}, {tuple(x) for x in cur["relationships"]}
    if prev is not None:
        for r in sorted(cr - pr):
            changes.append({"change_type": "relationship_added", "service_key": r[0], "service_name": r[0], "detail": {"from": r[0], "to": r[1], "protocol": r[2]}, "evidence_ids": []})
        for r in sorted(pr - cr):
            changes.append({"change_type": "relationship_removed", "service_key": r[0], "service_name": r[0],
                            "detail": {"from": r[0], "to": r[1], "protocol": r[2], "note": "not observed in this snapshot's telemetry window"},
                            "evidence_ids": []})
    return changes, cs


def latest(store) -> dict | None:
    r = store.db.execute("SELECT * FROM inventory_snapshot ORDER BY created DESC LIMIT 1").fetchone()
    return _row(r) if r else None


def _row(r) -> dict:
    d = dict(r)
    for k in ("coverage", "services", "relationships"):
        d[k] = json.loads(d[k]) if d.get(k) else ({} if k != "relationships" else [])
    return d


def record(store, aid: str, actor: str, trigger: str = "manual", reconstructed: bool = False, at: float | None = None) -> dict:
    """Create a snapshot from stored evidence of assessment `aid`, diff it against the previous snapshot, store both."""
    body = build(store, aid)
    prev = latest(store)
    changes, carried = diff(prev, body)
    body["services"] = carried
    digest = hashlib.sha256(json.dumps({"s": body["services"], "r": body["relationships"]}, sort_keys=True, default=str).encode()).hexdigest()
    snap = {"id": _id(), "created": at or time.time(), "source_assessment": aid, "actor": actor, "trigger": trigger,
            "reconstructed": int(reconstructed), "coverage": json.dumps(body["coverage"]), "services": json.dumps(body["services"]),
            "relationships": json.dumps(body["relationships"]), "digest": digest, "prev_id": prev["id"] if prev else None}
    store.db.execute("INSERT INTO inventory_snapshot VALUES (:id,:created,:source_assessment,:actor,:trigger,:reconstructed,:coverage,"
                     ":services,:relationships,:digest,:prev_id)", snap)
    for c in changes:
        store.db.execute("INSERT INTO inventory_change VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL)",
                         (_id(), snap["id"], snap["prev_id"], snap["created"], c["service_key"], c["service_name"], c["change_type"],
                          json.dumps(c["detail"], default=str), json.dumps([e for e in c["evidence_ids"] if e])))
    store.audit(actor, "inventory.snapshot", aid, {"snapshot": snap["id"], "trigger": trigger, "reconstructed": reconstructed,
                                                   "services": len(body["services"]), "changes": len(changes)})
    return {"snapshot_id": snap["id"], "services": len(body["services"]), "changes": len(changes), "prev_id": snap["prev_id"],
            "change_types": sorted({c["change_type"] for c in changes})}


def changes(store, snapshot_id: str | None = None, limit: int = 500) -> list[dict]:
    q, args = "SELECT * FROM inventory_change", ()
    if snapshot_id:
        q, args = q + " WHERE snapshot_id=?", (snapshot_id,)
    rows = store.db.execute(q + " ORDER BY ts DESC, rowid DESC LIMIT ?", (*args, limit)).fetchall()
    return [{**dict(r), "detail": json.loads(r["detail"] or "{}"), "evidence_ids": json.loads(r["evidence_ids"] or "[]")} for r in rows]


def backfill(store, actor: str, dry_run: bool = True) -> dict:
    """Migration aid: reconstruct snapshots from historical assessments (chronological, marked reconstructed).
    Skips assessments without technical evidence and assessments already used as a snapshot source."""
    live = store.db.execute("SELECT COUNT(*) FROM inventory_snapshot WHERE trigger!='migration'").fetchone()[0]
    if live and not dry_run:
        raise ValueError("backfill must run before the first non-migration snapshot (it would otherwise reorder the timeline)")
    used = {r[0] for r in store.db.execute("SELECT source_assessment FROM inventory_snapshot")}
    plan = []
    for r in store.db.execute("SELECT id, name, created FROM assessment ORDER BY created"):
        n = store.db.execute("SELECT COUNT(*) FROM evidence WHERE assessment_id=? AND source IN ('observe','enumerate','ingest')", (r["id"],)).fetchone()[0]
        last = store.db.execute("SELECT MAX(collected_at) FROM evidence WHERE assessment_id=?", (r["id"],)).fetchone()[0]
        plan.append({"assessment": r["id"], "name": r["name"], "technical_evidence": n, "at": last,
                     "action": "skip (already a snapshot source)" if r["id"] in used else "skip (no technical evidence)" if not n else "reconstruct"})
    if dry_run:
        return {"dry_run": True, "plan": plan}
    done = [record(store, p["assessment"], actor, trigger="migration", reconstructed=True, at=p["at"]) for p in plan if p["action"] == "reconstruct"]
    return {"dry_run": False, "plan": plan, "created": done}
