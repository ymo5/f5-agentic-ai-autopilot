"""Assessment workspace: evidence, assets, relationships, claims, findings, packages + append-only audit.

Design rules (enforced here, verified by tests):
  * A new assessment contains nothing. Assets/relationships exist only because a claim cites evidence.
  * Every claim records source (observe|describe|enumerate|ingest), evidence id, timestamp, confidence.
  * Customer assertions (describe) never become "verified": status is derived from technical sources.
  * Reset deletes only rows of the current assessment; the audit log is never deleted.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from typing import Any

SOURCES = ("observe", "describe", "enumerate", "ingest")
TECHNICAL = {"observe", "enumerate", "ingest"}
BASE_CONFIDENCE = {"observe": 0.95, "enumerate": 0.85, "ingest": 0.9, "describe": 0.3}

SCHEMA = """
CREATE TABLE IF NOT EXISTS assessment (id TEXT PRIMARY KEY, name TEXT, created REAL, status TEXT);
CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, assessment_id TEXT, source TEXT, method TEXT,
  collected_at REAL, summary TEXT, digest TEXT, raw TEXT);
CREATE TABLE IF NOT EXISTS asset (id TEXT PRIMARY KEY, assessment_id TEXT, key TEXT, kind TEXT, name TEXT,
  attrs TEXT, first_seen REAL, last_seen REAL, UNIQUE(assessment_id, key));
CREATE TABLE IF NOT EXISTS asset_claim (id TEXT PRIMARY KEY, assessment_id TEXT, asset_id TEXT, evidence_id TEXT,
  source TEXT, confidence REAL, attrs TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS rel (id TEXT PRIMARY KEY, assessment_id TEXT, src TEXT, dst TEXT, kind TEXT, path TEXT,
  attrs TEXT, first_seen REAL, last_seen REAL, UNIQUE(assessment_id, src, dst, kind));
CREATE TABLE IF NOT EXISTS rel_claim (id TEXT PRIMARY KEY, assessment_id TEXT, rel_id TEXT, evidence_id TEXT,
  source TEXT, confidence REAL, path TEXT, attrs TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS finding (id TEXT PRIMARY KEY, assessment_id TEXT, rule_id TEXT, category TEXT,
  severity TEXT, title TEXT, detail TEXT, asset_ids TEXT, evidence_ids TEXT, created REAL, UNIQUE(assessment_id, rule_id, title));
CREATE TABLE IF NOT EXISTS recommendation (id TEXT PRIMARY KEY, assessment_id TEXT, finding_ids TEXT, title TEXT,
  rationale TEXT, package_id TEXT, status TEXT, created REAL, decided_by TEXT, decided_at REAL);
CREATE TABLE IF NOT EXISTS package (id TEXT PRIMARY KEY, assessment_id TEXT, kind TEXT, title TEXT, target TEXT,
  body TEXT, validation TEXT, created REAL);
CREATE TABLE IF NOT EXISTS validation_run (id TEXT PRIMARY KEY, assessment_id TEXT, label TEXT, started REAL,
  finished REAL, results TEXT);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT,
  assessment_id TEXT, detail TEXT);
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""
WORKSPACE_TABLES = ["validation_run", "package", "recommendation", "finding", "rel_claim", "rel", "asset_claim", "asset", "evidence"]


def _id() -> str:
    return uuid.uuid4().hex[:16]


class Store:
    def __init__(self, path: str) -> None:
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        from . import approvals, auth
        self.db.executescript(approvals.SCHEMA)
        self.db.execute(auth.USERS_SCHEMA)
        self.lock = threading.RLock()

    # ---------------------------------------------------------------- assessments & audit
    def audit(self, actor: str, action: str, assessment_id: str | None, detail: dict | None = None) -> None:
        self.db.execute("INSERT INTO audit (ts, actor, action, assessment_id, detail) VALUES (?,?,?,?,?)",
                        (time.time(), actor, action, assessment_id, json.dumps(detail or {}, default=str)))

    def current(self) -> dict:
        row = self.db.execute("SELECT * FROM assessment WHERE status='active' ORDER BY created DESC LIMIT 1").fetchone()
        return dict(row) if row else self.new_assessment("system", "Assessment")

    def new_assessment(self, actor: str, name: str) -> dict:
        with self.lock:
            self.db.execute("UPDATE assessment SET status='closed' WHERE status='active'")
            a = {"id": _id(), "name": name, "created": time.time(), "status": "active"}
            self.db.execute("INSERT INTO assessment VALUES (:id,:name,:created,:status)", a)
            self.audit(actor, "assessment.created", a["id"], {"name": name})
            return a

    def reset(self, actor: str) -> dict:
        """Clear ONLY the current assessment workspace and derived results (audit retained)."""
        with self.lock:
            aid = self.current()["id"]
            counts = {}
            for t in WORKSPACE_TABLES:
                cond = " AND id NOT IN (SELECT package_id FROM approval)" if t == "package" else ""
                counts[t] = self.db.execute(f"DELETE FROM {t} WHERE assessment_id=?{cond}", (aid,)).rowcount
            self.audit(actor, "assessment.reset", aid, {"deleted_rows": counts})
            return {"assessment_id": aid, "deleted_rows": counts}

    # ---------------------------------------------------------------- evidence & claims
    def add_evidence(self, source: str, method: str, summary: str, raw: Any) -> str:
        assert source in SOURCES
        aid = self.current()["id"]
        blob = json.dumps(raw, default=str, sort_keys=True)
        eid = _id()
        self.db.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?)",
                        (eid, aid, source, method, time.time(), summary, hashlib.sha256(blob.encode()).hexdigest(), blob))
        return eid

    def claim_asset(self, evidence_id: str, source: str, key: str, kind: str, name: str,
                    attrs: dict | None = None, confidence: float | None = None) -> str:
        """Upsert an asset by canonical identity `key` (dedup) and attach a claim citing evidence."""
        aid = self.current()["id"]
        now = time.time()
        attrs = attrs or {}
        with self.lock:
            row = self.db.execute("SELECT id, attrs, kind, name FROM asset WHERE assessment_id=? AND key=?", (aid, key)).fetchone()
            if row:
                merged = {**json.loads(row["attrs"]), **attrs}
                # technical sources may refine kind/name asserted by a description; never the reverse
                kind_ = kind if (source in TECHNICAL and row["kind"] in ("unknown", "asserted_component")) else row["kind"]
                self.db.execute("UPDATE asset SET attrs=?, kind=?, last_seen=? WHERE id=?", (json.dumps(merged), kind_, now, row["id"]))
                asset_id = row["id"]
            else:
                asset_id = _id()
                self.db.execute("INSERT INTO asset VALUES (?,?,?,?,?,?,?,?)",
                                (asset_id, aid, key, kind, name, json.dumps(attrs), now, now))
            self.db.execute("INSERT INTO asset_claim VALUES (?,?,?,?,?,?,?,?)",
                            (_id(), aid, asset_id, evidence_id, source, confidence or BASE_CONFIDENCE[source], json.dumps(attrs), now))
        return asset_id

    def claim_rel(self, evidence_id: str, source: str, src_id: str, dst_id: str, kind: str, path: str = "unknown",
                  attrs: dict | None = None, confidence: float | None = None) -> str:
        """path: direct | via_bigip | unknown. Kept per-claim so conflicting evidence stays visible."""
        aid = self.current()["id"]
        now = time.time()
        with self.lock:
            row = self.db.execute("SELECT id FROM rel WHERE assessment_id=? AND src=? AND dst=? AND kind=?",
                                  (aid, src_id, dst_id, kind)).fetchone()
            if row:
                rel_id = row["id"]
                self.db.execute("UPDATE rel SET last_seen=? WHERE id=?", (now, rel_id))
            else:
                rel_id = _id()
                self.db.execute("INSERT INTO rel VALUES (?,?,?,?,?,?,?,?,?)",
                                (rel_id, aid, src_id, dst_id, kind, path, json.dumps(attrs or {}), now, now))
            self.db.execute("INSERT INTO rel_claim VALUES (?,?,?,?,?,?,?,?,?)",
                            (_id(), aid, rel_id, evidence_id, source, confidence or BASE_CONFIDENCE[source], path,
                             json.dumps(attrs or {}), now))
        return rel_id

    def merge_assets(self, keep_id: str, drop_id: str, evidence_id: str, reason: str) -> None:
        """Reconcile a described (asserted) component into a technically discovered asset."""
        with self.lock:
            for t, col in (("asset_claim", "asset_id"),):
                self.db.execute(f"UPDATE {t} SET {col}=? WHERE {col}=?", (keep_id, drop_id))
            for col in ("src", "dst"):
                for r in self.db.execute(f"SELECT * FROM rel WHERE {col}=?", (drop_id,)).fetchall():
                    other = {"src": r["src"], "dst": r["dst"], col: keep_id}
                    existing = self.db.execute("SELECT id FROM rel WHERE assessment_id=? AND src=? AND dst=? AND kind=?",
                                               (r["assessment_id"], other["src"], other["dst"], r["kind"])).fetchone()
                    if existing:
                        self.db.execute("UPDATE rel_claim SET rel_id=? WHERE rel_id=?", (existing["id"], r["id"]))
                        self.db.execute("DELETE FROM rel WHERE id=?", (r["id"],))
                    else:
                        self.db.execute(f"UPDATE rel SET {col}=? WHERE id=?", (keep_id, r["id"]))
            dropped = self.db.execute("SELECT name, attrs FROM asset WHERE id=?", (drop_id,)).fetchone()
            keep = self.db.execute("SELECT attrs FROM asset WHERE id=?", (keep_id,)).fetchone()
            attrs = json.loads(keep["attrs"])
            attrs.setdefault("described_as", []).append(dropped["name"])
            self.db.execute("UPDATE asset SET attrs=? WHERE id=?", (json.dumps(attrs), keep_id))
            self.db.execute("DELETE FROM asset WHERE id=?", (drop_id,))
            self.audit("autopilot", "asset.reconciled", self.current()["id"],
                       {"kept": keep_id, "merged": drop_id, "evidence": evidence_id, "reason": reason})

    # ---------------------------------------------------------------- derived views
    @staticmethod
    def _status(sources: set[str], paths: set[str] | None = None) -> str:
        tech = sources & TECHNICAL
        if paths is not None:
            tech_paths = paths - {"unknown"}
            if len(tech_paths) > 1:
                return "conflicted"
        if not tech:
            return "asserted"
        return "corroborated" if len(tech) >= 2 else "observed"

    def assets(self, assessment_id: str | None = None) -> list[dict]:
        aid = assessment_id or self.current()["id"]
        out = []
        for a in self.db.execute("SELECT * FROM asset WHERE assessment_id=? ORDER BY first_seen", (aid,)).fetchall():
            claims = [dict(c) for c in self.db.execute(
                "SELECT c.source, c.confidence, c.ts, c.evidence_id, e.method, e.summary FROM asset_claim c "
                "JOIN evidence e ON e.id=c.evidence_id WHERE c.asset_id=? ORDER BY c.ts", (a["id"],)).fetchall()]
            srcs = {c["source"] for c in claims}
            tech = [c["confidence"] for c in claims if c["source"] in TECHNICAL]
            conf = 1.0 - _prod(1 - c for c in tech) if tech else max((c["confidence"] for c in claims), default=0)
            out.append({**dict(a), "attrs": json.loads(a["attrs"]), "sources": sorted(srcs),
                        "status": self._status(srcs), "confidence": round(conf, 3), "claims": claims})
        return out

    def rels(self, assessment_id: str | None = None) -> list[dict]:
        aid = assessment_id or self.current()["id"]
        out = []
        for r in self.db.execute("SELECT * FROM rel WHERE assessment_id=? ORDER BY first_seen", (aid,)).fetchall():
            claims = [dict(c) for c in self.db.execute(
                "SELECT c.source, c.confidence, c.ts, c.path, c.evidence_id, c.attrs, e.method, e.summary FROM rel_claim c "
                "JOIN evidence e ON e.id=c.evidence_id WHERE c.rel_id=? ORDER BY c.ts", (r["id"],)).fetchall()]
            srcs = {c["source"] for c in claims}
            tech_paths = {c["path"] for c in claims if c["source"] in TECHNICAL}
            asserted_paths = {c["path"] for c in claims if c["source"] == "describe"} - {"unknown"}
            status = self._status(srcs, tech_paths)
            contradicts = bool(asserted_paths and tech_paths - {"unknown"} and not (asserted_paths & tech_paths))
            if contradicts:
                status = "conflicted"
            observed_path = next(iter(tech_paths - {"unknown"}), None) if len(tech_paths - {"unknown"}) == 1 else None
            tech = [c["confidence"] for c in claims if c["source"] in TECHNICAL]
            conf = 1.0 - _prod(1 - c for c in tech) if tech else max((c["confidence"] for c in claims), default=0)
            out.append({**dict(r), "attrs": json.loads(r["attrs"]), "sources": sorted(srcs), "status": status,
                        "observed_path": observed_path, "asserted_paths": sorted(asserted_paths),
                        "assertion_contradicted": contradicts, "confidence": round(conf, 3),
                        "claims": [{**c, "attrs": json.loads(c["attrs"])} for c in claims]})
        return out

    def evidence(self, eid: str | None = None) -> list[dict]:
        aid = self.current()["id"]
        q = "SELECT id, source, method, collected_at, summary, digest" + (", raw" if eid else "") + " FROM evidence WHERE assessment_id=?"
        args: tuple = (aid,)
        if eid:
            q += " AND id=?"
            args = (aid, eid)
        return [dict(r) for r in self.db.execute(q + " ORDER BY collected_at", args).fetchall()]

    def counters(self) -> dict:
        aid = self.current()["id"]
        c = lambda t: self.db.execute(f"SELECT COUNT(*) FROM {t} WHERE assessment_id=?", (aid,)).fetchone()[0]
        by_src = {s: self.db.execute("SELECT COUNT(*) FROM evidence WHERE assessment_id=? AND source=?", (aid, s)).fetchone()[0]
                  for s in SOURCES}
        return {"assets": c("asset"), "relationships": c("rel"), "evidence": c("evidence"), "findings": c("finding"),
                "recommendations": c("recommendation"), "evidence_by_source": by_src}


def _prod(xs) -> float:
    p = 1.0
    for x in xs:
        p *= x
    return p
