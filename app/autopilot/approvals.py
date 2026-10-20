"""Hash-bound human approvals.

An approval binds: assessment id, package id, SHA-256 of the canonical package content (configuration +
dependency plan + target), target device, the device-state fingerprint seen at approval time, approver
identity/role, decision and expiry. Deployment requires a *valid* approval:
  * decision == approved, by a human with role 'approver' (recorded from the authenticated session);
  * not expired, not consumed, not superseded;
  * package content hash recomputed at deploy time == approved hash (any modification => re-approval);
  * device fingerprint at deploy time == fingerprint approved (device drift => re-approval).
Rejected packages and packages with "changes requested" can never deploy.

Lifecycle (v2): an approval can only be recorded when
  * no other approval for the package is still active (no duplicates — enforced here, not only in the UI);
  * the package has no successful, un-rolled-back deployment;
  * a Preview/diff/preflight review of exactly this package hash against the current device fingerprint passed within
    the last REVIEW_TTL seconds — and, after a failed deployment, that review is newer than the failure
    (Review failure -> correct -> revalidate -> new approval -> retry). Consumed approvals are never reusable.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS approval (id TEXT PRIMARY KEY, assessment_id TEXT, package_id TEXT, package_hash TEXT,
  target TEXT, device_fingerprint TEXT, decision TEXT, approver TEXT, role TEXT, comment TEXT, created REAL,
  expires REAL, consumed_by TEXT);
CREATE TABLE IF NOT EXISTS deployment (id TEXT PRIMARY KEY, assessment_id TEXT, package_id TEXT, approval_id TEXT,
  package_hash TEXT, status TEXT, mode TEXT, requested_by TEXT, started REAL, finished REAL, steps TEXT,
  previous_state TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS package_review (id TEXT PRIMARY KEY, package_id TEXT, package_hash TEXT, device_fingerprint TEXT,
  ok INTEGER, checks TEXT, reviewer TEXT, created REAL);
"""
DEFAULT_TTL = 7200
REVIEW_TTL = 1800
FAILED = ("failed-rolled-back", "failed-rollback-failed", "failed-rolled-back-unverified", "failed-no-changes",
          "refused-preflight", "refused-window-closed", "failed")


class ApprovalError(Exception):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def package_hash(pkg: dict) -> str:
    """Hash of everything that determines what will be executed."""
    return hashlib.sha256(canonical({"kind": pkg["kind"], "target": pkg["target"], "body": pkg["body"]})).hexdigest()


def record_review(db, pkg: dict, device_fingerprint: str, checks: list[dict], reviewer: str) -> dict:
    r = {"id": uuid.uuid4().hex[:16], "package_id": pkg["id"], "package_hash": package_hash(pkg), "device_fingerprint": device_fingerprint,
         "ok": int(bool(checks) and all(c["ok"] for c in checks)), "checks": json.dumps(checks, default=str), "reviewer": reviewer,
         "created": time.time()}
    db.execute("INSERT INTO package_review VALUES (:id,:package_id,:package_hash,:device_fingerprint,:ok,:checks,:reviewer,:created)", r)
    return {**r, "checks": checks}


def latest_review(db, package_id: str) -> dict | None:
    r = db.execute("SELECT * FROM package_review WHERE package_id=? ORDER BY created DESC LIMIT 1", (package_id,)).fetchone()
    return {**dict(r), "checks": json.loads(r["checks"])} if r else None


def active(db, package_id: str, now: float | None = None, pkg_hash: str | None = None) -> dict | None:
    """The package's currently usable approval, if any (latest decision approved, unused, unexpired, and — when the
    current package hash is given — bound to that exact content)."""
    a = latest(db, package_id)
    if a and a["decision"] == "approved" and not a["consumed_by"] and (now or time.time()) <= a["expires"] \
            and (pkg_hash is None or a["package_hash"] == pkg_hash):
        return a
    return None


def deployments(db, package_id: str) -> list[dict]:
    return [dict(r) for r in db.execute("SELECT id, status, started, finished FROM deployment WHERE package_id=? ORDER BY started", (package_id,))]


def record(db, *, assessment_id: str, pkg: dict, device_fingerprint: str, decision: str, user: dict,
           comment: str = "", ttl: int = DEFAULT_TTL, now: float | None = None) -> dict:
    now = now or time.time()
    if decision not in ("approved", "rejected", "changes_requested"):
        raise ApprovalError("bad decision")
    if decision == "approved" and user.get("role") != "approver":
        raise ApprovalError("only a human with the approver role can approve")
    if decision == "approved" and pkg.get("validation", {}).get("valid") is False:
        raise ApprovalError("package failed validation")
    if decision == "approved":
        act = active(db, pkg["id"], now, package_hash(pkg))
        if act:
            raise ApprovalError(f"already approved by {act['approver']} (approval {act['id']}, expires "
                                f"{time.strftime('%H:%M UTC', time.gmtime(act['expires']))}) — duplicate approvals are not recorded")
        deps = deployments(db, pkg["id"])
        if any(d["status"] in ("running", "succeeded") for d in deps):
            raise ApprovalError("package already has a running or successful deployment — no new approval needed")
        rv = latest_review(db, pkg["id"])
        if not rv:
            raise ApprovalError("run 'Preview, diff & preflight' before approving")
        if rv["package_hash"] != package_hash(pkg):
            raise ApprovalError("the package changed since its last preflight — re-run 'Preview, diff & preflight'")
        if rv["device_fingerprint"] != device_fingerprint:
            raise ApprovalError("device state changed since the last preflight — re-run 'Preview, diff & preflight'")
        if now - rv["created"] > REVIEW_TTL:
            raise ApprovalError(f"the last preflight is older than {REVIEW_TTL // 60} minutes — re-run 'Preview, diff & preflight'")
        if not rv["ok"]:
            failed = [c["check"] for c in rv["checks"] if not c["ok"]]
            raise ApprovalError(f"preflight did not pass ({', '.join(failed)}) — correct the cause and re-run preflight")
        last_fail = max((d["finished"] or d["started"] for d in deps if d["status"] in FAILED), default=0)
        if rv["created"] < last_fail:
            raise ApprovalError("a deployment of this package failed after the last preflight — review the failure, "
                                "re-run 'Preview, diff & preflight', then approve again")
    a = {"id": uuid.uuid4().hex[:16], "assessment_id": assessment_id, "package_id": pkg["id"],
         "package_hash": package_hash(pkg), "target": pkg["target"], "device_fingerprint": device_fingerprint,
         "decision": decision, "approver": user["username"], "role": user["role"], "comment": comment[:500],
         "created": now, "expires": now + ttl, "consumed_by": None}
    db.execute("INSERT INTO approval VALUES (:id,:assessment_id,:package_id,:package_hash,:target,:device_fingerprint,"
               ":decision,:approver,:role,:comment,:created,:expires,:consumed_by)", a)
    return a


def latest(db, package_id: str) -> dict | None:
    r = db.execute("SELECT * FROM approval WHERE package_id=? ORDER BY created DESC LIMIT 1", (package_id,)).fetchone()
    return dict(r) if r else None


def verify(db, approval_id: str, pkg: dict, device_fingerprint: str, now: float | None = None) -> dict:
    """Raise ApprovalError unless approval_id authorises deploying exactly `pkg` to the device as it is now."""
    now = now or time.time()
    r = db.execute("SELECT * FROM approval WHERE id=?", (approval_id,)).fetchone()
    if not r:
        raise ApprovalError("approval not found")
    a = dict(r)
    newest = latest(db, a["package_id"])
    if newest and newest["id"] != a["id"]:
        raise ApprovalError(f"superseded by a later decision ({newest['decision']})")
    if a["decision"] != "approved":
        raise ApprovalError(f"package was {a['decision']}, not approved")
    if a["role"] != "approver":
        raise ApprovalError("approval not made by an approver")
    if a["package_id"] != pkg["id"]:
        raise ApprovalError("approval is for a different package")
    if a["consumed_by"]:
        raise ApprovalError(f"approval already used by deployment {a['consumed_by']}")
    if now > a["expires"]:
        raise ApprovalError("approval expired")
    if package_hash(pkg) != a["package_hash"]:
        raise ApprovalError("package content changed since approval (hash mismatch) — re-approval required")
    if a["target"] != pkg["target"]:
        raise ApprovalError("target device changed since approval")
    if device_fingerprint != a["device_fingerprint"]:
        raise ApprovalError("device state changed since approval (fingerprint mismatch) — re-approval required")
    return a


def consume(db, approval_id: str, deployment_id: str) -> None:
    cur = db.execute("UPDATE approval SET consumed_by=? WHERE id=? AND consumed_by IS NULL", (deployment_id, approval_id))
    if cur.rowcount != 1:
        raise ApprovalError("approval could not be consumed (race or reuse)")


def revoke(db, approval_id: str, actor: str, reason: str) -> dict:
    """Supersede an unused approval with a 'revoked' decision. The original row (and the audit log) are preserved."""
    r = db.execute("SELECT * FROM approval WHERE id=?", (approval_id,)).fetchone()
    if not r:
        raise ApprovalError("approval not found")
    a = dict(r)
    if a["decision"] != "approved" or a["consumed_by"]:
        raise ApprovalError("only an unused 'approved' decision can be revoked")
    newest = latest(db, a["package_id"])
    if newest["id"] != a["id"]:
        raise ApprovalError(f"already superseded by a later decision ({newest['decision']})")
    now = time.time()
    rv = {**a, "id": uuid.uuid4().hex[:16], "decision": "revoked", "approver": actor, "role": "maintenance",
          "comment": f"revokes {approval_id}: {reason}"[:500], "created": max(now, a["created"] + 1e-3), "expires": now, "consumed_by": None}
    db.execute("INSERT INTO approval VALUES (:id,:assessment_id,:package_id,:package_hash,:target,:device_fingerprint,"
               ":decision,:approver,:role,:comment,:created,:expires,:consumed_by)", rv)
    return rv


if __name__ == "__main__":  # maintenance: python -m autopilot.approvals revoke <approval_id> <actor> <reason...>
    import os
    import sys

    from .store import Store
    if len(sys.argv) < 5 or sys.argv[1] != "revoke":
        sys.exit("usage: python -m autopilot.approvals revoke <approval_id> <actor> <reason>")
    st = Store(os.environ.get("AUTOPILOT_DB", "/var/lib/autopilot/autopilot.db"))
    rv = revoke(st.db, sys.argv[2], sys.argv[3], " ".join(sys.argv[4:]))
    st.audit(sys.argv[3], "approval.revoked", rv["assessment_id"], {"approval": sys.argv[2], "revocation": rv["id"],
                                                                     "package": rv["package_id"], "hash": rv["package_hash"], "reason": rv["comment"]})
    print(json.dumps({k: rv[k] for k in ("id", "package_id", "decision", "approver", "comment")}))
