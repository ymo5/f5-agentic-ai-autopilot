"""Regression (L3 live finding, 2026-10-15): an OWNER session was offered Deploy, the web API accepted it (role ladder),
an operation was created, and the privileged deployer refused it ("deployment must be requested by a human approver").
The deployer's exact-approver rule (two-person: owner opens the window, approver deploys) is unchanged; the web layer now
mirrors it — the action is not offered, the request is refused with a clear 403, audited, and creates no operation."""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import discover, review  # noqa: E402


def approve(ctx, pid):
    review(ctx, pid)
    assert ctx.ap.post(f"/api/packages/{pid}/decision", json={"decision": "approved", "comment": "t"}).status_code == 200


def _ops(ctx):
    from autopilot import web
    return web.STORE.db.execute("SELECT COUNT(*) FROM operation WHERE kind IN ('deploy','rollback','reset_demo')").fetchone()[0]


def test_owner_deploy_is_refused_up_front_with_a_clear_reason_and_no_operation(ctx):
    from autopilot import web
    ids = discover(ctx)
    approve(ctx, ids["delivery"])
    ops0, deps0 = _ops(ctx), web.STORE.db.execute("SELECT COUNT(*) FROM deployment").fetchone()[0]
    for path in (f"/api/ops/deploy/{ids['delivery']}", f"/api/packages/{ids['delivery']}/deploy"):
        r = ctx.owner.post(path, json={})
        assert r.status_code == 403 and "approver account" in r.json()["detail"] and "role 'owner'" in r.json()["detail"], r.text
    assert _ops(ctx) == ops0 and web.STORE.db.execute("SELECT COUNT(*) FROM deployment").fetchone()[0] == deps0
    assert not [c for c in ctx.bigip.calls if c[0] in ("POST", "DELETE")]                    # BIG-IP untouched
    acts = [(r["actor"], r["action"]) for r in ctx.ap.get("/api/audit").json()["rows"]]
    assert ("owner1", "deployment.refused") in acts


def test_lifecycle_does_not_offer_deploy_to_the_owner_but_does_to_the_approver(ctx):
    from autopilot import web
    ids = discover(ctx)
    approve(ctx, ids["delivery"])
    own = next(p for p in ctx.owner.get("/api/packages").json() if p["id"] == ids["delivery"])["lifecycle"]["actions"]["deploy"]
    apr = next(p for p in ctx.ap.get("/api/packages").json() if p["id"] == ids["delivery"])["lifecycle"]["actions"]["deploy"]
    assert own["allowed"] is False and own["reason"] == web.DEPLOY_ROLE_REASON
    assert apr["allowed"] is True


def test_approver_still_deploys_and_owner_cannot_roll_back_or_reset(ctx):
    ids = discover(ctx)
    approve(ctx, ids["delivery"])
    d = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()
    assert d["status"] == "succeeded" and d["mode"] == "mock"
    for path, body in ((f"/api/ops/rollback/{d['id']}", {}), (f"/api/deployments/{d['id']}/rollback", {}),
                       ("/api/ops/reset-demo", {"confirmation": "RESET DEMO ENVIRONMENT"})):
        r = ctx.owner.post(path, json=body)
        assert r.status_code == 403 and "approver account" in r.json()["detail"], (path, r.text)
    own = next(p for p in ctx.owner.get("/api/packages").json() if p["id"] == ids["delivery"])["lifecycle"]["actions"]["rollback"]
    assert own["allowed"] is False


def test_deployer_rule_itself_is_unchanged():
    src = (pathlib.Path(__file__).resolve().parents[1] / "autopilot" / "deployer" / "engine.py").read_text()
    assert src.count('if user.get("role") != "approver":') == 3                                # deploy, rollback, reset
