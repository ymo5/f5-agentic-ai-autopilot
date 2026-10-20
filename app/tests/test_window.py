"""Time-bounded live window (Part B rehearsal): fail-closed expiry, cleanup grace, restart/tamper safety, revocation.

Real engine/approvals/policy/window code against the mock BIG-IP/host executors; the clock is injected.
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import discover, review  # noqa: E402

T0 = 1_800_000_000.0
H = 3600
AP = {"username": "approver1", "role": "approver"}


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture()
def win(ctx, tmp_path):
    from autopilot.deployer.engine import Engine
    from autopilot.deployer.window import Window
    w = type("W", (), {})()
    w.path, w.clock = tmp_path / "window.json", Clock()

    def write(**kw):
        d = {"window_id": "w1", "issued": T0, "not_after": T0 + 3 * H, "cleanup_until": T0 + 3 * H + 1800, "mode": "live",
             "authorized_by": "owner", "purpose": "test"}
        d.update(kw)
        w.path.write_text(d if isinstance(d, str) else json.dumps(d))

    def engine():
        async def validator(profile):
            return [{"test": "mock.gate", "result": ctx.gate["result"], "observed": {"profile": profile}, "expected": "pass"}]
        return Engine(ctx.web.STORE, ctx.bigip, ctx.hosts, validator, window=Window(str(w.path), ctx.web.STORE.db, clock=w.clock))
    w.write, w.engine = write, engine
    w.eng = None
    return w


def run(coro):
    return asyncio.run(coro)


def writes(c, since=0):
    return [x for x in c.bigip.calls[since:] if x[0] in ("POST", "DELETE")]


def host_writes(c, since=0):
    return [x for x in c.hosts.calls[since:] if x[1] != "status"]


def approved(ctx, kind="delivery"):
    ids = discover(ctx)
    review(ctx, ids[kind])
    assert ctx.ap.post(f"/api/packages/{ids[kind]}/decision", json={"decision": "approved", "comment": "t"}).status_code == 200
    pkg = ctx.web._pkg(ids[kind])
    return ids, pkg, ctx.web.approvals.latest(ctx.web.STORE.db, ids[kind])


def approve(ctx, pid):
    review(ctx, pid)
    assert ctx.ap.post(f"/api/packages/{pid}/decision", json={"decision": "approved", "comment": "t"}).status_code == 200
    return ctx.web._pkg(pid), ctx.web.approvals.latest(ctx.web.STORE.db, pid)


def audits(ctx):
    return [r["action"] for r in ctx.web.STORE.db.execute("SELECT action FROM audit ORDER BY seq")]


# ------------------------------------------------------------------ fail closed
@pytest.mark.parametrize("setup,reason", [
    (lambda w: None, "no live window authorised"),
    (lambda w: w.path.write_text("{not json"), "unreadable/invalid"),
    (lambda w: w.path.write_text(json.dumps({"window_id": "w1", "issued": T0})), "missing required fields"),
    (lambda w: w.write(not_after="soon"), "not numbers"),
    (lambda w: w.write(mode="forever"), "id/mode invalid"),
    (lambda w: w.write(not_after=T0 + 3 * H + 1, cleanup_until=T0 + 3 * H + 1), "exceeds the 3 hour maximum"),
    (lambda w: w.write(cleanup_until=T0 + 3 * H + 1801), "exceeds the 30 minute maximum"),
    (lambda w: w.write(issued=T0 + 600, not_after=T0 + 2 * H, cleanup_until=T0 + 2 * H), "issued in the future"),
])
def test_missing_invalid_or_oversized_window_refused(ctx, win, setup, reason):
    setup(win)
    eng = win.engine()
    _, pkg, a = approved(ctx)
    from autopilot.deployer.engine import DeploymentRefused
    with pytest.raises(DeploymentRefused, match="locked"):
        run(eng.deploy(pkg, a["id"], AP))
    assert reason in eng.window_status()["reason"]
    assert writes(ctx) == [] and host_writes(ctx) == []
    assert a["consumed_by"] is None and ctx.web.approvals.latest(ctx.web.STORE.db, pkg["id"])["consumed_by"] is None
    assert "deploy.refused" in audits(ctx) and "deployment.refused" in audits(ctx)


def test_valid_window_requires_normal_human_approval(ctx, win):
    from autopilot.deployer.engine import DeploymentRefused
    win.write()
    eng = win.engine()
    ids = discover(ctx)
    pkg = ctx.web._pkg(ids["delivery"])
    with pytest.raises(DeploymentRefused, match="not found"):                       # no approval
        run(eng.deploy(pkg, "nope", AP))
    with pytest.raises(DeploymentRefused, match="approver"):                        # operator cannot deploy
        run(eng.deploy(pkg, "nope", {"username": "se1", "role": "operator"}))
    pkg, a = approve(ctx, ids["delivery"])
    d = run(eng.deploy(pkg, a["id"], AP))
    assert d["status"] == "succeeded" and d["mode"] == "live"
    steps = [s["step"] for s in d["steps"]]
    assert steps.index("window.check[before first write]") < steps.index("as3.deploy")
    with pytest.raises(DeploymentRefused, match="already used"):                    # single use
        run(eng.deploy(pkg, a["id"], AP))


def test_expired_approval_refused_inside_valid_window(ctx, win):
    from autopilot.deployer.engine import DeploymentRefused
    win.write()
    eng = win.engine()
    _, pkg, a = approved(ctx)
    ctx.web.STORE.db.execute("UPDATE approval SET expires=1 WHERE id=?", (a["id"],))
    with pytest.raises(DeploymentRefused, match="expired"):
        run(eng.deploy(pkg, a["id"], AP))
    assert writes(ctx) == []


def test_tampered_package_or_device_drift_refused_inside_window(ctx, win):
    from autopilot.deployer.engine import DeploymentRefused
    win.write()
    eng = win.engine()
    _, pkg, a = approved(ctx)
    bad = json.loads(json.dumps(pkg))
    bad["body"]["dependencies"] = []
    with pytest.raises(DeploymentRefused, match="hash mismatch"):
        run(eng.deploy(bad, a["id"], AP))
    ctx.hosts.profile["ap-agent-a"] = "delivery"
    with pytest.raises(DeploymentRefused, match="fingerprint mismatch"):
        run(eng.deploy(pkg, a["id"], AP))
    assert writes(ctx) == []


# ------------------------------------------------------------------ expiry
@pytest.mark.parametrize("t", [T0 + 3 * H, T0 + 3 * H + 900, T0 + 3 * H + 1800, T0 + 10 * H])
def test_no_deployment_after_expiry(ctx, win, t):
    from autopilot.deployer.engine import DeploymentRefused
    win.write()
    eng = win.engine()
    _, pkg, a = approved(ctx)
    win.clock.t = t
    with pytest.raises(DeploymentRefused, match="locked"):
        run(eng.deploy(pkg, a["id"], AP))
    assert writes(ctx) == [] and host_writes(ctx) == []


def test_expiry_rechecked_immediately_before_first_write(ctx, win):
    win.write()
    eng = win.engine()
    _, pkg, a = approved(ctx)
    orig = eng._preflight_step

    async def slow_preflight(*args):
        r = await orig(*args)
        win.clock.t = T0 + 3 * H + 1           # window expires while preflight is running
        return r
    eng._preflight_step = slow_preflight
    d = run(eng.deploy(pkg, a["id"], AP))
    assert d["status"] == "refused-window-closed"
    assert writes(ctx) == [] and host_writes(ctx) == []                  # no dry-run, no deploy, no rollback write
    assert "rollback" not in [s["step"] for s in d["steps"]]
    assert "deploy.refused" in audits(ctx)


def test_in_progress_deployment_completes_including_automatic_rollback(ctx, win):
    win.write()
    eng = win.engine()
    _, pkg, a = approved(ctx)
    orig = ctx.bigip.as3_post

    async def post(decl):
        if decl["action"] == "deploy":
            win.clock.t = T0 + 3 * H + 1800 + 5      # window AND cleanup grace end mid-deployment
        return await orig(decl)
    ctx.bigip.as3_post = post
    ctx.gate["result"] = "fail"
    d = run(eng.deploy(pkg, a["id"], AP))
    st = {s["step"]: s["status"] for s in d["steps"]}
    assert d["status"] == "failed-rolled-back" and st["as3.deploy"] == "ok" and st["rollback"] == "ok"
    assert ctx.bigip.tenant is None and set(ctx.hosts.profile.values()) == {"baseline"}
    assert eng._inflight == 0


def test_in_flight_gate_may_use_replica_actions_but_external_callers_may_not(ctx, win):
    from autopilot.deployer.engine import DeploymentRefused
    win.write()
    eng = win.engine()
    win.clock.t = T0 + 3 * H + 1800 + 1
    with pytest.raises(DeploymentRefused, match="locked"):
        run(eng.validation_action({"action": "replica", "op": "stop", "n": 1}))
    with pytest.raises(DeploymentRefused, match="locked"):
        run(eng.validation_action({"action": "replica", "op": "stop", "n": 1}, internal=True))   # nothing in flight
    eng._inflight = 1
    run(eng.validation_action({"action": "replica", "op": "stop", "n": 1}, internal=True))
    eng._inflight = 0
    assert "replica_stop.refused" in audits(ctx)


# ------------------------------------------------------------------ cleanup grace
def _deploy_both(ctx, eng):
    ids = discover(ctx)
    pkg, a = approve(ctx, ids["delivery"])
    dd = run(eng.deploy(pkg, a["id"], AP))
    pkg, a = approve(ctx, ids["security"])
    ds = run(eng.deploy(pkg, a["id"], AP))
    assert dd["status"] == ds["status"] == "succeeded"
    return dd, ds


def test_rollback_in_cleanup_grace_only_to_verified_states(ctx, win):
    from autopilot.deployer.engine import DeploymentRefused
    win.write()
    eng = win.engine()
    dd, ds = _deploy_both(ctx, eng)
    win.clock.t = T0 + 3 * H + 60                                     # cleanup grace
    assert eng.window_status()["phase"] == "cleanup"
    run(eng.rollback(ds["id"], AP))                                    # security -> verified delivery state
    assert set(ctx.hosts.profile.values()) == {"delivery"}
    with pytest.raises(DeploymentRefused, match="cleanup grace"):     # already rolled back: no longer 'succeeded'
        run(eng.rollback(ds["id"], AP))
    run(eng.rollback(dd["id"], AP))                                    # delivery -> baseline
    assert ctx.bigip.tenant is None and set(ctx.hosts.profile.values()) == {"baseline"}
    # a deployment whose previous state was never verified cannot be a cleanup rollback target
    ctx.web.STORE.db.execute("UPDATE deployment SET status='succeeded', previous_state=? WHERE id=?",
                             (json.dumps({"tenant": {"x": 1}, "hosts": {"ap-agent-a": "security"}}), dd["id"]))
    n = len(ctx.bigip.calls)
    with pytest.raises(DeploymentRefused, match="cleanup grace"):
        run(eng.rollback(dd["id"], AP))
    assert writes(ctx, n) == []
    assert "rollback.refused" in audits(ctx)


def test_failed_deployment_cannot_be_rolled_back_in_cleanup(ctx, win):
    from autopilot.deployer.engine import DeploymentRefused
    win.write()
    eng = win.engine()
    _, pkg, a = approved(ctx)
    ctx.gate["result"] = "fail"
    d = run(eng.deploy(pkg, a["id"], AP))
    assert d["status"] == "failed-rolled-back"
    win.clock.t = T0 + 3 * H + 60
    with pytest.raises(DeploymentRefused, match="cleanup grace"):
        run(eng.rollback(d["id"], AP))


def test_reset_demo_in_cleanup_grace_restores_approved_baseline_only(ctx, win):
    from autopilot.deployer import policy
    from autopilot.deployer.engine import DeploymentRefused
    win.write()
    eng = win.engine()
    _deploy_both(ctx, eng)
    win.clock.t = T0 + 3 * H + 1799
    with pytest.raises(DeploymentRefused):
        run(eng.reset_demo(AP, "yes"))
    n, m = len(ctx.bigip.calls), len(ctx.hosts.calls)
    r = run(eng.reset_demo(AP, "RESET DEMO ENVIRONMENT"))
    assert r["ok"] and ctx.bigip.tenant is None and set(ctx.hosts.profile.values()) == {"baseline"}
    assert writes(ctx, n) == [("DELETE", "tenant")]
    assert {c for _, c in host_writes(ctx, m)} <= {"profile baseline", "replica start 1", "replica start 2"}
    assert {h for h, _ in ctx.hosts.calls[m:]} <= set(policy.HOSTS)
    # cleanup grace permits replica start (baseline) but not replica stop
    run(eng.validation_action({"action": "replica", "op": "start", "n": 2}))
    with pytest.raises(DeploymentRefused, match="locked"):
        run(eng.validation_action({"action": "replica", "op": "stop", "n": 2}))


def test_all_writes_refused_after_cleanup_grace(ctx, win):
    from autopilot.deployer.engine import DeploymentRefused
    win.write()
    eng = win.engine()
    dd, ds = _deploy_both(ctx, eng)
    pkg, a = approve(ctx, discover(ctx)["delivery"])
    win.clock.t = T0 + 3 * H + 1800
    n, m = len(ctx.bigip.calls), len(ctx.hosts.calls)
    for coro in (eng.deploy(pkg, a["id"], AP), eng.rollback(ds["id"], AP), eng.rollback(dd["id"], AP),
                 eng.reset_demo(AP, "RESET DEMO ENVIRONMENT"),
                 eng.validation_action({"action": "replica", "op": "stop", "n": 1}),
                 eng.validation_action({"action": "replica", "op": "start", "n": 1})):
        with pytest.raises(DeploymentRefused, match="locked"):
            run(coro)
    assert writes(ctx, n) == [] and host_writes(ctx, m) == []
    acts = audits(ctx)
    for ev in ("deploy.refused", "rollback.refused", "reset_demo.refused", "replica_stop.refused", "replica_start.refused"):
        assert ev in acts, ev


def test_timer_cleanup_mode_ends_live_phase_early(ctx, win):
    """The backup timer rewrites mode=cleanup at expiry; that alone stops deployments even if the clock disagreed."""
    from autopilot.deployer.engine import DeploymentRefused
    win.write(mode="cleanup")
    eng = win.engine()
    _, pkg, a = approved(ctx)
    assert eng.window_status()["phase"] == "cleanup"
    with pytest.raises(DeploymentRefused, match="locked"):
        run(eng.deploy(pkg, a["id"], AP))
    win.path.unlink()                                                   # timer close / manual stop
    assert eng.window_status()["phase"] == "locked"


# ------------------------------------------------------------------ restart / tamper / audit
def test_restart_cannot_extend_window(ctx, win):
    win.write()
    e1 = win.engine()
    assert e1.window_status()["phase"] == "live"
    win.clock.t = T0 + 3 * H + 1800 + 1
    e2 = win.engine()                                                   # "container restart": new engine, same file
    assert e2.window_status()["phase"] == "locked"
    win.write(issued=T0 + 3 * H, not_after=T0 + 6 * H, cleanup_until=T0 + 6 * H)   # same id, extended
    e3 = win.engine()
    st = e3.window_status()
    assert st["phase"] == "locked" and "tampered" in st["reason"]


def test_window_transitions_audited(ctx, win):
    win.write()
    eng = win.engine()
    store = ctx.web.STORE
    eng.window.transition(store.audit)
    win.clock.t = T0 + 3 * H
    eng.window.transition(store.audit)
    eng.window.transition(store.audit)                                  # no duplicate events
    win.clock.t = T0 + 3 * H + 1800
    eng.window.transition(store.audit)
    acts = [a for a in audits(ctx) if a.startswith("live_window.")]
    assert acts == ["live_window.opened", "live_window.expired", "live_window.closed"]


def test_window_file_removed_audited_as_closed(ctx, win):
    win.write()
    eng = win.engine()
    eng.window.transition(ctx.web.STORE.audit)
    win.path.unlink()
    eng.window.transition(ctx.web.STORE.audit)
    assert [a for a in audits(ctx) if a.startswith("live_window.")] == ["live_window.opened", "live_window.closed"]


# ------------------------------------------------------------------ approval revocation
def test_revoked_approval_cannot_deploy_and_history_is_preserved(ctx, win):
    from autopilot import approvals
    from autopilot.deployer.engine import DeploymentRefused
    win.write()
    eng = win.engine()
    _, pkg, a = approved(ctx)
    rv = approvals.revoke(ctx.web.STORE.db, a["id"], "maintenance", "test")
    with pytest.raises(DeploymentRefused, match="revoked"):
        run(eng.deploy(pkg, a["id"], AP))
    rows = ctx.web.STORE.db.execute("SELECT id, decision FROM approval WHERE package_id=? ORDER BY created", (pkg["id"],)).fetchall()
    assert [(r[0], r[1]) for r in rows] == [(a["id"], "approved"), (rv["id"], "revoked")]
    with pytest.raises(approvals.ApprovalError):
        approvals.revoke(ctx.web.STORE.db, a["id"], "maintenance", "again")
    assert writes(ctx) == []


def test_invalid_or_tampered_window_audited_once(ctx, win):
    from autopilot.deployer.window import Window
    win.write()
    w = Window(str(win.path), ctx.web.STORE.db, clock=win.clock, audit=ctx.web.STORE.audit)
    assert w.status()["phase"] == "live"
    win.write(not_after=T0 + 3 * H - 60)                                  # same id, times changed
    for _ in range(3):
        assert w.status()["phase"] == "locked"
    win.path.write_text("garbage")
    w.status()
    assert [a for a in audits(ctx) if a == "live_window.invalid"] == ["live_window.invalid"] * 2
