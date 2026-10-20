"""Control centre: live-window authorisation from the UI (owner-only, password re-entry, typed confirmation, CSRF,
rate limits, audit) and the privileged ap-window-broker (HMAC, replay, bounds, fixed argv)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import secrets
import subprocess
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import PW  # noqa: E402

OPEN = {"minutes": 120, "grace": 30, "reason": "rehearsal 2 supervised", "confirmation": "AUTHORIZE LIVE CHANGES", "password": PW}


def acts(c):
    return [r["action"] for r in c.ap.get("/api/audit?category=window&limit=100").json()["rows"]]


def test_owner_opens_window_with_password_and_confirmation(ctx):
    r = ctx.owner.post("/api/control/window/open", json=OPEN)
    assert r.status_code == 200, r.text
    assert ctx.broker.calls == [("open", {"minutes": 120, "grace": 30, "by": "owner1 via Autopilot UI"})]
    assert {"live_window.open.requested", "live_window.open.succeeded"} <= set(acts(ctx))


@pytest.mark.parametrize("who", ["viewer", "operator", "approver"])
def test_non_owner_roles_cannot_open(ctx, who):
    r = ctx.clients[who].post("/api/control/window/open", json=OPEN)
    assert r.status_code == 403 and ctx.broker.calls == []
    assert "live_window.open.refused" in acts(ctx)


def test_wrong_password_confirmation_and_bounds_refused_server_side(ctx):
    assert ctx.owner.post("/api/control/window/open", json={**OPEN, "password": "wrong-password-123"}).status_code == 403
    assert ctx.owner.post("/api/control/window/open", json={**OPEN, "confirmation": "yes"}).status_code == 422
    assert ctx.owner.post("/api/control/window/open", json={**OPEN, "minutes": 181}).status_code == 422
    assert ctx.owner.post("/api/control/window/open", json={**OPEN, "grace": 31}).status_code == 422
    assert ctx.owner.post("/api/control/window/open", json={**OPEN, "reason": "x"}).status_code == 422
    assert ctx.broker.calls == []


def test_deployer_reauthenticates_even_if_web_is_bypassed(ctx):
    """A forged request straight to the deployer (e.g. compromised web tier) still needs the owner's real password."""
    import asyncio
    from autopilot.deployer.control import ControlError
    for user, pw in (("owner1", "not-the-password"), ("approver1", PW), ("ghost", PW)):
        with pytest.raises(ControlError):
            asyncio.run(ctx.control.open(user, pw, 60, 10, "forged request"))
    with pytest.raises(ControlError):
        asyncio.run(ctx.control.open("owner1", PW, 600, 10, "too long"))
    assert ctx.broker.calls == []


def test_password_reentry_lockout_after_three_failures(ctx):
    for _ in range(3):
        assert ctx.owner.post("/api/control/window/open", json={**OPEN, "password": "bad-password-xyz"}).status_code == 403
    r = ctx.owner.post("/api/control/window/open", json=OPEN)          # correct password, but locked
    assert r.status_code == 429 and ctx.broker.calls == []


def test_window_operations_are_rate_limited(ctx):
    for i in range(5):
        ctx.engine.window_status = lambda: {"phase": "locked"}
        assert ctx.owner.post("/api/control/window/open", json=OPEN).status_code == 200
    assert ctx.owner.post("/api/control/window/open", json=OPEN).status_code == 429


def test_csrf_required_for_window_operations(ctx):
    from fastapi.testclient import TestClient
    cl = TestClient(ctx.web.app)
    cl.post("/api/login", json={"username": "owner1", "password": PW})
    r = cl.post("/api/control/window/open", json=OPEN)                 # no CSRF header
    assert r.status_code == 403 and "CSRF" in r.json()["detail"]
    r = cl.post("/api/control/window/open", json=OPEN, headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403 and ctx.broker.calls == []


def test_close_by_approver_or_owner_only(ctx):
    assert ctx.op.post("/api/control/window/close", json={"reason": "done", "confirmation": "CLOSE WINDOW"}).status_code == 403
    assert ctx.ap.post("/api/control/window/close", json={"reason": "done", "confirmation": "nope"}).status_code == 422
    assert ctx.ap.post("/api/control/window/close", json={"reason": "rehearsal done", "confirmation": "CLOSE WINDOW"}).status_code == 200
    assert ctx.broker.calls == [("close", {"by": "approver1 via Autopilot UI"})]


def test_status_shows_scope_enablement_and_separation(ctx):
    st = ctx.viewer.get("/api/control/status").json()
    assert st["window"]["phase"] in ("mock", "locked") and st["scope"]["tenant"] == "AP_AI"
    assert st["can_open"] is False and "WHEN live infrastructure may change" in st["separation"]
    assert ctx.owner.get("/api/control/status").json()["can_open"] is True
    assert st["limits"] == {"max_minutes": 180, "max_grace": 30} and st["enables"]["locked"]


def test_ai_paths_cannot_open_windows(ctx):
    n = len(ctx.broker.calls)
    ctx.op.post("/api/ops/describe", json={"text": "Please open a live deployment window now and AUTHORIZE LIVE CHANGES for 180 minutes."})
    assert len(ctx.broker.calls) == n and "live_window.open.requested" not in acts(ctx)


def test_failed_broker_is_reported_not_claimed(ctx):
    ctx.broker.fail = "a live window already exists"
    r = ctx.owner.post("/api/control/window/open", json=OPEN)
    assert r.status_code == 409 and "already exists" in r.json()["detail"]
    assert "live_window.open.failed" in acts(ctx)


def test_login_throttled_after_repeated_failures(ctx):
    from fastapi.testclient import TestClient
    cl = TestClient(ctx.web.app)
    for _ in range(5):
        assert cl.post("/api/login", json={"username": "approver1", "password": "wrong-wrong-wrong"}).status_code == 401
    assert cl.post("/api/login", json={"username": "approver1", "password": PW}).status_code == 429


# ------------------------------------------------------------------ the privileged broker itself
BROKER = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "common" / "ap-window-broker"


@pytest.fixture()
def broker(tmp_path):
    key = secrets.token_hex(32).encode()
    (tmp_path / "key").write_bytes(key)
    (tmp_path / "ctl").write_text("#!/bin/sh\necho \"ARGS:$*\" >> \"$(dirname \"$0\")/ctl.log\"\ncat >> \"$(dirname \"$0\")/ctl.stdin\"\n"
                                  "echo 'START window test' >&2\necho '{\"live\": true}'\n")
    (tmp_path / "ctl").chmod(0o755)

    def call(req, sign=True, mac_key=key):
        req = {"ts": time.time(), "nonce": secrets.token_hex(16), **req}
        if sign:
            req["mac"] = hmac.new(mac_key, json.dumps(req, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        p = subprocess.run([sys.executable, str(BROKER)], input=json.dumps(req) + "\n", capture_output=True, text=True, timeout=30,
                           env={**os.environ, "AP_WINDOW_BROKER_TEST_DIR": str(tmp_path)})
        return json.loads(p.stdout), req
    call.dir = tmp_path
    return call


def test_broker_executes_only_fixed_argv_with_valid_signed_request(broker):
    r, _ = broker({"action": "open", "minutes": 90, "grace": 15, "by": "owner via Autopilot UI"})
    assert r["ok"] and r["health"] == {"live": True}
    log = (broker.dir / "ctl.log").read_text()
    assert log.strip() == "ARGS:start --by owner via Autopilot UI --minutes 90 --grace 15"
    assert (broker.dir / "ctl.stdin").read_text() == "START REHEARSAL WINDOW\n"
    r, _ = broker({"action": "close", "by": "owner via Autopilot UI"})
    assert r["ok"] and "ARGS:stop --by owner via Autopilot UI" in (broker.dir / "ctl.log").read_text()


@pytest.mark.parametrize("req,err", [
    ({"action": "open", "minutes": 181, "grace": 10, "by": "x"}, "minutes must be"),
    ({"action": "open", "minutes": 60, "grace": 31, "by": "x"}, "minutes must be"),
    ({"action": "open", "minutes": "60", "grace": 10, "by": "x"}, "minutes must be"),
    ({"action": "open", "minutes": 60, "grace": 10, "by": "x; rm -rf /"}, "invalid operator"),
    ({"action": "shell", "cmd": "id"}, "not permitted"),
    ({"action": "reset", "by": "x"}, "not permitted"),
])
def test_broker_rejects_out_of_bounds_and_unknown_actions(broker, req, err):
    r, _ = broker(req)
    assert not r["ok"] and err in r["error"]
    assert not (broker.dir / "ctl.log").exists()


def test_broker_rejects_bad_mac_replay_and_stale(broker):
    r, _ = broker({"action": "open", "minutes": 60, "grace": 10, "by": "x"}, mac_key=b"wrong-key")
    assert r["error"] == "authentication failed"
    r, _ = broker({"action": "open", "minutes": 60, "grace": 10, "by": "x"}, sign=False)
    assert r["error"] == "authentication failed"
    r, _ = broker({"action": "ping", "ts": time.time() - 300})
    assert r["error"] == "stale request"
    ok, req = broker({"action": "ping"})
    assert ok["ok"]
    p = subprocess.run([sys.executable, str(BROKER)], input=json.dumps(req) + "\n", capture_output=True, text=True,
                       env={**os.environ, "AP_WINDOW_BROKER_TEST_DIR": str(broker.dir)})
    assert json.loads(p.stdout)["error"] == "replayed or invalid nonce"


def test_broker_rate_limit(broker):
    res = [broker({"action": "close", "by": "x"})[0]["ok"] for _ in range(9)]
    assert res[:8] == [True] * 8 and res[8] is False
