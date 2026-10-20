"""First-run administrator bootstrap and account boundaries (offline).

Covers: fresh install (no accounts, no default password), bootstrap of the first owner through the local CLI, successful
login, wrong-password rejection, role assignment, refusal of every later / remote account creation, persistence across a
process restart, secrets never printed, and the unchanged approval / deployment separation of duties.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import threading
import pathlib

import pytest

from conftest import CFG, SCHEMA, discover, review

APP = pathlib.Path(__file__).resolve().parents[1]
GOOD = "correct-horse-battery-staple-42"


def _cli(db, *args, stdin=""):
    env = {**os.environ, "AUTOPILOT_DB": str(db), "PYTHONPATH": str(APP)}
    return subprocess.run([sys.executable, "-B", "-m", "autopilot.auth", *args], input=stdin, env=env,
                          capture_output=True, text=True, timeout=60)


def _web(tmp_path, monkeypatch, db):
    """A fresh web application process state on the given database (simulates a service start)."""
    monkeypatch.setenv("AUTOPILOT_CONFIG", str(CFG))
    monkeypatch.setenv("AUTOPILOT_DB", str(db))
    monkeypatch.setenv("AUTOPILOT_SNAPSHOTS", str(tmp_path / "snaps"))
    monkeypatch.setenv("AS3_SCHEMA", str(SCHEMA))
    monkeypatch.setenv("AUTOPILOT_SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("LLM_PROVIDER", "none")
    for m in [k for k in sys.modules if k.startswith("autopilot")]:
        del sys.modules[m]
    from fastapi.testclient import TestClient
    from autopilot import web
    return web, TestClient(web.app)


# 1. fresh installation -------------------------------------------------------------------------------------------------
def test_fresh_install_has_no_accounts_and_no_default_login(tmp_path, monkeypatch):
    db = tmp_path / "fresh.db"
    web, c = _web(tmp_path, monkeypatch, db)
    assert web.STORE.db.execute("SELECT name FROM sqlite_master WHERE name='users'").fetchone() is None or \
        web.STORE.db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    for u, p in (("admin", "admin"), ("admin", "password"), ("owner", "owner"), ("root", "")):
        assert c.post("/api/login", json={"username": u, "password": p}).status_code == 401
    assert c.get("/api/me").status_code == 401


# 2. administrator creation ---------------------------------------------------------------------------------------------
def test_bootstrap_creates_one_owner_with_a_hashed_password(tmp_path):
    db = tmp_path / "ap.db"
    r = _cli(db, "bootstrap", "alice", stdin=GOOD + "\n")
    assert r.returncode == 0, r.stderr
    assert GOOD not in r.stdout + r.stderr                                   # never echoed
    con = sqlite3.connect(db)
    rows = con.execute("SELECT username, role, salt, pwhash FROM users").fetchall()
    assert [(u, role) for u, role, *_ in rows] == [("alice", "owner")]
    _, _, salt, pwhash = rows[0]
    assert len(salt) == 16 and len(pwhash) == 32 and GOOD.encode() not in pwhash   # scrypt hash, never plaintext
    assert GOOD.encode() not in db.read_bytes()
    audit = con.execute("SELECT actor, action FROM audit").fetchall()
    assert ("maintenance-cli", "auth.bootstrap") in audit


@pytest.mark.parametrize("pw", ["short", "", "elevenchars"])
def test_bootstrap_rejects_weak_passwords_and_creates_nothing(tmp_path, pw):
    db = tmp_path / "ap.db"
    r = _cli(db, "bootstrap", "alice", stdin=pw + "\n")
    assert r.returncode != 0 and "too short" in r.stderr
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_bootstrap_validates_username(tmp_path):
    db = tmp_path / "ap.db"
    for bad in ("Alice", "a", "x;drop", "../etc", "-x"):
        assert _cli(db, "bootstrap", bad, stdin=GOOD).returncode != 0, bad
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


# 3 + 4. login / wrong password ----------------------------------------------------------------------------------------
def test_owner_can_sign_in_and_wrong_password_is_rejected(tmp_path, monkeypatch):
    db = tmp_path / "ap.db"
    assert _cli(db, "bootstrap", "alice", stdin=GOOD).returncode == 0
    _, c = _web(tmp_path, monkeypatch, db)
    assert c.post("/api/login", json={"username": "alice", "password": GOOD + "x"}).status_code == 401
    assert c.post("/api/login", json={"username": "nobody", "password": GOOD}).status_code == 401
    r = c.post("/api/login", json={"username": "alice", "password": GOOD})
    assert r.status_code == 200 and r.json()["role"] == "owner"
    assert GOOD not in r.text and "pwhash" not in r.text
    assert c.get("/api/me").json()["username"] == "alice"


# 5. role assignment ----------------------------------------------------------------------------------------------------
def test_local_admin_assigns_roles_and_refuses_silent_overwrite(tmp_path, monkeypatch):
    db = tmp_path / "ap.db"
    assert _cli(db, "bootstrap", "alice", stdin=GOOD).returncode == 0
    assert _cli(db, "add", "bob", "approver", stdin=GOOD).returncode == 0
    assert _cli(db, "add", "carol", "viewer", stdin=GOOD).returncode == 0
    assert _cli(db, "add", "dave", "superuser", stdin=GOOD).returncode != 0          # unknown role
    r = _cli(db, "add", "carol", "owner", stdin=GOOD)                                 # escalation needs an explicit --replace
    assert r.returncode == 3 and "already exists" in r.stderr
    roles = dict(sqlite3.connect(db).execute("SELECT username, role FROM users").fetchall())
    assert roles == {"alice": "owner", "bob": "approver", "carol": "viewer"}
    out = _cli(db, "list").stdout
    assert "carol viewer" in out and GOOD not in out
    assert _cli(db, "disable", "carol").returncode == 0
    _, c = _web(tmp_path, monkeypatch, db)
    assert c.post("/api/login", json={"username": "carol", "password": GOOD}).status_code == 401   # disabled account


# 6. no unauthorised account creation ------------------------------------------------------------------------------------
def test_bootstrap_is_refused_once_any_account_exists(tmp_path):
    db = tmp_path / "ap.db"
    assert _cli(db, "bootstrap", "alice", stdin=GOOD).returncode == 0
    r = _cli(db, "bootstrap", "mallory", stdin=GOOD)
    assert r.returncode == 3 and "refused" in r.stderr
    assert [u for (u,) in sqlite3.connect(db).execute("SELECT username FROM users")] == ["alice"]


def test_concurrent_bootstraps_create_exactly_one_owner(tmp_path):
    from autopilot import auth
    db = tmp_path / "ap.db"
    results = []

    def go(name):
        con = sqlite3.connect(db, isolation_level=None, timeout=30)
        try:
            auth.bootstrap_owner(con, name, GOOD)
            results.append(name)
        except PermissionError:
            pass
    ts = [threading.Thread(target=go, args=(f"user{i}",)) for i in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(results) == 1
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_web_api_exposes_no_account_creation_or_role_change(tmp_path, monkeypatch):
    db = tmp_path / "ap.db"
    assert _cli(db, "bootstrap", "alice", stdin=GOOD).returncode == 0
    assert _cli(db, "add", "carol", "viewer", stdin=GOOD).returncode == 0
    web, anon = _web(tmp_path, monkeypatch, db)
    paths = {getattr(r, "path", "") for r in web.app.routes}
    assert not [p for p in paths if any(w in p for w in ("/users", "/signup", "/register", "/bootstrap", "/setup", "/role"))]
    for p in ("/api/users", "/api/signup", "/api/register", "/api/bootstrap", "/api/setup"):
        assert anon.post(p, json={"username": "mallory", "password": GOOD, "role": "owner"}).status_code in (401, 403, 404, 405)
    # a signed-in viewer cannot raise its own role: the session is HMAC-signed and the role comes from the database at login
    v = anon
    assert v.post("/api/login", json={"username": "carol", "password": GOOD, "role": "owner"}).status_code in (200, 422)
    me = v.get("/api/me")
    if me.status_code == 200:
        assert me.json()["role"] == "viewer"
    forged = v.cookies.get("ap_session", "")
    if forged:
        payload, sig = forged.rsplit(".", 1)
        import base64, json as _j
        d = _j.loads(base64.urlsafe_b64decode(payload)); d["r"] = "owner"
        tampered = base64.urlsafe_b64encode(_j.dumps(d).encode()).decode() + "." + sig
        v.cookies.set("ap_session", tampered)
        assert v.get("/api/me").status_code == 401
    rows = dict(sqlite3.connect(db).execute("SELECT username, role FROM users").fetchall())
    assert rows == {"alice": "owner", "carol": "viewer"}


def test_session_secret_is_mandatory(monkeypatch):
    from autopilot import auth
    monkeypatch.setenv("AUTOPILOT_SESSION_SECRET", "too-short")
    with pytest.raises(RuntimeError):
        auth.issue("alice", "owner")


# 7. persistence after restart -------------------------------------------------------------------------------------------
def test_accounts_persist_across_a_restart(tmp_path, monkeypatch):
    db = tmp_path / "ap.db"
    assert _cli(db, "bootstrap", "alice", stdin=GOOD).returncode == 0
    _, c1 = _web(tmp_path, monkeypatch, db)
    assert c1.post("/api/login", json={"username": "alice", "password": GOOD}).status_code == 200
    _, c2 = _web(tmp_path, monkeypatch, db)                   # module reload = a new service process on the same volume
    assert c2.post("/api/login", json={"username": "alice", "password": GOOD}).status_code == 200
    assert _cli(db, "bootstrap", "mallory", stdin=GOOD).returncode == 3     # still configured -> bootstrap stays disabled


# 8. approval and deployment boundaries are unchanged ---------------------------------------------------------------------
def test_bootstrapped_owner_still_cannot_deploy_and_viewers_cannot_approve(ctx):
    from autopilot import auth
    with pytest.raises(PermissionError):                       # ctx already has accounts: bootstrap is closed
        auth.bootstrap_owner(ctx.web.STORE.db, "late", GOOD)
    ids = discover(ctx)
    pid = ids["delivery"]
    for client in (ctx.viewer, ctx.op):
        assert client.post(f"/api/packages/{pid}/decision", json={"decision": "approved", "comment": "x"}).status_code == 403
    review(ctx, pid)
    assert ctx.ap.post(f"/api/packages/{pid}/decision", json={"decision": "approved", "comment": "ok"}).status_code == 200
    r = ctx.owner.post(f"/api/packages/{pid}/deploy", json={})      # two-person rule: the owner never deploys
    assert r.status_code == 403 and "approver" in r.json()["detail"]
    assert ctx.viewer.post(f"/api/packages/{pid}/deploy", json={}).status_code == 403
    assert ctx.op.post(f"/api/packages/{pid}/deploy", json={}).status_code == 403
