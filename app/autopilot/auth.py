"""Human operator authentication and roles.

Roles (ordered): viewer < operator < approver < owner.
  viewer   — read-only UI/API
  operator — run discovery, assessment, recommendation, validation, fraud-application investigations, Reset Assessment
  approver — approve / reject / request modification of change packages, request deployment, rollback, Reset Demo,
             close a live window early
  owner    — lab owner: everything above plus AUTHORISING live infrastructure changes (opening a supervised live window),
             which additionally requires password re-entry and typed confirmation for every window.
Package approval (approver) and live-change authorisation (owner) are separate decisions with separate records.
Passwords: scrypt (n=2^14, r=8, p=1, 16-byte salt). Sessions: HMAC-SHA256-signed cookie with expiry.
There is no service/LLM identity that can hold a session: approval and deployment always require a
logged-in human whose role is checked server-side.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time

from fastapi import Cookie, Depends, HTTPException

ROLES = {"viewer": 1, "operator": 2, "approver": 3, "owner": 4}
CSRF_COOKIE, CSRF_HEADER = "ap_csrf", "x-csrf-token"
COOKIE = "ap_session"
TTL = int(os.environ.get("AUTOPILOT_SESSION_TTL", "28800"))
USERS_SCHEMA = """CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, role TEXT, salt BLOB, pwhash BLOB,
                  created REAL, disabled INTEGER DEFAULT 0);"""


def _secret() -> bytes:
    s = os.environ.get("AUTOPILOT_SESSION_SECRET", "")
    if len(s) < 32:
        raise RuntimeError("AUTOPILOT_SESSION_SECRET must be set (>= 32 chars)")
    return s.encode()


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def add_user(db, username: str, role: str, password: str, allow_weak: bool = False) -> None:
    if role not in ROLES:
        raise ValueError("bad role")
    if len(password) < (1 if allow_weak else 12):
        raise ValueError("password too short (minimum 12 characters; lab override: --allow-weak)")
    salt = secrets.token_bytes(16)
    db.execute(USERS_SCHEMA)
    db.execute("INSERT OR REPLACE INTO users VALUES (?,?,?,?,?,0)", (username, role, salt, _hash(password, salt), time.time()))


def verify(db, username: str, password: str) -> str | None:
    db.execute(USERS_SCHEMA)
    r = db.execute("SELECT role, salt, pwhash, disabled FROM users WHERE username=?", (username,)).fetchone()
    if not r or r["disabled"]:
        _hash(password, b"0" * 16)  # constant-ish time for unknown users
        return None
    return r["role"] if hmac.compare_digest(_hash(password, r["salt"]), r["pwhash"]) else None


def issue(username: str, role: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"u": username, "r": role, "exp": int(time.time()) + TTL}).encode()).decode()
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def parse(token: str | None) -> dict | None:
    if not token or "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest(), sig):
        return None
    d = json.loads(base64.urlsafe_b64decode(payload))
    return d if d.get("exp", 0) > time.time() else None


def current_user(ap_session: str | None = Cookie(default=None)) -> dict:
    s = parse(ap_session)
    if not s:
        raise HTTPException(401, "login required")
    return {"username": s["u"], "role": s["r"]}


def require(role: str):
    def dep(user: dict = Depends(current_user)) -> dict:
        if ROLES.get(user["role"], 0) < ROLES[role]:
            raise HTTPException(403, f"role '{role}' required")
        return user
    return dep


def new_csrf() -> str:
    return secrets.token_urlsafe(32)


USERNAME_RE = r"^[a-z][a-z0-9._-]{1,31}$"


def user_count(db) -> int:
    db.execute(USERS_SCHEMA)
    return db.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def bootstrap_owner(db, username: str, password: str) -> None:
    """First-run setup: create the FIRST account (role owner). Refused once any account exists, so it can never be used to
    add or replace an account later. Atomic (BEGIN IMMEDIATE): two concurrent bootstraps cannot both succeed."""
    import re as _re
    if not _re.match(USERNAME_RE, username or ""):
        raise ValueError("username must be 2-32 characters: lowercase letters, digits, '.', '_' or '-', starting with a letter")
    db.execute(USERS_SCHEMA)
    db.execute("BEGIN IMMEDIATE")
    try:
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            raise PermissionError("bootstrap refused: accounts already exist (use 'add' as a local administrator)")
        add_user(db, username, "owner", password)
        _audit(db, "auth.bootstrap", {"user": username, "role": "owner"})
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


def _audit(db, action: str, detail: dict) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, "
               "assessment_id TEXT, detail TEXT)")
    db.execute("INSERT INTO audit (ts, actor, action, assessment_id, detail) VALUES (?,?,?,?,?)",
               (time.time(), "maintenance-cli", action, None, json.dumps(detail)))


def _read_password(confirm: bool) -> str:
    """Interactive terminal: hidden prompt (twice). Otherwise one line from stdin. Never argv, never echoed or logged."""
    if sys.stdin.isatty():
        import getpass
        pw = getpass.getpass("Password (min. 12 characters): ")
        if confirm and getpass.getpass("Repeat password: ") != pw:
            raise ValueError("passwords do not match")
        return pw
    return sys.stdin.read().strip()


USAGE = """usage: python -m autopilot.auth <command>
  bootstrap [<username>]                  first-run only: create the first account (role owner); refused if any account exists
  add <username> <role> [--replace]       local administrator: create an account (roles: viewer operator approver owner);
                                          --replace is required to reset an existing account's password/role
  disable <username> | enable <username>  local administrator: block / unblock sign-in for an account
  list                                    list accounts (no password data)
Passwords are read from a hidden prompt (terminal) or from stdin (one line) — never from the command line.
The database is AUTOPILOT_DB (default /var/lib/autopilot/autopilot.db)."""


def main(argv: list[str]) -> int:
    import sqlite3
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        return 0 if argv else 2
    db = sqlite3.connect(os.environ.get("AUTOPILOT_DB", "/var/lib/autopilot/autopilot.db"), isolation_level=None)
    db.row_factory = sqlite3.Row
    cmd = argv[0]
    try:
        if cmd == "bootstrap":
            if user_count(db):
                print("bootstrap refused: accounts already exist (use 'add' as a local administrator)", file=sys.stderr)
                return 3
            name = argv[1] if len(argv) > 1 else (input("Owner username: ").strip() if sys.stdin.isatty() else "")
            bootstrap_owner(db, name, _read_password(confirm=True))
            print(f"first account '{name}' created with role owner. Create a separate approver account next "
                  f"(deployments require the approver role): python -m autopilot.auth add <name> approver")
        elif cmd == "add" and len(argv) >= 3:
            name, role = argv[1], argv[2]
            weak, replace = "--allow-weak" in argv[3:], "--replace" in argv[3:]
            db.execute(USERS_SCHEMA)
            if db.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone() and not replace:
                print(f"account '{name}' already exists; pass --replace to reset its password and role", file=sys.stderr)
                return 3
            add_user(db, name, role, _read_password(confirm=True), allow_weak=weak)
            _audit(db, "auth.password.set", {"user": name, "role": role, "weak_password_override": weak, "replaced": replace})
            print(f"user {name} ({role}) stored" + (" — WEAK PASSWORD OVERRIDE (lab only)" if weak else ""))
        elif cmd in ("disable", "enable") and len(argv) == 2:
            db.execute(USERS_SCHEMA)
            n = db.execute("UPDATE users SET disabled=? WHERE username=?", (1 if cmd == "disable" else 0, argv[1])).rowcount
            if not n:
                print(f"no such account: {argv[1]}", file=sys.stderr)
                return 1
            _audit(db, f"auth.user.{cmd}d", {"user": argv[1]})
            print(f"account {argv[1]} {cmd}d (existing browser sessions expire within AUTOPILOT_SESSION_TTL)")
        elif cmd == "list":
            db.execute(USERS_SCHEMA)
            for r in db.execute("SELECT username, role, disabled FROM users ORDER BY username"):
                print(r["username"], r["role"], "disabled" if r["disabled"] else "")
        else:
            print(USAGE, file=sys.stderr)
            return 2
    except (ValueError, PermissionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
