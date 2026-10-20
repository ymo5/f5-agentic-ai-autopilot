"""Persistent failure throttling / rate limiting shared by autopilot-web and autopilot-deployer (same database).

  attempt(db, key, limit, window_s)       -> raises Throttled when more than `limit` attempts happened within window_s
  failure(db, key, max_failures, lock_s)  -> records a failure; locks the key for lock_s after max_failures
  check_locked(db, key)                   -> raises Throttled while a key is locked
  reset(db, key)                          -> clears failures after a success
"""
from __future__ import annotations

import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS throttle (key TEXT PRIMARY KEY, failures INTEGER, first REAL, locked_until REAL);
CREATE TABLE IF NOT EXISTS rate_event (key TEXT, ts REAL);
"""


class Throttled(Exception):
    pass


def _init(db):
    db.executescript(SCHEMA)


def attempt(db, key: str, limit: int, window_s: float, now: float | None = None) -> None:
    _init(db)
    now = now or time.time()
    db.execute("DELETE FROM rate_event WHERE ts < ?", (now - 86400,))
    n = db.execute("SELECT COUNT(*) FROM rate_event WHERE key=? AND ts > ?", (key, now - window_s)).fetchone()[0]
    if n >= limit:
        raise Throttled(f"rate limit: at most {limit} attempts per {int(window_s // 60)} min — try again later")
    db.execute("INSERT INTO rate_event VALUES (?,?)", (key, now))


def check_locked(db, key: str, now: float | None = None) -> None:
    _init(db)
    now = now or time.time()
    r = db.execute("SELECT locked_until FROM throttle WHERE key=?", (key,)).fetchone()
    if r and r[0] and r[0] > now:
        raise Throttled(f"temporarily locked after repeated failures — retry in {int(r[0] - now) // 60 + 1} min")


def failure(db, key: str, max_failures: int, lock_s: float, window_s: float = 900, now: float | None = None) -> None:
    _init(db)
    now = now or time.time()
    r = db.execute("SELECT failures, first FROM throttle WHERE key=?", (key,)).fetchone()
    fails, first = (r[0], r[1]) if r and now - r[1] < window_s else (0, now)
    fails += 1
    db.execute("INSERT OR REPLACE INTO throttle VALUES (?,?,?,?)", (key, fails, first, now + lock_s if fails >= max_failures else None))


def reset(db, key: str) -> None:
    _init(db)
    db.execute("DELETE FROM throttle WHERE key=?", (key,))
