"""Time-bounded live-deployment authorisation (Part B rehearsal window).

The only source of live authorisation is a window file written by root on the host (`ap-live-window start`) and
mounted read-only into the deployer. It holds ABSOLUTE UTC epoch times, so a container restart can never extend it:
  {"window_id", "issued", "not_after", "cleanup_until", "mode": "live"|"cleanup", "authorized_by", "purpose"}
Phases (re-evaluated from disk on every privileged operation; anything unexpected fails closed):
  live     issued <= now < not_after and mode == "live"   -> deploy, rollback, Reset Demo, replica actions
  cleanup  not_after <= now < cleanup_until (or mode == "cleanup" set by the backup timer)
                                                           -> rollback to a verified state, Reset Demo to baseline only
  locked   missing / unreadable / invalid / tampered / after cleanup_until -> every infrastructure write refused
Limits: window <= 3 h, cleanup grace <= 30 min. Each window_id is pinned in the database the first time it is seen;
a file that reuses a window_id with different times is treated as tampered.
"""
from __future__ import annotations

import json
import os
import time

MAX_WINDOW_S = 3 * 3600
MAX_GRACE_S = 30 * 60
FUTURE_SKEW_S = 60
FIELDS = ("window_id", "issued", "not_after", "cleanup_until", "mode")
BENIGN = ("no live window configured", "no live window authorised")

SCHEMA = """
CREATE TABLE IF NOT EXISTS live_window (window_id TEXT PRIMARY KEY, issued REAL, not_after REAL, cleanup_until REAL,
  first_seen REAL, last_phase TEXT);
"""

# operation -> phases in which it may run
ALLOWED = {"deploy": ("live",), "replica_stop": ("live",),
           "rollback": ("live", "cleanup"), "reset_demo": ("live", "cleanup"), "replica_start": ("live", "cleanup")}


class Window:
    def __init__(self, path: str | None, db=None, clock=time.time, audit=None):
        self.path, self.db, self.clock, self.audit = path, db, clock, audit
        self._reported: set = set()
        if db is not None:
            db.executescript(SCHEMA)

    def _load(self) -> tuple[dict | None, str | None]:
        if not self.path:
            return None, "no live window configured"
        try:
            with open(self.path) as f:
                w = json.load(f)
        except FileNotFoundError:
            return None, "no live window authorised"
        except (OSError, ValueError) as e:
            return None, f"live window file unreadable/invalid ({type(e).__name__})"
        if not isinstance(w, dict) or any(k not in w for k in FIELDS):
            return None, "live window file missing required fields"
        try:
            for k in ("issued", "not_after", "cleanup_until"):
                w[k] = float(w[k])
        except (TypeError, ValueError):
            return None, "live window times are not numbers"
        if not isinstance(w["window_id"], str) or not w["window_id"] or w["mode"] not in ("live", "cleanup"):
            return None, "live window id/mode invalid"
        if not (w["issued"] < w["not_after"] <= w["cleanup_until"]):
            return None, "live window times out of order"
        if w["not_after"] - w["issued"] > MAX_WINDOW_S:
            return None, "live window exceeds the 3 hour maximum"
        if w["cleanup_until"] - w["not_after"] > MAX_GRACE_S:
            return None, "cleanup grace exceeds the 30 minute maximum"
        return w, None

    def _pin(self, w: dict) -> str | None:
        """Pin window times on first sight; any later change to the same window_id is tampering."""
        if self.db is None:
            return None
        r = self.db.execute("SELECT issued, not_after, cleanup_until FROM live_window WHERE window_id=?", (w["window_id"],)).fetchone()
        if r is None:
            self.db.execute("INSERT INTO live_window VALUES (?,?,?,?,?,NULL)",
                            (w["window_id"], w["issued"], w["not_after"], w["cleanup_until"], self.clock()))
            return None
        if (r[0], r[1], r[2]) != (w["issued"], w["not_after"], w["cleanup_until"]):
            return "live window times changed after first use (tampered or reused id)"
        return None

    def status(self) -> dict:
        now = self.clock()
        w, err = self._load()
        if w and not err:
            err = self._pin(w)
        if err:
            wid = (w or {}).get("window_id")
            if self.audit and err not in BENIGN and (wid, err) not in self._reported:  # invalid / tampered: audit once
                self._reported.add((wid, err))
                self.audit("deployer", "live_window.invalid", None, {"window_id": wid, "reason": err})
            return {"phase": "locked", "reason": err, "window_id": wid, "now": now}
        out = {k: w[k] for k in ("window_id", "issued", "not_after", "cleanup_until", "mode")}
        out.update(now=now, authorized_by=w.get("authorized_by"), purpose=w.get("purpose"))
        if now < w["issued"] - FUTURE_SKEW_S:
            return {**out, "phase": "locked", "reason": "live window not yet valid (issued in the future)"}
        if now < w["not_after"] and w["mode"] == "live":
            return {**out, "phase": "live", "reason": None, "remaining_s": round(w["not_after"] - now)}
        if now < w["cleanup_until"]:
            return {**out, "phase": "cleanup", "reason": "live window expired; cleanup grace (rollback / Reset Demo to verified states only)",
                    "remaining_s": round(w["cleanup_until"] - now)}
        return {**out, "phase": "locked", "reason": "live window and cleanup grace expired"}

    def check(self, op: str) -> tuple[bool, dict]:
        st = self.status()
        return st["phase"] in ALLOWED[op], st

    def transition(self, audit) -> dict:
        """Record live->cleanup->locked transitions once per window (called by the deployer's background ticker)."""
        st = self.status()
        wid = st.get("window_id")
        if self.db is None:
            return st
        if not wid:  # file removed (timer close / manual stop): close every window still recorded as open
            for r in self.db.execute("SELECT window_id FROM live_window WHERE last_phase IN ('live','cleanup')").fetchall():
                self.db.execute("UPDATE live_window SET last_phase='locked' WHERE window_id=?", (r[0],))
                audit("deployer", "live_window.closed", None, {"window_id": r[0], "reason": st.get("reason")})
            return st
        r = self.db.execute("SELECT last_phase FROM live_window WHERE window_id=?", (wid,)).fetchone()
        last = r[0] if r else None
        if r is not None and st["phase"] != last:
            self.db.execute("UPDATE live_window SET last_phase=? WHERE window_id=?", (st["phase"], wid))
            ev = {"live": "live_window.opened", "cleanup": "live_window.expired", "locked": "live_window.closed"}[st["phase"]]
            audit("deployer", ev, None, {"window_id": wid, "reason": st.get("reason"), "not_after": st.get("not_after"),
                                         "cleanup_until": st.get("cleanup_until")})
        return st


def default_path() -> str | None:
    return os.environ.get("DEPLOYER_LIVE_WINDOW")
