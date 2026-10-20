"""Traffic Generator control (deployer side): server-side re-authorisation, conflict checks, audit, broker call.

The web container forwards only {username, preset id, typed confirmation}. Here:
  * the user's role is re-read from the shared users table (the web's claim is not trusted); viewers and disabled users
    are refused; the minimum role is MIN_ROLE;
  * the preset id must be one of PRESET_IDS (the host broker holds the authoritative argv table and re-checks it);
  * starts are refused while the live deployment window is not locked or a deployment, validation run or Autopilot operation
    (investigation, assessment) is in progress (generator traffic must never overlap gate validation or investigation evidence);
  * every request — accepted, refused or failed — is written to the append-only audit table;
  * the privileged action is performed only by ap-trafficgen-broker (Unix socket, HMAC, nonce), never here.
"""
from __future__ import annotations

import os
import re
import sqlite3
import time

from . import broker as broker_mod

ROLES = {"viewer": 1, "operator": 2, "approver": 3, "owner": 4}
MIN_ROLE = "operator"
PRESET_IDS = ("a2a-discovery-5m", "rag-retrieval-10m", "embeddings-10m", "ai-data-path-15m", "llm-chat-sample")
VALIDATION_STALE_S = 1800        # an unfinished validation_run older than this is treated as abandoned
USER_RE = re.compile(r"^[A-Za-z0-9._@\-]{1,64}$")


class TrafficgenError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


def client_from_env(secrets_dir: str) -> broker_mod.BrokerClient:
    path = os.environ.get("DEPLOYER_TRAFFICGEN_BROKER")
    kf = os.path.join(secrets_dir, "trafficgen_broker_key")
    key = open(kf, "rb").read().strip() if os.path.exists(kf) else None
    return broker_mod.BrokerClient(path, key)


class TrafficgenControl:
    def __init__(self, store, broker, window_status):
        self.s, self.broker, self.window_status = store, broker, window_status

    def _role(self, username: str) -> str | None:
        if not USER_RE.fullmatch(username or ""):
            return None
        r = self.s.db.execute("SELECT role, disabled FROM users WHERE username=?", (username,)).fetchone()
        if not r or r["disabled"]:
            return None
        return r["role"]

    def _audit(self, username: str, action: str, detail: dict) -> None:
        self.s.audit(username or "?", action, None, detail)

    def _authorise(self, username: str, action: str, detail: dict) -> None:
        role = self._role(username)
        if ROLES.get(role or "", 0) < ROLES[MIN_ROLE]:
            self._audit(username, f"trafficgen.{action}.refused", {**detail, "reason": "role", "role": role})
            raise TrafficgenError(403, f"Traffic Generator control requires the {MIN_ROLE} role")

    def _busy(self) -> str | None:
        w = self.window_status()
        if w.get("phase") != "locked" or w.get("live"):
            return f"live deployment window is {w.get('phase')}"
        db = self.s.db
        dep = db.execute("SELECT COUNT(*) FROM deployment WHERE status='running'").fetchone()[0]
        val = db.execute("SELECT COUNT(*) FROM validation_run WHERE finished IS NULL AND started > ?",
                         (time.time() - VALIDATION_STALE_S,)).fetchone()[0]
        try:        # web-side operations (investigations, assessments, UI validations) share the database
            ops = db.execute("SELECT COUNT(*) FROM operation WHERE status='running'").fetchone()[0]
        except sqlite3.OperationalError:
            ops = 0
        if dep:
            return f"{dep} deployment(s) running"
        if ops:
            return f"{ops} Autopilot operation(s) running"
        return f"{val} validation run(s) in progress" if val else None

    async def _call(self, action: str, **params) -> dict:
        try:
            return await self.broker.call(action, **params)
        except broker_mod.BrokerError as e:
            raise TrafficgenError(503, "Traffic Generator broker unavailable") from e

    async def status(self) -> dict:
        if not self.broker.available():
            return {"available": False, "reason": "Traffic Generator broker not installed or not reachable", "presets": list(PRESET_IDS),
                    "min_role": MIN_ROLE}
        try:
            st = await self._call("status")
        except TrafficgenError as e:
            return {"available": False, "reason": str(e), "presets": list(PRESET_IDS), "min_role": MIN_ROLE}
        busy = self._busy()
        return {"available": bool(st.get("ok")), "min_role": MIN_ROLE, "container": st.get("container"), "current": st.get("current"),
                "history": st.get("history"), "presets": st.get("presets"), "limits": st.get("limits"),
                "start_blocked": busy}

    async def start(self, username: str, preset: str, confirm: str) -> dict:
        detail = {"preset": preset}
        self._authorise(username, "start", detail)
        if preset not in PRESET_IDS:
            self._audit(username, "trafficgen.start.refused", {**detail, "reason": "unknown preset"})
            raise TrafficgenError(400, "unknown preset")
        if confirm != preset:
            self._audit(username, "trafficgen.start.refused", {**detail, "reason": "confirmation"})
            raise TrafficgenError(400, "confirmation must repeat the preset id")
        busy = self._busy()
        if busy:
            self._audit(username, "trafficgen.start.refused", {**detail, "reason": busy})
            raise TrafficgenError(409, f"start refused: {busy}")
        try:
            res = await self._call("start", preset=preset, by=f"{username} via Autopilot UI")
        except TrafficgenError as e:
            self._audit(username, "trafficgen.start.failed", {**detail, "error": str(e)})
            raise
        ok = bool(res.get("ok"))
        self._audit(username, "trafficgen.start" if ok else "trafficgen.start.failed",
                    {**detail, "broker": {k: res.get(k) for k in ("ok", "rc", "message", "error")}})
        if not ok:
            raise TrafficgenError(409, f"start refused by the broker: {res.get('error') or res.get('message') or 'failed'}")
        return {"started": True, "preset": preset, "message": res.get("message")}

    async def stop(self, username: str, confirm: str) -> dict:
        self._authorise(username, "stop", {})
        if confirm != "STOP":
            self._audit(username, "trafficgen.stop.refused", {"reason": "confirmation"})
            raise TrafficgenError(400, "confirmation must be STOP")
        try:
            res = await self._call("stop", by=f"{username} via Autopilot UI")
        except TrafficgenError as e:
            self._audit(username, "trafficgen.stop.failed", {"error": str(e)})
            raise
        ok = bool(res.get("ok"))
        self._audit(username, "trafficgen.stop" if ok else "trafficgen.stop.failed",
                    {"broker": {k: res.get(k) for k in ("ok", "stopped", "rc", "seconds", "archive", "error")}})
        if not ok:
            raise TrafficgenError(409, f"stop failed: {res.get('error') or 'broker error'}")
        return {"stopped": bool(res.get("stopped")), "seconds": res.get("seconds"), "archive": res.get("archive"), "message": res.get("message")}
