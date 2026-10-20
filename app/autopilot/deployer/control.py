"""Live-window control (deployer side): independent owner re-authentication, bounds, rate limits, audit, broker call.

The web service is NOT trusted to vouch for the owner: the deployer re-verifies the owner's password against the user
database itself, so a compromised web tier (or a forged API request) cannot open a window without the owner's
credentials. No AI/LLM component has a session or credentials, so none can reach this path.
"""
from __future__ import annotations

from .. import auth, throttle
from .broker import BrokerError

MAX_MINUTES, MAX_GRACE = 180, 30


class ControlError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class WindowControl:
    def __init__(self, store, broker, window_status):
        self.s, self.broker, self.window_status = store, broker, window_status

    def _refuse(self, user: str, action: str, status: int, msg: str, **detail):
        self.s.audit(user, f"live_window.{action}.refused", None, {"reason": msg, **detail})
        raise ControlError(status, msg)

    async def open(self, username: str, password: str, minutes: int, grace: int, reason: str) -> dict:
        db = self.s.db
        key = f"stepup:{username.lower()}"
        try:
            throttle.check_locked(db, key)
        except throttle.Throttled as e:
            self._refuse(username, "open", 429, str(e))
        role = auth.verify(db, username, password)
        if role is None:
            throttle.failure(db, key, max_failures=3, lock_s=900)
            self._refuse(username, "open", 403, "password re-entry failed")
        throttle.reset(db, key)
        if role != "owner":
            self._refuse(username, "open", 403, "only the lab owner role can authorise live infrastructure changes", role=role)
        if not (isinstance(minutes, int) and 1 <= minutes <= MAX_MINUTES and isinstance(grace, int) and 1 <= grace <= MAX_GRACE):
            self._refuse(username, "open", 422, f"window must be 1..{MAX_MINUTES} minutes with 1..{MAX_GRACE} minutes cleanup grace",
                         minutes=minutes, grace=grace)
        if not (5 <= len((reason or "").strip()) <= 200):
            self._refuse(username, "open", 422, "a reason (5..200 characters) is required")
        try:
            throttle.attempt(db, f"winop:{username.lower()}", limit=5, window_s=600)
        except throttle.Throttled as e:
            self._refuse(username, "open", 429, str(e))
        if self.window_status().get("phase") in ("live", "cleanup"):
            self._refuse(username, "open", 409, "a live window is already open — close it first")
        self.s.audit(username, "live_window.open.requested", None, {"minutes": minutes, "grace": grace, "reason": reason[:200]})
        try:
            res = await self.broker.call("open", minutes=minutes, grace=grace, by=f"{username} via Autopilot UI")
        except BrokerError as e:
            self.s.audit(username, "live_window.open.failed", None, {"error": str(e)})
            raise ControlError(503, str(e))
        self.s.audit(username, "live_window.open." + ("succeeded" if res.get("ok") else "failed"), None,
                     {"broker": {k: res.get(k) for k in ("ok", "rc", "message", "error")}, "reason": reason[:200]})
        if not res.get("ok"):
            raise ControlError(409, f"window not opened: {res.get('error') or res.get('message') or 'controller refused'}")
        return {"ok": True, "window": self.window_status(), "message": res.get("message")}

    async def close(self, username: str, role: str, reason: str) -> dict:
        if auth.ROLES.get(role, 0) < auth.ROLES["approver"]:
            self._refuse(username, "close", 403, "closing a window requires the approver or owner role", role=role)
        if len((reason or "").strip()) < 3:
            self._refuse(username, "close", 422, "a reason is required")
        try:
            throttle.attempt(self.s.db, f"winop:{username.lower()}", limit=10, window_s=600)
        except throttle.Throttled as e:
            self._refuse(username, "close", 429, str(e))
        try:
            res = await self.broker.call("close", by=f"{username} via Autopilot UI")
        except BrokerError as e:
            self.s.audit(username, "live_window.close.failed", None, {"error": str(e)})
            raise ControlError(503, str(e))
        self.s.audit(username, "live_window.close." + ("succeeded" if res.get("ok") else "failed"), None,
                     {"reason": reason[:200], "broker": {k: res.get(k) for k in ("ok", "rc", "message", "error")}})
        if not res.get("ok"):
            raise ControlError(409, f"window not closed: {res.get('error') or res.get('message')}")
        return {"ok": True, "window": self.window_status()}

    async def broker_health(self) -> dict:
        try:
            return {"available": True, **(await self.broker.call("ping"))}
        except BrokerError as e:
            return {"available": False, "error": str(e)}
