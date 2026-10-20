"""Client for ap-window-broker (Unix socket, HMAC-signed, single-use nonce). Used only by autopilot-deployer."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time


class BrokerError(Exception):
    pass


class BrokerClient:
    def __init__(self, socket_path: str | None, key: bytes | None):
        self.path, self.key = socket_path, key

    def available(self) -> bool:
        return bool(self.path and self.key and os.path.exists(self.path))

    async def call(self, action: str, **params) -> dict:
        if not self.available():
            raise BrokerError("window broker not installed or not reachable from the deployer")
        req = {"action": action, "ts": time.time(), "nonce": secrets.token_hex(16), **params}
        req["mac"] = hmac.new(self.key, json.dumps(req, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        try:
            r, w = await asyncio.wait_for(asyncio.open_unix_connection(self.path), 5)
            w.write((json.dumps(req) + "\n").encode())
            await w.drain()
            line = await asyncio.wait_for(r.readline(), 120)
            w.close()
        except (OSError, asyncio.TimeoutError) as e:
            raise BrokerError(f"window broker unreachable: {type(e).__name__}") from e
        try:
            return json.loads(line)
        except ValueError as e:
            raise BrokerError("window broker returned an invalid reply") from e


def from_env(secrets_dir: str) -> BrokerClient:
    path = os.environ.get("DEPLOYER_WINDOW_BROKER")
    kf = os.path.join(secrets_dir, "window_broker_key")
    key = open(kf, "rb").read().strip() if os.path.exists(kf) else None
    return BrokerClient(path, key)
