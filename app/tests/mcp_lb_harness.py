"""Offline harness for the L3 validation-gate root cause (doc 27): the REAL risk-scoring replicas and fraud-intel MCP
servers on 127.0.0.1 behind a TCP load balancer that models a BIG-IP virtual server WITHOUT OneConnect.

Model (matches the live evidence in doc 27 §2): the member is chosen once per client TCP connection
(least-connections-member, round-robin among ties) and every request on that connection goes to the same member.
Optional `persist=True` models the live iRule (universal persistence on Mcp-Session-Id): a session id seen in a server
response is bound to that member; a new connection whose first request carries a known session id goes to it.
Stateless requests carry no session id, so persistence never applies to them.
Loopback only; no lab contact.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

import httpx

APP = pathlib.Path(__file__).resolve().parents[1]
STANDINS = APP.parent / "devtools" / "fraudlocal" / "intel_standins.py"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait(url: str, proc: subprocess.Popen, secs: int = 60) -> None:
    for _ in range(secs * 10):
        if proc.poll() is not None:
            raise RuntimeError(f"{url}: process exited ({proc.returncode})")
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"{url} did not start")


class PerConnectionLB:
    """asyncio TCP proxy in a background thread. `connections` records (client_port, member) per accepted connection."""

    SID = re.compile(rb"(?im)^mcp-session-id:[ \t]*([!-~]+)")

    def __init__(self, members: list[tuple[str, int]], persist: bool = False):
        self.members, self.persist, self.table = members, persist, {}
        self.active = {m: 0 for m in members}
        self.rr = 0
        self.connections: list[tuple[int, tuple[str, int]]] = []
        self.port = free_port()
        self.loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def pick(self) -> tuple[str, int]:
        low = min(self.active.values())
        ties = [m for m in self.members if self.active[m] == low]
        m = ties[self.rr % len(ties)]
        self.rr += 1
        return m

    async def _pipe(self, r: asyncio.StreamReader, w: asyncio.StreamWriter, member=None, first: bytes = b"") -> None:
        try:
            if first:
                w.write(first)
            while data := await r.read(65536):
                if member and self.persist:
                    for sid in self.SID.findall(data):
                        self.table[sid] = member
                w.write(data)
                await w.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                w.close()

    async def _handle(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        first = await cr.read(65536)
        sid = self.SID.search(first)
        m = (self.table.get(sid.group(1)) if self.persist and sid else None) or self.pick()
        self.active[m] += 1
        self.connections.append((cw.get_extra_info("peername")[1], m))
        try:
            sr, sw = await asyncio.open_connection(*m)
            await asyncio.gather(self._pipe(cr, sw, first=first), self._pipe(sr, cw, member=m))
        finally:
            self.active[m] -= 1

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.server = self.loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", self.port))
        self._ready.set()
        self.loop.run_forever()

    def start(self) -> "PerConnectionLB":
        self.thread.start()
        self._ready.wait(10)
        return self

    def stop(self) -> None:
        async def close():
            self.server.close()
            for t in asyncio.all_tasks(self.loop) - {asyncio.current_task()}:
                t.cancel()
        asyncio.run_coroutine_threadsafe(close(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


@contextlib.contextmanager
def lab(persist: bool = True):
    """Start risk-scoring-1, risk-scoring-2 and fraud-intel (real servers) plus a per-connection LB over the replicas.
    Yields {'risk_vip', 'intel', 'risk1', 'risk2', 'lb', 'logs'}."""
    sys.path.insert(0, str(APP))
    from aplab import synthdata
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="mcp-lb-"))
    data = tmp / "synthetic.json"
    data.write_text(json.dumps(synthdata.build()))
    base = {**os.environ, "APLAB_DATA": str(data), "PYTHONPATH": str(APP), "MCP_ALLOWED_HOSTS": "127.0.0.1:*,localhost:*",
            "BIND_HOST": "127.0.0.1", "APP_DIR": str(APP)}
    base.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)
    ports = {k: free_port() for k in ("risk1", "risk2", "intel")}
    specs = [("risk1", [sys.executable, "-m", "services.mcp_risk.server"], {"REPLICA_ID": "risk-scoring-1"}),
             ("risk2", [sys.executable, "-m", "services.mcp_risk.server"], {"REPLICA_ID": "risk-scoring-2"}),
             ("intel", [sys.executable, str(STANDINS)], {})]
    procs, lb = [], None
    try:
        for name, cmd, env in specs:
            log = open(tmp / f"{name}.log", "w")
            p = subprocess.Popen(cmd, cwd=APP, env={**base, **env, "BIND_PORT": str(ports[name])}, stdout=log, stderr=subprocess.STDOUT)
            procs.append(p)
            _wait(f"http://127.0.0.1:{ports[name]}/healthz", p)
        lb = PerConnectionLB([("127.0.0.1", ports["risk1"]), ("127.0.0.1", ports["risk2"])], persist=persist).start()
        yield {"risk_vip": f"http://127.0.0.1:{lb.port}/mcp", "intel": f"http://127.0.0.1:{ports['intel']}/mcp",
               "risk1": f"http://127.0.0.1:{ports['risk1']}/mcp", "risk2": f"http://127.0.0.1:{ports['risk2']}/mcp",
               "lb": lb, "logs": tmp}
    finally:
        if lb:
            lb.stop()
        for p in procs:
            p.terminate()
        for p in procs:
            with contextlib.suppress(Exception):
                p.wait(10)
