"""MCP probing with the official SDK client (used by Enumerate and the validation framework)."""
from __future__ import annotations

import asyncio
import hashlib
import json

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


async def mcp_probe(url: str, timeout: float = 6.0, mode: str = "legacy") -> dict | None:
    """Return server identity + tool inventory if `url` speaks MCP without credentials, else None."""
    http = httpx2.AsyncClient(timeout=httpx2.Timeout(timeout))
    try:
        async def _run():
            async with Client(streamable_http_client(url, http_client=http), mode=mode) as c:
                tools = (await c.list_tools()).tools
                info = c.server_info
                inv = []
                for t in tools:
                    ann = t.annotations.model_dump(exclude_none=True) if getattr(t, "annotations", None) else {}
                    inv.append({"name": t.name, "description": (t.description or "")[:200], "annotations": ann})
                sig = hashlib.sha256(json.dumps(sorted(x["name"] for x in inv)).encode()).hexdigest()[:16]
                return {"server_name": getattr(info, "name", None), "server_version": getattr(info, "version", None),
                        "protocol_version": c.protocol_version, "tools": inv, "toolset_fingerprint": sig,
                        "authenticated": False, "session_mode": mode}
        return await asyncio.wait_for(_run(), timeout + 4)
    except BaseException as e:  # anyio ExceptionGroups, timeouts, HTTP errors -> not MCP (or not reachable)
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        return None
    finally:
        await http.aclose()
