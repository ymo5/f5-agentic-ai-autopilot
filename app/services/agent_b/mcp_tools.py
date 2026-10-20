"""MCP client helpers for Agent B.

Uses the official MCP SDK client over Streamable HTTP. A dedicated httpx2 client injects the W3C
`traceparent` header on every HTTP request (the SDK already propagates context in MCP `_meta`),
so the backend's HTTP-level span — which records the *client address* (direct caller vs. BIG-IP
SNAT) — joins the same distributed trace.
"""
from __future__ import annotations

import json
import os
import ssl
from contextlib import asynccontextmanager

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from opentelemetry.propagate import inject

MCP_MODE = os.environ.get("MCP_CLIENT_MODE", "legacy")  # "legacy" = initialize + Mcp-Session-Id; "auto" = 2026-07-28 stateless


async def _inject_trace(request: httpx2.Request) -> None:
    carrier: dict[str, str] = {}
    inject(carrier)
    for k, v in carrier.items():
        request.headers[k] = v


def _tls_context() -> ssl.SSLContext:
    """Build the verified MCP client context, including the optional mTLS identity.

    httpx2 rejects a CA path in ``verify`` combined with a ``cert`` tuple. Loading the
    client chain into the context preserves CA validation and hostname verification
    while making the mTLS identity usable by httpx2.
    """
    ca_bundle = os.environ.get("MCP_CA_BUNDLE")
    ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
    cert_path = os.environ.get("MCP_CLIENT_CERT")
    key_path = os.environ.get("MCP_CLIENT_KEY")
    if cert_path or key_path:
        if not cert_path or not key_path:
            raise ValueError("MCP client certificate and key must be configured together")
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def _http_client() -> httpx2.AsyncClient:
    return httpx2.AsyncClient(timeout=httpx2.Timeout(60.0, read=300.0), verify=_tls_context(),
                              event_hooks={"request": [_inject_trace]}, follow_redirects=False)


@asynccontextmanager
async def mcp_session(url: str):
    http = _http_client()
    try:
        async with Client(streamable_http_client(url, http_client=http), mode=MCP_MODE) as client:
            yield client
    finally:
        await http.aclose()


def result_data(res) -> object:
    """Prefer structured content; fall back to parsing the first text block."""
    if getattr(res, "is_error", False) or getattr(res, "isError", False):
        texts = [c.text for c in res.content if getattr(c, "type", "") == "text"]
        raise RuntimeError("MCP tool error: " + " ".join(texts))
    sc = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
    if sc is not None:
        return sc.get("result", sc) if isinstance(sc, dict) and set(sc) == {"result"} else sc
    for c in res.content:
        if getattr(c, "type", "") == "text":
            try:
                return json.loads(c.text)
            except json.JSONDecodeError:
                return c.text
    return None
