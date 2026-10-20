"""The MCP server behaviour the corrected AI Security iRule relies on (doc 34, B1), against the REAL fraud-intel server:
* protocol 2026-07-28: Mcp-Method / Mcp-Name headers that disagree with the body are rejected (-32020) -> the header path is safe;
* legacy sessions: those headers are ignored -> the iRule must never trust them (it body-inspects every legacy POST)."""
from __future__ import annotations

import json
import re

import httpx
import pytest

from mcp_lb_harness import lab

H = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {}}


@pytest.fixture(scope="module")
def intel():
    with lab() as env:
        yield env["intel"]


def _call(name, args):
    return {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": args}}


def test_2026_header_body_mismatch_is_rejected_by_the_server(intel):
    body = _call("freeze_account", {"account_id": "ACC-1", "reason": "t"})
    body["params"]["_meta"] = META
    v = {**H, "Mcp-Protocol-Version": "2026-07-28"}
    for hdr in ({"Mcp-Method": "tools/list"}, {"Mcp-Method": "ping"}, {"Mcp-Method": "tools/call", "Mcp-Name": "get_alert"}):
        r = httpx.post(intel, json=body, headers={**v, **hdr}, timeout=10)
        assert r.status_code == 400 and "-32020" in r.text, (hdr, r.text[:200])


def test_legacy_session_ignores_method_headers_which_is_why_the_irule_must_not_trust_them(intel):
    with httpx.Client(timeout=10) as c:
        r = c.post(intel, headers=H, json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
        hs = {**H, "Mcp-Session-Id": r.headers["mcp-session-id"], "Mcp-Protocol-Version": "2025-11-25"}
        c.post(intel, headers=hs, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        alerts = c.post(intel, headers=hs, json=_call("list_open_alerts", {})).text
        acct = re.search(r'account_id\\?"\s*:\s*\\?"([A-Z0-9-]+)', alerts).group(1)
        r = c.post(intel, headers={**hs, "Mcp-Method": "tools/list"}, json=_call("freeze_account", {"account_id": acct, "reason": "t"}))
    assert '\\"frozen\\": true' in r.text or '"frozen": true' in r.text, r.text[:300]
