"""Focused offline regressions for the three failed Security-gate areas (validator side).

Lab release-packaging regressions (deploy/tls release builders) are not part of the public repository."""
from __future__ import annotations

import asyncio
import pathlib

import pytest

from autopilot import validate


ROOT = pathlib.Path(__file__).resolve().parents[1].parent


def test_transport_failure_is_not_an_http_policy_denial(monkeypatch):
    async def fake(*_args, **_kwargs):
        return {"status": -1, "transport_error": "ConnectError: refused"}

    monkeypatch.setattr(validate, "_raw_mcp_result", fake)
    result = asyncio.run(validate._raw_mcp_result("https://mcp.example/mcp", "model_info", None))
    assert result["status"] == -1 and result["transport_error"]
    assert result["status"] != 403


def test_unknown_identity_transport_evidence_preserves_sanitized_exception_chain():
    chain = validate.exception_chain(ExceptionGroup("outer", [ValueError("certificate verify failed"),
                                                               RuntimeError("Authorization: bearer-secret")]))
    assert [x["type"] for x in chain] == ["ValueError", "RuntimeError"]
    assert "bearer-secret" not in str(chain)
    assert "certificate verify failed" in chain[0]["message"]


def test_rate_probe_uses_bounded_waves_and_keeps_http_and_transport_results_separate(monkeypatch):
    calls = []

    async def fake(*_args, **_kwargs):
        calls.append(1)
        return {"status": 200 if len(calls) <= 3 else 429, "transport_error": None}

    monkeypatch.setattr(validate, "_raw_mcp_result", fake)
    result = asyncio.run(validate._rate_limit_probe("https://mcp.example/mcp", validate.VALIDATOR, 7, concurrency=2))
    assert len(result) == 7
    assert sum(x["status"] == 429 for x in result) == 4
    assert all(x["transport_error"] is None for x in result)
    assert [x["sequence"] for x in result] == list(range(1, 8))
    assert all(x["client_identity"] == "ap-validator" and x["timestamp"] for x in result)
    assert all(x["outcome"].startswith("http_") for x in result)


def test_rate_probe_preserves_transport_failures_as_inconclusive():
    async def fake(*_args, **_kwargs):
        return {"status": -1, "transport_error": "SSL: certificate verify failed"}

    original = validate._raw_mcp_result
    try:
        validate._raw_mcp_result = fake
        result = asyncio.run(validate._rate_limit_probe("https://mcp.example/mcp", validate.VALIDATOR, 4, concurrency=2))
    finally:
        validate._raw_mcp_result = original
    assert all(x["status"] == -1 for x in result)
    assert all(x["transport_error"] for x in result)
    assert all(x["outcome"] == "transport_error" for x in result)


def test_rate_probe_can_start_after_a_fresh_calendar_minute(monkeypatch):
    delays = []
    calls = []

    async def fake_sleep(delay):
        delays.append(delay)

    async def fake(*_args, **_kwargs):
        calls.append(1)
        return {"status": 429 if len(calls) > 2 else 200, "transport_error": None}

    monkeypatch.setattr(validate.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(validate.time, "time", lambda: 120.25)
    monkeypatch.setattr(validate, "_raw_mcp_result", fake)
    result = asyncio.run(validate._rate_limit_probe("https://mcp.example/mcp", validate.VALIDATOR, 4,
                                                   concurrency=1, fresh_window=True))
    assert len(delays) == 1 and 59.7 < delays[0] < 59.9
    assert len(calls) == 4 and [x["sequence"] for x in result] == [1, 2, 3, 4]
    assert [x["status"] for x in result] == [200, 200, 429, 429]
    assert all(x["transport_error"] is None for x in result)


def test_rate_limit_verdict_marks_crossed_calendar_window_inconclusive():
    samples = [{"status": 200, "transport_error": None, "calendar_minute": 10},
               {"status": 429, "transport_error": None, "calendar_minute": 11}]
    ok, detail = validate._rate_limit_verdict(samples, 1)
    assert not ok
    assert detail["calendar_minute_crossed"] is True
    assert detail["calendar_minute_keys"] == [10, 11]


def test_rate_limit_verdict_keeps_transport_error_failing():
    samples = [{"status": 200, "transport_error": None, "calendar_minute": 10},
               {"status": -1, "transport_error": "ReadError", "calendar_minute": 10},
               {"status": 429, "transport_error": None, "calendar_minute": 10}]
    ok, detail = validate._rate_limit_verdict(samples, 1)
    assert not ok
    assert detail["calendar_minute_crossed"] is False
    assert detail["transport_errors"] == ["ReadError"]


def test_security_fingerprint_command_is_allowlisted_and_journaled_before_gate():
    from autopilot.deployer import policy
    assert policy.HOST_COMMANDS.match("status fingerprint")
    engine = (ROOT / "app/autopilot/deployer/engine.py").read_text()
    assert '"fingerprint.agent-b[security]"' in engine
    assert "mcp_tools_sha256" in (ROOT / "deploy/common/ap-dep-apply").read_text()
def test_security_fingerprint_command_is_allowlisted_and_journaled_before_gate():
    from autopilot.deployer import policy
    assert policy.HOST_COMMANDS.match("status fingerprint")
    engine = (ROOT / "app/autopilot/deployer/engine.py").read_text()
    assert '"fingerprint.agent-b[security]"' in engine
    assert "mcp_tools_sha256" in (ROOT / "deploy/common/ap-dep-apply").read_text()
