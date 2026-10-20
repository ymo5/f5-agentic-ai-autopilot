"""B2 (doc 34): convergence VIP probes must not burn the validator identity's 120/min AI Security budget.

Probes go through the BIG-IP virtual servers; under the security profile the MCP ones present the ap-validator certificate.
Before the fix every attempt (every ~2 s, ~28 attempts in L3) re-probed both MCP VIPs: ~56 counted requests right before the
gate. Now: deferred until the rest has converged, never repeated after passing, retried at most every vip_retry_s."""
from __future__ import annotations

import asyncio
import pathlib
import sys

import pytest
import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import CFG  # noqa: E402
from autopilot.deployer import converge  # noqa: E402

LAB_CFG = yaml.safe_load(open(CFG))


class Probes:
    """Scripted lab: agents up at once; DNS correct at once (TTL 60 -> ~60 s cache hold); members up at `members_up`;
    VIPs answer when members are up, optionally failing until `vip_ok_at`."""
    def __init__(self, members_up=6.0, vip_ok_at=0.0, regress_at=None):
        self.t, self.members_up, self.vip_ok_at, self.regress_at = 0.0, members_up, vip_ok_at, regress_at
        self.vip_calls: list[tuple[float, str, bool]] = []
        self.spec = converge.spec_for(LAB_CFG, "security", True, mtls=True)

    def clock(self):
        return self.t

    async def sleep(self, s):
        self.t += s

    async def http_json(self, url):
        prof = LAB_CFG["design"]["profiles"]["security"]
        if "agent-card" in url:
            return 200, {"skills": [{}], "supportedInterfaces": [{"url": f"https://{prof['card']['advertises_host']}/"}]}
        name = "agent-a" if ":8080" in url else "agent-b"
        if self.regress_at and self.regress_at[0] <= self.t < self.regress_at[1] and name == "agent-b":
            raise ConnectionError("agent-b restarting")
        return 200, dict(prof["agents"][name]["expect"])

    async def dns(self, server, name):
        return [self.spec["dns"][name]], 60

    async def pool_members(self):
        up = self.t >= self.members_up
        return [{"member": m, "availability": "available" if up else "offline"} for m in ("10.50.20.31:8000", "10.50.20.32:8000")]

    async def vip(self, address, name, probe, mtls):
        ok = self.t >= self.members_up and self.t >= self.vip_ok_at
        self.vip_calls.append((self.t, name, mtls))
        return ok, "HTTP 200" if ok else "ConnectError"


def run(p: Probes) -> dict:
    return asyncio.run(converge.wait(p.spec, p, changed_at=0.0, clock=p.clock, sleep=p.sleep))


def mtls_calls(p):
    return [c for c in p.vip_calls if c[2]]


def test_happy_path_spends_exactly_one_probe_per_vip_after_everything_else_converged():
    p = Probes()
    rep = run(p)
    assert all(c["ok"] for c in rep["checks"].values()) and rep["attempts"] >= 25           # ~60 s DNS cache hold, poll 2 s
    assert len(p.vip_calls) == 3 and len(mtls_calls(p)) == 2                               # was 3 per attempt (≈ 56 mTLS)
    assert min(t for t, _, _ in p.vip_calls) >= 60                                          # only after the cache hold
    assert rep["checks"]["vip.mcp-risk.aplab.internal"]["ok"] and "HTTP 200" in rep["checks"]["vip.mcp-risk.aplab.internal"]["observed"]


def test_failing_vip_is_retried_at_most_every_vip_retry_s():
    p = Probes(vip_ok_at=100.0)                    # VIPs fail for 40 s after the rest converged
    rep = run(p)
    assert all(c["ok"] for c in rep["checks"].values())
    risk = [t for t, n, _ in p.vip_calls if n == "mcp-risk.aplab.internal"]
    assert all(b - a >= p.spec["vip_retry_s"] for a, b in zip(risk, risk[1:])), risk
    per_minute = max(sum(1 for t, _, m in p.vip_calls if m and x <= t < x + 60) for x in range(0, 200))
    assert per_minute <= 2 * (60 // p.spec["vip_retry_s"] + 1)                              # ≤ 10 mTLS probes in any 60 s


def test_vip_must_still_pass_and_never_passing_vip_still_times_out():
    p = Probes(vip_ok_at=10**9)
    with pytest.raises(converge.ConvergenceTimeout) as ei:
        run(p)
    chk = ei.value.report["checks"]
    assert not chk["vip.mcp-risk.aplab.internal"]["ok"] and len(mtls_calls(p)) <= 2 * (p.spec["timeout_s"] // p.spec["vip_retry_s"] + 2)


def test_no_vip_probe_is_spent_while_another_check_has_regressed():
    """A VIP is probed only when everything else is converged in that attempt (so a pass completes convergence at once).
    If another check regresses while a VIP is still failing, probing pauses and resumes only after re-convergence."""
    p = Probes(vip_ok_at=95.0, regress_at=(70.0, 82.0))      # VIPs fail at 60 s; agent-b restarts 70–82 s; VIPs ok from 95 s
    rep = run(p)
    assert all(c["ok"] for c in rep["checks"].values())
    assert not [t for t, _, _ in p.vip_calls if 70.0 <= t < 82.0]                          # nothing spent during the regression
    assert max(t for t, _, _ in p.vip_calls) >= 95.0 and rep["checks"]["vip.mcp-intel.aplab.internal"]["ok"]
