"""B2 (doc 34): the ap-validator identity's requests through the AI Security policy during a security deployment
(convergence VIP probes + after-security gate) must stay under 120 per calendar minute with headroom, for every minute
alignment, fast and slow A2A tasks, and repeated convergence attempts. Uses the REAL converge.wait() timing logic."""
from __future__ import annotations

import asyncio
import math
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_converge_b2 import Probes  # noqa: E402
from autopilot.deployer import converge  # noqa: E402

LIMIT = 120
# after-security gate, ap-validator identity, in gate order (measured in the offline rehearsal, doc 33/34):
# tool_execution 12 calls + latency 10 calls (3 requests each) + legacy session 10 = 76 within ~1 s; failover 6 calls (18)
# ~22 s later; authorized/unauthorized tool tests (2) + decoy-header test (2) ~33 s after the MCP section starts.
GATE = [(0.0, 76), (22.0, 18), (33.0, 4)]


def converge_probe_times(scenario: str, legacy_behaviour: bool = False) -> tuple[list[float], float]:
    kw = {"happy": {}, "vip_fails_40s": {"vip_ok_at": 100.0}, "regression": {"vip_ok_at": 95.0, "regress_at": (70.0, 82.0)}}[scenario]
    p = Probes(**kw)
    rep = asyncio.run(converge.wait(p.spec, p, changed_at=0.0, clock=p.clock, sleep=p.sleep))
    end = rep["elapsed_s"]
    if legacy_behaviour:                       # pre-fix: both MCP VIPs probed on every attempt
        return [i * p.spec["poll_s"] for i in range(rep["attempts"]) for _ in range(2)], end
    return [t for t, _, mtls in p.vip_calls if mtls], end


def worst_minute(times: list[float], gate_start: float) -> tuple[int, bool]:
    """Max requests in any calendar minute over all alignments, and whether any gate request (before the final rate-limit
    burst) would see n > LIMIT."""
    worst, hit = 0, False
    for k in range(120):
        phi = k * 0.5
        cnt: dict[int, int] = {}
        for t in sorted(times):
            m = math.floor((t + phi) / 60)
            cnt[m] = cnt.get(m, 0) + 1
            worst = max(worst, cnt[m])
            if cnt[m] > LIMIT and t >= gate_start:
                hit = True
    return worst, hit


def budget(scenario: str, a2a_s: float, legacy_behaviour: bool = False) -> tuple[int, bool]:
    conv, end = converge_probe_times(scenario, legacy_behaviour)
    g0 = end + a2a_s                            # the gate's A2A task (agent-b identity) runs before its MCP section
    gate = [g0 + off + 0.013 * i for off, n in GATE for i in range(n)]
    return worst_minute(conv + gate, g0)


def test_fixed_convergence_keeps_at_least_15_requests_headroom_in_every_case():
    rows = []
    for scenario in ("happy", "vip_fails_40s", "regression"):
        for a2a_s in (0.0, 2.0, 5.0, 8.0, 12.7, 20.0, 45.0, 85.5, 120.0):
            worst, hit = budget(scenario, a2a_s)
            rows.append((scenario, a2a_s, worst))
            assert not hit and worst <= LIMIT - 15, (scenario, a2a_s, worst)   # gate alone = 98; convergence adds <= 4
    assert max(r[2] for r in rows) <= 102


def test_pre_fix_behaviour_would_exceed_the_limit_with_a_fast_a2a_task():
    worst, hit = budget("happy", 5.0, legacy_behaviour=True)
    assert worst > LIMIT and hit


def test_never_converging_vip_cannot_flood_the_identity():
    p = Probes(vip_ok_at=10**9)
    try:
        asyncio.run(converge.wait(p.spec, p, changed_at=0.0, clock=p.clock, sleep=p.sleep))
    except converge.ConvergenceTimeout:
        pass
    times = [t for t, _, m in p.vip_calls if m]
    assert max(sum(1 for t in times if x <= t < x + 60) for x in range(0, 200)) <= 10      # ≤ 10 per minute, then rollback
