"""packages.py multi-agent support: canonical A2A services, config-driven front doors, no silent omission; the lab-like
package bytes are identical to the pre-change goldens (fixtures/packages_golden, generated from the unmodified code)."""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import SCAN, TRACE  # noqa: E402
from test_wave2a import a2a, trace_b, world  # noqa: E402,F401
from test_wave3_placement import AGENT_C, LAB_SCAN  # noqa: E402

GOLD = pathlib.Path(__file__).resolve().parent / "fixtures" / "packages_golden"


def packages(world):
    from autopilot import web
    aid = web.STORE.current()["id"]
    assert world.op.post("/api/recommend").status_code == 200
    pk = world.viewer.get("/api/packages").json()
    return json.loads(json.dumps([{k: p[k] for k in ("kind", "title", "target", "body")} for p in pk]).replace(aid, "<AID>"))


@pytest.mark.parametrize("name,scan,traces", [("g1_conftest_scan", SCAN, [TRACE]), ("g2_lab_two_nics", LAB_SCAN, [trace_b()]),
                                              ("g3_enumerate_only", LAB_SCAN, [])])
def test_lab_like_packages_are_byte_identical_to_pre_change_goldens(world, name, scan, traces):
    world.run(scan, traces, name=name)
    got = packages(world)
    assert json.dumps(got, sort_keys=True) == json.dumps(json.loads((GOLD / f"{name}.json").read_text()), sort_keys=True)


def test_extra_agent_without_front_door_is_reported_not_silently_dropped(world):
    world.run(LAB_SCAN + [a2a("10.50.30.40", port=9100, card=AGENT_C)], [trace_b()], name="agent c")
    got = packages(world)
    gold = json.loads((GOLD / "g4_with_agent_c.json").read_text())
    for p, g in zip(got, gold):
        um = p["body"]["explanation"]["unmapped_services"]
        assert um == ["Receptionist Agent (Agent C, synthetic XGO scenario) (A2A agent at 10.50.30.40:9100): no front-door VIP configured"]
        assert g["body"]["explanation"]["unmapped_services"] == []                           # the old code dropped it silently
        p["body"]["explanation"]["unmapped_services"], g["body"]["explanation"]["unmapped_services"] = [], []
        assert json.dumps(p["body"]["as3"], sort_keys=True) == json.dumps(g["body"]["as3"], sort_keys=True)   # AS3 unchanged


def test_second_front_door_gives_the_second_agent_its_own_virtual_server(world, monkeypatch):
    from autopilot import web
    d = web.CFG["design"]
    doors = [dict(d["front_doors"]["a2a"]), {"name": "agent-c.aplab.internal", "vip": "10.50.10.103"}]
    monkeypatch.setitem(d["front_doors"], "a2a", doors)
    monkeypatch.setitem(d["profiles"]["baseline"]["dns"], "agent-c.aplab.internal", "10.50.20.40")
    world.run(LAB_SCAN + [a2a("10.50.20.40", port=9100, card=AGENT_C)], [trace_b()], name="two agents")
    got = packages(world)
    arch = {a["application"]: a for a in got[0]["body"]["architecture"]}
    assert arch["a2a_risk_assessment_agent"]["virtual_server"] == "10.50.10.100:443"
    c = next(v for k, v in arch.items() if k.startswith("a2a_receptionist_agent"))          # names are capped at 40 chars
    assert c["virtual_server"] == "10.50.10.103:443" and c["pool_members"] == ["10.50.20.40:9100"]
    assert got[0]["body"]["explanation"]["unmapped_services"] == []
    from autopilot.deployer import policy
    assert policy.check_as3(got[0]["body"]["as3"]) == []                                    # still inside the deployer policy
