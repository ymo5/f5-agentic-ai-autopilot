"""Verification levels describe the configuration that is in place NOW (L1c, owner requirement 2026-10-15).

Live case: deployment bcdfd459 read back its BIG-IP configuration successfully, failed the gate and was rolled back.
/api/verification then showed "Configuration: passed" although the tenant had been removed. A removed deployment's
read-back is historical evidence, kept and labelled as such, never the current result.
"""
from __future__ import annotations

import json
import sqlite3

from autopilot import verification

OK_STEPS = [("verify.bigip_config", "ok"), ("converge[delivery]", "ok"), ("gate.validate[after-delivery]", "ok")]


def dep(i, status, steps=OK_STEPS, started=100.0, finished=None, proven=("delivery.failover",), gate=None):
    st = [{"step": s, "status": x, "started": started + 1, "finished": started + 2} for s, x in steps]
    if gate is not None:
        for s in st:
            if s["step"].startswith("gate.validate"):
                s["report"] = {"results": gate}
    return {"id": f"dep{i:05d}", "status": status, "package_hash": "h", "steps": st, "started": started,
            "finished": finished or started + 10, "proven_by": list(proven)}


def levels(deps, vals=(), resets=()):
    v = verification.summarize(list(deps), list(vals), list(resets))
    return {l["key"]: l for l in v["levels"]}, v


def test_live_case_rolled_back_deployment_is_not_current_configuration():
    steps = OK_STEPS[:2] + [("gate.validate[after-delivery]", "failed"), ("rollback", "ok"), ("converge[rollback → baseline]", "ok")]
    d = dep(1, "failed-rolled-back", steps, gate=[{"test": "delivery.load_distribution", "result": "fail"},
                                                   {"test": "a2a.via_front_door", "result": "pass"}])
    L, v = levels([d])
    for k in ("configuration", "operational"):
        assert L[k]["result"] == "not_run" and L[k]["current"] is False and L[k]["checks"] == []
        assert L[k]["history"]["result"] == "passed" and L[k]["history"]["deployment"] == "dep00001"   # preserved, labelled
        assert "no deployed configuration is in place now" in L[k]["detail"] and "historical evidence, not the current state" in L[k]["detail"]
    assert L["functional"]["result"] == "not_run"            # the failed gate's results are not evidence of a deployed state
    assert v["current_state"] == {"kind": "baseline", "active_deployment": None, "last_change": "dep00001", "reset_at": None, "restored_to": None}


def test_active_successful_deployment_is_current_and_passed():
    L, v = levels([dep(1, "succeeded")], [{"label": "after-delivery", "started": 120, "results": [{"test": "delivery.failover", "result": "pass"}]}])
    assert L["configuration"]["result"] == "passed" and L["configuration"]["current"] is True and "in place" in L["configuration"]["detail"]
    assert L["functional"]["result"] == "passed" and v["current_state"]["kind"] == "active"


def test_reset_demo_after_success_makes_levels_not_run_and_failed_reset_inconclusive():
    d = dep(1, "succeeded", started=100, finished=110)
    L, v = levels([d], [], [{"ts": 200, "ok": True}])
    assert L["configuration"]["result"] == "not_run" and "Reset Demo at" in L["configuration"]["detail"]
    assert L["configuration"]["history"]["result"] == "passed" and v["current_state"]["reset_at"] == 200
    L, _ = levels([d], [], [{"ts": 200, "ok": False}])
    assert L["configuration"]["result"] == "inconclusive"
    L, _ = levels([d], [], [{"ts": 50, "ok": True}])        # a reset BEFORE the deployment does not matter
    assert L["configuration"]["result"] == "passed"


def test_rollback_to_an_earlier_deployment_is_inconclusive_until_reverified():
    delivery = dep(1, "succeeded", started=100)
    security = dep(2, "failed-rolled-back", started=200)
    L, v = levels([security, delivery])
    assert L["configuration"]["result"] == "inconclusive" and "dep00001" in L["configuration"]["detail"]
    assert v["current_state"]["kind"] == "restored" and v["current_state"]["restored_to"] == "dep00001"
    L, _ = levels([dep(3, "rolled-back", started=300), delivery])   # manual rollback of a later success
    assert L["configuration"]["result"] == "inconclusive"


def test_unverified_end_states_are_inconclusive():
    for st in ("failed-rollback-failed", "failed-rolled-back-unverified", "failed", "running"):
        L, v = levels([dep(1, st)])
        assert L["configuration"]["result"] == "inconclusive" and v["current_state"]["kind"] == "unverified", st


def test_refused_attempts_do_not_change_the_current_state():
    active = dep(1, "succeeded", started=100)
    refused = [dep(2, "refused-preflight", [], started=200), dep(3, "refused-window-closed", [], started=300), dep(4, "failed-no-changes", [], started=400)]
    L, v = levels(refused[::-1] + [active])
    assert L["configuration"]["result"] == "passed" and v["current_state"]["active_deployment"] == "dep00001"
    L, v = levels(refused[::-1])
    assert L["configuration"]["result"] == "not_run" and v["current_state"]["kind"] == "none"


def test_validations_after_a_since_removed_deployment_do_not_count():
    removed = dep(2, "rolled-back", started=100, finished=110)
    vals = [{"label": "after-delivery", "started": 105, "results": [{"test": "delivery.failover", "result": "pass"}]}]
    L, _ = levels([removed], vals)
    assert L["functional"]["result"] == "not_run" and "no deployed configuration is in place now" in L["functional"]["detail"]


def _store(rows, audits=()):
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE deployment (id TEXT, assessment_id TEXT, package_id TEXT, package_hash TEXT, status TEXT, steps TEXT, started REAL, finished REAL)")
    db.execute("CREATE TABLE package (id TEXT, kind TEXT, body TEXT)")
    db.execute("CREATE TABLE validation_run (id TEXT, assessment_id TEXT, label TEXT, started REAL, finished REAL, results TEXT)")
    db.execute("CREATE TABLE audit (seq INTEGER PRIMARY KEY, ts REAL, actor TEXT, action TEXT, assessment_id TEXT, detail TEXT)")
    db.execute("INSERT INTO package VALUES ('p1', 'delivery', ?)", (json.dumps({"expected_outcomes": {"proven_by": ["delivery.failover"]}}),))
    for d in rows:
        db.execute("INSERT INTO deployment VALUES (?,?,?,?,?,?,?,?)", (d["id"], "a1", "p1", "h", d["status"], json.dumps(d["steps"]), d["started"], d["finished"]))
    for ts, action in audits:
        db.execute("INSERT INTO audit (ts, actor, action) VALUES (?, 'approver', ?)", (ts, action))
    return type("S", (), {"db": db})()


def test_from_store_reads_reset_events_and_reports_the_live_case():
    live = dep(1, "failed-rolled-back", OK_STEPS[:2] + [("gate.validate[after-delivery]", "failed"), ("rollback", "ok")], started=1000, finished=1200)
    v = verification.from_store(_store([live]), "a1")
    L = {l["key"]: l for l in v["levels"]}
    assert L["configuration"]["result"] == "not_run" and L["configuration"]["history"]["result"] == "passed"
    ok = dep(2, "succeeded", started=2000, finished=2100)
    v = verification.from_store(_store([live, ok], [(2500, "reset_demo.started"), (2600, "reset_demo.verified")]), "a1")
    assert v["current_state"]["kind"] == "baseline" and v["current_state"]["reset_at"] == 2600
    v = verification.from_store(_store([live, ok]), "a1")
    assert v["current_state"]["kind"] == "active" and {l["key"]: l for l in v["levels"]}["configuration"]["result"] == "passed"
