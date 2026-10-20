"""Which validation results are current evidence for a deployed control — one definition shared by Assess, Compare and the reports.

Rules (each a reporting defect found in the 2026-10-17 report audit, doc 38):
  * A check refused because no live window was open ("live execution is locked") did not run: it is ``not_run``, never ``fail``.
  * Validation is environment-wide, not per assessment: runs of every assessment and the deployments' own validation gates count.
  * Evidence for a control of kind K is taken only from runs that started at/after the IN-PLACE deployment of kind K started,
    in a profile that exercises K: AI Delivery checks in ``after-delivery`` or ``after-security``; AI Security checks only in
    ``after-security`` (in a delivery profile the ``security.*`` checks confirm exposure, not protection).
  * Per check the latest run in which it actually ran (pass/fail) is the current result; older results are superseded.
  * A run in which the validator itself could not build its mTLS client (web validator 92e94f99, fixed in release
    75d1739f70e6) is annotated ``invalid_run`` — kept for audit, never used as evidence.
"""
from __future__ import annotations

import json

from . import verification

LOCKED = "live execution is locked"
CLIENT_DEFECT = "cannot be combined with `cert=...`"
PROFILES = {"delivery": ("after-delivery", "after-security", "after-data"), "security": ("after-security", "after-data"),
            "data": ("after-data",)}   # after-data is a superset of after-security (AI Data Delivery, opt-in)


def effective(t: dict) -> str:
    """pass | fail | not_run for one check result."""
    if t.get("result") == "fail" and LOCKED in json.dumps(t.get("observed") or {}, default=str):
        return "not_run"
    return t.get("result") or "not_run"


def run_note(results: list[dict]) -> str | None:
    if any(CLIENT_DEFECT in json.dumps(t.get("observed") or {}, default=str) for t in results):
        return ("invalid run — the validator could not present its mTLS client certificate (TLS client construction defect in the "
                "web validator, fixed by release 75d1739f70e6); results are not evidence about the deployment")
    if any(effective(t) == "not_run" and t.get("result") == "fail" for t in results):
        return "one or more checks need a live window and did not run (window locked) — reported as not run, not as failures"
    return None


def runs(store) -> list[dict]:
    """Every validation run (all assessments) plus every deployment's validation gate, newest first."""
    out = [{"id": r["id"], "source": "validation run", "assessment_id": r["assessment_id"], "profile": r["label"], "started": r["started"] or 0,
            "results": json.loads(r["results"] or "[]")}
           for r in store.db.execute("SELECT id, assessment_id, label, started, results FROM validation_run")]
    for d in store.db.execute("SELECT id, assessment_id, started, steps FROM deployment"):
        for s in json.loads(d["steps"] or "[]"):
            if not str(s.get("step", "")).startswith("gate.validate") or not isinstance(s.get("detail"), dict):
                continue
            res = s["detail"].get("results")
            if isinstance(res, list) and res:
                out.append({"id": f"{d['id']}:gate", "source": f"deployment {d['id']} validation gate", "assessment_id": d["assessment_id"],
                            "profile": s["step"][len("gate.validate"):].strip("[]"), "started": s.get("started") or d["started"] or 0,
                            "results": res})
    for r in out:
        r["note"] = run_note(r["results"])
    return sorted(out, key=lambda r: r["started"], reverse=True)


def in_place(store) -> dict:
    """{kind: in-place deployment} when the effective state is verified; nothing is in place otherwise."""
    p = verification.protection_from_store(store)
    return {d["kind"]: d for d in p["in_place"]} if p["verified"] else {}


def current(store, kind: str, tests, all_runs: list[dict] | None = None, place: dict | None = None) -> dict:
    """Latest effective result per test from qualifying runs of the in-place deployment of ``kind``.
    Returns {test: {result, run_id, at, source}}; a test without a qualifying result is absent."""
    place = in_place(store) if place is None else place
    dep = place.get(kind)
    if not dep:
        return {}
    out: dict = {}
    for r in all_runs if all_runs is not None else runs(store):
        if ((r["note"] or "").startswith("invalid run") or r["profile"] not in PROFILES.get(kind, ())
                or r["started"] < (dep["started"] or 0)):
            continue
        for t in r["results"]:
            if t["test"] in tests and t["test"] not in out and effective(t) in ("pass", "fail"):
                out[t["test"]] = {"result": effective(t), "run_id": r["id"], "at": r["started"], "source": r["source"]}
    return out


def validated(store, kind: str, test: str, all_runs: list[dict] | None = None, place: dict | None = None) -> dict | None:
    """Evidence that a control is enforced now: the in-place deployment of ``kind`` plus its latest qualifying passing ``test``."""
    place = in_place(store) if place is None else place
    res = current(store, kind, {test}, all_runs, place).get(test)
    if not res or res["result"] != "pass":
        return None
    return {"status": "verified", "test": test, "deployment": place[kind]["id"], "evidence_ids": [res["run_id"]], "at": res["at"],
            "source": res["source"]}
