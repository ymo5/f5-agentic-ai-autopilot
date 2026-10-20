"""Scheduled discovery (Wave 2A architecture) — DISABLED by default and network-free in this milestone.

Controls:
  * permitted   the environment configuration must contain `scheduler: {permitted: true}`; the lab configuration does
                not, so enabling is refused here (changing that needs a separately approved configuration deployment);
  * enabled     stored setting, default false; only the lab OWNER may change it (enforced in web.py) — audited;
  * jobs        this milestone allows ONLY "snapshot": build an inventory snapshot from already-stored evidence of the
                current assessment. Network-active methods (observe, enumerate, ingest, direct fingerprinting) are
                rejected at validation — they belong to Wave 2B and need separate authorisation;
  * cadence     >= 15 minutes; one run at a time (single-flight); jitter; failures are counted and the schedule
                auto-disables after MAX_FAILURES consecutive failures; every run is audited;
  * never       triggers recommendations, approvals or deployments, and never changes the discovery scope.
"""
from __future__ import annotations

import asyncio
import json
import random
import time

from . import inventory

SCHEMA = """
CREATE TABLE IF NOT EXISTS discovery_schedule (id TEXT PRIMARY KEY, enabled INTEGER, cadence_min INTEGER, jobs TEXT,
  updated_by TEXT, updated_at REAL, consecutive_failures INTEGER, last_run REAL, last_status TEXT, last_error TEXT);
"""
ALLOWED_JOBS = {"snapshot"}
NETWORK_JOBS = {"observe", "enumerate", "ingest", "direct", "fingerprint", "a2a_probe"}
MIN_CADENCE, MAX_FAILURES = 15, 3
DEFAULT = {"id": "default", "enabled": 0, "cadence_min": 60, "jobs": ["snapshot"], "updated_by": None, "updated_at": None,
           "consecutive_failures": 0, "last_run": None, "last_status": None, "last_error": None}


class ScheduleError(ValueError):
    def __init__(self, msg: str, status: int = 422):
        super().__init__(msg)
        self.status = status


def permitted(cfg: dict) -> bool:
    return bool((cfg.get("scheduler") or {}).get("permitted") is True)


def get(store) -> dict:
    r = store.db.execute("SELECT * FROM discovery_schedule WHERE id='default'").fetchone()
    d = dict(r) if r else dict(DEFAULT)
    d["jobs"] = json.loads(d["jobs"]) if isinstance(d["jobs"], str) else d["jobs"]
    d["enabled"] = bool(d["enabled"])
    return d


def _save(store, d: dict) -> None:
    store.db.execute("INSERT OR REPLACE INTO discovery_schedule VALUES (:id,:enabled,:cadence_min,:jobs,:updated_by,:updated_at,"
                     ":consecutive_failures,:last_run,:last_status,:last_error)", {**d, "enabled": int(bool(d["enabled"])), "jobs": json.dumps(d["jobs"])})


def update(store, cfg: dict, actor: str, enabled: bool | None = None, cadence_min: int | None = None, jobs: list[str] | None = None) -> dict:
    d = get(store)
    if jobs is not None:
        bad = sorted(set(jobs) & NETWORK_JOBS)
        if bad:
            raise ScheduleError(f"network-active jobs {bad} are not available in this milestone (Wave 2B, separate authorisation)")
        unknown = sorted(set(jobs) - ALLOWED_JOBS)
        if unknown or not jobs:
            raise ScheduleError(f"unknown or empty job list: {unknown or jobs}")
        d["jobs"] = sorted(set(jobs))
    if cadence_min is not None:
        if int(cadence_min) < MIN_CADENCE:
            raise ScheduleError(f"cadence must be at least {MIN_CADENCE} minutes")
        d["cadence_min"] = int(cadence_min)
    if enabled is not None:
        if enabled and not permitted(cfg):
            store.audit(actor, "schedule.enable.refused", None, {"reason": "not permitted by the environment configuration"})
            raise ScheduleError("scheduled discovery is not permitted in this environment (configuration `scheduler.permitted` is not true)", 409)
        d["enabled"] = bool(enabled)
        if enabled:
            d["consecutive_failures"] = 0
    d["updated_by"], d["updated_at"] = actor, time.time()
    _save(store, d)
    store.audit(actor, "schedule.updated", None, {"enabled": d["enabled"], "cadence_min": d["cadence_min"], "jobs": d["jobs"]})
    return d


async def run_once(store, actor: str = "scheduler") -> dict:
    """One scheduled run. Snapshot job only: reads stored evidence of the current assessment; opens no connections."""
    d = get(store)
    out = {}
    store.audit(actor, "schedule.run.started", None, {"jobs": d["jobs"]})
    try:
        for job in d["jobs"]:
            if job not in ALLOWED_JOBS:
                raise ScheduleError(f"job '{job}' not allowed")
            if job == "snapshot":
                out["snapshot"] = inventory.record(store, store.current()["id"], actor, trigger="scheduled")
        d.update(last_run=time.time(), last_status="ok", last_error=None, consecutive_failures=0)
        store.audit(actor, "schedule.run.finished", None, out)
    except Exception as e:  # failure handling: counted, audited, auto-disable after MAX_FAILURES
        d.update(last_run=time.time(), last_status="failed", last_error=f"{type(e).__name__}: {e}"[:300],
                 consecutive_failures=int(d.get("consecutive_failures") or 0) + 1)
        if d["consecutive_failures"] >= MAX_FAILURES:
            d["enabled"] = False
            store.audit(actor, "schedule.auto_disabled", None, {"failures": d["consecutive_failures"]})
        store.audit(actor, "schedule.run.failed", None, {"error": d["last_error"]})
        out["error"] = d["last_error"]
    _save(store, d)
    return out


class Scheduler:
    """Background loop. Does nothing unless the environment permits scheduling AND the owner enabled it."""

    def __init__(self, store, cfg: dict):
        self.s, self.cfg, self.task, self.lock = store, cfg, None, asyncio.Lock()

    def start(self) -> bool:
        if not permitted(self.cfg) or self.task:
            return False
        self.task = asyncio.get_event_loop().create_task(self._loop())
        return True

    async def _loop(self) -> None:
        while True:
            d = get(self.s)
            wait = max(MIN_CADENCE, int(d["cadence_min"])) * 60
            due = d["enabled"] and permitted(self.cfg) and (not d["last_run"] or time.time() - d["last_run"] >= wait)
            if due and not self.lock.locked():
                async with self.lock:
                    await run_once(self.s)
            await asyncio.sleep(60 + random.uniform(0, 15))
