"""Persistent operation tracking for long-running UI actions (discovery, recommendation, validation, deployment,
rollback, reset). Progress lives in the database, so it survives browser refreshes and is visible to every signed-in
user. Polling only reads these rows; it never triggers work.

ETA: reported only when at least MIN_SAMPLES earlier operations of the same kind succeeded; it is the median of their
durations minus the elapsed time (never shown when the current run is already past the median).
"""
from __future__ import annotations

import asyncio
import json
import statistics
import time
import traceback
import uuid
from typing import Any, Awaitable, Callable

SCHEMA = """
CREATE TABLE IF NOT EXISTS operation (id TEXT PRIMARY KEY, kind TEXT, title TEXT, status TEXT, actor TEXT, assessment_id TEXT,
  started REAL, finished REAL, current TEXT, steps TEXT, result TEXT, error TEXT, ref TEXT);
"""
MIN_SAMPLES = 3
INLINE = False   # tests: run operations to completion inside the request
EXCLUSIVE = {"investigate": "investigate", "discover": "discovery", "describe": "discovery", "recommend": "discovery", "validate": "validate",
             "deploy": "infrastructure", "rollback": "infrastructure", "reset_demo": "infrastructure"}


class Busy(Exception):
    pass


class Op:
    def __init__(self, store, row: dict):
        self.s, self.id, self.steps = store, row["id"], []

    def _save(self, **kw) -> None:
        sets = ", ".join(f"{k}=?" for k in kw)
        self.s.db.execute(f"UPDATE operation SET {sets} WHERE id=?", (*[json.dumps(v, default=str) if k in ("steps", "result", "ref") else v
                                                                        for k, v in kw.items()], self.id))

    def step(self, name: str, detail: Any = None) -> dict:
        for s in self.steps:
            if s["status"] == "running":
                s["status"], s["finished"] = "ok", time.time()
        st = {"name": name, "status": "running", "started": time.time(), "finished": None, "detail": detail}
        self.steps.append(st)
        self._save(steps=self.steps, current=name)
        return st

    def done(self, status: str = "ok", detail: Any = None) -> None:
        if self.steps and self.steps[-1]["status"] == "running":
            self.steps[-1].update(status=status, finished=time.time())
            if detail is not None:
                self.steps[-1]["detail"] = detail
        self._save(steps=self.steps)

    def ref(self, **kw) -> None:
        cur = get(self.s, self.id)["ref"] or {}
        self._save(ref={**cur, **kw})


def _row(r) -> dict:
    d = dict(r)
    for k in ("steps", "result", "ref"):
        d[k] = json.loads(d[k]) if d[k] else ([] if k == "steps" else None)
    return d


def get(store, op_id: str) -> dict | None:
    r = store.db.execute("SELECT * FROM operation WHERE id=?", (op_id,)).fetchone()
    return _with_eta(store, _row(r)) if r else None


def recent(store, limit: int = 20, active_only: bool = False) -> list[dict]:
    q = "SELECT * FROM operation" + (" WHERE status='running'" if active_only else "") + " ORDER BY started DESC LIMIT ?"
    return [_with_eta(store, _row(r)) for r in store.db.execute(q, (limit,))]


def _with_eta(store, op: dict) -> dict:
    now = time.time()
    op["elapsed_s"] = round((op["finished"] or now) - op["started"], 1)
    op["eta_s"] = None
    if op["status"] == "running":
        d = [r[0] - r[1] for r in store.db.execute(
            "SELECT finished, started FROM operation WHERE kind=? AND status='succeeded' AND finished IS NOT NULL "
            "ORDER BY started DESC LIMIT 10", (op["kind"],))]
        if len(d) >= MIN_SAMPLES:
            left = statistics.median(d) - op["elapsed_s"]
            op["eta_s"] = round(left) if left > 0 else None
            op["eta_basis"] = f"median of {len(d)} previous {op['kind']} runs"
    return op


def mark_interrupted(store) -> int:
    """At startup: operations left 'running' by a restarted web service are marked interrupted (never silently lost)."""
    return store.db.execute("UPDATE operation SET status='interrupted', finished=?, error=? WHERE status='running' AND kind NOT IN "
                            "('deploy','rollback','reset_demo')", (time.time(), "web service restarted during the operation")).rowcount


async def start(store, kind: str, title: str, actor: str, fn: Callable[[Op], Awaitable[Any]], ref: dict | None = None) -> dict:
    """Start `fn(op)` in the background unless an operation of the same exclusivity class is running."""
    group = EXCLUSIVE.get(kind, kind)
    for r in store.db.execute("SELECT kind, title, actor FROM operation WHERE status='running'"):
        if EXCLUSIVE.get(r["kind"], r["kind"]) == group:
            raise Busy(f"'{r['title']}' (started by {r['actor']}) is still running")
    row = {"id": uuid.uuid4().hex[:16], "kind": kind, "title": title, "status": "running", "actor": actor,
           "assessment_id": store.current()["id"], "started": time.time(), "finished": None, "current": "starting",
           "steps": "[]", "result": None, "error": None, "ref": json.dumps(ref or {})}
    store.db.execute("INSERT INTO operation VALUES (:id,:kind,:title,:status,:actor,:assessment_id,:started,:finished,:current,"
                     ":steps,:result,:error,:ref)", row)
    op = Op(store, row)

    async def runner():
        try:
            res = await fn(op)
            op.done("ok")
            partial = isinstance(res, dict) and res.pop("_partial", None)
            op._save(status="partial" if partial else "succeeded", finished=time.time(), result=res,
                     current=f"completed with errors: {partial}" if partial else "completed", error=partial or None)
        except Exception as e:  # recorded verbatim for the operator; never reported as success
            op.done("failed")
            detail = getattr(e, "detail", None) or str(e)
            op._save(status="failed", finished=time.time(), error=f"{type(e).__name__}: {detail}"[:1500], current="failed",
                     result={"trace": traceback.format_exc()[-1500:]})
    if INLINE:
        await runner()
    else:
        asyncio.get_running_loop().create_task(runner())
    return get(store, row["id"])
