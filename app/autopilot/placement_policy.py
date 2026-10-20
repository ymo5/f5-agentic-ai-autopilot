"""Wave 3 M2 — versioned placement health policies (advisory; never enforced on a device).

Placement health thresholds are reconciled with the deployer's preflight resource checks (deployer/engine.py) WITHOUT
changing them: a placement policy may only be equal to or stricter than preflight's fail levels, so placement never
recommends a device that preflight would refuse for the same metric AT THE SAME MOMENT. A recommendation is still not a
readiness verdict: health changes over time and preflight checks more than health. Preflight stays the only enforcement point.

Freshness (v1.1): a health sample older than max_sample_age_s (1800 s) is STALE — the health check is unknown, exactly
like a missing sample, and the device can only be an unverified candidate.

  preflight (enforced at deploy time)          placement-health/v1 (advisory, at recommendation time)
  control-plane memory  fail >= 95 %           fail >= 95 %                   (required metric)
  swap                  warn >= 75, fail >= 95 warn >= 75, fail >= 95         (required metric)
  REST latency          warn >= 2 s, fail >= 10 warn >= 2 s, fail >= 10 s     (required metric)
  CPU                   no check               warn >= 90 % (placement-only, never a fail)

Semantics follow preflight: a value >= threshold triggers. A required metric that is not in the evidence makes the health
check UNKNOWN (the device is an unverified candidate). Warnings never reject a device; they rank it lower.

A deployment may select another built-in version or a stricter override in autopilot.yaml (optional; absent today):
    placement: {health_policy: placement-health/v1}
    placement: {health_policy: {base: placement-health/v1, metrics: {swap_pct: {warn: 50}}}}
"""
from __future__ import annotations

import copy
import hashlib
import json

# Mirror of the deployer's preflight fail levels (deployer/engine.py MEMORY_FAIL_PCT, SWAP_FAIL_PCT, REST_FAIL_S and the
# warn levels). Kept as data here so the web side never imports the deployer; a test fails if the two drift apart.
PREFLIGHT = {"control_plane_memory_pct": {"fail": 95.0, "warn": None, "check": "resource.control_plane_memory"},
             "swap_pct": {"fail": 95.0, "warn": 75.0, "check": "resource.control_plane_memory"},
             "rest_latency_s": {"fail": 10.0, "warn": 2.0, "check": "resource.rest_latency"}}

POLICIES = {
    "placement-health/v1": {
        "version": "placement-health/v1",
        "status": "proposed — aligned with deployer preflight 2026-10-13; awaiting owner approval",
        "metrics": {
            "control_plane_memory_pct": {"fail": 95.0, "warn": None, "required": True, "unit": "%",
                                         "label": "control-plane (Other) memory used"},
            "swap_pct": {"fail": 95.0, "warn": 75.0, "required": True, "unit": "%", "label": "swap used"},
            "rest_latency_s": {"fail": 10.0, "warn": 2.0, "required": True, "unit": "s", "label": "iControl REST latency"},
            "cpu_pct": {"fail": None, "warn": 90.0, "required": False, "unit": "%", "label": "CPU (placement-only; preflight has no CPU check)"},
        },
        "ha_usable": ["active", "standalone"],
        "member_route_domain": 0,
        "max_sample_age_s": None,
    },
}
# v1.1 = v1 thresholds + a health freshness limit: a sample older than 30 min is STALE (the health check becomes unknown)
POLICIES["placement-health/v1.1"] = {**copy.deepcopy(POLICIES["placement-health/v1"]), "version": "placement-health/v1.1",
                                     "status": "proposed — v1 thresholds + 30-minute health freshness; awaiting owner approval",
                                     "max_sample_age_s": 1800}
DEFAULT = "placement-health/v1.1"


class PolicyError(ValueError):
    pass


def _validate(p: dict) -> None:
    for k, m in p["metrics"].items():
        for lvl in ("fail", "warn"):
            if m.get(lvl) is not None and not isinstance(m[lvl], (int, float)):
                raise PolicyError(f"{k}.{lvl} must be a number")
        if m.get("fail") is not None and m.get("warn") is not None and m["warn"] > m["fail"]:
            raise PolicyError(f"{k}: warn {m['warn']} above fail {m['fail']}")
        pf = PREFLIGHT.get(k)
        if pf and (m.get("fail") is None or m["fail"] > pf["fail"]):
            raise PolicyError(f"{k}: placement fail level {m.get('fail')} is looser than preflight ({pf['fail']}) — "
                              "a placement policy may only be equal to or stricter than preflight")


def load(cfg: dict | None = None) -> dict:
    """The active placement health policy (a copy), validated, with a content digest."""
    sel = ((cfg or {}).get("placement") or {}).get("health_policy") or DEFAULT
    if isinstance(sel, str):
        if sel not in POLICIES:
            raise PolicyError(f"unknown placement health policy {sel!r}")
        p, origin = copy.deepcopy(POLICIES[sel]), "built-in"
    else:
        base = sel.get("base") or DEFAULT
        if base not in POLICIES:
            raise PolicyError(f"unknown base policy {base!r}")
        p = copy.deepcopy(POLICIES[base])
        base_age = p.get("max_sample_age_s")
        for k, ov in (sel.get("metrics") or {}).items():
            if k not in p["metrics"]:
                raise PolicyError(f"unknown metric {k!r}")
            p["metrics"][k].update({x: ov[x] for x in ("fail", "warn", "required") if x in ov})
        if "max_sample_age_s" in sel:
            if base_age is not None and (sel["max_sample_age_s"] is None or sel["max_sample_age_s"] > base_age):
                raise PolicyError(f"max_sample_age_s may only be shortened (base {base_age} s)")
            p["max_sample_age_s"] = sel["max_sample_age_s"]
        p["version"] = f"{base}+override"
        origin = "autopilot.yaml placement.health_policy (override)"
    _validate(p)
    p["origin"] = origin
    p["preflight_reference"] = PREFLIGHT
    if p.get("max_sample_age_s") is not None and not (isinstance(p["max_sample_age_s"], (int, float)) and p["max_sample_age_s"] > 0):
        raise PolicyError("max_sample_age_s must be a positive number of seconds")
    # LAB-ONLY: devices whose swap % is informational (reported, never fail/warn/required) — mirrors the deployer preflight.
    # Absent from autopilot.yaml (production default) -> empty list and an unchanged digest.
    p["swap_informational_devices"] = sorted({str(x) for x in (((cfg or {}).get("lab_policy") or {}).get("swap_informational_devices") or [])})
    keys = ("version", "metrics", "ha_usable", "member_route_domain", "max_sample_age_s") + (("swap_informational_devices",) if p["swap_informational_devices"] else ())
    p["digest"] = hashlib.sha256(json.dumps({k: p[k] for k in keys}, sort_keys=True).encode()).hexdigest()[:16]
    return p
