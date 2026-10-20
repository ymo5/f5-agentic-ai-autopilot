"""Explicit BIG-IP control evidence used by assessment and claim verification.

An attached iRule is not a capability.  The Observe model exposes the
configuration objects, while control capability evidence must be supplied in
the structured ``capabilities`` field by a supported collector or validation
result.  This keeps persistence, authentication, authorization and rate
limiting independent and makes an unverified control conservative.
"""
from __future__ import annotations

CAPABILITIES = ("persistence", "authentication", "tool_authorization", "rate_limiting")


def _entry(asset: dict, capability: str):
    attrs = asset.get("attrs") or {}
    controls = attrs.get("capabilities")
    if not isinstance(controls, dict):
        controls = attrs.get("controls")
    return controls.get(capability) if isinstance(controls, dict) else None


def status(asset: dict, capability: str) -> str:
    """Return ``present``, ``absent`` or ``unknown`` for one explicit control.

    Boolean/nameless entries are deliberately not accepted as proof.  A
    positive control claim needs a verified status and at least one evidence
    id, so an arbitrary rule name or generic attachment cannot suppress a
    finding.
    """
    if capability not in CAPABILITIES:
        raise ValueError(f"unsupported capability: {capability}")
    if capability == "persistence" and (asset.get("attrs") or {}).get("persist"):
        return "present"
    entry = _entry(asset, capability)
    if isinstance(entry, dict):
        evidence = entry.get("evidence_ids") or entry.get("evidence") or []
        if entry.get("status") in ("verified", "present") and evidence:
            return "present"
        if entry.get("status") in ("absent", "not_present"):
            return "absent"
    return "unknown"


def aggregate(assets: list[dict], capability: str) -> str:
    states = [status(a, capability) for a in assets if a.get("kind") == "bigip_virtual"]
    if "present" in states:
        return "present"
    if states and all(s == "absent" for s in states):
        return "absent"
    return "unknown"


def evidence_ids(assets: list[dict], capability: str) -> list[str]:
    out: list[str] = []
    for asset in assets:
        if asset.get("kind") != "bigip_virtual" or status(asset, capability) != "present":
            continue
        entry = _entry(asset, capability) or {}
        for eid in entry.get("evidence_ids") or entry.get("evidence") or []:
            if eid not in out:
                out.append(eid)
    return out
