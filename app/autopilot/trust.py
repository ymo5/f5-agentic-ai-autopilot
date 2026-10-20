"""Evidence provenance / trust levels shown next to every claim, asset and relationship.

The level is derived from HOW a fact was obtained, never from what it says. LLM-interpreted customer statements are
always 'customer_assertion' (unverified) no matter how confident the model sounded.
"""
from __future__ import annotations

LEVELS = {
    "customer_assertion": {"label": "Customer-provided assertion", "rank": 1, "verified": False,
                           "meaning": "Stated by the customer/SE (optionally interpreted by the LLM). Not independently verified."},
    "hypothesis": {"label": "Unverified hypothesis", "rank": 1, "verified": False,
                   "meaning": "A possibility raised by Autopilot that no evidence confirms yet."},
    "inferred": {"label": "Inferred relationship", "rank": 2, "verified": False,
                 "meaning": "Derived by Autopilot from other evidence (e.g. grouping, attribution, reconciliation) — not observed directly."},
    "dns_metadata": {"label": "DNS metadata", "rank": 2, "verified": False,
                     "meaning": "A DNS record names this address. DNS proves a name exists, not what the service is."},
    "configured_inventory": {"label": "Approved inventory (configuration)", "rank": 2, "verified": False,
                             "meaning": "Listed in the engagement's approved inventory/configuration; not probed."},
    "protocol_fingerprint": {"label": "Active protocol fingerprint", "rank": 3, "verified": True,
                             "meaning": "Autopilot connected and the service answered a protocol handshake (Agent Card, MCP initialize, API probe)."},
    "otel_observation": {"label": "OpenTelemetry observation", "rank": 3, "verified": True,
                         "meaning": "Seen in real distributed traces emitted by the workloads."},
    "bigip_config": {"label": "BIG-IP configuration observation", "rank": 3, "verified": True,
                     "meaning": "Read from BIG-IP's configuration through the read-only account."},
}


def level(source: str, method: str | None = None) -> str:
    m = (method or "").lower()
    if source == "describe":
        return "inferred" if m == "reconciliation" else "customer_assertion"
    if source == "observe":
        return "bigip_config"
    if source == "ingest":
        return "otel_observation"
    if source == "enumerate":
        if "dns" in m:
            return "dns_metadata"
        if "inventory" in m:
            return "configured_inventory"
        return "protocol_fingerprint"
    return "hypothesis"


def describe(source: str, method: str | None = None) -> dict:
    k = level(source, method)
    return {"level": k, **LEVELS[k]}


def rel_level(kind: str, source: str, method: str | None = None) -> str:
    """Relationships Autopilot derives by grouping (replicas) or from card adverts are inferences, not observations."""
    if kind == "has_replica":
        return "inferred"
    return level(source, method)
