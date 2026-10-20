"""Finding catalogue — single source of truth for how each assessment rule is classified, what evidence basis it
rests on, which package addresses it, and which validation tests must pass before it may be reported as resolved.

Classes:
  confirmed_vulnerability  an active, credential-less probe by the discovery sensor succeeded (exposure verified)
  architectural_gap        a missing delivery/security control established from configuration + discovery + telemetry
  inferred_risk            a likely problem derived from observed protocol behaviour (not directly exercised)
  contradicted_claim       a customer assertion (Describe) contradicted by technical evidence
"""
from __future__ import annotations

CLASSES = {
    "confirmed_vulnerability": "Confirmed vulnerability",
    "architectural_gap": "Architectural gap",
    "inferred_risk": "Inferred risk",
    "contradicted_claim": "Contradicted customer claim",
}

RULES: dict[str, dict] = {
    "D-001": {"issue": "MCP replicas without load balancing", "class": "architectural_gap", "package": "delivery",
              "basis": "Replicas fingerprinted by Enumerate; no BIG-IP pool covers them (Observe); traffic distribution from telemetry (Ingest).",
              "tests": ["delivery.load_distribution"]},
    "D-002": {"issue": "No health monitoring / failover for MCP replicas", "class": "architectural_gap", "package": "delivery",
              "basis": "No BIG-IP pool or monitor references the replicas (Observe).", "tests": ["delivery.failover"]},
    "D-003": {"issue": "Stateful MCP sessions need persistence", "class": "inferred_risk", "package": "delivery",
              "basis": "Inferred from negotiated MCP protocol versions (initialize + Mcp-Session-Id) seen in telemetry.",
              "tests": ["delivery.session_persistence"]},
    "D-004": {"issue": "A2A agent served without an ADC", "class": "architectural_gap", "package": "delivery",
              "basis": "A2A tasks observed reaching the agent directly (Ingest) while no virtual server fronts it (Observe).",
              "tests": ["a2a.via_front_door"]},
    "D-005": {"issue": "Long-lived A2A streams need extended timeouts", "class": "inferred_risk", "package": "delivery",
              "basis": "Inferred from observed A2A task durations (Ingest).", "tests": ["a2a.via_front_door", "a2a.streaming"]},
    "D-006": {"issue": "AI data service (S3 / vector DB / LLM) served without an ADC", "class": "architectural_gap", "package": "data",
              "basis": "Enumerate fingerprinted the object store, vector database or LLM endpoint; no BIG-IP pool fronts it (Observe). "
                       "Raised only when the AI Data Delivery pattern is enabled (design.data_delivery).",
              "tests": ["data.pools_healthy", "data.s3_via_front_door", "data.s3_sigv4_enforced", "data.rag_via_front_door",
                        "data.llm_via_front_door", "data.bigip_statistics"]},
    "S-001": {"issue": "Traffic bypasses BIG-IP", "class": "architectural_gap", "package": "security",
              "basis": "Telemetry shows clients reaching backends directly although an ADC is present (Ingest + Observe).",
              "tests": ["security.direct_backend_blocked", "security.agent_b_direct_blocked"]},
    "S-002": {"issue": "MCP server accepts unauthenticated clients", "class": "confirmed_vulnerability", "package": "security",
              "basis": "Discovery sensor completed MCP initialize + tools/list without credentials (Enumerate).",
              "tests": ["security.unauthenticated_rejected"]},
    "S-003": {"issue": "Privileged MCP tools exposed beyond observed need", "class": "confirmed_vulnerability", "package": "security",
              "basis": "Unauthenticated tools/list exposes destructive tools that no observed agent uses (Enumerate + Ingest).",
              "tests": ["security.unauthorized_tool_denied"]},
    "S-004": {"issue": "A2A agent advertises no authentication", "class": "architectural_gap", "package": None,
              "basis": "Agent Card declares no securitySchemes (Enumerate).", "tests": [],
              "not_addressed": "Requires mTLS on the A2A virtual server plus a client certificate for Agent A and a securitySchemes "
                               "entry in Agent B's card — a host-profile change on AP-AGENT-A/AP-AGENT-B that is designed "
                               "(docs/40) but not yet approved. Reported as remaining."},
    "S-005": {"issue": "Agent Card advertises its direct endpoint", "class": "architectural_gap", "package": "delivery",
              "basis": "Card URL points at the agent's own address (Enumerate).", "tests": ["a2a.card_advertises_front_door"]},
    "S-006": {"issue": "Vector database readable without authentication", "class": "confirmed_vulnerability", "package": None,
              "basis": "Collections listed without an API key (Enumerate).", "tests": [],
              "not_addressed": "The vector database is not fronted by BIG-IP in this design; needs a Qdrant API key or a future "
                               "vector-DB virtual-server pattern."},
    "S-007": {"issue": "Customer assertion contradicted by telemetry", "class": "contradicted_claim", "package": "delivery",
              "basis": "A Describe claim is contradicted by observed paths or probe results.",
              "tests": ["a2a.via_front_door", "mcp.via_front_door"]},
    "S-008": {"issue": "LLM endpoint without authentication or rate limiting", "class": "confirmed_vulnerability", "package": None,
              "basis": "Models listed and invocable without credentials (Enumerate).", "tests": [],
              "not_addressed": "LLM endpoint protection is outside the AI Delivery/Security packages; candidate for an LLM "
                               "gateway pattern (see docs/41 future AI traffic discovery)."},
    "S-009": {"issue": "No rate limiting on MCP calls", "class": "architectural_gap", "package": "security",
              "basis": "MCP calls observed with no rate-limiting policy in the path (Ingest + Observe).", "tests": ["security.rate_limited"]},
}

RULE_TESTS = {r: m["tests"] for r, m in RULES.items() if m["tests"]}


def closes(package: str) -> set[str]:
    return {r for r, m in RULES.items() if m["package"] == package}


# S-007: which package/tests can settle a contradicted claim depends on the claim itself
S007_BY_CLAIM = {
    "behind_bigip": ("delivery", ["a2a.via_front_door", "mcp.via_front_door"]),
    "load_balanced": ("delivery", ["delivery.load_distribution"]),
    "health_monitored": ("delivery", ["delivery.failover"]),
    "authenticated": ("security", ["security.unauthenticated_rejected", "security.unknown_identity_denied"]),
    "rate_limited": ("security", ["security.rate_limited"]),
}


def meta(rule: str, title: str = "") -> dict:
    m = dict(RULES.get(rule, {"issue": rule, "class": "architectural_gap", "package": None, "basis": "", "tests": []}))
    if rule == "S-007":
        claim = next((c for c in S007_BY_CLAIM if f"'{c}'" in title), None)
        if claim:
            m["package"], m["tests"] = S007_BY_CLAIM[claim]
        else:
            m["package"], m["tests"] = None, []
            m["not_addressed"] = "the contradicted claim is not machine-verifiable; resolve with the customer"
    return {**m, "class_label": CLASSES[m["class"]]}


def tests_for(rule: str, title: str = "") -> list[str]:
    return meta(rule, title)["tests"]
