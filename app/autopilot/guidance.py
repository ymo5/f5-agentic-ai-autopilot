"""Finding guidance — business impact, mitigation, proposed BIG-IP control, confidence basis and limitations per rule.

Presentation only: it never changes which findings are produced, their severity, or any package. Wording stays within what
the evidence can support: a configuration finding is not presented as a demonstrated exploit, and every entry states what
was NOT established. The proposed control names the pattern-library control that the existing packages use, or says
plainly that no vetted pattern exists yet.
"""
from __future__ import annotations

CONFIDENCE = {
    "confirmed_vulnerability": ("high", "the discovery sensor exercised the condition directly (an unauthenticated protocol "
                                        "request succeeded)"),
    "architectural_gap": ("medium-high", "established from BIG-IP configuration (Observe) together with discovery and telemetry"),
    "inferred_risk": ("medium", "inferred from observed protocol behaviour; not exercised directly"),
    "contradicted_claim": ("high", "a customer statement is contradicted by technical evidence"),
}

GUIDANCE: dict[str, dict] = {
    "D-001": {"impact": "Fraud scoring capacity and availability depend on whichever replica happens to receive traffic; "
                        "if it fails, fraud decisions that need the scoring tool fail with it.",
              "mitigation": "Load-balance the MCP replicas behind one front door.",
              "control": "AI Delivery: HTTPS virtual server + least-connections pool for the MCP service",
              "limitations": "Distribution across replicas is proven only after deployment (validation test delivery.load_distribution)."},
    "D-002": {"impact": "A failed replica keeps receiving requests, so tool calls made during an investigation fail instead of "
                        "moving to a healthy replica.",
              "mitigation": "Monitor each replica at the MCP protocol level and remove unhealthy ones automatically.",
              "control": "AI Delivery: MCP-aware HTTP monitor (server/discover) on the pool",
              "limitations": "Failover is proven only after deployment (validation test delivery.failover)."},
    "D-003": {"impact": "Session-based MCP clients can lose their session when consecutive requests reach different replicas, "
                        "which shows up as intermittent tool errors.",
              "mitigation": "Keep each MCP session on the replica that created it.",
              "control": "AI Delivery: universal persistence on Mcp-Session-Id (iRule)",
              "limitations": "Inferred from negotiated protocol versions in telemetry; proven by delivery.session_persistence after deployment."},
    "D-004": {"impact": "Agent-to-agent traffic has no availability, TLS or visibility control point.",
              "mitigation": "Put the A2A agent behind a monitored front door.",
              "control": "AI Delivery: HTTPS virtual server + pool with an Agent Card health monitor",
              "limitations": "Only observed A2A paths are evaluated; proven by a2a.via_front_door after deployment."},
    "D-005": {"impact": "Long-running A2A tasks can be cut off by default idle timeouts once a front door is introduced.",
              "mitigation": "Use streaming-safe HTTP settings and longer idle timeouts on the A2A path.",
              "control": "AI Delivery: TCP profile idle timeout 900 s; HTTP profile with chunking 'sustain' (SSE-safe)",
              "limitations": "Inferred from observed task durations; proven by a2a.streaming after deployment."},
    "D-006": {"impact": "Training data, retrieval and inference traffic has no health-monitored front door and no request telemetry.",
              "mitigation": "Put the object store, vector database and LLM endpoint behind monitored virtual servers.",
              "control": "AI Data Delivery: HTTP virtual servers + pools with service health monitors; observe-only S3 request statistics",
              "limitations": "Fronting does not by itself force clients through BIG-IP (backends stay directly reachable until a "
                             "separately approved lockdown) and adds no authentication; proven by the data.* checks of after-data."},
    "S-001": {"impact": "Controls applied at BIG-IP can be bypassed by calling the backends directly.",
              "mitigation": "Accept backend connections only from the BIG-IP.",
              "control": "AI Security: backend lockdown to the BIG-IP self IP (host-profile step) after the front door exists",
              "limitations": "Based on observed traffic paths; paths that were not observed are not evaluated."},
    "S-002": {"impact": "Any client that can reach the service can use the fraud tools without presenting an identity.",
              "mitigation": "Require client identity before any MCP request is accepted.",
              "control": "AI Security: mutual TLS (client certificates) on the MCP virtual server",
              "limitations": "Shows that protocol operations (initialize, tools/list) work without credentials; it does not by itself "
                             "show the business effect of any particular tool call."},
    "S-003": {"impact": "Destructive tools are reachable by callers that never need them, widening the effect of a misused "
                        "or compromised agent.",
              "mitigation": "Allow each identity only the tools it has been observed to use; deny destructive tools by default.",
              "control": "AI Security: per-identity MCP tool allow-list (iRule); destructive tools denied",
              "limitations": "'Observed need' comes from the telemetry window available; legitimate but unobserved usage may be blocked "
                             "and must be reviewed before approval."},
    "S-004": {"impact": "Any client can submit tasks to the risk assessment agent.",
              "mitigation": "Authenticate A2A clients (mTLS) and declare the scheme in the Agent Card.",
              "control": None,
              "limitations": "No package in this iteration: the mTLS design (docs/40) needs agent and host-profile changes that are not approved."},
    "S-005": {"impact": "Clients that follow the Agent Card go straight to the agent and bypass the front door.",
              "mitigation": "Advertise the front-door name in the Agent Card.",
              "control": "AI Delivery: host-profile step that switches the card URL to the front-door name",
              "limitations": "Proven by a2a.card_advertises_front_door after deployment."},
    "S-006": {"impact": "Stored fraud-intelligence vectors can be read without authentication.",
              "mitigation": "Enable an API key on the vector database or front it with an access-controlled pattern.",
              "control": None,
              "limitations": "Not fronted by BIG-IP in this design; reported as remaining."},
    "S-007": {"impact": "A statement about the environment is wrong, so decisions based on it may be unsafe.",
              "mitigation": "Correct the statement with the customer; the technical evidence takes precedence.",
              "control": "Depends on the contradicted claim (see each finding)",
              "limitations": "Free-text claims are interpreted; a claim that cannot be checked technically is not resolved automatically."},
    "S-008": {"impact": "The model can be invoked without credentials (cost, abuse and data-exposure risk).",
              "mitigation": "Require authentication and rate limits on the LLM endpoint.",
              "control": None,
              "limitations": "Outside the current AI Delivery/Security packages; candidate for a future LLM-gateway pattern (docs/41)."},
    "S-009": {"impact": "A misbehaving or compromised agent can flood the fraud tools and degrade investigations for everyone.",
              "mitigation": "Limit request rates per caller identity.",
              "control": "AI Security: per-identity rate limiting (iRule)",
              "limitations": "The limit value is a design default; validate it against real traffic before approval (security.rate_limited)."},
}


def for_rule(rule: str, cls: str | None) -> dict:
    g = GUIDANCE.get(rule) or {"impact": None, "mitigation": None, "control": None, "limitations": "no guidance recorded for this rule"}
    level, basis = CONFIDENCE.get(cls or "", ("unknown", "classification unknown"))
    return {**g, "confidence": level, "confidence_basis": basis,
            "control_status": "pattern-library control in the current packages" if g.get("control") else "no vetted control in this iteration"}
