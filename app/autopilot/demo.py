"""Guided-demo narrative (served by the API so the UI stays free of hard-coded topology)."""
from __future__ import annotations

HERO = {
    "exec": "A synthetic bank runs an AI fraud-investigation application: one AI agent delegates cases to another, which calls AI tools (MCP) "
            "for data, scoring and knowledge. Today it works — but traffic is unprotected, unbalanced and invisible. Watch Autopilot discover it, "
            "recommend F5 controls, deploy them with human approval, and prove the result.",
    "tech": "Agent A (A2A client) → Agent B (A2A 1.0 server, SSE streaming) → MCP risk-scoring (2 replicas, stateful sessions) and MCP "
            "fraud-intel (Qdrant RAG, S3 case files) + local LLM. Autopilot discovers it from BIG-IP config, DNS/protocol handshakes and "
            "OpenTelemetry, generates AS3 from a vetted pattern library, deploys through a hash-bound approval and a time-boxed live window, "
            "then validates and compares with live tests and traces.",
}
EXPERIENCES = [
    {"n": 1, "page": "fraud", "title": "Fraud application — before F5",
     "exec": "See the bank's AI agents investigate a suspicious transaction in real time — and what is missing: no load balancing, no identity, no single point of control.",
     "tech": "Run a real investigation: Agent A → A2A → Agent B → MCP tools (risk-scoring ×2, fraud-intel with RAG + S3) → LLM. Inspect the live trace: direct paths, which replica answered, latency and errors."},
    {"n": 2, "page": "discover", "title": "Autopilot discovery & assessment",
     "exec": "Autopilot maps the AI application from what the network, DNS, telemetry and the customer say — and flags where reality contradicts the customer's beliefs.",
     "tech": "Observe (BIG-IP read-only), Describe (LLM extraction), Enumerate (approved-scope MCP/A2A handshakes), Ingest (OpenTelemetry). Deterministic rules classify confirmed vulnerabilities, architectural gaps, inferred risks and contradicted claims."},
    {"n": 3, "page": "recommend", "title": "AI Delivery",
     "exec": "F5 puts a resilient front door in front of the agents and tools: load balancing, health-checked failover and session-aware routing — approved by a human.",
     "tech": "AS3 tenant AP_AI: A2A + MCP virtual servers, MCP protocol monitors (server/discover), Mcp-Session-Id persistence, SSE-safe profiles. Preview/diff/preflight → approval → deploy with read-back verification and convergence."},
    {"n": 4, "page": "recommend", "title": "AI Security",
     "exec": "Only trusted agents may use the AI tools, each only the tools it needs, at a safe rate — and nobody can bypass F5.",
     "tech": "mTLS agent identity on MCP VIPs, per-identity tool allow-lists from observed usage (fail-closed iRule), per-identity rate limiting, backend lockdown to the BIG-IP self IP. Blocked until Delivery is validated."},
    {"n": 5, "page": "validate", "title": "Validation & observability",
     "exec": "Live tests prove the controls work: failover, persistence, blocked attackers, rate limits — and the same investigation still succeeds.",
     "tech": "Validation suite per profile (A2A/MCP via VIPs, LB distribution, persistence, monitor-driven failover, authN/authZ failures, 429s, bypass probes, trace propagation, latency measurements)."},
    {"n": 6, "page": "observe", "title": "Before / after comparison",
     "exec": "An evidence-backed before/after: what changed, what was proven, what remains — with an executive summary to hand to the customer.",
     "tech": "Rediscovery + comparison: resolved only with a successful linked deployment AND passing proving tests; topology changes, BIG-IP coverage, equivalent-workload performance, evidence bundle export."},
]
VALUE = {
    "exec": ["Resilience: agents and tools keep working when a replica fails", "Security: only authorised agents can call each AI tool — at a safe rate",
             "Control: one policy point for agent-to-agent and agent-to-tool traffic", "Proof: every claim backed by live tests, traces and an audit trail"],
    "tech": ["Protocol-aware delivery for A2A (SSE) and MCP (stateless + stateful sessions)", "Identity-aware MCP tool authorisation (mTLS CN → allow-list), fail-closed parsing",
             "Rate limiting per agent identity; backend lockdown removes bypass paths", "Read-back verification, convergence barrier, automatic rollback, append-only audit"],
}


def content() -> dict:
    return {"hero": HERO, "experiences": EXPERIENCES, "value": VALUE}
