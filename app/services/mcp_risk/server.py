"""Risk-scoring MCP server (deployed as two replicas: risk-scoring-1 / risk-scoring-2).

Real MCP over Streamable HTTP (stateful sessions for legacy-protocol clients; the SDK also serves
the stateless 2026-07-28 revision). Tools score synthetic transactions with a transparent
logistic model. Every result names the replica that produced it so load-balancing and failover
are observable end to end.
"""
from __future__ import annotations

import math
import os
import time

import uvicorn
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.responses import JSONResponse
from starlette.routing import Route

from aplab import telemetry

REPLICA = os.environ.get("REPLICA_ID", "risk-scoring-1")
MODEL_VERSION = "logit-risk-2026.10"
STARTED = time.time()
telemetry.setup("mcp-risk-scoring", **{"service.instance.id": REPLICA})

mcp = MCPServer(
    "risk-scoring",
    title="Transaction Risk Scoring",
    description="Scores transactions for fraud risk (synthetic model).",
    version=MODEL_VERSION,
    instructions="Call score_transaction with transaction features; higher score = higher fraud risk.",
)

HIGH_RISK_MCC = {"4829", "7995", "6051", "5944"}
WEIGHTS = {"intercept": -3.2, "log_amount": 0.42, "high_risk_mcc": 1.3, "foreign": 1.1,
           "wire_or_p2p": 0.6, "new_account": 0.9, "kyc_high": 0.8, "kyc_medium": 0.35, "velocity": 0.12}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def score_transaction(amount: float, mcc: str, country: str, home_country: str, channel: str,
                      account_age_days: int, kyc_risk: str = "low", recent_txn_count_24h: int = 0) -> dict:
    """Return a fraud-risk score (0-1), band and contributing factors for one transaction."""
    f = {
        "log_amount": math.log10(max(amount, 1.0)),
        "high_risk_mcc": 1.0 if mcc in HIGH_RISK_MCC else 0.0,
        "foreign": 1.0 if country != home_country else 0.0,
        "wire_or_p2p": 1.0 if channel in ("wire", "p2p") else 0.0,
        "new_account": 1.0 if account_age_days < 90 else 0.0,
        "kyc_high": 1.0 if kyc_risk == "high" else 0.0,
        "kyc_medium": 1.0 if kyc_risk == "medium" else 0.0,
        "velocity": float(min(recent_txn_count_24h, 20)),
    }
    z = WEIGHTS["intercept"] + sum(WEIGHTS[k] * v for k, v in f.items())
    score = 1 / (1 + math.exp(-z))
    contrib = sorted(((k, WEIGHTS[k] * v) for k, v in f.items() if v), key=lambda x: -x[1])
    band = "high" if score >= 0.7 else "elevated" if score >= 0.4 else "low"
    return {"score": round(score, 4), "band": band,
            "top_factors": [{"feature": k, "contribution": round(c, 3)} for k, c in contrib[:4]],
            "model_version": MODEL_VERSION, "replica": REPLICA}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def model_info() -> dict:
    """Describe the scoring model and the serving replica."""
    return {"model_version": MODEL_VERSION, "replica": REPLICA, "features": list(WEIGHTS)[1:],
            "uptime_s": int(time.time() - STARTED)}


def build_app():
    allowed = [h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "127.0.0.1:*,localhost:*").split(",") if h.strip()]
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=allowed),
    )

    async def healthz(_request):
        return JSONResponse({"status": "ok", "service": "risk-scoring", "replica": REPLICA,
                             "model_version": MODEL_VERSION})

    app.router.routes.append(Route("/healthz", healthz))
    return telemetry.asgi(app)


if __name__ == "__main__":
    uvicorn.run(build_app(), host=os.environ.get("BIND_HOST", "127.0.0.1"),
                port=int(os.environ.get("BIND_PORT", "8000")), proxy_headers=False, log_level="info")
