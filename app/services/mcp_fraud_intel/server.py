"""Fraud-intelligence MCP server.

Tools over the SYNTHETIC dataset, RAG (Qdrant + embeddings from the lab LLM host) and case files
in S3-compatible storage. It intentionally also exposes two privileged tools (freeze_account,
export_customer_data) that the Risk Assessment Agent does not need — the realistic
"excessive agent permissions" condition the Autopilot security assessment should detect.
Privileged actions only change in-memory synthetic state.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

import boto3
import httpx
import uvicorn
from botocore.config import Config
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
from qdrant_client import QdrantClient
from starlette.responses import JSONResponse
from starlette.routing import Route

from aplab import telemetry

telemetry.setup("mcp-fraud-intel", **{"service.instance.id": "fraud-intel-1"})
BotocoreInstrumentor().instrument()

DATA = json.load(open(os.environ.get("APLAB_DATA", "/data/synthetic.json")))
ACCOUNTS = {a["account_id"]: a for a in DATA["accounts"]}
MERCHANTS = {m["merchant_id"]: m for m in DATA["merchants"]}
ALERTS = {a["alert_id"]: a for a in DATA["alerts"]}
TXNS_BY_ACCOUNT: dict[str, list] = {}
for t in DATA["transactions"]:
    TXNS_BY_ACCOUNT.setdefault(t["account_id"], []).append(t)
FROZEN: dict[str, dict] = {}

QDRANT_URL = os.environ.get("QDRANT_URL", "http://10.50.20.40:6333")
EMBED_URL = os.environ.get("EMBED_URL", "http://10.50.20.45:11434")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")
COLLECTION = os.environ.get("RAG_COLLECTION", "fraud_patterns")
S3_BUCKET = os.environ.get("S3_BUCKET", "case-files")

qdrant = QdrantClient(url=QDRANT_URL, timeout=10)
s3 = boto3.client("s3", endpoint_url=os.environ.get("S3_ENDPOINT", "http://10.50.20.41:8333"),
                  aws_access_key_id=os.environ.get("S3_ACCESS_KEY"), aws_secret_access_key=os.environ.get("S3_SECRET_KEY"),
                  region_name="us-east-1", config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 2}))

mcp = MCPServer("fraud-intel", title="Fraud Intelligence", version="2026.10",
                description="Account context, fraud-pattern retrieval (RAG) and case files for investigations (synthetic data).")


def embed(text: str) -> list[float]:
    r = httpx.post(f"{EMBED_URL}/api/embed", json={"model": EMBED_MODEL, "input": text}, timeout=60)
    r.raise_for_status()
    return r.json()["embeddings"][0]


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def list_open_alerts() -> list[dict]:
    """List open fraud alerts awaiting investigation."""
    return [{"alert_id": a["alert_id"], "account_id": a["account_id"], "transactions": len(a["transaction_ids"]),
             "trigger": a["trigger"]} for a in ALERTS.values()]


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_alert(alert_id: str) -> dict:
    """Return an alert with its flagged transactions (enriched with merchant data)."""
    a = ALERTS.get(alert_id)
    if not a:
        raise ValueError(f"unknown alert {alert_id}")
    txns = [t for t in TXNS_BY_ACCOUNT[a["account_id"]] if t["transaction_id"] in a["transaction_ids"]]
    return {**a, "transactions": [{**{k: v for k, v in t.items() if k != "label"},
                                   "merchant": MERCHANTS[t["merchant_id"]]["name"],
                                   "category": MERCHANTS[t["merchant_id"]]["category"]} for t in txns]}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_account_profile(account_id: str) -> dict:
    """Return the synthetic account profile and derived behavioural baseline."""
    a = ACCOUNTS.get(account_id)
    if not a:
        raise ValueError(f"unknown account {account_id}")
    opened = datetime.fromisoformat(a["opened"]).replace(tzinfo=timezone.utc)
    hist = TXNS_BY_ACCOUNT.get(account_id, [])
    return {**a, "account_age_days": (datetime(2026, 10, 1, tzinfo=timezone.utc) - opened).days,
            "txn_count_30d": len(hist), "countries_30d": sorted({t["country"] for t in hist}),
            "frozen": account_id in FROZEN}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_recent_transactions(account_id: str, limit: int = 15) -> list[dict]:
    """Return the most recent transactions for an account (labels withheld)."""
    hist = sorted(TXNS_BY_ACCOUNT.get(account_id, []), key=lambda t: t["timestamp"], reverse=True)[:max(1, min(limit, 50))]
    return [{k: v for k, v in t.items() if k != "label"} for t in hist]


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def search_fraud_patterns(query: str, top_k: int = 3) -> list[dict]:
    """Semantic search over the fraud-pattern knowledge base (RAG via Qdrant)."""
    hits = qdrant.query_points(COLLECTION, query=embed(query), limit=max(1, min(top_k, 5)), with_payload=True).points
    return [{"pattern_id": h.payload["pattern_id"], "name": h.payload["name"], "text": h.payload["text"],
             "score": round(h.score, 4)} for h in hits]


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_case_document(case_id: str) -> dict:
    """Fetch a closed investigation case file from object storage (S3)."""
    obj = s3.get_object(Bucket=S3_BUCKET, Key=f"{case_id}.txt")
    return {"case_id": case_id, "content": obj["Body"].read().decode()[:4000],
            "etag": obj.get("ETag"), "bucket": S3_BUCKET}


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True, readOnlyHint=False))
def freeze_account(account_id: str, reason: str) -> dict:
    """PRIVILEGED: freeze an account (synthetic state only). Not required for risk assessment."""
    if account_id not in ACCOUNTS:
        raise ValueError(f"unknown account {account_id}")
    FROZEN[account_id] = {"reason": reason, "at": time.time()}
    return {"account_id": account_id, "frozen": True}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def export_customer_data(account_id: str) -> dict:
    """PRIVILEGED: export the full customer record and transaction history (synthetic)."""
    return {"profile": ACCOUNTS.get(account_id), "transactions": TXNS_BY_ACCOUNT.get(account_id, [])}


def build_app():
    allowed = [h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "127.0.0.1:*,localhost:*").split(",") if h.strip()]
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=allowed),
    )

    async def healthz(_request):
        return JSONResponse({"status": "ok", "service": "fraud-intel"})

    app.router.routes.append(Route("/healthz", healthz))
    return telemetry.asgi(app)


if __name__ == "__main__":
    uvicorn.run(build_app(), host=os.environ.get("BIND_HOST", "127.0.0.1"),
                port=int(os.environ.get("BIND_PORT", "8000")), log_level="info")
