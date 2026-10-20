"""Risk Assessment Agent (Agent B) — A2A server.

Receives an investigation request from the Fraud Investigation Agent (Agent A) over A2A, gathers
evidence through MCP (fraud-intel: alert/account/transactions, RAG pattern search, S3 case file;
risk-scoring: per-transaction model scores), and asks the LLM for a structured assessment.
Progress is streamed as A2A task status updates; the result is returned as A2A artifacts.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime

import uvicorn
from a2a.helpers import get_message_text, new_task_from_user_message, new_text_message, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill, TaskState
from opentelemetry import trace
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from aplab import telemetry
from aplab.llm import LLM, LLMUnavailable

from .mcp_tools import MCP_MODE, mcp_session, result_data
from .classifier import calibrate_assessment, classify
from .scenario import ScenarioError, parse_request

tracer = telemetry.setup("agent-b-risk-assessment", **{"gen_ai.agent.name": "risk-assessment-agent"})
llm = LLM()

INTEL_URL = os.environ.get("MCP_INTEL_URL", "http://10.50.20.33:8000/mcp")
RISK_URL = os.environ.get("MCP_RISK_URL", "http://10.50.20.31:8000/mcp")
PUBLIC_URL = os.environ.get("A2A_PUBLIC_URL", "http://10.50.10.22:9000/")

SYSTEM = (
    "You are a bank fraud risk-assessment agent. Use ONLY the evidence provided (synthetic data). "
    "Return a JSON object with keys: decision (one of: escalate, monitor, close), risk_level (low|elevated|high), "
    "confidence (0-1), matched_patterns (list of pattern_id), rationale (max 80 words), recommended_actions (list of strings). "
    "The deterministic evidence classifier is an independent input, not ground truth. Do not invent a pattern when it abstains. "
    "If evidence conflicts or is missing, explain the uncertainty and prefer monitor/close over escalation."
)


def deterministic_assessment(evidence: dict) -> dict:
    """Clearly-labelled NON-LLM fallback: rules over the model scores. Used only if the LLM is unavailable."""
    scores = [s["score"] for s in evidence["scores"]]
    top = max(scores) if scores else 0
    level = "high" if top >= 0.7 else "elevated" if top >= 0.4 else "low"
    return {"decision": {"high": "escalate", "elevated": "monitor", "low": "close"}[level], "risk_level": level,
            "confidence": round(top, 2), "matched_patterns": [p["pattern_id"] for p in evidence["patterns"][:2]],
            "rationale": "Deterministic rule fallback (no LLM): decision derived from maximum model score.",
            "recommended_actions": ["Analyst review"], "generated_by": "deterministic-fallback (not an LLM)"}


def behavioral_signals(transactions: list[dict]) -> dict:
    """Derive observable behavior without using synthetic ground-truth labels."""
    times = []
    for t in transactions:
        try:
            times.append(datetime.fromisoformat(str(t["timestamp"]).replace("Z", "+00:00")))
        except (KeyError, TypeError, ValueError):
            pass
    span_minutes = round((max(times) - min(times)).total_seconds() / 60, 1) if len(times) > 1 else None
    amounts = [float(t.get("amount", 0)) for t in transactions]
    return {"transaction_count": len(transactions),
            "time_span_minutes": span_minutes,
            "transactions_per_hour": round(len(transactions) / (span_minutes / 60), 2) if span_minutes else None,
            "distinct_merchants_or_categories": len({t.get("merchant_id") or t.get("mcc") or t.get("category") for t in transactions}),
            "distinct_countries": sorted({t.get("country") for t in transactions if t.get("country")}),
            "channels": sorted({t.get("channel") for t in transactions if t.get("channel")}),
            "small_amount_count_under_5": sum(a < 5 for a in amounts),
            "near_reporting_threshold_count": sum(9000 <= a < 10000 for a in amounts),
            "total_amount": round(sum(amounts), 2)}


def compact(ev: dict, classification: dict | None = None) -> dict:
    """Small, decision-relevant evidence summary for the LLM (CPU inference cost scales with prompt size)."""
    a = ev["account"]
    return {
        "account": {k: a.get(k) for k in ("account_id", "segment", "home_country", "account_age_days", "kyc_risk", "avg_monthly_spend",
                                            "opened", "known_device_ids", "credential_change_at", "new_payee_id")},
        "flagged_transactions": [{"id": t["transaction_id"], "amount": t["amount"], "category": t.get("category"),
                                  "mcc": t.get("mcc"), "country": t["country"], "channel": t["channel"],
                                  "timestamp": t.get("timestamp"), "direction": t.get("direction"),
                                  "sender_id": t.get("sender_id"), "beneficiary_id": t.get("beneficiary_id"),
                                  "device_id": t.get("device_id"), "credential_event": t.get("credential_event")} for t in ev["alert"]["transactions"]],
        "behavioral_signals": behavioral_signals(ev["alert"]["transactions"]),
        "model_scores": [{"id": s["transaction_id"], "score": s["score"], "band": s["band"],
                          "factors": [f["feature"] for f in s["top_factors"][:3]]} for s in ev["scores"]],
        "similar_patterns": [{"pattern_id": p["pattern_id"], "name": p["name"], "similarity": p["score"]} for p in ev["patterns"]],
        "independent_evidence_classifier": ({
            "status": classification["status"],
            "dominant_pattern": (classification["dominant_pattern"] or {}).get("pattern_id"),
            "confidence": classification["confidence"],
            "normality_score": classification["normality_score"],
            "candidate_patterns": [{"pattern_id": p["pattern_id"], "score": p["score"], "evidence": p["evidence"]}
                                   for p in classification["candidate_patterns"][:5]],
            "reason": classification["reason"],
        } if classification else None),
        "closest_case_excerpt": (ev["case_file"] or {}).get("content", "")[:300],
    }


class RiskAssessmentExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        task = context.current_task or new_task_from_user_message(context.message)
        if not context.current_task:
            await event_queue.enqueue_event(task)
        up = TaskUpdater(event_queue=event_queue, task_id=task.id, context_id=task.context_id)
        text = get_message_text(context.message) or ""
        try:
            alert_id, inline = parse_request(text)
        except ScenarioError as e:
            await up.update_status(state=TaskState.TASK_STATE_FAILED, message=new_text_message(str(e)))
            return
        with tracer.start_as_current_span("assess_fraud_alert", attributes={
                "a2a.task.id": task.id, "aplab.alert_id": alert_id, "mcp.client.mode": MCP_MODE,
                "aplab.request": "scenario" if inline else "alert",
                "gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "risk-assessment-agent"}) as span:
            await self._run(up, alert_id, span, inline)

    async def _run(self, up: TaskUpdater, alert_id: str, span, inline: dict | None = None) -> None:
        t0 = time.time()

        async def status(msg: str) -> None:
            await up.update_status(state=TaskState.TASK_STATE_WORKING, message=new_text_message(msg))

        try:
            await status(f"Retrieving alert {alert_id} and account context via MCP (fraud-intel)")
            async with mcp_session(INTEL_URL) as intel:
                alert = inline or result_data(await intel.call_tool("get_alert", {"alert_id": alert_id}))
                acct = result_data(await intel.call_tool("get_account_profile", {"account_id": alert["account_id"]}))
                recent = result_data(await intel.call_tool("get_recent_transactions", {"account_id": alert["account_id"], "limit": 10}))
                await status("Searching fraud-pattern knowledge base (RAG)")
                signals = behavioral_signals(alert["transactions"])
                desc = ("; ".join(f"{t['amount']} USD {t['channel']} {t.get('category', t.get('mcc'))} in {t['country']}" for t in alert["transactions"])
                        + f"; velocity {signals['transaction_count']} transactions over {signals['time_span_minutes']} minutes"
                        + f"; {signals['distinct_merchants_or_categories']} distinct merchants/categories"
                        + f"; countries {','.join(signals['distinct_countries'])}"
                        + f"; directions {','.join(str(t.get('direction', 'unknown')) for t in alert['transactions'])}"
                        + f"; device changes {sum(1 for t in alert['transactions'] if t.get('device_id'))}")
                patterns = result_data(await intel.call_tool("search_fraud_patterns", {"query": desc, "top_k": 3}))
                case_doc = None
                if patterns:
                    await status("Fetching most similar closed case from object storage (S3)")
                    case_id = f"CASE-{7000 + int(patterns[0]['pattern_id'].split('-')[1]) - 1}"
                    case_doc = result_data(await intel.call_tool("get_case_document", {"case_id": case_id}))
            await status(f"Scoring {len(alert['transactions'])} transactions via MCP (risk-scoring)")
            scores = []
            async with mcp_session(RISK_URL) as risk:
                for t in alert["transactions"]:
                    s = result_data(await risk.call_tool("score_transaction", {
                        "amount": t["amount"], "mcc": t["mcc"], "country": t["country"],
                        "home_country": acct["home_country"], "channel": t["channel"],
                        "account_age_days": acct["account_age_days"], "kyc_risk": acct["kyc_risk"],
                        "recent_txn_count_24h": len(alert["transactions"])}))
                    scores.append({"transaction_id": t["transaction_id"], **s})
            evidence = {"alert": alert, "account": acct, "recent_transactions": recent, "patterns": patterns,
                        "case_file": case_doc, "scores": scores}
            classification = classify(alert, acct, recent, scores, patterns)
            await status(f"Synthesising assessment ({llm.describe()['provider']}:{llm.describe()['model']})")
            try:
                res = await llm.complete(SYSTEM, json.dumps(compact(evidence, classification), default=str), json_mode=True, max_tokens=320)
                assessment = res.json()
                assessment["generated_by"] = f"llm:{res.provider}:{res.model}"
            except (LLMUnavailable, ValueError) as e:
                assessment = deterministic_assessment(evidence)
                assessment["fallback_reason"] = str(e)[:200]
            assessment = calibrate_assessment(assessment, classification)
            result = {"alert_id": alert_id, "account_id": alert["account_id"], "assessment": assessment,
                      "behavioral_signals": behavioral_signals(alert["transactions"]),
                      "classification": classification,
                      "model_scores": scores, "rag_patterns": [{k: p[k] for k in ("pattern_id", "name", "score")} for p in patterns],
                      "case_file": case_doc and case_doc["case_id"],
                      "replicas_used": sorted({s["replica"] for s in scores}),
                      "elapsed_s": round(time.time() - t0, 2)}
            span.set_attribute("aplab.decision", str(assessment.get("decision")))
            await up.add_artifact(parts=[new_text_part(text=json.dumps(result), media_type="application/json")],
                                  name="risk-assessment")
            await up.update_status(state=TaskState.TASK_STATE_COMPLETED,
                                   message=new_text_message(f"{alert_id}: {assessment.get('decision')} ({assessment.get('risk_level')})"))
        except Exception as e:  # report failure through A2A instead of dropping the task
            span.record_exception(e)
            await up.update_status(state=TaskState.TASK_STATE_FAILED,
                                   message=new_text_message(f"Assessment failed: {type(e).__name__}: {e}"[:500]))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("cancel not supported")


def build_app():
    card = AgentCard(
        name="Risk Assessment Agent",
        description="Assesses fraud alerts using MCP tools (account intel, RAG fraud patterns, case files, risk model) and an LLM.",
        version="0.1.0",
        default_input_modes=["text/plain"], default_output_modes=["application/json", "text/plain"],
        capabilities=AgentCapabilities(streaming=True),
        supported_interfaces=[AgentInterface(protocol_binding="JSONRPC", url=PUBLIC_URL, protocol_version="1.0")],
        skills=[AgentSkill(id="assess_fraud_alert", name="Assess fraud alert",
                           description="Given an alert id (ALERT-nnnn), return decision, risk level and rationale.",
                           input_modes=["text/plain"], output_modes=["application/json"],
                           tags=["fraud", "risk", "mcp", "rag"], examples=["Assess ALERT-9001"])],
    )
    handler = DefaultRequestHandler(agent_executor=RiskAssessmentExecutor(), task_store=InMemoryTaskStore(), agent_card=card)

    async def healthz(_r):
        return JSONResponse({"status": "ok", "agent": "risk-assessment", "llm": llm.describe(), "mcp_mode": MCP_MODE,
                             "mcp_intel_url": INTEL_URL, "mcp_risk_url": RISK_URL})

    routes = [Route("/healthz", healthz)]
    routes.extend(create_agent_card_routes(card))
    routes.extend(create_jsonrpc_routes(handler, "/"))
    return telemetry.asgi(Starlette(routes=routes))


if __name__ == "__main__":
    uvicorn.run(build_app(), host=os.environ.get("BIND_HOST", "0.0.0.0"), port=int(os.environ.get("BIND_PORT", "9000")),
                log_level="info")
