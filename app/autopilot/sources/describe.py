"""DESCRIBE — interpret an SE's natural-language description of the customer's AI environment.

The LLM extracts *asserted* components, relationships and control claims into a strict JSON schema.
Everything produced here is recorded as an unverified customer assertion (low confidence) and is only
promoted by technical evidence from Observe/Enumerate/Ingest. If no LLM is available, a clearly
labelled deterministic keyword parser is used instead — it is never presented as an LLM.
"""
from __future__ import annotations

import re

from aplab.llm import LLM, LLMUnavailable

KINDS = ["a2a_agent", "mcp_server", "llm_endpoint", "vector_db", "object_store", "otel_collector", "dns_server",
         "adc", "analytics", "client_app", "unknown"]
SYSTEM = (
    "You extract an inventory of an AI application environment from a sales engineer's notes. Output ONLY JSON:\n"
    '{"components":[{"name":str,"kind":one of ' + str(KINDS) + ',"address":str|null,"replicas":int|null,"notes":str|null}],'
    '"relationships":[{"from":str,"to":str,"protocol":"a2a"|"mcp"|"http"|"s3"|"vector_db"|"llm"|"unknown",'
    '"path":"via_bigip"|"direct"|"unknown"}],'
    '"control_claims":[{"subject":str,"claim":"load_balanced"|"health_monitored"|"authenticated"|"rate_limited"|"behind_bigip"|"other","text":str}]}\n'
    "kind describes what the component IS (an MCP server that does risk scoring is mcp_server, not llm_endpoint; "
    "S3/object storage is object_store; a vector database is vector_db). List every distinct component once. "
    "Use component names as written. Do not invent components that are not mentioned. "
    "path=via_bigip only if the notes say traffic goes through BIG-IP/F5/the load balancer."
)

_KEYWORDS = [
    (r"\b(a2a|agent)\b", "a2a_agent"), (r"\bmcp\b", "mcp_server"), (r"\b(rag|vector|qdrant|embedding)", "vector_db"),
    (r"\b(s3|object stor|bucket|minio)", "object_store"), (r"\b(llm|model|gpt|claude|ollama|qwen)\b", "llm_endpoint"),
    (r"\b(otel|opentelemetry|tracing|collector)\b", "otel_collector"), (r"\b(big-?ip|f5|load balanc|adc)\b", "adc"),
]


def _fallback(text: str) -> dict:
    """Deterministic, explicitly non-LLM extraction: one component per matched keyword class per sentence."""
    comps, claims = {}, []
    for sent in re.split(r"(?<=[.!?])\s+|\n", text):
        s = sent.strip()
        if not s:
            continue
        for rx, kind in _KEYWORDS:
            m = re.search(rx, s, re.I)
            if m:
                name = re.sub(r"\s+", " ", s[max(0, m.start() - 20):m.end() + 25]).strip(" ,.;")
                comps.setdefault(kind, {"name": name, "kind": kind, "address": None, "replicas": None, "notes": s[:160]})
        low = s.lower()
        if "big-ip" in low or "bigip" in low or "f5" in low:
            claims.append({"subject": s[:60], "claim": "behind_bigip", "text": s[:200]})
        if "load balanc" in low:
            claims.append({"subject": s[:60], "claim": "load_balanced", "text": s[:200]})
        if "auth" in low:
            claims.append({"subject": s[:60], "claim": "authenticated", "text": s[:200]})
    return {"components": list(comps.values()), "relationships": [], "control_claims": claims}


async def interpret(text: str, llm: LLM) -> tuple[dict, dict]:
    """Return (extraction, provenance). provenance.generated_by states exactly what produced it."""
    try:
        res = await llm.complete(SYSTEM, text[:6000], json_mode=True, max_tokens=900)
        data = res.json()
        if not isinstance(data, dict):
            raise ValueError("model did not return an object")
        data.setdefault("components", [])
        data.setdefault("relationships", [])
        data.setdefault("control_claims", [])
        data["components"] = [c for c in data["components"] if isinstance(c, dict) and c.get("name")]
        for c in data["components"]:
            if c.get("kind") not in KINDS:
                c["kind"] = "unknown"
        return data, {"generated_by": f"llm:{res.provider}:{res.model}", "llm": True,
                      "tokens": {"in": res.input_tokens, "out": res.output_tokens}}
    except (LLMUnavailable, ValueError, KeyError) as e:
        return _fallback(text), {"generated_by": "deterministic-keyword-parser (NOT an LLM)", "llm": False,
                                 "fallback_reason": str(e)[:200]}
