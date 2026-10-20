"""In-lab functional smoke test of MCP services (real MCP client, both protocol modes)."""
import asyncio, json, sys
import services.agent_b.mcp_tools as m
from services.agent_b.mcp_tools import mcp_session, result_data

async def main():
    ok = True
    for mode in ("legacy", "auto"):
        m.MCP_MODE = mode
        for url in ("http://10.50.20.31:8000/mcp", "http://10.50.20.32:8000/mcp"):
            async with mcp_session(url) as c:
                r = result_data(await c.call_tool("score_transaction", {"amount": 4200.0, "mcc": "6051", "country": "RO",
                    "home_country": "US", "channel": "p2p", "account_age_days": 30, "kyc_risk": "medium", "recent_txn_count_24h": 4}))
                print(f"[{mode}] {url} proto={c.protocol_version} replica={r['replica']} score={r['score']}")
    m.MCP_MODE = "legacy"
    async with mcp_session("http://10.50.20.33:8000/mcp") as c:
        tools = [t.name for t in (await c.list_tools()).tools]
        print("fraud-intel tools:", tools)
        pats = result_data(await c.call_tool("search_fraud_patterns", {"query": "many small card-not-present authorizations then a large purchase", "top_k": 2}))
        print("RAG top:", [(p["pattern_id"], p["name"], p["score"]) for p in pats])
        doc = result_data(await c.call_tool("get_case_document", {"case_id": "CASE-7000"}))
        print("S3 case:", doc["case_id"], doc["content"].splitlines()[1])
        ok &= pats[0]["pattern_id"] == "FP-001"
    print("SMOKE", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)

asyncio.run(main())
