"""End-to-end A2A test using the Fraud Investigation Agent's client code."""
import asyncio, json, os, sys
os.environ.setdefault("AGENT_A_DB", "/tmp/e2e.db")
from services.agent_a import agent as A
alert = sys.argv[1] if len(sys.argv) > 1 else "ALERT-9001"
r = asyncio.run(A.investigate(alert))
states = []
for u in r["updates"]:
    st = (u.get("status_update") or u.get("task") or {}).get("status", {})
    msg = " ".join(p.get("text", "") for p in (st.get("message") or {}).get("parts", []))
    states.append(f"{st.get('state')}: {msg}"[:140])
print("card_url:", r["card_url"]); print("trace_id:", r["trace_id"]); print("\n".join(states))
print("RESULT:", json.dumps(r["result"], indent=1)[:1800] if r["result"] else r["error"])
print("E2E", "PASS" if r["state"] == "completed" and r["result"] else "FAIL")
