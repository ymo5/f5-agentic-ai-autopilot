"""Run the REAL fraud-intel MCP server with in-memory stand-ins for its three external backends (offline harness only).

Stand-ins (clearly labelled; the live lab uses the real services):
  Qdrant vector search -> token-overlap ranking over the same synthetic fraud-pattern texts the lab indexes
  embeddings (Ollama)  -> not needed by the stand-in ranking (returns the text itself)
  S3 case files        -> the same synthetic case documents the lab stores in the 'case-files' bucket
Everything else — the MCP protocol, tool code, data access, annotations — is the unmodified server.
"""
import os
import re
import sys
import types

sys.path.insert(0, os.environ["APP_DIR"])
from services.mcp_fraud_intel import server  # noqa: E402

PATTERNS = server.DATA["fraud_patterns"]
CASES = {c["case_id"]: c for c in server.DATA["case_documents"]}
words = lambda t: set(re.findall(r"[a-z]{3,}", t.lower()))  # noqa: E731


class StandInQdrant:
    def query_points(self, collection, query, limit=3, with_payload=True):
        q = words(query if isinstance(query, str) else "")
        ranked = sorted(PATTERNS, key=lambda p: (-len(q & words(p["name"] + " " + p["text"])), p["pattern_id"]))[:limit]
        pts = [types.SimpleNamespace(payload=p, score=round(len(q & words(p["name"] + " " + p["text"])) / max(1, len(q)), 4)) for p in ranked]
        return types.SimpleNamespace(points=pts)


class _Body:
    def __init__(self, b):
        self.b = b

    def read(self):
        return self.b


class StandInS3:
    def get_object(self, Bucket, Key):
        c = CASES[Key.rsplit(".", 1)[0]]
        return {"Body": _Body(c["body"].encode()), "ETag": '"stand-in"'}


server.qdrant, server.s3, server.embed = StandInQdrant(), StandInS3(), (lambda text: text)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(server.build_app(), host="127.0.0.1", port=int(os.environ["BIND_PORT"]), log_level="warning")
