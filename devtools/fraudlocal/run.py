#!/usr/bin/env python3
"""Offline functional run of the bank fraud application: the REAL Agent A, Agent B (A2A), risk-scoring and fraud-intel
(MCP) services on 127.0.0.1, every scenario driven through Agent A exactly as the Autopilot Fraud page does.

No lab contact: loopback only; no LLM (Agent B uses its labelled deterministic fallback); no OTLP export; fraud-intel's
Qdrant/S3/embedding backends are labelled in-memory stand-ins (intel_standins.py).
Usage: app/.venv/bin/python devtools/fraudlocal/run.py [out.json]
"""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[2]
APP = ROOT / "app"
sys.path.insert(0, str(APP))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait(url, proc, secs=60):
    for _ in range(secs * 10):
        if proc.poll() is not None:
            raise RuntimeError(f"{url}: process exited ({proc.returncode})")
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"{url} did not start")


def run(out_path=None):
    from aplab import synthdata
    from autopilot import fraud
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="fraudlocal-"))
    data = tmp / "synthetic.json"
    data.write_text(json.dumps(synthdata.build()))
    ports = {k: free_port() for k in ("risk", "intel", "agent_b", "agent_a")}
    base = {**os.environ, "APLAB_DATA": str(data), "LLM_PROVIDER": "none", "APP_DIR": str(APP), "PYTHONPATH": str(APP),
            "MCP_ALLOWED_HOSTS": "127.0.0.1:*,localhost:*", "BIND_HOST": "127.0.0.1"}
    base.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)
    base.pop("LLM_BASE_URL", None)
    py = sys.executable
    specs = [
        ("risk", [py, "-m", "services.mcp_risk.server"], {"BIND_PORT": str(ports["risk"]), "REPLICA_ID": "risk-scoring-local"}, "/healthz"),
        ("intel", [py, str(pathlib.Path(__file__).parent / "intel_standins.py")], {"BIND_PORT": str(ports["intel"])}, "/healthz"),
        ("agent_b", [py, "-m", "services.agent_b.agent"], {"BIND_PORT": str(ports["agent_b"]),
                                                            "MCP_INTEL_URL": f"http://127.0.0.1:{ports['intel']}/mcp",
                                                            "MCP_RISK_URL": f"http://127.0.0.1:{ports['risk']}/mcp",
                                                            "A2A_PUBLIC_URL": f"http://127.0.0.1:{ports['agent_b']}/"}, "/healthz"),
        ("agent_a", [py, "-m", "services.agent_a.agent"], {"BIND_PORT": str(ports["agent_a"]), "AGENT_B_URL": f"http://127.0.0.1:{ports['agent_b']}",
                                                            "AGENT_A_DB": str(tmp / "agent-a.db")}, "/healthz"),
    ]
    procs = []
    try:
        for name, cmd, env, health in specs:
            log = open(tmp / f"{name}.log", "w")
            p = subprocess.Popen(cmd, cwd=APP, env={**base, **env}, stdout=log, stderr=subprocess.STDOUT)
            procs.append((name, p))
            wait(f"http://127.0.0.1:{ports[name]}{health}", p)
        card = httpx.get(f"http://127.0.0.1:{ports['agent_b']}/.well-known/agent-card.json", timeout=5).json()
        results = []
        agent_a = f"http://127.0.0.1:{ports['agent_a']}"
        for sc in fraud.scenarios():
            t0 = time.time()
            with httpx.Client(timeout=httpx.Timeout(30, read=300)) as c:
                if sc["kind"] == "suspicious":
                    r = c.post(f"{agent_a}/api/investigate", json={"alert_id": sc["alert_id"]})
                else:
                    r = c.post(f"{agent_a}/api/investigate-scenario", json={"scenario": {
                        "scenario_id": sc["id"], "account_id": sc["account"]["account_id"], "transactions": sc["transactions"]}})
            body = r.json()
            res = body.get("result") or {}
            a = res.get("assessment") or {}
            results.append({"scenario": sc["id"], "title": sc["title"], "kind": sc["kind"], "http": r.status_code, "state": body.get("state"),
                            "seconds": round(time.time() - t0, 2), "decision": a.get("decision"), "risk_level": a.get("risk_level"),
                            "generated_by": a.get("generated_by"), "classification_status": a.get("classification_status"),
                            "model_scores": len(res.get("model_scores") or []), "replicas_used": res.get("replicas_used") or [],
                            "rag_patterns": [p.get("pattern_id") for p in res.get("rag_patterns") or []],
                            "case_file": bool(res.get("case_file")), "tools_used": res.get("tools_used") or res.get("tool_calls"),
                            "coherence": fraud.classification_coherence(sc, res) if res else None, "error": body.get("error")})
        out = {"harness": "offline local run: real services on 127.0.0.1; Qdrant/S3/embeddings stand-ins; no LLM (deterministic fallback)",
               "agent_card": {k: card.get(k) for k in ("name", "url", "skills")}, "ports": ports, "results": results}
        if out_path:
            pathlib.Path(out_path).write_text(json.dumps(out, indent=1, default=str))
        return out
    finally:
        for _, p in procs:
            p.terminate()
        for _, p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    o = run(sys.argv[1] if len(sys.argv) > 1 else None)
    for r in o["results"]:
        print(f"{r['scenario']:10} {r['kind']:10} http={r['http']} state={r['state']} decision={r['decision']} risk={r['risk_level']} "
              f"scores={r['model_scores']} rag={r['rag_patterns']} case={r['case_file']} {r['seconds']}s {r['generated_by']} {r['error'] or ''}")
