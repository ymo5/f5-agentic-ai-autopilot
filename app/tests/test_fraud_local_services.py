"""The bank fraud application, run FUNCTIONALLY offline: the real Agent A, Agent B (A2A) and both MCP servers on
127.0.0.1 (devtools/fraudlocal/run.py). Stand-ins only for fraud-intel's Qdrant/S3/embedding backends (labelled); no LLM
(Agent B's labelled deterministic fallback, then its classifier-based calibration). Every scenario is driven through
Agent A exactly as the Autopilot Fraud page does."""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_all_scenarios_run_end_to_end_through_the_real_services():
    sys.path.insert(0, str(ROOT / "devtools" / "fraudlocal"))
    import run as fraudlocal
    out = fraudlocal.run()
    assert out["agent_card"]["name"] == "Risk Assessment Agent" and out["agent_card"]["skills"]       # A2A Agent Card served
    res = {r["scenario"]: r for r in out["results"]}
    assert len(res) == 11 and all(r["http"] == 200 and r["state"] == "completed" for r in res.values()), res
    for r in res.values():
        assert r["model_scores"] >= 1 and r["replicas_used"] == ["risk-scoring-local"]   # MCP risk-scoring called per transaction
        assert r["rag_patterns"] and r["case_file"]                                     # MCP fraud-intel tools called
        assert r["generated_by"] == "deterministic-fallback (not an LLM)"                # labelled, never presented as an LLM
        assert r["decision"] in ("escalate", "monitor", "close")
    for sid in ("ALERT-9000", "ALERT-9001", "ALERT-9002", "ALERT-9003", "ALERT-9004", "ALERT-9005", "ALERT-9006", "ALERT-9007"):
        assert res[sid]["classification_status"] == "classified" and res[sid]["coherence"]["status"] == "coherent", (sid, res[sid])
    for sid in ("NORMAL-1", "NORMAL-2", "NORMAL-3"):
        assert res[sid]["classification_status"] == "abstain" and res[sid]["risk_level"] == "low" and res[sid]["decision"] != "escalate"
