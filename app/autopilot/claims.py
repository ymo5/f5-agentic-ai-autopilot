"""Verification of customer assertions (Describe) against technical evidence (Observe / Enumerate / Ingest).

Every control claim extracted from a description is classified:
  confirmed     technical evidence supports it (cites the evidence)
  contradicted  technical evidence refutes it (cites the evidence) -> also raised as finding S-007
  unverified    no technical evidence about the subject yet (states which discovery method would settle it)
Follow-up questions are generated deterministically from unverified claims, unmatched components and coverage gaps —
they are suggestions for the SE, never findings.
"""
from __future__ import annotations

import json

from . import capabilities

KIND_WORDS = {"mcp": ("mcp_server", "mcp_service"), "tool": ("mcp_server", "mcp_service"), "agent": ("a2a_agent",), "a2a": ("a2a_agent",),
              "vector": ("vector_db",), "rag": ("vector_db",), "qdrant": ("vector_db",), "s3": ("object_store",),
              "object": ("object_store",), "llm": ("llm_endpoint",), "model": ("llm_endpoint",), "ai traffic": ("mcp_server", "mcp_service", "a2a_agent")}


def _ev(*items) -> list[str]:
    out = []
    for it in items:
        for c in it.get("claims", []):
            if c["evidence_id"] not in out:
                out.append(c["evidence_id"])
    return out


def _targets(subject: str, assets: list[dict]) -> list[dict]:
    subj = (subject or "").lower()
    kinds = {k for w, ks in KIND_WORDS.items() if w in subj for k in ks}
    if not kinds and ("all" in subj or "traffic" in subj):
        kinds = {"mcp_server", "mcp_service", "a2a_agent"}
    return [a for a in assets if a["kind"] in kinds and set(a["sources"]) - {"describe"}]


def verify(store) -> list[dict]:
    assets, rels = store.assets(), store.rels()
    by_id = {a["id"]: a for a in assets}
    calls = [r for r in rels if r["kind"].startswith("calls_")]
    pool_members = {a["key"].split(":", 1)[1] for a in assets if a["attrs"].get("bigip_pool_member_of")}
    out = []
    for ev in [e for e in store.evidence() if e["source"] == "describe" and e["method"].startswith(("llm:", "deterministic"))]:
        raw = json.loads(store.evidence(ev["id"])[0]["raw"])
        for cl in (raw.get("extraction") or {}).get("control_claims", []):
            targets = _targets(cl.get("subject"), assets)
            ids = {a["id"] for a in targets} | {r["dst"] for g in targets if g["kind"] == "mcp_service"
                                                for r in rels if r["src"] == g["id"] and r["kind"] == "has_replica"}
            row = {"claim": cl.get("claim"), "subject": cl.get("subject"),
                   "text": cl.get("text") or f"{cl.get('subject') or 'the environment'} is {str(cl.get('claim') or '').replace('_', ' ')}",
                   "describe_evidence": ev["id"],
                   "targets": sorted(a["name"] for a in targets), "target_ids": [a["id"] for a in targets], "status": "unverified", "evidence": [], "explanation": ""}
            if not targets:
                row["explanation"] = "No technically discovered component matches the subject yet — run Enumerate and Ingest."
                out.append(row)
                continue
            kind = cl.get("claim")
            if kind == "behind_bigip":
                inbound = [r for r in calls if r["dst"] in ids]
                direct = [r for r in inbound if r["observed_path"] == "direct"]
                via = [r for r in inbound if r["observed_path"] == "via_bigip"]
                if direct:
                    names = sorted({by_id[r["dst"]]["name"] for r in direct if r["dst"] in by_id})
                    row.update(status="contradicted", evidence=_ev(*direct), contradicted_for=names,
                               explanation=f"Telemetry shows {len(direct)} path(s) reaching {', '.join(names)} directly, not through BIG-IP.")
                elif via:
                    row.update(status="confirmed", evidence=_ev(*via), explanation=f"All {len(via)} observed path(s) traverse BIG-IP.")
                else:
                    row["explanation"] = "No observed traffic to the subject yet — run Ingest after traffic has flowed."
            elif kind == "authenticated":
                unauth = [a for a in targets if (a["attrs"].get("mcp") or {}).get("authenticated") is False
                          or (a["kind"] == "a2a_agent" and not (a["attrs"].get("agent_card") or {}).get("security_schemes"))]
                if unauth:
                    row.update(status="contradicted", evidence=_ev(*unauth), contradicted_for=sorted(a["name"] for a in unauth),
                               explanation="The discovery sensor reached these services without credentials.")
                else:
                    row.update(status="confirmed", evidence=_ev(*targets), explanation="Probes required authentication.")
            elif kind in ("load_balanced", "health_monitored"):
                eps = {a["key"].split(":", 1)[1] for a in assets if a["id"] in ids and a["key"].startswith("ep:")}
                if eps and eps <= pool_members:
                    row.update(status="confirmed", evidence=_ev(*[a for a in assets if a["id"] in ids]),
                               explanation="Every endpoint is a member of a BIG-IP pool.")
                elif eps:
                    row.update(status="contradicted", evidence=_ev(*[a for a in assets if a["id"] in ids]), contradicted_for=sorted(eps - pool_members),
                               explanation="Endpoints exist that no BIG-IP pool covers.")
                else:
                    row["explanation"] = "No endpoints of the subject discovered yet."
            elif kind == "rate_limited":
                state = capabilities.aggregate(assets, "rate_limiting")
                if state == "absent" and any(r["dst"] in ids for r in calls):
                    row.update(status="contradicted", evidence=_ev(*[r for r in calls if r["dst"] in ids]),
                               explanation="Traffic is observed but no rate-limiting control is evidenced on the virtual servers.")
                elif state == "present":
                    row.update(status="confirmed", evidence=capabilities.evidence_ids(assets, "rate_limiting"),
                               explanation="A supported validation/configuration record verifies rate-limiting enforcement.")
                else:
                    row["explanation"] = "Rate-limiting enforcement is unknown; confirm it with a supported validation test (security.rate_limited)."
            else:
                row["explanation"] = "This kind of claim is recorded but not machine-verifiable."
            out.append(row)
    return out


def follow_up_questions(store, gaps: list[dict], verified: list[dict]) -> list[str]:
    qs = []
    for v in verified:
        if v["status"] == "unverified":
            qs.append(f"Can you confirm \"{(v['text'] or v['subject'] or '')[:90]}\"? {v['explanation']}")
        if v["status"] == "contradicted":
            q = {"behind_bigip": "is there another path, or a planned migration of this traffic to BIG-IP?",
                 "authenticated": "which authentication do you expect (mTLS, OAuth, API keys) and where should it be enforced?",
                 "load_balanced": "which load balancer did you expect to cover these endpoints?",
                 "health_monitored": "which health monitoring did you expect to cover these endpoints?",
                 "rate_limited": "where is rate limiting expected to be enforced?"}.get(v["claim"], "can you clarify?")
            qs.append(f"Evidence contradicts \"{(v['text'] or '')[:90]}\" — {q}")
    for a in store.assets():
        if a["status"] == "asserted":
            qs.append(f"Where does '{a['name']}' run (address/port)? It was described but not found in the approved discovery scope.")
    for g in gaps:
        if g.get("close_with", "").startswith("ingest") and "No observed clients" in g["gap"]:
            qs.append(f"Which agents or applications use {g['gap'].split('for ', 1)[-1]}? No client traffic was observed.")
    seen, out = set(), []
    for q in qs:
        if q not in seen:
            seen.add(q)
            out.append(q)
    return out[:12]
