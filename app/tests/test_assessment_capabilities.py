"""Regression coverage for independent BIG-IP control capabilities."""
from __future__ import annotations

from autopilot import assess, capabilities


def virtual(**attrs):
    return {"id": "vs", "key": "bigip-vs:/Common/vs", "kind": "bigip_virtual", "name": "/Common/vs", "attrs": attrs, "claims": [], "sources": ["observe"], "status": "observed"}


def relation():
    return {"kind": "calls_mcp", "src": "agent", "dst": "mcp", "observed_path": "via_bigip",
            "assertion_contradicted": False, "asserted_paths": [],
            "claims": [{"source": "ingest", "evidence_id": "ing-1", "attrs": {"calls": 3}}]}


class Store:
    def __init__(self, vs):
        self._assets = [virtual(**vs), {"id": "mcp", "key": "ep:10.0.0.1:8000", "kind": "mcp_server", "name": "mcp", "attrs": {}, "status": "observed",
                                       "claims": [{"source": "ingest", "evidence_id": "ing-1", "attrs": {}}], "sources": ["ingest"]}]
        self._rels = [relation()]

    def assets(self): return self._assets
    def rels(self): return self._rels
    def evidence(self): return []


def evaluate(vs):
    findings, _ = assess.evaluate(Store(vs), {})
    return [f for f in findings if f["rule_id"] == "S-009"]


def verified(capability):
    return {"capabilities": {capability: {"status": "verified", "evidence_ids": ["val-1"]}}}


def test_persistence_only_does_not_suppress_rate_limit_finding():
    assert evaluate({"rules": ["/Common/irule_mcp_persist"], "persist": ["/Common/universal"]})
    assert capabilities.status(virtual(rules=["/Common/irule_mcp_persist"], persist=["/Common/universal"]), "persistence") == "present"
    assert capabilities.status(virtual(rules=["/Common/irule_mcp_persist"], persist=["/Common/universal"]), "rate_limiting") == "unknown"


def test_verified_rate_limit_satisfies_finding():
    assert evaluate(verified("rate_limiting")) == []


def test_authorization_only_does_not_count_as_rate_limiting():
    assert evaluate(verified("tool_authorization"))


def test_mixed_controls_remain_independent():
    vs = {"persist": ["/Common/universal"], "capabilities": {
        "authentication": {"status": "verified", "evidence_ids": ["auth-1"]},
        "tool_authorization": {"status": "verified", "evidence_ids": ["authz-1"]},
        "rate_limiting": {"status": "verified", "evidence_ids": ["rl-1"]},
    }}
    assert evaluate(vs) == []
    assert [capabilities.status(virtual(**vs), c) for c in capabilities.CAPABILITIES] == ["present", "present", "present", "present"]


def test_unknown_policy_is_conservative():
    assert evaluate({"rules": ["/Common/arbitrary_policy"]})
    assert capabilities.aggregate([virtual(rules=["/Common/arbitrary_policy"])], "rate_limiting") == "unknown"
