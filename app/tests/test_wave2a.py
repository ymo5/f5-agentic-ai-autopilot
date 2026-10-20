"""Wave 2A — evidence-only canonical identity, inventory snapshots/change history, disabled-by-default scheduler.

All discovery inputs are local fixtures (patched scan results and traces); a socket guard proves that identity
reconciliation, snapshots and scheduled runs open no network connections.
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import socket
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import TOOLS, proc, span  # noqa: E402

RISK = {"name": "Risk Assessment Agent", "skills": ["assess"], "security_schemes": [], "streaming": True, "bindings": ["JSONRPC"]}


def a2a(ip, port=9000, card=None, url=None):
    c = dict(card or RISK)
    c["advertised_urls"] = [url or f"http://{ip}:{port}/"]
    return {"ip": ip, "port": port, "protocol": "a2a", "kind": "a2a_agent", "name": c["name"], "agent_card": c}


def mcp(ip, name="risk-scoring", tools=TOOLS, fp="abc", port=8000):
    return {"ip": ip, "port": port, "protocol": "mcp", "kind": "mcp_server", "name": name,
            "mcp": {"server_name": name, "server_version": "x", "protocol_version": "2025-11-25", "tools": tools,
                    "toolset_fingerprint": fp, "authenticated": False}}


def trace_b(listen=("10.50.10.22:9000",), mcp_peer="10.50.20.22", instances=None, svc="agent-b-risk-assessment"):
    """Agent B serving on `listen` (one span per address/instance) and calling MCP from `mcp_peer`."""
    procs = {"pa": proc("agent-a-fraud-investigation"), "pr": proc("mcp-risk-scoring", "risk-scoring-1")}
    spans = [span("a1", "pa", "investigate_alert", "internal", {"gen_ai.agent.name": "fraud-investigation-agent"})]
    for i, addr in enumerate(listen):
        pid = f"pb{i}"
        procs[pid] = proc(svc, (instances or [None] * len(listen))[i])
        spans += [span(f"a2{i}", "pa", "POST", "client", {"http.url": f"http://{addr}/"}, "a1"),
                  span(f"b1{i}", pid, "POST /", "server", {"http.host": addr, "net.peer.ip": "10.50.10.21", "http.target": "/"}, f"a2{i}"),
                  span(f"b2{i}", pid, "assess_fraud_alert", "internal", {"gen_ai.agent.name": "risk-assessment-agent", "a2a.task.id": f"x{i}"}, f"b1{i}")]
    if mcp_peer:
        spans += [span("r1", "pr", "POST /mcp", "server", {"http.host": "10.50.20.31:8000", "net.peer.ip": mcp_peer, "http.target": "/mcp"}, "b20"),
                  span("r2", "pr", "tools/call score_transaction", "server", {"mcp.method.name": "tools/call", "gen_ai.tool.name": "score_transaction",
                                                                               "mcp.protocol.version": "2025-11-25"}, "r1")]
    return {"traceID": "t-w2a", "processes": procs, "spans": spans}


@pytest.fixture()
def world(ctx, monkeypatch):
    """Lets a test set the fixture scan and traces, then run discovery (no network: inputs are patched)."""
    from autopilot.sources import enumerate as e_src
    from autopilot.sources import ingest as i_src
    st = {"scan": [], "traces": []}

    async def fake_scan(*a, **k):
        return st["scan"]

    async def fake_traces(*a, **k):
        return st["traces"]
    monkeypatch.setattr(e_src, "scan", fake_scan)
    monkeypatch.setattr(i_src, "fetch_traces", fake_traces)

    def run(scan=None, traces=None, methods=("enumerate", "ingest"), name=None):
        if name:
            ctx.op.post("/api/assessment/new", json={"name": name})
        st["scan"], st["traces"] = scan or [], traces or []
        for m in methods:
            assert ctx.op.post(f"/api/discover/{m}").status_code == 200
        return ctx.viewer.get("/api/services").json()
    ctx.run = run
    return ctx


@pytest.fixture()
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def svc_by_name(view, name):
    return [s for s in view["services"] if s["name"] == name]


# ------------------------------------------------------------------ 1. canonical identity
def test_agent_b_two_interfaces_with_telemetry_is_one_agent_one_instance(world):
    v = world.run([a2a("10.50.10.22"), a2a("10.50.20.22", url="http://10.50.10.22:9000/")], [trace_b()], name="B two NICs")
    b = svc_by_name(v, "Risk Assessment Agent")
    assert len(b) == 1, [s["key"] for s in b]
    s = b[0]
    assert s["grouping"] == "corroborated" and len(s["instances"]) == 1 and s["instances"][0]["status"] == "resolved"
    assert sorted(e["address"] for e in s["endpoints"]) == ["10.50.10.22:9000", "10.50.20.22:9000"]
    assert {e["role"] for e in s["endpoints"]} == {"interface"} and s["replicas"] == 0
    assert any("10.50.20.22 emits traced spans" in b_ for b_ in s["basis"])
    # original endpoint evidence is preserved: both ep: assets still exist with their own claims
    keys = {n["key"] for n in world.viewer.get("/api/state").json()["graph"]["nodes"]}
    assert {"ep:10.50.10.22:9000", "ep:10.50.20.22:9000"} <= keys


def test_agent_b_two_interfaces_without_telemetry_stays_unresolved(world):
    v = world.run([a2a("10.50.10.22"), a2a("10.50.20.22", url="http://10.50.10.22:9000/")], methods=("enumerate",), name="cards only")
    b = svc_by_name(v, "Risk Assessment Agent")
    assert len(b) == 2 and {s["grouping"] for s in b} == {"unresolved-candidate"}
    u = [x for x in v["unresolved"] if x["type"] == "possibly_same_service"]
    assert u and sorted(u[0]["endpoints"]) == ["10.50.10.22:9000", "10.50.20.22:9000"] and "does not prove" in u[0]["why_unresolved"]


def test_independent_replicas_are_two_instances_of_one_logical_service(world):
    v = world.run([a2a("10.50.10.22"), a2a("10.50.10.23")],
                  [trace_b(listen=("10.50.10.22:9000", "10.50.10.23:9000"), mcp_peer=None, instances=["agent-b-1", "agent-b-2"])], name="replicas")
    b = svc_by_name(v, "Risk Assessment Agent")
    assert len(b) == 1 and len(b[0]["instances"]) == 2 and b[0]["replicas"] == 2 and b[0]["replica_status"] == "resolved"
    assert {i["label"] for i in b[0]["instances"]} == {"agent-b-1", "agent-b-2"}
    assert {e["role"] for e in b[0]["endpoints"]} == {"sole endpoint"}


def test_unrelated_agents_with_similar_names_are_not_merged(world):
    other = {**RISK, "skills": ["summarise_news"]}
    v = world.run([a2a("10.50.10.22"), a2a("10.50.10.30", card=other)], methods=("enumerate",), name="similar names")
    assert len(svc_by_name(v, "Risk Assessment Agent")) == 2
    assert not [x for x in v["unresolved"] if x["type"] == "possibly_same_service"]       # different capabilities: not even a candidate
    assert any(n["type"] == "similar_name_not_merged" for n in v["notes"])


def test_identical_cards_bound_to_different_telemetry_services_are_kept_separate(world):
    t1, t2 = trace_b(listen=("10.50.10.22:9000",), mcp_peer=None), trace_b(listen=("10.50.10.40:9000",), mcp_peer=None, svc="other-team-agent")
    t2["traceID"] = "t-other"
    v = world.run([a2a("10.50.10.22"), a2a("10.50.10.40")], [t1, t2], name="two teams")
    assert len(svc_by_name(v, "Risk Assessment Agent")) == 2
    assert any(n["type"] == "identical_card_different_telemetry" for n in v["notes"])


def test_mcp_replicas_group_and_uninstrumented_replica_is_an_inferred_member(world):
    from conftest import TRACE
    v = world.run([mcp("10.50.20.31"), mcp("10.50.20.32")], [TRACE], name="mcp")
    rs = [s for s in v["services"] if s["kind"] == "mcp_server" and s["name"] == "risk-scoring"]
    assert len(rs) == 1 and len(rs[0]["endpoints"]) == 2 and rs[0]["replicas"] == 2
    mem = {e["address"]: e["membership"] for e in rs[0]["endpoints"]}
    assert mem == {"10.50.20.31:8000": "corroborated", "10.50.20.32:8000": "inferred"}
    u = [x for x in v["unresolved"] if x["type"] == "instance_relationship_unknown" and x["service_key"] == rs[0]["key"]]
    assert u and u[0]["endpoints"] == ["10.50.20.32:8000"]          # risk-scoring-2's instance identity is not observed


def test_new_agent_and_new_mcp_service_appear_with_capabilities(world):
    agent_c = {"name": "Agent C", "skills": ["patrol_zone", "report_status"], "security_schemes": ["bearer"], "streaming": False, "bindings": ["JSONRPC"]}
    v = world.run([a2a("10.50.10.22"), a2a("10.50.10.23", 8080, card=agent_c), mcp("10.50.20.50", "robot-tools", [{"name": "get_battery", "annotations": {"readOnlyHint": True}},
                                                                                                                 {"name": "move_to", "annotations": {"destructiveHint": True}}], "rt1")],
                  methods=("enumerate",), name="new services")
    c = svc_by_name(v, "Agent C")[0]
    assert c["capabilities"]["skills"] == ["patrol_zone", "report_status"] and c["auth"]["security_schemes"] == ["bearer"]
    rt = svc_by_name(v, "robot-tools")[0]
    assert rt["grouping"] == "single" and rt["verified"] is True           # one fingerprinted endpoint: no inferred grouping
    assert rt["capabilities"]["privileged_tools"] == ["move_to"] and rt["auth"]["mcp_authenticated"] is False


# ------------------------------------------------------------------ 2. inventory snapshots and change history
def snap(ctx):
    r = ctx.op.post("/api/inventory/snapshot", json={})
    assert r.status_code == 200, r.text
    return r.json()


def changes_of(ctx, sid):
    return {(c["service_name"], c["change_type"]): c for c in ctx.viewer.get(f"/api/inventory/changes?snapshot={sid}").json()["changes"]}


AGENT_C = {"name": "Agent C", "skills": ["patrol_zone"], "security_schemes": [], "streaming": False, "bindings": ["JSONRPC"]}


def test_new_service_then_ip_change_then_unreachable_vs_unobserved(world):
    world.run([a2a("10.50.10.22")], methods=("enumerate",), name="t0")
    s0 = snap(world)
    assert all(c["change_type"] == "new" for c in changes_of(world, s0["snapshot_id"]).values())
    world.run([a2a("10.50.10.22"), a2a("10.50.10.23", 8080, card=AGENT_C)], methods=("enumerate",), name="t1")
    s1 = snap(world)
    assert ("Agent C", "new") in changes_of(world, s1["snapshot_id"])
    world.run([a2a("10.50.10.22"), a2a("10.50.10.24", 8080, card=AGENT_C)], methods=("enumerate",), name="t2")
    s2 = snap(world)
    ch = changes_of(world, s2["snapshot_id"])[("Agent C", "address_changed")]
    assert ch["detail"] == {"from": ["10.50.10.23:8080"], "to": ["10.50.10.24:8080"]}
    # scan ran and its scope/ports covered 10.50.10.24:8080, but the agent was not found -> unreachable (not deleted)
    world.run([a2a("10.50.10.22")], methods=("enumerate",), name="t3")
    s3 = snap(world)
    c3 = changes_of(world, s3["snapshot_id"])[("Agent C", "unreachable")]
    assert "covered 10.50.10.24:8080" in c3["detail"]["reason"] and c3["evidence_ids"]
    body = world.viewer.get(f"/api/inventory/snapshots/{s3['snapshot_id']}").json()
    carried = [s for s in body["services"].values() if s["name"] == "Agent C"][0]
    assert carried["status"] == "unreachable" and carried["misses"] == 1 and carried["last_seen"]
    # next snapshot from an assessment where no technical source ran: everything missing is UNOBSERVED, not removed
    world.op.post("/api/assessment/new", json={"name": "t4 nothing ran"})
    s4 = snap(world)
    c4 = changes_of(world, s4["snapshot_id"])
    assert ("Risk Assessment Agent", "unobserved") in c4 and ("Agent C", "unreachable") not in c4    # status unchanged -> no duplicate event
    world.run([a2a("10.50.10.22"), a2a("10.50.10.24", 8080, card=AGENT_C)], methods=("enumerate",), name="t5")
    s5 = snap(world)
    assert ("Agent C", "reappeared") in changes_of(world, s5["snapshot_id"])


def test_service_outside_scan_coverage_is_unobserved_not_unreachable(world):
    world.run([a2a("10.50.10.22"), a2a("10.50.10.23", 7777, card=AGENT_C)], methods=("enumerate",), name="odd port")   # 7777 not a scanned port
    snap(world)
    world.run([a2a("10.50.10.22")], methods=("enumerate",), name="later")
    s = snap(world)
    c = changes_of(world, s["snapshot_id"])[("Agent C", "unobserved")]
    assert "outside the coverage" in c["detail"]["reason"]


def test_telemetry_only_service_without_traffic_is_unobserved(world):
    world.run([], [trace_b(mcp_peer=None)], methods=("ingest",), name="traffic")
    snap(world)
    world.run([], [], methods=("ingest",), name="quiet")
    s = snap(world)
    ch = changes_of(world, s["snapshot_id"])
    assert any(t == "unobserved" and "absence of traffic" in c["detail"]["reason"] for (n, t), c in ch.items())


def test_replica_added_tools_changed_auth_changed(world):
    world.run([mcp("10.50.20.31"), mcp("10.50.20.32")], methods=("enumerate",), name="m0")
    snap(world)
    tools2 = TOOLS + [{"name": "delete_case", "annotations": {"destructiveHint": True}}]
    world.run([mcp("10.50.20.31", tools=tools2, fp="abc"), mcp("10.50.20.32", tools=tools2, fp="abc"), mcp("10.50.20.34", tools=tools2, fp="abc")],
              methods=("enumerate",), name="m1")
    s = snap(world)
    ch = changes_of(world, s["snapshot_id"])
    assert ("risk-scoring", "replica_added") in ch and ch[("risk-scoring", "replica_added")]["detail"]["instances_now"] == 3
    assert ch[("risk-scoring", "tools_changed")]["detail"]["privileged_added"] == ["delete_case"]
    world.run([a2a("10.50.10.22")], methods=("enumerate",), name="a0")
    snap(world)
    world.run([a2a("10.50.10.22", card={**RISK, "security_schemes": ["mtls"]})], methods=("enumerate",), name="a1")
    s2 = snap(world)
    ch2 = changes_of(world, s2["snapshot_id"])
    assert ch2[("Risk Assessment Agent", "auth_changed")]["detail"]["to"]["security_schemes"] == ["mtls"]
    assert ("Risk Assessment Agent", "new") not in ch2                # adding authentication does not create a "new" agent


def test_changes_can_be_acknowledged_and_notification_count_drops(world):
    world.run([a2a("10.50.10.22")], methods=("enumerate",), name="n0")
    s = snap(world)
    assert world.viewer.get("/api/inventory/changes").json()["unacknowledged_latest"] >= 1
    assert world.viewer.post("/api/inventory/changes/ack", json={"snapshot_id": s["snapshot_id"]}).status_code == 403   # viewer
    assert world.op.post("/api/inventory/changes/ack", json={"snapshot_id": s["snapshot_id"]}).json()["acknowledged"] >= 1
    assert world.viewer.get("/api/inventory/changes").json()["unacknowledged_latest"] == 0


# ------------------------------------------------------------------ 3. migration / compatibility
def test_historical_records_untouched_and_backfill_reconstructs_in_order(world, no_network):
    world.run([a2a("10.50.10.22"), a2a("10.50.20.22", url="http://10.50.10.22:9000/")], methods=("enumerate",), name="old-1")
    world.run([a2a("10.50.10.22")], methods=("enumerate",), name="old-2")
    db = world.web.STORE.db
    before = {t: db.execute(f"SELECT COUNT(*), TOTAL(LENGTH(attrs)) FROM {t}").fetchone()[:] for t in ("asset", "asset_claim", "rel", "rel_claim")}
    ev_before = [tuple(r) for r in db.execute("SELECT id, digest FROM evidence ORDER BY id")]
    plan = world.ap.post("/api/inventory/backfill", json={"dry_run": True}).json()
    assert [p["action"] for p in plan["plan"] if p["name"].startswith("old-")] == ["reconstruct", "reconstruct"]
    assert world.op.post("/api/inventory/backfill", json={"dry_run": False}).status_code == 403          # approver only
    done = world.ap.post("/api/inventory/backfill", json={"dry_run": False}).json()
    assert len(done["created"]) >= 2
    snaps = world.viewer.get("/api/inventory/snapshots").json()
    assert all(s["reconstructed"] == 1 and s["trigger"] == "migration" for s in snaps)
    after = {t: db.execute(f"SELECT COUNT(*), TOTAL(LENGTH(attrs)) FROM {t}").fetchone()[:] for t in ("asset", "asset_claim", "rel", "rel_claim")}
    assert before == after and ev_before == [tuple(r) for r in db.execute("SELECT id, digest FROM evidence ORDER BY id")]
    snap(world)                                                                               # first live snapshot
    assert world.ap.post("/api/inventory/backfill", json={"dry_run": False}).status_code == 409   # would reorder the timeline


def test_old_format_ingest_evidence_without_instance_fields_still_reconciles(world):
    world.run([a2a("10.50.10.22")], [trace_b(mcp_peer=None)], name="legacy ingest")
    db = world.web.STORE.db
    row = db.execute("SELECT id, raw FROM evidence WHERE source='ingest' ORDER BY collected_at DESC LIMIT 1").fetchone()
    raw = json.loads(row["raw"])
    raw.pop("instance_listen", None), raw.pop("peer_instances", None)
    db.execute("UPDATE evidence SET raw=? WHERE id=?", (json.dumps(raw), row["id"]))               # simulate pre-Wave-2A evidence
    v = world.viewer.get("/api/services").json()
    b = svc_by_name(v, "Risk Assessment Agent")
    assert len(b) == 1 and b[0]["grouping"] == "corroborated" and b[0]["instances"][0]["status"] == "resolved"   # single-instance fallback


def test_malformed_and_partial_evidence_does_not_break_reconciliation(world):
    bad = {"ip": "10.50.10.50", "port": 9000, "protocol": "a2a", "kind": "a2a_agent", "name": None, "agent_card": {"skills": "not-a-list"}}
    v = world.run([bad, a2a("10.50.10.22")], methods=("enumerate",), name="malformed")
    assert any(s["name"] == "Risk Assessment Agent" for s in v["services"]) and len(v["services"]) >= 2
    world.web.STORE.db.execute("UPDATE evidence SET raw='not json' WHERE source='enumerate' AND method='approved-inventory'")
    assert world.viewer.get("/api/services").status_code == 200 and snap(world)["services"] >= 2


def test_asset_dossier_carries_canonical_identity_and_wave1_fields(world):
    world.run([a2a("10.50.10.22"), a2a("10.50.20.22", url="http://10.50.10.22:9000/")], [trace_b()], name="dossier")
    node = next(n for n in world.viewer.get("/api/state").json()["graph"]["nodes"] if n["key"] == "ep:10.50.20.22:9000")
    d = world.viewer.get(f"/api/assets/{node['id']}").json()
    assert d["canonical"]["role"] == "interface" and d["canonical"]["service"]["grouping"] == "corroborated"
    assert len(d["canonical"]["endpoints"]) == 2 and {"identity", "claims", "findings", "communications"} <= set(d)


def test_identity_and_snapshots_open_no_network_connections(world, no_network):
    world.run([a2a("10.50.10.22"), mcp("10.50.20.31")], methods=("enumerate",), name="offline")
    assert world.viewer.get("/api/services").status_code == 200
    assert snap(world)["services"] >= 2


# ------------------------------------------------------------------ 4. scheduler
def test_scheduler_disabled_by_default_and_cannot_be_enabled_in_lab(world):
    g = world.viewer.get("/api/discovery/schedule").json()
    assert g["enabled"] is False and g["permitted"] is False and g["allowed_jobs"] == ["snapshot"]
    assert world.ap.put("/api/discovery/schedule", json={"enabled": True}).status_code == 403          # owner only
    r = world.owner.put("/api/discovery/schedule", json={"enabled": True})
    assert r.status_code == 409 and "not permitted" in r.json()["detail"]
    assert world.viewer.get("/api/discovery/schedule").json()["enabled"] is False
    assert world.web.SCHED.start() is False and world.web.SCHED.task is None                             # loop never starts here
    acts = [x["action"] for x in world.ap.get("/api/audit").json()["rows"]]
    assert "schedule.enable.refused" in acts


def test_scheduler_rejects_network_jobs_and_validates_cadence(world):
    for jobs in (["enumerate"], ["snapshot", "ingest"], ["direct"], ["a2a_probe"]):
        r = world.owner.put("/api/discovery/schedule", json={"jobs": jobs})
        assert r.status_code == 422 and "not available in this milestone" in r.json()["detail"]
    assert world.owner.put("/api/discovery/schedule", json={"cadence_min": 5}).status_code == 422
    assert world.owner.put("/api/discovery/schedule", json={"cadence_min": 30}).json()["cadence_min"] == 30


def test_scheduled_run_is_evidence_only_and_failures_auto_disable(world, no_network, monkeypatch):
    from autopilot import inventory, scheduler
    world.run([a2a("10.50.10.22")], methods=("enumerate",), name="sched")
    out = asyncio.run(scheduler.run_once(world.web.STORE))
    assert out["snapshot"]["services"] >= 1
    assert world.viewer.get("/api/inventory/snapshots").json()[0]["trigger"] == "scheduled"
    store, cfg = world.web.STORE, {"scheduler": {"permitted": True}}
    scheduler.update(store, cfg, "owner1", enabled=True)
    monkeypatch.setattr(inventory, "record", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    for _ in range(scheduler.MAX_FAILURES):
        asyncio.run(scheduler.run_once(store))
    g = scheduler.get(store)
    assert g["enabled"] is False and g["last_status"] == "failed" and g["consecutive_failures"] == scheduler.MAX_FAILURES


# ------------------------------------------------------------------ 5. access control
def test_wave2a_api_roles(world):
    assert world.anon.get("/api/services").status_code == 401
    assert world.viewer.get("/api/services").status_code == 200
    assert world.viewer.post("/api/inventory/snapshot", json={}).status_code == 403
    assert world.viewer.get("/api/inventory/snapshots").status_code == 200
    assert world.viewer.get("/api/services?assessment=nope").status_code == 404


def test_agent_finding_applies_to_every_interface_of_the_instance(world):
    world.run([a2a("10.50.10.22"), a2a("10.50.20.22", url="http://10.50.10.22:9000/")], [trace_b()], name="finding on both NICs")
    nodes = {n["key"]: n["id"] for n in world.viewer.get("/api/state").json()["graph"]["nodes"]}
    for k in ("ep:10.50.10.22:9000", "ep:10.50.20.22:9000"):
        d = world.viewer.get(f"/api/assets/{nodes[k]}").json()
        assert any(f["rule_id"] == "S-004" for f in d["findings"]), k     # stored once, visible from either interface
