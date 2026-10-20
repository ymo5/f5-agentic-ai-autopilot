"""Read-only Observe evidence for placement (offline): parser, evidence states, freshness, multi-device ingest, collector.

Nothing here contacts a device: raw responses are synthetic, written from the documented iControl REST shapes (the first
real owner-run capture replaces them as the regression fixture), and the collector runs against stub `curl`/`security`.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import INTEL_TOOLS  # noqa: E402
from test_wave2a import mcp, no_network, trace_b, world  # noqa: E402,F401
from test_wave3_placement import LAB_SCAN, NOW, POLICY, svc  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
T0 = NOW - 300


def ok(body):
    return {"status": 200, "body": body}


def raw_device(label="bigip-x", mgmt="192.0.2.20", collected_at=T0, selfs=(("/Common/self_agent", "10.50.10.10/24", "/Common/vlan_agent"),
               ("/Common/self_backend", "10.50.20.10/24", "/Common/vlan_backend")), routes=(), status="ACTIVE", clustered=False,
               mem=(1000, 400, 2000, 100), hostname="bigip-x.example.test", **overrides):
    """A synthetic raw snapshot in the collector's format (responses shaped like iControl REST)."""
    ot, ou, st_, su = mem
    devices = [{"name": "bigip-x"}] + ([{"name": "bigip-y"}] if clustered else [])
    r = {
        "version": ok({"entries": {"x": {"nestedStats": {"entries": {"Version": {"description": "21.1.0.3"}, "Build": {"description": "0.0.20"}}}}}}),
        "provision": ok({"items": [{"name": "ltm", "level": "nominal"}, {"name": "asm", "level": "none"}]}),
        "global": ok({"hostname": hostname}),
        "vlan": ok({"items": [{"fullPath": s[2]} for s in selfs]}),
        "self": ok({"items": [{"fullPath": n, "address": a, "vlan": v, "floating": "disabled", "trafficGroup": "/Common/traffic-group-local-only"}
                             for n, a, v in selfs]}),
        "virtual": ok({"items": []}), "virtual_stats": ok({"entries": {}}), "pool": ok({"items": []}), "pool_stats": ok({"entries": {}}),
        "monitor_http": ok({"items": []}), "monitor_https": ok({"items": []}), "rule": ok({"items": []}),
        "persistence_universal": ok({"items": []}), "clientssl": ok({"items": []}), "as3": ok({"version": "3.56.0"}),
        "log_destination": ok({"items": []}),
        "route": ok({"items": [dict(r) for r in routes]}),
        "failover_status": ok({"entries": {"https://localhost/mgmt/tm/cm/failover-status/0": {"nestedStats": {"entries": {
            "color": {"description": "green"}, "status": {"description": status}, "summary": {"description": "1/1 active"}}}}}}),
        "device_group": ok({"items": [{"name": "device_trust_group", "fullPath": "/Common/device_trust_group", "type": "sync-only",
                                       "devicesReference": {"items": devices}},
                                      {"name": "dg-ha", "fullPath": "/Common/dg-ha", "type": "sync-failover", "devicesReference": {"items": devices}}]}),
        "memory": ok({"entries": {"https://localhost/mgmt/tm/sys/memory/memory-host": {"nestedStats": {"entries": {
            "https://localhost/mgmt/tm/sys/memory/memory-host/0": {"nestedStats": {"entries": {
                "otherMemoryTotal": {"value": ot}, "otherMemoryUsed": {"value": ou}, "swapTotal": {"value": st_}, "swapUsed": {"value": su}}}}}}}}}),
        "cpu": ok({"entries": {"c": {"nestedStats": {"entries": {"cpuInfo": {"nestedStats": {"entries": {
            "0": {"nestedStats": {"entries": {"oneMinAvgIdle": {"value": 80}}}}, "1": {"nestedStats": {"entries": {"oneMinAvgIdle": {"value": 70}}}}}}}}}}}}),
        "_meta": {"device": {"label": label, "mgmt": mgmt}, "collected_at": collected_at,
                  "timings_s": {"version": 0.21, "memory": 0.35, "self": 0.18}, "collector": "observe-collect.sh/2"},
    }
    r.update(overrides)
    return r


def norm(raw):
    from autopilot.sources import observe
    return observe.normalize(raw)


def device(raw, did=None):
    from autopilot import placement
    m = norm(raw)
    ref = m["device_ref"] or {}
    return placement.device_from_model(did or f"bigip:{ref.get('mgmt')}", m, mgmt=ref.get("mgmt"), evidence_id=f"ev-{ref.get('label')}",
                                       origin="synthetic snapshot", mgmt_status="observed")


def plan(devs, **kw):
    from autopilot import identity, placement, web
    idn = identity.reconcile(web.STORE)
    return placement.evaluate(idn, devs, callers=placement.callers_from_store(web.STORE, idn), member_policy=POLICY, **{"now": NOW, **kw})


def chk(ev, name):
    return next(c for c in ev["checks"] if c["check"] == name)


# ------------------------------------------------------------------ 1. parser
def test_parser_extracts_subnets_routes_ha_and_health():
    m = norm(raw_device(routes=[{"fullPath": "/Common/default", "network": "default", "gw": "10.50.10.1"},
                                {"fullPath": "/Common/to_lab", "network": "10.60.0.0/16", "gw": "10.50.20.1"},
                                {"fullPath": "/Common/rd2", "network": "10.70.0.0%2/16", "gw": "10.50.30.1%2"},
                                {"fullPath": "/Common/vlan_rt", "network": "10.80.0.0/16", "tmInterface": "/Common/vlan_backend"},
                                {"fullPath": "/Common/bh", "network": "10.90.0.0/16", "blackhole": True},
                                {"fullPath": "/Common/v6", "network": "default-inet6", "gw": "fe80::1"}]))
    assert [n["network"] for n in m["self_ip_networks"]] == ["10.50.10.10/24", "10.50.20.10/24"]
    assert all(n["route_domain"] == 0 and n["floating"] is False for n in m["self_ip_networks"])
    assert [(r["network"], r["route_domain"], r["gw"], r["via"]) for r in m["routes"]] == [
        ("0.0.0.0/0", 0, "10.50.10.1", "gw"), ("10.60.0.0/16", 0, "10.50.20.1", "gw"), ("10.70.0.0/16", 2, "10.50.30.1", "gw"),
        ("10.80.0.0/16", 0, None, "interface"), ("10.90.0.0/16", 0, None, "blackhole")]
    assert m["ha"] == {"failover_state": "active", "mode": "standalone", "device_group": None, "summary": "1/1 active", "sync_failover_groups": 1}
    assert m["health"] == {"control_plane_memory_pct": 40.0, "swap_pct": 5.0, "cpu_pct": 25.0, "rest_latency_s": 0.35,
                           "rest_latency_method": "slowest of 3 read-only GETs in this collection", "sampled_at": T0,
                           "cpu_method": "100 - mean one-minute idle across the listed CPUs"}
    assert m["evidence_state"] == {"self_ip_networks": "observed", "routes": "observed", "ha": "observed", "health": "observed", "cpu": "observed",
                              "as3": "observed", "provision": "observed",
                              "virtuals": "observed", "pools": "observed"}
    assert m["device_ref"] == {"label": "bigip-x", "mgmt": "192.0.2.20"} and m["collected_at"] == T0


def test_clustered_device_group_and_standby_state():
    m = norm(raw_device(status="STANDBY", clustered=True))
    assert m["ha"] == {"failover_state": "standby", "mode": "clustered", "device_group": "/Common/dg-ha", "summary": "1/1 active",
                       "sync_failover_groups": 1}


def test_memory_arithmetic_equals_deployer_preflight():
    from autopilot.deployer import engine
    from autopilot.sources import observe
    for mem in ((1000, 400, 2000, 100), (5e9, 4.9e9, 1e9, 9.1e8), (1000, 0, 0, 0)):
        body = raw_device(mem=mem)["memory"]["body"]
        assert observe.memory_usage(body) == engine._memory(body)
    assert observe.memory_usage({"entries": {}}) is None and engine._memory({"entries": {}}) is None


@pytest.mark.parametrize("entry,state", [({"status": 403, "body": None}, "permission_denied"), ({"status": 401, "body": None}, "permission_denied"),
                                         ({"status": 404, "body": {"code": 404}}, "unsupported"), ({"status": 501, "body": None}, "unsupported"),
                                         ({"status": 200, "body": None}, "malformed"), ({"status": 0, "body": None}, "failed"),
                                         ({"status": 503, "body": None}, "failed")])
def test_evidence_states_are_distinguished(entry, state):
    m = norm(raw_device(route=entry, failover_status=entry, memory=entry))
    assert m["collection"]["route"]["state"] == state and m["evidence_state"]["routes"] == state and m["routes"] is None
    assert m["evidence_state"]["ha"] == state and m["evidence_state"]["health"] == state
    r = raw_device()
    del r["route"]
    assert norm(r)["evidence_state"]["routes"] == "missing"


def test_unexpected_shapes_are_malformed_not_guessed():
    m = norm(raw_device(failover_status=ok({"entries": {}}), memory=ok({"items": []}), cpu=ok({"weird": 1})))
    assert m["evidence_state"]["ha"] == "malformed" and m["evidence_state"]["health"] == "malformed" and m["evidence_state"]["cpu"] == "malformed"
    assert "control_plane_memory_pct" not in (m["health"] or {}) and "cpu_pct" not in (m["health"] or {})
    assert "failover_state" not in (m["ha"] or {}) and m["ha"]["mode"] == "standalone"      # device-group still observed


def test_legacy_model_fields_are_unchanged_by_the_new_evidence():
    """Adding the placement GETs changes no existing model field, so findings and packages cannot change."""
    from autopilot.sources import observe
    full = raw_device()
    legacy = {k: v for k, v in full.items() if k in observe.ENDPOINTS}       # what the deployer path / v1 collector produced
    a, b = norm(full), norm(legacy)
    old_keys = {"device", "vlans", "self_ips", "virtuals", "pools", "monitors", "irules", "persistence_profiles", "clientssl_profiles",
                "mgmt_log_destinations"}
    assert {k: a[k] for k in old_keys} == {k: b[k] for k in old_keys}
    assert all(set(s) == {"name", "address", "vlan"} for s in a["self_ips"])                  # legacy self IP shape kept
    assert b["evidence_state"] == {"self_ip_networks": "observed", "routes": "missing", "ha": "missing", "health": "missing", "cpu": "missing",
                                   "as3": "observed", "provision": "observed",
                              "virtuals": "observed", "pools": "observed"}
    assert [n["network"] for n in b["self_ip_networks"]] == ["10.50.10.10/24", "10.50.20.10/24"]   # subnets now kept on every path


# ------------------------------------------------------------------ 2. placement on parsed evidence: states, freshness, explanation
def test_complete_real_shaped_evidence_selects_with_explanation(world, no_network):
    from autopilot import placement
    world.run(LAB_SCAN, [trace_b()], name="complete")
    p = plan([device(raw_device())])
    assert p["status"] == "decided" and p["deployment_readiness"] == placement.NOT_PREFLIGHT
    rs = svc(p, "risk-scoring")
    ex = rs["selected"]["explanation"]
    assert rs["selected"]["device"] == "bigip:192.0.2.20"
    assert ex["why_selected"][0] == "all hard checks pass on observed/inferred evidence"
    assert {c.split(":")[0] for c in ex["checks_passed"]} == {"ltm_provisioned", "as3_available", "ha_state", "health", "backend_reachability"}
    assert ex["supporting_evidence"][0] == {"evidence_id": "ev-bigip-x", "what": "BIG-IP Observe record for bigip:192.0.2.20 (synthetic snapshot)",
                                            "collected_at": T0}
    assert placement.L3_ONLY in ex["unverified_assumptions"] and any("sampled 5 min before" in a for a in ex["unverified_assumptions"])
    assert any("instance relationship not observed" in a for a in ex["unverified_assumptions"]) or rs["uncertainty"] == []
    assert ex["deployment_readiness"] == placement.NOT_PREFLIGHT and "not deployment authorisation" in ex["deployment_readiness"]
    assert chk(rs["eligible"][0], "ha_state")["detail"] == "failover state active, standalone"


def test_stale_health_is_unknown_and_abstains(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="stale")
    f = svc(plan([device(raw_device(collected_at=NOW - 2000))]), "fraud-intel")
    h = chk(f["unverified"][0], "health")
    assert f["decision"] == "abstain" and h["result"] == "unknown" and h["evidence_state"] == "stale"
    assert h["detail"] == "sample is 33 min old (> 30 min, placement-health/v1.1) — collect a fresh snapshot"
    assert {"device": "bigip:192.0.2.20", "check": "health", "evidence_state": "stale", "detail": h["detail"]} in f["explanation"]["missing_evidence"]


def test_future_and_missing_timestamps_are_unknown(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="ts")
    f = svc(plan([device(raw_device(collected_at=NOW + 900))]), "fraud-intel")
    assert chk(f["unverified"][0], "health")["detail"] == "sample time is in the future (collector clock skew)"
    r = raw_device()
    r["_meta"] = {k: v for k, v in r["_meta"].items() if k != "collected_at"}
    f = svc(plan([device(r)]), "fraud-intel")
    assert chk(f["unverified"][0], "health")["detail"] == "health sample has no timestamp — freshness cannot be established"


def test_permission_denied_and_unsupported_are_explained(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="denied")
    d = device(raw_device(failover_status={"status": 403, "body": None}, device_group={"status": 403, "body": None}))
    f = svc(plan([d]), "fraud-intel")
    ha = chk(f["unverified"][0], "ha_state")
    assert ha["result"] == "unknown" and ha["evidence_state"] == "permission_denied" and "permission denied (HTTP 401/403)" in ha["detail"]
    world.run([mcp("10.60.5.5", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="unsupported routes")
    f = svc(plan([device(raw_device(route={"status": 404, "body": None}))]), "fraud-intel")
    rc = chk(f["unverified"][0], "backend_reachability")
    assert rc["result"] == "unknown" and "not supported by this device (HTTP 400/404/501)" in rc["detail"]


def test_routes_and_interface_routes_from_parsed_evidence(world, no_network):
    world.run([mcp("10.60.5.5", name="fraud-intel", tools=INTEL_TOOLS, fp="def"), mcp("10.80.1.1", name="other", tools=INTEL_TOOLS, fp="xyz")],
              [], name="routed")
    p = plan([device(raw_device(routes=[{"fullPath": "/Common/to_lab", "network": "10.60.0.0/16", "gw": "10.50.20.1"},
                                        {"fullPath": "/Common/vlan_rt", "network": "10.80.0.0/16", "tmInterface": "/Common/vlan_backend"}]))])
    f, o = svc(p, "fraud-intel"), svc(p, "other")
    assert f["selected"] and "via static route 10.60.0.0/16 (gateway 10.50.20.1 on a self IP subnet)" in chk(f["eligible"][0], "backend_reachability")["detail"]
    assert any("upstream gateway" in a for a in f["selected"]["explanation"]["unverified_assumptions"])
    assert o["selected"] and "(interface route)" in chk(o["eligible"][0], "backend_reachability")["detail"]


def test_preflight_warning_health_is_eligible_with_the_warning_explained(world, no_network):
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="warn")
    r = raw_device(mem=(1000, 500, 1000, 910))
    r["_meta"]["timings_s"]["version"] = 2.8                              # BIG-IP_C's last known state: swap 91 %, REST 2.8 s
    f = svc(plan([device(r)]), "fraud-intel")
    assert f["decision"] == "selected"
    assert {"Health warning (not a failure): swap_pct 91.0 >= 75.0 (warn).", "Health warning (not a failure): rest_latency_s 2.8 >= 2.0 (warn)."} \
        <= set(f["selected"]["explanation"]["unverified_assumptions"])


def test_explanations_never_claim_deployment_readiness(world, no_network):
    world.run(LAB_SCAN, [trace_b()], name="wording")
    txt = json.dumps(plan([device(raw_device())])).lower()
    for claim in ("ready to deploy", "deployment ready", "guaranteed", "safe to deploy", "will succeed"):
        assert claim not in txt, claim


# ------------------------------------------------------------------ 3. snapshot upload + multi-device ingest (API)
@pytest.fixture()
def token(world, monkeypatch):
    from autopilot import web
    monkeypatch.setattr(web, "TOKEN_SHA256", hashlib.sha256(b"op-token").hexdigest())
    return {"Authorization": "Bearer op-token"}


def test_multi_device_snapshots_become_one_registry_record_each(world, token, no_network):
    from autopilot import advisory, web
    world.run(LAB_SCAN, [trace_b()], name="multi")
    for label, mgmt, host in (("edge-a", "192.0.2.21", "a.example.test"), ("edge-b", "192.0.2.22", "b.example.test")):
        r = world.anon.post("/api/observe/snapshot", json=raw_device(label=label, mgmt=mgmt, hostname=host, collected_at=1792000000.0), headers=token)
        assert r.status_code == 200 and r.json()["device"] == label, r.text
    lst = world.viewer.get("/api/observe/snapshots").json()
    assert [(x["label"], x["device"]["mgmt"]) for x in lst] == [("edge-a", "192.0.2.21"), ("edge-b", "192.0.2.22")]
    assert all(x["evidence_state"]["health"] == "observed" for x in lst)
    assert world.viewer.post("/api/discover/observe/snapshots").status_code == 403
    r = world.op.post("/api/discover/observe/snapshots")
    assert r.status_code == 200 and [d["device"] for d in r.json()["devices"]] == ["edge-a", "edge-b"], r.text
    adcs = sorted(a["key"] for a in web.STORE.assets() if a["kind"] == "adc")
    assert {"bigip:192.0.2.21", "bigip:192.0.2.22"} <= set(adcs)
    a = advisory.build(web.STORE, web.CFG, now=1792000300)
    devs = {d["id"]: d for d in a["placement"]["devices"]}
    assert set(devs) == {"bigip:192.0.2.21", "bigip:192.0.2.22"} and all(d["mgmt"]["status"] == "observed" for d in devs.values())
    rs = next(p for p in a["proposals"] if p["service"]["name"] == "risk-scoring")
    assert rs["decision"] == "selected" and rs["proposal"]["device"] == "bigip:192.0.2.21"     # equal devices: device-id tie-break
    assert "deterministic tie-break on device id" in " ".join(next(s for s in a["placement"]["services"] if s["service"]["name"] == "risk-scoring")["selected"]["why"])
    assert a["deployment_readiness"].startswith("Placement is advisory")


def test_snapshot_upload_validation(world, token):
    good = raw_device()
    for bad, why in (({**good, "shell": {"status": 200, "body": {}}}, "unexpected snapshot keys"),
                     ({**good, "_meta": {**good["_meta"], "device": {"label": "../x", "mgmt": "192.0.2.1"}}}, "label"),
                     ({**good, "_meta": {**good["_meta"], "device": {"label": "ok", "mgmt": "a b"}}}, "label"),
                     ({**good, "_meta": {**good["_meta"], "collected_at": 9e9}}, "collected_at"),
                     ({**good, "_meta": {**good["_meta"], "timings_s": {"version": -1}}}, "timings_s"),
                     ({**good, "route": {"body": {}}}, "status: int")):
        r = world.anon.post("/api/observe/snapshot", json=bad, headers=token)
        assert r.status_code == 422 and why in r.text, (why, r.text)
    assert world.anon.post("/api/observe/snapshot", json=good).status_code == 401


def test_legacy_snapshot_upload_and_fallback_are_unchanged(world, token, tmp_path):
    from autopilot import web
    from autopilot.sources import observe
    legacy = {k: v for k, v in raw_device().items() if k in observe.ENDPOINTS}
    r = world.anon.post("/api/observe/snapshot", json=legacy, headers=token)
    assert r.status_code == 200 and r.json()["stored"].startswith("bigip-") and "device" not in r.json()
    assert world.anon.post("/api/observe/snapshot", json=raw_device(), headers=token).status_code == 200
    top = sorted(os.listdir(web.SNAPSHOT_DIR))
    assert "devices" in top and [f for f in top if f.endswith(".json")] == [r.json()["stored"]] or len([f for f in top if f.endswith(".json")]) == 1


# ------------------------------------------------------------------ 4. collector script (stubs; no network)
STUB_CURL = r'''#!/usr/bin/env python3
import json, os, sys
log = os.environ["STUB_LOG"]
args = sys.argv[1:]
conf = ""
if "-K" in args:
    conf = open(args[args.index("-K") + 1]).read()
with open(log, "a") as f:
    f.write(json.dumps({"argv": args, "K": conf}) + "\n")
if "-X" in args:                                   # upload to Autopilot
    open(os.environ["STUB_UPLOAD"], "a").write(sys.stdin.read())
    print('{"stored":"x"}')
    sys.exit(0)
fail = os.environ.get("STUB_FAIL")
if fail == "pin":
    sys.stdout.write("000 0.010"); sys.exit(90)
if fail == "tls":
    sys.stdout.write("000 0.010"); sys.exit(35)
url = args[-1]
out = args[args.index("-o") + 1]
if fail == "auth" or (fail == "as3-401" and "/appsvcs/" in url):
    json.dump({"code": 401, "message": "Authorization failed"}, open(out, "w")); sys.stdout.write("401 0.050"); sys.exit(0)
path = url.split("192.0.2.30", 1)[1]
bodies = json.load(open(os.environ["STUB_BODIES"]))
code, body = bodies.get(path, [404, {"code": 404}])
json.dump(body, open(out, "w"))
sys.stdout.write(f"{code} 0.123")
'''
STUB_SECURITY = r'''#!/bin/sh
case "$*" in
  *"-w"*) case "$*" in *op-token-item*) echo "OP-TOKEN-SECRET" ;; *) echo 'S3cret"PW\x' ;; esac ;;
  *) echo '    "acct"<blob>="observer"' ;;
esac
'''


def _collector_env(tmp_path, devices_conf, pins="TESTPIN=sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"):
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "curl").write_text(STUB_CURL)
    (stub / "security").write_text(STUB_SECURITY)
    for f in ("curl", "security"):
        (stub / f).chmod(0o755)
    conf = tmp_path / "conf"
    conf.mkdir()
    (conf / "observe-devices.conf").write_text(devices_conf)
    (conf / "f5-tls-pins.env").write_text(pins)
    (conf / "observe-collector.env").write_text("AUTOPILOT_URL=http://autopilot.test:8000\nAUTOPILOT_TOKEN_ITEM=op-token-item\n")
    from autopilot.sources import observe
    raw = raw_device()
    paths = {**observe.ENDPOINTS, **observe.PLACEMENT_ENDPOINTS}
    bodies = {p: [raw[k]["status"], raw[k]["body"]] for k, p in paths.items()}
    bodies[observe.PLACEMENT_ENDPOINTS["failover_status"]] = [403, {"code": 403, "message": "denied"}]
    (tmp_path / "bodies.json").write_text(json.dumps(bodies))
    env = {**os.environ, "PATH": f"{stub}:{os.environ['PATH']}", "OBSERVE_CONFIG_DIR": str(conf), "STUB_LOG": str(tmp_path / "log.jsonl"),
           "STUB_UPLOAD": str(tmp_path / "upload.json"), "STUB_BODIES": str(tmp_path / "bodies.json")}
    return env


def test_collector_endpoint_list_matches_the_parser():
    from autopilot.sources import observe
    src = (ROOT / "scripts" / "observe-collect.sh").read_text()
    block = src[src.index("typeset -A EP=("):src.index(")\n\ncq()")]
    pairs = dict(re.findall(r'(\w+) "?(/mgmt/[^\s"]+)"?', block))
    assert pairs == {**observe.ENDPOINTS, **observe.PLACEMENT_ENDPOINTS}
    assert "192.168." not in src and "192.0.2." not in src and "BIGIP=" not in src                     # no lab constants in the script


def test_collector_preserves_the_security_model_and_produces_a_valid_snapshot(world, tmp_path):
    from autopilot import web
    env = _collector_env(tmp_path, "# comment\nlab-x 192.0.2.30 TESTPIN bigip-ro-item\n")
    p = subprocess.run(["/bin/zsh", str(ROOT / "scripts" / "observe-collect.sh"), "--out", str(tmp_path / "out")], env=env,
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    calls = [json.loads(x) for x in (tmp_path / "log.jsonl").read_text().splitlines()]
    gets, posts = [c for c in calls if "-X" not in c["argv"]], [c for c in calls if "-X" in c["argv"]]
    assert len(gets) == 21 and len(posts) == 1 and all(c["argv"][0] == "-q" for c in calls)
    for c in gets:
        assert c["argv"][c["argv"].index("--pinnedpubkey") + 1].startswith("sha256//")    # every BIG-IP request pinned
        assert c["argv"][-1].startswith("https://192.0.2.30/mgmt/") and "-X" not in c["argv"]  # GET only
        assert 'user = "observer:S3cret\\"PW\\\\x"' in c["K"]                             # credential via -K file, escaped
    everything = json.dumps([c["argv"] for c in calls]) + p.stdout + p.stderr
    assert "S3cret" not in everything and "OP-TOKEN-SECRET" not in everything               # never in argv or output
    assert posts[0]["argv"][posts[0]["argv"].index("-X") + 1] == "POST" and "Bearer OP-TOKEN-SECRET" in posts[0]["K"]
    snap = json.loads((tmp_path / "upload.json").read_text())
    assert web._validate_snapshot(snap) == {"label": "lab-x", "mgmt": "192.0.2.30"}
    m = norm(snap)
    assert m["evidence_state"]["ha"] == "permission_denied" and m["evidence_state"]["routes"] == "observed"
    assert m["health"]["rest_latency_s"] == 0.123 and m["collected_at"] > 1.6e9
    local = list((tmp_path / "out").iterdir())
    assert len(local) == 1 and oct(local[0].stat().st_mode)[-3:] == "600" and json.loads(local[0].read_text()) == snap
    assert "S3cret" not in local[0].read_text()


def test_collector_refuses_devices_without_a_pin_or_with_bad_labels(tmp_path):
    env = _collector_env(tmp_path, "nopin 192.0.2.30 MISSINGPIN bigip-ro-item\n../bad 192.0.2.30 TESTPIN bigip-ro-item\n")
    p = subprocess.run(["/bin/zsh", str(ROOT / "scripts" / "observe-collect.sh"), "--no-upload"], env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 1 and "no pinned public key" in p.stderr and "invalid device line" in p.stderr
    assert not (tmp_path / "log.jsonl").exists()                                       # nothing was contacted
    p = subprocess.run(["/bin/zsh", str(ROOT / "scripts" / "observe-collect.sh"), "--no-upload", "unknown-label"], env=env,
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "no matching device" in p.stderr


# ------------------------------------------------------------------ 5. Phase-1 safety checks (offline)
def _run_collector(env, *args):
    return subprocess.run(["/bin/zsh", str(ROOT / "scripts" / "observe-collect.sh"), *args], env=env, capture_output=True, text=True, timeout=120)


def test_every_device_request_uses_the_safe_curl_options(tmp_path):
    env = _collector_env(tmp_path, "lab-x 192.0.2.30 TESTPIN bigip-ro-item\n")
    assert _run_collector(env, "--no-upload", "--out", str(tmp_path / "o")).returncode == 0
    calls = [json.loads(x)["argv"] for x in (tmp_path / "log.jsonl").read_text().splitlines()]
    assert len(calls) == 21                                                     # --no-upload: no POST, no token read
    for a in calls:
        assert a[0] == "-q"                                                     # ~/.curlrc ignored
        assert a[a.index("--proto") + 1] == "=https" and "--tlsv1.2" in a and a[a.index("--noproxy") + 1] == "*"
        assert not {"-L", "--location", "-X", "--request", "--data", "-d", "--data-binary"} & set(a)
        assert a[-1].startswith("https://") and "http://" not in " ".join(a)


@pytest.mark.parametrize("mode,msg", [("pin", "curl exit 90: pinned public key mismatch"),
                                      ("auth", "authentication failed (HTTP 401)"), ("tls", "curl exit 35: TLS handshake failed")])
def test_tls_pin_or_auth_failure_stops_the_device_without_fallback(tmp_path, mode, msg):
    env = _collector_env(tmp_path, "lab-x 192.0.2.30 TESTPIN bigip-ro-item\n")
    env["STUB_FAIL"] = mode
    p = _run_collector(env, "--out", str(tmp_path / "o"))
    calls = [json.loads(x)["argv"] for x in (tmp_path / "log.jsonl").read_text().splitlines()]
    assert p.returncode == 1 and msg in p.stderr and "nothing written or uploaded" in p.stderr
    assert len(calls) == 1 and "-X" not in calls[0]                             # one attempt, no retry, no upload
    assert not list((tmp_path / "o").iterdir()) and not (tmp_path / "upload.json").exists()


def test_secret_bearing_fields_are_redacted_and_parsing_still_works(world, tmp_path):
    from autopilot.sources import observe
    env = _collector_env(tmp_path, "lab-x 192.0.2.30 TESTPIN bigip-ro-item\n")
    bodies = json.loads((tmp_path / "bodies.json").read_text())
    bodies[observe.ENDPOINTS["clientssl"]] = [200, {"items": [{"fullPath": "/Common/cssl", "peerCertMode": "require", "passphrase": "$M$xyzENC",
                                                             "certKeyChain": [{"name": "c", "passphrase": "$M$abc"}]}]}]
    bodies[observe.ENDPOINTS["monitor_http"]] = [200, {"items": [{"fullPath": "/Common/mon_auth", "username": "svc", "password": "hunter2",
                                                                "send": "GET / HTTP/1.1\\r\\nAuthorization: Basic c3ZjOmh1bnRlcjI=\\r\\n\\r\\n",
                                                                "recv": "200 OK"}]}]
    bodies[observe.ENDPOINTS["rule"]] = [200, {"items": [{"fullPath": "/Common/my_rule", "apiAnonymous": "when HTTP_REQUEST { set k \"apikey-123\" }"}]}]
    bodies[observe.ENDPOINTS["global"]] = [200, {"hostname": "bigip-x", "guiSecurityBanner": "enabled", "note": "Cookie: session=abc123"}]
    (tmp_path / "bodies.json").write_text(json.dumps(bodies))
    assert _run_collector(env, "--no-upload", "--out", str(tmp_path / "o")).returncode == 0
    f = next((tmp_path / "o").iterdir())
    txt = f.read_text()
    for secret in ("$M$xyzENC", "$M$abc", "hunter2", "c3ZjOmh1bnRlcjI=", "apikey-123", "session=abc123"):
        assert secret not in txt, secret
    snap = json.loads(txt)
    assert snap["_meta"]["redaction"].startswith("secret-named fields")
    m = norm(snap)
    assert m["irules"] == ["/Common/my_rule"] and m["monitors"] == ["/Common/mon_auth"]
    assert m["clientssl_profiles"] == [{"name": "/Common/cssl", "peer_cert_mode": "require"}] and m["device"]["hostname"] == "bigip-x"
    assert oct(f.stat().st_mode)[-3:] == "600" and oct((tmp_path / "o").stat().st_mode)[-3:] == "700"


def test_share_extract_keeps_only_parser_inputs(tmp_path):
    cap = raw_device()
    cap["global"] = ok({"hostname": "secret-host"})
    cap["monitor_http"] = ok({"items": [{"fullPath": "/Common/m", "password": "pw"}]})
    cap["memory"]["body"]["password"] = "x"
    src, dst = tmp_path / "cap.json", tmp_path / "share.json"
    src.write_text(json.dumps(cap))
    p = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "observe-share.py"), str(src), str(dst)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    out = json.loads(dst.read_text())
    assert set(out) == {"version", "provision", "as3", "self", "route", "failover_status", "device_group", "memory", "cpu", "_meta"}
    assert "secret-host" not in dst.read_text() and out["memory"]["body"]["password"] == "[REDACTED]"
    assert oct(dst.stat().st_mode)[-3:] == "600"
    m = norm(out)                                                               # still enough for every placement parser
    assert m["evidence_state"] == {"self_ip_networks": "observed", "routes": "observed", "ha": "observed", "health": "observed", "cpu": "observed",
                              "as3": "observed", "provision": "observed",
                              "virtuals": "missing", "pools": "missing"}   # not in the share: never "observed: none"


def _tls_server(tmp_path):
    """A loopback HTTPS server with a fresh self-signed key — exercises the REAL curl binary, not a stub."""
    import http.server
    import ssl
    import threading
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=loopback-test", "-days", "1",
                    "-keyout", str(key), "-out", str(crt)], check=True, capture_output=True)
    pub = subprocess.run(["openssl", "x509", "-in", str(crt), "-pubkey", "-noout"], check=True, capture_output=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pub, check=True, capture_output=True).stdout
    import base64
    pin = "sha256//" + base64.b64encode(hashlib.sha256(der).digest()).decode()
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(("GET", self.path, bool(self.headers.get("Authorization"))))
            body = json.dumps({"items": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, pin, seen


def test_real_curl_refuses_a_wrong_pin_even_with_k_and_ignores_curlrc(tmp_path):
    import shutil
    if not shutil.which("openssl") or not shutil.which("curl"):
        pytest.skip("openssl/curl not available")
    srv, pin, seen = _tls_server(tmp_path)
    host = f"127.0.0.1:{srv.server_address[1]}"
    try:
        env = _collector_env(tmp_path, f"loop {host} GOODPIN bigip-ro-item\nloopbad {host} BADPIN bigip-ro-item\n",
                             pins=f"GOODPIN={pin}\nBADPIN=sha256//{'A' * 43}=\n")
        os.remove(tmp_path / "bin" / "curl")                                    # use the real curl
        home = tmp_path / "home"
        home.mkdir()
        (home / ".curlrc").write_text("insecure\nproxy = http://127.0.0.1:9\n")  # hostile ~/.curlrc must be ignored (-q)
        env.update(HOME=str(home), https_proxy="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9")
        p = _run_collector(env, "--no-upload", "--out", str(tmp_path / "o"), "loopbad")
        assert p.returncode == 1 and "curl exit 90: pinned public key mismatch" in p.stderr
        assert seen == []                                                      # no HTTP request ever reached the server
        p = _run_collector(env, "--no-upload", "--out", str(tmp_path / "o"), "loop")
        assert p.returncode == 0, p.stderr
        assert len(seen) == 21 and all(m == "GET" and auth for m, _, auth in seen)
        snap = json.loads(next((tmp_path / "o").iterdir()).read_text())
        assert snap["_meta"]["device"] == {"label": "loop", "mgmt": host} and snap["route"]["status"] == 200
    finally:
        srv.shutdown()


def test_advisory_separates_placement_eligibility_from_deployment_engine_support(world, no_network):
    from autopilot import advisory, web
    from test_wave3_placement import fixture_devices
    world.run(LAB_SCAN, [trace_b()], name="engine support")
    web.STORE.add_evidence("observe", "fixture", "fixture", {"origin": "fixture", "model": norm(raw_device(mgmt="192.0.2.16", label="BIG-IP_C",
                                                                                                           collected_at=NOW - 60))})
    a = advisory.build(web.STORE, web.CFG, extra_devices=fixture_devices(), environment=None, now=NOW)
    de = a["deployment_engine"]
    assert de["targets"] == ["192.0.2.16"] and "not the same as supported by the deployment engine" in de["statement"]
    assert de["devices"]["bigip:192.0.2.16"]["supported"] is True and de["devices"]["bigip-a"]["supported"] is False
    assert "advisory only" in de["devices"]["bigip-a"]["detail"] and "preflight" in de["devices"]["bigip:192.0.2.16"]["detail"]
    for p in a["proposals"]:
        if p["proposal"]:
            assert p["proposal"]["deployment_engine"]["supported"] == (p["proposal"]["device"] == "bigip:192.0.2.16")


def test_first_request_is_the_credential_check_and_order_is_fixed(tmp_path):
    env = _collector_env(tmp_path, "lab-x 192.0.2.30 TESTPIN bigip-ro-item\n")
    assert _run_collector(env, "--no-upload", "--out", str(tmp_path / "o")).returncode == 0
    urls = [json.loads(x)["argv"][-1].split("192.0.2.30", 1)[1] for x in (tmp_path / "log.jsonl").read_text().splitlines()]
    assert urls[0] == "/mgmt/tm/sys/version" and len(urls) == len(set(urls)) == 21
    first = urls
    (tmp_path / "log.jsonl").unlink()
    assert _run_collector(env, "--no-upload", "--out", str(tmp_path / "o2")).returncode == 0
    assert [json.loads(x)["argv"][-1].split("192.0.2.30", 1)[1] for x in (tmp_path / "log.jsonl").read_text().splitlines()] == first


def test_per_resource_401_is_permission_denied_not_an_abort_or_a_rejection(world, tmp_path, no_network):
    """BIG-IP answers RBAC denials on /mgmt/shared/* with 401: the capture continues and AS3 becomes unknown, not 'not installed'."""
    env = _collector_env(tmp_path, "lab-x 192.0.2.30 TESTPIN bigip-ro-item\n")
    env["STUB_FAIL"] = "as3-401"
    p = _run_collector(env, "--no-upload", "--out", str(tmp_path / "o"))
    assert p.returncode == 0, p.stderr
    snap = json.loads(next((tmp_path / "o").iterdir()).read_text())
    assert len(snap) == 22 and snap["as3"]["status"] == 401
    m = norm(snap)
    assert m["evidence_state"]["as3"] == "permission_denied" and m["device"]["as3_installed"] is False   # legacy flag unchanged
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="as3 denied")
    snap["_meta"]["collected_at"] = NOW - 60
    f = svc(plan([device(snap)]), "fraud-intel")
    a3 = chk(f["unverified"][0], "as3_available")
    assert f["decision"] == "abstain" and a3["result"] == "unknown" and a3["evidence_state"] == "permission_denied"
    assert "permission denied" in a3["detail"]
    nf = copy.deepcopy(snap)
    nf["as3"] = {"status": 404, "body": {"code": 404}}
    f = svc(plan([device(nf)]), "fraud-intel")
    assert f["decision"] == "no_eligible_device" and f["rejected"][0]["reasons"] == ["AS3 not installed (appsvcs/info: HTTP 404)"]


def test_snapshot_retention_keeps_the_newest_per_device_only(world, token, monkeypatch):
    from autopilot import web
    monkeypatch.setattr(web, "SNAPSHOT_KEEP", 3)
    for i in range(5):
        assert world.anon.post("/api/observe/snapshot", json=raw_device(label="edge-a", collected_at=1792000000.0 + i), headers=token).status_code == 200
    assert world.anon.post("/api/observe/snapshot", json=raw_device(label="edge-b", collected_at=1792000000.0), headers=token).status_code == 200
    d = pathlib.Path(web.SNAPSHOT_DIR) / "devices"
    a = sorted(os.listdir(d / "edge-a"))
    assert len(a) == 3 and all(f.startswith(("1792000002", "1792000003", "1792000004")) for f in a)
    assert len(os.listdir(d / "edge-b")) == 1                                      # other devices untouched
    rows = [r for r in world.ap.get("/api/audit").json()["rows"] if r["action"] == "observe.snapshot.uploaded"]
    assert any("pruned" in json.dumps(r) for r in rows)                            # pruning is audited


def test_reachability_names_the_missing_evidence_state(world, no_network):
    world.run([mcp("10.60.5.5", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="reach states")
    states = {}
    for label, raw in (("route-404", raw_device(route={"status": 404, "body": None})),
                       ("route-403", raw_device(route={"status": 403, "body": None})),
                       ("default-only", raw_device(routes=[{"fullPath": "/Common/default", "network": "default", "gw": "10.50.10.1"}]))):
        f = svc(plan([device(raw)]), "fraud-intel")
        states[label] = chk(f["unverified"][0], "backend_reachability")["evidence_state"]
    r = raw_device()
    r["self"] = {"status": 403, "body": None}
    f = svc(plan([device(r)]), "fraud-intel")
    assert states == {"route-404": "unsupported", "route-403": "permission_denied", "default-only": "insufficient"}
    assert f["decision"] in ("abstain", "no_eligible_device")


def test_legacy_stored_model_without_prefix_reports_missing_subnets(world, no_network):
    from autopilot import placement
    from test_wave3_placement import LAB
    world.run([mcp("10.50.20.33", name="fraud-intel", tools=INTEL_TOOLS, fp="def")], [], name="legacy reach")
    d = placement.device_from_model("bigip:192.0.2.16", LAB["model"], mgmt="192.0.2.16", evidence_id="e", origin="o", mgmt_status="configured")
    f = svc(plan([d]), "fraud-intel")
    assert chk(f["unverified"][0], "backend_reachability")["evidence_state"] == "missing"
