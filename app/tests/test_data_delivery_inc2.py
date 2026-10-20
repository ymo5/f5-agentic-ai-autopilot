"""AI Data Delivery, increment 2 (OFFLINE): Recommend + Validate integration.

Everything here runs against local mocks: the in-memory MockBigip / MockHosts of the deployer and small HTTP servers on
127.0.0.1 that behave like SeaweedFS, Qdrant and Ollama. "BIG-IP counters" in the validator scenarios are simulated by
the test harness. Nothing proves the live lab; the live proof is the after-data validation gate on BIG-IP_C (Approval A).
"""
from __future__ import annotations

import asyncio
import copy
import json
import pathlib
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import conftest  # noqa: E402
from conftest import discover, review  # noqa: E402

ROOT = HERE.parent.parent
OVERLAY = yaml.safe_load((ROOT / "deploy" / "autopilot" / "data-delivery.overlay.yaml").read_text())
DD = OVERLAY["design"]["data_delivery"]
DATA_SCAN = [
    {"ip": "10.50.20.41", "port": 8333, "protocol": "http", "kind": "object_store", "name": "s3", "s3": {"anonymous_list": False, "server": "SeaweedFS"}},
    {"ip": "10.50.20.40", "port": 6333, "protocol": "http", "kind": "vector_db", "name": "qdrant",
     "vector_db": {"product": "qdrant", "unauthenticated_read": True, "collections": ["fraud_patterns"]}},
    {"ip": "10.50.20.45", "port": 11434, "protocol": "http", "kind": "llm_endpoint", "name": "llm@10.50.20.45",
     "llm": {"unauthenticated": True, "models": ["qwen2.5:3b"]}},
]
DATA_TESTS = ["data.pools_healthy", "data.s3_via_front_door", "data.s3_sigv4_enforced", "data.rag_via_front_door",
              "data.llm_via_front_door", "data.bigip_statistics"]


def merged_config(tmp_path):
    cfg = yaml.safe_load((ROOT / "deploy" / "autopilot" / "autopilot.yaml").read_text())
    cfg["design"]["data_delivery"] = copy.deepcopy(DD)
    cfg.setdefault("validation", {})["data"] = copy.deepcopy(OVERLAY["validation"]["data"])
    p = tmp_path / "autopilot-with-data-delivery.yaml"
    p.write_text(yaml.safe_dump(cfg, sort_keys=False))
    return p


@pytest.fixture()
def dd_on(tmp_path, monkeypatch):
    """Config = autopilot.yaml + the opt-in data-delivery overlay; scan includes the three data services."""
    monkeypatch.setattr(conftest, "CFG", merged_config(tmp_path))
    monkeypatch.setattr(conftest, "SCAN", conftest.SCAN + DATA_SCAN)


@pytest.fixture()
def dctx(dd_on, ctx):
    return ctx


def norm(pkgs, aid):
    return json.loads(json.dumps(pkgs).replace(aid, "<AID>"))


def approve(c, pid):
    review(c, pid)
    return c.ap.post(f"/api/packages/{pid}/decision", json={"decision": "approved", "comment": "test"})


def deploy(c, pid):
    approve(c, pid)
    return c.ap.post(f"/api/packages/{pid}/deploy").json()


# ============================================================ Recommend: opt-in, cumulative, immutable
def test_without_overlay_no_d006_and_no_data_package(monkeypatch, ctx):
    from autopilot import web
    ids = discover(ctx)
    assert set(ids) == {"delivery", "security"}
    assert not [f for f in ctx.viewer.get("/api/findings").json().get("findings", []) if f.get("rule_id") == "D-006"]
    assert "data_delivery" not in web.CFG["design"]


def test_data_package_is_cumulative_valid_and_proven_by_data_checks(dctx):
    from autopilot import data_delivery as D
    from autopilot.deployer import policy
    ids = discover(dctx)
    assert list(ids) == ["delivery", "security", "data"]
    pk = {p["kind"]: p for p in dctx.ap.get("/api/packages").json()}
    data, sec = pk["data"], pk["security"]
    body = data["body"]
    assert body["requires"] == "security" and body["gate_profile"] == "after-data" and body["dependencies"] == []
    assert body["as3"] == D.extend(sec["body"]["as3"], DD)                  # exactly Security + additions
    assert body["as3_diff"]["modified_existing"] == [] and body["as3_diff"]["base"].startswith("AI Security")
    assert data["validation"]["valid"] is True and policy.check_as3(body["as3"]) == []
    assert body["expected_outcomes"]["closes"] == ["D-006"] and body["expected_outcomes"]["proven_by"] == DATA_TESTS
    expl = body["explanation"]
    assert [a["rule"] for a in expl["findings_addressed"]] == ["D-006"] and expl["findings_addressed"][0]["count"] == 3
    assert any("HTTP virtual server 10.50.10.103:8333" in c["detail"] for c in expl["change_summary"])
    assert data["recommendation"]["finding_ids"]                             # linked to the three D-006 findings


def test_enabling_data_delivery_leaves_delivery_and_security_byte_identical(dctx):
    from autopilot import web
    discover(dctx)
    aid_on = web.STORE.current()["id"]
    on = {p["kind"]: {k: p[k] for k in ("title", "target", "body")} for p in dctx.ap.get("/api/packages").json()}
    saved = web.CFG["design"].pop("data_delivery")
    try:
        dctx.op.post("/api/assessment/new", json={"name": "without data delivery"})
        ids = discover(dctx)
        aid_off = web.STORE.current()["id"]
        off = {p["kind"]: {k: p[k] for k in ("title", "target", "body")} for p in dctx.ap.get("/api/packages").json()}
    finally:
        web.CFG["design"]["data_delivery"] = saved
    assert set(ids) == {"delivery", "security"}
    for kind in ("delivery", "security"):
        assert json.dumps(norm(on[kind], aid_on), sort_keys=True) == json.dumps(norm(off[kind], aid_off), sort_keys=True), kind


def test_no_data_package_when_services_already_fronted_or_absent(tmp_path, monkeypatch, ctx):
    monkeypatch.setattr(conftest, "CFG", merged_config(tmp_path))       # overlay on, but no data services discovered
    ids = discover(ctx)
    assert "data" not in ids


# ============================================================ Deploy: gates, read-back, rollback (mock BIG-IP)
def test_data_package_requires_validated_security(dctx):
    ids = discover(dctx)
    rr = dctx.ap.post(f"/api/packages/{ids['data']}/decision", json={"decision": "approved", "comment": "t"})
    assert rr.status_code == 409 and "Preview, diff & preflight" in rr.json()["detail"]   # existing review gate
    rr = approve(dctx, ids["data"])                                       # review recorded; preflight sequence gate refuses
    assert rr.status_code == 409 and "sequence.requires" in rr.json()["detail"]
    assert dctx.ap.post(f"/api/packages/{ids['data']}/deploy").status_code == 409
    assert [x for x in dctx.bigip.calls if x[0] in ("POST", "DELETE")] == []


def test_full_sequence_success_readback_and_rollback_to_security(dctx):
    ids = discover(dctx)
    assert deploy(dctx, ids["delivery"])["status"] == "succeeded"
    assert deploy(dctx, ids["security"])["status"] == "succeeded"
    sec_tenant = json.loads(json.dumps(dctx.bigip.tenant))
    mutating = lambda: [c for c in dctx.hosts.calls if c[1].startswith(("profile ", "replica "))]
    before_mut = len(mutating())
    d = deploy(dctx, ids["data"])
    assert d["status"] == "succeeded", d
    steps = [s["step"] for s in d["steps"]]
    assert steps == ["preflight", "window.check[before dry-run]", "as3.dry_run", "window.check[before first write]", "as3.deploy",
                     "verify.bigip_config", "gate.validate[after-data]"]
    rb = next(s for s in d["steps"] if s["step"] == "verify.bigip_config")["detail"]
    assert rb["verified_objects"] == 6 and "/AP_AI/s3_seaweedfs/service" in rb["virtual_servers"]
    assert len(mutating()) == before_mut                                # the data package never changes a host (status reads only)
    t = dctx.bigip.tenant
    assert {"s3_seaweedfs", "rag_qdrant", "llm_ollama"} <= set(t) and t["Shared"]["tls_server_mtls"] == sec_tenant["Shared"]["tls_server_mtls"]
    for k, v in sec_tenant.items():                                     # Security objects intact on the device
        assert t[k] == v or k == "Shared"
    assert all(t["Shared"][o] == v for o, v in sec_tenant["Shared"].items())
    assert dctx.ap.post(f"/api/deployments/{d['id']}/rollback").status_code == 200
    assert dctx.bigip.tenant == sec_tenant and set(dctx.hosts.profile.values()) == {"security"}


@pytest.mark.parametrize("fault,needle", [("drop_stats", "statistics profile stats_s3 not attached"),
                                          ("add_client_ssl", "declared HTTP but has client-SSL"),
                                          ("drop_vlans", "VLAN restriction")])
def test_readback_mismatch_rolls_back(dctx, fault, needle):
    ids = discover(dctx)
    deploy(dctx, ids["delivery"]); deploy(dctx, ids["security"])
    sec_tenant = json.loads(json.dumps(dctx.bigip.tenant))
    dctx.bigip.profile_faults["s3_seaweedfs"] = fault
    d = deploy(dctx, ids["data"])
    assert d["status"] == "failed-rolled-back" and needle in d["error"]
    st = {s["step"]: s["status"] for s in d["steps"]}
    assert st["verify.bigip_config"] == "failed" and st["rollback"] == "ok" and "gate.validate[after-data]" not in st
    assert dctx.bigip.tenant == sec_tenant and set(dctx.hosts.profile.values()) == {"security"}


def test_existing_https_tls_readback_check_still_enforced(dctx):
    ids = discover(dctx)
    dctx.bigip.profile_faults["mcp_risk_scoring"] = "drop_tls"
    d = deploy(dctx, ids["delivery"])
    assert d["status"] == "failed-rolled-back" and "client-SSL profile tls_server not attached" in d["error"]


def test_failed_health_check_in_gate_rolls_back(dctx):
    """Real data_checks in the gate: BIG-IP (mock) reports the S3 pool member down -> gate fails -> automatic rollback."""
    from autopilot import validate
    ids = discover(dctx)
    deploy(dctx, ids["delivery"]); deploy(dctx, ids["security"])
    sec_tenant = json.loads(json.dumps(dctx.bigip.tenant))
    lab = Lab(); cfg = lab.cfg()
    dctx.bigip.member_state["10.50.20.41:8333"] = "offline"

    async def gate(profile):
        out = []
        await validate.data_checks(cfg, lambda req: dctx.engine.validation_action(req, internal=True),
                                   lambda t, ok, o, e, skipped=False: out.append({"test": t, "result": "skipped" if skipped else "pass" if ok else "fail", "observed": o, "expected": e}))
        return out
    dctx.engine.validator = gate
    try:
        d = deploy(dctx, ids["data"])
    finally:
        lab.close()
    assert d["status"] == "failed-rolled-back" and "data.pools_healthy" in d["error"]
    rep = next(s for s in d["steps"] if s["step"] == "gate.validate[after-data]")
    assert rep["status"] == "failed"
    assert dctx.bigip.tenant == sec_tenant


def test_data_status_action_reads_bigip(dctx):
    ids = discover(dctx)
    for k in ("delivery", "security", "data"):
        assert deploy(dctx, ids[k])["status"] == "succeeded"
    dctx.bigip.vs_conns["s3_seaweedfs"] = 7
    dctx.bigip.vs_reqs["s3_seaweedfs"] = 9
    dctx.bigip.s3_stats.update(s3_requests=11, s3_unsigned=3)
    st = asyncio.run(dctx.engine.validation_action({"action": "data_status"}))
    assert st["virtual_servers"]["s3"]["http.numberReqs"] == 9 and st["s3_statistics"]["s3_unsigned"] == 3   # parsed from description strings
    assert {f"{m['member']}:{m['port']}" for m in st["members"]} == {"10.50.20.41:8333", "10.50.20.40:6333", "10.50.20.45:11434"}
    assert st["virtual_servers"]["s3"]["clientside.totConns"] == 7 and st["s3_statistics"]["s3_requests"] == 11
    assert not [c for c in dctx.bigip.calls[-10:] if c[0] != "GET"]       # read-only


def test_skipped_check_fails_the_gate():
    from autopilot.deployer.engine import Engine, GateFailed
    eng = Engine.__new__(Engine)

    async def v(profile):
        return [{"test": "data.pools_healthy", "result": "skipped"}]
    eng.validator = v
    with pytest.raises(GateFailed):
        asyncio.run(eng._gate("after-data"))


# ============================================================ Validator data checks against local service mocks
class Lab:
    """127.0.0.1 servers behaving like SeaweedFS / Qdrant / Ollama, plus simulated BIG-IP counters (offline)."""

    def __init__(self, s3_mode="normal", rag_collections=("fraud_patterns",), models=("qwen2.5:3b",), member="available", counting=True):
        self.s3_mode, self.rag_collections, self.models, self.member, self.counting = s3_mode, rag_collections, models, member, counting
        self.conns = {"s3": 0, "rag": 0, "llm": 0}      # TCP connections (keep-alive: several requests per connection)
        self.reqs = {"s3": 0, "rag": 0, "llm": 0}       # HTTP requests (what BIG-IP's HTTP profile numberReqs counts)
        self.s3 = {"s3_requests": 0, "s3_unsigned": 0, "s3_resp_4xx": 0}
        self.servers = {s: self._serve(s) for s in ("s3", "rag", "llm")}

    def _serve(self, svc):
        lab = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def setup(self):
                super().setup()
                if lab.counting:
                    lab.conns[svc] += 1

            def send(self, code, body, ctype="application/json"):
                b = body.encode() if isinstance(body, str) else json.dumps(body).encode()
                self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)

            def do_GET(self):
                if lab.counting:
                    lab.reqs[svc] += 1
                if svc == "s3":
                    signed = (self.headers.get("Authorization") or "").startswith("AWS4-HMAC-SHA256")
                    if lab.counting:
                        lab.s3["s3_requests"] += 1; lab.s3["s3_unsigned"] += 0 if signed else 1
                    if lab.s3_mode == "open" or (signed and lab.s3_mode == "accept_any_signature"):
                        return self.send(200, '<?xml version="1.0"?><ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>', "application/xml")
                    if lab.counting:
                        lab.s3["s3_resp_4xx"] += 1
                    code = "InvalidAccessKeyId" if signed else "AccessDenied"
                    return self.send(403, f'<?xml version="1.0"?><Error><Code>{code}</Code><Message>x</Message></Error>', "application/xml")
                if svc == "rag":
                    if self.path == "/readyz":
                        return self.send(200, "all shards are ready", "text/plain")
                    if self.path == "/collections":
                        return self.send(200, {"result": {"collections": [{"name": n} for n in lab.rag_collections]}, "status": "ok"})
                if svc == "llm":
                    if self.path == "/api/version":
                        return self.send(200, {"version": "0.12.6"})
                    if self.path == "/api/tags":
                        return self.send(200, {"models": [{"name": m} for m in lab.models]})
                self.send(404, {"error": "not found"})

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H); srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def port(self, s):
        return self.servers[s].server_address[1]

    def cfg(self, closed=None):
        dd = copy.deepcopy(DD)
        for s in ("s3", "rag", "llm"):
            dd[s]["vip"] = "127.0.0.1"
            dd[s]["port"] = free_port() if s == closed else self.port(s)
        return {"design": {"data_delivery": dd}, "validation": {"data": {"s3_credentials_env": None,
                "stats_settle_s": 0.3, "stats_poll_s": 0.05}}}   # offline: short settle (production default 30 s)

    async def actions(self, req):
        assert req == {"action": "data_status"}
        members = [{"service": s, "member": m.rpartition(":")[0], "port": int(m.rpartition(":")[2]),
                    "availability": self.member if s == "s3" else "available", "enabled": "enabled"}
                   for s in ("s3", "rag", "llm") for m in DD[s]["members"]]
        vs = {s: {"clientside.totConns": self.conns[s], "http.numberReqs": self.reqs[s]} for s in self.conns}
        return {"members": members, "virtual_servers": vs, "s3_statistics": dict(self.s3)}

    def close(self):
        for s in self.servers.values():
            s.shutdown(); s.server_close()


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def run_checks(lab, cfg=None, actions="lab"):
    from autopilot import validate
    out = []
    act = lab.actions if actions == "lab" else actions
    asyncio.run(validate.data_checks(cfg or lab.cfg(), act, lambda t, ok, o, e, skipped=False: out.append(
        {"test": t, "result": "skipped" if skipped else "pass" if ok else "fail", "observed": o})))
    return {r["test"]: r for r in out}


@pytest.fixture()
def lab_factory():
    labs = []

    def make(**kw):
        labs.append(Lab(**kw)); return labs[-1]
    yield make
    for l in labs:
        l.close()


def test_all_data_checks_pass_when_services_answer_through_counting_path(lab_factory):
    r = run_checks(lab_factory())
    assert list(r) == DATA_TESTS and all(x["result"] == "pass" for x in r.values()), r
    assert r["data.s3_sigv4_enforced"]["observed"]["s3_error"] == "InvalidAccessKeyId"
    obs = r["data.bigip_statistics"]["observed"]
    assert obs["sent_requests"] == {"s3": 2, "rag": 2, "llm": 2} and obs["virtual_server_http_requests"] == {"s3": 2, "rag": 2, "llm": 2}
    # keep-alive: RAG and LLM each sent 2 requests on ONE connection; request accounting still passes
    assert obs["virtual_server_connections_info"]["rag"] == 1 and obs["virtual_server_connections_info"]["llm"] == 1


@pytest.mark.parametrize("kw,failing", [
    ({"member": "offline"}, "data.pools_healthy"),
    ({"s3_mode": "open"}, "data.s3_via_front_door"),
    ({"s3_mode": "accept_any_signature"}, "data.s3_sigv4_enforced"),
    ({"counting": False}, "data.bigip_statistics"),                 # traffic not seen by BIG-IP = not traversing it
    ({"rag_collections": ("other",)}, "data.rag_via_front_door"),
    ({"models": ("llama3:8b",)}, "data.llm_via_front_door"),
])
def test_each_failure_is_detected_by_its_check(lab_factory, kw, failing):
    r = run_checks(lab_factory(**kw))
    assert r[failing]["result"] == "fail", r[failing]
    unrelated = {"data.pools_healthy", "data.rag_via_front_door", "data.llm_via_front_door"} - {failing}
    assert all(r[t]["result"] == "pass" for t in unrelated), {t: r[t] for t in unrelated}


def test_unreachable_vip_is_a_named_failure(lab_factory):
    lab = lab_factory()
    r = run_checks(lab, cfg=lab.cfg(closed="rag"))
    assert r["data.rag_via_front_door"]["result"] == "fail" and "error" in r["data.rag_via_front_door"]["observed"]


def test_without_deployer_actions_bigip_checks_are_skipped_not_passed(lab_factory):
    r = run_checks(lab_factory(), actions=None)
    assert r["data.pools_healthy"]["result"] == "skipped" and r["data.bigip_statistics"]["result"] == "skipped"


def test_authorised_s3_read_only_when_identity_configured(lab_factory, monkeypatch):
    lab = lab_factory(s3_mode="accept_any_signature")
    cfg = lab.cfg(); cfg["validation"]["data"]["s3_credentials_env"] = "AP_VALIDATION_S3"
    assert "data.s3_sigv4_authorized_read" not in run_checks(lab, cfg)
    monkeypatch.setenv("AP_VALIDATION_S3_ACCESS_KEY_ID", "AKIDOFFLINETEST000002")
    monkeypatch.setenv("AP_VALIDATION_S3_SECRET_ACCESS_KEY", "offline-test-secret-not-a-credential")
    assert run_checks(lab, cfg)["data.s3_sigv4_authorized_read"]["result"] == "pass"


# ============================================================ preserved guarantees
def test_after_data_is_superset_and_runs_before_rate_limit():
    from autopilot import validate, validation_evidence
    a, s = validate.PROFILES["after-data"], validate.PROFILES["after-security"]
    assert all(a[k] == v for k, v in s.items()) and a["data"] is True and not s.get("data")
    src = (ROOT / "app" / "autopilot" / "validate.py").read_text()
    assert src.index("await data_checks(cfg, actions, rec)") < src.index("# ---------------- rate limit LAST")
    assert "after-data" in validation_evidence.PROFILES["security"] and validation_evidence.PROFILES["data"] == ("after-data",)


def test_validator_tls_and_mtls_code_unchanged():
    text = (ROOT / "app" / "autopilot" / "validate.py").read_text()
    assert "ctx.load_cert_chain(certfile=cert[0], keyfile=cert[1])" in text and "ssl.create_default_context(cafile=CA)" in text
    assert '"cert": cert' not in text and "CERT_NONE" not in text and "check_hostname = False" not in text
    base = (ROOT.parent / "autopilot-snapshot" / "app" / "autopilot" / "validate.py")
    if base.exists():                                   # every pre-existing line of the validator is kept
        removed = set(base.read_text().splitlines()) - set(text.splitlines())
        assert removed == set(), removed


def test_policy_and_deployer_scope_unchanged_except_data_delta():
    from autopilot.deployer import policy
    assert policy.TENANT == "AP_AI" and str(policy.VIP_RANGE) == "10.50.10.96/28" and str(policy.MEMBER_RANGE) == "10.50.20.0/24"
    assert policy.CLASSES >= {"Statistics_Profile"} and "WAF_Policy" not in policy.CLASSES
    assert policy.APP_NAME.match("rag_qdrant") and policy.APP_NAME.match("llm_ollama") and not policy.APP_NAME.match("web_x")
    assert policy.HOST_COMMANDS.pattern.endswith("probe direct-mcp)$")      # no new host commands in increment 2


# ============================================================ read-model formats (as BIG-IP really returns them)
def test_statistics_profile_counters_parsed_from_bigip_description_strings():
    """Structure copied from a real BIG-IP 21.1 statistics-profile REST response (Project B capture, 2026-10-06):
    counters are strings in `description`, keyed by the configured field name, next to tmName / typeId."""
    from autopilot.deployer.engine import Engine
    body = {"kind": "tm:ltm:profile:statistics:statisticsstats", "entries": {
        "https://localhost/mgmt/tm/ltm/profile/statistics/~AP_AI~Shared~stats_s3/stats": {"nestedStats": {
            "kind": "tm:ltm:profile:statistics:statisticsstats", "entries": {
                "s3_requests": {"description": "214"}, "s3_unsigned": {"description": "3"}, "s3_resp_4xx": {"description": "7"},
                "s3_put_bytes": {"description": "107122015"}, "tmName": {"description": "/AP_AI/Shared/stats_s3"},
                "typeId": {"description": "ltm profile statistics"}, "not_a_field": {"description": "5"}, "s3_get": {"description": "n/a"}}}}}}
    got = Engine._statistics_counters(body)
    assert got == {"s3_requests": 214, "s3_unsigned": 3, "s3_resp_4xx": 7, "s3_put_bytes": 107122015}


def test_irule_field_names_profile_fields_and_read_model_agree():
    from autopilot import data_delivery as D
    import re as _re
    irule = D.irule_s3_stats("AP_AI")
    used = set(_re.findall(r"STATS::incr /AP_AI/Shared/stats_s3 (\w+)", irule))
    checked = {"s3_requests", "s3_unsigned", "s3_resp_4xx"}                 # counters data.bigip_statistics relies on
    assert checked <= used == set(D.STATS_FIELDS)


def test_unreadable_counters_fail_instead_of_passing(lab_factory):
    lab = lab_factory()
    async def no_http_counters(req):
        st = await lab.actions(req)
        for v in st["virtual_servers"].values():
            v.pop("http.numberReqs")
        return st
    r = run_checks(lab, actions=no_http_counters)
    b = r["data.bigip_statistics"]
    assert b["result"] == "fail" and set(b["observed"]["unreadable_counters"]) == {"s3.http.numberReqs", "rag.http.numberReqs", "llm.http.numberReqs"}


def test_empty_statistics_profile_fails(lab_factory):
    lab = lab_factory()
    async def no_s3_stats(req):
        st = await lab.actions(req); st["s3_statistics"] = {}; return st
    r = run_checks(lab, actions=no_s3_stats)
    assert r["data.bigip_statistics"]["result"] == "fail" and "stats_s3.s3_requests" in r["data.bigip_statistics"]["observed"]["unreadable_counters"]
