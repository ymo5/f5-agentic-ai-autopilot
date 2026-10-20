"""Regression tests for the first Part B rehearsal failure (gate.validate[after-delivery] -> ConnectError).

A simulated lab reproduces the real timings observed on 2026-10-13: `profile delivery` recreates the agent containers
(listening again ~1 s later), CoreDNS serves the new zone after its reload interval, BIG-IP marks pool members up after
the first successful monitor probe. Real engine/converge/approval code; simulated clock; mock BIG-IP/host executors.
"""
from __future__ import annotations

import asyncio
import pathlib
import sys

import httpx
import pytest
import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import CFG, discover, review  # noqa: E402

AP = {"username": "approver1", "role": "approver"}
LAB_CFG = yaml.safe_load(open(CFG))


class Lab:
    """Time-driven model of the lab after a host-profile change."""
    AGENT_RESTART_S, DNS_RELOAD_S, MONITOR_UP_S = 1.2, 7.0, 6.0

    def __init__(self, hosts, bigip):
        self.t, self.hosts, self.bigip = 1000.0, hosts, bigip
        self.changed = {}           # host -> time of last profile change
        self.as3_at = None
        self.never_up = set()       # failure injection: members / agents that never converge
        self.probe_calls = 0
        orig_run, orig_post = hosts.run, bigip.as3_post

        async def run(h, cmd):
            r = await orig_run(h, cmd)
            if cmd.startswith("profile "):
                self.changed[h] = self.t
            return r

        async def post(decl):
            r = await orig_post(decl)
            if decl["action"] == "deploy":
                self.as3_at = self.t
            return r
        hosts.run, bigip.as3_post = run, post

    # --- clock used by the engine/converge
    def clock(self):
        return self.t

    async def sleep(self, s):
        self.t += s

    def agent_up(self, host):
        return host not in self.never_up and self.t - self.changed.get(host, -99) >= self.AGENT_RESTART_S

    def profile(self, host):
        return self.hosts.profile[host]


class LabProbes:
    def __init__(self, lab):
        self.lab, self.clock, self.sleep = lab, lab.clock, lab.sleep

    async def http_json(self, url):
        self.lab.probe_calls += 1
        host = "ap-agent-a" if ":8080" in url else "ap-agent-b"
        if not self.lab.agent_up(host):
            raise httpx.ConnectError("All connection attempts failed")
        prof = LAB_CFG["design"]["profiles"][self.lab.profile(host)]
        if "agent-card" in url:
            h = prof["card"]["advertises_host"]
            return 200, {"skills": [{}], "supportedInterfaces": [{"url": f"https://{h}/" if "." in h and not h[0].isdigit() else f"http://{h}:9000/"}]}
        name = "agent-a" if host == "ap-agent-a" else "agent-b"
        return 200, dict(prof["agents"][name]["expect"])

    async def dns(self, server, name):
        lab = self.lab
        ch = lab.changed.get("ap-ai-services")
        zone = lab.profile("ap-ai-services") if ch is not None and lab.t - ch >= lab.DNS_RELOAD_S else "baseline"
        if ch is None:
            zone = lab.profile("ap-ai-services")
        return [LAB_CFG["design"]["profiles"][zone]["dns"][name]], 60

    async def pool_members(self):
        lab = self.lab
        up = lab.as3_at is not None and lab.t - lab.as3_at >= lab.MONITOR_UP_S
        return [{"pool": "/AP_AI/mcp/pool", "member": m, "availability": "available" if up and m not in lab.never_up else "offline"}
                for m in ("10.50.20.31:8000", "10.50.20.32:8000")]

    async def vip(self, address, name, probe, mtls):
        ok = (await self.pool_members())[0]["availability"] == "available"
        return ok, "HTTP 200" if ok else "ConnectError"


@pytest.fixture()
def lab(ctx):
    return Lab(ctx.hosts, ctx.bigip)


def engine(ctx, lab, converge=True):
    from autopilot.deployer.engine import Engine
    from autopilot.deployer.window import Window
    calls = []

    async def gate_validator(profile):
        # behaves like the real gate's first action: connect to Agent A's API (and require converged DNS/pools)
        calls.append(lab.t)
        if not lab.agent_up("ap-agent-a"):
            raise httpx.ConnectError("All connection attempts failed")
        want = "10.50.10.22" if profile == "before" else "10.50.10.100"
        dns_ok = (await LabProbes(lab).dns(None, "agent-b.aplab.internal"))[0][0] == want
        pools_ok = profile == "before" or all(m["availability"] == "available" for m in await LabProbes(lab).pool_members())
        return [{"test": "a2a.via_front_door", "result": "pass" if dns_ok else "fail", "observed": {}, "expected": ""},
                {"test": "delivery.load_distribution", "result": "pass" if pools_ok else "fail", "observed": {}, "expected": ""}]
    e = Engine(ctx.web.STORE, ctx.bigip, ctx.hosts, gate_validator, window=Window(None, ctx.web.STORE.db), mock=True,
               cfg=LAB_CFG if converge else None, probes=LabProbes(lab) if converge else None)
    e.gate_calls = calls
    return e


def deploy_delivery(ctx, eng):
    ids = discover(ctx)
    review(ctx, ids["delivery"])
    assert ctx.ap.post(f"/api/packages/{ids['delivery']}/decision", json={"decision": "approved", "comment": "t"}).status_code == 200
    pkg = ctx.web._pkg(ids["delivery"])
    a = ctx.web.approvals.latest(ctx.web.STORE.db, ids["delivery"])
    return asyncio.run(eng.deploy(pkg, a["id"], AP))


def test_rehearsal_failure_reproduced_without_convergence_barrier(ctx, lab):
    """Root cause: the gate connects to Agent A immediately after `profile delivery` recreated its container."""
    d = deploy_delivery(ctx, engine(ctx, lab, converge=False))
    st = {s["step"]: s for s in d["steps"]}
    assert d["status"] == "failed-rolled-back"
    assert st["gate.validate[after-delivery]"]["detail"] == "ConnectError: All connection attempts failed"
    assert st["as3.deploy"]["status"] == "ok" and all(st[k]["status"] == "ok" for k in st if k.startswith("dependency"))


def test_convergence_barrier_waits_for_agents_dns_and_monitors_then_gate_passes(ctx, lab):
    eng = engine(ctx, lab)
    d = deploy_delivery(ctx, eng)
    steps = [s["step"] for s in d["steps"]]
    assert d["status"] == "succeeded", d["error"]
    assert steps.index("converge[delivery]") < steps.index("gate.validate[after-delivery]")
    rep = next(s for s in d["steps"] if s["step"] == "converge[delivery]")["detail"]
    chk = rep["checks"]
    assert chk["agent.agent-a"]["converged_after_s"] >= 1 and chk["agent.agent-b"]["ok"]
    assert chk["dns.agent-b.aplab.internal"]["converged_after_s"] >= Lab.DNS_RELOAD_S - 2
    assert chk["dns.cache_hold"]["ok"] and rep["elapsed_s"] >= 59          # waited out the 60 s record TTL
    assert chk["bigip.pools"]["ok"] and all(chk[f"vip.{n}"]["ok"] for n in ("agent-b.aplab.internal", "mcp-risk.aplab.internal",
                                                                            "mcp-intel.aplab.internal"))
    assert chk["card.advertises"]["observed"] == ["agent-b.aplab.internal"]
    assert eng.gate_calls and lab.agent_up("ap-agent-a")


def test_convergence_timeout_fails_with_explanation_rolls_back_and_never_retries(ctx, lab):
    lab.never_up.add("10.50.20.32:8000")                                     # one pool member never becomes available
    eng = engine(ctx, lab)
    d = deploy_delivery(ctx, eng)
    conv = next(s for s in d["steps"] if s["step"].startswith("converge[delivery"))
    assert d["status"].startswith("failed-rolled-back")
    assert conv["status"] == "failed" and "bigip.pools" in conv["detail"] and "10.50.20.32:8000" in conv["detail"]
    assert conv["report"]["checks"]["bigip.pools"]["ok"] is False
    assert [c for c in ctx.bigip.calls if c == ("POST", "deploy")] == [("POST", "deploy")]   # deployed once: no automatic retry
    assert not eng.gate_calls                                                # validation never ran on an unconverged lab
    assert ctx.bigip.tenant is None and set(ctx.hosts.profile.values()) == {"baseline"}


def test_probe_errors_count_as_not_converged_never_as_pass(ctx, lab):
    from autopilot.deployer import converge
    lab.never_up.add("ap-agent-a")
    spec = converge.spec_for(LAB_CFG, "baseline", False)
    spec["timeout_s"] = 10
    with pytest.raises(converge.ConvergenceTimeout) as e:
        asyncio.run(converge.wait(spec, LabProbes(lab), clock=lab.clock, sleep=lab.sleep))
    assert e.value.report["checks"]["agent.agent-a"]["ok"] is False
    assert "ConnectError" in e.value.report["checks"]["agent.agent-a"]["observed"]


def test_security_vip_probes_present_client_certificate(ctx):
    from autopilot.deployer import converge
    spec = converge.spec_for(LAB_CFG, "security", True, mtls=True)
    by = {v["name"]: v for v in spec["vips"]}
    assert by["mcp-risk.aplab.internal"]["mtls"] and by["mcp-intel.aplab.internal"]["mtls"] and not by["agent-b.aplab.internal"]["mtls"]
    assert converge.spec_for(LAB_CFG, "baseline", False)["vips"] == [] and not converge.spec_for(LAB_CFG, "baseline", False)["pools"]


def test_dry_run_failure_changes_nothing_and_skips_rollback(ctx, lab):
    ctx.bigip.fail_on = {"dry-run"}
    d = deploy_delivery(ctx, engine(ctx, lab))
    assert d["status"] == "failed-no-changes"
    assert "rollback" not in [s["step"] for s in d["steps"]]
    assert [c for c in ctx.bigip.calls if c[0] in ("POST", "DELETE")] == [("POST", "dry-run")]


def test_reset_demo_waits_for_baseline_before_verifying(ctx, lab):
    eng = engine(ctx, lab)
    assert deploy_delivery(ctx, eng)["status"] == "succeeded"
    r = asyncio.run(eng.reset_demo(AP, "RESET DEMO ENVIRONMENT"))
    assert r["ok"] and r["steps"]["converge"]["checks"]["agent.agent-a"]["ok"]
    assert r["steps"]["converge"]["checks"]["dns.mcp-risk.aplab.internal"]["observed"] == ["10.50.20.31"]


def test_validator_reports_unreachable_agent_as_named_precondition_failure(ctx, monkeypatch):
    from autopilot import validate

    class Down(httpx.AsyncClient):
        async def get(self, url, *a, **k):
            raise httpx.ConnectError("All connection attempts failed")
    monkeypatch.setattr(validate.httpx, "AsyncClient", Down)
    res = asyncio.run(validate.run(LAB_CFG, "after-delivery"))
    by = {r["test"]: r for r in res}
    assert by["precondition.agent_a_api"]["result"] == "fail"
    assert by["precondition.agent_a_api"]["observed"]["url"] == "http://10.50.10.21:8080/healthz"
    assert "All connection attempts failed" in by["precondition.agent_a_api"]["observed"]["error"]
    assert by["precondition.summary"]["result"] == "fail"


PKI = pathlib.Path(__file__).resolve().parents[2] / "secrets" / "pki"


@pytest.mark.skipif(not (PKI / "wildcard.pem").exists(), reason="lab PKI not present")
def test_vip_probe_connects_by_ip_verifies_tls_by_sni_and_sends_protocol_requests():
    """Real network test of Probes.vip against a local TLS server presenting the lab wildcard certificate."""
    import http.server
    import ssl
    import threading
    from autopilot.deployer import converge
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            seen.append(("GET", self.path, self.headers["Host"]))
            self._send(b'{"name":"Risk Assessment Agent","skills":[{"id":"assess"}]}')

        def do_POST(self):
            seen.append(("POST", self.path, self.headers["Host"], self.headers["Mcp-Method"]))
            self.rfile.read(int(self.headers["Content-Length"]))
            self._send(b'{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}')
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(PKI / "wildcard.pem"), str(PKI / "wildcard.key"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    p = converge.Probes(ca=str(PKI / "ca.pem"))
    orig = converge.httpx.AsyncClient

    class Port(orig):   # the probe uses https://<vip>/...: redirect :443 to the test server's port
        async def get(self, url, **k):
            return await super().get(url.replace("127.0.0.1/", f"127.0.0.1:{port}/"), **k)

        async def post(self, url, **k):
            return await super().post(url.replace("127.0.0.1/", f"127.0.0.1:{port}/"), **k)
    converge.httpx.AsyncClient = Port
    try:
        ok_a, d_a = asyncio.run(p.vip("127.0.0.1", "agent-b.aplab.internal", "a2a_card", False))
        ok_m, d_m = asyncio.run(p.vip("127.0.0.1", "mcp-risk.aplab.internal", "mcp_discover", False))
        bad, d_bad = asyncio.run(p.vip("127.0.0.1", "not-covered.example.com", "a2a_card", False))   # SNI not on the cert
    finally:
        converge.httpx.AsyncClient = orig
        srv.shutdown()
    assert ok_a and ok_m, (d_a, d_m)
    assert ("GET", "/.well-known/agent-card.json", "agent-b.aplab.internal") in seen
    assert ("POST", "/mcp", "mcp-risk.aplab.internal", "server/discover") in seen
    assert not bad and ("SSL" in d_bad or "certificate" in d_bad.lower() or "ConnectError" in d_bad)
