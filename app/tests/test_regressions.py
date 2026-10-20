"""Regression tests for issues found during the build and rehearsals (one test per issue)."""
from __future__ import annotations

import asyncio
import pathlib
import re
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from conftest import discover, review  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
AP = {"username": "approver1", "role": "approver"}


def approve(c, pid):
    review(c, pid)
    return c.ap.post(f"/api/packages/{pid}/decision", json={"decision": "approved", "comment": "t"})


def test_empty_assessment_has_empty_graph_and_all_counters(ctx):
    ctx.op.post("/api/assessment/new", json={"name": "empty"})
    st = ctx.viewer.get("/api/state").json()
    assert st["graph"] == {"nodes": [], "edges": []} and st["findings"] == [] and st["findings_grouped"] == []
    c = st["counters"]
    assert c["assets"] == c["relationships"] == c["evidence"] == c["findings"] == 0
    assert set(c["evidence_by_source"]) == {"observe", "describe", "enumerate", "ingest"} and set(st["sources"]) == set(c["evidence_by_source"])


def test_topology_shows_every_discovered_asset_and_relationship(ctx):
    discover(ctx)
    st = ctx.viewer.get("/api/state").json()
    assert len(st["graph"]["nodes"]) == st["counters"]["assets"] > 0
    assert len(st["graph"]["edges"]) == st["counters"]["relationships"] > 0
    ids = {n["id"] for n in st["graph"]["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in st["graph"]["edges"])     # no dangling edges hidden by the UI


@pytest.mark.parametrize("clock,ok", [("UTC-NOW", True), ("2026-10-13T10:00:00+0200", False), ("UTC-8H", False), ("garbage", False)])
def test_bigip_clock_timezone_and_skew(ctx, clock, ok):
    b = ctx.bigip
    orig = b.get

    async def get(path, admin=False):
        if path == "/mgmt/tm/sys/clock":
            now = time.time() - (8 * 3600 if clock == "UTC-8H" else 0)
            val = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)) if clock.startswith("UTC") else clock
            return 200, {"entries": {"x": {"nestedStats": {"entries": {"fullDate": {"description": val}}}}}}
        return await orig(path, admin)
    b.get = get
    ids = discover(ctx)
    pf = {c["check"]: c for c in ctx.ap.get(f"/api/packages/{ids['delivery']}/review").json()["preflight"]}
    assert pf["prereq.clock"]["ok"] is ok
    if clock == "garbage" or "+0200" in clock:
        assert "not in UTC" in pf["prereq.clock"]["detail"]


def test_schema_validation_errors_name_the_json_path():
    from autopilot.packages import _validate_as3
    bad = {"class": "AS3", "action": "deploy", "declaration": {"class": "ADC", "schemaVersion": "3.56.0", "AP_AI": {"class": "Tenant",
           "mcp_x": {"class": "Application", "service": {"class": "Service_HTTPS", "virtualAddresses": ["10.50.10.101"],
                                                         "virtualPort": "not-a-port", "pool": "pool", "snat": "auto"},
                     "pool": {"class": "Pool", "members": []}}}}}
    v = _validate_as3(bad)
    assert v["valid"] is False
    msgs = " | ".join(v["errors"] + v["lint"])
    assert "virtualPort" in msgs or "mcp_x" in msgs
    assert any("pool without health monitor" in x for x in v["lint"])


def test_no_secrets_in_process_arguments():
    """Credentials are passed via stdin / process-substitution config / files — never argv."""
    offenders = []
    for f in list((ROOT / "scripts").glob("*.sh")) + list((ROOT / "bin").glob("*")) + list((ROOT / "deploy" / "common").glob("*")):
        if not f.is_file():
            continue
        txt = f.read_text(errors="ignore")
        for pat in (r"curl[^\n|]*\s-u\s+\S+:\S+", r"sshpass", r"--password[= ]\S", r"security add-generic-password[^\n]*\s-w\s+\S"):
            if re.search(pat, txt):
                offenders.append(f"{f.name}: {pat}")
    for f in (ROOT / "app" / "autopilot").rglob("*.py"):
        txt = f.read_text()
        if re.search(r"subprocess\.(run|Popen|call)\([^)]*(password|token|secret)", txt):
            offenders.append(f"{f.name}: secret in subprocess argv")
    assert offenders == [], offenders
    assert "sys.stdin.read()" in (ROOT / "app" / "autopilot" / "auth.py").read_text()


def test_no_external_observability_platform_endpoints_are_exposed(ctx):
    """The public build ships no F5 Insight integration: its diagnostics / dashboard endpoints do not exist."""
    assert ctx.op.get("/api/diagnostics/insight").status_code == 404
    assert ctx.viewer.get("/api/aiops/insight").status_code == 404


@pytest.mark.parametrize("swap,ok,level", [(0.40, True, "pass"), (0.80, True, "warn"), (0.96, False, "fail")])
def test_bigip_memory_exhaustion_preflight(ctx, swap, ok, level):
    ctx.bigip.memory["swap_used"] = ctx.bigip.memory["swap_total"] * swap
    ids = discover(ctx)
    r = ctx.ap.get(f"/api/packages/{ids['delivery']}/review").json()
    m = next(c for c in r["preflight"] if c["check"] == "resource.control_plane_memory")
    assert m["ok"] is ok and m["level"] == level
    a = ctx.ap.post(f"/api/packages/{ids['delivery']}/decision", json={"decision": "approved", "comment": "t"})
    assert (a.status_code == 200) is ok


def test_approval_and_preflight_expiry(ctx):
    ids = discover(ctx)
    review(ctx, ids["delivery"])
    ctx.web.STORE.db.execute("UPDATE package_review SET created=created-1801")
    assert ctx.ap.post(f"/api/packages/{ids['delivery']}/decision", json={"decision": "approved", "comment": "t"}).status_code == 409
    a = approve(ctx, ids["delivery"]).json()
    ctx.web.STORE.db.execute("UPDATE approval SET expires=? WHERE id=?", (time.time() - 1, a["id"]))
    r = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy")
    assert r.status_code == 409 and "expired" in r.json()["detail"]


def test_security_depends_on_validated_delivery(ctx):
    ids = discover(ctx)
    r = ctx.ap.get(f"/api/packages/{ids['security']}/review").json()
    assert not next(c for c in r["preflight"] if c["check"] == "sequence.requires")["ok"]
    assert ctx.ap.post(f"/api/packages/{ids['security']}/decision", json={"decision": "approved", "comment": "t"}).status_code == 409
    sec = {p["kind"]: p for p in ctx.ap.get("/api/packages").json()}["security"]["lifecycle"]
    assert sec["blocked"] and not sec["actions"]["deploy"]["allowed"]


def test_success_is_never_reported_from_api_acceptance_alone(ctx):
    """AS3 returns 200 but an object is missing from the running config -> verification fails -> rollback, not success."""
    ids = discover(ctx)
    approve(ctx, ids["delivery"])
    ctx.bigip.drop_objects.add("mcp_fraud_intel")
    d = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()
    st = {s["step"]: s for s in d["steps"]}
    assert st["as3.deploy"]["status"] == "ok" and st["verify.bigip_config"]["status"] == "failed"
    assert "/AP_AI/mcp_fraud_intel/service not found" in st["verify.bigip_config"]["detail"]
    assert d["status"] == "failed-rolled-back" and ctx.bigip.tenant is None


def test_host_profile_confirmation(ctx):
    ids = discover(ctx)
    approve(ctx, ids["delivery"])
    orig = ctx.hosts.run

    async def run(h, cmd):
        r = await orig(h, cmd)
        if h == "ap-agent-b" and cmd == "profile delivery":
            ctx.hosts.profile[h] = "baseline"          # helper claimed success but the profile did not stick
        return r
    ctx.hosts.run = run
    d = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()
    st = {s["step"]: s for s in d["steps"]}
    assert st["verify.host_profiles[delivery]"]["status"] == "failed" and "ap-agent-b" in st["verify.host_profiles[delivery]"]["detail"]
    assert d["status"] == "failed-rolled-back"


def test_verified_success_journal(ctx):
    ids = discover(ctx)
    approve(ctx, ids["delivery"])
    d = ctx.ap.post(f"/api/packages/{ids['delivery']}/deploy").json()
    st = {s["step"]: s for s in d["steps"]}
    assert d["status"] == "succeeded" and st["verify.bigip_config"]["detail"]["verified_objects"] == 3
    assert set(st["verify.host_profiles[delivery]"]["detail"].values()) == {"delivery"}


def test_package_lists_targets_and_external_changes(ctx):
    ids = discover(ctx)
    p = {x["kind"]: x for x in ctx.ap.get("/api/packages").json()}
    ex = p["delivery"]["body"]["explanation"]
    assert ex["targets"]["tenant"] == "AP_AI" and ex["targets"]["device"].startswith("BIG-IP_C")
    assert {"name": "agent-b.aplab.internal", "from": "10.50.10.22", "to": "10.50.10.100"} in ex["external_changes"]["dns"]
    assert any(a["setting"] == "agent_b_url" for a in ex["external_changes"]["agent_configuration"])
    assert p["security"]["body"]["explanation"]["external_changes"]["firewall"]
    assert ids


def test_password_policy_default_and_explicit_lab_override(ctx):
    from autopilot import auth
    with pytest.raises(ValueError):
        auth.add_user(ctx.web.STORE.db, "weak1", "viewer", "test123")
    auth.add_user(ctx.web.STORE.db, "weak1", "viewer", "test123", allow_weak=True)
    assert auth.verify(ctx.web.STORE.db, "weak1", "test123") == "viewer"
