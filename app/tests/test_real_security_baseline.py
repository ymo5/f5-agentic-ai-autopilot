"""Checks against the REAL deployed AI Security declaration (package 361c421a) — read from a restricted local file whose path
is given in F5_REAL_SECURITY_DECL (never copied into the repository). Skipped when the variable is not set.

Offline: the device is the in-memory MockBigip pre-loaded with the real tenant; the rollback runs through the production
Engine.fingerprint() -> Engine._restore() path (policy check, AS3 re-POST, post-rollback read-back)."""
from __future__ import annotations

import asyncio
import copy
import json
import os
import pathlib

import pytest
import yaml

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
REAL = os.environ.get("F5_REAL_SECURITY_DECL")
pytestmark = pytest.mark.skipif(not REAL or not os.path.isfile(REAL or ""), reason="F5_REAL_SECURITY_DECL not set")
DD = yaml.safe_load((ROOT / "deploy" / "autopilot" / "data-delivery.overlay.yaml").read_text())["design"]["data_delivery"]
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"))


@pytest.fixture()
def real():
    return json.load(open(REAL))


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("AS3_SCHEMA", str(ROOT / "packages" / "vendor" / "as3-schema-3.56.0-10.json"))
    from autopilot.store import Store
    from autopilot.deployer.engine import Engine
    from autopilot.deployer.executors import MockBigip, MockHosts
    store = Store(str(tmp_path / "ap.db"))
    bigip, hosts = MockBigip(), MockHosts()
    hosts.profile = {h: "security" for h in hosts.profile}
    return Engine(store, bigip, hosts, None, mock=True), bigip, hosts


def test_real_declaration_is_the_expected_security_stage(real):
    t = real["declaration"]["AP_AI"]
    assert t["Shared"]["tls_server_mtls"]["authenticationMode"] == "require"
    assert {"irule_mcp_policy", "irule_mcp_persist", "mon_mcp", "mon_a2a", "tls_server", "cert_lab"} <= set(t["Shared"])
    vips = {a: b["service"]["virtualAddresses"][0] for a, b in t.items() if isinstance(b, dict) and "service" in b}
    assert sorted(vips.values()) == ["10.50.10.100", "10.50.10.101", "10.50.10.102"]
    assert all(t[a]["service"]["serverTLS"]["use"].endswith("tls_server_mtls") for a in vips if a.startswith("mcp_"))


def test_data_extension_of_the_real_declaration_is_valid_and_additive(real):
    from autopilot import data_delivery as D, packages as P
    from autopilot.deployer import policy
    P._schema = None
    P.AS3_SCHEMA_PATH = str(ROOT / "packages" / "vendor" / "as3-schema-3.56.0-10.json")   # read at import time in packages.py
    new = D.extend(real, DD)
    diff = D.added_objects(real, new)
    assert diff["modified_existing"] == [] and diff["applications"] == ["llm_ollama", "rag_qdrant", "s3_seaweedfs"]
    assert P._validate_as3(new)["valid"] is True and policy.check_as3(new) == []


def test_production_rollback_restores_the_exact_real_tenant_with_readback(real, engine):
    from autopilot import data_delivery as D
    eng, bigip, hosts = engine
    bigip.tenant = copy.deepcopy(real["declaration"]["AP_AI"])          # device state = the deployed Security stage
    fp, state = asyncio.run(eng.fingerprint())
    prev = {"tenant": state["tenant"], "hosts": state["hosts"]}           # exactly what deploy() records as previous_state
    bigip.tenant = copy.deepcopy(D.extend(real, DD)["declaration"]["AP_AI"])   # data package now on the device
    out = asyncio.run(eng._restore(prev))
    assert canon(bigip.tenant) == canon(real["declaration"]["AP_AI"])    # byte-for-byte canonical equality
    assert out["readback"]["verified_objects"] == 3 and set(hosts.profile.values()) == {"security"}
    assert not any(k in bigip.tenant for k in ("s3_seaweedfs", "rag_qdrant", "llm_ollama"))


def test_post_rollback_readback_mismatch_fails_the_rollback(real, engine):
    from autopilot.deployer.executors import ExecError
    eng, bigip, hosts = engine
    bigip.tenant = copy.deepcopy(real["declaration"]["AP_AI"])
    _, state = asyncio.run(eng.fingerprint())
    bigip.profile_faults["mcp_risk_scoring"] = "drop_tls"                 # device does not really restore the mTLS profile
    with pytest.raises(ExecError, match="client-SSL profile tls_server_mtls not attached"):
        asyncio.run(eng._restore({"tenant": state["tenant"], "hosts": state["hosts"]}))
