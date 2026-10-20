"""AI Data Delivery package (integration increment 1, offline): schema-valid, policy-valid, cumulative on top of the AI
Security declaration without changing any existing object, observe-only S3 telemetry. No BIG-IP is contacted."""
from __future__ import annotations

import copy
import json
import pathlib
import re

import pytest
import yaml

HERE = pathlib.Path(__file__).resolve().parent
GOLD = HERE / "fixtures" / "packages_golden"
ROOT = HERE.parent.parent
SCHEMA = ROOT / "packages" / "vendor" / "as3-schema-3.56.0-10.json"
DD = yaml.safe_load((ROOT / "deploy" / "autopilot" / "data-delivery.overlay.yaml").read_text())["design"]["data_delivery"]


@pytest.fixture(autouse=True)
def schema_env(monkeypatch):
    monkeypatch.setenv("AS3_SCHEMA", str(SCHEMA))
    import autopilot.packages as P
    P._schema = None


def security_decl(name="g2_lab_two_nics"):
    # goldens replace the assessment id with "<AID>", which AS3's id pattern rejects; use a real-shaped id
    pk = json.loads((GOLD / f"{name}.json").read_text().replace("<AID>", "0123456789abcdef"))
    return next(p for p in pk if p["kind"] == "security")["body"]["as3"]


@pytest.mark.parametrize("golden", ["g1_conftest_scan", "g2_lab_two_nics", "g3_enumerate_only"])
def test_declaration_is_schema_and_policy_valid(golden):
    from autopilot import data_delivery as D, packages as P
    from autopilot.deployer import policy
    decl = D.extend(security_decl(golden), DD)
    v = P._validate_as3(decl)
    assert v["valid"] is True, v
    assert policy.check_as3(decl) == []


def test_existing_objects_unchanged_and_rollback_is_security_stage():
    from autopilot import data_delivery as D
    base = security_decl(); new = D.extend(base, DD)
    diff = D.added_objects(base, new)
    assert diff["modified_existing"] == []
    assert diff["applications"] == ["llm_ollama", "rag_qdrant", "s3_seaweedfs"]
    assert diff["shared_objects"] == ["irule_s3_stats", "mon_llm", "mon_rag", "mon_s3", "stats_s3"]
    t_base, t_new = base["declaration"]["AP_AI"], new["declaration"]["AP_AI"]
    for k in t_base:                                                # every pre-existing object is identical
        if k == "Shared":
            assert all(t_new["Shared"][o] == v for o, v in t_base["Shared"].items())
        else:
            assert t_new[k] == t_base[k]
    assert new["declaration"]["id"].endswith("-data") and base["declaration"]["id"].endswith("-security")
    assert security_decl() == base                                  # input not mutated


def test_services_pools_monitors():
    from autopilot import data_delivery as D
    t = D.extend(security_decl(), DD)["declaration"]["AP_AI"]
    exp = {"s3_seaweedfs": ("10.50.10.103", 8333, "10.50.20.41", 8333, "mon_s3"), "rag_qdrant": ("10.50.10.104", 6333, "10.50.20.40", 6333, "mon_rag"),
           "llm_ollama": ("10.50.10.105", 11434, "10.50.20.45", 11434, "mon_llm")}
    for app, (vip, port, member, mport, mon) in exp.items():
        sv, pl = t[app]["service"], t[app]["pool"]
        assert sv["class"] == "Service_HTTP" and sv["virtualAddresses"] == [vip] and sv["virtualPort"] == port and sv["snat"] == "auto"
        assert pl["members"] == [{"servicePort": mport, "serverAddresses": [member]}]
        assert pl["monitors"] == [{"use": f"/AP_AI/Shared/{mon}"}]
    assert t["s3_seaweedfs"]["service"]["profileStatistics"] == {"use": "/AP_AI/Shared/stats_s3"}
    assert t["s3_seaweedfs"]["service"]["iRules"] == [{"use": "/AP_AI/Shared/irule_s3_stats"}]
    assert "profileStatistics" not in t["rag_qdrant"]["service"] and t["llm_ollama"]["service"]["iRules"] == []
    sh = t["Shared"]
    assert sh["mon_s3"]["receive"] == "<Code>AccessDenied</Code>" and "Host: s3.aplab.internal" in sh["mon_s3"]["send"]
    assert sh["mon_rag"]["receive"] == "all shards are ready" and sh["mon_rag"]["send"].startswith("GET /readyz ")
    assert sh["mon_llm"]["send"].startswith("GET /api/version ")


def test_s3_irule_is_observe_only_and_matches_statistics_fields():
    from autopilot import data_delivery as D
    sh = D.extend(security_decl(), DD)["declaration"]["AP_AI"]["Shared"]
    code = "\n".join(l for l in sh["irule_s3_stats"]["iRule"].splitlines() if not l.strip().startswith("#"))
    assert not D.FORBIDDEN_IRULE.search(code), D.FORBIDDEN_IRULE.search(code)
    used = set(re.findall(r"STATS::incr /AP_AI/Shared/stats_s3 (\w+)", code))
    fields = {v for k, v in sh["stats_s3"].items() if k.startswith("field")}
    assert used == fields == set(D.STATS_FIELDS) and len(fields) <= 32
    assert code.count("[catch {") == 2                               # every handler is wrapped


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d["s3"].update(vip="10.50.10.200"), "outside"),
    (lambda d: d["rag"].update(vip="10.50.10.101", port=443), None),
    (lambda d: d["llm"].update(members=["10.1.20.101:8333"]), "outside"),
    (lambda d: d["rag"].update(vip=d["s3"]["vip"], port=d["s3"]["port"]), "already used"),
    (lambda d: d["s3"].update(host="s3 aplab"), "DNS name"),
    (lambda d: d.pop("llm"), "missing"),
])
def test_design_errors_refused(mutate, needle):
    from autopilot import data_delivery as D
    dd = copy.deepcopy(DD); mutate(dd)
    errs = D.check_design(dd)
    if needle is None:                       # an address that collides with an existing MCP VIP:port is caught by the declaration
        assert errs == []
        with pytest.raises(Exception):
            new = D.extend(security_decl(), dd)
            t = new["declaration"]["AP_AI"]
            used = [(a["service"]["virtualAddresses"][0], a["service"]["virtualPort"]) for a in t.values() if isinstance(a, dict) and "service" in a]
            assert len(used) == len(set(used)), "duplicate VIP:port"
    else:
        assert any(needle in e for e in errs), errs
        with pytest.raises(ValueError):
            D.extend(security_decl(), dd)


def test_refuses_to_extend_twice():
    from autopilot import data_delivery as D
    once = D.extend(security_decl(), DD)
    with pytest.raises(ValueError):
        D.extend(once, DD)


def test_policy_still_refuses_what_it_refused_before():
    from autopilot import data_delivery as D
    from autopilot.deployer import policy
    decl = D.extend(security_decl(), DD)
    bad = copy.deepcopy(decl); bad["declaration"]["AP_AI"]["web_x"] = {"class": "Application"}
    assert any("not permitted by pattern library" in v for v in policy.check_as3(bad))
    bad = copy.deepcopy(decl); bad["declaration"]["AP_AI"]["rag_qdrant"]["service"]["virtualAddresses"] = ["10.50.20.40"]
    assert any("outside approved range" in v for v in policy.check_as3(bad))
    bad = copy.deepcopy(decl); bad["declaration"]["AP_AI"]["Shared"]["x"] = {"class": "WAF_Policy"}
    assert any("not permitted" in v for v in policy.check_as3(bad))
    bad = copy.deepcopy(decl); bad["declaration"]["Common"] = {"class": "Tenant"}
    assert policy.check_as3(bad)


def test_summary_rows():
    from autopilot import data_delivery as D
    rows = {r["application"]: r for r in D.summary(D.extend(security_decl(), DD))}
    assert rows["s3_seaweedfs"]["virtual_server"] == "10.50.10.103:8333" and rows["s3_seaweedfs"]["statistics_profile"] == "stats_s3"
    assert rows["llm_ollama"]["pool_members"] == ["10.50.20.45:11434"]


def test_data_vips_listen_only_on_isolated_lab_vlans():
    from autopilot import data_delivery as D
    from autopilot.deployer import policy
    new = D.extend(security_decl(), DD); t = new["declaration"]["AP_AI"]
    for app in ("s3_seaweedfs", "rag_qdrant", "llm_ollama"):
        assert t[app]["service"]["allowVlans"] == [{"bigip": "/Common/vlan_agent"}, {"bigip": "/Common/vlan_backend"}], app
    for app in ("mcp_risk_scoring", "mcp_fraud_intel"):                  # existing services untouched (no allowVlans added)
        assert "allowVlans" not in t[app]["service"]
    bad = copy.deepcopy(new); bad["declaration"]["AP_AI"]["rag_qdrant"]["service"]["allowVlans"] = [{"bigip": "/Common/external"}]
    assert any("/Common/external not allow-listed" in v for v in policy.check_as3(bad))
    dd = copy.deepcopy(DD); dd.pop("vlans")
    assert any("vlans" in e for e in D.check_design(dd))
