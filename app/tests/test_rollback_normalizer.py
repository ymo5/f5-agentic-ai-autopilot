"""Offline safety tests for captured deployment rollback state."""
from __future__ import annotations

import pytest

from autopilot.deployer import engine, policy


def tenant():
    return {"class": "Tenant", "Shared": {"class": "Application", "template": "shared"}}


def hosts(profile="delivery"):
    return {name: profile for name in policy.HOSTS}


def test_captured_adc_wrapper_extracts_only_ap_ai_tenant():
    captured = {"class": "ADC", "schemaVersion": "3.56.0", "id": "captured", "AP_AI": tenant()}
    assert engine._rollback_tenant(captured) == tenant()


def test_inner_tenant_shape_is_supported_for_legacy_mock_records():
    assert engine._rollback_tenant(tenant()) == tenant()


@pytest.mark.parametrize("bad", [
    None,
    {},
    {"class": "AS3", "declaration": {"class": "ADC"}},
    {"class": "ADC", "AP_AI": {"class": "ADC"}},
    {"class": "ADC", "AP_AI": tenant(), "OTHER": {"class": "Tenant"}},
    {"class": "Tenant", "AP_AI": tenant()},
])
def test_malformed_or_double_wrapped_tenant_is_refused(bad):
    with pytest.raises(engine.DeploymentRefused):
        engine._rollback_tenant(bad)


def test_host_profiles_must_be_exactly_the_allow_list_and_supported():
    assert engine._rollback_hosts(hosts()) == hosts()
    with pytest.raises(engine.DeploymentRefused):
        engine._rollback_hosts({"ap-agent-a": "delivery"})
    with pytest.raises(engine.DeploymentRefused):
        engine._rollback_hosts({**hosts(), "unexpected": "delivery"})
    with pytest.raises(engine.DeploymentRefused):
        engine._rollback_hosts(hosts("unknown"))


def test_rehearsed_declaration_stays_ap_ai_only_and_policy_safe():
    captured = {"class": "ADC", "schemaVersion": "3.56.0", "id": "captured", "AP_AI": tenant()}
    restored = engine._rollback_tenant(captured)
    declaration = {"class": "AS3", "action": "deploy", "persist": True,
                   "declaration": {"class": "ADC", "schemaVersion": "3.56.0",
                                   "id": "autopilot-rollback", policy.TENANT: restored}}
    assert policy.check_as3(declaration) == []
    assert set(declaration["declaration"]) == {"class", "schemaVersion", "id", "AP_AI"}


def test_double_wrapped_declaration_is_rejected_before_policy_or_write():
    captured = {"class": "ADC", "schemaVersion": "3.56.0", "id": "captured",
                "AP_AI": {"class": "ADC", "AP_AI": tenant()}}
    with pytest.raises(engine.DeploymentRefused):
        engine._rollback_tenant(captured)
