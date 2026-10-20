"""Deployer network allow-lists are configurable per installation (deployer_policy) and validated fail-closed."""
from __future__ import annotations

import ipaddress

import pytest

from autopilot.deployer import policy


def test_defaults_are_the_reference_topology():
    vip, mem, hosts = policy.load_network_policy({})
    assert (str(vip), str(mem)) == ("10.50.10.96/28", "10.50.20.0/24") and hosts == policy.DEFAULT_HOSTS


def test_installation_can_configure_its_own_networks():
    vip, mem, hosts = policy.load_network_policy({"deployer_policy": {
        "vip_range": "172.20.1.0/27", "member_range": "172.20.2.0/24",
        "hosts": {"ap-ai-services": "172.20.0.13", "ap-agent-b": "172.20.0.12", "ap-agent-a": "172.20.0.11"}}})
    assert vip == ipaddress.ip_network("172.20.1.0/27") and mem == ipaddress.ip_network("172.20.2.0/24")
    assert hosts["ap-agent-a"] == "172.20.0.11"


@pytest.mark.parametrize("dp", [
    {"vip_range": "0.0.0.0/0"},                       # would allow any VIP
    {"vip_range": "8.8.8.0/24"},                      # public
    {"member_range": "10.0.0.0/8"},                   # too wide
    {"vip_range": "10.50.20.0/28"},                   # overlaps the member range
    {"vip_range": "10.50.10.97/28"},                  # host bits set
    {"hosts": {"ap-agent-a": "10.0.0.1"}},            # missing roles
    {"hosts": {"ap-ai-services": "x", "ap-agent-b": "10.0.0.2", "ap-agent-a": "10.0.0.1"}},
    {"extra": 1},
    "not-a-dict",
])
def test_invalid_policy_is_refused(dp):
    with pytest.raises(ValueError):
        policy.load_network_policy({"deployer_policy": dp})
