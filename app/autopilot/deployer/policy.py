"""Deployment policy: what the deployment engine may ever send to BIG-IP_C (defence in depth).

Checked by the engine before execution AND again inside the BIG-IP executor before every write.
"""
from __future__ import annotations

import ipaddress
import re

TENANT = "AP_AI"
APP_NAME = re.compile(r"^(Shared|mcp_[a-z0-9_]+|a2a_[a-z0-9_]+|s3_[a-z0-9_]+|rag_[a-z0-9_]+|llm_[a-z0-9_]+)$")   # rag_/llm_: AI Data Delivery package
CLASSES = {"Application", "Service_HTTPS", "Service_HTTP", "Pool", "Monitor", "iRule", "TLS_Server", "TLS_Client",
           "Certificate", "HTTP_Profile", "TCP_Profile", "Statistics_Profile"}   # Statistics_Profile: S3 request telemetry (observe-only)
BIGIP_REFS = {"/Common/universal", "/Common/aplab-wildcard.crt", "/Common/aplab-wildcard.key", "/Common/aplab-ca.crt",
              "/Common/vlan_agent", "/Common/vlan_backend"}   # AI Data Delivery: allowVlans (isolated lab VLANs only)
HOST_COMMANDS = re.compile(r"^(status( fingerprint)?|profile (baseline|delivery|security)|replica (stop|start) [12]|probe direct-mcp)$")

# Network allow-lists. Defaults = the documented reference lab topology. An installation may override them in the
# Autopilot configuration (AUTOPILOT_CONFIG) under `deployer_policy:`:
#   deployer_policy:
#     vip_range: 10.50.10.96/28          # every VIP the deployer may create must be inside this network
#     member_range: 10.50.20.0/24        # every pool member must be inside this network
#     hosts: {ap-ai-services: 192.0.2.63, ap-agent-b: 192.0.2.62, ap-agent-a: 192.0.2.61}   # SSH helper targets
# Validation is fail-closed: an invalid section stops the deployer/web at import time instead of widening the policy.
DEFAULT_VIP_RANGE = "10.50.10.96/28"          # 10.50.10.96-111 (VIPs .100-.105)
DEFAULT_MEMBER_RANGE = "10.50.20.0/24"
DEFAULT_HOSTS = {"ap-ai-services": "192.0.2.63", "ap-agent-b": "192.0.2.62", "ap-agent-a": "192.0.2.61"}


def load_network_policy(cfg: dict | None) -> tuple:
    """(vip_range, member_range, hosts) from cfg['deployer_policy'] or the defaults. Raises ValueError when invalid."""
    dp = (cfg or {}).get("deployer_policy") or {}
    if not isinstance(dp, dict) or set(dp) - {"vip_range", "member_range", "hosts"}:
        raise ValueError("deployer_policy accepts only vip_range, member_range and hosts")
    vip = ipaddress.ip_network(str(dp.get("vip_range", DEFAULT_VIP_RANGE)), strict=True)
    mem = ipaddress.ip_network(str(dp.get("member_range", DEFAULT_MEMBER_RANGE)), strict=True)
    for name, net in (("vip_range", vip), ("member_range", mem)):
        if net.version != 4 or not net.is_private or net.prefixlen < 16:
            raise ValueError(f"deployer_policy.{name} must be a private IPv4 network of /16 or smaller")
    if vip.overlaps(mem):
        raise ValueError("deployer_policy.vip_range and member_range must not overlap")
    hosts = dp.get("hosts", DEFAULT_HOSTS)
    if not isinstance(hosts, dict) or set(hosts) != set(DEFAULT_HOSTS):
        raise ValueError(f"deployer_policy.hosts must define exactly {sorted(DEFAULT_HOSTS)}")
    hosts = {k: str(ipaddress.ip_address(str(v))) for k, v in hosts.items()}
    return vip, mem, hosts


def _config() -> dict | None:
    import os
    path = os.environ.get("AUTOPILOT_CONFIG")
    if not path or not os.path.exists(path):
        return None
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


VIP_RANGE, MEMBER_RANGE, HOSTS = load_network_policy(_config())


class PolicyViolation(Exception):
    pass


def _refs(obj, out):
    if isinstance(obj, dict):
        if set(obj) == {"bigip"}:
            out.append(obj["bigip"])
        for v in obj.values():
            _refs(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _refs(v, out)


def check_as3(decl: dict) -> list[str]:
    v = []
    if decl.get("class") != "AS3" or decl.get("action") not in ("deploy", "dry-run"):
        v.append("must be an AS3 deploy or dry-run request")
    adc = decl.get("declaration") or {}
    if adc.get("class") != "ADC":
        v.append("declaration.class must be ADC")
    tenants = [k for k, x in adc.items() if isinstance(x, dict) and x.get("class") == "Tenant"]
    if tenants != [TENANT]:
        v.append(f"tenants must be exactly ['{TENANT}'], got {tenants}")
    for k in adc:
        if k.lower() == "common":
            v.append("/Common must never be declared")
    t = adc.get(TENANT) or {}
    for app, body in t.items():
        if not isinstance(body, dict):
            continue
        if body.get("class") != "Application" or not APP_NAME.match(app):
            v.append(f"application '{app}' not permitted by pattern library")
            continue
        for name, obj in body.items():
            if isinstance(obj, dict) and "class" in obj and obj["class"] not in CLASSES:
                v.append(f"{app}/{name}: class {obj['class']} not permitted")
            if isinstance(obj, dict) and obj.get("class", "").startswith("Service_"):
                if obj.get("snat") != "auto":
                    v.append(f"{app}/{name}: snat must be auto")
                for a in obj.get("virtualAddresses", []):
                    if ipaddress.ip_address(a) not in VIP_RANGE:
                        v.append(f"{app}/{name}: VIP {a} outside approved range {VIP_RANGE}")
            if isinstance(obj, dict) and obj.get("class") == "Pool":
                for m in obj.get("members", []):
                    for a in m.get("serverAddresses", []):
                        if ipaddress.ip_address(a) not in MEMBER_RANGE:
                            v.append(f"{app}/{name}: member {a} outside {MEMBER_RANGE}")
    refs: list[str] = []
    _refs(decl, refs)
    for r in refs:
        if r not in BIGIP_REFS:
            v.append(f"reference to {r} not allow-listed")
    return v


def check_host_command(host: str, command: str) -> None:
    if host not in HOSTS:
        raise PolicyViolation(f"host {host} not allow-listed")
    if not HOST_COMMANDS.match(command):
        raise PolicyViolation(f"command '{command}' not permitted")


def check_tenant_path(path: str) -> None:
    if path.rstrip("/") not in ("/mgmt/shared/appsvcs/declare", f"/mgmt/shared/appsvcs/declare/{TENANT}"):
        raise PolicyViolation(f"AS3 path {path} not permitted")
