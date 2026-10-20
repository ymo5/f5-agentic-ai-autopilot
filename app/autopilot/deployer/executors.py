"""Executors: the only code that talks to BIG-IP_C (writes) and to project VMs (dependency profiles).

Live executors enforce policy again before every write. Mock executors implement the same interface for
tests and rehearsals without touching infrastructure (with failure injection).
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import re
import ssl
import time

import httpx

from . import policy


class ExecError(Exception):
    pass


class BigipExecutor:
    """BIG-IP iControl REST with (a) certificate pinning enforced on EVERY TLS connection (the pinned device certificate
    is the only trust anchor) and (b) token authentication (one login per account, reused until expiry)."""

    def __init__(self, host: str, cert_sha256: str, deployer: tuple[str, str], observer: tuple[str, str]):
        self.base, self.host = f"https://{host}", host
        self.creds = {"deployer": deployer, "observer": observer}
        pem = ssl.get_server_certificate((host, 443), timeout=10)
        if hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() != cert_sha256.replace(":", "").lower():
            raise ExecError("BIG-IP TLS certificate does not match pinned fingerprint")
        ctx = ssl.create_default_context(cadata=pem)
        ctx.check_hostname = False                       # device cert CN is localhost.localdomain; identity = pinned cert
        ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN  # trust the pinned self-signed leaf itself
        self.ctx = ctx
        self.tokens: dict[str, tuple[str, float]] = {}
        self.client: httpx.AsyncClient | None = None

    async def _client(self) -> httpx.AsyncClient:
        if self.client is None:
            self.client = httpx.AsyncClient(base_url=self.base, verify=self.ctx, timeout=120)
        return self.client

    async def _token(self, acct: str, force: bool = False) -> str:
        tok = self.tokens.get(acct)
        if tok and not force and tok[1] > time.time() + 60:
            return tok[0]
        u, p = self.creds[acct]
        c = await self._client()
        r = await c.post("/mgmt/shared/authn/login", json={"username": u, "password": p, "loginProviderName": "tmos"})
        if r.status_code != 200:
            raise ExecError(f"BIG-IP token login for {u} failed: HTTP {r.status_code}")
        t = r.json()["token"]
        self.tokens[acct] = (t["token"], time.time() + min(int(t.get("timeout", 1200)), 1200))
        return t["token"]

    async def _req(self, method: str, path: str, *, admin: bool, body=None, timeout: float = 120) -> tuple[int, object]:
        acct = "deployer" if admin else "observer"
        c = await self._client()
        for attempt in (0, 1):
            r = await c.request(method, path, json=body, timeout=timeout,
                                headers={"X-F5-Auth-Token": await self._token(acct, force=attempt == 1)})
            if r.status_code != 401:
                break
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, r.text

    async def get(self, path: str, admin: bool = False):
        return await self._req("GET", path, admin=admin)

    async def as3_get_tenant(self) -> dict | None:
        for _ in range(20):                              # AS3 answers 202/503 while busy: bounded polling
            code, body = await self._req("GET", f"/mgmt/shared/appsvcs/declare/{policy.TENANT}", admin=True)
            if code in (202, 503):
                await asyncio.sleep(3)
                continue
            if code in (204, 404) or not body:
                return None
            if code != 200:
                raise ExecError(f"AS3 GET tenant failed: HTTP {code}")
            return body
        raise ExecError("AS3 GET tenant: still busy after 60 s")

    async def as3_post(self, decl: dict) -> dict:
        v = policy.check_as3(decl)
        if v:
            raise policy.PolicyViolation("; ".join(v))
        for _ in range(10):
            code, body = await self._req("POST", "/mgmt/shared/appsvcs/declare", admin=True, body=decl, timeout=600)
            if code != 503:
                break
            await asyncio.sleep(6)
        results = (body or {}).get("results", []) if isinstance(body, dict) else []
        if code != 200 or any(r.get("code") not in (200, None) for r in results):
            raise ExecError(f"AS3 {decl.get('action')} failed: HTTP {code} {json.dumps(body)[:600]}")
        return body

    async def as3_delete_tenant(self) -> None:
        policy.check_tenant_path(f"/mgmt/shared/appsvcs/declare/{policy.TENANT}")
        code, body = await self._req("DELETE", f"/mgmt/shared/appsvcs/declare/{policy.TENANT}", admin=True, timeout=600)
        if code not in (200, 204, 404):
            raise ExecError(f"AS3 DELETE {policy.TENANT} failed: HTTP {code} {str(body)[:300]}")


class HostExecutor:
    def __init__(self, key_path: str, known_hosts: str):
        self.key, self.known = key_path, known_hosts

    async def run(self, host: str, command: str) -> dict:
        policy.check_host_command(host, command)
        p = await asyncio.create_subprocess_exec(
            "ssh", "-i", self.key, "-o", f"UserKnownHostsFile={self.known}", "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "IdentitiesOnly=yes",
            f"apdeploy@{policy.HOSTS[host]}", command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(p.communicate(), 300)
        try:
            d = json.loads(out.decode().strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise ExecError(f"{host} '{command}': rc={p.returncode} {err.decode()[:200]}")
        if p.returncode != 0 or not d.get("ok"):
            raise ExecError(f"{host} '{command}' failed: {d}")
        return d


# ------------------------------------------------------------------------------------- mocks
class MockBigip:
    """In-memory BIG-IP/AS3 with failure injection: fail_on = {'dry-run'|'deploy'|'delete'}."""

    def __init__(self, version="21.1.0.3", as3="3.56.0", fail_on: set | None = None):
        self.version, self.as3, self.fail_on = version, as3, set(fail_on or ())
        self.tenant: dict | None = None
        self.calls: list[tuple] = []
        self.memory = {"other_total": 2.8e9, "other_used": 1.9e9, "swap_total": 1.0e9, "swap_used": 0.4e9}
        self.drop_objects: set = set()   # failure injection: AS3 "accepts" but objects are missing from the running config
        # AI Data Delivery failure injection / counters (mock only): member availability per "ip:port", profiles silently not
        # attached / wrongly attached per application, virtual-server and S3 statistics counters advanced by tests.
        self.member_state: dict = {}
        self.profile_faults: dict = {}   # app -> "drop_stats" | "add_client_ssl" | "drop_tls" | "drop_vlans"
        self.vs_conns: dict = {}         # app -> clientside.totConns
        self.vs_reqs: dict = {}          # app -> HTTP profile numberReqs
        self.s3_stats: dict = {}         # field -> value

    async def get(self, path: str, admin: bool = False):
        self.calls.append(("GET", path))
        if path == "/mgmt/tm/sys/version":
            return 200, {"entries": {"x": {"nestedStats": {"entries": {"Version": {"description": self.version}}}}}}
        if path == "/mgmt/shared/appsvcs/info":
            return 200, {"version": self.as3}
        if path == "/mgmt/tm/sys/clock":
            return 200, {"entries": {"x": {"nestedStats": {"entries": {"fullDate": {"description": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}}}}}
        if path == "/mgmt/tm/net/self":
            return 200, {"items": [{"name": "self_agent", "fullPath": "/Common/self_agent", "address": "10.50.10.10/24", "vlan": "/Common/vlan_agent"},
                                   {"name": "self_backend", "fullPath": "/Common/self_backend", "address": "10.50.20.10/24", "vlan": "/Common/vlan_backend"}]}
        if path == "/mgmt/tm/sys/crypto/cert":
            return 200, {"items": [{"name": "/Common/aplab-ca.crt"}, {"name": "/Common/aplab-wildcard.crt"}]}
        if path == "/mgmt/tm/sys/memory":
            m = self.memory
            return 200, {"entries": {"x": {"nestedStats": {"entries": {k: {"value": v} for k, v in (
                ("otherMemoryTotal", m["other_total"]), ("otherMemoryUsed", m["other_used"]), ("swapTotal", m["swap_total"]),
                ("swapUsed", m["swap_used"]))}}}}}
        if path.startswith("/mgmt/tm/ltm/virtual?") or path.startswith("/mgmt/tm/ltm/pool?"):
            return 200, {"items": self._ltm("virtual" if "/virtual?" in path else "pool")}
        m = re.match(rf"^/mgmt/tm/ltm/pool/~{policy.TENANT}~([a-z0-9_]+)~pool/members/stats$", path)
        if m:
            b = (self.tenant or {}).get(m.group(1))
            if not b:
                return 404, {"message": "not found"}
            ent = {}
            for mem in b["pool"]["members"]:
                ip, port = mem["serverAddresses"][0], mem["servicePort"]
                ent[f"{ip}:{port}"] = {"nestedStats": {"entries": {"addr": {"description": ip}, "port": {"value": port},
                                       "status.availabilityState": {"description": self.member_state.get(f"{ip}:{port}", "available")},
                                       "status.enabledState": {"description": "enabled"}}}}
            return 200, {"entries": ent}
        m = re.match(rf"^/mgmt/tm/ltm/virtual/~{policy.TENANT}~([a-z0-9_]+)~service/stats$", path)
        if m:
            if m.group(1) not in (self.tenant or {}):
                return 404, {"message": "not found"}
            return 200, {"entries": {"x": {"nestedStats": {"entries": {"clientside.totConns": {"value": self.vs_conns.get(m.group(1), 0)},
                                                                        "clientside.curConns": {"value": 0}}}}}}
        m = re.match(rf"^/mgmt/tm/ltm/virtual/~{policy.TENANT}~([a-z0-9_]+)~service/profiles/~{policy.TENANT}~Shared~http_ai/stats$", path)
        if m:
            if m.group(1) not in (self.tenant or {}):
                return 404, {"message": "not found"}
            return 200, {"entries": {"x": {"nestedStats": {"entries": {"numberReqs": {"value": self.vs_reqs.get(m.group(1), 0)},
                                                                        "getReqs": {"value": self.vs_reqs.get(m.group(1), 0)}}}}}}
        if path == f"/mgmt/tm/ltm/profile/statistics/~{policy.TENANT}~Shared~stats_s3/stats":
            if "stats_s3" not in ((self.tenant or {}).get("Shared") or {}):
                return 404, {"message": "not found"}
            # the format BIG-IP really uses for statistics profiles: string values in `description`, plus non-counter entries
            ent = {k: {"description": str(v)} for k, v in self.s3_stats.items()}
            ent.update(tmName={"description": f"/{policy.TENANT}/Shared/stats_s3"}, typeId={"description": "ltm profile statistics"})
            return 200, {"entries": {f"https://localhost/mgmt/tm/ltm/profile/statistics/~{policy.TENANT}~Shared~stats_s3/stats":
                                     {"nestedStats": {"entries": ent}}}}
        return 200, {"items": []}

    def _ltm(self, kind: str) -> list[dict]:
        """Running-config view the way BIG-IP reports AS3-created objects (used by post-deploy verification)."""
        out = []
        for app, b in (self.tenant or {}).items():
            if not (isinstance(b, dict) and "service" in b) or app in self.drop_objects:
                continue
            sv, pl = b["service"], b["pool"]
            if kind == "virtual":
                profs = ([{"name": sv["serverTLS"]["use"].split("/")[-1], "fullPath": sv["serverTLS"]["use"]}]
                         if "serverTLS" in sv and self.profile_faults.get(app) != "drop_tls" else []) + \
                        [{"name": "http_ai", "fullPath": f"/{policy.TENANT}/{app}/http_ai"}]
                if "profileStatistics" in sv and self.profile_faults.get(app) != "drop_stats":
                    profs.append({"name": sv["profileStatistics"]["use"].split("/")[-1], "fullPath": sv["profileStatistics"]["use"]})
                if self.profile_faults.get(app) == "add_client_ssl":
                    profs.append({"name": "tls_server", "fullPath": f"/{policy.TENANT}/Shared/tls_server"})
                vl = {"vlansEnabled": True, "vlans": [x["bigip"] for x in sv["allowVlans"]]} \
                    if sv.get("allowVlans") and self.profile_faults.get(app) != "drop_vlans" else {}
                out.append({"fullPath": f"/{policy.TENANT}/{app}/service", "destination": f"/{policy.TENANT}/{sv['virtualAddresses'][0]}:{sv['virtualPort']}",
                            "pool": f"/{policy.TENANT}/{app}/pool", "rules": [r["use"] for r in sv.get("iRules", [])],
                            "profilesReference": {"items": profs}, **vl})
            else:
                out.append({"fullPath": f"/{policy.TENANT}/{app}/pool", "monitor": f"min 1 of {pl['monitors'][0]['use']} ",
                            "membersReference": {"items": [{"name": f"{m['serverAddresses'][0]}:{m['servicePort']}"} for m in pl["members"]]}})
        return out

    async def as3_get_tenant(self):
        self.calls.append(("GET", "tenant"))
        return copy.deepcopy(self.tenant)

    async def as3_post(self, decl: dict) -> dict:
        v = policy.check_as3(decl)
        if v:
            raise policy.PolicyViolation("; ".join(v))
        self.calls.append(("POST", decl["action"]))
        if decl["action"] in self.fail_on:
            raise ExecError(f"AS3 {decl['action']} failed: HTTP 422 (injected)")
        if decl["action"] == "deploy":
            self.tenant = copy.deepcopy(decl["declaration"][policy.TENANT])
        return {"results": [{"code": 200, "message": "success", "tenant": policy.TENANT}]}

    async def as3_delete_tenant(self):
        self.calls.append(("DELETE", "tenant"))
        if "delete" in self.fail_on:
            raise ExecError("AS3 DELETE failed (injected)")
        self.tenant = None


class MockHosts:
    def __init__(self, fail_on: set | None = None):
        self.profile = {h: "baseline" for h in policy.HOSTS}
        self.fail_on, self.calls = set(fail_on or ()), []
        self.replicas = {"1": True, "2": True}

    async def run(self, host: str, command: str) -> dict:
        policy.check_host_command(host, command)
        self.calls.append((host, command))
        if (host, command) in self.fail_on:
            raise ExecError(f"{host} '{command}' failed (injected)")
        if command.startswith("profile "):
            self.profile[host] = command.split()[1]
        elif command == "status fingerprint":
            return {"ok": True, "role": host, "profile": self.profile[host],
                    "container_id": "mock-agent-b-container", "image_id": "sha256:" + "a" * 64,
                    "started_at": "2026-01-01T00:00:00Z", "mcp_tools_sha256": "b" * 64,
                    "ap_dep_apply_sha256": "c" * 64, "executable": "/usr/local/sbin/ap-dep-apply"}
        elif command.startswith("replica "):
            _, op, n = command.split()
            self.replicas[n] = op == "start"
        return {"ok": True, "role": host, "profile": self.profile[host]}
