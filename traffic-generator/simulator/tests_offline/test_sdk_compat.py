"""Compatibility with the real libraries Project A uses: the official MCP Python SDK (mcp 2.3.0, the same server and
client stack as Project A's MCP servers and Autopilot's validator) and boto3 SigV4 S3 signing.

Requires Python >= 3.10 with `mcp`, `uvicorn` and `boto3` importable (skipped otherwise). Run it with an interpreter that
has them, e.g. read-only from the Autopilot venv with bytecode writes disabled:
    PYTHONDONTWRITEBYTECODE=1 <venv-python> -B -m unittest tests_offline.test_sdk_compat
All servers listen on 127.0.0.1; nothing leaves this machine.
"""
import asyncio, copy, importlib.util, json, os, socket, sys, tempfile, threading, time, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SIMDIR = os.path.dirname(HERE)
sys.path.insert(0, SIMDIR); sys.path.insert(0, HERE)
HAVE = sys.version_info >= (3, 10) and all(importlib.util.find_spec(m) for m in ("mcp", "uvicorn", "boto3", "httpx2"))

import sim_profiles, mcp_adapter                           # noqa: E402
import f5_ai_workload_sim as sim                           # noqa: E402
from mock_s3 import MockS3                                 # noqa: E402

ENV = "offline-test-sdk"
TEST_AK, TEST_SK = "AKIDOFFLINETEST000001", "offline-test-secret-not-a-credential"


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@unittest.skipUnless(HAVE, "needs Python >= 3.10 with mcp, uvicorn, boto3, httpx2 (e.g. the Autopilot venv, read-only)")
class SdkCompat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import uvicorn
        from mcp.server import MCPServer
        from mcp.server.transport_security import TransportSecuritySettings
        from mcp.types import ToolAnnotations
        srv = MCPServer("risk-scoring", version="sdk-compat-test")

        @srv.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def model_info() -> dict:
            """Describe the scoring model and the serving replica."""
            return {"model_version": "test", "replica": "risk-scoring-sdk"}

        @srv.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
        def score_transaction(amount: float, mcc: str = "5411") -> dict:
            """Return a synthetic score."""
            return {"score": 0.1, "band": "low", "replica": "risk-scoring-sdk"}

        app = srv.streamable_http_app(streamable_http_path="/mcp",
                                      transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                                                                   allowed_hosts=["127.0.0.1:*", "localhost:*"]))
        cls.port = free_port()
        cls.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=cls.port, log_level="error", lifespan="on"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True); cls.thread.start()
        for _ in range(100):
            if cls.server.started:
                break
            time.sleep(0.05)
        cls.s3 = MockS3({TEST_AK: TEST_SK}, {"case-files/CASE-7000.txt": b"synthetic case 7000", "case-files/CASE-7001.txt": b"synthetic case 7001",
                                             "ai-training-data/fraud-model/synthetic-v1/shard-000.bin": b"\x00" * 2048,
                                             "ai-training-data/fraud-model/synthetic-v1/shard-001.bin": b"\x01" * 4096})
        sim_profiles.register_test_environment(ENV, {f"127.0.0.1:{cls.port}": "SDK MCP server (mock VIP)", cls.s3.address: "S3_VIP (mock)"})
        sim.activate_environment(ENV)
        with open(os.path.join(SIMDIR, "profiles", "project-a.json")) as f:
            cls.base = json.load(f)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True; cls.thread.join(5); cls.s3.close()
        sim.ACTIVE.update(env="project-b", allowed=sim.ALLOWED)

    def target(self):
        return {"name": "SDK", "url": f"http://127.0.0.1:{self.port}/mcp", "address": f"127.0.0.1:{self.port}", "connect_host": "127.0.0.1",
                "connect_port": self.port, "scheme": "http", "via_bigip": True, "auth": "none", "tls": None}

    def session(self, mode):
        return mcp_adapter.McpSession(self.target(), mode=mode, allowed_tools=["model_info", "score_transaction"])

    # ------------------------------------------------------------------ MCP
    def test_legacy_handshake_against_official_sdk_server(self):
        s = self.session("legacy"); s.open()
        self.assertIn(s.protocol_version, mcp_adapter.HANDSHAKE_VERSIONS); self.assertTrue(s.session_id)
        self.assertEqual(s.server_info["name"], "risk-scoring")
        tools = s.list_tools(); r = s.call_tool("model_info"); s.close()
        self.assertEqual(tools, ["model_info", "score_transaction"])
        self.assertFalse(r["is_error"]); self.assertEqual(r["replica"], "risk-scoring-sdk")

    def test_stateless_2026_07_28_against_official_sdk_server(self):
        s = self.session("stateless")
        tools = s.list_tools(); r = s.call_tool("score_transaction", {"amount": 12.5})
        self.assertEqual(tools, ["model_info", "score_transaction"]); self.assertFalse(r["is_error"]); self.assertEqual(r["replica"], "risk-scoring-sdk")

    def test_adapter_and_official_sdk_client_see_the_same_tools(self):
        import httpx2
        from mcp import Client
        from mcp.client.streamable_http import streamable_http_client

        async def via_sdk():
            async with httpx2.AsyncClient(timeout=10) as http:
                async with Client(streamable_http_client(self.target()["url"], http_client=http), mode="legacy") as c:
                    return sorted(t.name for t in (await c.list_tools()).tools), c.protocol_version
        names, ver = asyncio.run(via_sdk())
        s = self.session("legacy"); s.open(); mine = s.list_tools(); s.close()
        self.assertEqual(names, mine); self.assertEqual(ver, s.protocol_version)

    def test_unknown_tool_reaches_server_as_error_not_success(self):
        s = mcp_adapter.McpSession(self.target(), allowed_tools=[], probe_tools=["freeze_account"]); s.open()
        try:
            r = s.call_tool("freeze_account", probe=True)
            self.assertTrue(r["is_error"])
        except mcp_adapter.McpRpcError:
            pass                                       # either representation means "reached the server, not denied by BIG-IP"
        finally:
            s.close()

    # ------------------------------------------------------------------ S3 (boto3 SigV4, credentials from environment only)
    def s3_workload(self, name, env):
        p = copy.deepcopy(self.base); p["environment"] = ENV
        for n, d in p["destinations"].items():          # only the S3 destination exists in this offline environment
            p["destinations"][n] = {"status": "not_configured", "reason": "not used by this offline test"}
        p["destinations"]["S3_VIP"] = {"status": "configured", "address": self.s3.address, "scheme": "http", "via_bigip": True, "auth": "s3-sigv4"}
        path = tempfile.mktemp(suffix=".json")
        with open(path, "w") as f:
            json.dump(p, f)
        try:
            with mock.patch.dict(os.environ, env):
                _, wl = sim.load_profile(path, "pa_lab")
        finally:
            os.unlink(path)
        wc = wl[name]; self.assertNotIn("_unavailable", wc, wc.get("_unavailable"))
        cls = sim.PROFILE_CLASSES.get(wc["kind"]) or sim.KINDS[wc["kind"]]
        return cls(wc, {"telemetry": sim.Telemetry(None, "test")})

    def creds(self, secret=TEST_SK):
        return {"F5SIM_PA_S3_ACCESS_KEY_ID": TEST_AK, "F5SIM_PA_S3_SECRET_ACCESS_KEY": secret}

    def test_s3_case_read_signed_with_environment_credentials(self):
        w = self.s3_workload("pa_s3_case_read", self.creds())
        with mock.patch.dict(os.environ, self.creds()):
            r = w.run()
        self.assertEqual(r["outcome"], "ok"); self.assertEqual(r["m"]["objects"], 2)
        self.assertTrue(all(ok for _, _, ok in self.s3.seen[-3:])); self.assertFalse([s for s in self.s3.seen if s[0] in ("PUT", "DELETE")])

    def test_s3_training_reads_signed(self):
        w = self.s3_workload("pa_training_data_read", self.creds())
        with mock.patch.dict(os.environ, self.creds()):
            r = w.run()
        self.assertEqual(r["outcome"], "ok"); self.assertEqual(r["m"]["objects"], 3)   # 2 shards, wrap-around epoch

    def test_s3_wrong_secret_is_refused(self):
        import botocore.exceptions
        w = self.s3_workload("pa_s3_case_read", self.creds())
        with mock.patch.dict(os.environ, self.creds("wrong-secret")):
            with self.assertRaises(botocore.exceptions.ClientError) as c:
                w.run()
        self.assertEqual(c.exception.response["Error"]["Code"], "SignatureDoesNotMatch")

    def test_s3_missing_credentials_refused_before_any_request(self):
        n = len(self.s3.seen)
        with mock.patch.dict(os.environ, {}, clear=False):
            for k in self.creds():
                os.environ.pop(k, None)
            with self.assertRaises(RuntimeError):
                sim.make_s3(f"http://{self.s3.address}", {"access_key_id": "F5SIM_PA_S3_ACCESS_KEY_ID", "secret_access_key": "F5SIM_PA_S3_SECRET_ACCESS_KEY"})
        self.assertEqual(len(self.s3.seen), n)


if __name__ == "__main__":
    unittest.main()
