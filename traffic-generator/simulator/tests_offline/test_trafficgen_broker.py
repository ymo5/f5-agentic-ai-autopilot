"""ap-trafficgen-broker, offline: the real broker script in a temp directory with stub ap-trafficgen / docker executables
that record every invocation. Nothing runs as root and no container is touched."""
import fcntl, hashlib, hmac, json, os, secrets, stat, subprocess, sys, tempfile, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BROKER = os.path.join(os.path.dirname(os.path.dirname(HERE)), "container", "ap-trafficgen-broker")
KEY = b"0123456789abcdef0123456789abcdef"

STUB_CTL = """#!/bin/bash
echo "$*" >> "$(dirname "$0")/ctl.calls"
case "$1" in
  start|once) touch "$(dirname "$0")/running"; echo "started ap-trafficgen: $*";;
  stop) rm -f "$(dirname "$0")/running"; echo "stopped (exit 0)";;
  archive) echo "archived /var/lib/ap-trafficgen/runs/20261020T000000Z";;
esac
"""
STUB_DOCKER = """#!/bin/bash
d="$(dirname "$0")"; echo "$*" >> "$d/docker.calls"
if [ -e "$d/running" ]; then echo 'true|2026-10-20T00:00:00Z|0001-01-01T00:00:00Z|0|["--duration","300"]'; exit 0; fi
if [ -e "$d/exited" ]; then echo 'false|2026-10-20T00:00:00Z|2026-10-20T00:05:00Z|0|["--duration","300"]'; exit 0; fi
exit 1
"""


class Broker(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="tgbroker-")
        open(f"{self.d}/key", "wb").write(KEY)
        for name, body in (("ctl", STUB_CTL), ("docker", STUB_DOCKER)):
            p = f"{self.d}/{name}"; open(p, "w").write(body); os.chmod(p, 0o755)

    def call(self, action, key=KEY, ts=None, nonce=None, mutate=None, **params):
        req = {"action": action, "ts": time.time() if ts is None else ts, "nonce": nonce or secrets.token_hex(16), **params}
        req["mac"] = hmac.new(key, json.dumps(req, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        if mutate:
            mutate(req)
        p = subprocess.run([sys.executable, "-B", BROKER], input=json.dumps(req) + "\n", capture_output=True, text=True, timeout=60,
                           env={"AP_TG_BROKER_TEST_DIR": self.d, "PATH": os.environ["PATH"]})
        return json.loads(p.stdout)

    def calls(self, name="ctl"):
        p = f"{self.d}/{name}.calls"
        return open(p).read().split("\n")[:-1] if os.path.exists(p) else []

    def state(self):
        return json.load(open(f"{self.d}/state.json"))

    # ---------------------------------------------------------------- authentication
    def test_authentication_failures_never_execute(self):
        self.assertEqual(self.call("start", key=b"wrong" * 6, preset="a2a-discovery-5m", by="se1")["error"], "authentication failed")
        self.assertEqual(self.call("start", ts=time.time() - 120, preset="a2a-discovery-5m", by="se1")["error"], "stale request")
        n = secrets.token_hex(16)
        self.assertTrue(self.call("ping", nonce=n)["ok"])
        self.assertIn("replayed", self.call("ping", nonce=n)["error"])
        self.assertEqual(self.call("start", preset="a2a-discovery-5m", by="se1", mutate=lambda r: r.update(preset="ai-data-path-15m"))["error"],
                         "authentication failed")                        # tampered after signing
        p = subprocess.run([sys.executable, "-B", BROKER], input="not json\n", capture_output=True, text=True, env={"AP_TG_BROKER_TEST_DIR": self.d})
        self.assertEqual(json.loads(p.stdout)["error"], "malformed request")
        self.assertEqual(self.calls(), [])

    def test_only_listed_actions(self):
        for a in ("exec", "archive", "shell", "reset", ""):
            self.assertFalse(self.call(a, by="se1")["ok"], a)
        self.assertEqual(self.calls(), [])

    # ---------------------------------------------------------------- presets are the authority
    def test_start_uses_only_the_fixed_preset_argv(self):
        r = self.call("start", preset="ai-data-path-15m", by="se1", argv=["start", "7200", "--max-rpm", "60"], duration=7200,
                      only="pa_mcp_delivery", max_rpm=60, extra="; rm -rf /")
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.calls(), ["start 900 --only pa_a2a_card,pa_vector_query,pa_embed --max-rpm 4"])
        cur = self.state()["current"]
        self.assertEqual((cur["preset"], cur["by"], cur["duration_s"], cur["max_rpm"], cur["outcome"]), ("ai-data-path-15m", "se1", 900, 4, "started"))

    def test_unknown_preset_and_bad_operator_refused(self):
        for p in ("custom", "../../x", "a2a-discovery-5m; id", None, 3):
            self.assertEqual(self.call("start", preset=p, by="se1")["error"], "unknown preset")
        self.assertEqual(self.call("start", preset="a2a-discovery-5m", by="se1; rm")["error"], "invalid operator name")
        self.assertEqual(self.calls(), [])

    def test_preset_table_is_bounded_and_excludes_mcp_and_s3(self):
        src = open(BROKER).read()
        ns = {}
        exec(src.split("PRESETS = ", 1)[1].split("\n\n\n", 1)[0].join(["PRESETS = ", ""]), ns)
        for k, (argv, dur, rpm, wl) in ns["PRESETS"].items():
            self.assertIn(argv[0], ("start", "once"), k)
            self.assertLessEqual(dur, 900, k); self.assertLessEqual(rpm, 4, k)
            self.assertFalse([w for w in wl if "mcp" in w or "s3" in w or "training" in w or "investigation" in w], k)
            only = argv[argv.index("--only") + 1].split(",")
            self.assertEqual(only, wl, k)
            if argv[0] == "start":
                self.assertEqual(int(argv[1]), dur, k); self.assertEqual(argv[argv.index("--max-rpm") + 1], str(rpm), k)

    # ---------------------------------------------------------------- one active run, stop, status
    def test_duplicate_start_refused_while_running(self):
        self.assertTrue(self.call("start", preset="a2a-discovery-5m", by="se1")["ok"])
        r = self.call("start", preset="embeddings-10m", by="approver1")
        self.assertFalse(r["ok"]); self.assertIn("already active", r["error"])
        self.assertEqual(len(self.calls()), 1)

    def test_stop_is_graceful_then_archives_and_records_who(self):
        self.call("start", preset="a2a-discovery-5m", by="se1")
        r = self.call("stop", by="owner1")
        self.assertTrue(r["ok"] and r["stopped"]); self.assertTrue(r["archive"].startswith("archived"))
        self.assertEqual(self.calls(), ["start 300 --only pa_a2a_card --max-rpm 2", "stop", "archive"])
        st = self.state()
        self.assertIsNone(st["current"])
        h = st["history"][-1]
        self.assertEqual((h["preset"], h["by"], h["stopped_by"], h["outcome"]), ("a2a-discovery-5m", "se1", "owner1", "stopped"))
        r2 = self.call("stop", by="owner1")
        self.assertTrue(r2["ok"]); self.assertFalse(r2["stopped"]); self.assertEqual(len(self.calls()), 3)   # idempotent no-op

    def test_status_reports_container_current_and_presets(self):
        self.call("start", preset="rag-retrieval-10m", by="se1")
        s = self.call("status")
        self.assertTrue(s["container"]["running"]); self.assertEqual(s["current"]["preset"], "rag-retrieval-10m")
        self.assertEqual(sorted(s["presets"]), ["a2a-discovery-5m", "ai-data-path-15m", "embeddings-10m", "llm-chat-sample", "rag-retrieval-10m"])
        os.remove(f"{self.d}/running"); open(f"{self.d}/exited", "w").close()    # ended by duration
        s2 = self.call("status")
        self.assertFalse(s2["container"]["running"]); self.assertTrue(s2["current"]["ended"])
        self.assertEqual(self.calls("docker")[-1], "inspect -f {{.State.Running}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.ExitCode}}|{{json .Config.Cmd}} ap-trafficgen")

    # ---------------------------------------------------------------- limits
    def test_start_rate_limit(self):
        for i in range(6):
            self.assertTrue(self.call("start", preset="a2a-discovery-5m", by="se1")["ok"], i)
            self.call("stop", by="se1")
        r = self.call("start", preset="a2a-discovery-5m", by="se1")
        self.assertIn("at most 6 runs per hour", r["error"])

    def test_mutation_rate_limit(self):
        for i in range(20):
            self.call("stop", by="se1")
        self.assertIn("rate limit", self.call("stop", by="se1")["error"])

    def test_concurrent_operation_refused(self):
        with open(f"{self.d}/broker.lock", "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            r = self.call("start", preset="a2a-discovery-5m", by="se1")
        self.assertIn("in progress", r["error"]); self.assertEqual(self.calls(), [])

    def test_log_has_no_request_secrets(self):
        self.call("start", preset="a2a-discovery-5m", by="se1")
        log = open(f"{self.d}/broker.log").read()
        self.assertIn("EXEC start preset=a2a-discovery-5m by='se1'", log)
        self.assertNotIn(KEY.decode(), log); self.assertNotIn('"mac"', log)


if __name__ == "__main__":
    unittest.main()
