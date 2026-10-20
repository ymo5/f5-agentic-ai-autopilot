"""ap-trafficgen container artifacts, offline: the entrypoint only allows bounded runs with fixed paths, the Dockerfile copies
only the engine + Project A profile, the host control script applies the isolation flags and a reliable stop, and the
release build is deterministic. No image is built and no container is run."""
import hashlib, os, re, subprocess, sys, tempfile, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CONT = os.path.join(ROOT, "container")
sys.path.insert(0, CONT)
import trafficgen_entry as entry                         # noqa: E402

BUILD_ROOT = os.path.expanduser("~/f5-ai-integration-dev/build-verify")


def read(name):
    with open(os.path.join(CONT, name)) as f:
        return f.read()


def code(name):
    """The file without comment lines (scans for forbidden commands must not match prose)."""
    return "\n".join(l for l in read(name).splitlines() if not l.lstrip().startswith("#"))


class Entrypoint(unittest.TestCase):
    def test_bounded_modes_only(self):
        with self.assertRaises(SystemExit):
            entry.build([], {})                                          # no continuous mode
        for bad in (["--duration", "59"], ["--duration", "3601"], ["--duration", "60", "--once"], ["--once", "--max-rpm", "0"],
                    ["--once", "--only", "pa_embed;touch /x"], ["--once", "--only", "../x"], ["--once", "--config", "/tmp/x.json"]):
            with self.assertRaises(SystemExit, msg=bad):
                entry.build(bad, {})

    def test_duration_limit_is_capped_at_7200(self):
        argv, _ = entry.build(["--duration", "7200"], {"TG_MAX_DURATION_S": "99999"})
        self.assertIn("7200", argv)
        with self.assertRaises(SystemExit):
            entry.build(["--duration", "7201"], {"TG_MAX_DURATION_S": "99999"})
        with self.assertRaises(SystemExit):
            entry.build(["--duration", "1800"], {"TG_MAX_DURATION_S": "900"})

    def test_fixed_profile_instance_status_and_stop_file(self):
        argv, backstop = entry.build(["--duration", "600", "--only", "pa_embed,pa_a2a_card", "--max-rpm", "4"], {})
        self.assertEqual(argv[2:13], [entry.ENGINE, "--config", entry.PROFILE, "--instance", "pa_lab", "--status-file", "/state/status.json",
                                      "--stop-file", "/state/STOP", "--duration", "600"])
        self.assertEqual(argv[13:], ["--only", "pa_embed,pa_a2a_card", "--max-rpm", "4"])
        self.assertEqual(backstop, 600 + entry.BACKSTOP_GRACE_S)
        self.assertIsNone(entry.build(["--dry-run"], {})[1])
        self.assertEqual(entry.build(["--once"], {})[1], 1800 + entry.BACKSTOP_GRACE_S)

    def test_main_arms_the_backstop_before_exec(self):
        calls = []
        with mock.patch.object(sys, "argv", ["e", "--duration", "120"]), \
                mock.patch.object(entry.signal, "alarm", lambda s: calls.append(("alarm", s))), \
                mock.patch.object(entry.os, "execv", lambda p, a: calls.append(("exec", a[3]))):
            entry.main()
        self.assertEqual(calls, [("alarm", 240), ("exec", "--config")])


class Dockerfile(unittest.TestCase):
    def test_minimal_offline_image(self):
        d = code("Dockerfile")
        copies = re.findall(r"^COPY (.+)$", d, re.M)
        srcs = sorted(x for c in copies for x in c.split()[:-1])
        self.assertEqual(srcs, sorted(["container/trafficgen_entry.py", "simulator/f5_ai_workload_sim.py", "simulator/mcp_adapter.py",
                                       "simulator/profiles/project-a.json", "simulator/sim_profiles.py", "simulator/sim_transport.py"]))
        for banned in ("ADD ", "pip ", "curl", "wget", "apt-get", "apt ", "sim-config.json", "control-center", "pki", ".pem", ".key", "s3.env"):
            self.assertNotIn(banned, d, banned)
        self.assertRegex(d, r"(?m)^USER 65534:65534$")
        self.assertIn('ENTRYPOINT ["python", "-B", "/opt/trafficgen/trafficgen_entry.py"]', d)


class ControlScript(unittest.TestCase):
    def setUp(self):
        self.s = read("ap-trafficgen")

    def test_syntax(self):
        subprocess.run(["bash", "-n", os.path.join(CONT, "ap-trafficgen")], check=True)
        for f in ("install.sh", "rollback.sh", "build.sh"):
            subprocess.run(["bash", "-n", os.path.join(CONT, f)], check=True)

    def test_isolation_flags(self):
        run = self.s[self.s.index("docker run -d"):self.s.index('echo "started')]
        for flag in ("--read-only", "--user 65534:65534", "--cap-drop ALL", "--security-opt no-new-privileges", "--memory 256m",
                     "--memory-swap 256m", "--cpus 0.5", "--pids-limit 64", "--restart no", "--stop-timeout 30", "--init",
                     "--log-opt max-size=10m", "-v $ETC/ca.pem:/run/tg/ca.pem:ro", "-v $STATE:/state:rw", "--network host"):
            self.assertIn(flag, run, flag)
        self.assertEqual(len(re.findall(r" -v ", run)), 2, "only the state volume and the CA certificate are mounted")
        for banned in ("--privileged", "docker.sock", "--pid host", "--restart always", "--restart unless-stopped", "--cap-add", "/opt/aplab/pki"):
            self.assertNotIn(banned, self.s, banned)

    def test_bounded_start_and_reliable_stop(self):
        self.assertIn('[ "$1" -ge 60 ] && [ "$1" -le "$MAX" ]', self.s)
        self.assertIn('running && die "already running', self.s)                         # one generator at a time
        stop = self.s[self.s.index("  stop)"):self.s.index("  status)")]
        self.assertLess(stop.index("touch $STATE/STOP"), stop.index("docker stop -t 30"))   # graceful first, then SIGTERM/SIGKILL
        self.assertIn("IMAGE=$(cat $ETC/image", self.s); self.assertIn("sha256:*", self.s)   # pinned image ID only

    def test_install_and_rollback_guards(self):
        i, r = code("install.sh"), code("rollback.sh")
        self.assertIn("--network none --pull=false", i)
        self.assertIn("68cd67758515a2e371cde94b3512c60e57367f5fbfc8b06c87dac5d95844b316", i)
        self.assertIn('grep -q "PRIVATE KEY" $LAB_CA', i)
        self.assertIn('diff "$BK/containers.before" "$BK/containers.after"', i)
        self.assertNotRegex(i, r"\$BIN (start|once)")                                       # install never starts a run
        for s in (i, r):
            self.assertNotRegex(s, r"rm -r|rm -f|compose|systemctl|/mgmt/|tmsh")
        self.assertIn('mv $p "$BK/"', r); self.assertIn('docker rmi "$TAG"', r)


class Build(unittest.TestCase):
    def test_deterministic_and_minimal(self):
        os.makedirs(BUILD_ROOT, exist_ok=True)
        a, b = tempfile.mkdtemp(prefix="tg-build-a-", dir=BUILD_ROOT), tempfile.mkdtemp(prefix="tg-build-b-", dir=BUILD_ROOT)
        for d in (a, b):
            subprocess.run(["bash", os.path.join(CONT, "build.sh"), d], check=True, capture_output=True)
        ids = [open(os.path.join(d, "BUILD_ID")).read().strip() for d in (a, b)]
        self.assertEqual(ids[0], ids[1])
        tgz = [hashlib.sha256(open(os.path.join(d, "ap-trafficgen-context.tgz"), "rb").read()).hexdigest() for d in (a, b)]
        self.assertEqual(tgz[0], tgz[1])
        files = sorted(l.split()[1] for l in open(os.path.join(a, "CONTEXT.sha256")))
        self.assertEqual(files, sorted(["container/Dockerfile", "container/trafficgen_entry.py", "simulator/f5_ai_workload_sim.py",
                                        "simulator/mcp_adapter.py", "simulator/profiles/project-a.json", "simulator/sim_profiles.py",
                                        "simulator/sim_transport.py"]))
        p = subprocess.run(["bash", os.path.join(CONT, "build.sh"), a], capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0); self.assertIn("not empty", p.stdout)


if __name__ == "__main__":
    unittest.main()
