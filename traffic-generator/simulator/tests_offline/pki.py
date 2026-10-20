"""Throwaway test PKI, generated with the openssl CLI into a temporary directory at test time.

Nothing here is a lab credential and nothing is written to the repository: the directory is created with mkdtemp and
removed by cleanup(). Certificates: a test CA, one server certificate covering the Project A front-door names (plus a
second, unrelated name for hostname-mismatch tests), and client certificates whose subject CN is the identity the mock
BIG-IP policy reads (ap-traffic-sim = allowed simulator identity, ap-unauthorized = unknown identity).
"""
import os, shutil, subprocess, tempfile

FRONT_DOORS = ("mcp-risk.aplab.internal", "mcp-intel.aplab.internal", "agent-b.aplab.internal")


def _run(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class TestPKI:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="f5sim-test-pki-")
        d = self.dir
        _run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=f5sim offline test CA",
             "-keyout", "ca.key", "-out", "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)
        self.ca = os.path.join(d, "ca.pem")
        self.server = self._leaf("server", "mcp-risk.aplab.internal", san=",".join(f"DNS:{n}" for n in FRONT_DOORS), server=True)
        self.other_server = self._leaf("other", "unrelated.example.test", san="DNS:unrelated.example.test", server=True)
        self.client = self._leaf("client", "ap-traffic-sim")
        self.unknown_client = self._leaf("unknown", "ap-unauthorized")
        # a second, untrusted CA: its certificates must be refused
        _run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=untrusted CA",
             "-keyout", "rogue-ca.key", "-out", "rogue-ca.pem", cwd=d)
        self.rogue_ca = os.path.join(d, "rogue-ca.pem")

    def _leaf(self, name, cn, san=None, server=False):
        d = self.dir
        ext = os.path.join(d, f"{name}.ext")
        with open(ext, "w") as f:
            f.write("basicConstraints=CA:FALSE\n")
            f.write(f"extendedKeyUsage={'serverAuth' if server else 'clientAuth'}\n")
            if san:
                f.write(f"subjectAltName={san}\n")
        _run("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={cn}", "-keyout", f"{name}.key", "-out", f"{name}.csr", cwd=d)
        _run("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "2",
             "-extfile", ext, "-out", f"{name}.pem", cwd=d)
        return (os.path.join(d, f"{name}.pem"), os.path.join(d, f"{name}.key"))

    def env(self, client=True, unknown=False):
        e = {"F5SIM_PA_CA_FILE": self.ca}
        if client:
            c = self.unknown_client if unknown else self.client
            e.update(F5SIM_PA_CLIENT_CERT=c[0], F5SIM_PA_CLIENT_KEY=c[1])
        return e

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)
