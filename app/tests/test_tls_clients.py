"""Focused regressions for the httpx2 mTLS client-context defect."""
from __future__ import annotations

import asyncio
import datetime as dt
import http.server
import json
import pathlib
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _throwaway_pki() -> pathlib.Path:
    """Generate a throwaway CA plus two client identities for these tests (no repository or lab PKI is used)."""
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp(prefix="ap-test-pki-"))
    now = dt.datetime.now(dt.timezone.utc)

    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def write(name, k, cert):
        (d / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        if k is not None:
            (d / f"{name}.key").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                            serialization.NoEncryption()))

    ca_key = key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Autopilot test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
          .sign(ca_key, hashes.SHA256()))
    write("ca", None, ca)
    for cn in ("ap-validator", "ap-unauthorized"):
        k = key()
        c = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
             .issuer_name(ca_name).public_key(k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
             .sign(ca_key, hashes.SHA256()))
        write(cn, k, c)
    return d


PKI = _throwaway_pki()
CA = PKI / "ca.pem"
VALIDATOR_CERT = PKI / "ap-validator.pem"
VALIDATOR_KEY = PKI / "ap-validator.key"
UNAUTHORIZED_CERT = PKI / "ap-unauthorized.pem"
UNAUTHORIZED_KEY = PKI / "ap-unauthorized.key"


@pytest.fixture()
def tls_modules(monkeypatch):
    """Reload the two modules after environment changes without touching live services."""
    import autopilot.validate as validate
    import services.agent_b.mcp_tools as mcp_tools

    monkeypatch.setattr(validate, "CA", str(CA))
    return validate, mcp_tools


def test_validator_context_preserves_verification_and_loads_valid_identity(tls_modules):
    validate, _ = tls_modules
    ctx = validate._tls_context((str(VALIDATOR_CERT), str(VALIDATOR_KEY)))
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.get_ca_certs()


def test_validator_rejects_invalid_ca_before_opening_a_client(tls_modules, monkeypatch, tmp_path):
    validate, _ = tls_modules
    bad_ca = tmp_path / "not-a-ca.pem"
    bad_ca.write_text("not a certificate")
    monkeypatch.setattr(validate, "CA", str(bad_ca))
    with pytest.raises((ssl.SSLError, OSError, ValueError)):
        validate._tls_context()


def test_agent_b_requires_certificate_and_key_as_a_pair(tls_modules, monkeypatch):
    _, mcp_tools = tls_modules
    monkeypatch.setenv("MCP_CLIENT_CERT", str(VALIDATOR_CERT))
    monkeypatch.delenv("MCP_CLIENT_KEY", raising=False)
    monkeypatch.setenv("MCP_CA_BUNDLE", str(CA))
    with pytest.raises(ValueError, match="certificate and key"):
        mcp_tools._tls_context()


def test_agent_b_passes_context_not_cert_tuple_to_httpx2(tls_modules, monkeypatch):
    _, mcp_tools = tls_modules
    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(mcp_tools.httpx2, "AsyncClient", FakeClient)
    monkeypatch.setenv("MCP_CA_BUNDLE", str(CA))
    monkeypatch.setenv("MCP_CLIENT_CERT", str(VALIDATOR_CERT))
    monkeypatch.setenv("MCP_CLIENT_KEY", str(VALIDATOR_KEY))
    mcp_tools._http_client()
    assert isinstance(captured["verify"], ssl.SSLContext)
    assert "cert" not in captured
    assert captured["verify"].verify_mode == ssl.CERT_REQUIRED
    assert captured["verify"].check_hostname is True


def test_validator_can_construct_each_allowed_and_wrong_identity_context(tls_modules):
    validate, _ = tls_modules
    allowed = validate._tls_context((str(VALIDATOR_CERT), str(VALIDATOR_KEY)))
    wrong_identity = validate._tls_context((str(UNAUTHORIZED_CERT), str(UNAUTHORIZED_KEY)))
    assert allowed.verify_mode == wrong_identity.verify_mode == ssl.CERT_REQUIRED
    assert allowed.check_hostname and wrong_identity.check_hostname


def _key(path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))
    return key


def _cert(path, key, issuer_key, issuer_cert, common_name, san=None, *, expired=False, client=False):
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_cert.subject if issuer_cert else name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=3))
               .not_valid_after(now - dt.timedelta(days=2) if expired else now + dt.timedelta(days=2)))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(x) for x in san]), critical=False)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]),
                                    critical=False)
    cert = builder.sign(issuer_key, hashes.SHA256())
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def _pki(tmp_path, *, server_name="localhost", client_expired=False):
    ca_key = _key(tmp_path / "ca.key")
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TLS test CA")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
               .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server_key = _key(tmp_path / "server.key")
    server_cert = _cert(tmp_path / "server.pem", server_key, ca_key, ca_cert, "server", [server_name])
    client_key = _key(tmp_path / "client.key")
    client_cert = _cert(tmp_path / "client.pem", client_key, ca_key, ca_cert, "ap-validator", client=True, expired=client_expired)
    unauthorized_key = _key(tmp_path / "unauthorized.key")
    unauthorized_cert = _cert(tmp_path / "unauthorized.pem", unauthorized_key, ca_key, ca_cert, "ap-unauthorized", client=True)
    return {"ca": ca_path, "server": tmp_path / "server.pem", "server_key": tmp_path / "server.key",
            "client": tmp_path / "client.pem", "client_key": tmp_path / "client.key",
            "unauthorized": tmp_path / "unauthorized.pem", "unauthorized_key": tmp_path / "unauthorized.key",
            "server_cert": server_cert, "client_cert": client_cert}


class _MCPHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _json(self, body, status=200, session=True):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if session:
            self.send_header("Mcp-Session-Id", "tls-session")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        peer = self.connection.getpeercert()
        cn = next((v for r in peer.get("subject", ()) for k, v in r if k == "commonName"), "")
        if cn != "ap-validator":
            self._json({"error": "client identity not authorized"}, 403, session=False)
            return
        n = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(n) or b"{}")
        method = req.get("method")
        if method == "initialize":
            self._json({"jsonrpc": "2.0", "id": req.get("id"), "result": {
                "protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                "serverInfo": {"name": "tls-test-mcp", "version": "1"}}})
        elif method == "notifications/initialized":
            self._json({}, 202, session=False)
        elif method == "tools/list":
            self._json({"jsonrpc": "2.0", "id": req.get("id"), "result": {
                "tools": [{"name": "model_info", "description": "test", "inputSchema": {"type": "object"}}]}})
        elif method == "tools/call":
            self._json({"jsonrpc": "2.0", "id": req.get("id"), "result": {
                "content": [{"type": "text", "text": json.dumps({"replica": "tls-test"})}],
                "structuredContent": {"replica": "tls-test"}, "isError": False}})
        else:
            self._json({"jsonrpc": "2.0", "id": req.get("id"), "result": {}})


class _TLSServer:
    def __init__(self, pki):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MCPHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_cert_chain(pki["server"], pki["server_key"])
        ctx.load_verify_locations(cafile=pki["ca"])
        ctx.set_alpn_protocols(["http/1.1"])
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"https://localhost:{self.httpd.server_address[1]}/mcp"

    def __exit__(self, *_args):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def test_real_agent_b_and_validator_clients_complete_mtls_mcp_over_http11(tmp_path, monkeypatch, tls_modules):
    validate, mcp_tools = tls_modules
    pki = _pki(tmp_path)
    monkeypatch.setenv("MCP_CA_BUNDLE", str(pki["ca"]))
    monkeypatch.setenv("MCP_CLIENT_CERT", str(pki["client"]))
    monkeypatch.setenv("MCP_CLIENT_KEY", str(pki["client_key"]))
    with _TLSServer(pki) as url:
        async def agent_b_call():
            async with mcp_tools.mcp_session(url) as client:
                result = await client.call_tool("model_info", {})
                return mcp_tools.result_data(result)

        assert asyncio.run(agent_b_call())["replica"] == "tls-test"
        validate.CA = str(pki["ca"])
        assert asyncio.run(validate._raw_mcp(url, "model_info", (str(pki["client"]), str(pki["client_key"])))) == 200
        http = mcp_tools._http_client()
        assert asyncio.run(http.get(url)).http_version == "HTTP/1.1"
        asyncio.run(http.aclose())


@pytest.mark.parametrize("case", ("invalid_ca", "wrong_hostname", "missing_client", "expired_client", "unauthorized_identity"))
def test_real_mtls_rejections_are_fail_closed(tmp_path, monkeypatch, tls_modules, case):
    validate, mcp_tools = tls_modules
    server_name = "wrong.example" if case == "wrong_hostname" else "localhost"
    pki = _pki(tmp_path, server_name=server_name, client_expired=case == "expired_client")
    validate.CA = str(pki["ca"])
    if case == "invalid_ca":
        bad_ca = tmp_path / "bad-ca.pem"
        bad_ca.write_text("not a CA")
        validate.CA = str(bad_ca)
    elif case == "wrong_hostname":
        # The server is still reached at localhost; its certificate SAN is intentionally different.
        pass
    elif case == "missing_client":
        monkeypatch.delenv("MCP_CLIENT_CERT", raising=False)
        monkeypatch.delenv("MCP_CLIENT_KEY", raising=False)
    elif case == "unauthorized_identity":
        monkeypatch.setenv("MCP_CLIENT_CERT", str(pki["unauthorized"]))
        monkeypatch.setenv("MCP_CLIENT_KEY", str(pki["unauthorized_key"]))
    else:
        monkeypatch.setenv("MCP_CLIENT_CERT", str(pki["client"]))
        monkeypatch.setenv("MCP_CLIENT_KEY", str(pki["client_key"]))
    monkeypatch.setenv("MCP_CA_BUNDLE", str(pki["ca"]))
    with _TLSServer(pki) as url:
        if case == "unauthorized_identity":
            assert asyncio.run(validate._raw_mcp(url, "model_info", (str(pki["unauthorized"]), str(pki["unauthorized_key"])))) == 403
        else:
            cert = None if case == "missing_client" else (str(pki["client"]), str(pki["client_key"]))
            assert asyncio.run(validate._raw_mcp(url, "model_info", cert)) == -1

