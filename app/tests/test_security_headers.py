"""Offline HTTPS-readiness: security headers on every response; HSTS and Secure cookies only over HTTPS."""
from __future__ import annotations

PW = "correct-horse-battery-staple"


def test_security_headers_on_http(ctx):
    r = ctx.viewer.get("/api/me")
    for k, v in (("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer")):
        assert r.headers.get(k) == v
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"] and "camera=()" in r.headers["Permissions-Policy"]
    assert "Strict-Transport-Security" not in r.headers                      # never on plain HTTP
    assert "X-Frame-Options" in ctx.anon.get("/").headers and "X-Frame-Options" in ctx.anon.get("/api/state").headers


def test_cookies_not_secure_on_http_and_secure_on_https(ctx):
    from fastapi.testclient import TestClient
    from autopilot import web
    r = TestClient(web.app).post("/api/login", json={"username": "viewer1", "password": PW})
    assert r.status_code == 200 and "secure" not in r.headers.get("set-cookie", "").lower()
    s = TestClient(web.app, base_url="https://testserver")
    r = s.post("/api/login", json={"username": "viewer1", "password": PW})
    cookies = r.headers.get_list("set-cookie")
    assert r.status_code == 200 and cookies and all("secure" in c.lower() for c in cookies)
    assert r.headers.get("Strict-Transport-Security") == "max-age=31536000"


def test_forwarded_proto_trusted_only_when_enabled(ctx, monkeypatch):
    from fastapi.testclient import TestClient
    from autopilot import web
    c = TestClient(web.app)
    assert "Strict-Transport-Security" not in c.get("/healthz", headers={"X-Forwarded-Proto": "https"}).headers
    monkeypatch.setattr(web, "TRUST_PROXY_PROTO", True)
    assert c.get("/healthz", headers={"X-Forwarded-Proto": "https"}).headers.get("Strict-Transport-Security") == "max-age=31536000"


def test_server_kwargs_plain_http_by_default_and_refuses_half_tls(ctx, tmp_path):
    import pytest
    from autopilot import web
    assert web.server_kwargs({"BIND_HOST": "127.0.0.1", "BIND_PORT": "8000"}) == {"host": "127.0.0.1", "port": 8000}
    with pytest.raises(SystemExit):
        web.server_kwargs({"TLS_CERTFILE": str(tmp_path / "c.pem")})            # key missing: never a silent HTTP fallback
    with pytest.raises(SystemExit):
        web.server_kwargs({"TLS_CERTFILE": str(tmp_path / "c.pem"), "TLS_KEYFILE": str(tmp_path / "k.pem")})   # files missing


def test_app_serves_https_with_secure_cookies_and_hsts_on_loopback(ctx, tmp_path):
    """Real uvicorn + TLS on 127.0.0.1 with a throwaway self-signed certificate (no external network)."""
    import shutil
    import socket
    import subprocess
    import threading
    import time

    import httpx
    import pytest
    import uvicorn
    from autopilot import web
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-days", "1",
                    "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(crt)], check=True, capture_output=True)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    kw = web.server_kwargs({"BIND_HOST": "127.0.0.1", "BIND_PORT": str(port), "TLS_CERTFILE": str(crt), "TLS_KEYFILE": str(key)})
    server = uvicorn.Server(uvicorn.Config(web.app, log_level="warning", **kw))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        import ssl
        with httpx.Client(base_url=f"https://127.0.0.1:{port}", verify=ssl.create_default_context(cafile=str(crt))) as c:
            r = c.post("/api/login", json={"username": "viewer1", "password": PW})
            assert r.status_code == 200 and all("secure" in x.lower() for x in r.headers.get_list("set-cookie"))
            assert r.headers.get("strict-transport-security") == "max-age=31536000"
            assert c.get("/api/me").json()["role"] == "viewer"
    finally:
        server.should_exit = True
        t.join(timeout=5)
