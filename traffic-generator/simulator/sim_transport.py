"""HTTP(S) transport for environment-profile targets (standard library only, Python 3.9+).

* Connects only to the target's pinned address (IPv4:port). The address must be in the active environment's allow-list
  and must not be a known backend behind BIG-IP (sim_profiles.FORBIDDEN_DIRECT); both are re-checked on every request.
* HTTPS is always verified: the lab CA (path from an environment variable), hostname verification against the
  certificate name (sent as SNI and Host while the TCP connection goes to the pinned VIP address), TLS 1.2 minimum.
  There is no "unverified" code path in this module.
* mTLS: the client certificate and key are loaded from files named by environment variables. They can be left out for
  a request on purpose (the unauthenticated security probe), never added implicitly.
* Bodies are bounded; nothing here logs request or response content.
"""
import http.client, json, os, socket, ssl, time

import sim_profiles

_ALLOWED = set()
_ENV = None


class TargetRefused(ValueError):
    pass


class CredentialMissing(RuntimeError):
    """TLS material or credentials named by the profile are not available on this host."""


def configure(env):
    global _ALLOWED, _ENV
    _ALLOWED = set(sim_profiles.approved(env))
    _ENV = env


def check_target(t):
    a = t.get("address")
    if a in sim_profiles.FORBIDDEN_DIRECT:
        raise TargetRefused(f"{a} is a backend behind BIG-IP ({sim_profiles.FORBIDDEN_DIRECT[a]}); direct access would bypass BIG-IP and is refused")
    if a not in _ALLOWED:
        raise TargetRefused(f"destination {a} is not in the {_ENV or '(no environment)'} allow-list")
    return t


def _file(environ, var, what):
    if not var:
        raise CredentialMissing(f"{what}: no environment variable configured")
    p = environ.get(var)
    if not p:
        raise CredentialMissing(f"{what}: {var} is not set")
    if not os.path.isfile(p):
        raise CredentialMissing(f"{what}: {var} does not point to a readable file")
    return p


def tls_context(tls, client_cert=True, environ=None):
    env = os.environ if environ is None else environ
    if not tls.get("verify", True):
        raise TargetRefused("TLS verification cannot be disabled for profile targets")
    ctx = ssl.create_default_context(cafile=_file(env, tls.get("ca_file_env"), "lab CA"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if client_cert and tls.get("cert_file_env"):
        ctx.load_cert_chain(certfile=_file(env, tls["cert_file_env"], "client certificate"),
                            keyfile=_file(env, tls.get("key_file_env"), "client key"))
    return ctx


class _PinnedHTTPS(http.client.HTTPSConnection):
    """TCP to the pinned VIP address, TLS SNI + certificate verification against the front-door name."""
    def __init__(self, host, port, server_name, context, timeout):
        super().__init__(host, port, timeout=timeout, context=context)
        self._server_name = server_name

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._server_name)


def connection(t, timeout=15, client_cert=True, environ=None):
    check_target(t)
    if t["scheme"] == "https":
        tls = t.get("tls") or {}
        ctx = tls_context(tls, client_cert=client_cert, environ=environ)
        return _PinnedHTTPS(t["connect_host"], t["connect_port"], tls.get("server_name") or t["connect_host"], ctx, timeout)
    return http.client.HTTPConnection(t["connect_host"], t["connect_port"], timeout=timeout)


def host_header(t):
    tls = t.get("tls") or {}
    name = tls.get("server_name") or t["connect_host"]
    default = 443 if t["scheme"] == "https" else 80
    return name if t["connect_port"] == default else f"{name}:{t['connect_port']}"


def request(t, method, path, body=None, headers=None, timeout=15, max_bytes=1 << 20, client_cert=True, environ=None):
    """One request on a new connection -> (status, {header: value} lower-cased, payload[:max_bytes], elapsed_ms, ttfb_ms)."""
    conn = connection(t, timeout, client_cert, environ)
    h = {"Host": host_header(t), **(headers or {})}
    if body is not None and not isinstance(body, bytes):
        body = json.dumps(body, separators=(",", ":")).encode()
    if body is not None:
        h.setdefault("Content-Length", str(len(body)))   # explicit: the BIG-IP policy refuses bodies without it (411)
    t0 = time.perf_counter()
    try:
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse(); ttfb = (time.perf_counter() - t0) * 1000
        data = r.read(max_bytes)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data, round((time.perf_counter() - t0) * 1000, 1), round(ttfb, 1)
    finally:
        conn.close()
