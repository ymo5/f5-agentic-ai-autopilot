"""Deterministic offline mock services for Project A (standard library only, Python 3.9+). Local 127.0.0.1 only.

MockMcpServer  MCP Streamable HTTP backend with the Project A tool sets (risk-scoring / fraud-intel). Legacy sessions
               (initialize -> Mcp-Session-Id -> notifications/initialized -> requests -> DELETE) and stateless
               2026-07-28 requests (Mcp-Method / Mcp-Name headers must match the body). JSON or SSE response framing.
               The risk server does NOT implement freeze_account, like the real one.
MockBigIp      TLS front that emulates BIG-IP_C's client-SSL profile (client certificate optional or required) and the
               Autopilot irule_mcp_policy semantics: identity = client-certificate CN, per-identity tool allow-list,
               per-identity per-minute rate limit, Content-Length required for legacy bodies, method/tool taken from the
               body (legacy) or the headers (2026-07-28), the iRule's response texts. `fail_open=True` forwards
               everything (to prove the simulator detects a policy that does not deny).
MockAgentA     GET /api/alerts, POST /api/investigate (front-door or bypass card_url).
MockQdrant     GET /collections/{c}, POST /collections/{c}/points/query; any other request is recorded and refused.
MockOllama     POST /api/embed, POST /v1/chat/completions (Ollama / OpenAI-compatible shapes); anything else refused.
MockA2aCard    TLS front serving /.well-known/agent-card.json (server TLS only; records whether a client certificate was sent).
Every mock records the requests it saw, for assertions.
"""
import http.client, json, socket, ssl, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HANDSHAKE = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
RISK_TOOLS = {"score_transaction": {"readOnlyHint": True}, "model_info": {"readOnlyHint": True}}
INTEL_TOOLS = {n: {"readOnlyHint": True} for n in ("list_open_alerts", "get_alert", "get_account_profile", "get_recent_transactions",
                                                    "search_fraud_patterns", "get_case_document")}
INTEL_TOOLS.update({"freeze_account": {"destructiveHint": True}, "export_customer_data": {"openWorldHint": True}})


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start(server):
    t = threading.Thread(target=server.serve_forever, daemon=True); t.start()
    return server


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code, body=b"", ctype="application/json", headers=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


# --------------------------------------------------------------------------------------------- MCP backend
class MockMcpServer:
    def __init__(self, kind="risk", replica="risk-scoring-1", framing="json", server_version="2025-11-25", force_version=None):
        self.kind, self.replica, self.framing, self.server_version = kind, replica, framing, server_version
        self.force_version = force_version            # tests: answer initialize with this version regardless of the offer
        self.tools = RISK_TOOLS if kind == "risk" else INTEL_TOOLS
        self.sessions = {}; self.seen = []; self.lock = threading.Lock()
        mock = self

        class H(_Base):
            def do_POST(self):
                raw = self._body()
                try:
                    msg = json.loads(raw)
                except ValueError:
                    return self._send(400, {"error": "bad json"})
                h = {k.lower(): v for k, v in self.headers.items()}
                with mock.lock:
                    mock.seen.append({"verb": "POST", "method": msg.get("method"), "headers": h, "tool": (msg.get("params") or {}).get("name")})
                if "text/event-stream" not in h.get("accept", "") or "application/json" not in h.get("accept", ""):
                    return self._send(406, {"error": "Accept must include application/json and text/event-stream"})
                return mock.handle(self, msg, h)

            def do_DELETE(self):
                h = {k.lower(): v for k, v in self.headers.items()}
                with mock.lock:
                    mock.seen.append({"verb": "DELETE", "method": None, "headers": h, "tool": None})
                    ok = mock.sessions.pop(h.get("mcp-session-id"), None) is not None
                self._send(200 if ok else 404, b"")

        self.httpd = _start(_Server(("127.0.0.1", 0), H))
        self.port = self.httpd.server_address[1]

    def reply(self, handler, obj, headers=None):
        if self.framing == "sse":
            body = f"event: message\ndata: {json.dumps(obj)}\n\n".encode()
            return handler._send(200, body, "text/event-stream", headers)
        return handler._send(200, obj, "application/json", headers)

    def handle(self, handler, msg, h):
        m, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if h.get("mcp-protocol-version") == "2026-07-28":                     # stateless revision
            if h.get("mcp-method") != m or (m == "tools/call" and h.get("mcp-name") != params.get("name")):
                return self.reply(handler, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32020, "message": "header mismatch"}})
            if (params.get("_meta") or {}).get("io.modelcontextprotocol/protocolVersion") != "2026-07-28":
                return self.reply(handler, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "missing _meta"}})
            return self.dispatch(handler, m, mid, params, {})
        if m == "initialize":
            want = params.get("protocolVersion")
            v = want if want in HANDSHAKE and want <= self.server_version else self.server_version
            v = self.force_version or v
            sid = uuid.uuid4().hex
            with self.lock:
                self.sessions[sid] = {"version": v, "initialized": False}
            return self.reply(handler, {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": v, "capabilities": {"tools": {}},
                              "serverInfo": {"name": "risk-scoring" if self.kind == "risk" else "fraud-intel", "version": "test"}}},
                              {"Mcp-Session-Id": sid})
        sid = h.get("mcp-session-id")
        s = self.sessions.get(sid)
        if not s:
            return handler._send(404 if sid else 400, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "session required"}})
        if h.get("mcp-protocol-version") not in (None, s["version"]):
            return handler._send(400, {"error": "protocol version header mismatch"})
        if m == "notifications/initialized":
            s["initialized"] = True
            return handler._send(202, b"")
        if not s["initialized"]:
            return handler._send(400, {"error": "not initialized"})
        return self.dispatch(handler, m, mid, params, {})

    def dispatch(self, handler, m, mid, params, headers):
        if m == "tools/list":
            tools = [{"name": n, "description": "test", "inputSchema": {"type": "object"}, "annotations": a} for n, a in self.tools.items()]
            return self.reply(handler, {"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}})
        if m == "tools/call":
            name = params.get("name")
            if name not in self.tools:
                return self.reply(handler, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"Unknown tool: {name}"}})
            sc = {"replica": self.replica, "tool": name, "model_version": "test"}
            return self.reply(handler, {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": json.dumps(sc)}],
                              "structuredContent": sc, "isError": False}})
        if m in ("ping", "server/discover"):
            return self.reply(handler, {"jsonrpc": "2.0", "id": mid, "result": {}})
        return self.reply(handler, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}})

    def calls(self, method=None):
        return [s for s in self.seen if method is None or s["method"] == method]

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()


# --------------------------------------------------------------------------------------------- BIG-IP front
class _TLSServer(_Server):
    def __init__(self, addr, handler, ctx):
        super().__init__(addr, handler); self.ctx = ctx

    def get_request(self):
        sock, addr = self.socket.accept()
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def finish_request(self, request, client_address):
        try:
            request.settimeout(5); request.do_handshake()
        except (ssl.SSLError, OSError):
            try: request.close()
            except OSError: pass
            return
        super().finish_request(request, client_address)


class MockBigIp:
    def __init__(self, pki, backend_ports, allow, rate_per_min=120, client_cert="optional", fail_open=False, server_cert=None):
        """backend_ports: list of backend MockMcpServer ports (round-robin; Mcp-Session-Id persistence)."""
        self.allow, self.rate, self.fail_open = allow, rate_per_min, fail_open
        self.backends = list(backend_ports); self.rr = 0; self.persist = {}
        self.counts = {}; self.decisions = []; self.lock = threading.Lock()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        cert = server_cert or pki.server
        ctx.load_cert_chain(cert[0], cert[1])
        ctx.load_verify_locations(pki.ca)
        ctx.verify_mode = ssl.CERT_REQUIRED if client_cert == "required" else ssl.CERT_OPTIONAL
        front = self

        class H(_Base):
            def _ident(self):
                pc = self.connection.getpeercert() if hasattr(self.connection, "getpeercert") else None
                for rdn in (pc or {}).get("subject", ()):
                    for k, v in rdn:
                        if k == "commonName":
                            return v
                return ""

            def _deny(self, code, text, branch, extra=None):
                with front.lock:
                    front.decisions.append({"status": code, "branch": branch})
                self._send(code, text.encode(), "text/plain", extra)

            def do_POST(self):
                return self.policy("POST")

            def do_DELETE(self):
                return self.policy("DELETE")

            def policy(self, verb):
                ident = self._ident()
                raw = self._body() if self.headers.get("Content-Length") else b""
                h = {k: v for k, v in self.headers.items()}
                if not front.fail_open:
                    if not ident:
                        return self._deny(401, "client certificate required", "no_identity")
                    if ident not in front.allow:
                        return self._deny(403, "unknown agent identity", "unknown_identity")
                    key = f"{ident}:{int(time.time() // 60)}"
                    with front.lock:
                        front.counts[key] = front.counts.get(key, 0) + 1; n = front.counts[key]
                    if n > front.rate:
                        return self._deny(429, "rate limit exceeded", "rate_limit", {"Retry-After": "60"})
                    allowed = front.allow[ident]
                    if verb == "POST":
                        if self.headers.get("Mcp-Protocol-Version") == "2026-07-28":
                            meth = self.headers.get("Mcp-Method", "")
                            if meth == "tools/call" and self.headers.get("Mcp-Name") not in allowed:
                                return self._deny(403, f"tool not permitted for {ident}", "tool_denied")
                            if meth == "":
                                return self._deny(400, "Mcp-Method header required", "no_method")
                            if meth not in ("server/discover", "tools/list", "ping", "tools/call"):
                                return self._deny(403, "MCP method not permitted", "method_denied")
                        else:
                            if self.headers.get("Content-Length") in (None, ""):
                                return self._deny(411, "Content-Length required for policy inspection", "length")
                            try:
                                msg = json.loads(raw)
                            except ValueError:
                                return self._deny(400, "exactly one JSON-RPC method required", "parse")
                            if isinstance(msg, list):
                                return self._deny(400, "JSON-RPC batches are not permitted", "batch")
                            m = msg.get("method")
                            if m == "tools/call":
                                if (msg.get("params") or {}).get("name") not in allowed:
                                    return self._deny(403, f"tool not permitted for {ident}", "tool_denied")
                            elif m not in ("initialize", "notifications/initialized", "notifications/cancelled", "ping", "tools/list"):
                                return self._deny(403, "MCP method not permitted", "method_denied")
                with front.lock:
                    front.decisions.append({"status": "forwarded", "identity": ident})
                    sid = self.headers.get("Mcp-Session-Id")
                    port = front.persist.get(sid) if sid else None
                    if port is None:
                        port = front.backends[front.rr % len(front.backends)]; front.rr += 1
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                fwd = {k: v for k, v in h.items() if k.lower() not in ("host", "connection")}
                fwd["X-Agent-Identity"] = ident
                c.request(verb, self.path, body=raw or None, headers=fwd)
                r = c.getresponse(); data = r.read()
                rh = {k: v for k, v in r.getheaders() if k.lower() in ("content-type", "mcp-session-id")}
                new_sid = r.getheader("Mcp-Session-Id")
                if new_sid:
                    with front.lock:
                        front.persist[new_sid] = port
                c.close()
                self._send(r.status, data, rh.pop("Content-Type", rh.pop("content-type", "application/json")), rh)

        self.httpd = _start(_TLSServer(("127.0.0.1", 0), H, ctx))
        self.port = self.httpd.server_address[1]
        self.address = f"127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()


# --------------------------------------------------------------------------------------------- Agent A, Qdrant
class MockAgentA:
    def __init__(self, card_host="agent-b.aplab.internal", investigations=None):
        self.card_host = card_host; self.seen = []
        self.investigations = investigations          # None -> /api/investigations is 404 (older Agent A)
        mock = self

        class H(_Base):
            def do_GET(self):
                mock.seen.append(("GET", self.path))
                if self.path.split("?")[0] == "/api/investigations" and mock.investigations is not None:
                    return self._send(200, mock.investigations)
                if self.path == "/api/alerts":
                    return self._send(200, [{"alert_id": "ALERT-9000"}, {"alert_id": "ALERT-9001"}, {"alert_id": "not-an-alert"}])
                if self.path == "/healthz":
                    return self._send(200, {"status": "ok"})
                self._send(404, {"error": "not found"})

            def do_POST(self):
                body = json.loads(self._body() or b"{}")
                mock.seen.append(("POST", self.path, body.get("alert_id")))
                if self.path != "/api/investigate":
                    return self._send(404, {"error": "not found"})
                self._send(200, {"id": "x", "alert_id": body.get("alert_id"), "state": "completed", "trace_id": "0" * 32,
                                 "card_url": f"https://{mock.card_host}/", "error": None,
                                 "result": {"assessment": {"decision": "escalate", "risk_level": "high"}, "replicas_used": ["risk-scoring-1", "risk-scoring-2"]}})

        self.httpd = _start(_Server(("127.0.0.1", 0), H))
        self.port = self.httpd.server_address[1]

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()


class MockQdrant:
    def __init__(self, collection="fraud_patterns", points=10, require_key=None):
        self.collection, self.points, self.require_key = collection, points, require_key
        self.seen = []
        mock = self

        class H(_Base):
            def _key_ok(self):
                return mock.require_key is None or self.headers.get("api-key") == mock.require_key

            def do_GET(self):
                mock.seen.append(("GET", self.path))
                if not self._key_ok():
                    return self._send(401, {"status": "unauthorized"})
                if self.path == f"/collections/{mock.collection}":
                    return self._send(200, {"result": {"status": "green", "points_count": mock.points,
                                                       "config": {"params": {"vectors": {"size": 768, "distance": "Cosine"}}}}, "status": "ok"})
                self._send(404, {"status": "not found"})

            def do_POST(self):
                body = json.loads(self._body() or b"{}")
                mock.seen.append(("POST", self.path, body))
                if not self._key_ok():
                    return self._send(401, {"status": "unauthorized"})
                if self.path == f"/collections/{mock.collection}/points/query":
                    seed = body.get("query"); lim = int(body.get("limit", 3))
                    pts = [{"id": i, "score": round(0.99 - i / 100, 3)} for i in range(1, mock.points + 1) if i != seed][:lim]
                    return self._send(200, {"result": {"points": pts}, "status": "ok"})
                self._send(403, {"status": "write or unknown operation refused by the mock"})

            def do_PUT(self):
                mock.seen.append(("PUT", self.path)); self._send(403, {"status": "refused"})

            def do_DELETE(self):
                mock.seen.append(("DELETE", self.path)); self._send(403, {"status": "refused"})

        self.httpd = _start(_Server(("127.0.0.1", 0), H))
        self.port = self.httpd.server_address[1]

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()


# --------------------------------------------------------------------------------------------- Ollama, A2A card
class MockOllama:
    def __init__(self, dims=768, status=200, models=("nomic-embed-text", "qwen2.5:3b")):
        self.dims, self.status, self.models = dims, status, set(models)
        self.seen = []
        mock = self

        class H(_Base):
            def do_POST(self):
                raw = self._body()
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    body = None
                mock.seen.append(("POST", self.path, body, {k.lower(): v for k, v in self.headers.items()}))
                if mock.status != 200:
                    return self._send(mock.status, {"error": "mock status"})
                if not isinstance(body, dict) or body.get("model") not in mock.models:
                    return self._send(404, {"error": "model not found"})
                if self.path == "/api/embed":
                    return self._send(200, {"model": body["model"], "embeddings": [[0.01] * mock.dims]})
                if self.path == "/v1/chat/completions":
                    n = min(int(body.get("max_tokens") or 700), 12)
                    return self._send(200, {"id": "chatcmpl-x", "object": "chat.completion", "model": body["model"],
                                            "choices": [{"index": 0, "message": {"role": "assistant", "content": "SECRET-ANSWER-TEXT " * 2},
                                                         "finish_reason": "stop" if n < int(body.get("max_tokens") or 700) else "length"}],
                                            "usage": {"prompt_tokens": 30, "completion_tokens": n, "total_tokens": 30 + n}})
                self._send(403, {"error": "operation refused by the mock"})

            def do_GET(self):
                mock.seen.append(("GET", self.path, None, {})); self._send(403, {"error": "refused"})

            def do_DELETE(self):
                mock.seen.append(("DELETE", self.path, None, {})); self._send(403, {"error": "refused"})

        self.httpd = _start(_Server(("127.0.0.1", 0), H))
        self.port = self.httpd.server_address[1]
        self.address = f"127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()


class MockA2aCard:
    def __init__(self, pki, card_host="agent-b.aplab.internal", skills=2):
        self.card_host, self.skills = card_host, skills
        self.seen = []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(pki.server[0], pki.server[1])
        ctx.load_verify_locations(pki.ca)
        ctx.verify_mode = ssl.CERT_OPTIONAL                      # records whether the client sent a certificate
        mock = self

        class H(_Base):
            def do_GET(self):
                pc = self.connection.getpeercert() if hasattr(self.connection, "getpeercert") else None
                mock.seen.append(("GET", self.path, bool(pc), self.headers.get("Host")))
                if self.path != "/.well-known/agent-card.json":
                    return self._send(404, {"error": "not found"})
                self._send(200, {"name": "Risk Assessment Agent", "version": "1.0",
                                 "supportedInterfaces": [{"url": f"https://{mock.card_host}/", "protocolBinding": "JSONRPC"}],
                                 "skills": [{"id": f"s{i}", "name": f"skill {i}"} for i in range(mock.skills)]})

            def do_POST(self):
                mock.seen.append(("POST", self.path, None, None)); self._send(403, {"error": "refused"})

        self.httpd = _start(_TLSServer(("127.0.0.1", 0), H, ctx))
        self.port = self.httpd.server_address[1]
        self.address = f"127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()
