"""MCP Streamable-HTTP client adapter for Project A (standard library only, Python 3.9+).

Wire-compatible with the official MCP Python SDK (mcp 2.3.0) that Project A's servers and Autopilot's own validator use
(app/autopilot/mcpclient.py, validate.py): the same two client modes, verified against a real SDK server in
tests/test_sdk_compat.py.

  legacy    (2025-xx handshake): POST initialize with an offered protocolVersion -> server's negotiated version and an
            Mcp-Session-Id -> POST notifications/initialized -> requests carry Mcp-Session-Id + MCP-Protocol-Version ->
            DELETE the session at the end. On BIG-IP_C the policy iRule takes method and tool from the JSON-RPC body for
            these requests (Content-Length is always sent; chunked bodies would be refused with 411).
  stateless (2026-07-28): no handshake; every request carries Mcp-Protocol-Version, Mcp-Method and (for tools/call)
            Mcp-Name headers that match the body, plus io.modelcontextprotocol/* _meta, as Autopilot's validator sends.

Responses may be JSON or an SSE stream (text/event-stream); both are parsed. HTTP refusals are classified from the known
BIG-IP AI Security policy messages; response bodies are never returned or logged.
"""
import json, random

import sim_transport

CLIENT_INFO = {"name": "f5-ai-workload-sim", "version": "3.0"}
HANDSHAKE_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")   # = mcp 2.3.0 HANDSHAKE_PROTOCOL_VERSIONS
STATELESS_VERSION = "2026-07-28"
OFFERED_VERSION = "2025-11-25"
ACCEPT = "application/json, text/event-stream"
POLICY_MESSAGES = (                     # BIG-IP_C irule_mcp_policy responses (packages.py) -> refusal class
    ("client certificate required", "no_identity"), ("unknown agent identity", "unknown_identity"),
    ("tool not permitted", "tool_denied"), ("rate limit exceeded", "rate_limited"),
    ("MCP method not permitted", "method_denied"), ("Content-Length required", "length_required"),
    ("cannot be identified", "ambiguous_tool"), ("batches are not permitted", "batch_refused"),
)


class McpHttpStatus(Exception):
    def __init__(self, status, refusal, method):
        super().__init__(f"{method} -> HTTP {status} ({refusal})")
        self.status, self.refusal, self.method = status, refusal, method


class McpProtocolError(Exception):
    pass


class McpRpcError(Exception):
    def __init__(self, code, method):
        super().__init__(f"{method} -> JSON-RPC error {code}")
        self.code, self.method = code, method


def classify_refusal(status, body):
    text = (body or b"")[:400].decode("utf-8", "replace")
    for needle, cls in POLICY_MESSAGES:
        if needle in text:
            return cls
    return {401: "unauthorized", 403: "forbidden", 429: "rate_limited", 404: "not_found"}.get(status, f"http_{status}")


def parse_body(headers, data, want_id):
    """JSON-RPC response object for `want_id` from a JSON or SSE body."""
    ctype = (headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype == "text/event-stream":
        msgs, buf = [], []
        for raw in data.decode("utf-8", "replace").splitlines() + [""]:
            if raw.startswith("data:"):
                buf.append(raw[5:].lstrip(" "))
            elif raw == "" and buf:
                try:
                    msgs.append(json.loads("\n".join(buf)))
                except ValueError:
                    pass
                buf = []
        for m in msgs:
            if isinstance(m, dict) and m.get("id") == want_id and ("result" in m or "error" in m):
                return m
        raise McpProtocolError("no JSON-RPC response for the request in the SSE stream")
    try:
        m = json.loads(data or b"null")
    except ValueError:
        raise McpProtocolError("response is not JSON")
    if isinstance(m, list):
        m = next((x for x in m if isinstance(x, dict) and x.get("id") == want_id), None)
    if not isinstance(m, dict) or m.get("id") != want_id:
        raise McpProtocolError("response id does not match the request")
    return m


class McpSession:
    def __init__(self, target, mode="legacy", allowed_tools=(), probe_tools=(), allowed_methods=None, client_cert=True,
                 timeout=15, environ=None, request_id_prefix="sim"):
        if mode not in ("legacy", "stateless"):
            raise ValueError("mode must be legacy or stateless")
        self.t, self.mode, self.client_cert, self.timeout, self.environ = target, mode, client_cert, timeout, environ
        self.allowed_tools, self.probe_tools = set(allowed_tools), set(probe_tools)
        self.allowed_methods = set(allowed_methods) if allowed_methods else None
        self.session_id = None
        self.protocol_version = STATELESS_VERSION if mode == "stateless" else None
        self.server_info = None
        self.requests = 0
        self._id = random.randint(1, 10 ** 6)
        self._rid = request_id_prefix

    # ------------------------------------------------------------------ wire
    def _headers(self, method=None, tool=None):
        h = {"Content-Type": "application/json", "Accept": ACCEPT, "User-Agent": "f5-ai-workload-sim/3.0",
             "X-F5-Lab-Synthetic": "true", "X-Request-ID": f"{self._rid}-{random.getrandbits(48):012x}"}
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            h["MCP-Protocol-Version"] = self.protocol_version
        if self.mode == "stateless" and method:
            h["Mcp-Method"] = method
            if tool:
                h["Mcp-Name"] = tool
        return h

    def _meta(self):
        return {"io.modelcontextprotocol/protocolVersion": STATELESS_VERSION, "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
                "io.modelcontextprotocol/clientCapabilities": {}}

    def _check_method(self, method):
        if self.allowed_methods is not None and method not in self.allowed_methods:
            raise PermissionError(f"MCP method {method} is not an allowed operation in this environment")

    def _post(self, method, params, notification=False, tool=None):
        self._check_method(method)
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            self._id += 1; msg["id"] = self._id
        st, hd, data, ms, _ = sim_transport.request(self.t, "POST", self._path(), msg, self._headers(method, tool), self.timeout,
                                                    client_cert=self.client_cert, environ=self.environ)
        self.requests += 1
        if st in (502, 503, 504):
            raise ConnectionError(f"{method} -> {st}")
        if notification:
            if st not in (200, 202, 204):
                raise McpHttpStatus(st, classify_refusal(st, data), method)
            return None, hd
        if st != 200:
            raise McpHttpStatus(st, classify_refusal(st, data), method)
        m = parse_body(hd, data, msg["id"])
        if "error" in m:
            raise McpRpcError((m.get("error") or {}).get("code"), method)
        return m.get("result"), hd

    def _path(self):
        u = self.t["url"]
        rest = u.split("://", 1)[1]
        return "/" + rest.split("/", 1)[1] if "/" in rest else "/"

    # ------------------------------------------------------------------ protocol
    def open(self):
        if self.mode == "stateless":
            return self
        res, hd = self._post("initialize", {"protocolVersion": OFFERED_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO})
        v = (res or {}).get("protocolVersion")
        if v not in HANDSHAKE_VERSIONS:
            raise McpProtocolError(f"server negotiated unsupported protocol version {v!r}")
        self.protocol_version = v
        self.server_info = {k: (res.get("serverInfo") or {}).get(k) for k in ("name", "version")}
        self.session_id = hd.get("mcp-session-id")
        self._post("notifications/initialized", {}, notification=True)
        return self

    def list_tools(self):
        params = {"_meta": self._meta()} if self.mode == "stateless" else {}
        res, _ = self._post("tools/list", params)
        return sorted(t.get("name") for t in (res or {}).get("tools", []) if isinstance(t, dict))

    def call_tool(self, name, arguments=None, probe=False):
        allowed = self.probe_tools if probe else self.allowed_tools
        if name not in allowed:
            raise PermissionError(f"tool {name} is not {'an approved deny probe' if probe else 'an allowed read-only tool'}")
        params = {"name": name, "arguments": arguments or {}}
        if self.mode == "stateless":
            params["_meta"] = self._meta()
        res, _ = self._post("tools/call", params, tool=name)
        res = res or {}
        sc = res.get("structuredContent")
        if isinstance(sc, dict) and set(sc) == {"result"}:
            sc = sc["result"]
        replica = sc.get("replica") if isinstance(sc, dict) else None
        if replica is None:
            for c in res.get("content") or []:
                if isinstance(c, dict) and c.get("type") == "text":
                    try:
                        replica = json.loads(c.get("text") or "").get("replica")
                    except (ValueError, AttributeError):
                        pass
        return {"is_error": bool(res.get("isError")), "replica": replica if isinstance(replica, str) else None}

    def close(self):
        if self.mode != "legacy" or not self.session_id:
            return
        try:
            sim_transport.request(self.t, "DELETE", self._path(), None, self._headers(), self.timeout,
                                  client_cert=self.client_cert, environ=self.environ)
            self.requests += 1
        except Exception:                                     # noqa: BLE001 - best effort; the server expires sessions
            pass
        self.session_id = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()
