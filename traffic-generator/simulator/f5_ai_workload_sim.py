#!/usr/bin/env python3
"""F5 AI lab workload simulator: continuous, bounded, read-only, real traffic (v2, unified config).

Generates genuine application traffic through the lab's BIG-IP VIPs so the AI Data Delivery and AI Security
dashboards stay populated. It never changes configuration, never stops services, never writes data and only
uses approved read-only MCP tools, read-only S3 objects, vector queries and fixed, non-sensitive questions.

One config file (sim-config.json) describes every workload and the instance (host) that runs it. Each workload has
its own interval (with jitter) and an hourly cap; a global per-minute budget caps each instance. Results go to a
status file, to stdout (journal / log file) and to the existing telemetry collector as `sim_workload` events
(classes, counts, sizes and timings only: no prompts, answers, bodies, credentials or session ids).

Result classes: ok | expected_denial (intentional, synthetic 403/429 security probe) | unexpected | unavailable
(backend unreachable / 5xx; the workload backs off) | error (simulator-side exception).

usage: f5_ai_workload_sim.py --config sim-config.json --instance aiclient|mac
                             [--dry-run | --once | --duration SECONDS] [--only w1,w2] [--status-file PATH]
"""
import argparse, errno, hashlib, http.client, json, os, random, re, shutil, signal, socket, ssl, subprocess, sys, threading, time, urllib.parse, uuid

STOP = threading.Event()
for _sig in (signal.SIGINT, signal.SIGTERM):
    signal.signal(_sig, lambda *_: STOP.set())

# Destinations the simulator may ever contact (host:port). Anything else is refused at startup.
ALLOWED = {
    "10.1.10.130:8001", "10.1.10.131:8001", "10.1.10.132:8001", "10.1.10.133:8001", "10.1.10.135:8001",  # MCP VIPs
    "10.1.10.134:8001",          # AI_SSE_VIP
    "10.1.10.100:8333",          # S3_VIP
    "10.1.10.110:8501",          # CHATBOT_VIP (RAG chatbot, Streamlit)
    "10.1.10.120:8000",          # VECTOR_VIP
    "127.0.0.1:9464", "10.1.10.10:9464", "192.0.2.50:9464",  # telemetry collector
    "127.0.0.1:11434",           # Ollama (local to the host running the agent/inference workloads)
}
READ_ONLY_TOOLS = {"get_vector_db_status"}          # tools the simulator may execute
DENY_PROBE_TOOL = "get_lab_info"                    # read-only tool the security policy denies (403 expected)
UA = "f5-ai-workload-sim/2.0"
SYN = {"User-Agent": UA, "X-F5-Lab-Synthetic": "true"}   # marks every simulator request as synthetic lab traffic
MCP_H = {**SYN, "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-03-26"}
CLASSES = ("ok", "expected_denial", "unexpected", "unavailable", "error")
# The dashboards' simulator table understands ok | unexpected | error; intentional probes are ok with a 4xx status.
TEL_OUTCOME = {"ok": "ok", "expected_denial": "ok", "unexpected": "unexpected", "unavailable": "error", "error": "error"}
# Numeric result fields that may be logged / sent (never free text from a backend).
METRIC_KEYS = ("bytes", "objects", "mbps", "ttfb_ms", "first_event_ms", "last_event_ms", "events", "ttft_ms", "server_ttft_ms",
               "gen_ms", "prompt_tokens", "generated_tokens", "tokens_per_s", "results", "embed_ms", "query_ms", "sources",
               "answer_chars", "tool_calls", "tool_selections", "discoveries", "denied_calls", "llm_calls", "blocked_calls",
               "tools_listed", "mcp_requests", "replicas_used", "dims", "skills")
# Active allow-list. Legacy runs (sim-config.json = Project B) use ALLOWED unchanged; an environment profile replaces it with
# that environment's code-pinned list (sim_profiles.APPROVED) before any workload is constructed.
ACTIVE = {"env": "project-b", "allowed": ALLOWED}


def ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log(**kv):
    print(json.dumps({"ts": ts(), **kv}, separators=(",", ":")), flush=True)


def check_url(url):
    u = urllib.parse.urlsplit(url)
    if u.username or u.password or u.scheme not in ("http", "https"):
        raise ValueError(f"refused URL scheme/credentials: {u.scheme}")
    hp = f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"
    if hp not in ACTIVE["allowed"]:
        raise ValueError(f"destination {hp} is not in the simulator allowlist")
    return u


def _conn(u, timeout):
    return (http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ssl._create_unverified_context())
            if u.scheme == "https" else http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout))


def http_req(url, method="GET", body=None, headers=None, timeout=10, max_bytes=1 << 20):
    """One request on a new connection. Returns (status, bytes, elapsed_ms, ttfb_ms, payload[:max_bytes])."""
    u = check_url(url); conn = _conn(u, timeout)
    t0 = time.perf_counter()
    try:
        conn.request(method, (u.path or "/") + (("?" + u.query) if u.query else ""), body=body, headers={**SYN, **(headers or {})})
        r = conn.getresponse(); ttfb = (time.perf_counter() - t0) * 1000
        data = r.read(max_bytes)
        return r.status, len(data), round((time.perf_counter() - t0) * 1000, 1), round(ttfb, 1), data
    finally:
        conn.close()


def http_lines(url, method="GET", body=None, headers=None, timeout=15, max_bytes=1 << 20):
    """Streaming request. Returns (status, ttfb_ms, elapsed_ms, [(ms_since_start, line_bytes)...]); bounded by bytes and time."""
    u = check_url(url); conn = _conn(u, timeout)
    t0 = time.perf_counter(); lines = []; total = 0
    try:
        conn.request(method, (u.path or "/") + (("?" + u.query) if u.query else ""), body=body, headers={**SYN, **(headers or {})})
        r = conn.getresponse(); ttfb = round((time.perf_counter() - t0) * 1000, 1)
        while total < max_bytes and time.perf_counter() - t0 < timeout and not STOP.is_set():
            line = r.readline(65536)
            if not line:
                break
            total += len(line); lines.append((round((time.perf_counter() - t0) * 1000, 1), line))
        return r.status, ttfb, round((time.perf_counter() - t0) * 1000, 1), lines
    finally:
        conn.close()


NET_ERRNOS = {errno.ECONNREFUSED, errno.ECONNRESET, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT, errno.EHOSTDOWN}


class Unavailable(Exception):
    """Backend unreachable or returned 5xx: counted as `unavailable` and the workload backs off."""


def _is_unavailable(e):
    if isinstance(e, (Unavailable, ConnectionError, TimeoutError, socket.timeout, http.client.RemoteDisconnected)):
        return True
    if isinstance(e, OSError) and e.errno in NET_ERRNOS:
        return True
    return type(e).__name__ in {"EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError", "ConnectionClosedError",
                                "ConnectionError", "ConnectTimeout", "ReadTimeout"}   # botocore / requests (agent.py)


def R(outcome, detail, status=None, cost=1, ms=None, **metrics):
    return {"outcome": outcome, "detail": detail, "status": status, "cost": cost, "ms": ms,
            "m": {k: v for k, v in metrics.items() if k in METRIC_KEYS and v is not None}}


class Telemetry:
    """Fail-open sender of sim_workload events to the existing collector."""
    def __init__(self, url, host):
        self.url, self.host = url, host
        if url: check_url(url)

    def post(self, ev):
        if not self.url:
            return
        try:
            http_req(self.url, "POST", json.dumps(ev).encode(), {"Content-Type": "application/json"}, timeout=2)
        except Exception:
            pass

    def send(self, workload, res):
        self.post({"event_type": "sim_workload", "source": f"workload-sim@{self.host}", "service": "simulator", "tool": workload,
                   "outcome": TEL_OUTCOME[res["outcome"]], "request_id": str(uuid.uuid4()), "duration_ms": res["ms"],
                   "status_code": res["status"], "attributes": {"synthetic": True, "result_class": res["outcome"], **res["m"]}})


def make_s3(endpoint, auth=None):
    """auth=None: legacy behaviour (boto3 default credential chain = the RAG app's own credentials on AI-CLIENT).
    auth={"access_key_id": ENV, "secret_access_key": ENV[, "ca_file_env": ENV]}: explicit credentials read from the named
    environment variables (environment profiles). Missing variables refuse the workload; there is no anonymous fallback."""
    import boto3; from botocore.config import Config
    check_url(endpoint)
    kw = {}
    if auth is not None:
        ak, sk = os.environ.get(auth.get("access_key_id") or ""), os.environ.get(auth.get("secret_access_key") or "")
        if not ak or not sk:
            raise RuntimeError("S3 credentials not set: " + ", ".join(v for v in (auth.get("access_key_id"), auth.get("secret_access_key")) if v))
        kw = {"aws_access_key_id": ak, "aws_secret_access_key": sk}
        if endpoint.startswith("https"):
            kw["verify"] = os.environ.get(auth.get("ca_file_env") or "") or True
    return boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}, connect_timeout=5, read_timeout=30,
                                      user_agent_extra="f5-ai-workload-sim/2.0"), **kw)


# ------------------------------------------------------------------ workloads
class Workload:
    name = "base"
    MAX_BACKOFF = 1800

    def __init__(self, cfg, ctx):
        self.cfg, self.ctx = cfg, ctx
        if cfg.get("_name"):                       # environment profiles: workload name differs from its kind
            self.name = cfg["_name"]
        self.interval = float(cfg["interval_s"]); self.jitter = float(cfg.get("jitter", 0.2)); self.cap = int(cfg.get("max_per_hour", 60))
        if not (0 <= self.jitter <= 0.5 and self.interval >= 10 and 1 <= self.cap <= 120):
            raise ValueError(f"{self.name}: interval_s >= 10, jitter 0..0.5, max_per_hour 1..120 required")
        self.next_at = time.monotonic() + random.uniform(2, min(30, self.interval))   # spread first runs
        self.history = []                                                              # monotonic start times (last hour)
        self.fails = 0                                                                 # consecutive `unavailable` results

    def destinations(self):
        return [u for u in [self.cfg.get("url"), self.cfg.get("endpoint")] + list(self.cfg.get("urls", [])) if u]

    def due(self, now):
        self.history = [t for t in self.history if now - t < 3600]
        return now >= self.next_at and len(self.history) < self.cap

    def schedule(self, now):
        self.history.append(now)
        self.next_at = now + self.interval * random.uniform(1 - self.jitter, 1 + self.jitter)

    def backoff(self, now, unavailable):
        """Exponential back-off while the backend is unavailable (never faster than the normal interval)."""
        self.fails = self.fails + 1 if unavailable else 0
        if unavailable:
            self.next_at = now + min(self.MAX_BACKOFF, max(self.interval, 60) * 2 ** min(self.fails - 1, 5))

    def run(self):
        """Return R(...)."""
        raise NotImplementedError

    def deferred(self):
        """(reason, requests_sent) if this run must be skipped now, else None. Only profile workloads with an activity
        guard (defer_while_investigating) ever defer."""
        return None

    def attribution(self):
        """{destination name: {address, bigip_object, via_bigip}} for the status file (BIG-IP virtual server attribution).
        Only environment-profile workloads have resolved targets; legacy workloads return {}."""
        return {dn: {"address": t["address"], "bigip_object": t.get("bigip_object"), "via_bigip": t.get("via_bigip")}
                for dn, t in (self.cfg.get("targets") or {}).items()}


def mcp_call(url, method, tool=None, timeout=10):
    params = {"name": tool, "arguments": {}} if method == "tools/call" else {}
    body = json.dumps({"jsonrpc": "2.0", "id": random.randint(1, 10**9), "method": method, "params": params}).encode()
    return http_req(url, "POST", body, {**MCP_H, "X-Request-ID": "sim-" + uuid.uuid4().hex[:12]}, timeout=timeout)


def _5xx(st, what):
    if st in (502, 503, 504):
        raise Unavailable(f"{what} -> {st}")


class McpDelivery(Workload):
    name = "mcp_delivery"
    def run(self):
        url = random.choice(self.cfg["urls"])
        method, tool = random.choice([("tools/list", None), ("tools/call", "get_vector_db_status")])
        st, n, ms, ttfb, data = mcp_call(url, method, tool); _5xx(st, method)
        ok = st == 200 and b'"result"' in data
        return R("ok" if ok else "unexpected", f"{urllib.parse.urlsplit(url).hostname} {method} -> {st}", st, 1, ms, bytes=n, ttfb_ms=ttfb)


class McpAuthz(Workload):
    """Allowed calls on the protected VIP; a low-volume, intentional denial probe (read-only tool, 403 expected)."""
    name = "mcp_authz"
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx); self.deny_every = int(cfg.get("deny_every_n", 10))
        self.n = self.deny_every - 1 if cfg.get("probe_first") else 0     # probe_first: bounded tests exercise the probe immediately
        if self.deny_every < 5: raise ValueError("mcp_authz: deny_every_n must be >= 5")
    def run(self):
        self.n += 1
        if self.n % self.deny_every == 0:
            st, _, ms, _, _ = mcp_call(self.cfg["url"], "tools/call", DENY_PROBE_TOOL); _5xx(st, "deny probe")
            return R("expected_denial" if st == 403 else "unexpected", f"synthetic deny probe {DENY_PROBE_TOOL} -> {st} (403 expected)", st, 1, ms)
        method, tool = random.choice([("tools/list", None), ("tools/call", "get_vector_db_status")])
        st, _, ms, _, _ = mcp_call(self.cfg["url"], method, tool); _5xx(st, method)
        return R("ok" if st == 200 else "unexpected", f"{method} -> {st}", st, 1, ms)


class McpRateBurst(Workload):
    """Bounded burst: limit+1 calls inside one window -> exactly one 429 expected. Runs rarely (default 30 min)."""
    name = "mcp_rate_burst"
    def run(self):
        n = int(self.cfg.get("limit", 5)) + 1; codes = []; t0 = time.perf_counter()
        if n > 8: raise ValueError("mcp_rate_burst: limit too high for a low-frequency probe")
        for _ in range(n):
            if STOP.is_set(): break
            codes.append(mcp_call(self.cfg["url"], "tools/call", "get_vector_db_status")[0]); time.sleep(1.5)
        if codes and all(c in (502, 503, 504) for c in codes): raise Unavailable(f"codes={codes}")
        ok = codes == [200] * (n - 1) + [429]
        return R("expected_denial" if ok else "unexpected", f"synthetic rate burst codes={codes} (one 429 expected)",
                 429 if 429 in codes else codes[-1] if codes else None, len(codes), round((time.perf_counter() - t0) * 1000, 1))


class Sse(Workload):
    """One finite SSE stream through AI_SSE_VIP; measures headers, first/last event and event count (never content)."""
    name = "sse_stream"
    def run(self):
        st, ttfb, ms, lines = http_lines(self.cfg["url"], headers={"Accept": "text/event-stream"}, timeout=15); _5xx(st, "sse")
        ev = [t for t, l in lines if l.startswith(b"event:")]
        exp = int(self.cfg.get("expected_events", 3))
        return R("ok" if st == 200 and len(ev) == exp else "unexpected", f"{len(ev)} events ({exp} expected)", st, 1, ms,
                 bytes=sum(len(l) for _, l in lines), events=len(ev), ttfb_ms=ttfb,
                 first_event_ms=ev[0] if ev else None, last_event_ms=ev[-1] if ev else None)


class S3RagRead(Workload):
    """HEAD + GET of the RAG source document through S3_VIP with the RAG app's own credentials (never logged)."""
    name = "s3_rag_read"
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx); self.s3 = None; check_url(cfg["endpoint"])
    def run(self):
        self.s3 = self.s3 or make_s3(self.cfg["endpoint"], self.cfg.get("_s3_auth"))
        t0 = time.perf_counter()
        h = self.s3.head_object(Bucket=self.cfg["bucket"], Key=self.cfg["key"])
        t1 = time.perf_counter()
        body = self.s3.get_object(Bucket=self.cfg["bucket"], Key=self.cfg["key"])["Body"].read()
        t2 = time.perf_counter(); ms = round((t2 - t0) * 1000, 1)
        ok = len(body) == h["ContentLength"] and (not self.cfg.get("sha256") or hashlib.sha256(body).hexdigest() == self.cfg["sha256"])
        return R("ok" if ok else "unexpected", f"{len(body)} B{' sha256 ok' if ok and self.cfg.get('sha256') else ''}", 200, 2, ms,
                 bytes=len(body), objects=1, mbps=round(len(body) / 1e6 / max(t2 - t1, 1e-6), 2))


class TrainingDataRead(Workload):
    """Training-style data delivery: GETs of approved test-dataset shards (walked in order, wrapping = repeated epochs)
    and optional model-artifact objects through S3_VIP. Read-only: one listing of the approved prefix, then GETs.
    Objects are read and discarded; they are never deserialized (pickle shards are never loaded)."""
    name = "training_data_read"
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx); self.s3 = None; self.keys = None; self.pos = 0; check_url(cfg["endpoint"])
        self.per_run = int(cfg.get("objects_per_run", 3)); self.max_obj = int(cfg.get("max_object_bytes", 8 << 20))
        if not (1 <= self.per_run <= 10) or not cfg.get("dataset_prefixes"):
            raise ValueError("training_data_read: dataset_prefixes required, objects_per_run 1..10")
    def _list(self):
        keys = []
        for pre in self.cfg["dataset_prefixes"]:
            for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.cfg["bucket"], Prefix=pre, PaginationConfig={"MaxItems": 5000}):
                keys += [o["Key"] for o in page.get("Contents", []) if 0 < o["Size"] <= self.max_obj]
        return sorted(keys)
    def run(self):
        self.s3 = self.s3 or make_s3(self.cfg["endpoint"], self.cfg.get("_s3_auth"))
        cost = 0
        if self.keys is None:
            self.keys = self._list(); cost += 1
            self.pos = random.randrange(len(self.keys)) if self.keys else 0
        if not self.keys:
            return R("unexpected", "no objects under the approved dataset prefixes", None, cost, None)
        batch = [self.keys[(self.pos + i) % len(self.keys)] for i in range(self.per_run)]; self.pos = (self.pos + self.per_run) % len(self.keys)
        batch += list(self.cfg.get("artifact_keys", []))
        total = 0; bad = 0; n = 0; t0 = time.perf_counter()
        for k in batch:
            if STOP.is_set(): break
            o = self.s3.get_object(Bucket=self.cfg["bucket"], Key=k); b = o["Body"].read(self.max_obj + 1)
            n += 1; total += len(b); bad += len(b) != o["ContentLength"]
        s = time.perf_counter() - t0
        return R("ok" if n == len(batch) and not bad else "unexpected", f"{n} objects, {total} B" + (f", {bad} size mismatch" if bad else ""),
                 200, cost + n, round(s * 1000, 1), bytes=total, objects=n, mbps=round(total / 1e6 / max(s, 1e-6), 2))


class VectorQuery(Workload):
    """Embedding + similarity query through VECTOR_VIP, as chatbot.py does (fixed, non-sensitive questions)."""
    name = "vector_query"
    QUESTIONS = ["What is model risk management?", "How should banks validate models?", "Who is responsible for model governance?",
                 "How should banks monitor model performance?", "What are model limitations?"]
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx); self.col = None; self.emb = None
        check_url(f"http://{cfg['host']}:{cfg['port']}/")
    def destinations(self):
        return [f"http://{self.cfg['host']}:{self.cfg['port']}/"]
    def run(self):
        if self.col is None:
            import chromadb; from sentence_transformers import SentenceTransformer
            self.emb = self.emb or SentenceTransformer(self.cfg.get("model", "all-MiniLM-L6-v2"), device="cpu")
            self.col = chromadb.HttpClient(host=self.cfg["host"], port=int(self.cfg["port"])).get_collection(self.cfg["collection"])
        t0 = time.perf_counter()
        v = self.emb.encode(random.choice(self.QUESTIONS), normalize_embeddings=True)
        t1 = time.perf_counter()
        r = self.col.query(query_embeddings=[v.tolist()], n_results=3)
        t2 = time.perf_counter()
        n = len(r["ids"][0])
        return R("ok" if n == 3 else "unexpected", f"{n} results", 200, 1, round((t2 - t0) * 1000, 1),
                 results=n, embed_ms=round((t1 - t0) * 1000, 1), query_ms=round((t2 - t1) * 1000, 1))


class OllamaInference(Workload):
    """One short generation directly against local Ollama (no inference VIP exists: NOT through BIG-IP).
    Alternates stream / non-stream. Token counts and durations are Ollama's own fields; ttft_ms is measured by the
    client on streamed responses (first non-empty token); server_ttft_ms = load + prompt-eval time reported by Ollama."""
    name = "ollama_inference"
    PROMPTS = ["In one sentence, what does a load balancer do?", "In one sentence, what is a vector database?"]
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx); self.flip = False
    def run(self):
        self.flip = not self.flip; stream = self.flip
        body = json.dumps({"model": self.cfg["model"], "prompt": random.choice(self.PROMPTS), "stream": stream,
                           "options": {"num_predict": min(64, int(self.cfg.get("num_predict", 32))), "temperature": 0}}).encode()
        ttft = None
        if stream:
            st, ttfb, ms, lines = http_lines(self.cfg["url"], "POST", body, {"Content-Type": "application/json"}, timeout=120)
            _5xx(st, "generate")
            chunks = []
            for t, l in lines:
                try: c = json.loads(l)
                except ValueError: continue
                chunks.append(c)
                if ttft is None and c.get("response"): ttft = t
            last = chunks[-1] if chunks else {}
        else:
            st, _, ms, ttfb, data = http_req(self.cfg["url"], "POST", body, {"Content-Type": "application/json"}, timeout=120)
            _5xx(st, "generate")
            try: last = json.loads(data) if st == 200 else {}
            except ValueError: last = {}
        ns = lambda k: round(last[k] / 1e6, 1) if isinstance(last.get(k), int) else None
        server_ttft = round((last.get("load_duration", 0) + last.get("prompt_eval_duration", 0)) / 1e6, 1) if "prompt_eval_duration" in last else None
        gen = last.get("eval_count"); gen_ms = ns("eval_duration")
        m = dict(ttft_ms=ttft, server_ttft_ms=server_ttft, gen_ms=gen_ms, prompt_tokens=last.get("prompt_eval_count"), generated_tokens=gen,
                 tokens_per_s=round(gen / (gen_ms / 1000), 1) if gen and gen_ms else None, ttfb_ms=ttfb)
        tel = self.ctx["telemetry"]
        if st == 200 and last.get("done"):
            tel.post({"event_type": "llm_inference", "source": f"workload-sim@{tel.host}", "service": "ollama", "tool": self.cfg["model"],
                      "outcome": "success", "request_id": str(uuid.uuid4()), "duration_ms": ms, "status_code": st,
                      "attributes": {"synthetic": True, "prompt_tokens": last.get("prompt_eval_count"), "generated_tokens": gen,
                                     "eval_duration_ns": last.get("eval_duration"), "total_duration_ns": last.get("total_duration"),
                                     "ttft_ms": ttft, "server_ttft_ms": server_ttft, "streaming": stream}})
        return R("ok" if st == 200 and last.get("done") else "unexpected", f"{'stream' if stream else 'non-stream'} {gen} tokens", st, 1, ms, **m)


class AgentRun(Workload):
    """A complete agent run with agent.py: MCP tools/list (discovery) via the protected VIP, LLM tool selection on local
    Ollama, tool execution through BIG-IP, final answer. Fixed questions; agent output is discarded.
    The simulator guards agent.py's MCP client: only READ_ONLY_TOOLS and the deny probe can be sent; anything else the LLM
    picks is blocked client-side and the run is flagged unexpected. Every MCP request carries the agent's X-Request-ID
    and run id (correlated with BIG-IP's MCP RESPONSE corr= field by the collector)."""
    name = "agent_run"
    QUESTIONS = ["Is the vector database healthy?", "Is the vector database healthy? Check it twice to confirm.",
                 "Check whether the vector database is healthy, and also show me the lab configuration."]
    def _agent(self):
        if self.cfg["agent_dir"] not in sys.path: sys.path.insert(0, self.cfg["agent_dir"])
        import agent  # noqa: E402  (agent.py emits its own agent/MCP/LLM telemetry)
        check_url(agent.MCP); check_url(agent.OLLAMA); check_url(self.cfg["telemetry_url"])
        return agent
    def destinations(self):
        a = self._agent(); return [a.MCP, a.OLLAMA, self.cfg["telemetry_url"]]
    def run(self):
        import builtins, contextlib, io
        os.environ["F5_TELEMETRY_URL"] = self.cfg["telemetry_url"]
        agent = self._agent()
        seen = []; blocked = []
        real_emit, real_mcp, real_input = agent.emit, agent.mcp_request, builtins.input
        def emit(event_type, **f):                       # observe agent events locally (types/outcomes only), then forward
            seen.append((event_type, f.get("outcome"), f.get("request_id") if event_type == "agent_run" else None))
            real_emit(event_type, **f)
        def guarded(method, params=None):
            if method == "tools/call" and (params or {}).get("name") not in READ_ONLY_TOOLS | {DENY_PROBE_TOOL}:
                blocked.append(1)
                return {"isError": True, "message": "tool not permitted by the lab simulator"}
            return real_mcp(method, params)
        q = random.choice(self.QUESTIONS); t0 = time.perf_counter()
        agent.emit, agent.mcp_request, builtins.input = emit, guarded, (lambda *_: q)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                agent.main()
        finally:
            agent.emit, agent.mcp_request, builtins.input = real_emit, real_mcp, real_input
        ms = round((time.perf_counter() - t0) * 1000, 1)
        cnt = lambda et, oc=None: sum(1 for e, o, _ in seen if e == et and (oc is None or o == oc))
        run_ids = {r for e, _, r in seen if e == "agent_run" and r}
        final = [o for e, o, _ in seen if e == "agent_run" and o != "started"]
        denied = cnt("mcp_tool_call", "deny")
        m = dict(discoveries=cnt("mcp_discovery", "success"), tool_selections=cnt("agent_tool_selection"),
                 tool_calls=cnt("mcp_tool_call", "success"), denied_calls=denied, llm_calls=cnt("llm_inference", "success"), blocked_calls=len(blocked))
        ok = final == ["success"] and m["discoveries"] == 1 and not blocked
        detail = (f"run {next(iter(run_ids))[:8] if run_ids else '?'} {final[0] if final else 'no-end'}: {m['discoveries']} discovery, "
                  f"{m['tool_selections']} selected, {m['tool_calls']} executed, {denied} denied (synthetic, expected 403), {m['llm_calls']} LLM")
        return R("ok" if ok else "unexpected", detail, None, m["discoveries"] + m["tool_calls"] + denied + m["llm_calls"], ms, **m)


class RagChat(Workload):
    """Real RAG question answering through CHATBOT_VIP, driven like a user with the lab's existing headless-Chrome client
    (~/f5-ai-data-delivery/tools/chat_test.mjs: Streamlit UI -> embedding -> VECTOR_VIP retrieval -> Ollama answer).
    Fixed, non-sensitive questions; the client never prints the answer, and only counts/route/timing are kept."""
    name = "rag_chat"
    QUESTIONS = ["What does SR 26-2 say about model risk management?", "What does the Federal Reserve guidance say about model validation?",
                 "According to SR 26-2, who is responsible for model governance?"]
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx); check_url(cfg["url"])
        for k in ("node", "client"):
            if not os.path.isfile(cfg[k]): raise ValueError(f"rag_chat: {k} not found")
    def run(self):
        tmp = os.path.join(self.cfg["state_dir"], "chat-tmp"); os.makedirs(tmp, exist_ok=True)
        qi = random.randrange(len(self.QUESTIONS)); t0 = time.perf_counter()
        p = subprocess.Popen([self.cfg["node"], self.cfg["client"], self.cfg.get("mode", "RAG"), self.QUESTIONS[qi], self.cfg["url"]],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={**os.environ, "TMPDIR": tmp}, start_new_session=True)
        try:
            out, _ = p.communicate(timeout=int(self.cfg.get("timeout_s", 300)))
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); p.communicate()
            raise Unavailable("chat client timed out")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)       # headless Chrome profile dirs
        ms = round((time.perf_counter() - t0) * 1000, 1)
        try: r = json.loads(out.decode().strip().splitlines()[-1])
        except (ValueError, IndexError): return R("error", "chat client produced no result", None, 1, ms)
        n_src = len([s for s in (r.get("sources") or "").split(" | ") if s])
        if r.get("error"):
            err = str(r["error"])
            cls = "llm_unavailable" if "Ollama request failed" in err else "chat_input_not_found" if "chat input" in err else "app_error"
            if cls != "app_error": raise Unavailable(cls)
            return R("unexpected", f"q{qi} {cls}", None, 1, ms)
        ok = r.get("ok") and r.get("route") == "RAG retrieval" and n_src > 0
        return R("ok" if ok else "unexpected", f"q{qi} route={r.get('route') or '?'} {n_src} sources {r.get('answer_chars')} chars "
                 f"answer {r.get('wall_seconds')} s", None, 1, ms, sources=n_src, answer_chars=r.get("answer_chars"))


class Health(Workload):
    name = "health"
    def run(self):
        res = []; t0 = time.perf_counter()
        for u in self.cfg["urls"]:
            try: res.append(http_req(u, timeout=10)[0])
            except Exception: res.append(None)
        ok = all(s == 200 for s in res)
        return R("ok" if ok else "unexpected", f"statuses={res}", None, len(res), round((time.perf_counter() - t0) * 1000, 1))


# ------------------------------------------------------------------ environment-profile workloads (Project A)
# These use sim_transport (verified TLS, pinned addresses, optional mTLS) and mcp_adapter, imported lazily so the legacy
# single-file deployment keeps working without them. Their destinations come only from resolved profile targets.
def _pa_targets(cfg):
    import sim_transport
    ts_ = cfg.get("targets") or {}
    if not ts_:
        raise ValueError(f"{cfg.get('_name')}: no resolved targets (workload is not available in this environment)")
    for t in ts_.values():
        sim_transport.check_target(t)
    return ts_


def _target_urls(cfg):
    """Allow-list form (scheme://address/) of every target, for the start-up destination check."""
    return [f"{t['scheme']}://{t['address']}/" for t in (cfg.get("targets") or {}).values()]


def _mcp_unavailable(e):
    import mcp_adapter
    return isinstance(e, mcp_adapter.McpHttpStatus) and e.status in (502, 503, 504)


class McpSessionDelivery(Workload):
    """One MCP session per run on one BIG-IP_C MCP VIP (mTLS identity): initialize with protocol-version negotiation ->
    notifications/initialized -> tools/list -> one approved read-only tools/call -> session DELETE. The serving replica
    named in the tool result is recorded (load distribution evidence)."""
    name = "mcp_session"
    def destinations(self):
        return _target_urls(self.cfg)
    def run(self):
        import mcp_adapter
        targets = _pa_targets(self.cfg); ops = self.cfg.get("_ops") or {}
        dn = random.choice(sorted(targets)); tool = self.cfg["tools"][dn]
        s = mcp_adapter.McpSession(targets[dn], mode=self.cfg.get("protocol", "legacy"), allowed_tools=ops.get("mcp_tools", ()),
                                   allowed_methods=ops.get("mcp_methods"), timeout=float(self.cfg.get("timeout_s", 15)))
        t0 = time.perf_counter()
        try:
            s.open(); names = s.list_tools(); r = s.call_tool(tool, {})
        except mcp_adapter.McpHttpStatus as e:
            if e.status in (502, 503, 504): raise Unavailable(str(e))
            return R("unexpected", f"{dn} {e.method} -> {e.status} ({e.refusal})", e.status, max(1, s.requests),
                     round((time.perf_counter() - t0) * 1000, 1), mcp_requests=s.requests)
        finally:
            s.close()
        ms = round((time.perf_counter() - t0) * 1000, 1)
        ok = tool in names and not r["is_error"]
        return R("ok" if ok else "unexpected", f"{dn} mcp {s.protocol_version} tools/list {len(names)} tools/call {tool} "
                 f"{'ok' if ok else 'failed'}" + (f" replica={r['replica']}" if r["replica"] else ""), 200, s.requests, ms,
                 tools_listed=len(names), mcp_requests=s.requests)


class McpIdentityAuthz(Workload):
    """BIG-IP_C AI Security policy, observed from a client: allowed calls with the simulator identity; every Nth run a
    deny probe (a tool outside the identity's allow-list, sent to a VIP whose server does not implement it, so a policy
    that failed open still changes nothing) -> 403 expected; every Mth run an unauthenticated probe (no client
    certificate) -> TLS rejection or 401 expected."""
    name = "mcp_identity_authz"
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx); self.n = 0
        self.deny_every = int(cfg.get("deny_every_n", 5)); self.unauth_every = int(cfg.get("unauthenticated_every_n", 10))
        if self.deny_every < 3 or self.unauth_every < 3: raise ValueError(f"{self.name}: probe frequencies must be >= 3")
        if cfg.get("deny_probe_tool") not in (cfg.get("_ops") or {}).get("mcp_deny_probe_tools", []):
            raise ValueError(f"{self.name}: deny_probe_tool must be listed in allowed_operations.mcp_deny_probe_tools")
    def destinations(self):
        return _target_urls(self.cfg)
    def _session(self, t, client_cert=True):
        import mcp_adapter
        ops = self.cfg.get("_ops") or {}
        return mcp_adapter.McpSession(t, mode=self.cfg.get("protocol", "legacy"), allowed_tools=ops.get("mcp_tools", ()),
                                      probe_tools=ops.get("mcp_deny_probe_tools", ()), allowed_methods=ops.get("mcp_methods"),
                                      client_cert=client_cert, timeout=float(self.cfg.get("timeout_s", 15)))
    def run(self):
        import mcp_adapter
        t = next(iter(_pa_targets(self.cfg).values())); self.n += 1; t0 = time.perf_counter()
        el = lambda: round((time.perf_counter() - t0) * 1000, 1)
        if self.n % self.unauth_every == 0:
            s = self._session(t, client_cert=False)
            try:
                s.open(); s.list_tools()
            except mcp_adapter.McpHttpStatus as e:
                if e.status in (502, 503, 504): raise Unavailable(str(e))
                ok = e.status == 401 or (e.status == 403 and e.refusal in ("no_identity", "unknown_identity"))
                return R("expected_denial" if ok else "unexpected", f"synthetic unauthenticated probe -> {e.status} ({e.refusal}) "
                         "(TLS rejection or 401 expected)", e.status, 1, el())
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError) as e:
                return R("expected_denial", f"synthetic unauthenticated probe -> TLS rejected ({type(e).__name__}) "
                         "(TLS rejection or 401 expected)", None, 1, el())
            finally:
                s.close()
            return R("unexpected", "synthetic unauthenticated probe -> accepted without a client certificate (TLS rejection or 401 expected)",
                     200, max(1, s.requests), el())
        s = self._session(t)
        probe = self.n % self.deny_every == 0
        tool = self.cfg["deny_probe_tool"] if probe else self.cfg["allowed_tool"]
        try:
            s.open(); r = s.call_tool(tool, {}, probe=probe)
        except mcp_adapter.McpHttpStatus as e:
            if e.status in (502, 503, 504): raise Unavailable(str(e))
            if probe:
                ok = e.status == 403 and e.refusal == "tool_denied"
                return R("expected_denial" if ok else "unexpected", f"synthetic deny probe {tool} -> {e.status} ({e.refusal}) (403 expected)",
                         e.status, max(1, s.requests), el(), mcp_requests=s.requests)
            return R("unexpected", f"tools/call {tool} -> {e.status} ({e.refusal})", e.status, max(1, s.requests), el(), mcp_requests=s.requests)
        except mcp_adapter.McpRpcError as e:
            if probe:      # the request reached the MCP server: the BIG-IP policy did not deny it
                return R("unexpected", f"synthetic deny probe {tool} -> reached the server (JSON-RPC {e.code}) (403 expected)",
                         200, s.requests, el(), mcp_requests=s.requests)
            return R("unexpected", f"tools/call {tool} -> JSON-RPC error {e.code}", 200, s.requests, el(), mcp_requests=s.requests)
        finally:
            s.close()
        if probe:
            return R("unexpected", f"synthetic deny probe {tool} -> 200 (403 expected)", 200, s.requests, el(), mcp_requests=s.requests)
        return R("ok" if not r["is_error"] else "unexpected", f"tools/call {tool} -> 200 (allowed identity)", 200, s.requests, el(),
                 mcp_requests=s.requests)


class AgentInvestigation(Workload):
    """A real fraud investigation through Agent A's API (management LAN). Agent A calls Agent B through the BIG-IP_C A2A
    VIP and Agent B calls the MCP VIPs. F5 delivery is claimed only if the result's card_url names the expected front door;
    a direct Agent B URL is reported as a bypass (unexpected)."""
    name = "agent_investigation"
    ALERT_RE = re.compile(r"^ALERT-\d{4}$")
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx); self.alerts = None
        self.timeout = int(cfg.get("timeout_s", 300))
        if not 60 <= self.timeout <= 600: raise ValueError(f"{self.name}: timeout_s must be 60..600")
        if not cfg.get("expect_front_door"): raise ValueError(f"{self.name}: expect_front_door is required")
    def destinations(self):
        return _target_urls(self.cfg)
    def _allowed(self, method, path):
        ops = ((self.cfg.get("_ops") or {}).get("http") or {}).get("AGENT_A_API", [])
        if f"{method} {path}" not in ops:
            raise PermissionError(f"{method} {path} is not an allowed operation for AGENT_A_API")
    def run(self):
        import sim_transport
        t = next(iter(_pa_targets(self.cfg).values())); cost = 0; t0 = time.perf_counter()
        if self.alerts is None:
            self._allowed("GET", "/api/alerts")
            st, _, data, _, _ = sim_transport.request(t, "GET", "/api/alerts", headers={"Accept": "application/json", **SYN}, timeout=15)
            _5xx(st, "alerts"); cost += 1
            try: ids = [a.get("alert_id") for a in json.loads(data) if isinstance(a, dict)]
            except ValueError: ids = []
            self.alerts = sorted(i for i in ids if isinstance(i, str) and self.ALERT_RE.match(i))
        if not self.alerts:
            return R("unexpected", "Agent A returned no alerts", None, max(cost, 1), None)
        alert = random.choice(self.alerts)
        self._allowed("POST", "/api/investigate")
        st, _, data, ms, _ = sim_transport.request(t, "POST", "/api/investigate", {"alert_id": alert},
                                                   {"Content-Type": "application/json", "Accept": "application/json", **SYN},
                                                   timeout=self.timeout, max_bytes=4 << 20)
        _5xx(st, "investigate"); cost += 1
        if st != 200:
            return R("unexpected", f"investigate -> {st}", st, cost, ms)
        try: row = json.loads(data)
        except ValueError: return R("unexpected", "investigate -> non-JSON response", st, cost, ms)
        card_host = urllib.parse.urlsplit(row.get("card_url") or "").hostname
        front = card_host == self.cfg["expect_front_door"]
        state = row.get("state"); result = row.get("result") or {}
        has_decision = bool(isinstance(result, dict) and (result.get("assessment") or {}).get("decision"))
        reps = len(result.get("replicas_used") or []) if isinstance(result, dict) else 0
        if state == "completed" and has_decision and front:
            return R("ok", f"investigation completed via front door {card_host}; decision present", st, cost,
                     round((time.perf_counter() - t0) * 1000, 1), replicas_used=reps)
        why = ("BYPASS: Agent B reached directly at " + str(card_host) + " (BIG-IP A2A VIP not in path)") if card_host and not front \
            else f"state={state} decision={'yes' if has_decision else 'no'}"
        return R("unexpected", f"investigation {why}", st, cost, round((time.perf_counter() - t0) * 1000, 1), replicas_used=reps)


class QdrantQuery(Workload):
    """Read-only RAG retrieval against Qdrant through a BIG-IP virtual server: collection info, then a nearest-neighbour
    query seeded by an existing point id (no embedding model needed, deterministic). Only the two operations listed in
    allowed_operations.qdrant are ever sent."""
    name = "qdrant_query"
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        self.limit = int(cfg.get("limit", 3))
        if not 1 <= self.limit <= 10 or not cfg.get("neighbours_of"): raise ValueError(f"{self.name}: limit 1..10 and neighbours_of required")
        if not re.match(r"^[A-Za-z0-9_-]{1,64}$", cfg.get("collection", "")): raise ValueError(f"{self.name}: invalid collection")
    def destinations(self):
        return _target_urls(self.cfg)
    def run(self):
        import sim_transport
        t = next(iter(_pa_targets(self.cfg).values())); c = self.cfg["collection"]
        ops = (self.cfg.get("_ops") or {}).get("qdrant", [])
        if "GET /collections/{collection}" not in ops or "POST /collections/{collection}/points/query" not in ops:
            raise PermissionError("qdrant operations not allowed in this environment")
        h = {"Accept": "application/json", **SYN}
        key_env = self.cfg.get("api_key_env")
        if key_env:
            if not os.environ.get(key_env): raise RuntimeError(f"Qdrant API key not set ({key_env})")
            h["api-key"] = os.environ[key_env]
        t0 = time.perf_counter()
        st, _, data, _, _ = sim_transport.request(t, "GET", f"/collections/{c}", headers=h, timeout=10); _5xx(st, "collection")
        if st != 200: return R("unexpected", f"collection info -> {st}", st, 1, round((time.perf_counter() - t0) * 1000, 1))
        try: points = int(((json.loads(data).get("result") or {}).get("points_count")) or 0)
        except (ValueError, TypeError, AttributeError): points = 0
        seed = random.choice(self.cfg["neighbours_of"])
        t1 = time.perf_counter()
        st, _, data, _, _ = sim_transport.request(t, "POST", f"/collections/{c}/points/query",
                                                  {"query": seed, "limit": self.limit, "with_payload": False, "with_vector": False},
                                                  {"Content-Type": "application/json", **h}, timeout=10)
        _5xx(st, "query"); t2 = time.perf_counter()
        try: n = len((json.loads(data).get("result") or {}).get("points") or []) if st == 200 else 0
        except (ValueError, AttributeError): n = 0
        ok = st == 200 and 1 <= n <= self.limit
        return R("ok" if ok else "unexpected", f"{n} results (collection {points} points)", st, 2, round((t2 - t0) * 1000, 1),
                 results=n, query_ms=round((t2 - t1) * 1000, 1))


class S3ObjectRead(Workload):
    """Authenticated (SigV4) read of objects under an approved prefix through an S3 virtual server: one listing, then
    GETs. Credentials come only from the environment variables named in credentials_env."""
    name = "s3_object_read"
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx); self.s3 = None; self.keys = None
        self.per_run = int(cfg.get("objects_per_run", 2)); self.max_obj = int(cfg.get("max_object_bytes", 1 << 20))
        if not 1 <= self.per_run <= 5 or not cfg.get("prefix"): raise ValueError(f"{self.name}: prefix required, objects_per_run 1..5")
        check_url(cfg["endpoint"])
    def run(self):
        self.s3 = self.s3 or make_s3(self.cfg["endpoint"], self.cfg.get("_s3_auth"))
        cost = 0
        if self.keys is None:
            r = self.s3.list_objects_v2(Bucket=self.cfg["bucket"], Prefix=self.cfg["prefix"], MaxKeys=200); cost += 1
            self.keys = sorted(o["Key"] for o in r.get("Contents", []) if 0 < o["Size"] <= self.max_obj)
        if not self.keys:
            return R("unexpected", "no objects under the approved prefix", None, max(cost, 1), None)
        total = 0; n = 0; t0 = time.perf_counter()
        for k in random.sample(self.keys, min(self.per_run, len(self.keys))):
            if STOP.is_set(): break
            o = self.s3.get_object(Bucket=self.cfg["bucket"], Key=k); b = o["Body"].read(self.max_obj + 1)
            n += 1; total += len(b)
        s = time.perf_counter() - t0
        return R("ok" if n else "unexpected", f"{n} objects, {total} B", 200, cost + n, round(s * 1000, 1), bytes=total, objects=n,
                 mbps=round(total / 1e6 / max(s, 1e-6), 2))


def _http_op(cfg, dname, method, path):
    ops = ((cfg.get("_ops") or {}).get("http") or {}).get(dname, [])
    if f"{method} {path.split('?')[0]}" not in ops:
        raise PermissionError(f"{method} {path.split('?')[0]} is not an allowed operation for {dname}")


def _target(cfg, dname):
    ts_ = _pa_targets(cfg)
    if dname not in ts_:
        raise ValueError(f"{cfg.get('_name')}: destination {dname} is not resolved for this workload")
    return ts_[dname]


class _ProfileHttp(Workload):
    """Base of the plain profile workloads (Project A): resolved targets only, BIG-IP attribution, optional activity guard.

    Activity guard (defer_while_investigating): before an LLM workload runs, Agent A's investigation list is read. If the
    most recent investigation finished less than quiet_s ago, the fraud application is in active use and the run is
    deferred (no inference request). If the list cannot be read the run is also deferred (fail closed). Agent A stores an
    investigation only when it finishes, so an investigation that is in flight right now is not visible: the guard detects
    activity sessions, not every single in-flight run. The residual overlap is bounded by the small request sizes below."""
    DEST = None
    def destinations(self):
        out = _target_urls(self.cfg)
        g = self.cfg.get("_guard")
        if g:
            out.append(f"{g['target']['scheme']}://{g['target']['address']}/")
        return out
    def deferred(self):
        g = self.cfg.get("_guard")
        if not g:
            return None
        import sim_transport
        t = g["target"]
        _http_op(self.cfg, t["name"], "GET", g["path"])
        try:
            st, _, data, _, _ = sim_transport.request(t, "GET", g["path"], headers={"Accept": "application/json", **SYN}, timeout=10)
        except Exception as e:
            return f"activity guard: Agent A unreachable ({type(e).__name__}); deferring (fail closed)", 1
        if st != 200:
            return f"activity guard: Agent A -> {st}; deferring (fail closed)", 1
        try:
            rows = json.loads(data)
            last = max((float(r.get("finished") or r.get("started") or 0) for r in rows if isinstance(r, dict)), default=0.0)
        except (ValueError, TypeError, AttributeError):
            return "activity guard: unreadable investigation list; deferring (fail closed)", 1
        age = time.time() - last
        if age < g["quiet_s"]:
            return f"activity guard: an investigation finished {int(max(age, 0))} s ago (< {g['quiet_s']} s); deferring", 1
        return None


class OllamaEmbed(_ProfileHttp):
    """One embedding of a fixed, non-sensitive sentence through the BIG-IP_C inference VIP (POST /api/embed), the same
    call the fraud-intel MCP server makes for RAG. Records dimensions, latency and response size; never the vector."""
    name = "ollama_embed"
    TEXTS = ["card-not-present purchase followed by a foreign wire transfer", "new device login and change of payee",
             "many small transfers to a peer-to-peer account"]
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        if not re.match(r"^[A-Za-z0-9._:-]{1,64}$", cfg.get("model", "")): raise ValueError(f"{self.name}: invalid model")
        self.timeout = int(cfg.get("timeout_s", 30))
        if not 5 <= self.timeout <= 60: raise ValueError(f"{self.name}: timeout_s must be 5..60")
    def run(self):
        import sim_transport
        t = _target(self.cfg, "INFERENCE_VIP"); _http_op(self.cfg, "INFERENCE_VIP", "POST", "/api/embed")
        st, _, data, ms, ttfb = sim_transport.request(t, "POST", "/api/embed", {"model": self.cfg["model"], "input": random.choice(self.TEXTS)},
                                                      {"Content-Type": "application/json", "Accept": "application/json", **SYN},
                                                      timeout=self.timeout, max_bytes=1 << 20)
        _5xx(st, "embed")
        try: emb = (json.loads(data).get("embeddings") or [[]])[0] if st == 200 else []
        except (ValueError, AttributeError, IndexError, TypeError): emb = []
        dims = len(emb) if isinstance(emb, list) else 0
        want = self.cfg.get("expected_dims")
        ok = st == 200 and dims > 0 and (not want or dims == int(want))
        return R("ok" if ok else "unexpected", f"INFERENCE_VIP embed {self.cfg['model']} -> {st} dims={dims}", st, 1, ms,
                 dims=dims, bytes=len(data), ttfb_ms=ttfb, embed_ms=ms)


class ChatCompletionSmall(_ProfileHttp):
    """One small, non-streaming OpenAI-compatible chat completion through the BIG-IP_C inference VIP (the call Agent B
    makes), with a hard max_tokens cap. Only token counts, timings and the answer length are recorded."""
    name = "chat_completion"
    PROMPTS = ["In one short sentence, what is a load balancer?", "In one short sentence, what is account takeover fraud?"]
    MAX_TOKENS_CAP = 64
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        if not re.match(r"^[A-Za-z0-9._:-]{1,64}$", cfg.get("model", "")): raise ValueError(f"{self.name}: invalid model")
        self.max_tokens = int(cfg.get("max_tokens", 16)); self.timeout = int(cfg.get("timeout_s", 90))
        if not 1 <= self.max_tokens <= self.MAX_TOKENS_CAP: raise ValueError(f"{self.name}: max_tokens must be 1..{self.MAX_TOKENS_CAP}")
        if not 10 <= self.timeout <= 180: raise ValueError(f"{self.name}: timeout_s must be 10..180")
    def run(self):
        import sim_transport
        t = _target(self.cfg, "INFERENCE_VIP"); _http_op(self.cfg, "INFERENCE_VIP", "POST", "/v1/chat/completions")
        body = {"model": self.cfg["model"], "messages": [{"role": "user", "content": random.choice(self.PROMPTS)}],
                "max_tokens": self.max_tokens, "temperature": 0, "stream": False}
        st, _, data, ms, ttfb = sim_transport.request(t, "POST", "/v1/chat/completions", body,
                                                      {"Content-Type": "application/json", "Accept": "application/json", **SYN},
                                                      timeout=self.timeout, max_bytes=256 << 10)
        _5xx(st, "chat")
        try: j = json.loads(data) if st == 200 else {}
        except ValueError: j = {}
        ch = (j.get("choices") or [{}])[0] if isinstance(j, dict) else {}
        u = (j.get("usage") or {}) if isinstance(j, dict) else {}
        text = ((ch.get("message") or {}).get("content") or "") if isinstance(ch, dict) else ""
        gen = u.get("completion_tokens")
        ok = st == 200 and bool(text) and ch.get("finish_reason") in ("stop", "length") and (gen is None or gen <= self.max_tokens)
        return R("ok" if ok else "unexpected", f"INFERENCE_VIP chat {self.cfg['model']} -> {st} {gen} tokens ({ch.get('finish_reason')})",
                 st, 1, ms, prompt_tokens=u.get("prompt_tokens"), generated_tokens=gen, answer_chars=len(text), bytes=len(data),
                 ttfb_ms=ttfb, tokens_per_s=round(gen / (ms / 1000), 1) if gen and ms else None)


class A2aAgentCard(_ProfileHttp):
    """A2A discovery through the BIG-IP_C A2A VIP: GET /.well-known/agent-card.json with verified TLS (lab CA, hostname =
    front-door name, no client certificate - the A2A VIP is server-TLS only). OK only if the card lists skills and its
    interface URL names the expected front door; a card that advertises a direct Agent B address is reported as a bypass."""
    name = "a2a_card"
    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        if not cfg.get("expect_front_door"): raise ValueError(f"{self.name}: expect_front_door is required")
    def run(self):
        import sim_transport
        t = _target(self.cfg, "A2A_VIP"); _http_op(self.cfg, "A2A_VIP", "GET", "/.well-known/agent-card.json")
        st, _, data, ms, ttfb = sim_transport.request(t, "GET", "/.well-known/agent-card.json", headers={"Accept": "application/json", **SYN},
                                                      timeout=15, max_bytes=256 << 10, client_cert=False)
        _5xx(st, "agent card")
        try: card = json.loads(data) if st == 200 else {}
        except ValueError: card = {}
        if not isinstance(card, dict): card = {}
        skills = card.get("skills") if isinstance(card.get("skills"), list) else []
        urls = [i.get("url") for i in (card.get("supportedInterfaces") or card.get("supported_interfaces") or []) if isinstance(i, dict)]
        urls = [u for u in urls + [card.get("url")] if isinstance(u, str) and u]
        host = urllib.parse.urlsplit(urls[0]).hostname if urls else None
        if st == 200 and skills and host == self.cfg["expect_front_door"]:
            return R("ok", f"A2A_VIP agent card -> 200 {len(skills)} skills, front door {host}", st, 1, ms, skills=len(skills),
                     bytes=len(data), ttfb_ms=ttfb)
        why = f"BYPASS: card advertises {host} (BIG-IP A2A VIP not in path)" if host and host != self.cfg["expect_front_door"] \
            else f"-> {st} skills={len(skills)}"
        return R("unexpected", f"A2A_VIP agent card {why}", st, 1, ms, skills=len(skills), bytes=len(data), ttfb_ms=ttfb)


KINDS = {c.name: c for c in (McpDelivery, McpAuthz, McpRateBurst, Sse, S3RagRead, TrainingDataRead, VectorQuery,
                             OllamaInference, AgentRun, RagChat, Health)}
# Classes reachable ONLY from environment-profile workloads (resolved by load_profile, which sets `_name`). A legacy
# sim-config.json (Project B) can never instantiate them.
PROFILE_CLASSES = {c.name: c for c in (McpSessionDelivery, McpIdentityAuthz, AgentInvestigation, QdrantQuery, S3ObjectRead,
                                       OllamaEmbed, ChatCompletionSmall, A2aAgentCard)}
# Kinds an environment profile may use (Project B keeps using sim-config.json; its profile is descriptive).
PROFILE_KINDS = set(PROFILE_CLASSES) | {"training_data_read", "ollama_inference", "health"}


# ------------------------------------------------------------------ runner
class Status:
    def __init__(self, path, names, mode, targets=None):
        self.path = path
        self.s = {"started": ts(), "mode": mode, "workloads": {n: {"runs": 0, **{c: 0 for c in CLASSES}, "requests": 0, "last_ok": None,
                                                                    "last_result": None, "avg_ms": None} for n in names}}
        for n, t in (targets or {}).items():          # environment profiles only: which BIG-IP virtual server each workload uses
            if t:
                self.s["workloads"][n].update(targets=t, deferred=0, last_deferred=None, bytes=0)
    def record(self, name, res):
        w = self.s["workloads"][name]; w["runs"] += 1; w[res["outcome"]] += 1; w["requests"] += res["cost"]
        w["last_result"] = {"ts": ts(), "outcome": res["outcome"], "detail": res["detail"], "ms": res["ms"], **res["m"]}
        if res["outcome"] in ("ok", "expected_denial"): w["last_ok"] = w["last_result"]["ts"]
        if res["ms"] is not None: w["avg_ms"] = round(res["ms"] if w["avg_ms"] is None else (w["avg_ms"] * 0.8 + res["ms"] * 0.2), 1)
        if "bytes" in w: w["bytes"] += int(res["m"].get("bytes") or 0)
        self.save()
    def defer(self, name, reason):
        w = self.s["workloads"][name]; w["deferred"] = w.get("deferred", 0) + 1; w["last_deferred"] = {"ts": ts(), "reason": reason}
        self.save()
    def save(self):
        if not self.path: return
        self.s["updated"] = ts()
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f: json.dump(self.s, f, indent=1)
        os.replace(tmp, self.path)


def _legacy_fields(name, kind, wc):
    """Map resolved profile targets onto the field names the reused legacy workload classes read. Legacy classes use the
    legacy (unverified-TLS) http_req, so they may only be given plain-http targets here."""
    ts_ = wc.get("targets") or {}
    if kind in ("health", "ollama_inference", "training_data_read") and any(t["scheme"] != "http" for t in ts_.values()):
        raise SystemExit(f"{name}: https targets are not supported for kind {kind} (it would not verify TLS)")
    if kind == "health":
        paths = wc.get("paths") or {}
        wc["urls"] = [f"http://{t['address']}{paths.get(dn, '/')}" for dn, t in ts_.items()]
    elif kind == "ollama_inference":
        wc["url"] = f"http://{next(iter(ts_.values()))['address']}/api/generate"
    elif kind in ("training_data_read", "s3_object_read"):
        t = next(iter(ts_.values()))
        if t["scheme"] != "http":
            raise SystemExit(f"{name}: https S3 endpoints are not supported yet (hostname-verified S3 needs Phase 3 work)")
        wc["endpoint"] = f"http://{t['address']}"
        if not wc.get("credentials_env"):
            raise SystemExit(f"{name}: credentials_env is required in environment profiles (no default credential chain)")
        wc["_s3_auth"] = dict(wc["credentials_env"])
    return wc


def activate_environment(env):
    import sim_profiles, sim_transport
    ACTIVE["env"], ACTIVE["allowed"] = env, frozenset(sim_profiles.approved(env))
    sim_transport.configure(env)


def load_profile(path, instance):
    """Environment profile -> (instance cfg, {workload: cfg}). Unavailable workloads keep `_unavailable` (never constructed)."""
    import sim_profiles
    prof = sim_profiles.load(path)
    if prof.get("runtime_config"):                       # legacy environment (Project B): its runtime config is sim-config.json
        return load_config(os.path.join(os.path.dirname(os.path.abspath(path)), prof["runtime_config"]), instance)
    activate_environment(prof["environment"])
    inst, wl = sim_profiles.resolve(prof, instance)
    for name, wc in wl.items():
        kind = wc.get("kind", name)
        wc["_name"] = name
        if "_unavailable" in wc:                         # listed with its reason, never constructed
            continue
        if kind not in PROFILE_KINDS:
            raise SystemExit(f"{name}: kind {kind!r} is not supported in environment profiles")
        _legacy_fields(name, kind, wc)
    return inst, wl


def load_config(path, instance):
    """Unified config: {"instances": {name: {...}}, "workloads": {name: {"instance": name, ...}}}. Legacy per-host files
    (no "instances" key) are still accepted. A file with an "environment" key is an environment profile."""
    with open(path) as f: cfg = json.load(f)
    if "environment" in cfg:
        return load_profile(path, instance)
    if "instances" not in cfg:
        return cfg, cfg["workloads"]
    if instance not in cfg["instances"]:
        raise SystemExit(f"--instance must be one of {sorted(cfg['instances'])}")
    inst = dict(cfg["instances"][instance])
    wl = {n: {k: v for k, v in w.items() if k != "instance"} for n, w in cfg["workloads"].items() if w.get("instance") == instance}
    return inst, wl


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True); ap.add_argument("--instance")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", help="validate config and destinations, print the plan, send nothing")
    g.add_argument("--once", action="store_true", help="bounded: run every selected workload once, then exit")
    g.add_argument("--duration", type=int, help="bounded: run the normal schedule for N seconds (60..7200), then exit")
    ap.add_argument("--only", help="comma-separated workload names (bounded tests)")
    ap.add_argument("--status-file", help="override the status file (use for bounded tests so the service's file is untouched)")
    ap.add_argument("--stop-file", help="kill switch: stop (between requests) as soon as this file exists")
    ap.add_argument("--max-rpm", type=int, help="lower the instance per-minute request budget for this run (never raises it)")
    a = ap.parse_args()
    if a.duration is not None and not 60 <= a.duration <= 7200: ap.error("--duration must be 60..7200")
    cfg, wcfg = load_config(a.config, a.instance)
    only = set(a.only.split(",")) if a.only else None
    if only and not only <= set(wcfg): sys.exit(f"--only: unknown or other-instance workloads {sorted(only - set(wcfg))}")
    tel = Telemetry(cfg.get("telemetry_url"), cfg.get("host_label", socket.gethostname()))
    ctx = {"telemetry": tel}
    wls = []; unavailable = {}
    for name, wc in wcfg.items():
        if only is not None and name not in only: continue
        if "_unavailable" in wc:                      # environment profile: never constructed, never sends anything
            if only is not None:
                sys.exit(f"workload {name} is {wc['_unavailable']['status'].upper().replace('_', ' ')}: {wc['_unavailable']['reason']}")
            unavailable[name] = wc["_unavailable"]; continue
        if only is None and not wc.get("enabled", True): continue
        kind = wc.get("kind", name)
        cls = (PROFILE_CLASSES.get(kind) if wc.get("_name") else None) or KINDS.get(kind)
        if cls is None: sys.exit(f"unknown workload {name}")
        wls.append(cls(wc, ctx))
    for w in wls:
        for u in w.destinations(): check_url(u)
    budget = int(cfg.get("max_requests_per_minute", 30))
    if not 1 <= budget <= 60: sys.exit("max_requests_per_minute must be 1..60")
    if a.max_rpm is not None:
        if not 1 <= a.max_rpm <= 60: sys.exit("--max-rpm must be 1..60")
        budget = min(budget, a.max_rpm)
    stopped = lambda: STOP.is_set() or bool(a.stop_file and os.path.exists(a.stop_file))
    if a.stop_file and os.path.exists(a.stop_file) and not a.dry_run:
        sys.exit(f"stop file {a.stop_file} exists: remove it to start")
    mode = "dry-run" if a.dry_run else "once" if a.once else f"bounded {a.duration}s" if a.duration else "continuous"
    extra = {"environment": cfg["environment"], "unavailable": sorted(unavailable)} if cfg.get("environment") else {}
    log(event="start", version=UA, mode=mode, instance=a.instance or cfg.get("host_label"), workloads=[w.name for w in wls], budget_per_min=budget, **extra)
    if a.dry_run:
        for w in wls:
            log(plan=w.name, every_s=w.interval, jitter=w.jitter, max_per_hour=w.cap,
                destinations=sorted({urllib.parse.urlsplit(u).netloc for u in w.destinations()}) or ["(via agent.py / chat client)"])
        for n, u in sorted(unavailable.items()):
            log(plan=n, status=u["status"], reason=u["reason"])
        log(event="dry-run ok", telemetry=bool(tel.url)); return
    st = Status(a.status_file or cfg.get("status_file"), [w.name for w in wls], mode, {w.name: w.attribution() for w in wls}); sent = []
    pending = list(wls) if a.once else None
    end = time.monotonic() + a.duration if a.duration else None
    if a.duration:                                                   # bounded test: start each workload promptly
        for w in wls: w.next_at = time.monotonic() + random.uniform(0, 5)
    while not stopped() and (end is None or time.monotonic() < end):
        now = time.monotonic(); sent = [t for t in sent if now - t < 60]
        todo = list(pending) if a.once else [w for w in wls if w.due(now)]
        if a.once and not todo: break
        for w in todo:
            if stopped() or len(sent) >= budget or (end and time.monotonic() >= end): break
            try:
                d = w.deferred()
            except Exception as e:
                d = (f"activity guard error: {type(e).__name__}; deferring (fail closed)", 0)
            if d:
                why, c = d; sent += [now] * c
                w.next_at = now + max(60.0, w.interval / 2)
                st.defer(w.name, why); log(workload=w.name, event="deferred", reason=why)
                if a.once: pending.remove(w)
                continue
            w.schedule(now)
            try:
                res = w.run()
            except Exception as e:
                res = R("unavailable" if _is_unavailable(e) else "error", f"{'unavailable' if _is_unavailable(e) else 'error'}: {type(e).__name__}"
                        + (f" {e}" if isinstance(e, Unavailable) else ""), None, 1, None)
            w.backoff(time.monotonic(), res["outcome"] == "unavailable")
            sent += [now] * res["cost"]
            st.record(w.name, res)
            tel.send(w.name, res)
            log(workload=w.name, outcome=res["outcome"], detail=res["detail"], ms=res["ms"], status=res["status"], **res["m"])
            if a.once: pending.remove(w)
        STOP.wait(1.0)
    if a.stop_file and os.path.exists(a.stop_file): log(event="stop-file", path=a.stop_file)
    log(event="stopped", totals={n: {k: v[k] for k in ("runs",) + CLASSES} for n, v in st.s["workloads"].items()})


if __name__ == "__main__":
    main()
