"""Provider-independent LLM interface.

Providers:
  * "openai-compatible" — any OpenAI-style /v1/chat/completions endpoint (the lab runs a local
    open-weight model via Ollama on AP-AI-SERVICES: LLM_BASE_URL=http://10.50.20.45:11434/v1).
  * "anthropic" — Claude via the Messages API, if ANTHROPIC_API_KEY is provided.
  * "none" — no model configured. Callers get `LLMUnavailable` and must use their own clearly
    labelled deterministic fallback. Nothing here ever pretends a fallback is an LLM.

Every response carries `provider` and `model` so the UI/evidence can show exactly what produced it.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

import httpx
from opentelemetry import trace

_tracer = trace.get_tracer("aplab.llm")


class LLMUnavailable(RuntimeError):
    pass


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str
    input_tokens: int | None = None
    output_tokens: int | None = None

    def json(self) -> dict | list:
        """Parse the first JSON object/array in the text (models sometimes wrap it in prose)."""
        t = self.text.strip()
        if t.startswith("```"):
            t = t.split("\n", 1)[1].rsplit("```", 1)[0]
        start = min((i for i in (t.find("{"), t.find("[")) if i >= 0), default=-1)
        if start < 0:
            raise ValueError("no JSON in model output")
        return json.JSONDecoder().raw_decode(t[start:])[0]


class LLM:
    def __init__(self) -> None:
        self.provider = os.environ.get("LLM_PROVIDER", "openai-compatible" if os.environ.get("LLM_BASE_URL") else "none")
        self.base_url = os.environ.get("LLM_BASE_URL", "")
        self.model = os.environ.get("LLM_MODEL", "qwen2.5:3b")
        self.timeout = float(os.environ.get("LLM_TIMEOUT", "180"))

    @property
    def available(self) -> bool:
        return self.provider != "none"

    def describe(self) -> dict:
        return {"provider": self.provider, "model": self.model if self.available else None,
                "endpoint": self.base_url or None}

    async def complete(self, system: str, user: str, *, json_mode: bool = False,
                       max_tokens: int = 700, temperature: float = 0.1) -> LLMResult:
        if not self.available:
            raise LLMUnavailable("no LLM provider configured")
        with _tracer.start_as_current_span("chat " + self.model, kind=trace.SpanKind.CLIENT) as span:
            span.set_attributes({"gen_ai.operation.name": "chat", "gen_ai.system": self.provider,
                                 "gen_ai.request.model": self.model, "server.address": self.base_url})
            if self.provider == "anthropic":
                res = await self._anthropic(system, user, max_tokens, temperature)
            else:
                res = await self._openai(system, user, json_mode, max_tokens, temperature)
            if res.input_tokens is not None:
                span.set_attribute("gen_ai.usage.input_tokens", res.input_tokens)
            if res.output_tokens is not None:
                span.set_attribute("gen_ai.usage.output_tokens", res.output_tokens)
            return res

    async def _openai(self, system, user, json_mode, max_tokens, temperature) -> LLMResult:
        body = {"model": self.model, "temperature": temperature, "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {}
        if os.environ.get("LLM_API_KEY"):
            headers["Authorization"] = f"Bearer {os.environ['LLM_API_KEY']}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.post(f"{self.base_url.rstrip('/')}/chat/completions", json=body, headers=headers)
                r.raise_for_status()
        except httpx.HTTPError as e:
            raise LLMUnavailable(f"LLM endpoint error: {e}") from e
        d = r.json()
        u = d.get("usage") or {}
        return LLMResult(d["choices"][0]["message"]["content"], self.provider, d.get("model", self.model),
                         u.get("prompt_tokens"), u.get("completion_tokens"))

    async def _anthropic(self, system, user, max_tokens, temperature) -> LLMResult:
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise LLMUnavailable("ANTHROPIC_API_KEY not set")
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                "system": system, "messages": [{"role": "user", "content": user}]}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.post("https://api.anthropic.com/v1/messages", json=body,
                                 headers={"x-api-key": key, "anthropic-version": "2023-06-01"})
                r.raise_for_status()
        except httpx.HTTPError as e:
            raise LLMUnavailable(f"Anthropic API error: {e}") from e
        d = r.json()
        text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
        u = d.get("usage") or {}
        return LLMResult(text, "anthropic", d.get("model", self.model), u.get("input_tokens"), u.get("output_tokens"))
