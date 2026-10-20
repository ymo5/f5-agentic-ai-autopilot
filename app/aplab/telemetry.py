"""OpenTelemetry bootstrap shared by every lab service.

Exports OTLP/HTTP to the collector on AP-AI-SERVICES (OTEL_EXPORTER_OTLP_ENDPOINT).
A2A uses httpx (auto-instrumented here). The MCP SDK creates its own client/server spans and
propagates W3C trace context inside MCP `_meta`, so it only needs the global TracerProvider.
"""
from __future__ import annotations

import os
import socket

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_configured = False


def setup(service_name: str, **resource_attrs: str) -> trace.Tracer:
    global _configured
    if not _configured:
        attrs = {
            "service.name": service_name,
            "service.namespace": "aplab",
            "service.version": os.environ.get("APLAB_VERSION", "0.1.0"),
            "host.name": socket.gethostname(),
            "deployment.environment": "innovation-lab",
        }
        attrs.update(resource_attrs)
        provider = TracerProvider(resource=Resource.create(attrs))
        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        if endpoint:
            provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces"))
            )
        trace.set_tracer_provider(provider)
        HTTPXClientInstrumentor().instrument()
        _configured = True
    return trace.get_tracer(service_name)


def asgi(app):
    """Wrap an ASGI app so inbound HTTP requests become SERVER spans (W3C context extracted)."""
    return OpenTelemetryMiddleware(app, exclude_spans=["receive", "send"])
