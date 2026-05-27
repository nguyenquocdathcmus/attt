"""
OpenTelemetry tracing — auto-instruments FastAPI, SQLAlchemy, Redis.

Call setup_tracing(app) once in create_app() AFTER the app object is created.
The OTEL_EXPORTER_OTLP_ENDPOINT env var controls where traces are exported.
Defaults to http://localhost:4318 (OTLP/HTTP — works with Jaeger, Tempo, etc.).

If opentelemetry packages are not installed, this module is a no-op so the
rest of the codebase doesn't need to guard every import.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_OTEL_AVAILABLE = False

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    _OTEL_AVAILABLE = True
except ImportError:
    pass


def setup_tracing(app: object | None = None) -> None:
    """Configure the global OTEL tracer and instrument FastAPI + SQLAlchemy + Redis."""
    if not _OTEL_AVAILABLE:
        logger.warning("opentelemetry packages not installed — tracing disabled")
        return

    endpoint = os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"
    )
    service_name = os.getenv("OTEL_SERVICE_NAME", "attt-backend")

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces")
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    # ── FastAPI auto-instrumentation ─────────────────────────────────────
    if app is not None:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app)  # type: ignore[arg-type]
            logger.info("OpenTelemetry: FastAPI instrumented")
        except Exception as exc:
            logger.warning("FastAPI OTel instrumentation failed: %s", exc)

    # ── SQLAlchemy auto-instrumentation ──────────────────────────────────
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from app.db.session import engine
        SQLAlchemyInstrumentor().instrument(engine=engine)
        logger.info("OpenTelemetry: SQLAlchemy instrumented")
    except Exception as exc:
        logger.warning("SQLAlchemy OTel instrumentation failed: %s", exc)

    # ── Redis auto-instrumentation ───────────────────────────────────────
    try:
        from opentelemetry.instrumentation.redis import RedisInstrumentor
        RedisInstrumentor().instrument()
        logger.info("OpenTelemetry: Redis instrumented")
    except Exception as exc:
        logger.warning("Redis OTel instrumentation failed: %s", exc)

    logger.info(
        "OpenTelemetry tracing configured service=%s endpoint=%s",
        service_name, endpoint,
    )


def get_tracer(name: str) -> object:
    """Return a tracer for manual spans. Returns a no-op tracer when OTEL unavailable."""
    if _OTEL_AVAILABLE:
        return trace.get_tracer(name)  # type: ignore[return-value]

    class _NoOpTracer:
        def start_as_current_span(self, name: str, **kw: object) -> object:
            from contextlib import contextmanager

            @contextmanager
            def _noop():
                yield None

            return _noop()

    return _NoOpTracer()
