"""
Structured JSON logging with per-request trace ID injection.

- Uses structlog when available (production); falls back to stdlib logging.
- Every log record carries trace_id (UUID4 per request via contextvars).
- FastAPI middleware injects the trace ID into structlog's context and
  echoes it in the X-Trace-ID response header.
- Log format:
    {"timestamp": "...", "level": "info", "logger": "...", "trace_id": "...", "event": "..."}

Usage:
    from app.core.logging import get_logger, set_trace_id, get_trace_id
    log = get_logger(__name__)
    log.info("scan started", scan_id=42)
"""
from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar

from app.core.config import settings

# ── Trace ID context ──────────────────────────────────────────────────────────

_trace_id_var: ContextVar[str] = ContextVar("trace_id", default="")


def new_trace_id() -> str:
    return uuid.uuid4().hex


def set_trace_id(tid: str) -> None:
    _trace_id_var.set(tid)


def get_trace_id() -> str:
    return _trace_id_var.get() or new_trace_id()


# ── Structlog setup (optional dep) ────────────────────────────────────────────

try:
    import structlog

    def _add_trace_id(
        logger: object, method_name: str, event_dict: dict
    ) -> dict:
        event_dict["trace_id"] = get_trace_id()
        return event_dict

    def setup_logging() -> None:
        level = getattr(logging, settings.log_level.upper(), logging.INFO)
        logging.basicConfig(level=level, format="%(message)s")

        structlog.configure(
            processors=[
                structlog.stdlib.add_log_level,
                structlog.stdlib.add_logger_name,
                structlog.processors.TimeStamper(fmt="iso"),
                _add_trace_id,
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

    def get_logger(name: str) -> structlog.stdlib.BoundLogger:
        return structlog.get_logger(name)

    _STRUCTLOG = True

except ImportError:
    # Fallback: stdlib with a simple JSON formatter
    import json

    class _JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload = {
                "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                "level": record.levelname.lower(),
                "logger": record.name,
                "trace_id": get_trace_id(),
                "event": record.getMessage(),
            }
            if record.exc_info:
                payload["exc_info"] = self.formatException(record.exc_info)
            return json.dumps(payload)

    def setup_logging() -> None:
        level = getattr(logging, settings.log_level.upper(), logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        root = logging.getLogger()
        root.handlers.clear()
        root.addHandler(handler)
        root.setLevel(level)

    def get_logger(name: str) -> logging.Logger:  # type: ignore[misc]
        return logging.getLogger(name)

    _STRUCTLOG = False


# ── FastAPI middleware ─────────────────────────────────────────────────────────

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class TraceIDMiddleware(BaseHTTPMiddleware):
    """Attach a trace_id to every request and echo it in the response header."""

    async def dispatch(self, request: Request, call_next: object) -> Response:
        incoming = request.headers.get("X-Trace-ID") or new_trace_id()
        set_trace_id(incoming)
        response: Response = await call_next(request)  # type: ignore[arg-type]
        response.headers["X-Trace-ID"] = incoming
        return response
