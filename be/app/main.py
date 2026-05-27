from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.v1.routers import (
    assets,
    auth,
    demo,
    evaluations,
    findings,
    health,
    knowledge,
    reports,
    scans,
)
from app.core.config import settings
from app.core.logging import setup_logging, TraceIDMiddleware
from app.core.rate_limit import limiter
from app.core.tracing import setup_tracing
from app.db.session import init_db


def create_app() -> FastAPI:
    setup_logging()

    app = FastAPI(
        title="AI-Augmented Web Vulnerability Assessment API",
        version="0.1.0",
        openapi_url="/api/v1/openapi.json",
        docs_url="/api/v1/docs",
        redoc_url="/api/v1/redoc",
    )

    # ── Rate limiter ──────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # ── CORS — controlled by CORS_ORIGINS env var ─────────────────────────
    origins = [o.strip() for o in settings.cors_origins.split() if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Trace ID + Audit log middleware ──────────────────────────────────
    app.add_middleware(TraceIDMiddleware)
    from app.api.v1.middleware.audit_log import AuditLogMiddleware
    app.add_middleware(AuditLogMiddleware)

    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
    app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
    app.include_router(knowledge.router, prefix="/api/v1/knowledge", tags=["knowledge"])
    app.include_router(demo.router, prefix="/api/v1/demo", tags=["demo"])
    app.include_router(evaluations.router, prefix="/api/v1/evaluations", tags=["evaluations"])

    Instrumentator().instrument(app).expose(
        app, endpoint="/metrics", include_in_schema=False
    )

    @app.on_event("startup")
    def _startup() -> None:
        init_db()
        setup_tracing(app)

    return app


app = create_app()
