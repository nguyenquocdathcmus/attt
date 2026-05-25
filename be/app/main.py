from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from app.api.v1.routers import (
    assets,
    auth,
    demo,
    findings,
    health,
    knowledge,
    reports,
    scans,
)
from app.core.logging import setup_logging
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

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
    app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
    app.include_router(knowledge.router, prefix="/api/v1/knowledge", tags=["knowledge"])
    app.include_router(demo.router, prefix="/api/v1/demo", tags=["demo"])

    Instrumentator().instrument(app).expose(
        app, endpoint="/metrics", include_in_schema=False
    )

    @app.on_event("startup")
    def _startup() -> None:
        init_db()

    return app


app = create_app()
