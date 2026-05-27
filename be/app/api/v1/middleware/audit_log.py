"""Starlette middleware that writes one AuditLog row per request."""
import logging
import time

from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings

logger = logging.getLogger(__name__)

# Skip noise paths — health checks and metrics don't need audit trail
_SKIP_PATHS = {"/api/v1/health", "/metrics", "/docs", "/openapi.json"}


def _extract_username(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    try:
        payload = jwt.decode(
            token, settings.jwt_secret, algorithms=["HS256"],
            options={"verify_exp": False},  # still log even if expired
        )
        return payload.get("sub")
    except JWTError:
        return None


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if any(request.url.path.startswith(p) for p in _SKIP_PATHS):
            return await call_next(request)

        t0 = time.monotonic()
        response = await call_next(request)
        duration_ms = int((time.monotonic() - t0) * 1000)

        username = _extract_username(request)
        ip = request.client.host if request.client else None

        try:
            from app.db.models.audit_log import AuditLog
            from app.db.session import SessionLocal

            with SessionLocal() as db:
                db.add(AuditLog(
                    username=username,
                    method=request.method,
                    path=str(request.url.path),
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                    ip=ip,
                    user_agent=request.headers.get("user-agent"),
                ))
                db.commit()
        except Exception as exc:
            logger.debug("Audit log write failed: %s", exc)

        return response
