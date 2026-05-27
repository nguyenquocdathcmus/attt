"""
Scan router — CRUD + real-time WebSocket (Redis Pub/Sub).

WebSocket upgrade path:
  Client → ws://…/api/v1/scans/{id}/ws?token=<jwt>
  Server subscribes to Redis channel scan:events:{scan_id}
  Celery tasks publish JSON events via publish_scan_event()
  Client receives events immediately; no DB polling loop

Fallback: if Redis Pub/Sub subscribe fails, falls back to 3-second DB poll
          (matches prior behaviour, never breaks the client).
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import require_roles
from app.db.models.asset import Asset
from app.db.models.finding import Finding
from app.db.models.scan import Scan
from app.db.session import SessionLocal, get_db
from app.schemas.scan import ScanCreate, ScanOut
from app.tasks.scan_tasks import start_scan

logger = logging.getLogger(__name__)
router = APIRouter()

ANALYST_ROLES = ["analyst", "admin"]

_PUBSUB_CHANNEL_PREFIX = "scan:events:"


# ── Pub/Sub helpers (called by Celery tasks) ──────────────────────────────────

def publish_scan_event(scan_id: str | UUID, event: dict) -> None:
    """Publish a scan status event to Redis. Fire-and-forget."""
    try:
        from app.core.cache import get_redis
        channel = f"{_PUBSUB_CHANNEL_PREFIX}{scan_id}"
        get_redis().publish(channel, json.dumps(event, default=str))
    except Exception as exc:
        logger.warning("publish_scan_event failed scan_id=%s: %s", scan_id, exc)


def _build_event_from_db(scan_id: UUID, session: Session) -> dict | None:
    scan = session.get(Scan, scan_id)
    if not scan:
        return {"status": "not_found"}
    total = session.query(Finding).filter(Finding.scan_id == scan_id).count()
    ai_ready = (
        session.query(Finding)
        .filter(Finding.scan_id == scan_id, Finding.risk_score.isnot(None))
        .count()
        > 0
    ) if total > 0 else False
    return {
        "status": scan.status,
        "scanner": scan.scanner,
        "findings_count": total,
        "ai_ready": ai_ready,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    }


# ── REST endpoints ────────────────────────────────────────────────────────────

@router.post("", response_model=ScanOut)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> Scan:
    asset = db.get(Asset, payload.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    scan = Scan(
        asset_id=payload.asset_id,
        scanner=payload.scanner,
        status="queued",
        config=payload.config or {},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    config = payload.config or {}
    priority = max(0, min(9, int(config.get("priority", 5))))
    start_scan.apply_async(
        (str(scan.id), asset.url, payload.scanner, config),
        queue="scans",
        priority=priority,
    )
    publish_scan_event(scan.id, {"status": "queued", "scan_id": str(scan.id)})
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> list[Scan]:
    return db.query(Scan).order_by(Scan.created_at.desc()).all()


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/{scan_id}", response_model=ScanOut)
def delete_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> Scan:
    """DELETE alias for scan cancellation — matches system-flow API reference."""
    return cancel_scan(scan_id=scan_id, db=db, _user=_user)


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("queued", "running"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot cancel a scan with status '{scan.status}'",
        )
    scan.status = "cancelled"
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)
    publish_scan_event(scan_id, {"status": "cancelled", "scan_id": str(scan_id)})
    return scan


# ── WebSocket — Redis Pub/Sub with DB-poll fallback ───────────────────────────

@router.websocket("/{scan_id}/ws")
async def scan_ws(
    scan_id: UUID,
    websocket: WebSocket,
    token: str | None = Query(None),
) -> None:
    if settings.auth_enabled:
        if not token:
            await websocket.close(code=4001)
            return
        try:
            payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
            if not payload.get("sub"):
                await websocket.close(code=4001)
                return
        except JWTError:
            await websocket.close(code=4001)
            return

    await websocket.accept()

    # Send current state immediately from DB so client isn't blank
    with SessionLocal() as session:
        initial = _build_event_from_db(scan_id, session)
    if initial:
        await websocket.send_json(initial)
        if initial.get("status") in ("completed", "failed", "cancelled", "not_found"):
            return

    # ── Try Redis Pub/Sub ─────────────────────────────────────────────────
    try:
        await _ws_pubsub_loop(scan_id, websocket)
    except Exception as exc:
        logger.warning("Pub/Sub loop error scan_id=%s: %s — falling back to poll", scan_id, exc)
        await _ws_poll_loop(scan_id, websocket)


async def _ws_pubsub_loop(scan_id: UUID, websocket: WebSocket) -> None:
    """Subscribe to the Redis channel and forward messages to the WebSocket."""
    from app.core.cache import get_redis
    import redis.asyncio as aioredis

    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    pubsub = redis_client.pubsub()
    channel = f"{_PUBSUB_CHANNEL_PREFIX}{scan_id}"
    await pubsub.subscribe(channel)

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                event = json.loads(message["data"])
            except (json.JSONDecodeError, TypeError):
                continue
            await websocket.send_json(event)
            status = event.get("status", "")
            if status in ("complete", "completed", "failed", "cancelled", "not_found"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await redis_client.aclose()


async def _ws_poll_loop(scan_id: UUID, websocket: WebSocket) -> None:
    """DB-polling fallback (legacy behaviour, 3-second interval)."""
    try:
        while True:
            with SessionLocal() as session:
                event = _build_event_from_db(scan_id, session)
            if event:
                await websocket.send_json(event)
                if event.get("status") in ("complete", "completed", "failed", "cancelled", "not_found"):
                    break
            await asyncio.sleep(3)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
