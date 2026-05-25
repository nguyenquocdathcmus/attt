import asyncio
import uuid
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

router = APIRouter()

ANALYST_ROLES = ["analyst", "admin"]


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
    try:
        while True:
            session = SessionLocal()
            try:
                scan = session.get(Scan, scan_id)
                if not scan:
                    await websocket.send_json({"status": "not_found"})
                    break

                total = session.query(Finding).filter(Finding.scan_id == scan_id).count()
                ai_ready = (
                    session.query(Finding)
                    .filter(Finding.scan_id == scan_id, Finding.risk_score.isnot(None))
                    .count()
                    > 0
                ) if total > 0 else False

                await websocket.send_json({
                    "status": scan.status,
                    "scanner": scan.scanner,
                    "findings_count": total,
                    "ai_ready": ai_ready,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                })

                if scan.status in ("completed", "failed"):
                    break
            finally:
                session.close()

            await asyncio.sleep(3)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
