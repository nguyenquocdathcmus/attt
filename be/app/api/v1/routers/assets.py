from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.models.asset import Asset
from app.db.session import get_db
from app.schemas.asset import AssetCreate, AssetOut

router = APIRouter()

ANALYST_ROLES = ["analyst", "admin"]


@router.post("", response_model=AssetOut)
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> Asset:
    asset = Asset(url=payload.url, owner=payload.owner, tags=payload.tags or [])
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("", response_model=list[AssetOut])
def list_assets(
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> list[Asset]:
    return db.query(Asset).order_by(Asset.created_at.desc()).all()
