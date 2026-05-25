from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.models.finding import Finding
from app.db.session import get_db
from app.schemas.finding import FindingOut

router = APIRouter()

VIEWER_ROLES = ["viewer", "analyst", "admin"]


@router.get("", response_model=list[FindingOut])
def list_findings(
    scan_id: UUID | None = None,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(VIEWER_ROLES)),
) -> list[Finding]:
    query = db.query(Finding)
    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    return query.order_by(Finding.created_at.desc()).all()
