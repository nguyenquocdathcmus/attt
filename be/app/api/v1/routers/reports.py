from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.models.report import Report
from app.db.session import get_db
from app.schemas.report import ReportCreate, ReportOut
from app.tasks.report_tasks import generate_report

router = APIRouter()

ANALYST_ROLES = ["analyst", "admin"]
VIEWER_ROLES = ["viewer", "analyst", "admin"]


@router.post("", response_model=ReportOut)
def create_report(
    payload: ReportCreate,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> Report:
    report = Report(
        scan_id=payload.scan_id,
        report_type=payload.report_type,
        content={"status": "queued"},
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    generate_report.apply_async(
        (str(report.id), str(payload.scan_id), payload.report_type),
        queue="reports",
        priority=5,
    )
    return report


@router.get("", response_model=list[ReportOut])
def list_reports(
    scan_id: UUID | None = None,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(VIEWER_ROLES)),
) -> list[Report]:
    q = db.query(Report)
    if scan_id:
        q = q.filter(Report.scan_id == scan_id)
    return q.order_by(Report.created_at.desc()).all()


@router.get("/{report_id}", response_model=ReportOut)
def get_report(
    report_id: UUID,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(VIEWER_ROLES)),
) -> Report:
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
