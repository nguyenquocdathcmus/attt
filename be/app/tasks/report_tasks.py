import uuid

from app.core.celery_app import celery_app
from app.db.models.finding import Finding
from app.db.models.report import Report
from app.db.models.scan import Scan
from app.db.session import SessionLocal
from app.services.reporting.generator import build_report


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "id": str(finding.id),
        "type": finding.type,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "evidence": finding.evidence,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "false_positive_score": finding.false_positive_score,
        "risk_score": finding.risk_score,
        "remediation": finding.remediation,
        "created_at": finding.created_at.isoformat(),
    }


@celery_app.task(
    name="report.generate",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    retry_kwargs={"max_retries": 2},
)
def generate_report(report_id: str, scan_id: str, report_type: str) -> dict:
    session = SessionLocal()
    try:
        report = session.get(Report, uuid.UUID(report_id))
        if not report:
            return {"report_id": report_id, "status": "missing"}

        scan = session.get(Scan, uuid.UUID(scan_id))
        raw_output = scan.raw_output if scan else None

        findings = (
            session.query(Finding)
            .filter(Finding.scan_id == uuid.UUID(scan_id))
            .all()
        )

        report.content = build_report(
            [_finding_to_dict(f) for f in findings],
            raw_output=raw_output,
        )
        report.report_type = report_type
        session.commit()

        return {"report_id": report_id, "status": "ok"}
    finally:
        session.close()
