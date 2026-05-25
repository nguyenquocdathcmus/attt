import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.models.asset import Asset
from app.db.models.finding import Finding
from app.db.models.report import Report
from app.db.models.scan import Scan
from app.db.session import get_db
from app.schemas.demo import SeedOut
from app.services.reporting.generator import build_report

router = APIRouter()

ADMIN_ROLES = ["admin"]


@router.post("/seed", response_model=SeedOut)
def seed_demo_data(
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ADMIN_ROLES)),
) -> SeedOut:
    asset = Asset(url="https://demo-target.local", owner="demo")
    db.add(asset)
    db.commit()
    db.refresh(asset)

    scan = Scan(
        asset_id=asset.id,
        status="completed",
        scanner="zap",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        config={"demo": True},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    finding_payloads = [
        {
            "type": "zap",
            "severity": "High",
            "title": "Cross-site scripting in login form",
            "description": "Reflected XSS in login endpoint.",
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        {
            "type": "zap",
            "severity": "Medium",
            "title": "Missing security headers",
            "description": "CSP and HSTS headers are not configured.",
            "cwe": "CWE-693",
            "owasp": "A05:2021",
        },
        {
            "type": "nikto",
            "severity": "Low",
            "title": "Directory listing enabled",
            "description": "Server exposes directory listing in /assets/.",
            "cwe": "CWE-548",
            "owasp": "A01:2021",
        },
    ]

    finding_ids = []
    for payload in finding_payloads:
        finding = Finding(scan_id=scan.id, evidence={}, **payload)
        db.add(finding)
        db.flush()
        finding_ids.append(finding.id)

    db.commit()

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(Finding.created_at)
        .all()
    )
    report = Report(
        scan_id=scan.id,
        report_type="executive",
        content=build_report(
            [
                {
                    "id": str(item.id),
                    "type": item.type,
                    "severity": item.severity,
                    "title": item.title,
                    "description": item.description,
                    "evidence": item.evidence,
                    "cwe": item.cwe,
                    "owasp": item.owasp,
                    "false_positive_score": item.false_positive_score,
                    "risk_score": item.risk_score,
                    "created_at": item.created_at.isoformat(),
                }
                for item in findings
            ]
        ),
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return SeedOut(
        asset_id=asset.id,
        scan_id=scan.id,
        finding_ids=finding_ids,
        report_id=report.id,
    )
