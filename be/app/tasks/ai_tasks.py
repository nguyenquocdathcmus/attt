import uuid

from app.core.celery_app import celery_app
from app.db.models.finding import Finding
from app.db.session import SessionLocal
from app.services.ai import remediation as remediation_svc
from app.services.ai.cwe_mapper import map_cwe
from app.services.ai.cvss_scorer import score as cvss_score
from app.services.ai.duplicate_detector import detect as detect_duplicates
from app.services.ai.false_positive import analyze as analyze_false_positive
from app.services.ai.risk_prioritizer import prioritize


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
    }


@celery_app.task(
    name="ai.analyze",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    retry_kwargs={"max_retries": 2},
)
def analyze_scan(scan_id: str) -> dict:
    session = SessionLocal()
    scan_uuid = uuid.UUID(scan_id)

    try:
        findings = (
            session.query(Finding)
            .filter(Finding.scan_id == scan_uuid)
            .order_by(Finding.created_at.asc())
            .all()
        )
        data = [_finding_to_dict(item) for item in findings]

        # Pipeline — each step enriches the shared list in place:
        # 1. Fill missing CWE (static lookup → LLM batch)
        data = map_cwe(data)
        # 2. Risk scoring (severity baseline → LLM batch for High/Critical/Medium)
        data = prioritize(data)
        # 3. False positive scoring (LLM batch, all findings)
        data = analyze_false_positive(data)
        # 4. CVSS v3.1 scoring (severity defaults → LLM batch for High/Critical/Medium)
        data = cvss_score(data)
        # 5. Duplicate / root-cause grouping (heuristic, no LLM)
        data = detect_duplicates(data)
        # 6. Remediation guidance (LLM batch for High/Critical, templates for rest)
        remediations = remediation_svc.generate(data)

        score_map = {item["id"]: item for item in data}
        rem_map = {item["finding_id"]: item for item in remediations}

        for finding in findings:
            fid = str(finding.id)
            payload = score_map.get(fid, {})

            finding.risk_score = payload.get("risk_score", finding.risk_score)
            finding.false_positive_score = payload.get(
                "false_positive_score", finding.false_positive_score
            )
            finding.cvss_score = payload.get("cvss_score", finding.cvss_score)
            finding.cvss_vector = payload.get("cvss_vector", finding.cvss_vector)
            finding.duplicate_group = payload.get("duplicate_group", finding.duplicate_group)

            # Persist CWE if the mapper filled it in
            if payload.get("cwe") and not finding.cwe:
                finding.cwe = payload["cwe"]

            rem = rem_map.get(fid, {})
            finding.remediation = {k: v for k, v in rem.items() if k != "finding_id"} or None

        session.commit()
        return {"scan_id": scan_id, "status": "ok", "count": len(findings)}
    finally:
        session.close()
