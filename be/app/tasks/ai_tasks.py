"""
Checkpointed AI analysis pipeline.

Each step is idempotent: if a step was already completed (recorded in Redis),
it is skipped on retry. Only the failed step re-runs.

Redis keys: ai:pipeline:{scan_id}:step:{step_name}  →  "done"
TTL: 24 hours
"""
import logging
import uuid

from app.core.celery_app import celery_app
from app.db.models.finding import Finding
from app.db.session import SessionLocal

logger = logging.getLogger(__name__)

_STEP_TTL = 86400  # 24 h
_STEPS_TOTAL = 7


def _publish_step(scan_id: str, step: int, step_name: str, status: str = "done") -> None:
    try:
        from app.api.v1.routers.scans import publish_scan_event
        publish_scan_event(scan_id, {
            "status": "ai_progress",
            "scan_id": scan_id,
            "step": step,
            "steps_total": _STEPS_TOTAL,
            "step_name": step_name,
            "step_status": status,
        })
    except Exception as exc:
        logger.debug("publish_step skip: %s", exc)


# ── Checkpoint helpers ────────────────────────────────────────────────────────

def _step_key(scan_id: str, step: str) -> str:
    return f"ai:pipeline:{scan_id}:step:{step}"


def _step_done(redis_client, scan_id: str, step: str) -> bool:
    try:
        return redis_client.get(_step_key(scan_id, step)) == "done"
    except Exception:
        return False


def _mark_done(redis_client, scan_id: str, step: str) -> None:
    try:
        redis_client.setex(_step_key(scan_id, step), _STEP_TTL, "done")
    except Exception:
        pass


# ── Finding helpers ───────────────────────────────────────────────────────────

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
        "risk_score": finding.risk_score,
        "false_positive_score": finding.false_positive_score,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "duplicate_group": finding.duplicate_group,
        "remediation": finding.remediation,
    }


def _flush(session, findings: list[Finding], data: list[dict], fields: list[str]) -> None:
    """Write specific fields from data dicts back to ORM objects and commit."""
    score_map = {item["id"]: item for item in data}
    for f in findings:
        payload = score_map.get(str(f.id), {})
        for field in fields:
            if field in payload:
                setattr(f, field, payload[field])
    session.commit()


# ── Main task ─────────────────────────────────────────────────────────────────

@celery_app.task(
    name="ai.analyze",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    retry_kwargs={"max_retries": 3},
)
def analyze_scan(scan_id: str) -> dict:
    from app.core.cache import get_redis
    from app.services.ai import remediation as remediation_svc
    from app.services.ai.confidence import enrich_with_confidence
    from app.services.ai.cwe_mapper import map_cwe
    from app.services.ai.cvss_scorer import score as cvss_score
    from app.services.ai.duplicate_detector import detect as detect_duplicates
    from app.services.ai.false_positive import analyze as analyze_false_positive
    from app.services.ai.risk_prioritizer import prioritize

    redis_client = get_redis()
    session = SessionLocal()
    scan_uuid = uuid.UUID(scan_id)

    try:
        findings = (
            session.query(Finding)
            .filter(Finding.scan_id == scan_uuid)
            .order_by(Finding.created_at.asc())
            .all()
        )
        if not findings:
            return {"scan_id": scan_id, "status": "ok", "count": 0}

        # Reload data from DB each time so we pick up partial progress on retry
        data = [_finding_to_dict(f) for f in findings]

        _publish_step(scan_id, 0, "start", status="running")

        # ── Step 1: CWE mapping ───────────────────────────────────────────
        if not _step_done(redis_client, scan_id, "cwe_map"):
            logger.info("AI pipeline scan=%s step=cwe_map", scan_id)
            data = map_cwe(data)
            _flush(session, findings, data, ["cwe"])
            _mark_done(redis_client, scan_id, "cwe_map")
            _publish_step(scan_id, 1, "cwe_map")
        else:
            logger.debug("AI pipeline scan=%s step=cwe_map SKIP (already done)", scan_id)

        # ── Step 2: Risk scoring ─────────────────────────────────────────
        if not _step_done(redis_client, scan_id, "risk_score"):
            logger.info("AI pipeline scan=%s step=risk_score", scan_id)
            data = prioritize(data)
            _flush(session, findings, data, ["risk_score"])
            _mark_done(redis_client, scan_id, "risk_score")
            _publish_step(scan_id, 2, "risk_score")
        else:
            logger.debug("AI pipeline scan=%s step=risk_score SKIP", scan_id)

        # ── Step 3: False positive scoring ───────────────────────────────
        if not _step_done(redis_client, scan_id, "false_positive"):
            logger.info("AI pipeline scan=%s step=false_positive", scan_id)
            data = analyze_false_positive(data)
            _flush(session, findings, data, ["false_positive_score"])
            _mark_done(redis_client, scan_id, "false_positive")
            _publish_step(scan_id, 3, "false_positive")
        else:
            logger.debug("AI pipeline scan=%s step=false_positive SKIP", scan_id)

        # ── Step 4: CVSS scoring ─────────────────────────────────────────
        if not _step_done(redis_client, scan_id, "cvss_score"):
            logger.info("AI pipeline scan=%s step=cvss_score", scan_id)
            data = cvss_score(data)
            _flush(session, findings, data, ["cvss_score", "cvss_vector"])
            _mark_done(redis_client, scan_id, "cvss_score")
            _publish_step(scan_id, 4, "cvss_score")
        else:
            logger.debug("AI pipeline scan=%s step=cvss_score SKIP", scan_id)

        # ── Step 5: Deduplication ────────────────────────────────────────
        if not _step_done(redis_client, scan_id, "dedup"):
            logger.info("AI pipeline scan=%s step=dedup", scan_id)
            data = detect_duplicates(data)
            _flush(session, findings, data, ["duplicate_group"])
            _mark_done(redis_client, scan_id, "dedup")
            _publish_step(scan_id, 5, "dedup")
        else:
            logger.debug("AI pipeline scan=%s step=dedup SKIP", scan_id)

        # ── Step 6: Remediation ──────────────────────────────────────────
        if not _step_done(redis_client, scan_id, "remediation"):
            logger.info("AI pipeline scan=%s step=remediation", scan_id)
            remediations = remediation_svc.generate(data)
            rem_map = {item["finding_id"]: item for item in remediations}
            for f in findings:
                rem = rem_map.get(str(f.id), {})
                f.remediation = {k: v for k, v in rem.items() if k != "finding_id"} or None
            session.commit()
            _mark_done(redis_client, scan_id, "remediation")
            _publish_step(scan_id, 6, "remediation")
        else:
            logger.debug("AI pipeline scan=%s step=remediation SKIP", scan_id)

        # ── Step 7: Confidence scoring (local, no LLM) ───────────────────
        if not _step_done(redis_client, scan_id, "confidence"):
            logger.info("AI pipeline scan=%s step=confidence", scan_id)
            data = [_finding_to_dict(f) for f in findings]  # reload after all steps
            data = enrich_with_confidence(data)
            _flush(session, findings, data, ["ai_confidence", "ai_confidence_tier"])
            _mark_done(redis_client, scan_id, "confidence")
            _publish_step(scan_id, 7, "confidence")

        # Emit confidence histogram per finding
        try:
            from app.core.metrics import LLM_CONFIDENCE_HISTOGRAM
            data_final = [_finding_to_dict(f) for f in findings]
            for f in data_final:
                score = f.get("ai_confidence")
                tier = f.get("ai_confidence_tier") or "unknown"
                if score is not None:
                    LLM_CONFIDENCE_HISTOGRAM.labels(tier=tier.lower()).observe(score)
        except Exception:
            pass

        _publish_step(scan_id, 7, "complete", status="complete")
        return {"scan_id": scan_id, "status": "ok", "count": len(findings)}

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
