import logging
import uuid
from datetime import datetime, timezone

from app.core.celery_app import celery_app
from app.db.models.finding import Finding
from app.db.models.scan import Scan
from app.db.session import SessionLocal
from app.services.normalization.normalize import normalize
from app.services.scanners import nikto, zap
from app.tasks.ai_tasks import analyze_scan

logger = logging.getLogger(__name__)


def _make_cancel_fn(session, scan_uuid):
    """Returns a callable that checks whether the scan has been cancelled in DB."""
    def is_cancelled() -> bool:
        session.expire_all()
        scan = session.get(Scan, scan_uuid)
        return scan is not None and scan.status == "cancelled"
    return is_cancelled


@celery_app.task(
    name="scan.start",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    retry_kwargs={"max_retries": 2},
)
def start_scan(
    scan_id: str, target_url: str, scanner: str, config: dict | None = None
) -> dict:
    session = SessionLocal()
    scan_uuid = uuid.UUID(scan_id)
    scan = session.get(Scan, scan_uuid)

    if not scan:
        session.close()
        return {"scan_id": scan_id, "status": "missing"}

    # Bail out early if already cancelled before the task even starts
    if scan.status == "cancelled":
        session.close()
        return {"scan_id": scan_id, "status": "cancelled"}

    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    session.commit()

    cancel_fn = _make_cancel_fn(session, scan_uuid)

    try:
        if scanner == "zap":
            raw = zap.run(target_url, config, cancel_fn=cancel_fn)
        elif scanner == "nikto":
            raw = nikto.run(target_url, config)
        else:
            raw = {"scanner": scanner, "target": target_url, "alerts": []}

        scan.raw_output = raw
        normalized = normalize(scanner, raw)
        for item in normalized:
            finding = Finding(
                scan_id=scan_uuid,
                type=item.get("type", scanner),
                severity=item.get("severity", "Info"),
                title=item.get("title", "Finding"),
                description=item.get("description"),
                evidence=item.get("evidence") or {},
                cwe=item.get("cwe"),
                owasp=item.get("owasp"),
            )
            session.add(finding)

        scan.status = "completed"
        scan.finished_at = datetime.now(timezone.utc)
        session.commit()

        analyze_scan.apply_async((scan_id,), queue="analysis", priority=5)
        return {"scan_id": scan_id, "status": scan.status, "count": len(normalized)}

    except InterruptedError:
        # User cancelled — status already set to "cancelled" by the API endpoint.
        # Just ensure finished_at is recorded; do NOT retry and do NOT start AI.
        session.expire_all()
        scan = session.get(Scan, scan_uuid)
        if scan and not scan.finished_at:
            scan.finished_at = datetime.now(timezone.utc)
            session.commit()
        logger.info("Scan %s was cancelled by user", scan_id)
        return {"scan_id": scan_id, "status": "cancelled"}

    except Exception as exc:
        logger.exception("Scan failed: %s", exc)
        scan.status = "failed"
        scan.finished_at = datetime.now(timezone.utc)
        session.commit()
        raise

    finally:
        session.close()
