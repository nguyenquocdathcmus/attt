from app.core.celery_app import celery_app
from app.services.normalization.normalize import normalize


@celery_app.task(name="scan.normalize")
def normalize_results(scanner: str, raw: dict) -> list[dict]:
    return normalize(scanner, raw)
