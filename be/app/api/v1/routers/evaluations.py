"""
Pipeline evaluation router.

Endpoints:
  POST /api/v1/evaluations/{scan_id}   — run evaluator, cache result 24h
  GET  /api/v1/evaluations/{scan_id}   — return cached result (or 404)
  POST /api/v1/evaluations/suite       — run offline eval suite (no DB, for CI health check)
"""
from __future__ import annotations

import json
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()

_CACHE_TTL = 86400  # 24 h
_CACHE_PREFIX = "eval:result:"

ANALYST_ROLES = ["analyst", "admin"]


def _cache_key(scan_id: str | UUID) -> str:
    return f"{_CACHE_PREFIX}{scan_id}"


@router.post("/{scan_id}")
def run_evaluation(
    scan_id: UUID,
    db: Session = Depends(get_db),
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> dict:
    """Run pipeline evaluation for a completed scan and cache the result."""
    from app.services.agents.evaluator import PipelineEvaluator

    evaluator = PipelineEvaluator(scan_id=scan_id, db=db)
    report = evaluator.evaluate()
    result = report.as_dict()

    try:
        from app.core.cache import get_redis
        get_redis().setex(_cache_key(scan_id), _CACHE_TTL, json.dumps(result))
    except Exception as exc:
        logger.warning("Could not cache eval result: %s", exc)

    return result


@router.get("/{scan_id}")
def get_evaluation(
    scan_id: UUID,
    _user: object = Depends(require_roles(ANALYST_ROLES)),
) -> dict:
    """Return cached evaluation result for a scan."""
    try:
        from app.core.cache import get_redis
        raw = get_redis().get(_cache_key(scan_id))
        if raw:
            return json.loads(raw)
    except Exception as exc:
        logger.warning("Cache read failed: %s", exc)

    raise HTTPException(
        status_code=404,
        detail="No evaluation found for this scan. POST to /evaluations/{scan_id} first.",
    )


@router.post("/suite/run")
def run_eval_suite(
    _user: object = Depends(require_roles(["admin"])),
) -> dict:
    """Run the offline eval test suite (no DB required). Used by CI health checks."""
    from app.services.agents.evaluator import run_eval_suite

    results = run_eval_suite()
    passed = sum(1 for r in results if r["passed"])
    return {
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
    }
