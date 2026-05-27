import logging

from celery import Celery, Task
from kombu import Queue

from app.core.config import settings

logger = logging.getLogger(__name__)


class _DLQTask(Task):
    """Base task that routes permanently-failed jobs to the dead_letter queue."""

    abstract = True

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        if self.request.retries >= self.max_retries:
            logger.error(
                "Task %s[%s] exhausted retries — routing to dead_letter. Error: %s",
                self.name, task_id, exc,
            )
            try:
                celery_app.send_task(
                    "dead_letter.record",
                    args=[self.name, task_id, str(exc)],
                    queue="dead_letter",
                )
            except Exception:
                pass
        super().on_failure(exc, task_id, args, kwargs, einfo)


celery_app = Celery(
    "app",
    broker=settings.redis_url,
    backend=settings.redis_url,
    task_cls=_DLQTask,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.normalization_tasks",
        "app.tasks.ai_tasks",
        "app.tasks.rag_tasks",
        "app.tasks.report_tasks",
    ],
)
celery_app.conf.update(
    # ── Queues ────────────────────────────────────────────────────────────
    task_default_queue="default",
    task_queues=(
        Queue("default"),
        Queue("scans"),
        Queue("analysis"),
        Queue("rag"),
        Queue("reports"),
        Queue("dead_letter"),
    ),
    task_routes={
        "scan.start":      {"queue": "scans"},
        "ai.analyze":      {"queue": "analysis"},
        "rag.ingest":      {"queue": "rag"},
        "report.generate": {"queue": "reports"},
    },

    # ── Reliability ───────────────────────────────────────────────────────
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,

    # ── Timeouts ──────────────────────────────────────────────────────────
    task_time_limit=1200,
    task_soft_time_limit=900,

    # ── Result backend TTL — prevents Redis OOM ───────────────────────────
    result_expires=86400,   # 24 h

    broker_transport_options={"priority_steps": list(range(10))},

    # ── Beat schedule ─────────────────────────────────────────────────────
    beat_schedule={
        "rag-reindex-stale": {
            "task": "rag.reindex_stale",
            "schedule": 3600.0,  # every 1 hour
        },
    },
)
