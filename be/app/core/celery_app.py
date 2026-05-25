from celery import Celery
from kombu import Queue

from app.core.config import settings

celery_app = Celery(
    "app",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.normalization_tasks",
        "app.tasks.ai_tasks",
        "app.tasks.rag_tasks",
        "app.tasks.report_tasks",
    ],
)
celery_app.conf.update(
    task_default_queue="default",
    task_queues=(
        Queue("default"),
        Queue("scans"),
        Queue("analysis"),
        Queue("rag"),
        Queue("reports"),
    ),
    task_routes={
        "scan.start": {"queue": "scans"},
        "ai.analyze": {"queue": "analysis"},
        "rag.ingest": {"queue": "rag"},
        "report.generate": {"queue": "reports"},
    },
    task_time_limit=1200,
    task_soft_time_limit=900,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    broker_transport_options={"priority_steps": list(range(10))},
)
