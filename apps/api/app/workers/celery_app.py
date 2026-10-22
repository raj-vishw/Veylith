from celery import Celery
from celery.schedules import crontab

from ..config import get_settings

s = get_settings()

# Always on: retries any background job whose immediate dispatch failed (e.g. while Redis was unreachable).
OUTBOX = {"dispatch-outbox": {"task": "app.workers.tasks.dispatch_outbox", "schedule": 10.0}}

celery = Celery("veylith", broker=s.redis_url, backend=s.redis_url, include=["app.workers.tasks"])
celery.conf.update(
    task_always_eager=s.celery_eager,
    task_eager_propagates=True,
    task_acks_late=True,  # a crashed worker's task is redelivered instead of lost
    worker_prefetch_multiplier=1,
    task_default_queue="default",
    task_routes={"app.workers.tasks.build_report": {"queue": "reports"}},
    task_soft_time_limit=240,
    task_time_limit=300,
    result_expires=3600,
    broker_connection_retry_on_startup=True,
    timezone="UTC",
    beat_schedule=(
        {
            **OUTBOX,
            "ingest-kev-daily": {"task": "app.workers.tasks.scheduled_ingest", "schedule": crontab(hour=3, minute=15), "args": ("kev",)},
            "ingest-nvd-hourly": {"task": "app.workers.tasks.scheduled_ingest", "schedule": crontab(minute=20), "args": ("nvd",)},
        }
        if s.scheduled_ingestion
        else OUTBOX
    ),
)
