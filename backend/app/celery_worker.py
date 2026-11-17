"""SENTINEL — Celery app and analysis task.

Used when USE_CELERY=true. Start a worker with:

    celery -A app.celery_worker:celery_app worker --loglevel=info

The API enqueues analyze_file_task through app.worker.dispatch_analysis, and
the worker runs the same run_analysis pipeline the thread mode uses.
"""

import logging
import random

from celery import Celery

from app.core.config import get_settings
from app.services.file_service import TransientStorageError
from app.worker import run_analysis

settings = get_settings()
logger = logging.getLogger("sentinel.celery")

# Thread mode leaves REDIS_URL empty; the fallback only lets this module import.
broker_url = settings.REDIS_URL or "redis://localhost:6379/0"

celery_app = Celery("sentinel", broker=broker_url, backend=broker_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    result_expires=24 * 60 * 60,
    timezone="UTC",
    enable_utc=True,
    # Ack only after the task finishes, so a worker that dies mid-task does not
    # lose the job. run_analysis is idempotent, so redelivery is safe.
    task_acks_late=True,
    # With late acks, prefetching would park extra jobs on a busy worker.
    worker_prefetch_multiplier=1,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
)


def retry_countdown(retries: int) -> float:
    """Exponential backoff with jitter: base * 2**retries, capped."""
    delay = min(
        settings.CELERY_RETRY_BACKOFF_MAX_SECONDS,
        settings.CELERY_RETRY_BACKOFF_SECONDS * (2 ** retries),
    )
    return delay * random.uniform(0.8, 1.2)


@celery_app.task(
    bind=True,
    name="sentinel.analyze_file",
    acks_late=True,
    soft_time_limit=settings.CELERY_TASK_SOFT_TIME_LIMIT_SECONDS,
    time_limit=settings.CELERY_TASK_TIME_LIMIT_SECONDS,
    max_retries=settings.CELERY_MAX_RETRIES,
)
def analyze_file_task(self, job_id: str):
    """Run static analysis for one job.

    Only transient storage errors are retried, with backoff. On the last
    attempt run_analysis is told not to raise them, so the job ends FAILED
    instead of being left QUEUED. Every other error fails the job once.
    """
    retries_left = self.request.retries < self.max_retries
    try:
        return run_analysis(job_id, raise_transient=retries_left)
    except TransientStorageError as exc:
        countdown = retry_countdown(self.request.retries)
        logger.warning(
            "Job %s: transient storage error, retry %d/%d in %.0fs",
            job_id, self.request.retries + 1, self.max_retries, countdown,
        )
        raise self.retry(exc=exc, countdown=countdown)
