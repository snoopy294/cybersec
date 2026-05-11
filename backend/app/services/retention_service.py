"""Tenant-scoped retention cleanup for old analyses and stored samples."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.models import AnalysisJob, JobStatus
from app.services.file_service import delete_stored_file

settings = get_settings()

TERMINAL_STATUSES = (JobStatus.COMPLETED.value, JobStatus.FAILED.value)


async def enforce_tenant_retention(db: AsyncSession, tenant_id: UUID) -> int:
    """Delete expired terminal jobs and unreferenced stored samples for a tenant."""
    if settings.RETENTION_DAYS <= 0 and settings.RETENTION_MAX_JOBS_PER_TENANT <= 0:
        return 0

    candidate_jobs: dict[UUID, AnalysisJob] = {}

    if settings.RETENTION_DAYS > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=settings.RETENTION_DAYS)
        result = await db.execute(
            select(AnalysisJob).where(
                AnalysisJob.tenant_id == tenant_id,
                AnalysisJob.status.in_(TERMINAL_STATUSES),
                AnalysisJob.created_at < cutoff,
            )
        )
        candidate_jobs.update({job.id: job for job in result.scalars().all()})

    if settings.RETENTION_MAX_JOBS_PER_TENANT > 0:
        result = await db.execute(
            select(AnalysisJob)
            .where(
                AnalysisJob.tenant_id == tenant_id,
                AnalysisJob.status.in_(TERMINAL_STATUSES),
            )
            .order_by(desc(AnalysisJob.created_at))
            .offset(settings.RETENTION_MAX_JOBS_PER_TENANT)
        )
        candidate_jobs.update({job.id: job for job in result.scalars().all()})

    if not candidate_jobs:
        return 0

    delete_ids = set(candidate_jobs)
    object_paths = {job.minio_object_path for job in candidate_jobs.values() if job.minio_object_path}

    removable_paths: set[str] = set()
    for object_path in object_paths:
        result = await db.execute(
            select(func.count()).select_from(AnalysisJob).where(
                AnalysisJob.minio_object_path == object_path,
                AnalysisJob.id.notin_(delete_ids),
            )
        )
        if result.scalar() == 0:
            removable_paths.add(object_path)

    for job in candidate_jobs.values():
        await db.delete(job)
    await db.flush()

    for object_path in removable_paths:
        try:
            delete_stored_file(object_path)
        except Exception as exc:
            print(f"[SENTINEL] Retention cleanup could not remove {object_path}: {exc}")

    return len(candidate_jobs)
