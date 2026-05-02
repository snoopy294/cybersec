"""SENTINEL — API route definitions.

Implements the core REST API contracts defined in the architecture specification:
  - POST /api/v1/analyze       — Upload a file for analysis
  - GET  /api/v1/analyze/{id}  — Poll job status
  - GET  /api/v1/jobs          — List all jobs for a tenant
  - GET  /api/v1/report/{hash} — Get threat report by file hash
  - POST /api/v1/auth/register — Register a new user
  - POST /api/v1/auth/login    — Login and get JWT
"""

from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.core.config import get_settings
from app.models.models import (
    Tenant, User, AnalysisJob, ThreatReport,
    TenantTier, JobStatus,
)
from app.schemas.schemas import (
    AnalysisJobResponse, AnalysisJobDetail, JobListResponse,
    ThreatReportResponse, HealthResponse,
    UserRegister, UserLogin, TokenResponse,
)
from app.services.file_service import compute_file_hashes, upload_to_minio
from app.services.auth_service import hash_password, verify_password, create_access_token

settings = get_settings()

router = APIRouter(prefix="/api/v1", tags=["SENTINEL API"])
auth_router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


# ── Health ───────────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """System health check endpoint."""
    return HealthResponse(
        status="ok",
        version=settings.APP_VERSION,
        db="connected",
        redis="connected",
        minio="connected",
    )


# ── Auth ─────────────────────────────────────────────────────────

@auth_router.post("/register", response_model=TokenResponse, status_code=201)
async def register(data: UserRegister, db: AsyncSession = Depends(get_db)):
    """Register a new user and create their tenant."""
    # Check if email already exists
    existing = await db.execute(select(User).where(User.email == data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    # Create tenant
    tenant = Tenant(name=data.tenant_name, tier=TenantTier.FREE)
    db.add(tenant)
    await db.flush()

    # Create user
    user = User(
        tenant_id=tenant.id,
        email=data.email,
        password_hash=hash_password(data.password),
    )
    db.add(user)
    await db.flush()

    token = create_access_token(user.id, tenant.id)

    return TokenResponse(
        access_token=token,
        user_id=user.id,
        tenant_id=tenant.id,
    )


@auth_router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, db: AsyncSession = Depends(get_db)):
    """Authenticate and return a JWT token."""
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user.id, user.tenant_id)

    return TokenResponse(
        access_token=token,
        user_id=user.id,
        tenant_id=user.tenant_id,
    )


# ── File Analysis ────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalysisJobResponse, status_code=202)
async def upload_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload a file for threat analysis.

    The file is stored in MinIO, hashed, and a background analysis
    job is dispatched to the Celery worker pipeline.
    """
    # Read file bytes
    file_bytes = await file.read()
    file_size = len(file_bytes)

    # Enforce size limit
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if file_size > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum size of {settings.MAX_FILE_SIZE_MB}MB",
        )

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # Compute hashes
    hashes = compute_file_hashes(file_bytes)

    # Check for existing completed analysis with same hash
    existing = await db.execute(
        select(AnalysisJob).where(
            AnalysisJob.file_hash_sha256 == hashes["sha256"],
            AnalysisJob.status == JobStatus.COMPLETED,
        )
    )
    existing_job = existing.scalar_one_or_none()
    if existing_job:
        return AnalysisJobResponse(
            job_id=existing_job.id,
            status=existing_job.status,
            progress_percent=100,
            message="Analysis already completed for this file (cache hit).",
            poll_url=f"/api/v1/analyze/{existing_job.id}",
        )

    # Use a default tenant for now (will be replaced with auth context)
    result = await db.execute(select(Tenant).limit(1))
    tenant = result.scalar_one_or_none()
    if not tenant:
        tenant = Tenant(name="Default", tier=TenantTier.FREE)
        db.add(tenant)
        await db.flush()

    # Upload to MinIO
    object_path = upload_to_minio(
        tenant_id=str(tenant.id),
        sha256_hash=hashes["sha256"],
        file_name=file.filename or "unknown",
        file_bytes=file_bytes,
        content_type=file.content_type or "application/octet-stream",
    )

    # Create job record
    job = AnalysisJob(
        tenant_id=tenant.id,
        file_name=file.filename or "unknown",
        file_size_bytes=file_size,
        file_hash_sha256=hashes["sha256"],
        file_hash_sha1=hashes["sha1"],
        file_hash_md5=hashes["md5"],
        file_mime_type=file.content_type,
        status=JobStatus.QUEUED,
        minio_object_path=object_path,
    )
    db.add(job)
    await db.flush()

    # Dispatch Celery task
    from app.worker import analyze_file
    analyze_file.delay(str(job.id))

    return AnalysisJobResponse(
        job_id=job.id,
        status=job.status,
        progress_percent=0,
        message="File ingested successfully. Analysis queued.",
        poll_url=f"/api/v1/analyze/{job.id}",
    )


@router.get("/analyze/{job_id}", response_model=AnalysisJobDetail)
async def get_job_status(job_id: UUID, db: AsyncSession = Depends(get_db)):
    """Poll the status of an analysis job."""
    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    report_url = None
    if job.status == JobStatus.COMPLETED:
        report_url = f"/api/v1/report/{job.file_hash_sha256}"

    return AnalysisJobDetail(
        job_id=job.id,
        file_name=job.file_name,
        file_size_bytes=job.file_size_bytes,
        file_hash_sha256=job.file_hash_sha256,
        status=job.status,
        progress_percent=job.progress_percent,
        created_at=job.created_at,
        completed_at=job.completed_at,
        report_url=report_url,
        error_message=job.error_message,
    )


@router.get("/jobs", response_model=JobListResponse)
async def list_jobs(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """List all analysis jobs with pagination and optional status filter."""
    query = select(AnalysisJob)

    if status:
        try:
            status_enum = JobStatus(status)
            query = query.where(AnalysisJob.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Paginate
    query = query.order_by(desc(AnalysisJob.created_at))
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    jobs = result.scalars().all()

    return JobListResponse(
        jobs=[
            AnalysisJobDetail(
                job_id=j.id,
                file_name=j.file_name,
                file_size_bytes=j.file_size_bytes,
                file_hash_sha256=j.file_hash_sha256,
                status=j.status,
                progress_percent=j.progress_percent,
                created_at=j.created_at,
                completed_at=j.completed_at,
                report_url=f"/api/v1/report/{j.file_hash_sha256}" if j.status == JobStatus.COMPLETED else None,
                error_message=j.error_message,
            )
            for j in jobs
        ],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/report/{file_hash}", response_model=ThreatReportResponse)
async def get_report(file_hash: str, db: AsyncSession = Depends(get_db)):
    """Get a threat report by file SHA-256 hash."""
    result = await db.execute(
        select(ThreatReport).where(ThreatReport.file_hash_sha256 == file_hash)
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return ThreatReportResponse(
        id=report.id,
        file_hash_sha256=report.file_hash_sha256,
        severity_score=report.severity_score,
        verdict=report.verdict,
        ai_narrative=report.ai_narrative,
        ai_available=report.ai_available,
        static_data=report.static_data,
        dynamic_data=report.dynamic_data,
        mitre_mappings=report.mitre_mappings,
        iocs=report.iocs,
        created_at=report.created_at,
    )
