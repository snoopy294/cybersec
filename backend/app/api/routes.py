"""SENTINEL — API route definitions.

Implements the core REST API contracts defined in the architecture specification:
  - POST /api/v1/analyze       — Upload a file for analysis
  - GET  /api/v1/analyze/{id}  — Poll job status
  - GET  /api/v1/jobs          — List all jobs for a tenant
  - GET  /api/v1/report/{hash} — Get threat report by file hash
  - POST /api/v1/auth/register — Register a new user
  - POST /api/v1/auth/login    — Login and get JWT
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4
from typing import Optional

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Query, Body
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, text

from app.core.database import get_db
from app.core.config import get_settings
from app.models.models import (
    Tenant, User, AnalysisJob, ThreatReport,
    TenantTier, JobStatus,
)
from app.schemas.schemas import (
    AnalysisJobResponse, AnalysisJobDetail, JobListResponse,
    ThreatReportResponse, HealthResponse,
    UserRegister, UserLogin, TokenResponse, UserProfileResponse,
    BehaviorSimilarityResponse, DetectionPackRequest, DetectionPackResponse,
    AnalystFeedbackRequest, AnalystFeedbackResponse, GraphRelationshipResponse,
)
from app.services.file_service import (
    StorageConfigurationError,
    StorageOperationError,
    compute_file_hashes,
    storage_health_status,
    upload_file as store_file,
)
from app.services.auth_service import hash_password, verify_password, create_access_token, decode_access_token
from app.services.detection_service import (
    DETECTION_STRICTNESS_LEVELS,
    DETECTION_TARGETS,
    generate_detection_pack as build_detection_pack,
)
from app.services.graph_service import build_relationship_graph

settings = get_settings()
bearer_scheme = HTTPBearer(auto_error=False)

router = APIRouter(prefix="/api/v1", tags=["SENTINEL API"])
auth_router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def _latest_report_query(file_hash: str):
    return (
        select(ThreatReport)
        .join(AnalysisJob, ThreatReport.job_id == AnalysisJob.id)
        .where(ThreatReport.file_hash_sha256 == file_hash)
        .order_by(desc(ThreatReport.created_at))
        .limit(1)
    )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authentication required")

    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    if not user_id or not tenant_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    try:
        user_uuid = UUID(user_id)
        tenant_uuid = UUID(tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid token payload") from exc

    result = await db.execute(
        select(User).where(
            User.id == user_uuid,
            User.tenant_id == tenant_uuid,
            User.is_active.is_(True),
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


# ── Health ───────────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    """System health check endpoint."""
    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    redis_status = "disabled"
    if settings.REDIS_URL:
        redis_status = "configured"

    storage_status = storage_health_status()
    is_storage_ready = storage_status.endswith(":ready") or storage_status.endswith(":connected")
    return HealthResponse(
        status="ok" if db_status == "connected" and is_storage_ready else "degraded",
        version=settings.APP_VERSION,
        db=db_status,
        redis=redis_status,
        minio=storage_status,
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

    if not user or not user.is_active or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user.id, user.tenant_id)

    return TokenResponse(
        access_token=token,
        user_id=user.id,
        tenant_id=user.tenant_id,
    )


# ── Authenticated Profile ────────────────────────────────────────

@auth_router.get("/me", response_model=UserProfileResponse)
async def get_authenticated_profile(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return the authenticated user's current workspace profile."""
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=401, detail="Tenant not found")

    return UserProfileResponse(
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        email=current_user.email,
        role=current_user.role,
        tenant_name=tenant.name,
        tenant_tier=tenant.tier,
    )


# ── File Analysis ────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalysisJobResponse, status_code=202)
async def upload_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
    from app.worker import ANALYZER_VERSION

    # Check for existing completed analysis with same hash
    existing = await db.execute(
        select(AnalysisJob, ThreatReport).join(
            ThreatReport, ThreatReport.job_id == AnalysisJob.id
        ).where(
            AnalysisJob.file_hash_sha256 == hashes["sha256"],
            AnalysisJob.tenant_id == current_user.tenant_id,
            AnalysisJob.status == JobStatus.COMPLETED,
        ).order_by(desc(AnalysisJob.completed_at))
    )
    existing_result = existing.first()
    if existing_result:
        existing_job, existing_report = existing_result
        static_data = existing_report.static_data or {}
        if static_data.get("analyzer_version") == ANALYZER_VERSION:
            return AnalysisJobResponse(
                job_id=existing_job.id,
                status=existing_job.status,
                progress_percent=100,
                message="Analysis already completed for this file (cache hit).",
                poll_url=f"/api/v1/analyze/{existing_job.id}",
            )

    # Store file (local filesystem or MinIO depending on config)
    try:
        object_path = store_file(
            tenant_id=str(current_user.tenant_id),
            sha256_hash=hashes["sha256"],
            file_name=file.filename or "unknown",
            file_bytes=file_bytes,
            content_type=file.content_type or "application/octet-stream",
        )
    except (StorageConfigurationError, StorageOperationError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    # Create job record
    job = AnalysisJob(
        tenant_id=current_user.tenant_id,
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
    await db.commit()

    # Dispatch analysis (background thread or Celery)
    from app.worker import dispatch_analysis
    dispatch_analysis(str(job.id))

    return AnalysisJobResponse(
        job_id=job.id,
        status=job.status,
        progress_percent=0,
        message="File ingested successfully. Analysis queued.",
        poll_url=f"/api/v1/analyze/{job.id}",
    )


@router.get("/analyze/{job_id}", response_model=AnalysisJobDetail)
async def get_job_status(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Poll the status of an analysis job."""
    result = await db.execute(
        select(AnalysisJob).where(
            AnalysisJob.id == job_id,
            AnalysisJob.tenant_id == current_user.tenant_id,
        )
    )
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
    current_user: User = Depends(get_current_user),
):
    """List all analysis jobs with pagination and optional status filter."""
    query = select(AnalysisJob).where(AnalysisJob.tenant_id == current_user.tenant_id)

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
async def get_report(
    file_hash: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a threat report by file SHA-256 hash."""
    result = await db.execute(
        _latest_report_query(file_hash).where(AnalysisJob.tenant_id == current_user.tenant_id)
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


@router.post("/report/{file_hash}/refresh", response_model=AnalysisJobResponse, status_code=202)
async def refresh_report(
    file_hash: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Queue a fresh analysis run for an existing uploaded file."""
    result = await db.execute(
        select(AnalysisJob)
        .where(
            AnalysisJob.file_hash_sha256 == file_hash,
            AnalysisJob.tenant_id == current_user.tenant_id,
        )
        .order_by(desc(AnalysisJob.created_at))
        .limit(1)
    )
    source_job = result.scalar_one_or_none()
    if not source_job:
        raise HTTPException(status_code=404, detail="File hash not found")

    refresh_job = AnalysisJob(
        tenant_id=source_job.tenant_id,
        file_name=source_job.file_name,
        file_size_bytes=source_job.file_size_bytes,
        file_hash_sha256=source_job.file_hash_sha256,
        file_hash_sha1=source_job.file_hash_sha1,
        file_hash_md5=source_job.file_hash_md5,
        file_mime_type=source_job.file_mime_type,
        status=JobStatus.QUEUED,
        minio_object_path=source_job.minio_object_path,
    )
    db.add(refresh_job)
    await db.flush()
    await db.commit()

    from app.worker import dispatch_analysis
    dispatch_analysis(str(refresh_job.id))

    return AnalysisJobResponse(
        job_id=refresh_job.id,
        status=refresh_job.status,
        progress_percent=0,
        message="Report refresh queued.",
        poll_url=f"/api/v1/analyze/{refresh_job.id}",
    )


@router.get("/report/{file_hash}/similar", response_model=BehaviorSimilarityResponse)
async def get_behavior_similarity(
    file_hash: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return behavior similarity matches from the latest report."""
    result = await db.execute(
        _latest_report_query(file_hash).where(AnalysisJob.tenant_id == current_user.tenant_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    static_data = report.static_data or {}
    cross_reference = static_data.get("cross_reference") or {
        "match_count": 0,
        "top_matches": [],
        "method": "not_available",
    }
    return {
        "hash": file_hash,
        "matches": cross_reference.get("top_matches", []),
        "match_count": cross_reference.get("match_count", 0),
        "method": cross_reference.get("method", "not_available"),
    }


@router.post("/report/{file_hash}/detections", response_model=DetectionPackResponse)
async def generate_detection_pack(
    file_hash: str,
    payload: Optional[DetectionPackRequest] = Body(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate draft detection artifacts from report evidence."""
    result = await db.execute(
        _latest_report_query(file_hash).where(AnalysisJob.tenant_id == current_user.tenant_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    payload = payload or DetectionPackRequest()
    targets = payload.targets
    normalized_targets = [str(target).lower() for target in targets]
    invalid = [target for target in normalized_targets if target not in DETECTION_TARGETS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unsupported detection target(s): {', '.join(invalid)}")

    strictness = payload.strictness.lower()
    if strictness not in DETECTION_STRICTNESS_LEVELS:
        raise HTTPException(status_code=400, detail="strictness must be strict, balanced, or broad")

    return build_detection_pack(report, normalized_targets, strictness)


@router.post("/report/{file_hash}/feedback", response_model=AnalystFeedbackResponse)
async def submit_analyst_feedback(
    file_hash: str,
    payload: AnalystFeedbackRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Attach analyst feedback to a living report."""
    result = await db.execute(
        _latest_report_query(file_hash).where(AnalysisJob.tenant_id == current_user.tenant_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    created_at = datetime.now(timezone.utc).isoformat()
    feedback = {
        "id": str(uuid4()),
        "type": payload.type,
        "value": payload.value,
        "comment": payload.comment,
        "created_at": created_at,
    }

    static_data = dict(report.static_data or {})
    feedback_items = list(static_data.get("analyst_feedback") or [])
    feedback_items.append(feedback)
    static_data["analyst_feedback"] = feedback_items

    event_log = list(static_data.get("event_log") or [])
    event_log.append({
        "type": "feedback.submitted",
        "created_at": created_at,
        "feedback_id": feedback["id"],
    })
    static_data["event_log"] = event_log[-100:]

    report.static_data = static_data
    await db.commit()

    return {
        "file_hash_sha256": report.file_hash_sha256,
        "feedback": feedback,
        "feedback_count": len(feedback_items),
    }


@router.get("/graph/relationships", response_model=GraphRelationshipResponse)
async def get_graph_relationships(
    entity_type: str = Query(...),
    entity_id: str = Query(...),
    depth: int = Query(1, ge=1, le=2),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return report-derived graph relationships for files, behaviors, and IOCs."""
    normalized_type = entity_type.lower()
    if normalized_type not in {"file", "behavior", "ioc"}:
        raise HTTPException(status_code=400, detail="entity_type must be file, behavior, or ioc")

    if normalized_type == "file":
        result = await db.execute(
            _latest_report_query(entity_id).where(AnalysisJob.tenant_id == current_user.tenant_id)
        )
        report = result.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        reports = [report]
    else:
        result = await db.execute(
            select(ThreatReport)
            .join(AnalysisJob, ThreatReport.job_id == AnalysisJob.id)
            .where(AnalysisJob.tenant_id == current_user.tenant_id)
            .order_by(desc(ThreatReport.created_at))
            .limit(250)
        )
        reports = result.scalars().all()

    return build_relationship_graph(normalized_type, entity_id, depth, reports)
