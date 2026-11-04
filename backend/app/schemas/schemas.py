"""SENTINEL — Pydantic schemas for API request/response validation."""

from __future__ import annotations
import re
from datetime import datetime
from uuid import UUID
from typing import Optional, List, Any

from pydantic import BaseModel, Field, field_validator

from app.models.models import TenantTier, UserRole, JobStatus, Verdict

EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _clean_text(value: str, field_name: str) -> str:
    value = value.strip()
    if _CONTROL_CHARS.search(value):
        raise ValueError(f"{field_name} contains invalid characters")
    return value


# ── Auth Schemas ─────────────────────────────────────────────────

class UserRegister(BaseModel):
    email: str = Field(
        ...,
        min_length=3,
        max_length=320,
        pattern=EMAIL_PATTERN,
        description="User email address",
    )
    password: str = Field(..., min_length=12, max_length=128, description="Password (min 12 chars)")
    tenant_name: str = Field(..., min_length=1, max_length=100, description="Organization name")

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value):
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("tenant_name")
    @classmethod
    def clean_tenant_name(cls, value: str) -> str:
        value = _clean_text(value, "Name")
        if not value:
            raise ValueError("Name is required")
        return value


class UserLogin(BaseModel):
    email: str = Field(
        ...,
        min_length=3,
        max_length=320,
        pattern=EMAIL_PATTERN,
    )
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value):
        return value.strip().lower() if isinstance(value, str) else value


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: UUID
    tenant_id: UUID


class UserProfileResponse(BaseModel):
    user_id: UUID
    tenant_id: UUID
    email: str
    role: UserRole
    tenant_name: str
    tenant_tier: TenantTier


# ── Job Schemas ──────────────────────────────────────────────────

class AnalysisJobCreate(BaseModel):
    """Internal schema — not exposed to API (file comes via multipart)."""
    file_name: str
    file_size_bytes: int
    file_hash_sha256: str
    minio_object_path: str


class AnalysisJobResponse(BaseModel):
    job_id: UUID
    status: JobStatus
    progress_percent: int = 0
    message: str = "File ingested successfully."
    poll_url: str

    model_config = {"from_attributes": True}


class AnalysisJobDetail(BaseModel):
    job_id: UUID
    file_name: str
    file_size_bytes: int
    file_hash_sha256: str
    status: JobStatus
    progress_percent: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    report_url: Optional[str] = None
    error_message: Optional[str] = None

    model_config = {"from_attributes": True}


class JobListResponse(BaseModel):
    jobs: List[AnalysisJobDetail]
    total: int
    page: int
    per_page: int


# ── Report Schemas ───────────────────────────────────────────────

class ThreatReportResponse(BaseModel):
    id: UUID
    file_name: Optional[str] = None
    file_hash_sha256: str
    severity_score: int
    verdict: Verdict
    ai_narrative: Optional[str] = None
    ai_available: bool = False
    static_data: Optional[dict] = None
    dynamic_data: Optional[dict] = None
    mitre_mappings: Optional[list] = None
    iocs: Optional[dict] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# -- Detection Schemas ---------------------------------------------------------

class SimilarReportMatch(BaseModel):
    file_name: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    verdict: Optional[str] = None
    severity_score: Optional[int] = None
    created_at: Optional[str] = None
    similarity_score: int = 0
    matched_behaviors: List[str] = Field(default_factory=list)
    shared_api_tokens: List[str] = Field(default_factory=list)
    shared_iocs: List[str] = Field(default_factory=list)


class BehaviorSimilarityResponse(BaseModel):
    hash: str
    matches: List[SimilarReportMatch] = Field(default_factory=list)
    match_count: int = 0
    method: str = "not_available"


class DetectionPackRequest(BaseModel):
    targets: List[str] = Field(
        default_factory=lambda: ["yara", "sigma", "splunk"],
        min_length=1,
        max_length=10,
    )
    strictness: str = Field("balanced", max_length=20)

    @field_validator("targets")
    @classmethod
    def limit_target_length(cls, value: List[str]) -> List[str]:
        if any(len(target) > 20 for target in value):
            raise ValueError("Detection target names must be 20 characters or fewer")
        return value


class DetectionRuleResponse(BaseModel):
    format: str
    name: str
    confidence: float
    validation_status: str
    evidence: List[str] = Field(default_factory=list)
    content: Any


class DetectionPackResponse(BaseModel):
    file_hash_sha256: str
    strictness: str
    source_report_id: str
    evidence_count: int
    rules: List[DetectionRuleResponse] = Field(default_factory=list)


# -- Feedback and Graph Schemas ------------------------------------------------

class AnalystFeedbackRequest(BaseModel):
    type: str = Field(..., min_length=1, max_length=32, pattern=r"^[a-z_]+$")
    value: str = Field(..., min_length=1, max_length=200)
    comment: Optional[str] = Field(None, max_length=2000)

    @field_validator("value")
    @classmethod
    def clean_value(cls, value: str) -> str:
        value = _clean_text(value, "Feedback value")
        if not value:
            raise ValueError("Feedback value is required")
        return value

    @field_validator("comment")
    @classmethod
    def clean_comment(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        # Comments may span lines; reject other control characters.
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
            raise ValueError("Comment contains invalid characters")
        return value.strip() or None


class AnalystFeedbackEntry(BaseModel):
    id: str
    type: str
    value: str
    comment: Optional[str] = None
    created_at: str


class AnalystFeedbackResponse(BaseModel):
    file_hash_sha256: str
    feedback: AnalystFeedbackEntry
    feedback_count: int


class GraphRelationshipResponse(BaseModel):
    entity_type: str
    entity_id: str
    depth: int
    method: str
    nodes: List[dict] = Field(default_factory=list)
    edges: List[dict] = Field(default_factory=list)


# -- Health --------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    db: str = "connected"
    redis: str = "connected"
    minio: str = "connected"
