"""SENTINEL — Pydantic schemas for API request/response validation."""

from __future__ import annotations
from datetime import datetime
from uuid import UUID
from typing import Optional, List, Any

from pydantic import BaseModel, EmailStr, Field

from app.models.models import TenantTier, UserRole, JobStatus, Verdict


# ── Auth Schemas ─────────────────────────────────────────────────

class UserRegister(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (min 8 chars)")
    tenant_name: str = Field(..., min_length=1, description="Organization name")


class UserLogin(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: UUID
    tenant_id: UUID


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
    file_hash_sha256: str
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
    targets: List[str] = Field(default_factory=lambda: ["yara", "sigma", "splunk"])
    strictness: str = "balanced"


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


# -- Health --------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    db: str = "connected"
    redis: str = "connected"
    minio: str = "connected"
