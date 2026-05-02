"""SENTINEL — SQLAlchemy ORM models.

Defines the core data entities: Tenant, User, AnalysisJob, and ThreatReport.
These map directly to the schemas defined in the architecture specification.

Compatible with both SQLite (local dev) and PostgreSQL (production).
"""

import uuid
import enum
import json
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, BigInteger, Text, Enum, ForeignKey,
    DateTime, Boolean, Index, TypeDecorator, types
)
from sqlalchemy.orm import relationship

from app.core.database import Base


# ── Cross-DB Compatible Types ────────────────────────────────────

class GUID(TypeDecorator):
    """Platform-independent GUID type.
    Uses String(36) on SQLite, native UUID on PostgreSQL.
    """
    impl = String(36)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return str(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return uuid.UUID(value) if not isinstance(value, uuid.UUID) else value
        return value


class JSONType(TypeDecorator):
    """Platform-independent JSON type.
    Uses TEXT with JSON serialization on SQLite, native JSONB on PostgreSQL.
    """
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return value


# ── Enums ────────────────────────────────────────────────────────

class TenantTier(str, enum.Enum):
    FREE = "FREE"
    PRO = "PRO"
    TEAM = "TEAM"
    ENTERPRISE = "ENTERPRISE"


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class JobStatus(str, enum.Enum):
    INGESTING = "INGESTING"
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    CORTEX_REASONING = "CORTEX_REASONING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Verdict(str, enum.Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


# ── Utility ──────────────────────────────────────────────────────

def _utcnow():
    return datetime.now(timezone.utc)


def _uuid():
    return uuid.uuid4()


# ── Models ───────────────────────────────────────────────────────

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(GUID(), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    tier = Column(String(20), nullable=False, default=TenantTier.FREE.value)
    created_at = Column(DateTime, default=_utcnow, nullable=False)

    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    jobs = relationship("AnalysisJob", back_populates="tenant", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(GUID(), primary_key=True, default=_uuid)
    tenant_id = Column(GUID(), ForeignKey("tenants.id"), nullable=False)
    email = Column(String(320), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default=UserRole.ANALYST.value)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=_utcnow, nullable=False)

    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(GUID(), primary_key=True, default=_uuid)
    user_id = Column(GUID(), ForeignKey("users.id"), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    prefix = Column(String(12), nullable=False)
    name = Column(String(100), nullable=False, default="Default")
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=_utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="api_keys")


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(GUID(), primary_key=True, default=_uuid)
    tenant_id = Column(GUID(), ForeignKey("tenants.id"), nullable=False)
    file_name = Column(String(512), nullable=False)
    file_size_bytes = Column(BigInteger, nullable=False)
    file_hash_sha256 = Column(String(64), nullable=False, index=True)
    file_hash_sha1 = Column(String(40), nullable=True)
    file_hash_md5 = Column(String(32), nullable=True)
    file_mime_type = Column(String(128), nullable=True)
    status = Column(String(20), nullable=False, default=JobStatus.QUEUED.value)
    minio_object_path = Column(String(1024), nullable=False)
    error_message = Column(Text, nullable=True)
    progress_percent = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=_utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    tenant = relationship("Tenant", back_populates="jobs")
    report = relationship("ThreatReport", back_populates="job", uselist=False, cascade="all, delete-orphan")


class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id = Column(GUID(), primary_key=True, default=_uuid)
    job_id = Column(GUID(), ForeignKey("analysis_jobs.id"), unique=True, nullable=False)
    file_hash_sha256 = Column(String(64), nullable=False, index=True)
    severity_score = Column(Integer, default=0, nullable=False)  # 0-100
    verdict = Column(String(20), nullable=False, default=Verdict.UNKNOWN.value)
    ai_narrative = Column(Text, nullable=True)
    ai_available = Column(Boolean, default=False, nullable=False)
    static_data = Column(JSONType(), nullable=True)   # PE headers, strings, entropy
    dynamic_data = Column(JSONType(), nullable=True)   # syscalls, network, behavior
    mitre_mappings = Column(JSONType(), nullable=True)  # ATT&CK technique IDs
    iocs = Column(JSONType(), nullable=True)            # IPs, domains, URLs, hashes
    created_at = Column(DateTime, default=_utcnow, nullable=False)

    # Relationships
    job = relationship("AnalysisJob", back_populates="report")
