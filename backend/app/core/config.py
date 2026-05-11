"""SENTINEL — Core configuration module."""

from functools import lru_cache
import os

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "SENTINEL"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    # ── Deployment ────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ALLOWED_ORIGINS: str = "*"  # Comma-separated list, e.g. "https://sentinel.example.com,https://www.sentinel.example.com"

    # ── Database (SQLite by default — no install required) ───────
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinel.db"
    DATABASE_URL_SYNC: str = ""

    # ── Storage (local filesystem — no MinIO required) ───────────
    STORAGE_DIR: str = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "storage")
    STORAGE_BACKEND: str = "local"  # "local" or "minio"

    # ── MinIO (only used if STORAGE_BACKEND=minio) ───────────────
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "sentinel_admin"
    MINIO_SECRET_KEY: str = "sentinel_minio_2026"
    MINIO_BUCKET: str = "sentinel-payloads"
    MINIO_SECURE: bool = False

    # ── Redis (optional — runs sync mode without it) ─────────────
    REDIS_URL: str = ""
    USE_CELERY: bool = False  # Set True if Redis + Celery are available

    # ── Auth ─────────────────────────────────────────────────────
    SECRET_KEY: str = "sentinel-dev-secret-change-in-production-2026"  # ⚠ CHANGE THIS in .env for production!
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── Upload Limits ────────────────────────────────────────────
    MAX_FILE_SIZE_MB: int = 100
    UPLOAD_READ_CHUNK_SIZE_BYTES: int = 1024 * 1024
    UPLOAD_RATE_LIMIT_PER_MINUTE: int = 5
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    MAX_ACTIVE_JOBS_PER_TENANT: int = 3
    MAX_DAILY_UPLOAD_MB_PER_TENANT: int = 1024
    RETENTION_DAYS: int = 30
    RETENTION_MAX_JOBS_PER_TENANT: int = 250
    EXPOSE_API_DOCS: bool = True

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_async_database_url(cls, value):
        if isinstance(value, str) and value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+asyncpg://", 1)
        return value

    @model_validator(mode="after")
    def derive_sync_database_url(self):
        if not self.DATABASE_URL_SYNC:
            if self.DATABASE_URL.startswith("sqlite+aiosqlite://"):
                self.DATABASE_URL_SYNC = self.DATABASE_URL.replace("sqlite+aiosqlite://", "sqlite://", 1)
            elif self.DATABASE_URL.startswith("postgresql+asyncpg://"):
                self.DATABASE_URL_SYNC = self.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)
            else:
                self.DATABASE_URL_SYNC = self.DATABASE_URL
        return self

    @property
    def cors_origins(self) -> list[str]:
        return [item.strip() for item in self.CORS_ORIGINS.split(",") if item.strip()]

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
