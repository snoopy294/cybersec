"""SENTINEL — Core configuration module."""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "SENTINEL"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    # ── Database ─────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://sentinel:sentinel_dev_2026@localhost:5432/sentinel_db"
    DATABASE_URL_SYNC: str = "postgresql://sentinel:sentinel_dev_2026@localhost:5432/sentinel_db"

    # ── Redis ────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── MinIO ────────────────────────────────────────────────────
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "sentinel_admin"
    MINIO_SECRET_KEY: str = "sentinel_minio_2026"
    MINIO_BUCKET: str = "sentinel-payloads"
    MINIO_SECURE: bool = False

    # ── Auth ─────────────────────────────────────────────────────
    SECRET_KEY: str = "sentinel-dev-secret-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── Upload Limits ────────────────────────────────────────────
    MAX_FILE_SIZE_MB: int = 500

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
