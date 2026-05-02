"""SENTINEL — Core configuration module."""

from pydantic_settings import BaseSettings
from functools import lru_cache
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "SENTINEL"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    # ── Database (SQLite by default — no install required) ───────
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinel.db"
    DATABASE_URL_SYNC: str = "sqlite:///./sentinel.db"

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
