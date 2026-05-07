"""SENTINEL — File service for storage operations.

Supports two backends:
  - "local": Stores files on the local filesystem (default, no dependencies)
  - "minio": Stores files in MinIO/S3 (requires MinIO running)
"""

import hashlib
import io
import os
import re
from app.core.config import get_settings

settings = get_settings()


class StorageConfigurationError(RuntimeError):
    """Raised when the configured storage backend is missing required settings."""


class StorageOperationError(RuntimeError):
    """Raised when a storage backend cannot complete an operation."""


def compute_file_hashes(file_bytes: bytes) -> dict:
    """Compute SHA-256, SHA-1, and MD5 hashes for a file."""
    return {
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "md5": hashlib.md5(file_bytes).hexdigest(),
    }


def sanitize_file_name(file_name: str) -> str:
    """Return a storage-safe basename while preserving useful analyst context."""
    name = os.path.basename(file_name or "unknown").strip()
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name)
    name = re.sub(r"\s+", " ", name).strip(" .")
    if not name:
        return "unknown"
    return name[:180]


# ── Local Filesystem Backend ────────────────────────────────────

def _ensure_storage_dir():
    """Create the storage directory if it doesn't exist."""
    os.makedirs(settings.STORAGE_DIR, exist_ok=True)


def upload_to_local(
    tenant_id: str,
    sha256_hash: str,
    file_name: str,
    file_bytes: bytes,
) -> str:
    """Save a file to local filesystem and return the relative path."""
    _ensure_storage_dir()
    safe_name = sanitize_file_name(file_name)
    dir_path = os.path.join(settings.STORAGE_DIR, tenant_id, sha256_hash)
    os.makedirs(dir_path, exist_ok=True)

    file_path = os.path.join(dir_path, safe_name)
    with open(file_path, "wb") as f:
        f.write(file_bytes)

    # Return relative path for DB storage
    return f"{tenant_id}/{sha256_hash}/{safe_name}"


def download_from_local(object_path: str) -> bytes:
    """Read a file from local filesystem."""
    full_path = os.path.join(settings.STORAGE_DIR, object_path)
    with open(full_path, "rb") as f:
        return f.read()


# ── Unified Interface ────────────────────────────────────────────

def upload_file(
    tenant_id: str,
    sha256_hash: str,
    file_name: str,
    file_bytes: bytes,
    content_type: str = "application/octet-stream",
) -> str:
    """Upload a file using the configured storage backend."""
    if settings.STORAGE_BACKEND == "minio":
        return _upload_to_minio(tenant_id, sha256_hash, file_name, file_bytes, content_type)
    return upload_to_local(tenant_id, sha256_hash, file_name, file_bytes)


def download_file(object_path: str) -> bytes:
    """Download a file using the configured storage backend."""
    if settings.STORAGE_BACKEND == "minio":
        return _download_from_minio(object_path)
    return download_from_local(object_path)


def validate_storage_configuration() -> None:
    """Validate static storage settings without making network calls."""
    backend = settings.STORAGE_BACKEND.lower()
    if backend not in {"local", "minio"}:
        raise StorageConfigurationError("STORAGE_BACKEND must be 'local' or 'minio'")
    if backend == "local":
        return

    required = {
        "MINIO_ENDPOINT": settings.MINIO_ENDPOINT,
        "MINIO_ACCESS_KEY": settings.MINIO_ACCESS_KEY,
        "MINIO_SECRET_KEY": settings.MINIO_SECRET_KEY,
        "MINIO_BUCKET": settings.MINIO_BUCKET,
    }
    missing = [key for key, value in required.items() if not str(value or "").strip()]
    if missing:
        raise StorageConfigurationError(
            "Missing required object storage setting(s): " + ", ".join(missing)
        )
    if settings.MINIO_ENDPOINT.startswith(("http://", "https://")):
        raise StorageConfigurationError(
            "MINIO_ENDPOINT must be a host name only, without http:// or https://"
        )


def storage_health_status() -> str:
    """Return a compact health status for the configured storage backend."""
    try:
        validate_storage_configuration()
        if settings.STORAGE_BACKEND.lower() == "local":
            _ensure_storage_dir()
            return "local:ready" if os.access(settings.STORAGE_DIR, os.W_OK) else "local:not_writable"
        client = _minio_client()
        return "minio:connected" if client.bucket_exists(settings.MINIO_BUCKET) else "minio:bucket_missing"
    except Exception as exc:
        return f"{settings.STORAGE_BACKEND}:error:{type(exc).__name__}"


# ── MinIO Backend (optional) ────────────────────────────────────

def _upload_to_minio(tenant_id, sha256_hash, file_name, file_bytes, content_type):
    """Upload to MinIO (only used if STORAGE_BACKEND=minio)."""
    validate_storage_configuration()
    client = _minio_client()
    bucket = settings.MINIO_BUCKET
    try:
        bucket_exists = client.bucket_exists(bucket)
    except Exception as exc:
        raise StorageOperationError(f"Object storage bucket '{bucket}' is not reachable: {exc}") from exc
    if not bucket_exists:
        if "r2.cloudflarestorage.com" in settings.MINIO_ENDPOINT:
            raise StorageOperationError(f"Object storage bucket '{bucket}' is not reachable")
        try:
            client.make_bucket(bucket)
        except Exception as exc:
            raise StorageOperationError(f"Failed to create object storage bucket '{bucket}': {exc}") from exc

    object_path = f"{tenant_id}/{sha256_hash}/{sanitize_file_name(file_name)}"
    try:
        client.put_object(
            bucket_name=bucket,
            object_name=object_path,
            data=io.BytesIO(file_bytes),
            length=len(file_bytes),
            content_type=content_type,
        )
    except Exception as exc:
        raise StorageOperationError(f"Failed to upload object to '{bucket}': {exc}") from exc
    return object_path


def _download_from_minio(object_path):
    """Download from MinIO."""
    validate_storage_configuration()
    client = _minio_client()
    try:
        response = client.get_object(settings.MINIO_BUCKET, object_path)
    except Exception as exc:
        raise StorageOperationError(f"Failed to download object '{object_path}': {exc}") from exc
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()


def _minio_client():
    """Build a MinIO/S3-compatible client from validated settings."""
    from minio import Minio

    return Minio(
        endpoint=settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE,
    )
