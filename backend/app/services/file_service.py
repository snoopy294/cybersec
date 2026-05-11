"""SENTINEL — File service for storage operations.

Supports two backends:
  - "local": Stores files on the local filesystem (default, no dependencies)
  - "minio": Stores files in MinIO/S3 (requires MinIO running)
"""

import hashlib
import io
import os
from app.core.config import get_settings

settings = get_settings()


def compute_file_hashes(file_bytes: bytes) -> dict:
    """Compute SHA-256, SHA-1, and MD5 hashes for a file."""
    return {
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "md5": hashlib.md5(file_bytes).hexdigest(),
    }


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
    dir_path = os.path.normpath(os.path.join(settings.STORAGE_DIR, tenant_id, sha256_hash))
    os.makedirs(dir_path, exist_ok=True)

    file_path = os.path.join(dir_path, file_name)
    with open(file_path, "wb") as f:
        f.write(file_bytes)

    # Return relative path for DB storage (forward slashes for portability)
    return f"{tenant_id}/{sha256_hash}/{file_name}"


def download_from_local(object_path: str) -> bytes:
    """Read a file from local filesystem."""
    # Normalize separators: object_path uses forward slashes but Windows needs backslashes
    full_path = os.path.normpath(os.path.join(settings.STORAGE_DIR, object_path))
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


# ── MinIO Backend (optional) ────────────────────────────────────

def _upload_to_minio(tenant_id, sha256_hash, file_name, file_bytes, content_type):
    """Upload to MinIO (only used if STORAGE_BACKEND=minio)."""
    from minio import Minio

    client = Minio(
        endpoint=settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE,
    )
    bucket = settings.MINIO_BUCKET
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)

    object_path = f"{tenant_id}/{sha256_hash}/{file_name}"
    client.put_object(
        bucket_name=bucket,
        object_name=object_path,
        data=io.BytesIO(file_bytes),
        length=len(file_bytes),
        content_type=content_type,
    )
    return object_path


def _download_from_minio(object_path):
    """Download from MinIO."""
    from minio import Minio

    client = Minio(
        endpoint=settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE,
    )
    response = client.get_object(settings.MINIO_BUCKET, object_path)
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()
