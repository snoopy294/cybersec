"""SENTINEL — File service for MinIO object storage operations."""

import hashlib
import io
from minio import Minio
from app.core.config import get_settings

settings = get_settings()


def get_minio_client() -> Minio:
    """Create and return a MinIO client instance."""
    return Minio(
        endpoint=settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE,
    )


def compute_file_hashes(file_bytes: bytes) -> dict:
    """Compute SHA-256, SHA-1, and MD5 hashes for a file."""
    return {
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "md5": hashlib.md5(file_bytes).hexdigest(),
    }


def upload_to_minio(
    tenant_id: str,
    sha256_hash: str,
    file_name: str,
    file_bytes: bytes,
    content_type: str = "application/octet-stream",
) -> str:
    """Upload a file to MinIO and return the object path.

    Path format: {tenant_id}/{sha256}/{original_filename}
    """
    client = get_minio_client()
    bucket = settings.MINIO_BUCKET

    # Ensure bucket exists
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


def download_from_minio(object_path: str) -> bytes:
    """Download a file from MinIO by its object path."""
    client = get_minio_client()
    response = client.get_object(settings.MINIO_BUCKET, object_path)
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()
