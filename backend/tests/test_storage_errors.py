"""Object-storage download errors are split into retryable and permanent."""

import pytest
from minio.error import S3Error, ServerError
from urllib3.exceptions import MaxRetryError, ProtocolError

from app.services import file_service
from app.services.file_service import StorageOperationError, TransientStorageError


def _s3_error(code):
    return S3Error(None, code, f"{code} message", "resource", "request-id", "host-id")


class _Client:
    def __init__(self, exc):
        self.exc = exc

    def get_object(self, bucket, path):
        raise self.exc


@pytest.mark.parametrize(
    "exc",
    [
        MaxRetryError(None, "/obj", "connection refused"),
        ProtocolError("connection reset"),
        ConnectionResetError("reset by peer"),
        TimeoutError("read timed out"),
        ServerError("503 Service Unavailable", 503),
        _s3_error("SlowDown"),
        _s3_error("InternalError"),
    ],
)
def test_network_timeouts_and_5xx_are_transient(monkeypatch, exc):
    monkeypatch.setattr(file_service, "validate_storage_configuration", lambda: None)
    monkeypatch.setattr(file_service, "_minio_client", lambda: _Client(exc))

    with pytest.raises(TransientStorageError):
        file_service._download_from_minio("tenant/hash/sample.bin")


@pytest.mark.parametrize(
    "exc",
    [_s3_error("NoSuchKey"), _s3_error("AccessDenied"), _s3_error("NoSuchBucket"), ValueError("bad")],
)
def test_missing_objects_and_auth_errors_are_permanent(monkeypatch, exc):
    monkeypatch.setattr(file_service, "validate_storage_configuration", lambda: None)
    monkeypatch.setattr(file_service, "_minio_client", lambda: _Client(exc))

    with pytest.raises(StorageOperationError) as caught:
        file_service._download_from_minio("tenant/hash/sample.bin")
    assert not isinstance(caught.value, TransientStorageError)
