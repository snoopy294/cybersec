from pathlib import Path
from uuid import uuid4

import pytest

from app.services.file_service import (
    StorageOperationError,
    delete_from_local,
    download_from_local,
)
from app.services.security_service import (
    InMemoryRateLimiter,
    RateLimitExceeded,
    validate_password_strength,
    validate_runtime_security,
)


def test_password_strength_rejects_short_or_simple_values():
    with pytest.raises(ValueError):
        validate_password_strength("short1A!")

    with pytest.raises(ValueError):
        validate_password_strength("alllowercasepassword")


def test_password_strength_accepts_mixed_long_value():
    validate_password_strength("BetterPassphrase2026!")


def test_in_memory_rate_limiter_blocks_after_limit():
    limiter = InMemoryRateLimiter()

    limiter.check("login:127.0.0.1", limit=2, window_seconds=60)
    limiter.check("login:127.0.0.1", limit=2, window_seconds=60)

    with pytest.raises(RateLimitExceeded) as exc:
        limiter.check("login:127.0.0.1", limit=2, window_seconds=60)

    assert exc.value.retry_after_seconds > 0


def test_runtime_security_rejects_default_secret_in_production():
    class Settings:
        DEBUG = False
        SECRET_KEY = "sentinel-dev-secret-change-in-production-2026"
        STORAGE_BACKEND = "minio"
        cors_origins = ["https://example.com"]

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        validate_runtime_security(Settings)


def _test_storage_dir() -> Path:
    return Path(__file__).resolve().parent / "_virtual_storage" / uuid4().hex


def test_local_storage_rejects_path_traversal(monkeypatch):
    from app.services import file_service

    storage_dir = _test_storage_dir()
    monkeypatch.setattr(file_service.settings, "STORAGE_DIR", str(storage_dir))

    with pytest.raises(StorageOperationError):
        download_from_local("../outside.bin")


def test_local_storage_delete_removes_file_and_empty_parents(monkeypatch):
    from app.services import file_service

    storage_dir = _test_storage_dir()
    monkeypatch.setattr(file_service.settings, "STORAGE_DIR", str(storage_dir))
    removed_files = []
    removed_dirs = []

    monkeypatch.setattr(file_service.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(file_service.os, "remove", lambda path: removed_files.append(path))
    monkeypatch.setattr(file_service.os, "rmdir", lambda path: removed_dirs.append(path))

    object_path = f"tenant/{'a' * 64}/sample.bin"

    delete_from_local(object_path)

    assert removed_files[0].endswith("sample.bin")
    assert removed_dirs[0].endswith("a" * 64)
