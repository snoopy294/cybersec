"""Security and abuse-control helpers for API routes."""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque


class RateLimitExceeded(RuntimeError):
    """Raised when a caller exceeds a configured request limit."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = max(1, retry_after_seconds)
        super().__init__("Rate limit exceeded")


class InMemoryRateLimiter:
    """Small process-local fixed-window limiter.

    This is suitable for the local MVP and single-process deployments. A shared
    Redis-backed limiter should replace it before horizontally scaling the API.
    """

    def __init__(self):
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: int) -> None:
        if limit <= 0 or window_seconds <= 0:
            return

        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()

            if len(events) >= limit:
                retry_after = int(window_seconds - (now - events[0])) + 1
                raise RateLimitExceeded(retry_after)

            events.append(now)


def client_ip_from_request(request) -> str:
    """Return the best-effort client IP while respecting a single proxy hop."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"


def validate_password_strength(password: str) -> None:
    """Enforce a baseline password policy without dictating a specific format."""
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")

    classes = 0
    classes += bool(re.search(r"[a-z]", password))
    classes += bool(re.search(r"[A-Z]", password))
    classes += bool(re.search(r"\d", password))
    classes += bool(re.search(r"[^A-Za-z0-9]", password))
    if classes < 3:
        raise ValueError(
            "Password must include at least three of: lowercase, uppercase, number, symbol"
        )


def validate_runtime_security(settings) -> None:
    """Fail fast for production settings that would expose the MVP unsafely."""
    if settings.DEBUG:
        return

    default_secret = "sentinel-dev-secret-change-in-production-2026"
    if settings.SECRET_KEY == default_secret or len(settings.SECRET_KEY) < 32:
        raise RuntimeError("SECRET_KEY must be changed to a strong value when DEBUG=false")

    if "*" in settings.cors_origins:
        raise RuntimeError("CORS_ORIGINS must be explicit when DEBUG=false")

    if settings.STORAGE_BACKEND.lower() == "local":
        raise RuntimeError("STORAGE_BACKEND=minio is required when DEBUG=false")
