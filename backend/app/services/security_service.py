"""Security and abuse-control helpers for API routes."""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque

BCRYPT_MAX_PASSWORD_BYTES = 72


class RateLimitExceeded(RuntimeError):
    """Raised when a caller exceeds a configured request limit."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = max(1, retry_after_seconds)
        super().__init__("Rate limit exceeded")


class InMemoryRateLimiter:
    """Small process-local sliding-window limiter.

    This is suitable for the local MVP and single-process deployments. A shared
    Redis-backed limiter should replace it before horizontally scaling the API.
    """

    # Drop idle keys once the table grows past this, so spoofed or one-off
    # callers cannot grow memory without bound.
    PURGE_THRESHOLD = 10_000

    def __init__(self):
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float, window_seconds: int) -> deque[float]:
        events = self._events[key]
        cutoff = now - window_seconds
        while events and events[0] <= cutoff:
            events.popleft()
        return events

    def _purge_idle(self, now: float, window_seconds: int) -> None:
        if len(self._events) <= self.PURGE_THRESHOLD:
            return
        cutoff = now - window_seconds
        for key in [k for k, events in self._events.items() if not events or events[-1] <= cutoff]:
            del self._events[key]

    def ensure_allowed(self, key: str, limit: int, window_seconds: int) -> None:
        """Raise if the key is already at its limit, without recording an event."""
        if limit <= 0 or window_seconds <= 0:
            return

        now = time.monotonic()
        with self._lock:
            events = self._prune(key, now, window_seconds)
            if len(events) >= limit:
                retry_after = int(window_seconds - (now - events[0])) + 1
                raise RateLimitExceeded(retry_after)
            if not events:
                del self._events[key]

    def record(self, key: str, window_seconds: int) -> None:
        """Record one event for the key."""
        now = time.monotonic()
        with self._lock:
            self._purge_idle(now, window_seconds)
            self._events[key].append(now)

    def check(self, key: str, limit: int, window_seconds: int) -> None:
        """Raise if over the limit, otherwise record this request."""
        if limit <= 0 or window_seconds <= 0:
            return
        self.ensure_allowed(key, limit, window_seconds)
        self.record(key, window_seconds)

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


def client_ip_from_request(request, trusted_proxy_hops: int = 1) -> str:
    """Return the client IP as seen by the outermost trusted proxy.

    Each proxy appends the address it received the request from, so the left
    side of X-Forwarded-For is whatever the client chose to send. Counting from
    the right past our own proxies gives an address the client cannot forge.
    """
    peer = request.client.host if request.client else "unknown"
    if trusted_proxy_hops <= 0:
        return peer

    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return peer

    hops = [part.strip() for part in forwarded.split(",") if part.strip()]
    if not hops:
        return peer
    return hops[-min(trusted_proxy_hops, len(hops))]


def validate_password_strength(password: str) -> None:
    """Enforce a baseline password policy without dictating a specific format."""
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")

    if len(password.encode("utf-8")) > BCRYPT_MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {BCRYPT_MAX_PASSWORD_BYTES} bytes long")

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

    insecure = [origin for origin in settings.cors_origins if not origin.startswith("https://")]
    if insecure:
        raise RuntimeError("CORS_ORIGINS must use https:// when DEBUG=false: " + ", ".join(insecure))

    if settings.STORAGE_BACKEND.lower() == "local":
        raise RuntimeError("STORAGE_BACKEND=minio is required when DEBUG=false")

    if settings.DATABASE_URL.startswith("sqlite"):
        raise RuntimeError("A managed Postgres DATABASE_URL is required when DEBUG=false")
