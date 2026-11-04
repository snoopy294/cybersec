"""End-to-end API tests through the ASGI app and a real database."""

import asyncio

import httpx
import pytest

from app.api import routes
from app.core.database import Base, engine
from app.main import app, recover_interrupted_jobs

PASSWORD = "BetterPassphrase2026!"


def run(test_coro):
    """Run one async test body with fresh tables, then release DB connections.

    Each test gets its own event loop, and asyncpg connections cannot cross
    loops, so the pool is disposed inside the same loop that used it.
    """

    async def wrapper():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        try:
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                await test_coro(client)
        finally:
            await engine.dispose()

    asyncio.run(wrapper())


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    # Analysis threads would outlive the test's database; record dispatches instead.
    dispatched = []
    monkeypatch.setattr("app.worker.dispatch_analysis", dispatched.append)
    monkeypatch.setattr(routes, "rate_limiter", routes.InMemoryRateLimiter())
    monkeypatch.setattr(routes.settings, "ALLOW_REGISTRATION", True)
    return dispatched


async def _register(client, email="analyst@example.com", password=PASSWORD):
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "tenant_name": "Lab"},
    )
    return response


async def _auth_headers(client, email="analyst@example.com"):
    response = await _register(client, email)
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_register_login_and_profile_round_trip():
    async def body(client):
        registered = await _register(client)
        assert registered.status_code == 201, registered.text

        login = await client.post(
            "/api/v1/auth/login",
            json={"email": " Analyst@Example.com ", "password": PASSWORD},
        )
        assert login.status_code == 200, login.text

        me = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )
        assert me.status_code == 200
        assert me.json()["email"] == "analyst@example.com"
        assert me.json()["tenant_name"] == "Lab"

    run(body)


def test_duplicate_registration_is_rejected():
    async def body(client):
        assert (await _register(client)).status_code == 201
        duplicate = await _register(client, email="ANALYST@example.com")
        assert duplicate.status_code == 409

    run(body)


def test_validation_errors_are_readable_and_do_not_echo_passwords():
    async def body(client):
        response = await client.post(
            "/api/v1/auth/register",
            json={"email": "not-an-email", "password": "hunter2", "tenant_name": "Lab"},
        )
        assert response.status_code == 422
        payload = response.json()
        assert isinstance(payload["detail"], str)
        assert "hunter2" not in response.text
        assert {e["field"] for e in payload["errors"]} >= {"email", "password"}

    run(body)


def test_weak_password_gets_specific_message():
    async def body(client):
        response = await _register(client, password="alllowercasepassword")
        assert response.status_code == 400
        assert "three of" in response.json()["detail"]

    run(body)


def test_login_locks_account_after_repeated_failures(monkeypatch):
    monkeypatch.setattr(routes.settings, "LOGIN_FAILURES_PER_EMAIL", 3)
    monkeypatch.setattr(routes.settings, "AUTH_RATE_LIMIT_PER_MINUTE", 100)

    async def body(client):
        await _register(client)
        for _ in range(3):
            bad = await client.post(
                "/api/v1/auth/login",
                json={"email": "analyst@example.com", "password": "WrongPassword123!"},
            )
            assert bad.status_code == 401

        locked = await client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@example.com", "password": PASSWORD},
        )
        assert locked.status_code == 429
        assert "Retry-After" in locked.headers

    run(body)


def test_spoofed_forwarded_for_does_not_bypass_auth_rate_limit(monkeypatch):
    monkeypatch.setattr(routes.settings, "AUTH_RATE_LIMIT_PER_MINUTE", 2)

    async def body(client):
        statuses = []
        for i in range(3):
            response = await client.post(
                "/api/v1/auth/login",
                json={"email": "nobody@example.com", "password": "Whatever12345!"},
                headers={"X-Forwarded-For": f"10.0.0.{i}, 203.0.113.9"},
            )
            statuses.append(response.status_code)
        assert statuses == [401, 401, 429]

    run(body)


def test_protected_routes_require_valid_token():
    async def body(client):
        assert (await client.get("/api/v1/jobs")).status_code == 401
        bad = await client.get("/api/v1/jobs", headers={"Authorization": "Bearer not-a-token"})
        assert bad.status_code == 401

    run(body)


def test_upload_creates_job_and_sanitizes_metadata(isolate):
    async def body(client):
        headers = await _auth_headers(client)
        long_name = "<script>" + "a" * 900 + ".exe"
        response = await client.post(
            "/api/v1/analyze",
            headers=headers,
            files={"file": (long_name, b"MZ hello world", "x" * 300)},
        )
        assert response.status_code == 202, response.text
        assert len(isolate) == 1

        jobs = (await client.get("/api/v1/jobs", headers=headers)).json()["jobs"]
        assert len(jobs) == 1
        assert "<" not in jobs[0]["file_name"]
        assert len(jobs[0]["file_name"]) <= 180

        job = await client.get(f"/api/v1/analyze/{jobs[0]['job_id']}", headers=headers)
        assert job.status_code == 200

    run(body)


def test_empty_and_oversized_uploads_are_rejected(monkeypatch):
    monkeypatch.setattr(routes.settings, "MAX_FILE_SIZE_MB", 1)

    async def body(client):
        headers = await _auth_headers(client)
        empty = await client.post(
            "/api/v1/analyze", headers=headers, files={"file": ("e.bin", b"", "application/octet-stream")}
        )
        assert empty.status_code == 400

        big = await client.post(
            "/api/v1/analyze",
            headers=headers,
            files={"file": ("big.bin", b"\0" * (3 * 1024 * 1024), "application/octet-stream")},
        )
        assert big.status_code == 413

    run(body)


def test_report_routes_validate_hash_format():
    async def body(client):
        headers = await _auth_headers(client)
        bad = await client.get("/api/v1/report/../../etc", headers=headers)
        assert bad.status_code in (404, 422)
        not_hex = await client.get("/api/v1/report/" + "z" * 64, headers=headers)
        assert not_hex.status_code == 422
        missing = await client.get("/api/v1/report/" + "a" * 64, headers=headers)
        assert missing.status_code == 404

    run(body)


def test_tenants_cannot_see_each_others_jobs():
    async def body(client):
        alice = await _auth_headers(client, "alice@example.com")
        bob = await _auth_headers(client, "bob@example.com")
        upload = await client.post(
            "/api/v1/analyze", headers=alice, files={"file": ("a.bin", b"alice data", "application/octet-stream")}
        )
        job_id = upload.json()["job_id"]

        assert (await client.get(f"/api/v1/analyze/{job_id}", headers=bob)).status_code == 404
        assert (await client.get("/api/v1/jobs", headers=bob)).json()["total"] == 0

    run(body)


def test_refresh_respects_active_job_limit(monkeypatch):
    monkeypatch.setattr(routes.settings, "MAX_ACTIVE_JOBS_PER_TENANT", 1)

    async def body(client):
        headers = await _auth_headers(client)
        upload = await client.post(
            "/api/v1/analyze", headers=headers, files={"file": ("a.bin", b"data", "application/octet-stream")}
        )
        assert upload.status_code == 202
        file_hash = (await client.get("/api/v1/jobs", headers=headers)).json()["jobs"][0]["file_hash_sha256"]

        refresh = await client.post(f"/api/v1/report/{file_hash}/refresh", headers=headers)
        assert refresh.status_code == 429

    run(body)


def test_interrupted_jobs_are_failed_on_startup():
    async def body(client):
        headers = await _auth_headers(client)
        upload = await client.post(
            "/api/v1/analyze", headers=headers, files={"file": ("a.bin", b"data", "application/octet-stream")}
        )
        job_id = upload.json()["job_id"]

        assert await recover_interrupted_jobs() == 1
        job = (await client.get(f"/api/v1/analyze/{job_id}", headers=headers)).json()
        assert job["status"] == "FAILED"
        assert "interrupted" in job["error_message"]

    run(body)


def test_unhandled_errors_return_generic_message(monkeypatch):
    async def explode(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(routes, "enforce_tenant_retention", explode)

    async def body(client):
        headers = await _auth_headers(client)
        response = await client.post(
            "/api/v1/analyze", headers=headers, files={"file": ("a.bin", b"data", "application/octet-stream")}
        )
        assert response.status_code == 500
        assert "secret internal detail" not in response.text
        assert response.json()["reference"]

    run(body)


def test_security_headers_present():
    async def body(client):
        response = await client.get("/api/v1/health")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Request-ID"]

    run(body)
