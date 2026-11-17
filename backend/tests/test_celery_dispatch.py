"""Analysis dispatch through Celery (eager) and the background thread worker."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app import worker
from app.api import routes
from app.celery_worker import analyze_file_task, celery_app
from app.main import recover_interrupted_jobs
from app.services.file_service import StorageOperationError, TransientStorageError
from tests.test_api import _auth_headers, run

# Captured before the autouse fixture swaps dispatch_analysis for a recorder.
real_dispatch_analysis = worker.dispatch_analysis

SAMPLE = b"MZ" + b"\x00" * 64 + b"http://c2.example/beacon\x00cmd.exe /c whoami\x00"


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    dispatched = []
    monkeypatch.setattr("app.worker.dispatch_analysis", dispatched.append)
    monkeypatch.setattr(routes, "rate_limiter", routes.InMemoryRateLimiter())
    monkeypatch.setattr(routes.settings, "ALLOW_REGISTRATION", True)
    return dispatched


@pytest.fixture
def eager_celery(monkeypatch):
    monkeypatch.setattr(worker.settings, "USE_CELERY", True)
    monkeypatch.setitem(celery_app.conf, "task_always_eager", True)
    # Eager retries only re-run inline when errors are not propagated.
    monkeypatch.setitem(celery_app.conf, "task_eager_propagates", False)
    # Retries would otherwise sleep for their backoff countdown in eager mode.
    monkeypatch.setattr("app.celery_worker.retry_countdown", lambda retries: 0)


def _job(job_id):
    from app.models.models import AnalysisJob

    session = worker.SyncSession()
    try:
        job = session.query(AnalysisJob).filter_by(id=job_id).one()
        session.expunge(job)
        return job
    finally:
        session.close()


async def _upload(client, headers, name="sample.exe", data=SAMPLE):
    response = await client.post(
        "/api/v1/analyze", headers=headers, files={"file": (name, data, "application/octet-stream")}
    )
    assert response.status_code == 202, response.text
    return response.json()["job_id"]


def test_celery_dispatch_runs_analysis_end_to_end(isolate, eager_celery):
    async def body(client):
        headers = await _auth_headers(client)
        job_id = await _upload(client, headers)
        assert isolate == [job_id]

        result = await asyncio.to_thread(real_dispatch_analysis, job_id)

        assert result.successful()
        assert result.get()["job_id"] == job_id
        job = (await client.get(f"/api/v1/analyze/{job_id}", headers=headers)).json()
        assert job["status"] == "COMPLETED"
        report = await client.get(job["report_url"], headers=headers)
        assert report.status_code == 200, report.text

    run(body)


def test_thread_dispatch_still_runs_analysis(isolate, monkeypatch):
    monkeypatch.setattr(worker.settings, "USE_CELERY", False)

    async def body(client):
        headers = await _auth_headers(client)
        job_id = await _upload(client, headers)

        thread = real_dispatch_analysis(job_id)
        await asyncio.to_thread(thread.join, 30)

        assert not thread.is_alive()
        job = (await client.get(f"/api/v1/analyze/{job_id}", headers=headers)).json()
        assert job["status"] == "COMPLETED"

    run(body)


def test_retried_completed_job_is_a_no_op(isolate, eager_celery, monkeypatch):
    async def body(client):
        headers = await _auth_headers(client)
        job_id = await _upload(client, headers)
        await asyncio.to_thread(worker.run_analysis, job_id)
        first = _job(job_id)
        assert first.status == "COMPLETED"

        downloads = []
        monkeypatch.setattr(worker, "download_file", lambda path: downloads.append(path))
        result = await asyncio.to_thread(analyze_file_task.apply, (job_id,))

        assert result.get() == {"job_id": job_id, "status": "already_completed"}
        assert downloads == []
        again = _job(job_id)
        assert again.status == "COMPLETED"
        assert again.completed_at == first.completed_at

    run(body)


def test_transient_storage_error_is_retried_then_succeeds(isolate, eager_celery, monkeypatch):
    real_download = worker.download_file
    calls = []

    def flaky_download(path):
        calls.append(path)
        if len(calls) < 3:
            raise TransientStorageError("connection reset")
        return real_download(path)

    monkeypatch.setattr(worker, "download_file", flaky_download)

    async def body(client):
        headers = await _auth_headers(client)
        job_id = await _upload(client, headers)

        result = await asyncio.to_thread(analyze_file_task.apply, (job_id,))

        assert result.get()["job_id"] == job_id
        assert len(calls) == 3
        assert _job(job_id).status == "COMPLETED"

    run(body)


def test_transient_storage_error_fails_job_after_last_retry(isolate, eager_celery, monkeypatch):
    calls = []

    def down(path):
        calls.append(path)
        raise TransientStorageError("storage unavailable")

    monkeypatch.setattr(worker, "download_file", down)

    async def body(client):
        headers = await _auth_headers(client)
        job_id = await _upload(client, headers)

        result = await asyncio.to_thread(analyze_file_task.apply, (job_id,))

        assert "error" in result.get()
        assert len(calls) == analyze_file_task.max_retries + 1
        job = _job(job_id)
        assert job.status == "FAILED"
        assert job.error_message == worker.SAMPLE_UNREADABLE_MESSAGE

    run(body)


def test_permanent_storage_error_is_not_retried(isolate, eager_celery, monkeypatch):
    calls = []

    def missing(path):
        calls.append(path)
        raise StorageOperationError("NoSuchKey")

    monkeypatch.setattr(worker, "download_file", missing)

    async def body(client):
        headers = await _auth_headers(client)
        job_id = await _upload(client, headers)

        await asyncio.to_thread(analyze_file_task.apply, (job_id,))

        assert len(calls) == 1
        assert _job(job_id).status == "FAILED"

    run(body)


def test_recovery_keeps_celery_queued_jobs_but_fails_stale_ones(isolate, monkeypatch):
    from app.models.models import AnalysisJob

    monkeypatch.setattr(worker.settings, "USE_CELERY", True)

    async def body(client):
        headers = await _auth_headers(client)
        fresh_id = await _upload(client, headers, name="fresh.exe", data=SAMPLE + b"1")
        stale_id = await _upload(client, headers, name="stale.exe", data=SAMPLE + b"2")

        session = worker.SyncSession()
        try:
            stale = session.query(AnalysisJob).filter_by(id=stale_id).one()
            stale.created_at = datetime.now(timezone.utc) - timedelta(
                minutes=worker.settings.CELERY_STALE_JOB_MINUTES + 5
            )
            session.commit()
        finally:
            session.close()

        assert await recover_interrupted_jobs() == 1
        assert _job(fresh_id).status == "QUEUED"
        assert _job(stale_id).status == "FAILED"

    run(body)


def test_celery_app_is_configured_for_safe_redelivery():
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.worker_prefetch_multiplier == 1
    assert analyze_file_task.acks_late is True
    assert analyze_file_task.time_limit > analyze_file_task.soft_time_limit > 0
