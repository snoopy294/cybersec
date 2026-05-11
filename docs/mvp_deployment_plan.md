# SENTINEL MVP Deployment Plan

## Summary

This plan covers the remaining work to make SENTINEL a hosted MVP app:

- Public landing page served by Vercel at `/`
- Analyst dashboard served by Vercel at `/dashboard`
- FastAPI backend deployed to Render
- Postgres database hosted on Render
- Uploaded samples stored durably in Cloudflare R2 through the existing MinIO/S3-compatible storage path
- Repeatable verification checklist after every deploy

MVP means hosted and demonstrable. It does not mean fully production-hardened.

## MVP Architecture

| Component | Provider | Repo/config |
| --- | --- | --- |
| Frontend | Vercel | Project root: `frontend` |
| Backend API | Render Docker web service | Service root: `backend`; blueprint: `render.yaml` |
| Database | Render Postgres | `DATABASE_URL` injected into Render service |
| File storage | Cloudflare R2 | Use `STORAGE_BACKEND=minio` with R2 S3-compatible credentials |
| Worker mode | Backend background thread | Keep `USE_CELERY=false` for MVP |

Keep background-thread analysis for the MVP unless analysis jobs become too slow or unreliable. If that happens, promote analysis to a separate worker service with Redis/Celery.

The Render blueprint is configured for R2-backed storage. Do not switch the hosted MVP back to local storage unless you are intentionally running a temporary demo and accept losing uploaded samples on redeploy.

## Environment Variables

### Vercel

Set this in the Vercel project for the `frontend` app:

```env
BACKEND_URL=https://<render-api-host>
```

The frontend calls `/api/v1/...`; Next.js rewrites those requests to `BACKEND_URL`.

### Render

Set these on the Render backend service:

```env
DEBUG=false
CORS_ORIGINS=https://<vercel-host>
DATABASE_URL=<render-postgres-connection-string>
SECRET_KEY=<generated-secret>
STORAGE_BACKEND=minio
USE_CELERY=false
MAX_FILE_SIZE_MB=100
UPLOAD_RATE_LIMIT_PER_MINUTE=5
AUTH_RATE_LIMIT_PER_MINUTE=10
MAX_ACTIVE_JOBS_PER_TENANT=3
MAX_DAILY_UPLOAD_MB_PER_TENANT=1024
RETENTION_DAYS=30
RETENTION_MAX_JOBS_PER_TENANT=250
EXPOSE_API_DOCS=false
```

Render commonly provides `DATABASE_URL` as `postgresql://...`. The backend normalizes that value for async SQLAlchemy and derives the sync URL used by the analysis worker.

### Cloudflare R2

Create a private R2 bucket and an API token/key pair with object read/write access to that bucket. Then set these on Render:

```env
MINIO_ENDPOINT=<account-id>.r2.cloudflarestorage.com
MINIO_ACCESS_KEY=<r2-access-key-id>
MINIO_SECRET_KEY=<r2-secret-access-key>
MINIO_BUCKET=<r2-bucket-name>
MINIO_SECURE=true
```

Use the account-specific R2 S3 API endpoint. The MinIO client expects the endpoint as a host-style value, so do not include `https://` in `MINIO_ENDPOINT`.

## Deployment Sequence

1. Push the latest `main` branch to GitHub.
2. Create a private Cloudflare R2 bucket for uploaded samples.
3. Create a Cloudflare R2 API token/key pair with object read/write access to the bucket.
4. Create a Render Postgres database.
5. Deploy the Render backend from `render.yaml`.
6. Set the Render environment variables listed above.
7. Confirm the backend health endpoint:

```bash
curl https://<render-api-host>/api/v1/health
```

8. Deploy the Vercel frontend from the `frontend` project root.
9. Set Vercel `BACKEND_URL` to the Render backend URL.
10. Update Render `CORS_ORIGINS` to the final Vercel URL.
11. Redeploy Render after the final CORS value is set.
12. Run the end-to-end smoke test through the Vercel URL.

## Cloudflare R2 Setup Details

1. In Cloudflare, create an R2 bucket for SENTINEL uploads.
2. Keep the bucket private.
3. Create an R2 API token or access key pair with permission to read and write objects in that bucket.
4. Copy the account-specific S3 API endpoint, usually shaped like:

```text
<account-id>.r2.cloudflarestorage.com
```

5. Set Render `MINIO_ENDPOINT` to that host-only value. Do not include `https://`.
6. Set `MINIO_SECURE=true`.
7. After deploy, `GET /api/v1/health` should return a storage value like `minio:connected`.

If health returns `minio:bucket_missing`, the bucket name is wrong or inaccessible to the key. If it returns `minio:error:*`, verify endpoint format, key permissions, and whether `MINIO_SECURE` is set to `true`.

## MVP Acceptance Criteria

- `/` loads the public SENTINEL landing page.
- `/dashboard` loads the app shell.
- `https://<vercel-host>/api/v1/health` reaches the Render backend through the Vercel rewrite.
- Uploading a small harmless test file through `/dashboard` creates an analysis job.
- The job completes or fails with a visible error state.
- A completed report opens from dashboard history.
- The uploaded object exists in the Cloudflare R2 bucket.
- A backend redeploy does not remove uploaded sample storage because samples live in R2.

## Verification Checklist

Run these before calling an MVP deployment complete:

```bash
cd frontend
npm run build
```

```bash
cd ..
python -m py_compile backend/app/core/config.py backend/app/main.py backend/app/api/routes.py backend/app/worker.py
```

Health checks:

- Local: `GET http://localhost:8000/api/v1/health`
- Render: `GET https://<render-api-host>/api/v1/health`
- Vercel rewrite: `GET https://<vercel-host>/api/v1/health`

Expected hosted health response:

```json
{
  "status": "ok",
  "version": "0.1.0",
  "db": "connected",
  "redis": "disabled",
  "minio": "minio:connected"
}
```

Upload smoke test:

- Upload a small harmless test file through `/dashboard`.
- Verify the job appears in history.
- Verify the report opens after completion.
- Redeploy the backend.
- Confirm report metadata still loads.
- Confirm the uploaded object exists in the R2 bucket.

## Current MVP Safety Controls

- Basic dashboard auth and tenant-scoped jobs/reports are in place.
- Signup requires stronger passwords, auth endpoints and upload endpoints are rate limited, and uploads are capped by active job count plus daily tenant quota.
- Terminal jobs are cleaned up by retention age and maximum tenant history; unreferenced stored files are removed with those records.
- Hosted startup fails fast when `DEBUG=false` is paired with the default secret, wildcard CORS, or local file storage.

## Known MVP Limitations

- There is no invite-only signup gate yet.
- Background-thread analysis is acceptable for the MVP but not ideal for long-running production jobs.
- Malware sample handling still needs isolated execution infrastructure and operational safety rules before public launch.
- The Cloudflare R2 bucket should remain private; do not enable public object access for uploaded samples.
- The MVP should be demoed to trusted users until auth and abuse controls are added.

## Next Product Phase

After the MVP deployment is live, prioritize:

1. Invite-only signup or admin-managed workspace invites.
2. Redis-backed distributed rate limiting for multi-instance deployments.
3. Isolated sandbox execution for untrusted samples.
4. Optional Redis/Celery worker split if analysis runtime exceeds Render web-service expectations.
