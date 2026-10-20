# SENTINEL Deployment Guide

This repo is set up for a split deployment:

- Frontend: Vercel, using `frontend/` as the project root
- Backend API: Render Docker web service, using `backend/` as the service root
- Database: Neon Postgres (free tier)

For the remaining hosted MVP rollout, see [MVP Deployment Plan](mvp_deployment_plan.md). For the exact deploy procedure and smoke test, use the [Deployment Runbook](deployment_runbook.md).

## Backend on Render

1. Create a Render Blueprint from `render.yaml`, or create a Docker web service manually.
2. Set the service root to `backend`.
3. Set the health check path to `/api/v1/health`.
4. Configure environment variables:

```env
DEBUG=false
CORS_ORIGINS=https://your-vercel-app.vercel.app
DATABASE_URL=<Neon Postgres connection string>
STORAGE_BACKEND=minio
MINIO_ENDPOINT=<account-id>.r2.cloudflarestorage.com
MINIO_ACCESS_KEY=<r2-access-key-id>
MINIO_SECRET_KEY=<r2-secret-access-key>
MINIO_BUCKET=<r2-bucket-name>
MINIO_SECURE=true
SECRET_KEY=<generated secret>
USE_CELERY=false
MAX_FILE_SIZE_MB=100
UPLOAD_RATE_LIMIT_PER_MINUTE=5
MAX_ACTIVE_JOBS_PER_TENANT=3
MAX_DAILY_UPLOAD_MB_PER_TENANT=1024
RETENTION_DAYS=30
RETENTION_MAX_JOBS_PER_TENANT=250
EXPOSE_API_DOCS=false
ALLOW_REGISTRATION=true  # set to false after creating your accounts
```

The backend normalizes a `postgresql://...` connection string (including Neon's `sslmode`/`channel_binding` params) to the async URL used by SQLAlchemy and derives the sync URL used by the analysis worker.

Cloudflare R2 is the MVP object-storage target. Keep the R2 bucket private and set `MINIO_ENDPOINT` to the host-only account endpoint without `https://`.

When `DEBUG=false`, the backend refuses to start with the default development secret, wildcard CORS origins, or local filesystem sample storage. This is intentional; uploaded samples must stay in private object storage for hosted environments.

## Free Tier Notes

Everything here runs on free tiers, which suits a personal, non-commercial project:

- **Vercel Hobby**: free, non-commercial use only.
- **Render free web service**: spins down after ~15 minutes idle; the first request afterwards takes up to a minute while it wakes.
- **Neon Postgres** (instead of Render Postgres): Render's free Postgres is deleted 30 days after creation, Neon's free tier does not expire. Paste Neon's connection string as-is; the backend rewrites `sslmode`/`channel_binding` for asyncpg.
- **Cloudflare R2**: 10 GB free, but Cloudflare requires a card or PayPal on file to enable R2.

## Registration

`ALLOW_REGISTRATION` defaults to `true`. After creating your own account (and a demo account to share), set it to `false` on Render and redeploy so strangers can't sign up and upload files.

## Frontend on Vercel

1. Import the GitHub repo into Vercel.
2. Set the project root directory to `frontend`.
3. Add this environment variable:

```env
BACKEND_URL=https://your-render-api.onrender.com
```

The frontend calls `/api/v1/...`; Next.js rewrites those requests to `BACKEND_URL` on the server. Locally, it defaults to `http://localhost:8000`.

## Local Development

Backend:

```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Frontend:

```bash
cd frontend
npm run dev
```

Health check:

```bash
curl http://localhost:8000/api/v1/health
```
