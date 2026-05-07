# SENTINEL Deployment Guide

This repo is set up for a split deployment:

- Frontend: Vercel, using `frontend/` as the project root
- Backend API: Render Docker web service, using `backend/` as the service root
- Database: Render Postgres

For the remaining hosted MVP rollout, see [MVP Deployment Plan](mvp_deployment_plan.md).

## Backend on Render

1. Create a Render Blueprint from `render.yaml`, or create a Docker web service manually.
2. Set the service root to `backend`.
3. Set the health check path to `/api/v1/health`.
4. Configure environment variables:

```env
DEBUG=false
CORS_ORIGINS=https://your-vercel-app.vercel.app
DATABASE_URL=<Render Postgres connection string>
STORAGE_BACKEND=local
STORAGE_DIR=/app/storage
SECRET_KEY=<generated secret>
USE_CELERY=false
```

Render commonly provides `DATABASE_URL` as `postgresql://...`; the backend normalizes it to the async URL used by SQLAlchemy and derives the sync URL used by the analysis worker.

Local storage on Render is ephemeral. It is acceptable for an early demo, but uploaded samples can disappear after redeploys. Move `STORAGE_BACKEND` to MinIO/S3-compatible storage before relying on retained samples.

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
