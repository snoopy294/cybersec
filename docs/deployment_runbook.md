# SENTINEL Deployment Runbook

Use this runbook for the first hosted MVP deployment and for each redeploy after that.

## Goal

Deploy SENTINEL as a hosted MVP:

- Public landing page on Vercel at `/`
- Protected dashboard on Vercel at `/dashboard`
- FastAPI backend on Render
- Postgres on Render
- Uploaded samples stored in a private Cloudflare R2 bucket
- Vercel `/api/v1/*` requests rewritten to the Render backend

## Pre-Deploy Checklist

- Latest `main` is pushed to GitHub.
- Cloudflare R2 bucket exists and is private.
- R2 access keys can read and write objects in the bucket.
- Render Postgres database exists.
- Render backend service is connected to this GitHub repo.
- Vercel frontend project uses `frontend` as the project root.
- No secrets are committed to the repo.

## Cloudflare R2

Create a private R2 bucket for uploaded samples. Then create an R2 access key pair with object read/write permission for that bucket.

Render needs these values:

```env
STORAGE_BACKEND=minio
MINIO_ENDPOINT=<account-id>.r2.cloudflarestorage.com
MINIO_ACCESS_KEY=<r2-access-key-id>
MINIO_SECRET_KEY=<r2-secret-access-key>
MINIO_BUCKET=<r2-bucket-name>
MINIO_SECURE=true
```

Use the account-specific S3 API endpoint without `https://` in `MINIO_ENDPOINT`.

## Render Backend

Deploy the backend as a Render Docker web service.

- Service root: `backend`
- Dockerfile: `backend/Dockerfile`
- Health check path: `/api/v1/health`

Set these Render environment variables:

```env
DEBUG=false
SECRET_KEY=<long-random-secret>
DATABASE_URL=<render-postgres-url>
CORS_ORIGINS=https://<vercel-host>
STORAGE_BACKEND=minio
MINIO_ENDPOINT=<account-id>.r2.cloudflarestorage.com
MINIO_ACCESS_KEY=<r2-access-key-id>
MINIO_SECRET_KEY=<r2-secret-access-key>
MINIO_BUCKET=<r2-bucket-name>
MINIO_SECURE=true
USE_CELERY=false
```

After the backend deploys, verify:

```bash
curl https://<render-api-host>/api/v1/health
```

Expected hosted shape:

```json
{
  "status": "ok",
  "db": "connected",
  "redis": "disabled",
  "minio": "minio:connected"
}
```

## Vercel Frontend

Import the repo into Vercel.

- Framework: Next.js
- Project root: `frontend`
- Build command: `npm run build`

Set this Vercel environment variable:

```env
BACKEND_URL=https://<render-api-host>
```

Deploy Vercel, then update Render `CORS_ORIGINS` to the final Vercel URL and redeploy the Render backend.

## Smoke Test

Run this through the final Vercel URL:

1. Open `/` and confirm the public landing page loads.
2. Open `/dashboard` and confirm the login/signup screen loads.
3. Create a test account.
4. Log out and log back in.
5. Confirm refreshing `/dashboard` keeps a valid session.
6. Upload a small harmless test file well under the 500 MB MVP limit.
7. Confirm an analysis job appears in history.
8. Wait for the job to complete or fail with a visible error.
9. Open the completed report from dashboard history.
10. Redeploy the Render backend.
11. Confirm report metadata still loads.
12. Confirm the uploaded object exists in the R2 bucket.

## Release Checks

Run before a deploy when working locally:

```bash
cd frontend
npm run build
```

```bash
cd ..
python -m py_compile backend/app/core/config.py backend/app/main.py backend/app/api/routes.py backend/app/worker.py
```

Hosted checks:

```bash
curl https://<render-api-host>/api/v1/health
curl https://<vercel-host>/api/v1/health
```

The Vercel health check should reach the Render backend through the rewrite.

## MVP Guardrails

- Keep the R2 bucket private.
- Use a strong Render `SECRET_KEY`.
- Keep `DEBUG=false` on Render.
- Use `USE_CELERY=false` for the MVP unless analysis jobs become too slow for the web service.
- Treat uploaded samples as sensitive. Do not publicly expose object URLs.
- Demo to trusted users until rate limiting, retention controls, deletion, and stronger malware-handling procedures are added.

## Troubleshooting

- `minio:bucket_missing`: verify bucket name and R2 key permissions.
- `minio:error:*`: verify endpoint format, `MINIO_SECURE=true`, and access keys.
- Vercel `/api/v1/health` fails but Render health works: verify `BACKEND_URL` in Vercel and redeploy.
- Browser CORS error: update Render `CORS_ORIGINS` to the final Vercel URL and redeploy Render.
- Login works then dashboard returns to login: verify Render `SECRET_KEY` is stable across redeploys.
