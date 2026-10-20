# Deploy To-Do

Personal checklist for getting SENTINEL live on free tiers. Full details and troubleshooting: [docs/deployment_runbook.md](docs/deployment_runbook.md).

## 0. Code (done, needs pushing)

- [ ] Commit and push the deploy fixes to `main` (env var fix, `ALLOW_REGISTRATION`, Neon support, free `render.yaml`)

## 1. Neon Postgres (free, no expiry)

- [ ] Sign up at neon.tech and create a project
- [ ] Copy the connection string (`postgresql://...?sslmode=require...`) and paste it as-is later. The backend fixes the params itself.

## 2. Cloudflare R2 (10 GB free, needs card/PayPal on file)

- [ ] Enable R2 in the Cloudflare dashboard
- [ ] Create a **private** bucket (e.g. `sentinel-samples`). Never turn on public access.
- [ ] Create an R2 API token with object read/write on that bucket
- [ ] Save: access key ID, secret access key, bucket name, account endpoint (`<account-id>.r2.cloudflarestorage.com`, **no** `https://`)

## 3. Render backend (free web service)

- [ ] New > Blueprint > connect the `snoopy294/cybersec` repo (uses `render.yaml`)
- [ ] Set these env vars when prompted:
  - `DATABASE_URL` = Neon connection string
  - `MINIO_ENDPOINT` = R2 endpoint (host only)
  - `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` = R2 keys
  - `MINIO_BUCKET` = bucket name
  - `CORS_ORIGINS` = put anything for now, fixed in step 5
- [ ] Wait for the deploy, then open `https://<render-host>/api/v1/health`
  - Expect `"db": "connected"` and `"minio": "minio:connected"`

## 4. Vercel frontend (Hobby, free)

- [ ] Import the same repo, set **Root Directory** to `frontend`
- [ ] Add env var `BACKEND_URL` = `https://<render-host>` (no trailing slash)
- [ ] Deploy and note the Vercel URL

## 5. Connect them

- [ ] On Render, set `CORS_ORIGINS` = `https://<vercel-host>` and redeploy
- [ ] Open `https://<vercel-host>/api/v1/health` and confirm it reaches the backend

## 6. Smoke test

- [ ] `/` landing page loads, `/dashboard` shows login
- [ ] Create your own account
- [ ] Upload a small harmless file (e.g. a text file or a known-good `.exe` like `notepad.exe`)
- [ ] Job appears in history and the report opens
- [ ] File shows up in the R2 bucket

## 7. Lock it down

- [ ] Create a demo account for recruiters and upload 2-3 sample files so it has reports to show
- [ ] On Render, set `ALLOW_REGISTRATION=false` and redeploy
- [ ] Confirm signing up now says "Registration is closed"

## 8. Resume

- [ ] Add the live Vercel link to the "Malware Analysis Tool" entry
- [ ] Put the demo login in the README or share it on request
- [ ] Use "built" rather than "deployed" until this list is done
- [ ] Consider adding the project to the 8 resumes that leave it out: `Downloads/Derek_Resume.pdf`, AMEX, BOA, Boeing, Cisco, pwc, saronic

## Things to remember

- Render free tier sleeps after ~15 min idle, so the first visit takes up to a minute. Open the link yourself before sharing it live.
- Vercel Hobby is non-commercial only. That's fine for this project.
- Never run uploaded files on the backend or your own PC. The app only does static analysis.

## Later: own sandbox (separate project)

- Use self-hosted CAPE or DRAKVUF (open source, no samples leave your hardware) or build your own
- Run it on a dedicated Linux box with KVM, not your main PC
- Isolated network: outbound blocked or faked, VM snapshot reverted after every run
- Website talks to it only through a `sandbox_provider` interface (see `docs/next_session_notes.md`)
