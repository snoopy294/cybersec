# SENTINEL Next Session Notes

Use this file as the starting point for the next AI agent or development session.

## Current Direction

SENTINEL is being built as a hosted cybersecurity analysis website. The current product direction is:

- A useful analyst-facing web app for uploading suspicious files.
- Static analysis first: PE metadata, strings, IOCs, entropy, behavior profile, scoring, detection pack generation, and historical similarity.
- Hosted MVP before full malware detonation.
- Dynamic malware execution only after isolated sandbox infrastructure exists.

Do not run uploaded malware inside the FastAPI web service, the Next.js frontend, Render web workers, or the local developer machine.

## Current Stack

- Frontend: Next.js App Router, React, Axios, Recharts, lucide-react.
- Backend API: FastAPI, SQLAlchemy, Pydantic, Python.
- Database: SQLite locally by default; Postgres for hosted deployment.
- Object storage: local storage for development; MinIO/S3-compatible storage for hosted deployment.
- Worker model: background thread by default; Celery path exists for Redis-backed workers.
- Deployment target in docs: Vercel frontend, Render backend, Render Postgres, Cloudflare R2 private bucket.

The repo is already moving toward public deployment, but the hosted MVP should remain static-analysis only until sandboxing is built.

## Important Current Caveat

There is a deployment config mismatch to fix:

- Docs mention `BACKEND_URL` for the Vercel frontend.
- `frontend/next.config.js` currently reads `NEXT_PUBLIC_API_URL`.

Pick one name and make the docs and frontend config match before deploying.

## Public Web Requirements

Before this can safely run on the public internet:

- Use a generated production `SECRET_KEY`.
- Keep `DEBUG=false`.
- Use explicit `CORS_ORIGINS`; never wildcard CORS in production.
- Use private object storage for uploaded samples.
- Keep API docs disabled in production unless intentionally exposed.
- Add invite-only signup or admin-managed invites.
- Move rate limiting to Redis if running more than one backend instance.
- Use queue-backed workers for long analysis jobs.
- Add logging, monitoring, backups, and retention checks.
- Treat uploaded files as hostile, even before execution.

## Sandboxing Direction

The right architecture for malware isolation is a separate sandbox runner, not code inside the web server.

Target flow:

1. API receives upload and stores sample in private object storage.
2. API creates an analysis job in Postgres.
3. Queue dispatches job to a worker.
4. Worker submits the sample to a sandbox runner.
5. Sandbox runner creates or restores a disposable VM/microVM snapshot.
6. Network starts as deny-all, or routes only to a controlled fake lab network.
7. Sample runs with strict timeout, CPU, memory, filesystem, and network limits.
8. Sandbox collects behavior logs, dropped files, PCAP, screenshots, registry/process/file events, and exit metadata.
9. Sandbox destroys or reverts the VM.
10. Worker stores sanitized dynamic results and updates the report.

Recommended practical sandbox options:

- CAPE Sandbox for Windows malware dynamic analysis and payload/config extraction.
- DRAKVUF Sandbox for stealthier VM introspection if the infrastructure budget and hardware allow it.
- Cuckoo-style architecture if keeping the initial setup simpler.
- Vercel Sandbox or Firecracker-style Linux microVMs only for isolated Linux command execution, not full Windows malware detonation.

## Suggested Next Implementation Steps

1. Fix the frontend deployment env var mismatch.
2. Make the hosted MVP deploy cleanly with static analysis only.
3. Add invite-only signup or admin-created tenant invites.
4. Switch hosted analysis dispatch from background thread to a real queue/worker setup.
5. Add database models for dynamic sandbox results without implementing detonation yet.
6. Add a `sandbox_provider` abstraction with a stub provider first.
7. Later plug the provider into CAPE/DRAKVUF through their API or a private internal service.

## Data Model Direction

Keep static and dynamic analysis separate:

- `ThreatReport.static_data`: existing static analysis output.
- `ThreatReport.iocs`: extracted indicators.
- Future `ThreatReport.dynamic_data`: sandbox behavior output.
- Future `SandboxRun`: provider, status, timeout, network policy, artifact paths, started/completed timestamps, error message.

This keeps the current UI/report structure stable while allowing dynamic analysis to be added later.

## Product Direction

For current cybersecurity usefulness, prioritize:

- Clear verdict explanations with evidence.
- Behavior-focused summaries instead of only hashes.
- IOC extraction and export.
- Detection pack generation.
- Historical similarity between samples.
- Tenant-scoped report history.
- Safe handling and retention of uploaded samples.

Avoid marketing-page work until the core analyst workflow is reliable.

## Safety Rule

Until sandboxing is implemented, do not add code that executes uploaded files. Static parsing, hashing, string extraction, PE analysis, and report generation are acceptable. Detonation belongs only in disposable isolated infrastructure.
