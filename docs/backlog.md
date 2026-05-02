# SENTINEL — Product Backlog & Sprint Plan

> **Classification:** Internal — Engineering Program v1.0
> **Team Size:** 6–8 Engineers + 1 Architect Lead
> **Sprint Cadence:** 2-week sprints
> **Velocity Assumption:** ~40–50 story points per sprint
> **Date:** May 2026

---

## Team Roster & Ownership

| Role | Count | Primary Ownership |
|:---|:---:|:---|
| **Tech Lead / Architect** | 1 | System design, code review, cross-cutting concerns |
| **Backend Engineer (Go)** | 2 | Ingestion service, static analysis worker, API performance |
| **Backend Engineer (Python)** | 2 | Orchestrator, Cortex AI service, Celery pipeline |
| **Frontend Engineer** | 1–2 | Next.js dashboard, real-time UX, design system |
| **Infra / Platform Engineer** | 1 | Docker, CI/CD, Terraform, observability, MinIO/Postgres |

---

## Story Point Scale

| Points | Meaning | Example |
|:---|:---|:---|
| 1 | Trivial | Add an env variable, update a config |
| 2 | Small | Write a single API endpoint with tests |
| 3 | Medium | Build a React component with state management |
| 5 | Large | Implement a full Celery worker pipeline |
| 8 | Very Large | Build the sandbox orchestrator or LLM integration |
| 13 | Epic-level spike | Full end-to-end feature with multiple services |

---

# EPICS

## Epic 1: Platform Foundation & Local Dev Environment
**Owner:** Infra Engineer + Tech Lead
**Goal:** Every engineer can `docker-compose up` and have a fully functional local stack within 5 minutes of cloning the repo.

## Epic 2: File Ingestion & Storage Pipeline
**Owner:** Go Backend Engineers
**Goal:** Accept file uploads at scale, hash them, store to object storage, and produce events for downstream processing.

## Epic 3: Orchestration & Job State Machine
**Owner:** Python Backend Engineers
**Goal:** A reliable, observable state machine that tracks every file from INGESTING → QUEUED → ANALYZING → CORTEX_REASONING → COMPLETED/FAILED.

## Epic 4: Static Analysis Engine
**Owner:** Go Backend Engineers
**Goal:** Extract meaningful intelligence from binaries without execution — headers, strings, entropy, YARA matches, packer detection.

## Epic 5: Cortex AI — Threat Narrative Generation
**Owner:** Python Backend Engineers
**Goal:** Consume static/dynamic analysis artifacts and generate human-readable, explainable threat intelligence reports via LLM.

## Epic 6: SOC Analyst Dashboard (Frontend)
**Owner:** Frontend Engineers
**Goal:** A world-class, real-time dashboard where analysts upload files, track analysis progress, and consume threat intelligence.

## Epic 7: Auth, Multi-Tenancy & RBAC
**Owner:** Tech Lead + Backend
**Goal:** Secure, tenant-isolated authentication and authorization system with role-based access.

## Epic 8: Dynamic Sandbox (Stretch)
**Owner:** Go Engineers + Infra
**Goal:** Execute untrusted binaries in Firecracker micro-VMs, capture syscalls via eBPF, and extract behavioral data.

---

# SPRINT 1 — "Zero to Stack" (Weeks 1–2)

**Sprint Goal:** Local dev environment is operational. A file can be uploaded via API, stored in MinIO, and a job record created in Postgres.

---

### User Stories

#### S1.1 — Local Development Environment
**As a** developer on the SENTINEL team,
**I want** to run `docker-compose up` and have Postgres, Redis, and MinIO running locally,
**So that** I can develop and test without any cloud dependencies.

**Points:** 3 | **Owner:** Infra Engineer

**Acceptance Tests:**
- [ ] `docker-compose up` starts Postgres 16, Redis 7, and MinIO containers without errors.
- [ ] Postgres has a database `sentinel_db` created automatically via init script.
- [ ] MinIO has a bucket `sentinel-payloads` created automatically.
- [ ] A `README.md` documents the full setup in under 10 steps.
- [ ] Health check endpoints confirm all services are reachable.

---

#### S1.2 — Backend Project Scaffold (FastAPI)
**As a** backend engineer,
**I want** a properly structured FastAPI project with SQLAlchemy, Alembic migrations, and Pydantic schemas,
**So that** we have a clean, extensible foundation to build every API endpoint on.

**Points:** 3 | **Owner:** Python Backend

**Acceptance Tests:**
- [ ] FastAPI app starts on port 8000 with hot-reload via Uvicorn.
- [ ] Alembic is configured and can generate/run migrations against local Postgres.
- [ ] Project structure follows: `app/api/`, `app/models/`, `app/schemas/`, `app/services/`, `app/core/`.
- [ ] A `/health` endpoint returns `{"status": "ok", "db": "connected"}`.
- [ ] Pytest is configured with a test database fixture.

---

#### S1.3 — Core Database Models
**As a** backend engineer,
**I want** the `tenants`, `users`, and `analysis_jobs` tables defined and migrated,
**So that** we can persist upload metadata and track job state.

**Points:** 3 | **Owner:** Python Backend

**Acceptance Tests:**
- [ ] `alembic upgrade head` creates all three tables.
- [ ] `tenants` has: `id (UUID PK)`, `name`, `tier (ENUM)`, `created_at`.
- [ ] `users` has: `id (UUID PK)`, `tenant_id (FK)`, `email (unique)`, `role (ENUM)`, `password_hash`.
- [ ] `analysis_jobs` has all fields per architecture spec (id, tenant_id, file_hash_sha256, status ENUM, minio_object_path, timestamps).
- [ ] Foreign key constraints are enforced (user → tenant, job → tenant).
- [ ] Unit test: Create a tenant, create a user under that tenant, create a job — all succeed.

---

#### S1.4 — File Upload Endpoint (`POST /api/v1/analyze`)
**As a** SOC analyst,
**I want** to upload a suspicious file via the API and receive a job ID immediately,
**So that** I can track the analysis progress without waiting.

**Points:** 5 | **Owner:** Go or Python Backend

**Acceptance Tests:**
- [ ] `POST /api/v1/analyze` accepts multipart/form-data with a `file` field.
- [ ] The file is streamed to MinIO under path `{tenant_id}/{sha256_hash}/{original_filename}`.
- [ ] SHA-256, SHA-1, and MD5 hashes are computed during stream (not after full buffering).
- [ ] A new `analysis_jobs` row is created with status `QUEUED`.
- [ ] Response is `202 Accepted` with JSON: `{ job_id, status, poll_url }`.
- [ ] Duplicate hash detection: if the same SHA-256 exists and has a completed report, return the cached report with `200 OK` instead.
- [ ] Files larger than 500MB are rejected with `413 Payload Too Large`.
- [ ] Integration test: Upload a test PE file → verify MinIO object exists → verify Postgres row.

---

#### S1.5 — Job Status Endpoint (`GET /api/v1/analyze/{job_id}`)
**As a** SOC analyst,
**I want** to poll for the status of my submitted analysis,
**So that** I know when results are ready.

**Points:** 2 | **Owner:** Python Backend

**Acceptance Tests:**
- [ ] Returns `200 OK` with `{ job_id, status, progress_percent, created_at }`.
- [ ] Returns `404 Not Found` for non-existent job IDs.
- [ ] When status is `COMPLETED`, response includes `report_url`.
- [ ] Unit test: Create job with each status enum → verify correct response shape.

---

#### S1.6 — Frontend Project Scaffold (Next.js)
**As a** frontend engineer,
**I want** a Next.js 14 project initialized with the design system, routing, and API client,
**So that** I can start building UI components on a solid foundation.

**Points:** 3 | **Owner:** Frontend Engineer

**Acceptance Tests:**
- [ ] `npm run dev` starts the app on port 3000.
- [ ] App Router is configured with layout: `/dashboard`, `/upload`, `/reports`.
- [ ] Global styles use a dark-mode-first design system (CSS variables for colors, spacing, typography).
- [ ] An Axios/fetch API client wrapper is configured pointing to `localhost:8000`.
- [ ] A placeholder Dashboard page renders with the SENTINEL logo and nav sidebar.

---

**Sprint 1 Total: ~19 points**

---

# SPRINT 2 — "The Pipeline" (Weeks 3–4)

**Sprint Goal:** A file upload triggers a background Celery task. The job status updates in real time. The frontend shows upload + progress tracking.

---

#### S2.1 — Celery Worker Infrastructure
**As a** platform engineer,
**I want** Celery configured with Redis as the broker and a task routing system,
**So that** we can process analysis jobs asynchronously in the background.

**Points:** 5 | **Owner:** Python Backend

**Acceptance Tests:**
- [ ] Celery worker starts alongside the FastAPI app via docker-compose.
- [ ] A task `process_analysis_job(job_id)` is registered and discoverable.
- [ ] Task accepts a job_id, fetches the job from Postgres, updates status to `ANALYZING`, sleeps 10s (mock), then updates to `COMPLETED`.
- [ ] Failed tasks update status to `FAILED` with an error message.
- [ ] Celery Flower monitoring UI is accessible at `localhost:5555`.

---

#### S2.2 — Event-Driven Job Dispatch
**As the** system,
**I want** the upload endpoint to automatically enqueue a Celery task after saving the file,
**So that** analysis begins immediately without manual intervention.

**Points:** 3 | **Owner:** Python Backend

**Acceptance Tests:**
- [ ] After `POST /api/v1/analyze` saves to MinIO and Postgres, it calls `process_analysis_job.delay(job_id)`.
- [ ] The Celery task picks up the job within 2 seconds.
- [ ] End-to-end test: Upload file → poll status → eventually see `COMPLETED` (within 15s for mock).

---

#### S2.3 — Upload UI Component
**As a** SOC analyst,
**I want** a drag-and-drop file upload interface with progress feedback,
**So that** I can submit suspicious files intuitively.

**Points:** 5 | **Owner:** Frontend Engineer

**Acceptance Tests:**
- [ ] Drag-and-drop zone accepts files and shows the filename + size.
- [ ] Upload progress bar shows real upload percentage.
- [ ] On success, the UI transitions to a "Processing…" view with an animated status indicator.
- [ ] The component polls `GET /api/v1/analyze/{job_id}` every 2 seconds.
- [ ] When status reaches `COMPLETED`, a "View Report" button appears.
- [ ] Error states (network failure, 413 too large) show clear error messages.

---

#### S2.4 — Job History Dashboard
**As a** SOC analyst,
**I want** to see a table of all my past analyses with their status and verdict,
**So that** I can quickly find and revisit previous results.

**Points:** 5 | **Owner:** Frontend Engineer

**Acceptance Tests:**
- [ ] `GET /api/v1/jobs` returns paginated list of jobs for the current tenant.
- [ ] Table columns: File Name, SHA-256 (truncated), Status (with color badge), Verdict, Submitted At.
- [ ] Clicking a row navigates to the full report page.
- [ ] Table supports sorting by date and filtering by status.
- [ ] Empty state shows a clear "No analyses yet" message with CTA to upload.

---

#### S2.5 — Threat Report Data Model
**As a** backend engineer,
**I want** the `threat_reports` table created and linked to `analysis_jobs`,
**So that** analysis results have a structured home.

**Points:** 2 | **Owner:** Python Backend

**Acceptance Tests:**
- [ ] Alembic migration creates `threat_reports` table per architecture spec.
- [ ] One-to-one relationship: each `analysis_job` has at most one `threat_report`.
- [ ] JSONB columns `static_data` and `dynamic_data` accept arbitrary JSON payloads.
- [ ] `GET /api/v1/report/{hash}` returns the report or `404`.

---

**Sprint 2 Total: ~20 points**

---

# SPRINT 3 — "Real Intelligence" (Weeks 5–6)

**Sprint Goal:** Replace mock analysis with real static file parsing. The report page shows actual extracted data.

---

#### S3.1 — Static Analysis: PE Header Extraction
**As the** system,
**I want** to parse PE (Portable Executable) file headers and extract metadata,
**So that** we generate real intelligence about Windows binaries.

**Points:** 5 | **Owner:** Go Backend

**Acceptance Tests:**
- [ ] Worker pulls file from MinIO by `minio_object_path`.
- [ ] Extracts: compile timestamp, entry point, sections (name, virtual size, entropy), imports (DLL + function names), exports.
- [ ] Results saved as JSON to `threat_reports.static_data`.
- [ ] High-entropy sections (>7.0) are flagged as potentially packed/encrypted.
- [ ] Non-PE files are gracefully handled with a "format not supported for deep static" note.

---

#### S3.2 — Static Analysis: String Extraction & IOC Detection
**As a** threat analyst,
**I want** the system to extract human-readable strings and automatically classify IOCs,
**So that** I can immediately see C2 URLs, IPs, and suspicious registry keys.

**Points:** 5 | **Owner:** Go Backend

**Acceptance Tests:**
- [ ] Extracts ASCII and Unicode strings (min length 4 chars).
- [ ] Regex classifiers tag strings as: `URL`, `IP_ADDRESS`, `EMAIL`, `REGISTRY_KEY`, `FILE_PATH`, `CRYPTO_WALLET`, or `UNKNOWN`.
- [ ] Results stored in `static_data.strings[]` with `{ value, classification, offset }`.
- [ ] Unit test: Feed a known malware sample → verify expected C2 URLs are extracted and classified.

---

#### S3.3 — Static Analysis: YARA Rule Engine
**As a** threat analyst,
**I want** uploaded files scanned against a curated YARA ruleset,
**So that** known malware families are immediately flagged.

**Points:** 5 | **Owner:** Go Backend

**Acceptance Tests:**
- [ ] A `/rules` directory holds `.yar` files loaded at worker startup.
- [ ] Worker scans each file against all loaded rules.
- [ ] Matches stored in `static_data.yara_matches[]` with `{ rule_name, tags, meta }`.
- [ ] Hot-reload: adding a new `.yar` file and sending SIGHUP reloads rules without restart.
- [ ] Ships with at least 50 community YARA rules from the YARAify/YARA-Rules GitHub repos.

---

#### S3.4 — Report Detail Page (Frontend)
**As a** SOC analyst,
**I want** a rich, tabbed report page showing all extracted intelligence,
**So that** I can investigate a file thoroughly without leaving the platform.

**Points:** 8 | **Owner:** Frontend Engineer

**Acceptance Tests:**
- [ ] Route: `/report/{hash}` renders the full threat report.
- [ ] **Overview Tab:** Verdict badge (BENIGN/SUSPICIOUS/MALICIOUS), severity score (0-100 gauge), file metadata (name, size, hashes).
- [ ] **Static Analysis Tab:** PE header table, imports/exports lists, section entropy bar chart.
- [ ] **Strings Tab:** Searchable, filterable table of extracted strings with IOC classification badges.
- [ ] **YARA Tab:** List of matched rules with expandable metadata.
- [ ] All tabs lazy-load data and show skeleton loaders.

---

#### S3.5 — CI/CD Pipeline & Quality Gates
**As a** tech lead,
**I want** automated testing, linting, and build verification on every PR,
**So that** we maintain code quality at high velocity.

**Points:** 3 | **Owner:** Infra Engineer

**Acceptance Tests:**
- [ ] GitHub Actions workflow runs on every PR to `main`.
- [ ] Backend: `pytest` with 80%+ coverage gate, `ruff` linting, `mypy` type checking.
- [ ] Frontend: `eslint`, `tsc --noEmit`, `jest` unit tests.
- [ ] Go workers: `go test ./...`, `golangci-lint`.
- [ ] All checks must pass before merge is allowed.

---

**Sprint 3 Total: ~26 points**

---

# SPRINT 4 — "The Brain" (Weeks 7–8)

**Sprint Goal:** Cortex AI generates real natural-language threat narratives. The report page shows AI-powered analysis.

---

#### S4.1 — Cortex AI Service Scaffold
**As a** ML engineer,
**I want** a dedicated FastAPI microservice for AI inference,
**So that** the ML pipeline is isolated, independently scalable, and GPU-aware.

**Points:** 5 | **Owner:** Python Backend

**Acceptance Tests:**
- [ ] `sentinel-cortex` runs as a separate Docker container on port 8001.
- [ ] Exposes `POST /cortex/analyze` accepting JSON (static_data + dynamic_data).
- [ ] Returns `{ narrative, severity_score, verdict, mitre_mappings[] }`.
- [ ] Health check: `GET /cortex/health` returns model load status.
- [ ] Configurable backend: `CORTEX_BACKEND=openai|ollama|mock` via env var.

---

#### S4.2 — LLM Prompt Engineering & Threat Narratives
**As a** SOC analyst,
**I want** the AI to generate a clear, actionable explanation of what a file does,
**So that** I don't need deep reverse-engineering expertise to understand the threat.

**Points:** 8 | **Owner:** Python Backend (ML)

**Acceptance Tests:**
- [ ] Prompt template includes: file metadata, PE header summary, top IOCs, YARA matches.
- [ ] Output is structured: Executive Summary (2-3 sentences), Detailed Findings (bullet points), Recommended Actions.
- [ ] Severity score (0-100) is derived from LLM output + static heuristics (weighted formula).
- [ ] Verdict (BENIGN/SUSPICIOUS/MALICIOUS) is deterministic based on severity thresholds.
- [ ] MITRE ATT&CK technique IDs are extracted and validated against the ATT&CK matrix.
- [ ] Response time < 15 seconds (for OpenAI) or < 30 seconds (for local Ollama).
- [ ] Eval test: Run against 10 known malware samples → human review confirms narratives are accurate and actionable.

---

#### S4.3 — Orchestrator → Cortex Integration
**As the** system,
**I want** the Celery pipeline to automatically call Cortex after static analysis completes,
**So that** every uploaded file gets a full AI-powered report end-to-end.

**Points:** 3 | **Owner:** Python Backend

**Acceptance Tests:**
- [ ] Job state machine: QUEUED → ANALYZING (static) → CORTEX_REASONING → COMPLETED.
- [ ] Orchestrator calls `POST /cortex/analyze` with the static_data payload.
- [ ] Cortex response is saved to `threat_reports` (ai_narrative, severity_score, verdict).
- [ ] If Cortex fails, job status is set to `COMPLETED` with a flag `ai_available: false` (graceful degradation).
- [ ] End-to-end test: Upload PE file → poll → receive full report with AI narrative.

---

#### S4.4 — AI Narrative UI Component
**As a** SOC analyst,
**I want** the AI-generated threat narrative displayed prominently on the report page,
**So that** I get instant, human-readable understanding of the threat.

**Points:** 5 | **Owner:** Frontend Engineer

**Acceptance Tests:**
- [ ] **AI Summary** tab is the default/first tab on the report page.
- [ ] Narrative renders as formatted markdown (headers, bullets, bold for IOCs).
- [ ] MITRE ATT&CK technique IDs are clickable links to attack.mitre.org.
- [ ] Severity gauge animates from 0 to the final score.
- [ ] Verdict badge uses color coding: green (BENIGN), amber (SUSPICIOUS), red (MALICIOUS).
- [ ] "AI-generated" disclaimer is shown with a timestamp.

---

#### S4.5 — API Key Authentication
**As an** API consumer,
**I want** to authenticate via API keys,
**So that** I can integrate SENTINEL into my scripts and CI/CD pipelines.

**Points:** 5 | **Owner:** Python Backend

**Acceptance Tests:**
- [ ] `POST /api/v1/auth/register` creates a user and returns a JWT.
- [ ] `POST /api/v1/auth/api-keys` generates a prefixed API key (`stl_live_...`).
- [ ] All `/api/v1/*` endpoints require either JWT (cookie) or API key (`X-API-Key` header).
- [ ] Rate limiting: Free tier = 100 req/hour, Pro = 5000 req/hour.
- [ ] API keys are hashed (bcrypt) in the database — plaintext shown only once at creation.
- [ ] Unauthorized requests return `401` with clear error message.

---

**Sprint 4 Total: ~26 points**

---

# SPRINT 5 — "Ship It" (Weeks 9–10)

**Sprint Goal:** Production deployment, auth flows, and polish. The platform is publicly accessible.

---

#### S5.1 — User Auth Flows (Frontend)
**Points:** 5 | **Owner:** Frontend

- [ ] Login page with email/password.
- [ ] Registration page with tenant creation.
- [ ] JWT stored in httpOnly cookie; auto-refresh before expiry.
- [ ] Protected routes redirect unauthenticated users to login.
- [ ] Logout clears session.

---

#### S5.2 — Production Infrastructure (Terraform)
**Points:** 8 | **Owner:** Infra Engineer

- [ ] Terraform modules for: VPC, EKS/GKE cluster, RDS (Postgres), ElastiCache (Redis), S3 bucket.
- [ ] Kubernetes manifests (or Helm charts) for all microservices.
- [ ] TLS termination via cert-manager + Let's Encrypt.
- [ ] Environment separation: `staging` and `production`.
- [ ] Secrets managed via AWS Secrets Manager / Vault.

---

#### S5.3 — Observability Stack
**Points:** 5 | **Owner:** Infra Engineer

- [ ] OpenTelemetry SDK integrated into FastAPI and Go services.
- [ ] Prometheus scrapes metrics from all services.
- [ ] Grafana dashboards: API latency (p50/p95/p99), job throughput, queue depth, error rates.
- [ ] Structured JSON logging with correlation IDs across the full pipeline.
- [ ] PagerDuty/Slack alerting for p99 latency > 5s or error rate > 1%.

---

#### S5.4 — Landing Page & Documentation
**Points:** 5 | **Owner:** Frontend + Tech Lead

- [ ] Public landing page at `sentinel.dev` with product overview, pricing tiers, and signup CTA.
- [ ] API documentation auto-generated from FastAPI OpenAPI spec, hosted at `/docs`.
- [ ] Quick-start guide: "Analyze your first file in 60 seconds."
- [ ] Python SDK published to PyPI with `pip install sentinel-sdk`.

---

#### S5.5 — Security Hardening
**Points:** 5 | **Owner:** Tech Lead + Infra

- [ ] OWASP Top 10 audit on all API endpoints.
- [ ] Input validation on all file uploads (magic byte verification, not just extension).
- [ ] SQL injection prevention verified (parameterized queries only).
- [ ] CORS policy locked to allowed origins.
- [ ] Rate limiting enforced at gateway level.
- [ ] Dependency vulnerability scan (Snyk/Dependabot) on all repos.

---

**Sprint 5 Total: ~28 points**

---

# Definition of Done (Global)

Every story is considered **Done** when:
1. Code is merged to `main` via approved PR (1+ reviewer).
2. All acceptance tests pass in CI.
3. No regressions in existing test suite.
4. API changes are reflected in OpenAPI spec.
5. Database changes have a reversible Alembic migration.
6. Feature is deployed to staging and smoke-tested.

---

# Backlog (Unprioritized — Future Sprints)

| ID | Story | Epic | Points |
|:---|:---|:---|:---:|
| B1 | Dynamic sandbox MVP (Firecracker micro-VM) | Epic 8 | 13 |
| B2 | eBPF syscall tracing inside sandbox | Epic 8 | 8 |
| B3 | Network PCAP capture and C2 detection | Epic 8 | 8 |
| B4 | Multi-tenant data isolation (row-level security) | Epic 7 | 5 |
| B5 | RBAC — Admin/Analyst/Viewer permission enforcement | Epic 7 | 5 |
| B6 | Webhook notifications on job completion | Epic 2 | 3 |
| B7 | CLI tool (`sentinel-cli upload <file>`) | Epic 2 | 5 |
| B8 | GitHub Actions integration | Epic 2 | 5 |
| B9 | Team workspaces & shared analyses | Epic 7 | 8 |
| B10 | STIX/TAXII export for threat reports | Epic 6 | 5 |
| B11 | ClickHouse analytics pipeline | Epic 3 | 8 |
| B12 | Milvus vector similarity search for code genome | Epic 5 | 8 |
| B13 | ELF (Linux) binary support in static worker | Epic 4 | 5 |
| B14 | Mach-O (macOS) binary support | Epic 4 | 5 |
| B15 | SSO/SAML integration for enterprise | Epic 7 | 8 |
