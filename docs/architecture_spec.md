# SENTINEL: System Architecture & Engineering Blueprint

> **Classification:** Internal — Core Engineering v2.0
> **Status:** Approved for Implementation
> **Date:** May 2026

## 1. Executive Engineering Vision

SENTINEL is a planetary-scale, autonomous threat intelligence engine. This document translates the visionary masterplan into an **executable engineering blueprint**. It defines the exact microservices, data schemas, API contracts, and phased implementation steps required to build the platform from scratch.

---

## 2. System Components & Repository Structure

We will adopt a multi-repo (or well-architected monorepo using Nx/Turborepo) structure. The system is decomposed into the following core services:

### 2.1 Edge & Frontend
*   **`sentinel-web` (React/Next.js):** The SOC Analyst Dashboard.
    *   *Tech:* Next.js 14 (App Router), TailwindCSS, Shadcn UI, Zustand (State), Recharts (Data Viz).
*   **`sentinel-api-gateway` (Kong / NGINX):** Handles rate-limiting, JWT validation, and routes traffic.

### 2.2 Core Platform Services
*   **`sentinel-ingestion` (Go):** High-throughput file receiver.
    *   *Tech:* Go, Fiber framework, AWS SDK (for MinIO).
    *   *Role:* Streams uploads directly to MinIO, computes hashes (SHA-256), and publishes a `job_created` event to Redis/RabbitMQ.
*   **`sentinel-orchestrator` (Python):** The state machine.
    *   *Tech:* Python, Celery, Redis.
    *   *Role:* Listens to new jobs and routes them to respective worker queues. Tracks job state (Pending -> Static -> Dynamic -> AI -> Complete).

### 2.3 Analysis Workers
*   **`sentinel-worker-static` (Go):** 
    *   *Role:* Pulls binary from MinIO, extracts PE/ELF headers, runs YARA rules, computes entropy, and saves results to Postgres/ClickHouse.
*   **`sentinel-worker-sandbox` (Rust):** 
    *   *Role:* Orchestrates Firecracker micro-VMs. Injects payload, traces syscalls via eBPF, extracts PCAPs, and tears down the VM.
*   **`sentinel-cortex` (Python):** 
    *   *Tech:* FastAPI, PyTorch, vLLM.
    *   *Role:* Takes static/dynamic JSON outputs, runs them through the local LLM/Classifier, and generates the final natural language narrative.

---

## 3. Data Models & Schemas

The primary relational store is **PostgreSQL 16**. Below are the core tables to bootstrap the application.

### `tenants`
*   `id` (UUID, PK)
*   `name` (String)
*   `tier` (Enum: FREE, PRO, ENTERPRISE)
*   `created_at` (Timestamp)

### `users`
*   `id` (UUID, PK)
*   `tenant_id` (UUID, FK)
*   `email` (String, Unique)
*   `role` (Enum: ADMIN, ANALYST, VIEWER)
*   `password_hash` (String)

### `analysis_jobs` (The core state machine)
*   `id` (UUID, PK) - Returned to user immediately upon upload.
*   `tenant_id` (UUID, FK)
*   `file_hash_sha256` (String, Indexed)
*   `file_name` (String)
*   `file_size_bytes` (BigInt)
*   `status` (Enum: INGESTING, QUEUED, ANALYZING, CORTEX_REASONING, COMPLETED, FAILED)
*   `minio_object_path` (String)
*   `created_at` (Timestamp)
*   `completed_at` (Timestamp, Nullable)

### `threat_reports`
*   `id` (UUID, PK)
*   `job_id` (UUID, FK, Unique)
*   `file_hash_sha256` (String, Indexed)
*   `severity_score` (Int: 0-100)
*   `verdict` (Enum: BENIGN, SUSPICIOUS, MALICIOUS)
*   `ai_narrative` (Text)
*   `static_data` (JSONB) - Headers, strings, entropy.
*   `dynamic_data` (JSONB) - API calls, network streams.

---

## 4. Core API Contracts (REST)

To unblock frontend and backend teams simultaneously, we define the core API contracts upfront.

### `POST /api/v1/analyze`
**Request (Multipart Form Data):**
*   `file`: The binary file.
*   `priority`: Optional boolean (for Enterprise tenants).

**Response (202 Accepted):**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "QUEUED",
  "message": "File ingested successfully. Polling URL provided.",
  "poll_url": "/api/v1/analyze/550e8400-e29b-41d4-a716-446655440000"
}
```

### `GET /api/v1/analyze/{job_id}`
**Response (200 OK):**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "COMPLETED",
  "progress": 100,
  "report_url": "/api/v1/report/sha256-hash-here"
}
```

### `GET /api/v1/report/{hash}`
**Response (200 OK):**
```json
{
  "hash": "...",
  "verdict": "MALICIOUS",
  "severity_score": 98,
  "cortex_narrative": "This file establishes persistence via a scheduled task (T1053.005), then exfiltrates browser credentials...",
  "indicators_of_compromise": {
    "ips": ["185.12.x.x"],
    "domains": ["malicious-c2.com"]
  }
}
```

---

## 5. Local Development Environment (Phase 0)

To achieve maximum developer velocity, the entire stack must be runnable locally on a standard MacBook Pro (M-series) or Windows/WSL2 machine via `docker-compose.yml`.

**Local Services:**
1.  **PostgreSQL:** Relational DB.
2.  **Redis:** Message broker & caching.
3.  **MinIO:** Local S3 replacement. Create a bucket `sentinel-payloads` on startup.
4.  **Backend API:** FastAPI running via Uvicorn with hot-reload.
5.  **Frontend:** Next.js running on port 3000.

*Note: For local development, the Sandbox and Cortex ML models will be "mocked" (returning static JSON fixtures) to save compute, unless explicitly enabled via `MOCK_SERVICES=false`.*

---

## 6. Implementation Roadmap (Sprints)

This translates the blueprint into actionable engineering sprints.

### Sprint 1: The Core Skeleton (Foundation)
*   **Goal:** A user can upload a file, it saves to MinIO, logs to Postgres, and returns a Job ID.
*   **Tasks:**
    *   Setup Git repositories and CI/CD linting.
    *   Write `docker-compose.yml` for local Postgres, Redis, MinIO.
    *   Initialize FastAPI backend and connect to DB using SQLAlchemy/Alembic.
    *   Implement `POST /analyze` (Upload -> MinIO -> Postgres -> return Job ID).

### Sprint 2: Frontend & Orchestration
*   **Goal:** Real-time progress tracking in the UI.
*   **Tasks:**
    *   Initialize Next.js dashboard. Build layout and basic auth screens.
    *   Build the "Upload File" drag-and-drop component.
    *   Implement Celery workers in Python. When a file is uploaded, a background Celery task starts, sleeps for 10 seconds (mocking analysis), and updates the Job status to COMPLETED.
    *   Frontend polls `GET /api/v1/analyze/{job_id}` and shows a progress bar.

### Sprint 3: The Static Worker & Real Data
*   **Goal:** Replace the 10-second sleep with actual file parsing.
*   **Tasks:**
    *   Create the Go static worker.
    *   It pulls the file from MinIO, computes hashes, extracts PE headers (using e.g., `pefile` equivalent in Go), and extracts human-readable strings.
    *   Save this JSON payload to the `threat_reports.static_data` column.
    *   Frontend reads this data and displays a beautiful "Static Analysis" tab.

### Sprint 4: Cortex ML Integration (MVP AI)
*   **Goal:** Generate the natural language report.
*   **Tasks:**
    *   Create the FastAPI `sentinel-cortex` service.
    *   Integrate the OpenAI API (or a local quantized Llama3 model via Ollama for privacy) as a placeholder for our custom fine-tuned model.
    *   Feed the static JSON data into a prompt template: *"You are an expert SOC analyst. Review this static file data and generate a threat summary."*
    *   Save the response to `threat_reports.ai_narrative`.
    *   Frontend displays the AI Summary.

---

## 7. Next Steps for the Engineering Team

1.  **Approval:** Review this blueprint.
2.  **Repository Creation:** Create `sentinel-backend`, `sentinel-frontend`, and `sentinel-infra` repos.
3.  **Sprint 1 Kickoff:** Assign the API Ingestion and MinIO/Postgres setup tasks. 
4.  **Design System:** Have UI/UX spin up the Figma utilizing Shadcn UI components.
