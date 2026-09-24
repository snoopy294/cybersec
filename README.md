# Autonomous Threat Intelligence Platform

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 18+ (for frontend dev)

### 1. Start the backend stack
```bash
docker-compose up --build
```

This starts:
| Service | URL |
|:---|:---|
| **FastAPI Backend** | http://localhost:8000 |
| **API Docs (Swagger)** | http://localhost:8000/docs |
| **MinIO Console** | http://localhost:9001 |
| **Celery Flower** | http://localhost:5555 |

### 2. Start the frontend
```bash
cd frontend
npm install
npm run dev
```

Dashboard: **http://localhost:3000**

## Deployment

See [docs/deployment.md](docs/deployment.md) for the Vercel + Render setup, required environment variables, and health check configuration.

## Architecture

```
cyber/
├── backend/              # FastAPI + Celery + SQLAlchemy
│   ├── app/
│   │   ├── api/          # REST route handlers
│   │   ├── core/         # Config, database engine
│   │   ├── models/       # SQLAlchemy ORM models
│   │   ├── schemas/      # Pydantic request/response schemas
│   │   ├── services/     # Business logic (file storage, auth)
│   │   ├── worker.py     # Celery analysis pipeline
│   │   └── main.py       # FastAPI app entry point
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/             # Next.js 14 dashboard
│   └── src/app/
│       ├── globals.css   # Design system
│       ├── layout.js     # Root layout
│       └── page.js       # Main dashboard SPA
├── docs/                 # Strategic documentation
│   ├── masterplan.md     # Vision & business plan
│   ├── architecture_spec.md  # Engineering blueprint
│   └── backlog.md        # Epics, stories & sprints
└── docker-compose.yml    # Full local dev stack
```
